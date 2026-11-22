"""Pair a rebuilt policy backend with an unchanged, already extended SDK helper."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from policy_backend_identity import describe_backend, write_identity
from verify_sdk_member_diff import compare_members, parse_ar

ROOT = Path(__file__).resolve().parents[1]
sha = lambda data: hashlib.sha256(data).hexdigest()


def symbols(data):
    elf = ELFFile(io.BytesIO(data))
    return sorted((s.name, s['st_info']['bind'], s['st_info']['type'], s['st_other']['visibility'],
                   s['st_shndx'] == 'SHN_UNDEF') for s in elf.get_section_by_name('.symtab').iter_symbols()
                  if s['st_info']['bind'] != 'STB_LOCAL')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backend', required=True, type=Path)
    p.add_argument('--entry', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--ndk', required=True, type=Path)
    p.add_argument('--build-id', required=True)
    p.add_argument('--source', type=Path, default=ROOT / 'runtime/maplesu-sdk')
    a = p.parse_args()
    out = a.out.resolve()
    assert out.is_relative_to(ROOT / 'work') and out != ROOT / 'work' and not out.exists()
    source = a.source.resolve()
    manifest_bytes = (source / 'SDK-RELEASE.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    archive = ROOT / manifest['archive']['path']
    base = archive.read_bytes()
    assert sha(base) == manifest['archive']['sha256']
    members = parse_ar(str(archive))
    member = members['members'][52]
    original_object = base[member['body_offset']:member['body_offset'] + member['size']]
    data = ELFFile(io.BytesIO(original_object)).get_section_by_name('.data')
    original = data.data()
    assert sha(original) == manifest['helper']['sha256']
    original_elf = ELFFile(io.BytesIO(original))
    entry = json.loads((a.entry / 'build.json').read_text())
    entry_elf = a.entry / 'entry.elf'
    if not entry_elf.is_file():
        entry_elf = a.entry / 'paired/entry.elf'
    extension = ELFFile(io.BytesIO(entry_elf.read_bytes())).get_section_by_name('.extension')
    va, expected = extension['sh_addr'], extension.data()
    offset = next(s['p_offset'] + va - s['p_vaddr'] for s in original_elf.iter_segments()
                  if s['p_type'] == 'PT_LOAD' and s['p_vaddr'] <= va and va + len(expected) <= s['p_vaddr'] + s['p_filesz'])
    assert original[offset:offset + len(expected)] == expected, 'Paired entry baseline drift'
    assert (ROOT / manifest['environmentPolicyBoot']['backend']['path']).is_file()
    old_identity = describe_backend(ROOT / manifest['environmentPolicyBoot']['backend']['path'])
    new_identity = describe_backend(a.backend)
    if 'requestContextRepair' in manifest:
        backend_elf = ELFFile(io.BytesIO(a.backend.read_bytes()))
        assert any(s.name == 'maplesu_prepare_kernel_request' and s['st_shndx'] != 'SHN_UNDEF'
                   for s in backend_elf.get_section_by_name('.symtab').iter_symbols()), \
            'Policy backend was not relinked with request credential isolation'
    out.mkdir(parents=True)
    tool = a.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'

    def run(name, *args):
        r = subprocess.run([str(tool / (name + '.exe')), *map(str, args)], capture_output=True, timeout=60)
        if r.returncode:
            raise RuntimeError(r.stderr.decode('utf-8', 'replace'))

    dyn, plt = original_elf.get_section_by_name('.dynsym'), original_elf.get_section_by_name('.plt')['sh_addr']
    defs = {dyn.get_symbol(r['r_info_sym']).name: plt + 32 + 16 * i
            for i, r in enumerate(original_elf.get_section_by_name('.rela.plt').iter_relocations())}
    defs.update(original_selinux_initializer=entry['originalSelinuxInitializer'],
                original_module_loader=entry['originalModuleLoader'], original_root_key=entry['keyAddress'],
                policy_ready_slot=entry['readySlot'])
    linker = out / 'entry.ld'
    linker.write_text(f'SECTIONS {{ . = {hex(va)}; .extension : {{ *(.text*) *(.rodata*) }} '
                      '/DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) } }\n')

    def compile_entry(label, identity):
        target = out / label
        target.mkdir()
        write_identity(target / 'environment_backend_identity.h', identity)
        objects = []
        for name in ('environment_loader.c', 'environment_entry.S'):
            obj = target / (name + '.o')
            run('clang', '--target=aarch64-linux-android21', '-Oz', '-ffreestanding', '-fno-builtin', '-fPIC',
                '-fno-stack-protector', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
                '-Wall', '-Wextra', '-Werror', '-I', target, '-c', ROOT / 'runtime/ultra/policy' / name, '-o', obj)
            objects.append(obj)
        linked = target / 'entry.elf'
        run('ld.lld', '-T', linker, '--entry=maplesu_environment_policy_entry',
            *[f'--defsym={k}={hex(v)}' for k, v in defs.items()], *objects, '-o', linked)
        elf = ELFFile(io.BytesIO(linked.read_bytes()))
        assert not [s for s in elf.iter_sections() if s['sh_type'] in ('SHT_REL', 'SHT_RELA') and s['sh_size']]
        return elf.get_section_by_name('.extension').data(), {
            s.name: s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols()}

    baseline, old_symbols = compile_entry('baseline', old_identity)
    assert baseline == expected, 'Current loader does not reproduce the pinned helper extension'
    replacement, new_symbols = compile_entry('paired', new_identity)
    assert len(replacement) == len(expected), 'Backend rebinding changed the helper layout'
    for name in ('maplesu_environment_policy_entry', 'maplesu_environment_policy_module_entry',
                 'maplesu_environment_policy_load'):
        assert old_symbols[name] == new_symbols[name], 'Backend rebinding moved an entry'
    helper = bytearray(original)
    helper[offset:offset + len(expected)] = replacement
    note = original_elf.get_section_by_name('.note.gnu.build-id')['sh_offset'] + 16
    helper[note:note + 20] = bytes(20)
    normalized = bytearray(helper)
    slot = manifest['helper']['keySlotOffset']
    normalized[slot:slot + 4096] = bytes(4096)
    build_id = hashlib.sha1(normalized).digest()
    helper[note:note + 20] = normalized[note:note + 20] = build_id
    assert helper[slot:slot + 4096] == original[slot:slot + 4096]
    assert all(x == y or offset <= i < offset + len(expected) or note <= i < note + 20
               for i, (x, y) in enumerate(zip(original, helper)))
    # The containing program headers, module gate, Identity, completion and all
    # previous repairs stay byte-for-byte intact. No new extension is appended.
    (out / 'embedded-bootstrap.elf').write_bytes(helper)
    body = bytearray(original_object)
    body[data['sh_offset']:data['sh_offset'] + len(helper)] = helper
    assert symbols(body) == symbols(original_object)
    patched_object = out / member['name']
    patched_object.write_bytes(body)
    candidate = out / 'lib/arm64-v8a' / archive.name
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(base)
    run('llvm-ar', 'rD', candidate, patched_object)
    run('llvm-ar', 'sD', candidate)
    after = parse_ar(str(candidate))
    diff = compare_members(members, after)
    assert [m['ord'] for m in diff['changed']] == [52]
    assert not diff['added'] and not diff['removed'] and not diff['orderErrors']
    baseline_members = parse_ar(str(ROOT / 'runtime/maplesu-sdk/maintenance/baseline/libkernel_module_kit_static.a'))
    count = baseline_members['member_count']
    full = compare_members(baseline_members, dict(after, members=after['members'][:count], member_count=count))
    full['added'] = [dict(ord=m['ord'], name=m['name'], candidateSha256=m['sha256']) for m in after['members'][count:]]
    diff_file = out / 'SU-AUTH-MEMBER-DIFF.json'
    diff_file.write_text(json.dumps(dict(schemaVersion=1, baselineArchiveSha256=baseline_members['file_sha256'],
        archiveSha256=after['file_sha256'], totalMembers=after['member_count'], **full), indent=2) + '\n')
    release = copy.deepcopy(manifest)
    release.update(sdkBuildId=a.build_id, generatedUtc=datetime.now(timezone.utc).isoformat())
    release['archive'].update(path=candidate.relative_to(ROOT).as_posix(), sha256=after['file_sha256'], size=candidate.stat().st_size)
    for key in ('helper', 'bootstrap'):
        release[key].update(sha256=sha(helper), buildId=build_id.hex(), size=len(helper))
    release['helper']['normalizedSha256'] = sha(normalized)
    release['moduleControl'].update(helperSha256=sha(helper), helperNormalizedSha256=sha(normalized),
        helperBuildId=build_id.hex(), helperBytes=len(helper), archiveSha256=after['file_sha256'])
    for repair in release['repairs']:
        if repair['memberOrdinal'] == 52: repair['sha256'] = diff['changed'][0]['candidateSha256']
    release['memberDiff'].update(path=diff_file.relative_to(ROOT).as_posix(), sha256=sha(diff_file.read_bytes()),
        changed=len(full['changed']), added=len(full['added']), removed=len(full['removed']))
    backend = out / 'backend' / new_identity['fileName']
    backend.parent.mkdir()
    backend.write_bytes(a.backend.read_bytes())
    release['environmentPolicyBoot'].update(backend=dict(new_identity, path=backend.relative_to(ROOT).as_posix()),
        entryHelperSha256=sha(helper), identityMatched=True, complete=False, deviceAcceptance=False)
    if 'requestContextRepair' in release:
        release['requestContextRepair'].update(deliveredArchiveSha256=after['file_sha256'],
            deliveredHelperSha256=sha(helper), policyBackendSha256=new_identity['sha256'],
            policyBackendUsesRepairedSdk=True)
    if 'credentialSnapshotRepair' in release:
        release['credentialSnapshotRepair'].update(deliveredArchiveSha256=after['file_sha256'],
            deliveredHelperSha256=sha(helper), policyBackendSha256=new_identity['sha256'])
    (out / 'SDK-RELEASE.json').write_text(json.dumps(release, indent=2) + '\n')
    # Keep the existing startup replay's exact entry addresses for regression.
    entry.update(helperSha256=sha(helper), helperNormalizedSha256=sha(normalized), helperBuildId=build_id.hex(),
                 helperBytes=len(helper), backend=dict(new_identity, path=str(backend)))
    (out / 'build.json').write_text(json.dumps(entry, indent=2) + '\n')
    record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), passed=True, memberDiff=diff,
        previousSdkSha256=sha(base), sdkSha256=after['file_sha256'], backendSha256=new_identity['sha256'],
        baselineExtensionReproduced=True, helperLayoutUnchanged=True, legacyAbiPreserved=True,
        priorRepairsPreserved=True, keySlotPreserved=True, deviceAccess=False)
    (out / 'verification.json').write_text(json.dumps(record, indent=2) + '\n')
    assert archive.read_bytes() == base and (source / 'SDK-RELEASE.json').read_bytes() == manifest_bytes
    print(json.dumps({k:v for k,v in record.items() if k != 'memberDiff'}, indent=2))


if __name__ == '__main__':
    main()
