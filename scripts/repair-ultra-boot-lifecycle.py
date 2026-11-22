"""Repair the pinned r14 bootstrap completion; retain all earlier SDK repairs."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import parse_ar, compare_members

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk_upgrade', ROOT / 'scripts/repair-ultra-environment-upgrade.py')
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)
keep_bootstrap_until_publish, patch_stream, object_contract = upgrade.keep_bootstrap_until_publish, upgrade.patch_stream, upgrade.object_contract
BASE = 'c4795e8a3d221017119cda62baa6a19050eee86710a13bcf8970ab0e34df220d'
HELPER = 'bcfbf38b532fae7631c863ef1e7dfa9e8880f779e6a663363335fa7d03437c75'
sha = lambda data: hashlib.sha256(data).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--ndk', type=Path, required=True)
    p.add_argument('--install', action='store_true')
    a = p.parse_args()
    sdk, out = ROOT / 'runtime/maplesu-sdk', a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    data = a.archive.read_bytes()
    assert sha(data) == BASE, 'Use the frozen r14 archive; preserve other SDK work'
    if a.install:
        assert a.archive.resolve() == (sdk / 'lib/arm64-v8a/libkernel_module_kit_static.a').resolve()
    before = parse_ar(str(a.archive))
    m = before['members'][52]
    original = data[m['body_offset']:m['body_offset'] + m['size']]
    elf = ELFFile(io.BytesIO(original))
    old = elf.get_section_by_name('.data').data()
    assert sha(old) == HELPER
    he = ELFFile(io.BytesIO(old))
    index, tail = max(((i, s) for i, s in enumerate(he.iter_segments()) if s['p_type'] == 'PT_LOAD'),
                      key=lambda item: item[1]['p_vaddr'])
    assert tail['p_flags'] == 5
    va = (tail['p_vaddr'] + max(tail['p_memsz'], len(old) - tail['p_offset']) + 15) & ~15
    tool = a.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'

    def run(name, *argv):
        r = subprocess.run([str(tool / (name + '.exe')), *map(str, argv)], capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(r.stdout + r.stderr)

    sources = [ROOT / 'runtime/ultra/boot/bootstrap_finish.S', ROOT / 'runtime/ultra/boot/bootstrap_finish.c']
    common = ['--target=aarch64-linux-android21', '-Oz', '-ffreestanding', '-fno-builtin', '-fPIC',
              '-fno-stack-protector', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
              '-Wall', '-Wextra', '-Werror', '-c']
    objects = []
    for source in sources:
        obj = out / (source.name + '.o')
        run('clang', *common, source, '-o', obj)
        objects.append(obj)
    dyn, plt = he.get_section_by_name('.dynsym'), he.get_section_by_name('.plt')['sh_addr']
    definitions = {dyn.get_symbol(r['r_info_sym']).name: plt + 32 + i * 16
                   for i, r in enumerate(he.get_section_by_name('.rela.plt').iter_relocations())}
    definitions.update(original_bootstrap_exit=0xa9688, original_bootstrap_finish_continue=0xa95bc)
    script = out / 'finish.ld'
    script.write_text(f'SECTIONS {{ . = {hex(va)}; .extension : {{ *(.text*) *(.rodata*) }} '
                      '/DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) } }')
    linked = out / 'finish.elf'
    run('ld.lld', '-T', script, '--entry=maplesu_bootstrap_finish_entry',
        *[f'--defsym={name}={hex(value)}' for name, value in definitions.items()], *objects, '-o', linked)
    le = ELFFile(io.BytesIO(linked.read_bytes()))
    assert not [s for s in le.iter_sections() if s['sh_type'] in ('SHT_REL', 'SHT_RELA') and s['sh_size']]
    code = le.get_section_by_name('.extension').data()
    symbols = {s.name: s['st_value'] for s in le.get_section_by_name('.symtab').iter_symbols()}
    at = tail['p_offset'] + va - tail['p_vaddr']
    assert at >= len(old)
    helper = bytearray(old + bytes(at - len(old)) + code)
    helper.extend(bytes((-len(helper)) % 8))

    def branch(site, target, link=False):
        assert (target - site) % 4 == 0 and abs(target - site) < (1 << 27)
        return struct.pack('<I', (0x94000000 if link else 0x14000000) | (((target - site) // 4) & 0x3ffffff))

    assert old[0xa95b8:0xa95bc] == bytes.fromhex('e8430491')
    assert old[0xa9670:0xa9678] == bytes.fromhex('c4a5019400070034')
    helper[0xa95b8:0xa95bc] = branch(0xa95b8, symbols['maplesu_bootstrap_finish_entry'])
    # Completion no longer depends on a child living for 25 seconds after main exits.
    helper[0xa9670:0xa9674] = branch(0xa9670, 0xa55e4, link=True)
    helper[0xa9674:0xa9678] = bytes.fromhex('1f2003d5')
    ph = he['e_phoff'] + index * he['e_phentsize']
    length = len(helper) - tail['p_offset']
    struct.pack_into('<QQ', helper, ph + 32, length, length)
    note = he.get_section_by_name('.note.gnu.build-id')['sh_offset'] + 16
    helper[note:note + 20] = bytes(20)
    normalized = bytearray(helper)
    normalized[182886:182886 + 4096] = bytes(4096)
    build_id = hashlib.sha1(normalized).digest()
    helper[note:note + 20] = normalized[note:note + 20] = build_id
    allowed = [(0xa95b8, 0xa95bc), (0xa9670, 0xa9678), (ph + 32, ph + 48), (note, note + 20)]
    assert all(x == y or any(lo <= i < hi for lo, hi in allowed) for i, (x, y) in enumerate(zip(old, helper)))
    helper_path = out / 'embedded-bootstrap.elf'
    helper_path.write_bytes(helper)

    # Recreate the r13 atomic installer from its frozen IR, then replace only the
    # embedded helper and its size constants. Reproduction is checked against r14.
    source = ROOT / 'runtime/ultra/upgrade/sdk-m052.bc'
    assert sha(source.read_bytes()) == '342b920914ad62f700398482f8bfd403344e54cf36f032a77c51d0c1e306d3c2'
    ll = out / 'm052.input.ll'
    run('clang', '--target=aarch64-linux-android21', '-S', '-emit-llvm', '-x', 'ir', source, '-o', ll)
    ir = patch_stream(ll.read_text(), '_ZN7maplesu3sdk32unsafe_install_autorun_bootstrapEv',
                      131, 148, 151, 10, 1215088, 78, 145, 144, (147, 146), 'u:object_r:kernel:s0')
    ir = keep_bootstrap_until_publish(ir)
    payload = re.compile(r'^(@_ZN7maplesu3sdkL27autorun_bootstrap_file_dataE = internal global )[^\n]+, align 8$', re.M)
    assert len(payload.findall(ir)) == 1

    def installer_ir(blob):
        encoded = ''.join('\\%02X' % c for c in blob)
        updated = payload.sub(lambda match: match[1] + f'[{len(blob)} x i8] c"' + encoded + '", align 8', ir)
        return re.sub(r'\b1215088\b', str(len(blob)), updated)

    baseline_ir, baseline_obj = out / 'm052.baseline.ll', out / 'm052.baseline.o'
    baseline_ir.write_text(installer_ir(old))
    run('clang', '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', baseline_ir, '-o', baseline_obj)
    assert object_contract(baseline_obj.read_bytes()) == object_contract(original), 'r14 installer code/ABI drift'
    updated_ir, installer = out / 'm052.patched.ll', out / m['name']
    updated_ir.write_text(installer_ir(helper))
    run('clang', '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', updated_ir, '-o', installer)
    assert ELFFile(io.BytesIO(installer.read_bytes())).get_section_by_name('.data').data() == helper
    assert object_contract(installer.read_bytes())[1] == object_contract(original)[1]

    gate = json.loads((sdk / 'SDK-RELEASE.json').read_text())['moduleControl']
    gate_at, gate_size = gate['gateFileOffset'], gate['gateBytes']
    header = '#pragma once\n' + f'#define MAPLESU_GATE_FILE_OFFSET {gate_at}\n#define MAPLESU_GATE_BRANCH_OFFSET {0xa6d68}\n#define MAPLESU_GATE_PHDR_OFFSET {ph}\n'
    for name, b in [('bytes', helper[gate_at:gate_at + gate_size]), ('branch', helper[0xa6d68:0xa6d6c]), ('phdr', helper[ph:ph + 56])]:
        header += 'static constexpr unsigned char maplesu_gate_' + name + '[] = {' + ','.join(map(str, b)) + '};\n'
    (out / 'module_gate_identity.h').write_text(header)
    control = out / 'maplesu_module_control.o'
    run('clang++', '--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fexceptions',
        '-ffunction-sections', '-fdata-sections', '-I', sdk / 'include', '-I', out,
        '-c', ROOT / 'runtime/ultra/modules/module_control.cpp', '-o', control)
    cm = before['members'][255]
    assert object_contract(control.read_bytes())[1] == object_contract(data[cm['body_offset']:cm['body_offset'] + cm['size']])[1]
    candidate = out / a.archive.name
    assert candidate.resolve() != a.archive.resolve()
    candidate.write_bytes(data)
    run('llvm-ar', 'rD', candidate, installer, control)
    run('llvm-ar', 'sD', candidate)
    after = parse_ar(str(candidate))
    diff = compare_members(before, after)
    assert [row['ord'] for row in diff['changed']] == [52, 255]
    assert not diff['added'] and not diff['removed'] and not diff['orderErrors']
    report = dict(baselineArchiveSha256=BASE, archiveSha256=sha(candidate.read_bytes()), memberDiff=diff,
        helperSha256=sha(helper), helperNormalizedSha256=sha(normalized), helperBuildId=build_id.hex(), helperBytes=len(helper),
        extensionAddress=va, extensionBytes=len(code), finishEntry=symbols['maplesu_bootstrap_finish_entry'],
        finishFunction=symbols['maplesu_bootstrap_finish'], abiPreserved=True, installerBaselineReproduced=True,
        protectionBranchUnchanged=True, duplicateGuardUnchanged=True, previousRepairsPreserved=True,
        completion='Commit checked one-byte success synchronously before publishing Running; no delayed child',
        deviceVerification=False, sources={str(s.relative_to(ROOT)).replace('\\', '/'): sha(s.read_bytes())
            for s in [*sources, source, Path(__file__).resolve()]})
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    if a.install:
        manifest_path = sdk / 'SDK-RELEASE.json'
        manifest = json.loads(manifest_path.read_text())
        assert manifest['archive']['sha256'] == sha(a.archive.read_bytes()) == BASE
        backup = out / 'before'
        backup.mkdir(exist_ok=True)
        for s in [a.archive, manifest_path, sdk / 'SDK-IDENTITY.cmake', sdk / 'SU-AUTH-MEMBER-DIFF.json']:
            shutil.copy2(s, backup / s.name)
        baseline = parse_ar(str(ROOT / 'runtime/maplesu-sdk/maintenance/baseline/libkernel_module_kit_static.a'))
        n = baseline['member_count']
        full = compare_members(baseline, dict(after, members=after['members'][:n], member_count=n))
        full['added'] = [dict(ord=s['ord'], name=s['name'], candidateSha256=s['sha256']) for s in after['members'][n:]]
        diff_path = sdk / 'SU-AUTH-MEMBER-DIFF.json'
        diff_path.write_text(json.dumps(dict(schemaVersion=1, baselineArchiveSha256=baseline['file_sha256'],
            archiveSha256=report['archiveSha256'], totalMembers=after['member_count'], **full), indent=2) + '\n')
        manifest['sdkBuildId'] = 'maplesu-ultra-5.1.0-boot-lifecycle-r15-20261108'
        manifest['generatedUtc'] = datetime.now(timezone.utc).isoformat()
        manifest['archive'].update(sha256=report['archiveSha256'], size=candidate.stat().st_size)
        for name in ['helper', 'bootstrap']:
            manifest[name].update(sha256=report['helperSha256'], buildId=report['helperBuildId'], size=len(helper), changed=True)
        manifest['helper']['normalizedSha256'] = report['helperNormalizedSha256']
        manifest['moduleControl'].update(helperSha256=report['helperSha256'], helperNormalizedSha256=report['helperNormalizedSha256'],
            helperBuildId=report['helperBuildId'], helperBytes=len(helper), archiveSha256=report['archiveSha256'])
        manifest['bootLifecycleRepair'] = report
        manifest['statement'] = 'SDK r15: bootstrap success is durable before exit and Running publication; initialization failures retain protection. r14 request validation, r13 atomic installation, module gate, identity, authorization and prior Panic repairs preserved. Device acceptance pending.'
        for row in diff['changed']:
            for repair in manifest['repairs']:
                if repair['memberOrdinal'] == row['ord']:
                    repair['sha256'] = row['candidateSha256']
        manifest['memberDiff'].update(sha256=sha(diff_path.read_bytes()), changed=len(full['changed']), added=len(full['added']), removed=len(full['removed']))
        shutil.copy2(candidate, a.archive)
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
        subprocess.run([sys.executable, str(ROOT / 'scripts/sync-ultra-sdk-identity.py')], check=True)
    print(json.dumps({k: v for k, v in report.items() if k not in ('memberDiff', 'sources')}, indent=2))


if __name__ == '__main__':
    main()
