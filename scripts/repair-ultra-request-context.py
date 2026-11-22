"""Give the SDK and embedded bootstrap private saved-ID reply credentials."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import runpy
import shutil
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import compare_members, parse_ar

ROOT = Path(__file__).resolve().parents[1]
SEND = '_ZN13kernel_moduleL19send_kernel_requestENS_13KernelCmdFlagEhmjjPm'
sha = lambda data: hashlib.sha256(data).hexdigest()


def isolate_request(ir):
    signature = 'define internal fastcc noundef i64 @' + SEND + '('
    assert ir.count(signature) == 1
    ir = ir.replace(signature, signature.replace(SEND, SEND + '.raw'), 1)
    # The new errors also flow through the allocator/read/exec wrappers. Old
    # optimizer ranges described only the legacy transport's possible results.
    ir = re.sub(r', !range !\d+', '', ir)
    return ir + f'''
declare hidden i64 @maplesu_prepare_kernel_request() nounwind
define internal fastcc i64 @{SEND}(i8 %flag, i8 %byte, i64 %address, i32 %size, i32 %pages, ptr %out) uwtable {{
  %status = call i64 @maplesu_prepare_kernel_request()
  %ready = icmp eq i64 %status, 0
  br i1 %ready, label %send, label %failed
send:
  %result = call fastcc i64 @{SEND}.raw(i8 %flag, i8 %byte, i64 %address, i32 %size, i32 %pages, ptr %out)
  ret i64 %result
failed:
  ret i64 %status
}}
'''


def unwind_entries(data, address):
    assert data[:4] == bytes.fromhex('011b033b')
    count = struct.unpack_from('<I', data, 8)[0]
    assert len(data) == 12 + count * 8
    return [(address + pc, address + fde) for pc, fde in struct.iter_unpack('<ii', data[12:])]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--ndk', required=True, type=Path)
    p.add_argument('--source', type=Path, default=ROOT / 'runtime/maplesu-sdk')
    a = p.parse_args()
    sdk, out = a.source.resolve(), a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((sdk / 'SDK-RELEASE.json').read_text())
    base = a.archive.read_bytes()
    assert sha(base) == manifest['archive']['sha256'], 'SDK manifest/archive mismatch'
    assert 'requestContextRepair' not in manifest, 'Request context is already installed'
    before = parse_ar(str(a.archive))
    tool = a.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'
    upgrade = runpy.run_path(str(ROOT / 'scripts/repair-ultra-environment-upgrade.py'))
    contract = upgrade['object_contract']

    def run(name, *args):
        r = subprocess.run([str(tool / (name + '.exe')), *map(str, args)], capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(r.stdout + r.stderr)

    def member(ordinal):
        m = before['members'][ordinal]
        return m, base[m['body_offset']:m['body_offset'] + m['size']]

    target = '--target=aarch64-linux-android21'
    headers = ROOT / 'runtime/maplesu-sdk/include'
    context = ROOT / 'runtime/ultra/authorization/request_context.cpp'
    context_obj = out / 'request-context.o'
    run('clang++', target, '-std=c++17', '-Oz', '-fPIC', '-fno-stack-protector',
        '-fno-exceptions', '-fno-rtti', '-funwind-tables', '-Wall', '-Wextra', '-Werror',
        '-I', headers, '-c', context, '-o', context_obj)

    request_member, old_request = member(23)
    ll = out / 'm023.input.ll'
    run('clang', target, '-S', '-emit-llvm', '-x', 'ir', ROOT / 'runtime/ultra/panic/sdk-m023-r13.bc', '-o', ll)
    ir = runpy.run_path(str(ROOT / 'scripts/repair-ultra-request-reply.py'))['patch_request'](ll.read_text())
    baseline_ir = out / 'm023.baseline.ll'
    baseline_ir.write_text(ir)
    baseline_obj = out / 'm023.baseline.o'
    run('clang', target, '-Oz', '-fPIC', '-c', baseline_ir, '-o', baseline_obj)
    assert baseline_obj.read_bytes() == old_request, 'Request IR does not reproduce the installed SDK'
    request_ir = out / 'm023.patched.ll'
    request_ir.write_text(isolate_request(ir))
    request_obj = out / 'request.o'
    run('clang', target, '-Oz', '-fPIC', '-c', request_ir, '-o', request_obj)
    request = out / request_member['name']
    run('ld.lld', '-r', request_obj, context_obj, '-o', request)
    assert set(contract(old_request)[1]) <= set(contract(request.read_bytes())[1]), 'Existing SDK ABI drift'

    installer_member, old_installer = member(52)
    old_helper = ELFFile(io.BytesIO(old_installer)).get_section_by_name('.data').data()
    assert sha(old_helper) == manifest['helper']['sha256']
    he = ELFFile(io.BytesIO(old_helper))
    loads = [(i, s) for i, s in enumerate(he.iter_segments()) if s['p_type'] == 'PT_LOAD']
    index, tail = max(loads, key=lambda item: item[1]['p_vaddr'])
    assert tail['p_flags'] == 5
    va = (tail['p_vaddr'] + max(tail['p_memsz'], len(old_helper) - tail['p_offset']) + 15) & ~15
    entry_source = (ROOT / 'runtime/ultra/authorization/bootstrap_request.S').read_text(encoding='utf-8-sig')
    point = ' // ADR x8, 0x11fa88 (same key storage as the original helper).'
    assert entry_source.count(point) == 1
    entry_source = entry_source.replace(point, ' bl maplesu_prepare_kernel_request\n cbnz x0, 6f\n' + point)
    (out / 'request-entry.S').write_text(entry_source)
    run('clang', target, '-c', out / 'request-entry.S', '-o', out / 'request-entry.o')
    linker = out / 'request-context.ld'
    linker.write_text(f'''SECTIONS {{
 .request 0xc4598 : {{ *request-entry.o(.text) }}
 . = {hex(va)};
 .extension : {{ *(.text*) *(.rodata*) }}
 .eh_frame_hdr : {{ *(.eh_frame_hdr) }}
 .eh_frame : {{ KEEP(*(.eh_frame)) }}
 /DISCARD/ : {{ *(.comment) *(.note*) }}
}}
''')
    definitions = dict(ROOT_KEY=0x11fa88, SYSCALL=0x112fc0, syscall=0x112fc0,
                       GET_SUID=0xc4560, GET_SGID=0xc457c, EXECUTOR_RETURN=0xc5e60)
    linked = out / 'helper-context.elf'
    run('ld.lld', '-T', linker, '--eh-frame-hdr', '--entry=maplesu_bootstrap_request',
        *[f'--defsym={k}={hex(v)}' for k, v in definitions.items()],
        out / 'request-entry.o', context_obj, '-o', linked)
    le = ELFFile(io.BytesIO(linked.read_bytes()))
    assert not [s for s in le.iter_sections() if s['sh_type'] in ('SHT_REL', 'SHT_RELA') and s['sh_size']]
    replacement = le.get_section_by_name('.request').data()
    assert len(replacement) == 336 and replacement[304:] == old_helper[0xc46c8:0xc46e8]
    at = tail['p_offset'] + va - tail['p_vaddr']
    helper = bytearray(old_helper + bytes(at - len(old_helper)))
    extension_sections = [le.get_section_by_name(n) for n in ('.extension', '.eh_frame_hdr', '.eh_frame')]
    for section in extension_sections:
        offset = at + section['sh_addr'] - va
        helper.extend(bytes(offset - len(helper)))
        helper.extend(section.data())
    helper[0xc4598:0xc46c8] = replacement[:304]
    old_header_index, old_header = next((i, s) for i, s in enumerate(he.iter_segments()) if s['p_type'] == 'PT_GNU_EH_FRAME')
    new_header = le.get_section_by_name('.eh_frame_hdr')
    entries = sorted(unwind_entries(old_header.data(), old_header['p_vaddr']) +
                     unwind_entries(new_header.data(), new_header['sh_addr']))
    assert len({pc for pc, fde in entries}) == len(entries)
    header_at = (tail['p_vaddr'] + len(helper) - tail['p_offset'] + 3) & ~3
    frame_at = old_header['p_vaddr'] + 4 + struct.unpack_from('<i', old_header.data(), 4)[0]
    header = bytes.fromhex('011b033b') + struct.pack('<iI', frame_at - header_at - 4, len(entries))
    header += b''.join(struct.pack('<ii', pc - header_at, fde - header_at) for pc, fde in entries)
    header_offset = tail['p_offset'] + header_at - tail['p_vaddr']
    helper.extend(bytes(header_offset - len(helper)))
    helper.extend(header)
    helper.extend(bytes((-len(helper)) % 8))
    ph = he['e_phoff'] + index * he['e_phentsize']
    length = len(helper) - tail['p_offset']
    struct.pack_into('<QQ', helper, ph + 32, length, length)
    eh_ph = he['e_phoff'] + old_header_index * he['e_phentsize']
    struct.pack_into('<QQQQQ', helper, eh_ph + 8, header_offset, header_at, header_at, len(header), len(header))
    note = he.get_section_by_name('.note.gnu.build-id')['sh_offset'] + 16
    helper[note:note + 20] = bytes(20)
    normalized = bytearray(helper)
    slot = manifest['helper']['keySlotOffset']
    normalized[slot:slot + 4096] = bytes(4096)
    build_id = hashlib.sha1(normalized).digest()
    helper[note:note + 20] = normalized[note:note + 20] = build_id
    allowed = [(0xc4598, 0xc46c8), (ph + 32, ph + 48), (eh_ph + 8, eh_ph + 48), (note, note + 20)]
    assert all(x == y or any(lo <= i < hi for lo, hi in allowed) for i, (x, y) in enumerate(zip(old_helper, helper)))
    assert helper[slot:slot + 4096] == old_helper[slot:slot + 4096]
    for name in ('.eh_frame', '.dynamic', '.rela.dyn', '.rela.plt', '.dynsym'):
        assert ELFFile(io.BytesIO(helper)).get_section_by_name(name).data() == he.get_section_by_name(name).data()
    (out / 'embedded-bootstrap.elf').write_bytes(helper)

    ll = out / 'm052.input.ll'
    run('clang', target, '-S', '-emit-llvm', '-x', 'ir', ROOT / 'runtime/ultra/upgrade/sdk-m052.bc', '-o', ll)
    ir = upgrade['patch_stream'](ll.read_text(), '_ZN7maplesu3sdk32unsafe_install_autorun_bootstrapEv',
        131, 148, 151, 10, 1215088, 78, 145, 144, (147, 146), 'u:object_r:kernel:s0')
    ir = upgrade['keep_bootstrap_until_publish'](ir).replace('5.1.0', manifest['sdkVersion'])
    payload = re.compile(r'^(@_ZN7maplesu3sdkL27autorun_bootstrap_file_dataE = internal global )[^\n]+, align 8$', re.M)

    def installer_ir(blob):
        encoded = ''.join('\\%02X' % byte for byte in blob)
        updated = payload.sub(lambda m: m[1] + f'[{len(blob)} x i8] c"' + encoded + '", align 8', ir)
        return re.sub(r'\b1215088\b', str(len(blob)), updated)

    ll.write_text(installer_ir(old_helper))
    run('clang', target, '-Oz', '-fPIC', '-c', ll, '-o', out / 'm052.baseline.o')
    assert contract((out / 'm052.baseline.o').read_bytes()) == contract(old_installer), 'Installer code/ABI drift'
    ll.write_text(installer_ir(helper))
    installer = out / installer_member['name']
    run('clang', target, '-Oz', '-fPIC', '-c', ll, '-o', installer)
    gate = manifest['moduleControl']
    header_text = '#pragma once\n' + f'#define MAPLESU_GATE_FILE_OFFSET {gate["gateFileOffset"]}\n#define MAPLESU_GATE_BRANCH_OFFSET {0xa6d68}\n#define MAPLESU_GATE_PHDR_OFFSET {ph}\n'
    for name, blob in [('bytes', helper[gate['gateFileOffset']:gate['gateFileOffset'] + gate['gateBytes']]),
                       ('branch', helper[0xa6d68:0xa6d6c]), ('phdr', helper[ph:ph + 56])]:
        header_text += 'static constexpr unsigned char maplesu_gate_' + name + '[] = {' + ','.join(map(str, blob)) + '};\n'
    (out / 'module_gate_identity.h').write_text(header_text)
    control = out / 'maplesu_module_control.o'
    run('clang++', target, '-std=c++17', '-Oz', '-fPIC', '-fexceptions', '-ffunction-sections', '-fdata-sections',
        '-I', headers, '-I', out, '-c', ROOT / 'runtime/ultra/modules/module_control.cpp', '-o', control)
    assert contract(control.read_bytes())[1] == contract(member(255)[1])[1]
    archive = out / a.archive.name
    assert archive.resolve() != a.archive.resolve()
    archive.write_bytes(base)
    run('llvm-ar', 'rD', archive, request, installer, control)
    run('llvm-ar', 'sD', archive)
    after = parse_ar(str(archive))
    diff = compare_members(before, after)
    assert [m['ord'] for m in diff['changed']] == [23, 52, 255]
    assert not diff['added'] and not diff['removed'] and not diff['orderErrors']
    report = dict(baselineArchiveSha256=sha(base), archiveSha256=sha(archive.read_bytes()), memberDiff=diff,
        helperSha256=sha(helper), helperNormalizedSha256=sha(normalized), helperBuildId=build_id.hex(),
        helperBytes=len(helper), credentialIsolation='raw capget/capset before every kernel request, including after fork',
        inheritedCapabilitiesUnchanged=True, requestBaselineReproduced=True, installerBaselineReproduced=True,
        legacyRequestAbiPreserved=True, previousUnwindEntriesPreserved=len(entries) - len(unwind_entries(new_header.data(), new_header['sh_addr'])),
        newUnwindEntries=len(unwind_entries(new_header.data(), new_header['sh_addr'])), deviceVerification=False,
        sources={str(path.relative_to(ROOT)).replace('\\', '/'): sha(path.read_bytes()) for path in
                 [context, Path(__file__), ROOT / 'runtime/ultra/authorization/bootstrap_request.S',
                  ROOT / 'runtime/ultra/panic/sdk-m023-r13.bc', ROOT / 'runtime/ultra/upgrade/sdk-m052.bc',
                  ROOT / 'runtime/ultra/modules/module_control.cpp',
                  ROOT / 'scripts/repair-ultra-request-reply.py', ROOT / 'scripts/repair-ultra-environment-upgrade.py',
                  headers / 'module_err_def.h']})
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    # Stage the SDK so the policy backend can be relinked and paired before any
    # production inputs are replaced.
    candidate_sdk = out / 'sdk'
    candidate_archive = candidate_sdk / 'lib/arm64-v8a' / a.archive.name
    candidate_archive.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(archive, candidate_archive)
    original = parse_ar(str(ROOT / 'runtime/maplesu-sdk/maintenance/baseline/libkernel_module_kit_static.a'))
    n = original['member_count']
    full = compare_members(original, dict(after, members=after['members'][:n], member_count=n))
    full['added'] = [dict(ord=m['ord'], name=m['name'], candidateSha256=m['sha256']) for m in after['members'][n:]]
    diff_path = candidate_sdk / 'SU-AUTH-MEMBER-DIFF.json'
    diff_path.write_text(json.dumps(dict(schemaVersion=1, baselineArchiveSha256=original['file_sha256'],
        archiveSha256=report['archiveSha256'], totalMembers=after['member_count'], **full), indent=2) + '\n')
    manifest.update(sdkBuildId='maplesu-ultra-5.2.0-request-context-r24-20261110', generatedUtc=datetime.now(timezone.utc).isoformat())
    manifest['archive'].update(path=candidate_archive.relative_to(ROOT).as_posix(),
        sha256=report['archiveSha256'], size=archive.stat().st_size)
    for key in ('helper', 'bootstrap'):
        manifest[key].update(sha256=report['helperSha256'], buildId=report['helperBuildId'], size=len(helper), changed=True)
    manifest['helper']['normalizedSha256'] = report['helperNormalizedSha256']
    manifest['moduleControl'].update(archiveSha256=report['archiveSha256'], helperSha256=report['helperSha256'],
        helperNormalizedSha256=report['helperNormalizedSha256'], helperBuildId=report['helperBuildId'], helperBytes=len(helper))
    manifest['environmentPolicyBoot']['entryHelperSha256'] = report['helperSha256']
    manifest['requestContextRepair'] = report
    for row in diff['changed']:
        for repair in manifest['repairs']:
            if repair['memberOrdinal'] == row['ord']:
                repair['sha256'] = row['candidateSha256']
    manifest['memberDiff'].update(path=diff_path.relative_to(ROOT).as_posix(),
        sha256=sha(diff_path.read_bytes()), changed=len(full['changed']), added=len(full['added']), removed=len(full['removed']))
    candidate_manifest = candidate_sdk / 'SDK-RELEASE.json'
    candidate_manifest.write_text(json.dumps(manifest, indent=2) + '\n')
    subprocess.run([sys.executable, str(ROOT / 'scripts/sync-ultra-sdk-identity.py'),
        '--manifest', str(candidate_manifest), '--output', str(candidate_sdk / 'SDK-IDENTITY.cmake')], check=True)
    print(json.dumps({k: v for k, v in report.items() if k not in ('sources', 'memberDiff')}, indent=2))


if __name__ == '__main__':
    main()
