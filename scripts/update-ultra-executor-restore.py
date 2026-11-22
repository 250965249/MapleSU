"""Restore securebits through the current request's reply slot in both SDK copies."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import runpy
import struct
import subprocess

from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import compare_members, parse_ar

ROOT = Path(__file__).resolve().parents[1]
EXEC = '_ZN13kernel_moduleL22__exec_kernel_asm_funcEPKhjRm'
sha = lambda data: hashlib.sha256(data).hexdigest()


def patch_executor(ir):
    start = ir.index('51:                                               ; preds = %49\n')
    end = ir.index('\n191: ', start)
    ir = ir[:start] + '''51:
  %52 = icmp eq i64 %50, 0
  br i1 %52, label %restore, label %187
53:
  %54 = landingpad { ptr, i32 } cleanup
  br label %189
55:
  %56 = landingpad { ptr, i32 } cleanup
  br label %189
restore:
  %restored = invoke i64 @maplesu_restore_securebits(i32 %48)
          to label %restored.done unwind label %55
restored.done:
  br label %187
187:
  %188 = phi i64 [ %50, %51 ], [ %restored, %restored.done ]
  call void @llvm.lifetime.end.p0(i64 4, ptr nonnull %17)
  call void @_ZN13kernel_module13SuidSgidGuardD2Ev(ptr %16)
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %16)
  br label %191
189:
  %190 = phi { ptr, i32 } [ %54, %53 ], [ %56, %55 ]
  call void @llvm.lifetime.end.p0(i64 4, ptr nonnull %17)
  call void @_ZN13kernel_module13SuidSgidGuardD2Ev(ptr %16)
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %16)
  resume { ptr, i32 } %190
''' + ir[end:]
    fn = ir.index('define hidden noundef i64 @_ZN13kernel_module32execute_kernel_asm_func_with_buf')
    tail = ir.index('\n}', fn) + 2
    body = re.sub(r'%(\d+)\b', r'%v\1', ir[fn:tail])
    body = re.sub(r'^(\d+):', r'v\1:', body, flags=re.M)
    body = body.replace(' {\n', ' {\nv3:\n', 1)
    ir = ir[:fn] + body + ir[tail:]
    return ir + f'''
declare hidden i64 @maplesu_restore_securebits(i32)
define hidden i64 @maplesu_raw_execute(ptr %code, i32 %size, ptr %out) {{
  %result = call fastcc i64 @{EXEC}(ptr %code, i32 %size, ptr %out)
  ret i64 %result
}}
'''


def unwind_entries(data, address):
    assert data[:4] == bytes.fromhex('011b033b')
    count = struct.unpack_from('<I', data, 8)[0]
    assert len(data) == 12 + count * 8
    return [(address + pc, address + fde) for pc, fde in struct.iter_unpack('<ii', data[12:])]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ndk', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / 'runtime/maplesu-sdk/SDK-RELEASE.json').read_text())
    archive = ROOT / manifest['archive']['path']
    data = archive.read_bytes()
    assert sha(data) == manifest['archive']['sha256']
    before = parse_ar(str(archive))
    tool = a.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'

    def run(name, *args):
        r = subprocess.run([str(tool / (name + '.exe')), *map(str, args)], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr

    flags = ['--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c']
    original = ROOT / 'work/panic-root-cause-20261105/sdk-members/m025.ll'
    ir = runpy.run_path(str(ROOT / 'scripts/repair-ultra-panic-sdk.py'))['patch_executor'](original.read_text())
    ir = re.sub(r'^\^.*\n?', '', ir, flags=re.M)
    baseline = out / 'm025.baseline.ll'
    baseline.write_text(ir)
    run('clang', *flags, baseline, '-o', out / 'baseline.o')
    m = before['members'][25]
    assert sha((out / 'baseline.o').read_bytes()) == m['sha256'], 'Executor baseline drift'
    patched = out / 'm025.patched.ll'
    patched.write_text(patch_executor(ir))
    source = ROOT / 'runtime/ultra/authorization/executor_restore.cpp'
    run('clang', *flags, patched, '-o', out / 'executor.o')
    run('clang++', *flags, '-std=c++17', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
        '-fno-exceptions', '-fno-rtti', '-funwind-tables', source, '-o', out / 'restore.o')
    run('ld.lld', '-r', out / 'executor.o', out / 'restore.o', '-o', out / m['name'])
    helper = (ROOT / manifest['helper']['path']).read_bytes()
    assert sha(helper) == manifest['helper']['sha256']
    image = ELFFile(io.BytesIO(helper))
    rxid, rx = max(((i, s) for i, s in enumerate(image.iter_segments()) if s['p_type'] == 'PT_LOAD'),
                   key=lambda row: row[1]['p_vaddr'])
    start = (rx['p_vaddr'] + max(rx['p_memsz'], len(helper) - rx['p_offset']) + 15) & ~15
    entry = 0xc5b78
    at = next(s['p_offset'] + entry - s['p_vaddr'] for s in image.iter_segments()
              if s['p_type'] == 'PT_LOAD' and s['p_vaddr'] <= entry < s['p_vaddr'] + s['p_filesz'])
    # Preserve the original main frame, guard and error epilogues. Skip the old
    # pointer-query callback and four byte-wise writes into the previous cred.
    (out / 'entry.S').write_text('.section .patch,"ax"\nldr w0, [sp, #12]\n'
        'bl maplesu_restore_securebits\nmov x19, x0\nb original_restore_return\n')
    run('clang', '--target=aarch64-linux-android21', '-c', out / 'entry.S', '-o', out / 'entry.o')
    (out / 'helper.ld').write_text(f'SECTIONS {{ .patch {entry:#x} : {{ *(.patch) }} '
        f'. = {start:#x}; .extension : {{ *(.text*) *(.rodata*) }} '
        '.eh_frame_hdr : { *(.eh_frame_hdr) } .eh_frame : { KEEP(*(.eh_frame)) } '
        '/DISCARD/ : { *(.comment) *(.note*) } }')
    run('ld.lld', '-T', out / 'helper.ld', '--eh-frame-hdr', '--entry=maplesu_restore_securebits',
        '--defsym=maplesu_raw_execute=0xc5dd8', '--defsym=original_restore_return=0xc5ce8',
        out / 'entry.o', out / 'restore.o', '-o', out / 'extension.elf')
    linked = ELFFile(io.BytesIO((out / 'extension.elf').read_bytes()))
    assert not any(s['sh_type'] in ('SHT_REL', 'SHT_RELA') and s['sh_size'] for s in linked.iter_sections())
    result = bytearray(helper)
    branch = linked.get_section_by_name('.patch').data()
    assert len(branch) == 16 and helper[at:at + 4] == bytes.fromhex('00e4006f')
    result[at:at + 16] = branch
    for section in linked.iter_sections():
        if not section['sh_flags'] & 2 or not section['sh_size'] or section.name == '.patch':
            continue
        assert section.name in ('.extension', '.eh_frame', '.eh_frame_hdr')
        position = rx['p_offset'] + section['sh_addr'] - rx['p_vaddr']
        assert position >= len(helper)
        result.extend(bytes(max(0, position + section['sh_size'] - len(result))))
        result[position:position + section['sh_size']] = section.data()
    ehid, old_header = next((i, s) for i, s in enumerate(image.iter_segments()) if s['p_type'] == 'PT_GNU_EH_FRAME')
    eh = linked.get_section_by_name('.eh_frame_hdr')
    entries = sorted(unwind_entries(old_header.data(), old_header['p_vaddr']) + unwind_entries(eh.data(), eh['sh_addr']))
    assert len(set(pc for pc, _ in entries)) == len(entries)
    header_va = (rx['p_vaddr'] + len(result) - rx['p_offset'] + 3) & ~3
    frame_va = old_header['p_vaddr'] + 4 + struct.unpack_from('<i', old_header.data(), 4)[0]
    header = bytes.fromhex('011b033b') + struct.pack('<iI', frame_va - header_va - 4, len(entries))
    header += b''.join(struct.pack('<ii', pc - header_va, fde - header_va) for pc, fde in entries)
    header_at = rx['p_offset'] + header_va - rx['p_vaddr']
    result.extend(bytes(header_at - len(result)) + header)
    result.extend(bytes((-len(result)) % 8))
    struct.pack_into('<QQ', result, image['e_phoff'] + rxid * image['e_phentsize'] + 32,
                     len(result) - rx['p_offset'], len(result) - rx['p_offset'])
    struct.pack_into('<QQQQQ', result, image['e_phoff'] + ehid * image['e_phentsize'] + 8,
                     header_at, header_va, header_va, len(header), len(header))
    note = image.get_section_by_name('.note.gnu.build-id')['sh_offset'] + 16
    result[note:note + 20] = bytes(20)
    normalized = bytearray(result)
    slot = manifest['helper']['keySlotOffset']
    normalized[slot:slot + 4096] = bytes(4096)
    build_id = hashlib.sha1(normalized).digest()
    result[note:note + 20] = normalized[note:note + 20] = build_id
    allowed = [(at, at + 16), (image['e_phoff'] + rxid * image['e_phentsize'] + 32,
               image['e_phoff'] + rxid * image['e_phentsize'] + 48),
               (image['e_phoff'] + ehid * image['e_phentsize'] + 8,
                image['e_phoff'] + ehid * image['e_phentsize'] + 48), (note, note + 20)]
    assert all(x == y or any(lo <= i < hi for lo, hi in allowed)
               for i, (x, y) in enumerate(zip(helper, result)))
    (out / 'autorun_bootstrap').write_bytes(result)
    candidate = out / archive.name
    candidate.write_bytes(data)
    run('llvm-ar', 'rD', candidate, out / m['name'])
    upgrade = runpy.run_path(str(ROOT / 'scripts/repair-ultra-environment-upgrade.py'))
    frozen = ROOT / 'runtime/ultra/upgrade/sdk-m052.bc'
    run('clang', '--target=aarch64-linux-android21', '-S', '-emit-llvm', '-x', 'ir', frozen,
        '-o', out / 'm052.input.ll')
    installer_ir = upgrade['patch_stream']((out / 'm052.input.ll').read_text(),
        '_ZN7maplesu3sdk32unsafe_install_autorun_bootstrapEv', 131, 148, 151, 10, 1215088,
        78, 145, 144, (147, 146), 'u:object_r:kernel:s0')
    installer_ir = upgrade['keep_bootstrap_until_publish'](installer_ir).replace('5.1.0', manifest['sdkVersion'])
    payload = re.compile(r'^(@_ZN7maplesu3sdkL27autorun_bootstrap_file_dataE = internal global )[^\n]+, align 8$', re.M)

    def installer(blob, label):
        text = payload.sub(lambda m: m[1] + f'[{len(blob)} x i8] c"' +
                           ''.join('\\%02X' % b for b in blob) + '", align 8', installer_ir)
        text = re.sub(r'\b1215088\b', str(len(blob)), text)
        path = out / (label + '.ll')
        path.write_text(text)
        obj = out / (label + '.o')
        run('clang', *flags, path, '-o', obj)
        return obj

    old_member = before['members'][52]
    old_object = data[old_member['body_offset']:old_member['body_offset'] + old_member['size']]
    assert upgrade['object_contract'](installer(helper, 'installer.baseline').read_bytes()) == upgrade['object_contract'](old_object)
    new_installer = installer(result, 'installer.candidate')
    installer_object = out / old_member['name']
    installer_object.write_bytes(new_installer.read_bytes())
    # The SDK module gate also pins the final RX program header.
    gate = manifest['moduleControl']
    gate_at, size = gate['gateFileOffset'], gate['gateBytes']
    ph = image['e_phoff'] + rxid * image['e_phentsize']

    def control(blob, label):
        directory = out / label
        directory.mkdir(exist_ok=True)
        header = (f'#pragma once\n#define MAPLESU_GATE_FILE_OFFSET {gate_at}\n'
                  f'#define MAPLESU_GATE_BRANCH_OFFSET {0xa6d68}\n#define MAPLESU_GATE_PHDR_OFFSET {ph}\n')
        for name, value in [('bytes', blob[gate_at:gate_at + size]),
                            ('branch', blob[0xa6d68:0xa6d6c]), ('phdr', blob[ph:ph + 56])]:
            header += 'static constexpr unsigned char maplesu_gate_' + name + '[] = {' + ','.join(map(str, value)) + '};\n'
        (directory / 'module_gate_identity.h').write_text(header)
        obj = directory / 'maplesu_module_control.o'
        run('clang++', *flags, '-std=c++17', '-fexceptions', '-ffunction-sections', '-fdata-sections',
            '-I', ROOT / 'runtime/maplesu-sdk/include', '-I', directory,
            ROOT / 'runtime/ultra/modules/module_control.cpp', '-o', obj)
        return obj

    old_gate = before['members'][255]
    assert upgrade['object_contract'](control(helper, 'baseline-gate').read_bytes()) == upgrade['object_contract'](
        data[old_gate['body_offset']:old_gate['body_offset'] + old_gate['size']])
    new_gate = control(result, 'candidate-gate')
    run('llvm-ar', 'rD', candidate, installer_object, new_gate)
    run('llvm-ar', 'sD', candidate)
    difference = compare_members(before, parse_ar(str(candidate)))
    assert [m['ord'] for m in difference['changed']] == [25, 52, 255]
    report = dict(baselineArchiveSha256=sha(data), archiveSha256=sha(candidate.read_bytes()),
        baselineHelperSha256=sha(helper), helperSha256=sha(result), helperNormalizedSha256=sha(normalized),
        helperBuildId=build_id.hex(), helperBytes=len(result), memberDiff=difference,
        helperEntry=dict(offset=at, before=helper[at:at + 16].hex(), after=branch.hex()),
        sources={p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in (source, Path(__file__).resolve())},
        deviceAcceptance=False)
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS paired executor candidates built; no credential address crosses request boundaries')


if __name__ == '__main__':
    main()
