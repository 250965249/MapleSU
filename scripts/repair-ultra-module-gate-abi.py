"""Rebuild the ARM64 module gate while preserving the paired r9 Panic repairs."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import parse_ar, compare_members

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--ndk', type=Path, required=True)
p.add_argument('--install', action='store_true')
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
sdk = root / 'runtime/maplesu-sdk'
out = a.out.resolve()
out.mkdir(parents=True, exist_ok=True)
tool = a.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'
sha = lambda b: hashlib.sha256(b).hexdigest()
manifest = json.loads((sdk / 'SDK-RELEASE.json').read_text())
archive = sdk / 'lib/arm64-v8a/libkernel_module_kit_static.a'
baseline = archive.read_bytes()
assert sha(baseline) == manifest['archive']['sha256'] == '3b8c478d978ae3780f73f177d0b784e909dd04184546c97b84fab9e46ff10f87'
members = parse_ar(str(archive))['members']
member = members[52]
obj = baseline[member['body_offset']:member['body_offset'] + member['size']]
elf = ELFFile(io.BytesIO(obj))
old = elf.get_section_by_name('.data').data()
assert sha(old) == manifest['helper']['sha256']
helper = bytearray(old)
he = ELFFile(io.BytesIO(helper))
gate = manifest['moduleControl']
at, va, size = gate['gateFileOffset'], gate['gateVirtualAddress'], gate['gateBytes']

def run(name, *args):
    result = subprocess.run([str(tool / (name + '.exe')), *map(str, args)], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)

for source in ['helper_module_gate.S', 'helper_module_gate.c']:
    run('clang', '--target=aarch64-linux-android21', '-Oz', '-ffreestanding', '-fno-stack-protector',
        '-fPIC', '-c', root / 'runtime/ultra/modules' / source, '-o', out / (source + '.o'))
(out / 'gate.ld').write_text('SECTIONS { . = ' + hex(va) + '; .text : { *(.text*) } .rodata : { *(.rodata*) } /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) } }')
run('ld.lld', '-T', out / 'gate.ld', '--defsym=module_private_path=0xa6a9c',
    '--defsym=helper_delete=0x9f200', '--defsym=original_precheck_body=0xa6d6c',
    '--entry=maplesu_module_gate', out / 'helper_module_gate.S.o', out / 'helper_module_gate.c.o', '-o', out / 'gate.elf')
run('llvm-objcopy', '-O', 'binary', out / 'gate.elf', out / 'gate.bin')
code = (out / 'gate.bin').read_bytes()
assert len(code) <= (size + 15) & ~15
assert helper[at + size:at + len(code)] == bytes(max(0, len(code) - size))
assert code[:104] == helper[at:at + 104]  # Preserve the assembly ABI and displaced prologue.
changes = [i for i, (x, y) in enumerate(zip(helper[at:at + len(code)], code)) if x != y]
assert changes
helper[at:at + len(code)] = code
size = len(code)
note = he.get_section_by_name('.note.gnu.build-id')['sh_offset'] + 16
helper[note:note + 20] = bytes(20)
normalized = bytearray(helper)
slot = manifest['helper']['keySlotOffset']
normalized[slot:slot + 4096] = bytes(4096)
build_id = hashlib.sha1(normalized).digest()
helper[note:note + 20] = normalized[note:note + 20] = build_id
assert len(helper) == len(old)
assert all(x == y or at <= i < at + size or note <= i < note + 20
           for i, (x, y) in enumerate(zip(old, helper)))
(out / 'embedded-bootstrap.elf').write_bytes(helper)
ph = he['e_phoff'] + next(i for i, s in enumerate(he.iter_segments()) if s['p_type'] == 'PT_LOAD' and s['p_offset'] == at) * he['e_phentsize']
header = '#pragma once\n' + f'#define MAPLESU_GATE_FILE_OFFSET {at}\n#define MAPLESU_GATE_BRANCH_OFFSET {0xa6d68}\n#define MAPLESU_GATE_PHDR_OFFSET {ph}\n'
for name, data in [('bytes', code), ('branch', helper[0xa6d68:0xa6d6c]), ('phdr', helper[ph:ph + 56])]:
    header += 'static constexpr unsigned char maplesu_gate_' + name + '[] = {' + ','.join(map(str, data)) + '};\n'
(out / 'module_gate_identity.h').write_text(header)
assert obj.count(old) == 1
rebuilt_installer = obj.replace(old, helper)
(out / member['name']).write_bytes(rebuilt_installer)
control = out / 'maplesu_module_control.o'
run('clang++', '--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fexceptions',
    '-ffunction-sections', '-fdata-sections', '-I', sdk / 'include', '-I', out,
    '-c', root / 'runtime/ultra/modules/module_control.cpp', '-o', control)

def contract(blob):
    return sorted((s.name, s['st_info']['bind'], s['st_info']['type'], s['st_other']['visibility'], s['st_shndx'] == 'SHN_UNDEF')
                  for s in ELFFile(io.BytesIO(blob)).get_section_by_name('.symtab').iter_symbols() if s['st_info']['bind'] != 'STB_LOCAL')

previous_control = next(m for m in members if m['name'] == control.name)
assert contract(baseline[previous_control['body_offset']:previous_control['body_offset'] + previous_control['size']]) == contract(control.read_bytes())
candidate = out / archive.name
candidate.write_bytes(baseline)
run('llvm-ar', 'rD', candidate, out / member['name'], control)
run('llvm-ar', 'sD', candidate)
after = parse_ar(str(candidate))
diff = compare_members(parse_ar(str(archive)), after)
assert [x['ord'] for x in diff['changed']] == [52, previous_control['ord']]
assert not diff['added'] and not diff['removed'] and not diff['orderErrors']
meta = dict(baselineArchiveSha256=sha(baseline), archiveSha256=sha(candidate.read_bytes()),
            helperSha256=sha(helper), helperNormalizedSha256=sha(normalized), helperBuildId=build_id.hex(),
            helperBytes=len(helper), gateFileOffset=at, gateVirtualAddress=va, gateBytes=size,
            changedGateByteOffsets=changes, memberChanges=diff['changed'],
            sourceSha256=sha((root / 'runtime/ultra/modules/helper_module_gate.c').read_bytes()),
            deviceVerification=False, preservesPanicRepair=True, abiPreserved=True)
(out / 'build.json').write_text(json.dumps(meta, indent=2) + '\n')
if a.install:
    backup = out / 'before'
    backup.mkdir(exist_ok=True)
    for path in [archive, sdk / 'SDK-RELEASE.json', sdk / 'SDK-IDENTITY.cmake', sdk / 'SU-AUTH-MEMBER-DIFF.json']:
        shutil.copy2(path, backup / path.name)
    manifest['sdkBuildId'] = 'maplesu-ultra-5.1.0-module-startup-r10-20261106'
    manifest['archive'].update(sha256=meta['archiveSha256'], size=candidate.stat().st_size)
    for name in ['bootstrap', 'helper']:
        manifest[name].update(sha256=meta['helperSha256'], buildId=meta['helperBuildId'], size=len(helper), changed=True)
    manifest['helper']['normalizedSha256'] = meta['helperNormalizedSha256']
    manifest['moduleControl'].update({k: v for k, v in meta.items() if k in gate and k != 'sourceSha256'})
    manifest['moduleGateAbiRepair'] = meta
    manifest['statement'] = 'SDK 5.1.0 r10: ARM64 module gate flags corrected; r9 Panic repairs and legacy module ABI preserved; device boot acceptance pending.'
    for row in diff['changed']:
        for repair in manifest['repairs']:
            if repair['memberOrdinal'] == row['ord']:
                repair['sha256'] = row['candidateSha256']
    original = parse_ar(str(root / 'runtime/maplesu-sdk/maintenance/baseline/libkernel_module_kit_static.a'))
    count = original['member_count']
    common = dict(after, members=after['members'][:count], member_count=count)
    full_diff = compare_members(original, common)
    full_diff['added'] = [dict(ord=m['ord'], name=m['name'], candidateSha256=m['sha256']) for m in after['members'][count:]]
    document = dict(schemaVersion=1, baselineArchiveSha256=original['file_sha256'], archiveSha256=meta['archiveSha256'], totalMembers=len(members), **full_diff)
    diff_path = sdk / 'SU-AUTH-MEMBER-DIFF.json'
    diff_path.write_text(json.dumps(document, indent=2) + '\n')
    manifest['memberDiff'].update(sha256=sha(diff_path.read_bytes()), changed=len(full_diff['changed']), added=len(full_diff['added']), removed=len(full_diff['removed']))
    identity = sdk / 'SDK-IDENTITY.cmake'
    text = identity.read_text()
    for key, value in {'MAPLESU_ULTRA_SDK_BUILD_ID': manifest['sdkBuildId'], 'MAPLESU_ULTRA_SDK_SHA256': meta['archiveSha256'],
                       'MAPLESU_ULTRA_HELPER_SHA256': meta['helperNormalizedSha256'], 'MAPLESU_ULTRA_HELPER_BUILD_ID': meta['helperBuildId']}.items():
        text = re.sub(r'set\(' + key + r' "[^"]*"\)', f'set({key} "{value}")', text)
    identity.write_text(text)
    shutil.copy2(candidate, archive)
    (sdk / 'SDK-RELEASE.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(meta, indent=2))
