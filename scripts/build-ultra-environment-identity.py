"""Add the identity entry to the pinned r11 bootstrap, preserving its prior repairs."""
import argparse
import hashlib
import io
import json
from pathlib import Path
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
archive = sdk / 'lib/arm64-v8a/libkernel_module_kit_static.a'
manifest = json.loads((sdk / 'SDK-RELEASE.json').read_text())
out = a.out.resolve()
out.mkdir(parents=True, exist_ok=True)
tool = a.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'
sha = lambda data: hashlib.sha256(data).hexdigest()
base = archive.read_bytes()
assert sha(base) == manifest['archive']['sha256'] == 'ec0b483d9c041ed90a85188f9ad3e59bb65894e53ae6474630479dc4b3b13938'
before = parse_ar(str(archive))
member = before['members'][52]
obj = base[member['body_offset']:member['body_offset'] + member['size']]
elf = ELFFile(io.BytesIO(obj))
original = elf.get_section_by_name('.data').data()
assert sha(original) == manifest['helper']['sha256'] == '38691adbc90e2e0bfc89943b15e2b64dc8d2fc61990dfc128b079bb09f1b95a3'
helper = bytearray(original)
he = ELFFile(io.BytesIO(original))
index, tail = max(((i, s) for i, s in enumerate(he.iter_segments()) if s['p_type'] == 'PT_LOAD'), key=lambda row: row[1]['p_vaddr'])
assert tail['p_flags'] == 5
va = (tail['p_vaddr'] + max(tail['p_memsz'], len(original) - tail['p_offset']) + 15) & ~15
site, loader = 0xa974c, 0xa6f34
old_branch = struct.pack('<I', 0x94000000 | (((loader - site) // 4) & 0x3ffffff))
assert original[site:site + 4] == old_branch

def run(name, *args):
    r = subprocess.run([str(tool / (name + '.exe')), *map(str, args)], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(r.stdout + r.stderr)

common = ['--target=aarch64-linux-android21', '-Oz', '-ffreestanding', '-fno-builtin', '-fPIC',
          '-fno-stack-protector', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-Wall', '-Wextra', '-Werror', '-c']
for name in ['environment_start.c', 'environment_start.S']:
    run('clang', *common, root / 'runtime/ultra/identity' / name, '-o', out / (name + '.o'))
(out / 'entry.ld').write_text(f'SECTIONS {{ . = {hex(va)}; .extension : {{ *(.text*) *(.rodata*) }} /DISCARD/ : {{ *(.comment) *(.note*) *(.eh_frame*) }} }}')
dyn = he.get_section_by_name('.dynsym')
plt = he.get_section_by_name('.plt')['sh_addr']
defs = {dyn.get_symbol(r['r_info_sym']).name: plt + 32 + 16 * i for i, r in enumerate(he.get_section_by_name('.rela.plt').iter_relocations())}
defs['original_module_loader'] = loader
run('ld.lld', '-T', out / 'entry.ld', '--entry=maplesu_environment_identity_entry',
    *[f'--defsym={name}={hex(value)}' for name, value in defs.items()],
    out / 'environment_start.S.o', out / 'environment_start.c.o', '-o', out / 'entry.elf')
linked = ELFFile(io.BytesIO((out / 'entry.elf').read_bytes()))
assert not [s for s in linked.iter_sections() if s['sh_type'] in ('SHT_REL', 'SHT_RELA') and s['sh_size']]
code = linked.get_section_by_name('.extension').data()
symbols = {s.name: s['st_value'] for s in linked.get_section_by_name('.symtab').iter_symbols()}
entry = symbols['maplesu_environment_identity_entry']
file_at = tail['p_offset'] + va - tail['p_vaddr']
assert file_at >= len(helper)
helper.extend(bytes(file_at - len(helper)))
helper.extend(code)
helper.extend(bytes((-len(helper)) % 8))
branch = struct.pack('<I', 0x94000000 | (((entry - site) // 4) & 0x3ffffff))
helper[site:site + 4] = branch
ph = he['e_phoff'] + index * he['e_phentsize']
length = len(helper) - tail['p_offset']
struct.pack_into('<QQ', helper, ph + 32, length, length)
note = he.get_section_by_name('.note.gnu.build-id')['sh_offset'] + 16
helper[note:note + 20] = bytes(20)
normalized = bytearray(helper)
slot = manifest['helper']['keySlotOffset']
normalized[slot:slot + 4096] = bytes(4096)
build_id = hashlib.sha1(normalized).digest()
helper[note:note + 20] = normalized[note:note + 20] = build_id
allowed = [(site, site + 4), (ph + 32, ph + 48), (note, note + 20)]
assert all(x == y or any(start <= i < end for start, end in allowed) for i, (x, y) in enumerate(zip(original, helper)))
(out / 'embedded-bootstrap.elf').write_bytes(helper)
# Update only the embedded array, its three compiled size pairs and its symbol size.
text = bytearray(elf.get_section_by_name('.text').data())
for low, high, reg in [(0x374, 0x37c, 0), (0x3ac, 0x3b8, 2), (0x49c, 0x4a4, 2)]:
    for at, opcode, shift in [(low, 0x52800000, 0), (high, 0x72a00000, 16)]:
        assert struct.unpack_from('<I', text, at)[0] == opcode | (((len(original) >> shift) & 65535) << 5) | reg
        struct.pack_into('<I', text, at, opcode | (((len(helper) >> shift) & 65535) << 5) | reg)
(out / 'installer-text.bin').write_bytes(text)
(out / 'baseline-installer.o').write_bytes(obj)
installer = out / member['name']
run('llvm-objcopy', '--update-section', f'.data={out / "embedded-bootstrap.elf"}', '--update-section',
    f'.text={out / "installer-text.bin"}', out / 'baseline-installer.o', installer)
rebuilt = bytearray(installer.read_bytes())
se = ELFFile(io.BytesIO(rebuilt)).get_section_by_name('.symtab')
changed = []
for i, symbol in enumerate(se.iter_symbols()):
    if symbol.name == '_ZN7maplesu3sdkL27autorun_bootstrap_file_dataE':
        assert symbol['st_size'] == len(original)
        struct.pack_into('<Q', rebuilt, se['sh_offset'] + i * se['sh_entsize'] + 16, len(helper))
        changed.append(symbol.name)
assert len(changed) == 1
installer.write_bytes(rebuilt)
for first, second in zip(elf.iter_sections(), ELFFile(io.BytesIO(rebuilt)).iter_sections()):
    assert first.name == second.name
    if first.name not in ('.data', '.text', '.symtab'):
        assert first.data() == second.data(), first.name
# The existing module-control gate includes its containing segment header in its identity.
gate = manifest['moduleControl']
gate_at, gate_size = gate['gateFileOffset'], gate['gateBytes']
header = '#pragma once\n' + f'#define MAPLESU_GATE_FILE_OFFSET {gate_at}\n#define MAPLESU_GATE_BRANCH_OFFSET {0xa6d68}\n#define MAPLESU_GATE_PHDR_OFFSET {ph}\n'
for name, data in [('bytes', helper[gate_at:gate_at + gate_size]), ('branch', helper[0xa6d68:0xa6d6c]), ('phdr', helper[ph:ph + 56])]:
    header += 'static constexpr unsigned char maplesu_gate_' + name + '[] = {' + ','.join(map(str, data)) + '};\n'
(out / 'module_gate_identity.h').write_text(header)
control = out / 'maplesu_module_control.o'
run('clang++', '--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fexceptions', '-ffunction-sections',
    '-fdata-sections', '-I', sdk / 'include', '-I', out, '-c', root / 'runtime/ultra/modules/module_control.cpp', '-o', control)
candidate = out / archive.name
candidate.write_bytes(base)
run('llvm-ar', 'rD', candidate, installer, control)
run('llvm-ar', 'sD', candidate)
after = parse_ar(str(candidate))
diff = compare_members(before, after)
assert [row['ord'] for row in diff['changed']] == [52, 255] and not diff['added'] and not diff['removed'] and not diff['orderErrors']
def contract(data):
    return sorted((s.name, s['st_info']['bind'], s['st_info']['type'], s['st_other']['visibility'], s['st_shndx'] == 'SHN_UNDEF')
                  for s in ELFFile(io.BytesIO(data)).get_section_by_name('.symtab').iter_symbols() if s['st_info']['bind'] != 'STB_LOCAL')
for row in diff['changed']:
    old, new = before['members'][row['ord']], after['members'][row['ord']]
    assert contract(base[old['body_offset']:old['body_offset'] + old['size']]) == contract(candidate.read_bytes()[new['body_offset']:new['body_offset'] + new['size']])
report = dict(baselineArchiveSha256=sha(base), archiveSha256=sha(candidate.read_bytes()), helperSha256=sha(helper),
              helperNormalizedSha256=sha(normalized), helperBuildId=build_id.hex(), helperBytes=len(helper),
              hookSite=site, hookEntry=entry, launcher=symbols['maplesu_environment_identity_start'],
              originalModuleLoader=loader, extensionAddress=va, extensionBytes=len(code),
              abiPreserved=True, preservesPreviousRepairs=True, memberDiff=diff, deviceVerification=False,
              sourceSha256={name: sha((root / 'runtime/ultra/identity' / name).read_bytes()) for name in ['environment_start.c', 'environment_start.S']})
(out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
if a.install:
    backup = out / 'before'
    backup.mkdir(exist_ok=True)
    for path in [archive, sdk / 'SDK-RELEASE.json', sdk / 'SDK-IDENTITY.cmake', sdk / 'SU-AUTH-MEMBER-DIFF.json']:
        shutil.copy2(path, backup / path.name)
    manifest['sdkBuildId'] = 'maplesu-ultra-5.1.0-environment-identity-r12-20261107'
    manifest['archive'].update(sha256=report['archiveSha256'], size=candidate.stat().st_size)
    for name in ['helper', 'bootstrap']:
        manifest[name].update(sha256=report['helperSha256'], buildId=report['helperBuildId'], size=len(helper), changed=True)
    manifest['helper']['normalizedSha256'] = report['helperNormalizedSha256']
    manifest['moduleControl'].update(helperSha256=report['helperSha256'], helperNormalizedSha256=report['helperNormalizedSha256'],
                                     helperBuildId=report['helperBuildId'], helperBytes=len(helper), archiveSha256=report['archiveSha256'])
    manifest['environmentIdentity'] = report
    manifest['statement'] = 'SDK r12: identity daemon starts from the environment bootstrap before user modules; r11 authorization and prior Panic repairs preserved. Device acceptance pending.'
    for row in diff['changed']:
        for repair in manifest['repairs']:
            if repair['memberOrdinal'] == row['ord']:
                repair['sha256'] = row['candidateSha256']
    original_members = parse_ar(str(root / 'runtime/maplesu-sdk/maintenance/baseline/libkernel_module_kit_static.a'))
    n = original_members['member_count']
    full = compare_members(original_members, dict(after, members=after['members'][:n], member_count=n))
    full['added'] = [dict(ord=m['ord'], name=m['name'], candidateSha256=m['sha256']) for m in after['members'][n:]]
    diff_path = sdk / 'SU-AUTH-MEMBER-DIFF.json'
    diff_path.write_text(json.dumps(dict(schemaVersion=1, baselineArchiveSha256=original_members['file_sha256'], archiveSha256=report['archiveSha256'], totalMembers=after['member_count'], **full), indent=2) + '\n')
    manifest['memberDiff'].update(sha256=sha(diff_path.read_bytes()), changed=len(full['changed']), added=len(full['added']), removed=len(full['removed']))
    shutil.copy2(candidate, archive)
    (sdk / 'SDK-RELEASE.json').write_text(json.dumps(manifest, indent=2) + '\n')
    subprocess.run([__import__('sys').executable, str(root / 'scripts/sync-ultra-sdk-identity.py')], check=True)
print(json.dumps({k: v for k, v in report.items() if k not in ('memberDiff', 'sourceSha256')}, indent=2))
