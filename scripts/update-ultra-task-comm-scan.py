"""Build an isolated task comm batch scanner; retain all other SDK members."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import subprocess
import sys
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
from verify_sdk_member_diff import parse_ar, compare_members

EXPECTED = 'cdeeec80f790c9c3891b8dab95e3c5419b486408230e087946808033a4d5a3b6'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--archive', required=True, type=Path)
parser.add_argument('--out', required=True, type=Path)
parser.add_argument('--ndk', required=True, type=Path)
args = parser.parse_args()
ARCHIVE = args.archive.resolve()
HERE = args.out.resolve()
assert HERE.is_relative_to(ROOT / 'work') and HERE != ROOT / 'work' and not HERE.exists()
assert ARCHIVE != HERE / ARCHIVE.name
HERE.mkdir(parents=True)
SOURCE = ROOT / 'runtime/ultra/authorization/task_comm_scan.cpp'
HEADER = SOURCE.with_suffix('.h')
TOOLS = args.ndk.resolve() / 'toolchains/llvm/prebuilt/windows-x86_64/bin'
CANONICAL = '_ZN13kernel_module27get_task_struct_comm_offsetERj'
commands = []


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(name, *arguments):
    command = [str(TOOLS / (name + '.exe')), *map(str, arguments)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    commands.append(dict(command=command, exitCode=result.returncode, stderr=result.stderr))
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


base = ARCHIVE.read_bytes()
assert sha(base) == EXPECTED
sources = {p: p.read_bytes() for p in (SOURCE, HEADER, Path(__file__).resolve(),
    ROOT / 'runtime/maplesu-sdk/include/module_err_def.h',
    ROOT / 'runtime/maplesu-sdk/include/aarch64_asm_helper.h',
    ROOT / 'runtime/maplesu-sdk/include/module_base_kernel_export_symbol.h',
    ROOT / 'runtime/maplesu-sdk/include/module_base_kernel_export_symbol.inl',
    ROOT / 'runtime/maplesu-sdk/include/module_base_kernel_func_executor.h',
    ROOT / 'runtime/maplesu-sdk/include/module_base_kernel_mem.h',
    ROOT / 'runtime/maplesu-sdk/include/kernel_offsets/task_struct.h')}
before = parse_ar(str(ARCHIVE))
member = before['members'][1]
assert member['name'] == 'task_struct.o'
assert member['sha256'] == '3939fc09c9c7e75792224a73f7a9d088eb6387ef78031629442c79f06431882f'
original = base[member['body_offset']:member['body_offset'] + member['size']]
original_path = HERE / 'task_struct.original.o'
original_path.write_bytes(original)
weak_path = HERE / 'task_struct.weak.o'
run('llvm-objcopy', '--weaken-symbol=' + CANONICAL, original_path, weak_path)

def elf(data):
    return ELFFile(io.BytesIO(data))


def defined(data):
    return {s.name: (s['st_info']['bind'], s['st_info']['type'], s['st_other']['visibility'], s['st_size'])
            for s in elf(data).get_section_by_name('.symtab').iter_symbols()
            if s['st_info']['bind'] != 'STB_LOCAL' and s['st_shndx'] != 'SHN_UNDEF'}


weak = weak_path.read_bytes()
original_defs = defined(original)
expected_defs = dict(original_defs)
expected_defs[CANONICAL] = ('STB_WEAK', *expected_defs[CANONICAL][1:])
assert defined(weak) == expected_defs
for section in elf(original).iter_sections():
    if section['sh_flags'] & 2:
        assert elf(weak).get_section_by_name(section.name).data() == section.data()
replacement = HERE / 'task-comm-scan.o'
run('clang++', '--target=aarch64-linux-android26', '-std=c++20', '-O2', '-fPIC',
    '-fexceptions', '-fno-rtti', '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections',
    '-Wall', '-Wextra', '-Werror', '-Wno-packed-non-pod',
    '-isystem', ROOT / 'runtime/maplesu-sdk/include', '-c', SOURCE, '-o', replacement)
combined_path = HERE / 'task_struct.o'
run('ld.lld', '-r', weak_path, replacement, '-o', combined_path)
combined = combined_path.read_bytes()
defs = defined(combined)
assert defs[CANONICAL] == defined(replacement.read_bytes())[CANONICAL]
assert defs[CANONICAL][0] == 'STB_GLOBAL'
assert all(defs.get(name) == info for name, info in original_defs.items() if name != CANONICAL)
assert elf(combined).get_section_by_name('.text').data() == elf(original).get_section_by_name('.text').data()
# Every original task-struct call still resolves through the canonical symbol,
# which the relocatable linker has bound to the new strong implementation.
original_elf, combined_elf = elf(original), elf(combined)
def targets(image):
    result = []
    symbols = image.get_section_by_name('.symtab')
    for section in image.iter_sections():
        if section['sh_type'] == 'SHT_RELA' and section.name == '.rela.text':
            for r in section.iter_relocations():
                symbol = symbols.get_symbol(r['r_info_sym'])
                addend = r['r_addend']
                target = symbol.name
                if not target and isinstance(symbol['st_shndx'], int):
                    target_section = image.get_section(symbol['st_shndx'])
                    if target_section['sh_flags'] & 0x10:  # SHF_MERGE reorders constants.
                        data = target_section.data()
                        start = symbol['st_value'] + addend
                        if target_section['sh_flags'] & 0x20:  # SHF_STRINGS
                            end = data.index(b'\0', start) + 1
                        else:
                            end = start + target_section['sh_entsize']
                        target = (target_section.name, data[start:end])
                        addend = 0
                result.append((r['r_offset'], r['r_info_type'], target, addend))
    return result
assert targets(original_elf) == targets(combined_elf)
candidate = HERE / 'comm-scan-sdk.a'
candidate.write_bytes(base)
run('llvm-ar', 'rD', candidate, combined_path)
run('llvm-ar', 'sD', candidate)
after = parse_ar(str(candidate))
diff = compare_members(before, after)
assert [m['ord'] for m in diff['changed']] == [1]
assert not diff['added'] and not diff['removed'] and not diff['orderErrors']
assert ARCHIVE.read_bytes() == base
assert all(p.read_bytes() == data for p, data in sources.items())
report = dict(passed=True, deviceExecuted=False, productionArchiveUnchanged=True,
    baselineArchiveSha256=EXPECTED, archiveSha256=sha(candidate.read_bytes()), archivePath=str(candidate),
    memberDiff=diff, originalM001TextPreserved=True, originalM001RelocationsPreserved=True,
    canonicalStrongDefinition=True, originalOtherGlobalDefinitionsPreserved=True,
    sources={p.relative_to(ROOT).as_posix(): sha(data) for p, data in sources.items()},
    baselineCredentialSnapshotMemberSha256=member['sha256'], requestIsolationPreserved=True,
    validationScope=['ndk-compile','m001-text-preserved','m001-relocations-preserved','canonical-strong-definition','archive-member-diff'],
    deviceAcceptance=False, commands=commands)
(HERE / 'task-comm-scan-repair.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps({k:v for k,v in report.items() if k != 'commands'}, indent=2))
