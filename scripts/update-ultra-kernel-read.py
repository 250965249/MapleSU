"""Build an isolated kernel-read SDK candidate while retaining request isolation."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess

from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import compare_members, parse_ar

ROOT = Path(__file__).resolve().parents[1]
BASELINE_ARCHIVE_SHA = '09c475dfbeff7c13c85a1df9874ae7423244ac58f0f13bc87477caa02c5dddcc'
BASELINE_MEMBER_SHA = '91b710329a50636572b8844bc659efe0dc4c8ebeebfe3b53322881e763163af0'
CANONICAL = '_ZN13kernel_module23request_kernel_read_memEmPvj'
LEGACY = 'maplesu_legacy_request_kernel_read_mem'
WRAPPED = '__wrap_' + CANONICAL


def sha(data):
    return hashlib.sha256(data).hexdigest()


def elf(data):
    return ELFFile(io.BytesIO(data))


def definitions(data):
    return {s.name: (s['st_info']['bind'], s['st_info']['type'],
                     s['st_other']['visibility'], s['st_size'])
            for s in elf(data).get_section_by_name('.symtab').iter_symbols()
            if s['st_info']['bind'] != 'STB_LOCAL' and s['st_shndx'] != 'SHN_UNDEF'}


def relocations(data, limit):
    image = elf(data)
    section = image.get_section_by_name('.rela.text')
    symbols = image.get_section(section['sh_link'])
    return [(r['r_offset'], r['r_info_type'], symbols.get_symbol(r['r_info_sym']).name,
             r['r_addend']) for r in section.iter_relocations() if r['r_offset'] < limit]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--ndk', required=True, type=Path)
    args = parser.parse_args()
    archive, out = args.archive.resolve(), args.out.resolve()
    assert args.out.is_absolute(), 'Candidate output must be an explicit absolute path'
    assert not out.is_relative_to(ROOT), 'Candidate output must be outside the source checkout'
    assert not out.exists(), 'Candidate output must be a fresh directory'
    assert archive != out / archive.name
    manifest_path = ROOT / 'runtime/maplesu-sdk/SDK-RELEASE.json'
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    assert manifest['archive']['sha256'] == BASELINE_ARCHIVE_SHA, 'Pinned SDK manifest drift'
    repair = next(r for r in manifest['repairs'] if r['memberOrdinal'] == 23)
    assert repair['sha256'] == BASELINE_MEMBER_SHA, 'Pinned request member manifest drift'
    base = archive.read_bytes()
    assert sha(base) == BASELINE_ARCHIVE_SHA, 'Pinned SDK archive drift'
    before = parse_ar(str(archive))
    member = before['members'][23]
    assert member['name'] == 'module_base_kernel_request.o'
    assert member['sha256'] == BASELINE_MEMBER_SHA, 'Pinned request member drift'
    assert sum(m['name'] == member['name'] for m in before['members']) == 1
    original = base[member['body_offset']:member['body_offset'] + member['size']]
    original_definitions = definitions(original)
    assert CANONICAL in original_definitions and LEGACY not in original_definitions
    assert 'maplesu_prepare_kernel_request' in original_definitions
    sources = [ROOT / 'runtime/ultra/authorization/kernel_read.cpp', Path(__file__).resolve(),
               ROOT / 'runtime/ultra/authorization/kernel_read_metadata.h']
    sources += [ROOT / 'runtime/maplesu-sdk/include' / name for name in (
        'module_err_def.h', 'aarch64_asm_helper.h', 'module_base_kernel_mem.h',
        'module_base_kernel_symbol_kaddr.h')]
    source_hashes = {p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in sources}
    tool = args.ndk.resolve() / 'toolchains/llvm/prebuilt/windows-x86_64/bin'
    for name in ('clang++', 'llvm-objcopy', 'ld.lld', 'llvm-ar', 'llvm-nm'):
        assert (tool / (name + '.exe')).is_file(), 'Missing NDK tool: ' + name
    out.mkdir(parents=True)
    commands = []

    def run(name, *arguments):
        command = [str(tool / (name + '.exe')), *map(str, arguments)]
        result = subprocess.run(command, capture_output=True, encoding='utf-8', errors='replace')
        commands.append(dict(command=command, exitCode=result.returncode, stderr=result.stderr))
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return result.stdout

    original_path, renamed_path = out / 'request.original.o', out / 'request.legacy.o'
    original_path.write_bytes(original)
    run('llvm-objcopy', '--redefine-sym=' + CANONICAL + '=' + LEGACY,
        original_path, renamed_path)
    renamed = renamed_path.read_bytes()
    expected = dict(original_definitions)
    expected[LEGACY] = expected.pop(CANONICAL)
    assert definitions(renamed) == expected, 'Symbol rename changed the request ABI'
    for section in elf(original).iter_sections():
        if section['sh_flags'] & 2:
            replacement = elf(renamed).get_section_by_name(section.name)
            assert replacement and replacement.data() == section.data(), section.name
    old_text = elf(original).get_section_by_name('.text').data()
    assert relocations(renamed, len(old_text)) == relocations(original, len(old_text)), \
        'Symbol rename changed request relocations'

    compiled_path = out / 'kernel-read.o'
    run('clang++', '--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC',
        '-fexceptions', '-fno-rtti', '-fvisibility=hidden', '-ffunction-sections',
        '-fdata-sections', '-Wall', '-Wextra', '-Werror', '-Wno-packed-non-pod',
        '-DMAPLESU_KERNEL_READ_CANONICAL=1', '-isystem', ROOT / 'runtime/maplesu-sdk/include',
        '-c', sources[0], '-o', compiled_path)
    compiled = compiled_path.read_bytes()
    assert definitions(compiled)[CANONICAL][:3] == ('STB_GLOBAL', 'STT_FUNC', 'STV_HIDDEN')
    assert not any(s.name in (WRAPPED, LEGACY) for s in
                   elf(compiled).get_section_by_name('.symtab').iter_symbols())
    combined_path = out / member['name']
    run('ld.lld', '-r', renamed_path, compiled_path, '-o', combined_path)
    combined = combined_path.read_bytes()
    combined_definitions = definitions(combined)
    assert all(combined_definitions.get(name) == value for name, value in expected.items()), \
        'Existing request symbols changed'
    assert combined_definitions[CANONICAL] == definitions(compiled)[CANONICAL]
    assert not any(s.name == WRAPPED for s in
                   elf(combined).get_section_by_name('.symtab').iter_symbols())
    assert elf(combined).get_section_by_name('.text').data()[:len(old_text)] == old_text, \
        'Existing request implementation changed'
    assert relocations(combined, len(old_text)) == relocations(original, len(old_text)), \
        'Existing request credential-isolation calls changed'
    candidate = out / archive.name
    candidate.write_bytes(base)
    run('llvm-ar', 'rD', candidate, combined_path)
    run('llvm-ar', 'sD', candidate)
    after = parse_ar(str(candidate))
    diff = compare_members(before, after)
    assert [m['ord'] for m in diff['changed']] == [23]
    assert not diff['added'] and not diff['removed'] and not diff['orderErrors']
    assert after['symbol_index']['present'] and after['symbol_index']['size'] > 0
    assert before['members'][52]['sha256'] == after['members'][52]['sha256']
    symbol_output = run('llvm-nm', '--extern-only', '--defined-only', '--format=posix', candidate)
    names = [line.split()[0] for line in symbol_output.splitlines() if line.strip()]
    symbol_counts = {name: names.count(name) for name in (CANONICAL, LEGACY, WRAPPED)}
    assert symbol_counts == {CANONICAL: 1, LEGACY: 1, WRAPPED: 0}, \
        'Canonical, legacy and linker-wrap symbols are ambiguous'
    assert archive.read_bytes() == base and manifest_path.read_bytes() == manifest_bytes
    assert all(sha((ROOT / name).read_bytes()) == value for name, value in source_hashes.items()), \
        'Build input changed during candidate construction'
    report = dict(passed=True, baselineArchiveSha256=sha(base),
        archiveSha256=after['file_sha256'], archivePath=str(candidate), memberDiff=diff,
        canonicalSymbol=CANONICAL, legacySymbol=LEGACY, wrappedSymbolAbsent=True,
        archiveSymbolCounts=symbol_counts,
        requestIsolationPreserved=True, originalRequestTextSha256=sha(old_text),
        originalRequestRelocationsPreserved=True, helperMemberUnchanged=True,
        productionArchiveUnchanged=True, deviceAccess=False, sources=source_hashes,
        commands=commands)
    (out / 'kernel-read-repair.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS only SDK member 23 changed; original request isolation retained')


if __name__ == '__main__':
    main()
