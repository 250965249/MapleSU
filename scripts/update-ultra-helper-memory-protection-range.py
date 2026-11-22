"""Build an independent pinned helper protection-range correction."""
import argparse
import hashlib
import io
import json
import struct
import subprocess
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
PIN = 'c7f6bf334221184446639dac8ecdbce979d00643e1fdc998f56b3df92d8f1781'
OUT_ROOT = ROOT / 'work/panic-implementation-20261114/helper-memory-range-candidate'
sha = lambda data: hashlib.sha256(data).hexdigest()
DEFS = dict(original_ro_continue=0xc09b8, original_rw_continue=0xc0944,
            original_x_continue=0xc0920, original_ro_invalid=0xc09d0,
            original_main_invalid=0xc0964)
PATCHES = {0xc09ac: 'mov x20, x0', 0xc0938: 'mov x20, x21', 0xc0914: 'mov x20, x21',
           0xc09b4: 'b range_ro', 0xc0940: 'b range_rw', 0xc091c: 'b range_x'}
SOURCE = ROOT / 'runtime/ultra/boot/helper_memory_protection_range.S'



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--out', type=Path, default=OUT_ROOT)
    args = parser.parse_args()
    out = args.out.resolve()
    assert out == OUT_ROOT or out.is_relative_to(OUT_ROOT), 'Use dedicated candidate output'
    assert not out.exists() or not any(out.iterdir()), 'Use fresh candidate output'
    original_path = ROOT / 'runtime/maplesu-sdk/helper/autorun_bootstrap'
    original = original_path.read_bytes()
    assert sha(original) == PIN, 'Pinned helper changed'
    image = ELFFile(io.BytesIO(original))
    loads = [(index, segment) for index, segment in enumerate(image.iter_segments())
             if segment['p_type'] == 'PT_LOAD']
    rxid, rx = max(loads, key=lambda item: item[1]['p_vaddr'])
    assert image['e_type'] == 'ET_DYN' and rx['p_flags'] == 5
    extension_va = (rx['p_vaddr'] + max(rx['p_memsz'], len(original) - rx['p_offset']) + 15) & ~15
    extension_at = rx['p_offset'] + extension_va - rx['p_vaddr']
    assert extension_at >= len(original)

    def offset(address):
        return next(segment['p_offset'] + address - segment['p_vaddr'] for _, segment in loads
                    if segment['p_vaddr'] <= address and address + 4 <= segment['p_vaddr'] + segment['p_filesz'])

    out.mkdir(parents=True, exist_ok=True)
    tool = args.ndk.resolve() / 'toolchains/llvm/prebuilt/windows-x86_64/bin'

    def run(name, *arguments):
        result = subprocess.run([str(tool / (name + '.exe')), *map(str, arguments)],
                                capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr

    assembly = SOURCE.read_text() + '\n' + '\n'.join(f'.section .patch{address:x},"ax"\n{code}'
                                             for address, code in PATCHES.items()) + '\n'
    (out / 'range.S').write_text(assembly, encoding='utf-8')
    run('clang', '--target=aarch64-linux-android21', '-c', out / 'range.S', '-o', out / 'range.o')
    sections = ' '.join(f'.patch{address:x} {hex(address)} : {{ *(.patch{address:x}) }}'
                        for address in sorted(PATCHES))
    (out / 'candidate.ld').write_text(f'SECTIONS {{ {sections} .extension {hex(extension_va)} : '
        '{ *(.extension) } /DISCARD/ : { *(.comment) *(.note*) } }\n', encoding='utf-8')
    run('ld.lld', '-T', out / 'candidate.ld', '--entry=range_ro',
        *[f'--defsym={name}={hex(value)}' for name, value in DEFS.items()],
        out / 'range.o', '-o', out / 'extension.elf')
    linked = ELFFile(io.BytesIO((out / 'extension.elf').read_bytes()))
    assert not any(s['sh_type'] in ('SHT_REL', 'SHT_RELA') and s['sh_size'] for s in linked.iter_sections())
    assert not any(s.name and s['st_shndx'] == 'SHN_UNDEF' for s in linked.get_section_by_name('.symtab').iter_symbols())
    assert all(not (s['sh_flags'] & 2 and s['sh_size']) or s.name == '.extension' or s.name.startswith('.patch')
               for s in linked.iter_sections())
    result = bytearray(original)
    patches = {}
    for address in PATCHES:
        section = linked.get_section_by_name(f'.patch{address:x}')
        assert section['sh_addr'] == address and section['sh_size'] == 4
        at = offset(address)
        patches[address] = section.data()
        result[at:at + 4] = section.data()
    extension = linked.get_section_by_name('.extension')
    assert extension['sh_addr'] == extension_va
    result.extend(bytes(extension_at - len(result)) + extension.data())
    result.extend(bytes((-len(result)) % 8))
    ph = image['e_phoff'] + rxid * image['e_phentsize']
    length = len(result) - rx['p_offset']
    struct.pack_into('<QQ', result, ph + 32, length, length)
    note = image.get_section_by_name('.note.gnu.build-id')['sh_offset'] + 16
    slot = 182886
    result[note:note + 20] = bytes(20)
    normalized = bytearray(result)
    normalized[slot:slot + 4096] = bytes(4096)
    build_id = hashlib.sha1(normalized).digest()
    result[note:note + 20] = normalized[note:note + 20] = build_id
    allowed = [(offset(address), offset(address) + 4) for address in patches]
    allowed += [(ph + 32, ph + 48), (note, note + 20)]
    assert all(a == b or any(lo <= index < hi for lo, hi in allowed)
               for index, (a, b) in enumerate(zip(original, result)))
    assert result[slot:slot + 4096] == original[slot:slot + 4096]
    final = ELFFile(io.BytesIO(result))
    for section in image.iter_sections():
        updated = final.get_section_by_name(section.name)
        assert updated.header == section.header, section.name
        assert all(a == b or any(lo <= section['sh_offset'] + index < hi for lo, hi in allowed)
                   for index, (a, b) in enumerate(zip(section.data(), updated.data()))), section.name
    for name in ('.dynamic', '.rela.dyn', '.rela.plt', '.dynsym', '.eh_frame', '.eh_frame_hdr', '.gcc_except_table'):
        assert final.get_section_by_name(name).data() == image.get_section_by_name(name).data(), name
    assert original_path.read_bytes() == original
    candidate = out / 'candidate-helper.elf'
    candidate.write_bytes(result)
    for test, name in [('test-ultra-helper-memory-protection-range.py', 'range-replay.json'),
                       ('test-ultra-helper-allowlist.py', 'allowlist-replay.json')]:
        subprocess.run([sys.executable, str(ROOT / 'scripts/tests' / test), '--helper', str(candidate),
                        '--out', str(out / name)], check=True)
    report = dict(schemaVersion=1, baselineHelperSha256=PIN, helperSha256=sha(result),
        helperNormalizedSha256=sha(normalized), helperBuildId=build_id.hex(), helperBytes=len(result),
        patches=[dict(address=hex(address), offset=offset(address),
                      baselineHex=original[offset(address):offset(address) + 4].hex(),
                      candidateHex=replacement.hex()) for address, replacement in patches.items()],
        extension=dict(address=hex(extension_va), offset=extension_at, bytes=extension['sh_size'], sha256=sha(extension.data())),
        keySlotPreserved=True, originalSectionsWhitelistVerified=True, dynamicMetadataPreserved=True,
        originalUnwindMetadataPreserved=True, noNewCallsOrStackFrames=True, existingFixesPreserved=True,
        productionInputsModified=False, deviceRequests=False,
        scope='Protection range validation and page arithmetic; current NX panic causality remains unestablished.',
        sources={p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in
                 (Path(__file__).resolve(), SOURCE, ROOT / 'scripts/tests/test-ultra-helper-memory-protection-range.py')},
        replays={name: sha((out / name).read_bytes()) for name in ('range-replay.json', 'allowlist-replay.json')})
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS pinned independent helper range candidate:', report['helperSha256'])


if __name__ == '__main__':
    main()
