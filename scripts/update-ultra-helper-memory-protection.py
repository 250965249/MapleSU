"""Prepare the pinned helper permission-return selector without publishing it."""
import argparse, hashlib, io, json, struct, subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
OUT_ROOT = ROOT / 'work/panic-kernel-read-20261114/helper-permissions'
PIN = '915c38312dad33bd905c80b21f3f712b2317fb96a2e5d2d8413101f24b0e50db'
ENTRY = 0xc04d4
SYMBOL = 'maplesu_helper_memory_protection_identify'
DEFS = dict(original_text_vtable=0x119660, original_ro_vtable=0x1196a8,
            original_rw_vtable=0x1196f0, original_x_vtable=0x119738,
            original_noresult_init_call=0xc04d8)
sha = lambda data: hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', required=True, type=Path)
    parser.add_argument('--out', type=Path, default=OUT_ROOT)
    args = parser.parse_args()
    out = args.out.resolve()
    assert out == OUT_ROOT or out.is_relative_to(OUT_ROOT), 'Use helper-permissions/ output'
    source = ROOT / 'runtime/ultra/boot/helper_memory_protection.S'
    original_path = ROOT / 'runtime/maplesu-sdk/helper/autorun_bootstrap'
    original = original_path.read_bytes()
    assert sha(original) == PIN, 'Pinned helper changed'
    image = ELFFile(io.BytesIO(original))
    loads = [(i, s) for i, s in enumerate(image.iter_segments()) if s['p_type'] == 'PT_LOAD']
    rxid, rx = max(loads, key=lambda row: row[1]['p_vaddr'])
    assert image['e_type'] == 'ET_DYN' and rx['p_flags'] == 5
    start = (rx['p_vaddr'] + max(rx['p_memsz'], len(original) - rx['p_offset']) + 15) & ~15
    at = next(s['p_offset'] + ENTRY - s['p_vaddr'] for _, s in loads
              if s['p_vaddr'] <= ENTRY and ENTRY + 4 <= s['p_vaddr'] + s['p_filesz'])
    assert struct.unpack_from('<I', original, at)[0] & 0xfc000000 == 0x14000000
    out.mkdir(parents=True, exist_ok=True)
    assert not any(out.iterdir()), 'Use a fresh output directory'
    tool = args.ndk.resolve() / 'toolchains/llvm/prebuilt/windows-x86_64/bin'

    def run(name, *arguments):
        result = subprocess.run([str(tool / (name + '.exe')), *map(str, arguments)],
                                capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr

    (out / 'entry.S').write_text('.section .patch,"ax"\nb ' + SYMBOL + '\n', encoding='utf-8')
    for name, path in [('selector', source), ('entry', out / 'entry.S')]:
        run('clang', '--target=aarch64-linux-android21', '-c', path, '-o', out / (name + '.o'))
    (out / 'candidate.ld').write_text(f'SECTIONS {{ .patch {hex(ENTRY)} : {{ *(.patch) }} '
        f'.extension {hex(start)} : {{ *(.text*) }} /DISCARD/ : {{ *(.comment) *(.note*) }} }}\n')
    run('ld.lld', '-T', out / 'candidate.ld', '--entry=' + SYMBOL,
        *[f'--defsym={name}={hex(value)}' for name, value in DEFS.items()],
        out / 'entry.o', out / 'selector.o', '-o', out / 'extension.elf')
    linked = ELFFile(io.BytesIO((out / 'extension.elf').read_bytes()))
    assert not any(s['sh_type'] in ('SHT_REL', 'SHT_RELA') and s['sh_size'] for s in linked.iter_sections())
    assert not any(s.name and s['st_shndx'] == 'SHN_UNDEF' for s in linked.get_section_by_name('.symtab').iter_symbols())
    assert all(not (s['sh_flags'] & 2 and s['sh_size']) or s.name in ('.patch', '.extension') for s in linked.iter_sections())
    branch, extension = linked.get_section_by_name('.patch').data(), linked.get_section_by_name('.extension')
    assert len(branch) == 4 and extension['sh_addr'] == start
    position = rx['p_offset'] + start - rx['p_vaddr']
    assert position >= len(original)
    result = bytearray(original)
    result[at:at + 4] = branch
    result.extend(bytes(position - len(result)) + extension.data())
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
    allowed = [(at, at + 4), (ph + 32, ph + 48), (note, note + 20)]
    assert all(x == y or any(lo <= i < hi for lo, hi in allowed) for i, (x, y) in enumerate(zip(original, result)))
    assert result[slot:slot + 4096] == original[slot:slot + 4096]
    final = ELFFile(io.BytesIO(result))
    for section in image.iter_sections():
        updated = final.get_section_by_name(section.name)
        assert updated.header == section.header, section.name
        assert all(x == y or any(lo <= section['sh_offset'] + i < hi for lo, hi in allowed)
                   for i, (x, y) in enumerate(zip(section.data(), updated.data()))), section.name
    for name in ('.dynamic', '.rela.dyn', '.rela.plt', '.dynsym', '.eh_frame', '.eh_frame_hdr', '.gcc_except_table'):
        assert final.get_section_by_name(name).data() == image.get_section_by_name(name).data(), name
    assert original_path.read_bytes() == original
    (out / 'candidate-helper.elf').write_bytes(result)
    report = dict(baselineHelperSha256=PIN, helperSha256=sha(result), helperNormalizedSha256=sha(normalized),
        helperBuildId=build_id.hex(), helperBytes=len(result), selectorVtables=DEFS,
        entryPatch=dict(offset=at, baselineHex=original[at:at + 4].hex(), candidateHex=branch.hex()),
        extension=dict(address=start, offset=position, bytes=extension['sh_size'], sha256=sha(extension.data())),
        keySlotPreserved=True, originalSectionsWhitelistVerified=True, dynamicMetadataPreserved=True,
        originalUnwindMetadataPreserved=True, productionInputsModified=False, deviceRequests=False,
        sources={p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in (source, Path(__file__).resolve())})
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS helper permission selector built; existing frames and metadata preserved')


if __name__ == '__main__':
    main()
