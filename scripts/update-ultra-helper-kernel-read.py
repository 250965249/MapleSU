"""Build and replay an independent, pinned helper nofault-read candidate."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
PIN = '525efe304aaf480e3dedbaa4e9d2c26d158ed8a837e99a7244b88c09fc490504'
APIS = {
    'helper_append': (0xbfad4, 48, 'eafc7ed1b1d75e6e7820e9e47ea1ca4ef86068f0ade4f68cbe800ef70f3cb149'),
    'helper_lookup': (0xbac9c, 88, 'c176753032e4ca3c314903537214f26732058f40b2a8380d9a60d9ddc65bf737'),
    'helper_execute': (0xc5aa8, 732, '523207f924d88bf0b55699512818fdff7777aa92ba6419b6ca186547475c2887'),
}
ENTRY = 0xc48e8
sha = lambda data: hashlib.sha256(data).hexdigest()


def entries(data, address):
    assert data[:4] == bytes.fromhex('011b033b')
    count = struct.unpack_from('<I', data, 8)[0]
    assert len(data) == 12 + count * 8
    return [(address + pc, address + fde) for pc, fde in struct.iter_unpack('<ii', data[12:])]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--build-only', action='store_true')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    original_path = ROOT / 'runtime/maplesu-sdk/helper/autorun_bootstrap'
    assert out != original_path.parent
    original = original_path.read_bytes()
    assert sha(original) == PIN, 'Pinned helper changed'
    image = ELFFile(io.BytesIO(original))
    manifest = json.loads((ROOT / 'runtime/maplesu-sdk/SDK-RELEASE.json').read_text())
    loads = [(i, s) for i, s in enumerate(image.iter_segments()) if s['p_type'] == 'PT_LOAD']

    def offset(address):
        return next(s['p_offset'] + address - s['p_vaddr'] for _, s in loads
                    if s['p_vaddr'] <= address < s['p_vaddr'] + s['p_filesz'])

    for address, length, digest in APIS.values():
        at = offset(address)
        assert sha(original[at:at + length]) == digest, 'Helper API code drift'
    rxid, rx = max(loads, key=lambda row: row[1]['p_vaddr'])
    assert rx['p_flags'] == 5 and image['e_type'] == 'ET_DYN'
    start = (rx['p_vaddr'] + max(rx['p_memsz'], len(original) - rx['p_offset']) + 15) & ~15
    tool = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'

    def run(name, *arguments):
        result = subprocess.run([str(tool / (name + '.exe')), *map(str, arguments)],
                                capture_output=True, encoding='utf-8', errors='replace', timeout=60)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    source = ROOT / 'runtime/ultra/authorization'
    target = '--target=aarch64-linux-android21'
    run('clang++', target, '-std=c++17', '-Oz', '-fPIC', '-ffreestanding', '-fno-builtin',
        '-fno-stack-protector', '-fno-exceptions', '-fno-rtti', '-funwind-tables',
        '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror',
        '-c', source / 'helper_kernel_read.cpp', '-o', out / 'helper_kernel_read.o')
    run('clang', target, '-c', source / 'helper_kernel_read.S', '-o', out / 'helper_kernel_read_asm.o')
    (out / 'entry.S').write_text('.section .patch,"ax"\nb maplesu_helper_kernel_read\n')
    run('clang', target, '-c', out / 'entry.S', '-o', out / 'entry.o')
    linker = out / 'candidate.ld'
    linker.write_text(f'''SECTIONS {{
 .patch {hex(ENTRY)} : {{ *(.patch) }}
 . = {hex(start)};
 .extension : {{ *(.text*) *(.rodata*) }}
 .eh_frame_hdr : {{ *(.eh_frame_hdr) }}
 .eh_frame : {{ KEEP(*(.eh_frame)) }}
 /DISCARD/ : {{ *(.comment) *(.note*) }}
}}
''')
    linked_path = out / 'candidate-extension.elf'
    run('ld.lld', '-T', linker, '--eh-frame-hdr', '--entry=maplesu_helper_kernel_read',
        *[f'--defsym={name}={hex(value[0])}' for name, value in APIS.items()],
        out / 'entry.o', out / 'helper_kernel_read.o', out / 'helper_kernel_read_asm.o', '-o', linked_path)
    linked = ELFFile(io.BytesIO(linked_path.read_bytes()))
    assert not [s.name for s in linked.iter_sections() if s['sh_type'] in ('SHT_REL', 'SHT_RELA') and s['sh_size']]
    assert not [s.name for s in linked.iter_sections() if s.name in ('.got', '.data', '.data.rel.ro', '.bss', '.tdata', '.tbss') and s['sh_size']]
    assert not [s.name for s in linked.get_section_by_name('.symtab').iter_symbols()
                if s.name and s['st_shndx'] == 'SHN_UNDEF']
    result = bytearray(original)
    branch = linked.get_section_by_name('.patch').data()
    at = offset(ENTRY)
    assert len(branch) == 4
    result[at:at + 4] = branch
    for section in linked.iter_sections():
        if not section['sh_flags'] & 2 or not section['sh_size'] or section.name == '.patch':
            continue
        assert section.name in ('.extension', '.eh_frame_hdr', '.eh_frame'), section.name
        position = rx['p_offset'] + section['sh_addr'] - rx['p_vaddr']
        assert position >= len(original)
        result.extend(bytes(max(0, position + section['sh_size'] - len(result))))
        result[position:position + section['sh_size']] = section.data()
    ehid, old_header = next((i, s) for i, s in enumerate(image.iter_segments()) if s['p_type'] == 'PT_GNU_EH_FRAME')
    new_header = linked.get_section_by_name('.eh_frame_hdr')
    old_entries = entries(old_header.data(), old_header['p_vaddr'])
    new_entries = entries(new_header.data(), new_header['sh_addr'])
    all_entries = sorted(old_entries + new_entries)
    assert len({pc for pc, _ in all_entries}) == len(all_entries)
    header_va = (rx['p_vaddr'] + len(result) - rx['p_offset'] + 3) & ~3
    frame_va = old_header['p_vaddr'] + 4 + struct.unpack_from('<i', old_header.data(), 4)[0]
    header = bytes.fromhex('011b033b') + struct.pack('<iI', frame_va - header_va - 4, len(all_entries))
    header += b''.join(struct.pack('<ii', pc - header_va, fde - header_va) for pc, fde in all_entries)
    header_at = rx['p_offset'] + header_va - rx['p_vaddr']
    result.extend(bytes(header_at - len(result)))
    result.extend(header)
    result.extend(bytes((-len(result)) % 8))
    ph = image['e_phoff'] + rxid * image['e_phentsize']
    length = len(result) - rx['p_offset']
    struct.pack_into('<QQ', result, ph + 32, length, length)
    eh_ph = image['e_phoff'] + ehid * image['e_phentsize']
    struct.pack_into('<QQQQQ', result, eh_ph + 8, header_at, header_va, header_va, len(header), len(header))
    note = image.get_section_by_name('.note.gnu.build-id')['sh_offset'] + 16
    slot = manifest['helper']['keySlotOffset']
    result[note:note + 20] = bytes(20)
    normalized = bytearray(result)
    normalized[slot:slot + 4096] = bytes(4096)
    build_id = hashlib.sha1(normalized).digest()
    result[note:note + 20] = normalized[note:note + 20] = build_id
    allowed = [(at, at + 4), (ph + 32, ph + 48), (eh_ph + 8, eh_ph + 48), (note, note + 20)]
    assert all(x == y or any(lo <= i < hi for lo, hi in allowed)
               for i, (x, y) in enumerate(zip(original, result)))
    assert result[slot:slot + 4096] == original[slot:slot + 4096]
    final = ELFFile(io.BytesIO(result))
    for name in ('.eh_frame', '.eh_frame_hdr', '.dynamic', '.rela.dyn', '.rela.plt', '.dynsym'):
        assert final.get_section_by_name(name).data() == image.get_section_by_name(name).data()
    extension = linked.get_section_by_name('.extension')
    symbols = {s.name: s['st_value'] for s in linked.get_section_by_name('.symtab').iter_symbols()
               if s.name.startswith('maplesu_')}
    for name in ('maplesu_read', 'maplesu_metadata'):
        assert symbols[name + '_template_end'] - symbols[name + '_template'] <= 512
    candidate_path = out / 'candidate-helper.elf'
    candidate_path.write_bytes(result)
    replay_path = out / 'helper-read-replay.json'
    if not args.build_only:
        subprocess.run([sys.executable, str(ROOT / 'scripts/tests/test-ultra-helper-kernel-read.py'),
                        '--helper', str(candidate_path), '--out', str(replay_path)], check=True)
    sources = [source / name for name in ('helper_kernel_read.cpp', 'helper_kernel_read.S', 'kernel_read_metadata.h')]
    sources += [Path(__file__).resolve(), ROOT / 'scripts/tests/test-ultra-helper-kernel-read.py']
    report = dict(schemaVersion=1, baselineHelperSha256=PIN, helperSha256=sha(result),
        helperNormalizedSha256=sha(normalized), helperBuildId=build_id.hex(), helperBytes=len(result),
        entryPatch=dict(offset=at, baselineHex=original[at:at + 4].hex(), candidateHex=branch.hex()),
        extension=dict(address=extension['sh_addr'], offset=rx['p_offset'] + extension['sh_addr'] - rx['p_vaddr'],
                       bytes=extension['sh_size'], sha256=sha(extension.data())), symbols=symbols,
        apiBoundaries={name: dict(address=row[0], bytes=row[1], sha256=row[2]) for name, row in APIS.items()},
        keySlotPreserved=True, dynamicMetadataPreserved=True, oldExecutableRangesPreserved=True,
        requestCredentialIsolationPreserved=True,
        originalUnwindEntriesPreserved=len(old_entries), addedUnwindEntries=len(new_entries),
        productionInputsModified=False, deviceRequests=False,
        sources={p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in sources})
    if replay_path.exists() and not args.build_only:
        replay = json.loads(replay_path.read_text())
        assert replay['passed'] and replay['helperSha256'] == report['helperSha256']
        report['callbackReplay'] = dict(path=replay_path.relative_to(ROOT).as_posix(), sha256=sha(replay_path.read_bytes()))
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS independent helper candidate built; existing API code, key slot and unwind ranges preserved')


if __name__ == '__main__':
    main()
