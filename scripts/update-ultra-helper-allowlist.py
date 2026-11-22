"""Build an independent pinned helper allowlist-lifetime correction."""
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
PIN = '7a05bc7461413a1725606ee779e9c6b1618cd01cc87a10fb32315cb97801d6e0'
OUT_ROOT = ROOT / 'work/panic-implementation-20261114/native-audit/helper-candidate'
EXPECTED = {
    0xf5130: '60f9ffd000fc3591eb040094c00000b4c62cff97f60300aaa01500b5e0031faade040094',
    0xf517c: 'e8c340f9',
    0xf5eec: '80f9ff90',
}
sha = lambda data: hashlib.sha256(data).hexdigest()


def branch(source, target, link=False):
    delta = target - source
    assert delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27)
    return struct.pack('<I', (0x94000000 if link else 0x14000000) | ((delta // 4) & 0x3ffffff))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=OUT_ROOT)
    args = parser.parse_args()
    out = args.out.resolve()
    assert out == OUT_ROOT or out.is_relative_to(OUT_ROOT), 'Use dedicated candidate output'
    assert not out.exists() or not any(out.iterdir()), 'Use fresh candidate output'
    original_path = ROOT / 'runtime/maplesu-sdk/helper/autorun_bootstrap'
    original = original_path.read_bytes()
    assert sha(original) == PIN, 'Pinned helper changed'
    image = ELFFile(io.BytesIO(original))
    loads = [(i, s) for i, s in enumerate(image.iter_segments()) if s['p_type'] == 'PT_LOAD']
    rxid, rx = max(loads, key=lambda item: item[1]['p_vaddr'])
    assert image['e_type'] == 'ET_DYN' and rx['p_flags'] == 5
    extension_va = (rx['p_vaddr'] + max(rx['p_memsz'], len(original) - rx['p_offset']) + 15) & ~15
    extension_at = rx['p_offset'] + extension_va - rx['p_vaddr']
    assert extension_at >= len(original)

    def offset(address):
        return next(s['p_offset'] + address - s['p_vaddr'] for _, s in loads
                    if s['p_vaddr'] <= address < s['p_vaddr'] + s['p_filesz'])

    for address, expected in EXPECTED.items():
        at = offset(address)
        assert original[at:at + len(bytes.fromhex(expected))] == bytes.fromhex(expected), hex(address)
    # Clear the obsolete retirement record without freeing a published snapshot.
    # Its write error must take the original function's existing cleanup path.
    prepare = bytes.fromhex('e0031faa') + branch(0xf5134, 0xf64c8, True) + bytes.fromhex('f60300aa')
    delta = 0xf53fc - 0xf513c
    prepare += struct.pack('<I', 0xb5000000 | ((delta // 4) << 5))
    prepare += branch(0xf5140, 0xf5154) + bytes.fromhex('1f2003d5') * 4
    assert len(prepare) == 36
    # This continuation uses the original caller's frame and cleanup machinery.
    # It adds no stack frame, relocations, globals, or dynamic/unwind metadata.
    empty = branch(extension_va, 0xf64d8, True)
    empty += struct.pack('<I', 0xb4000000 | (5 << 5))  # cbz x0, missing-control
    empty += bytes.fromhex('e1031faa')
    empty += branch(extension_va + 12, 0xc082c, True)
    empty += bytes.fromhex('f60300aa')
    empty += branch(extension_va + 20, 0xf5f0c)
    empty += bytes.fromhex('16ba8992')  # original ERR_MODULE_UID_PP_ADDR_NOT_FOUND
    empty += branch(extension_va + 28, 0xf5f0c)
    patches = {0xf5130: prepare, 0xf517c: branch(0xf517c, 0xf51a0),
               0xf5eec: branch(0xf5eec, extension_va)}
    result = bytearray(original)
    for address, replacement in patches.items():
        at = offset(address)
        result[at:at + len(replacement)] = replacement
    result.extend(bytes(extension_at - len(result)) + empty)
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
    allowed = [(offset(address), offset(address) + len(replacement)) for address, replacement in patches.items()]
    allowed += [(ph + 32, ph + 48), (note, note + 20)]
    assert all(a == b or any(lo <= i < hi for lo, hi in allowed)
               for i, (a, b) in enumerate(zip(original, result)))
    assert result[slot:slot + 4096] == original[slot:slot + 4096]
    final = ELFFile(io.BytesIO(result))
    for section in image.iter_sections():
        updated = final.get_section_by_name(section.name)
        assert updated.header == section.header, section.name
        assert all(a == b or any(lo <= section['sh_offset'] + i < hi for lo, hi in allowed)
                   for i, (a, b) in enumerate(zip(section.data(), updated.data()))), section.name
    for name in ('.dynamic', '.rela.dyn', '.rela.plt', '.dynsym', '.eh_frame', '.eh_frame_hdr', '.gcc_except_table'):
        assert final.get_section_by_name(name).data() == image.get_section_by_name(name).data(), name
    assert original_path.read_bytes() == original
    out.mkdir(parents=True, exist_ok=True)
    candidate = out / 'candidate-helper.elf'
    candidate.write_bytes(result)
    replay = out / 'allowlist-replay.json'
    subprocess.run([sys.executable, str(ROOT / 'scripts/tests/test-ultra-helper-allowlist.py'),
                    '--helper', str(candidate), '--out', str(replay)], check=True)
    report = dict(schemaVersion=1, baselineHelperSha256=PIN, helperSha256=sha(result),
        helperNormalizedSha256=sha(normalized), helperBuildId=build_id.hex(), helperBytes=len(result),
        patches=[dict(address=hex(address), offset=offset(address),
                      baselineHex=original[offset(address):offset(address)+len(replacement)].hex(),
                      candidateHex=replacement.hex()) for address, replacement in patches.items()],
        extension=dict(address=hex(extension_va), offset=extension_at, bytes=len(empty), sha256=sha(empty)),
        keySlotPreserved=True, originalSectionsWhitelistVerified=True, dynamicMetadataPreserved=True,
        originalUnwindMetadataPreserved=True, existingFixesPreserved=True, productionInputsModified=False,
        callbackReplay=dict(path=replay.relative_to(ROOT).as_posix(), sha256=sha(replay.read_bytes())),
        causality='Helper initialization clears old control and retirement keys before this writer. '
                  'This fixes its stale writer lifecycle coverage, but does not establish the current NX panic cause.',
        sources={p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in
                 (Path(__file__).resolve(), ROOT / 'scripts/tests/test-ultra-helper-allowlist.py')})
    (out / 'build.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print('PASS pinned independent helper allowlist candidate:', report['helperSha256'])


if __name__ == '__main__':
    main()
