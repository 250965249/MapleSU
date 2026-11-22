"""Independent compressed-block vectors from CPython's libzstd, without production Java code."""
from compression import zstd
import hashlib
import json
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parent
P = zstd.CompressionParameter
files = {}


def save(name, data, **metadata):
    (ROOT / name).write_bytes(data)
    files[name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), **metadata)


def blocks(data):
    descriptor = data[4]
    fcs = [1 if descriptor & 32 else 0, 2, 4, 8][descriptor >> 6]
    position = 5 + (0 if descriptor & 32 else 1) + [0,1,2,4][descriptor & 3] + fcs
    result = []
    while True:
        header = int.from_bytes(data[position:position + 3], 'little'); position += 3
        size, kind = header >> 3, (header >> 1) & 3
        result.append(dict(type=kind, encodedSize=size,
                           literalsType=(data[position] & 3) if kind == 2 else None))
        position += 1 if kind == 1 else size
        if header & 1:
            break
    return result


def frame(name, raw, **options):
    encoded = zstd.compress(raw, options={P.checksum_flag:1, **{P[k]:v for k,v in options.items()}})
    assert zstd.decompress(encoded) == raw
    profile = blocks(encoded)
    assert any(b['type'] == 2 for b in profile), name
    save(name, encoded, blocks=profile)
    return encoded


raw = (ROOT.parent / 'kernel-streams/arm64.raw').read_bytes()
save('kernel.raw', raw)
for level in (1,3,19):
    frame('kernel-' + str(level) + '.zst', raw, compression_level=level)
frame('kernel-unknown.zst', raw, compression_level=3, content_size_flag=0)
wide = bytearray(zstd.compress(raw, options={P.checksum_flag:1, P.content_size_flag:0}))
assert not wide[4] & 32
wide[5] = (27 - 10) << 3
assert zstd.decompress(wide) == raw
save('kernel-window27.zst', wide, declaredWindowBytes=1 << 27, blocks=blocks(wide))
first = frame('first.zst', raw[:1001], compression_level=9)
second = frame('second.zst', raw[1001:], compression_level=5)
skip = bytes.fromhex('502a4d1803000000010203')
save('kernel-concat.zst', first + skip + second, frames=2, skippable=True)
rng = random.Random(20261116)
multi = bytearray(raw)
for i in range(9):
    multi += raw if i % 3 != 0 else bytes(rng.randrange(17) for _ in range(len(raw)))
save('multi.raw', multi)
frame('multi.zst', multi, compression_level=9, window_log=21)
frame('multi-unknown.zst', multi, compression_level=19, content_size_flag=0)
text = b''.join((b'Linux version sample row %d compression literals statistics %d\n' % (i % 97, i % 31)) for i in range(7000))
save('text.raw', text)
frame('text.zst', text, compression_level=5)
tiny = b'A' * 10
save('rle-literals.raw', tiny)
checksum = zstd.compress(tiny, options={P.checksum_flag:1})[-4:]
rle = bytes.fromhex('28b52ffd240a1d0000514100') + checksum
assert zstd.decompress(rle) == tiny
save('rle-literals.zst', rle, blocks=blocks(rle))
receipt = dict(schema='maplesu-libzstd-compressed-fixtures/1', pythonModule=zstd.__file__,
               libzstdVersion=zstd.zstd_version, productionJavaUsed=False,
               generatorSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), files=files)
(ROOT / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
print('independent libzstd ' + zstd.zstd_version + ': ' + str(len(files)) + ' files')
