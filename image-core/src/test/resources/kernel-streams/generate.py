"""Independent fixtures: run in the pinned ramdisk-codecs image with --network none --pull never."""
import ctypes as C
import ctypes.util
import hashlib
import json
import lzma
from pathlib import Path
import random
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
IMAGE = 'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e'
files = {}


def save(name, data, **metadata):
    (ROOT / name).write_bytes(data)
    files[name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), **metadata)


def xz(raw, *options):
    result = subprocess.run(['xz', '--threads=1', '--check=crc32', '--stdout', *options],
                            input=raw, capture_output=True, check=True).stdout
    assert lzma.decompress(result) == raw
    return result


raw = bytearray(131101)
rng = random.Random(20261116)
for offset in range(256, len(raw) - 3, 4):
    if 1024 <= offset < 1100 or 2048 <= offset < 2304:
        continue
    instruction = rng.getrandbits(32)
    if offset % 12 == 0:
        instruction = 0x94000000 | (instruction & 0x03ffffff)
    elif offset % 12 == 4:
        page = rng.choice([0,1,0x1ffff,0x20000,0x1dffff,0x1e0000,0x1fffff])
        instruction = 0x90000000 | ((page & 3) << 29) | ((page & 0x1ffffc) << 3) | (offset & 31)
    struct.pack_into('<I', raw, offset, instruction)
raw[56:60] = b'ARMd'
banner = b'Linux version 6.6.89-tail-fixture (test)'
raw[128:128 + len(banner)] = banner
raw[-1] = 0x5a
save('arm64.raw', bytes(raw))
for start in (0, 0x1000, 0xfffffffc):
    encoded = xz(raw, '--arm64=start=' + str(start), '--lzma2=dict=1MiB')
    save('arm64-' + str(start) + '.xz', encoded, filters=['arm64', 'lzma2'], startOffset=start)
save('arm64-blocks.xz', xz(raw, '--block-size=1001', '--arm64', '--lzma2=dict=1MiB'),
     filters=['arm64', 'lzma2'], blocks=True)
save('delta.xz', xz(raw, '--delta=dist=256', '--lzma2=dict=1MiB'), filters=['delta:256', 'lzma2'])
save('arm64-delta.xz', xz(raw, '--arm64', '--delta=dist=4', '--lzma2=dict=1MiB'),
     filters=['arm64', 'delta:4', 'lzma2'])
save('four-filters.xz', xz(raw, '--delta=dist=256', '--arm64', '--delta=dist=4', '--lzma2=dict=1MiB'),
     filters=['delta:256', 'arm64', 'delta:4', 'lzma2'])
for check in ('crc64', 'sha256'):
    save('arm64-' + check + '.xz', xz(raw, '--check=' + check, '--arm64', '--lzma2=dict=1MiB'),
         filters=['arm64', 'lzma2'], check=check)
save('plain-blocks.xz', xz(raw, '--block-size=1001', '--lzma2=dict=1MiB'), blocks=True)
first, second = bytes(raw[:1001]), bytes(raw[1001:])
save('concat.xz', xz(first) + bytes(8) + xz(second), streams=2, padding=8)

lib = C.CDLL(ctypes.util.find_library('lz4'))
lib.LZ4_versionString.restype = C.c_char_p
lib.LZ4F_isError.argtypes, lib.LZ4F_isError.restype = [C.c_size_t], C.c_uint
lib.LZ4F_compressFrameBound.argtypes, lib.LZ4F_compressFrameBound.restype = [C.c_size_t, C.c_void_p], C.c_size_t
lib.LZ4F_compressFrame.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p]
lib.LZ4F_compressFrame.restype = C.c_size_t
lib.LZ4F_createDecompressionContext.argtypes = [C.POINTER(C.c_void_p), C.c_uint]
lib.LZ4F_createDecompressionContext.restype = C.c_size_t
lib.LZ4F_decompress.argtypes = [C.c_void_p, C.c_void_p, C.POINTER(C.c_size_t),
                              C.c_void_p, C.POINTER(C.c_size_t), C.c_void_p]
lib.LZ4F_decompress.restype = C.c_size_t
lib.LZ4F_freeDecompressionContext.argtypes = [C.c_void_p]


def checked(value):
    assert not lib.LZ4F_isError(value), value
    return value


def lz4(raw):
    bound = checked(lib.LZ4F_compressFrameBound(len(raw), None))
    dest = C.create_string_buffer(bound)
    length = checked(lib.LZ4F_compressFrame(dest, bound, raw, len(raw), None))
    encoded = dest.raw[:length]
    context = C.c_void_p()
    checked(lib.LZ4F_createDecompressionContext(C.byref(context), 100))
    output = C.create_string_buffer(len(raw) + 1)
    produced, consumed = C.c_size_t(len(output)), C.c_size_t(len(encoded))
    try:
        assert checked(lib.LZ4F_decompress(context, output, C.byref(produced), encoded,
                                          C.byref(consumed), None)) == 0
        assert consumed.value == len(encoded) and output.raw[:produced.value] == raw
    finally:
        lib.LZ4F_freeDecompressionContext(context)
    return encoded


skip = bytes.fromhex('502a4d1803000000010203')
save('concat.lz4', lz4(first) + skip + lz4(second), streams=2, skippable=True)
receipt = dict(schema='maplesu-independent-kernel-streams/1', image=IMAGE, network='none', pull='never',
               generatorSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               versions=dict(xz=subprocess.run(['xz', '--version'], capture_output=True, check=True).stdout.decode().strip(),
                             liblz4=lib.LZ4_versionString().decode()), files=files,
               oracle='liblzma via xz + Python lzma; liblz4 frame encode/decode', productionJavaUsed=False)
(ROOT / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
print(json.dumps(receipt))
