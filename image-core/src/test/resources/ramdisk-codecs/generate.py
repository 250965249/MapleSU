"""Run with pinned Docker image, --pull never --network none; no third-party Python modules."""
import ctypes as C
import ctypes.util
import hashlib
import json
import lzma
from pathlib import Path
import struct
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parent
IMAGE = 'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e'
sha = lambda data: hashlib.sha256(data).hexdigest()
files = {}

def save(name, data, **metadata):
    (ROOT / name).write_bytes(data)
    files[name] = dict(bytes=len(data), sha256=sha(data), **metadata)

def entry(name, body, inode, mode):
    name = name.encode() + b'\0'
    fields = (inode, mode, 0, 0, 1, 0, len(body), 0, 0, 0, 0, len(name), 0)
    result = b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + name
    result += bytes(-len(result) % 4)
    return result + body + bytes(-len(body) % 4)

raw = (entry('init', b'stock-android-init', 1, 0o100755)
       + entry('system/bin/sh', b'stock-shell', 2, 0o100755)
       + entry('TRAILER!!!', b'', 0, 0))
save('stock.cpio', raw)
listing = subprocess.run(['cpio', '-itv', '--quiet'], input=raw, capture_output=True, check=True).stdout.decode()
assert len(listing.splitlines()) == 2 and all(line.startswith('-rwxr-xr-x') for line in listing.splitlines())
for name, body in (('init', b'stock-android-init'), ('system/bin/sh', b'stock-shell')):
    assert subprocess.run(['cpio', '-i', '--to-stdout', '--quiet', name], input=raw,
                          capture_output=True, check=True).stdout == body
cpio_version = subprocess.run(['cpio', '--version'], capture_output=True, check=True).stdout.decode().splitlines()[0]

lib = C.CDLL(ctypes.util.find_library('lz4'))
lib.LZ4_versionString.restype = C.c_char_p
lib.LZ4F_isError.argtypes, lib.LZ4F_isError.restype = [C.c_size_t], C.c_uint
lib.LZ4F_getErrorName.argtypes, lib.LZ4F_getErrorName.restype = [C.c_size_t], C.c_char_p

def checked(value):
    if lib.LZ4F_isError(value):
        raise RuntimeError(lib.LZ4F_getErrorName(value).decode())
    return value

class Frame(C.Structure):
    _fields_ = [(n, t) for n, t in (
        ('blockSizeID', C.c_int), ('blockMode', C.c_int), ('contentChecksumFlag', C.c_int),
        ('frameType', C.c_int), ('contentSize', C.c_ulonglong), ('dictID', C.c_uint),
        ('blockChecksumFlag', C.c_int))]

class Preferences(C.Structure):
    _fields_ = [('frameInfo', Frame), ('compressionLevel', C.c_int), ('autoFlush', C.c_uint),
                ('favorDecSpeed', C.c_uint), ('reserved', C.c_uint * 3)]

lib.LZ4F_compressFrameBound.argtypes = [C.c_size_t, C.POINTER(Preferences)]
lib.LZ4F_compressFrameBound.restype = C.c_size_t
lib.LZ4F_compressFrame.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t, C.POINTER(Preferences)]
lib.LZ4F_compressFrame.restype = C.c_size_t
lib.LZ4F_createDecompressionContext.argtypes = [C.POINTER(C.c_void_p), C.c_uint]
lib.LZ4F_createDecompressionContext.restype = C.c_size_t
lib.LZ4F_decompress.argtypes = [C.c_void_p, C.c_void_p, C.POINTER(C.c_size_t),
                              C.c_void_p, C.POINTER(C.c_size_t), C.c_void_p]
lib.LZ4F_decompress.restype = C.c_size_t
lib.LZ4F_freeDecompressionContext.argtypes = [C.c_void_p]
lib.LZ4F_freeDecompressionContext.restype = C.c_size_t

for checks in (False, True):
    prefs = Preferences()
    prefs.frameInfo = Frame(4, 1, int(checks), 0, len(raw), 0, int(checks))
    capacity = checked(lib.LZ4F_compressFrameBound(len(raw), C.byref(prefs)))
    output = C.create_string_buffer(capacity)
    size = checked(lib.LZ4F_compressFrame(output, capacity, raw, len(raw), C.byref(prefs)))
    encoded = output.raw[:size]
    context = C.c_void_p()
    checked(lib.LZ4F_createDecompressionContext(C.byref(context), 100))
    try:
        decoded = C.create_string_buffer(len(raw) + 1)
        out_size, in_size = C.c_size_t(len(raw) + 1), C.c_size_t(size)
        hint = checked(lib.LZ4F_decompress(context, decoded, C.byref(out_size),
                                         encoded, C.byref(in_size), None))
        assert hint == 0 and in_size.value == size and decoded.raw[:out_size.value] == raw
    finally:
        checked(lib.LZ4F_freeDecompressionContext(context))
    flag = encoded[4]
    size_at = 7 + (8 if flag & 8 else 0) + (4 if flag & 1 else 0)
    block = struct.unpack_from('<I', encoded, size_at)[0]
    assert block and not block & 0x80000000
    block_size = block & 0x7fffffff
    check_at = size_at + 4 + block_size
    end_at = check_at + (4 if flag & 16 else 0)
    assert encoded[end_at:end_at + 4] == bytes(4)
    content_at = end_at + 4 if flag & 4 else None
    assert (content_at + 4 if content_at is not None else end_at + 4) == size
    save('stock-checksums.cpio.lz4' if checks else 'stock.cpio.lz4', encoded,
         oracle='liblz4.LZ4F_decompress', roundTrip=True, firstBlockSizeOffset=size_at,
         firstBlockDataOffset=size_at + 4, firstBlockSize=block_size, firstBlockType='compressed',
         blockChecksumOffset=check_at if flag & 16 else None, contentChecksumOffset=content_at)

def vli(data, position):
    value, shift = 0, 0
    while True:
        byte = data[position]
        position += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, position
        shift += 7

def crc64(data):
    value = 0xffffffffffffffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0xc96c5795d7870f42 if value & 1 else 0)
    return struct.pack('<Q', value ^ 0xffffffffffffffff)

for name, check, checksum in (
        ('crc32', lzma.CHECK_CRC32, struct.pack('<I', zlib.crc32(raw))),
        ('crc64', lzma.CHECK_CRC64, crc64(raw)),
        ('sha256', lzma.CHECK_SHA256, hashlib.sha256(raw).digest())):
    encoded = lzma.compress(raw, format=lzma.FORMAT_XZ, check=check, preset=6)
    assert lzma.decompress(encoded, format=lzma.FORMAT_XZ) == raw
    index_at = len(encoded) - 12 - (struct.unpack_from('<I', encoded, len(encoded) - 8)[0] + 1) * 4
    assert encoded[index_at] == 0
    records, pos = vli(encoded, index_at + 1)
    unpadded, pos = vli(encoded, pos)
    original_size, pos = vli(encoded, pos)
    assert records == 1 and original_size == len(raw)
    header_size = (encoded[12] + 1) * 4
    check_at = 12 + (unpadded + 3) // 4 * 4 - len(checksum)
    assert check_at + len(checksum) == index_at and encoded[check_at:index_at] == checksum
    assert encoded[12 + header_size] >= 128  # genuinely compressed LZMA2 chunk
    save('stock-' + name + '.cpio.xz', encoded, oracle='python.lzma.decompress', roundTrip=True,
         blockCount=1, blockHeaderOffset=12, blockHeaderSize=header_size,
         compressedDataBytes=unpadded - header_size - len(checksum),
         firstLzma2Control=encoded[12 + header_size], blockCheck=name,
         blockCheckOffset=check_at, blockCheckBytes=len(checksum), indexOffset=index_at,
         independentlyComputedBlockCheck=True)

xzlib = C.CDLL(ctypes.util.find_library('lzma'))
xzlib.lzma_version_string.restype = C.c_char_p
receipt = dict(schemaVersion=1, image=IMAGE, network='none', pull='never',
    generator=dict(file='generate.py', sha256=sha(Path(__file__).read_bytes())),
    versions=dict(python=sys.version.split()[0], liblz4=lib.LZ4_versionString().decode(),
                  liblzma=xzlib.lzma_version_string().decode(), cpio=cpio_version),
    cpio=dict(format='newc', uid=0, gid=0, mtime=0, regularMode='0100755',
              entries={'init':'stock-android-init', 'system/bin/sh':'stock-shell'}, trailer='TRAILER!!!',
              oracle='GNU cpio list and extract-to-stdout', listing=listing, oracleVerified=True),
    files=files, productionJavaUsed=False, sdkUsed=False, deviceUsed=False)
(ROOT / 'receipt.json').write_text(json.dumps(receipt, separators=(',', ':')) + '\n', encoding='utf-8')
print(json.dumps(dict(files=len(files), fixtureBytes=sum(f['bytes'] for f in files.values()),
                     versions=receipt['versions'], roundTrip=True)))
