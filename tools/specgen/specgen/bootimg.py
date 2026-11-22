"""Android boot v0-v4 container: read the kernel back out, and (optionally) rebuild.

Only what the spec generator needs:

  * ``inspect``  - the header fields ``BootImageInspector`` reports for the fields we use;
  * ``kernel``   - the *decoded* raw ARM64 kernel, because every recipe site is a file offset
                   inside the decompressed image;
  * ``rebuild``  - not implemented here. The applier owns the container rebuild, so the
                   self-check delegates it to the shipped ``image-core.jar`` when the caller
                   points at one, and reports SKIP otherwise. Re-implementing it would make
                   the check agree with itself instead of with the applier.

Compression coverage matches the applier's decoders for the formats Python can read natively.
"""
from __future__ import annotations

import gzip
import io
import os
import struct
import zlib

MAX_KERNEL_BYTES = 128 * 1024 * 1024


class BootImageError(ValueError):
    pass


def _load(path) -> bytes:
    with open(path, "rb") as source:
        before = os.fstat(source.fileno())
        if before.st_size > 512 * 1024 * 1024:
            raise BootImageError("BOOT_IMAGE_SIZE_LIMIT")
        data = source.read(before.st_size + 1)
        after = os.fstat(source.fileno())
    if (len(data) != before.st_size or
            (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
        raise BootImageError("BOOT_SOURCE_CHANGED")
    return data


def _inspect(data: bytes) -> dict:
    if len(data) < 44 or data[:8] != b"ANDROID!":
        raise BootImageError("NOT_ANDROID_BOOT")

    def u32(at):
        return struct.unpack_from("<I", data, at)[0]

    header_version = u32(40)
    if header_version > 4:
        raise BootImageError("BOOT_HEADER_UNSUPPORTED")
    minimum = (1632, 1648, 1660, 1580, 1584)[header_version]
    if len(data) < minimum:
        raise BootImageError("BOOT_HEADER_TRUNCATED")
    legacy = header_version < 3
    kernel_size = u32(8)
    ramdisk_size = u32(16 if legacy else 12)
    header_size = (1632 if header_version == 0 else u32(1644)) if legacy else u32(20)
    # Mirrors image-core's BootImageInspector: v3/v4 are always 4096, v0-v2 carry it at 36.
    page_size = u32(36) if legacy else 4096
    if page_size not in (2048, 4096, 8192, 16384):
        raise BootImageError("BOOT_PAGE_SIZE_INVALID:%d" % page_size)
    if len(data) < page_size:
        raise BootImageError("BOOT_HEADER_PAGE_TRUNCATED")
    if header_size < minimum or header_size > page_size:
        raise BootImageError("BOOT_HEADER_SIZE_INVALID")

    def align(value):
        return (value + page_size - 1) // page_size * page_size

    def region(offset, size):
        if size and (offset > len(data) or size > len(data) - offset):
            raise BootImageError("BOOT_COMPONENT_OUT_OF_RANGE")

    kernel_offset = page_size
    ramdisk_offset = align(kernel_offset + kernel_size)
    second_offset = align(ramdisk_offset + ramdisk_size) if legacy else 0
    second_size = u32(24) if legacy else 0
    after_second = align(second_offset + second_size) if legacy else align(ramdisk_offset + ramdisk_size)
    dtbo_size = u32(1632) if 0 < header_version < 3 else 0
    dtbo_offset = struct.unpack_from("<Q", data, 1636)[0] if 0 < header_version < 3 else 0
    if 0 < header_version < 3 and dtbo_offset != (after_second if dtbo_size else 0):
        raise BootImageError("BOOT_RECOVERY_DTBO_OFFSET_INVALID")
    dtb_size = u32(1648) if header_version == 2 else 0
    dtb_offset = align(after_second + dtbo_size) if header_version == 2 else 0
    signature_size = u32(1580) if header_version == 4 else 0
    signature_offset = align(ramdisk_offset + ramdisk_size) if not legacy else 0
    for offset, size in ((kernel_offset, kernel_size), (ramdisk_offset, ramdisk_size),
                         (second_offset, second_size), (dtbo_offset, dtbo_size),
                         (dtb_offset, dtb_size), (signature_offset, signature_size)):
        region(offset, size)
    return {
        "fileSize": len(data),
        "headerVersion": header_version,
        "headerSize": header_size,
        "pageSize": page_size,
        "kernelOffset": kernel_offset,
        "kernelSize": kernel_size,
        "ramdiskOffset": ramdisk_offset,
        "ramdiskSize": ramdisk_size,
        "secondOffset": second_offset,
        "secondSize": second_size,
        "recoveryDtboOffset": dtbo_offset,
        "recoveryDtboSize": dtbo_size,
        "dtbOffset": dtb_offset,
        "dtbSize": dtb_size,
        "signatureOffset": signature_offset,
        "signatureSize": signature_size,
    }


def inspect(path) -> dict:
    return _inspect(_load(path))


def kernel_container(path) -> bytes:
    data = _load(path)
    report = _inspect(data)
    if not report["kernelSize"]:
        raise BootImageError("BOOT_KERNEL_MISSING:EXTERNAL_TARGET_REQUIRED")
    return data[report["kernelOffset"]:report["kernelOffset"] + report["kernelSize"]]


def kernel(path) -> bytes:
    """The decoded raw ARM64 Image inside a boot image."""
    container = kernel_container(path)
    return decode(container)


def decode(container: bytes) -> bytes:
    if len(container) > 60 and container[56:60] == b"ARMd":
        if len(container) > MAX_KERNEL_BYTES:
            raise BootImageError("KERNEL_RAW_DECODE_LIMIT")
        return container
    if container[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(container)) as source:
                raw = source.read(MAX_KERNEL_BYTES + 1)
        except (OSError, EOFError, zlib.error) as error:
            raise BootImageError("KERNEL_GZIP_INVALID:%s" % error)
        if len(raw) > MAX_KERNEL_BYTES:
            raise BootImageError("KERNEL_GZIP_DECODE_LIMIT")
        if raw[56:60] != b"ARMd":
            raise BootImageError("KERNEL_NOT_RAW_ARM64")
        return raw
    if container[:4] == b"\x02\x21\x4c\x18":
        try:
            import lz4.block
        except ImportError as error:
            raise BootImageError("KERNEL_LZ4_DECODER_REQUIRED:python-lz4") from error
        blocks, position, decoded_size = [], 4, 0
        block_limit, kernel_limit = 8 * 1024 * 1024, MAX_KERNEL_BYTES
        while position < len(container):
            if len(container) - position < 4:
                raise BootImageError("KERNEL_LZ4_TRUNCATED_HEADER")
            size = struct.unpack_from("<I", container, position)[0]
            position += 4
            if not size or size > block_limit + block_limit // 255 + 16 or size > len(container) - position:
                raise BootImageError("KERNEL_LZ4_INVALID_BLOCK_SIZE")
            try:
                block = lz4.block.decompress(container[position:position + size],
                                             uncompressed_size=block_limit)
            except lz4.block.LZ4BlockError as error:
                raise BootImageError("KERNEL_LZ4_INVALID_BLOCK") from error
            decoded_size += len(block)
            if decoded_size > kernel_limit:
                raise BootImageError("KERNEL_LZ4_DECODE_LIMIT")
            blocks.append(block)
            position += size
        raw = b"".join(blocks)
        if raw[56:60] != b"ARMd":
            raise BootImageError("KERNEL_NOT_RAW_ARM64")
        return raw
    if container[:4] == b"\x28\xb5\x2f\xfd":
        raise BootImageError("KERNEL_ZSTD_UNSUPPORTED")
    if container[:4] == b"\x04\x22\x4d\x18":
        raise BootImageError("KERNEL_LZ4_FRAME_UNSUPPORTED")
    raise BootImageError("KERNEL_COMPRESSION_UNKNOWN")


def encode(raw: bytes, like: bytes) -> bytes:
    """Re-encode a decoded kernel the way ``like`` was stored (raw or gzip only)."""
    if len(like) > 60 and like[56:60] == b"ARMd":
        return raw
    if like[:2] == b"\x1f\x8b":
        return gzip.compress(raw, mtime=0)
    raise BootImageError("KERNEL_COMPRESSION_UNKNOWN")


def gzip_compress(raw: bytes) -> bytes:
    return zlib.compress(raw)
