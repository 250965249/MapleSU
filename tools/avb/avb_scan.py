"""Detect and classify the AVB surface of an OPPO/OnePlus boot image.

This tool *detects* and *advises*; it never signs, never writes an image and never
touches a device. The strategy text it prints is a recommendation keyed to what
the image actually contains. Digest matches describe the inspected bytes;
they do not establish a device boot result.

What it reports per image:

  footer      `AVBf` at the tail (big endian): version, original_image_size,
              vbmeta_offset, vbmeta_size - plus whether the hash descriptor's
              covered region actually contains the kernel.
  vbmeta      `AVB0` header at `vbmeta_offset` (or found by scanning, which is
              recorded as a weaker detection): algorithm, flags, rollback index,
              public-key fingerprint, descriptor list.
  coverage    whether original_image_size reaches past the kernel, i.e. whether a
              single patched kernel byte invalidates the descriptor.
  digest      an attempt to reproduce the hash descriptor's digest under the
              AOSP layout and two vendor variants. A miss is a finding, not an
              error: it means "re-sign it ourselves" is not a known-good route.

Usage:
  avb_scan.py --boot boot.img [--kernel kernel.bin|--kernel-range off:size]
              [--json out.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

AVB_MAGIC = b"AVB0"
FOOTER_MAGIC = b"AVBf"
AVB_ALGORITHMS = {0: "NONE", 1: "SHA256_RSA2048", 2: "SHA256_RSA4096", 3: "SHA256_RSA8192"}
DESCRIPTOR_TAGS = {0: "property", 1: "hashtree", 2: "hash", 3: "kernel_cmdline",
                   4: "chain_partition"}
# AvbVBMetaImageHeader.flags
FLAG_HASHTREE_DISABLED = 1
FLAG_VERIFICATION_DISABLED = 2
KCFI_TRAP = 0xD4304440


def be32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def be64(data: bytes, offset: int) -> int:
    return struct.unpack_from(">Q", data, offset)[0]


def printable(data: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in data)


def find_footer(image: bytes) -> dict:
    """`AVBf` at the very tail, or reported absent (no guessing)."""
    if image[-64:-60] == FOOTER_MAGIC:
        footer = image[-64:]
        return {
            "present": True,
            "foundAt": "tail",
            "version": "%d.%d" % (be32(footer, 4), be32(footer, 8)),
            "original_image_size": be64(footer, 12),
            "vbmeta_offset": be64(footer, 20),
            "vbmeta_size": be64(footer, 28),
        }
    return {"present": False, "reason": "last 64 bytes do not start with AVBf"}


def parse_vbmeta(blob: bytes) -> dict:
    if blob[:4] != AVB_MAGIC:
        return {"present": False, "reason": "no AVB0 magic at the footer offset"}
    auth_size = be64(blob, 12)
    aux_size = be64(blob, 20)
    algorithm = be32(blob, 28)
    record = {
        "present": True,
        "required_libavb_version": "%d.%d" % (be32(blob, 4), be32(blob, 8)),
        "authentication_data_block_size": auth_size,
        "auxiliary_data_block_size": aux_size,
        "algorithm": AVB_ALGORITHMS.get(algorithm, algorithm),
        "hash_size": be64(blob, 40),
        "signature_size": be64(blob, 56),
        "public_key_size": be64(blob, 72),
        "descriptors_size": be64(blob, 104),
        "rollback_index": be64(blob, 112),
        "flags": be32(blob, 120),
        "rollback_index_location": be32(blob, 124),
        "release_string": printable(blob[128:176].split(b"\x00")[0]),
        "public_key_sha256": hashlib.sha256(
            blob[256 + be64(blob, 64):256 + be64(blob, 64) + be64(blob, 72)]).hexdigest(),
    }
    record["verification_disabled"] = bool(record["flags"] & FLAG_VERIFICATION_DISABLED)
    record["hashtree_disabled"] = bool(record["flags"] & FLAG_HASHTREE_DISABLED)

    auth_start = 256
    aux_start = 256 + auth_size
    desc_offset, desc_size = be64(blob, 96), be64(blob, 104)
    cursor = aux_start + desc_offset
    end = cursor + desc_size
    descriptors = []
    while cursor + 16 <= end:
        tag, following = be64(blob, cursor), be64(blob, cursor + 8)
        body = blob[cursor + 16:cursor + 16 + following]
        item = {"tag": DESCRIPTOR_TAGS.get(tag, "unknown(%d)" % tag),
                "numBytesFollowing": following}
        if tag == 2:
            item.update(parse_hash_descriptor(body))
        elif tag == 0:
            key, _, rest = body[8:].partition(b"\x00")
            value = rest.split(b"\x00")[0]
            item.update({"key": printable(key), "value": printable(value)})
        descriptors.append(item)
        cursor += 16 + following
    record["descriptors"] = descriptors
    record["authentication_block"] = {"offset": auth_start, "size": auth_size}
    record["auxiliary_block"] = {"offset": aux_start, "size": aux_size}
    return record


def parse_hash_descriptor(body: bytes) -> dict:
    """Best-effort parse: the field order here is NOT the AOSP one.

    The OPPO images carry `image_size`, `hash_algorithm`, then 4-byte length
    fields, an inline partition name and a trailing digest/salt payload. The
    parser therefore reports what it can prove (image size, algorithm, name,
    payload sizes) and keeps the raw payload hex for the digest check.
    """
    record = {
        "image_size": be64(body, 0),
        "hash_algorithm": body[8:40].split(b"\x00")[0].decode("latin1", "replace"),
        "partition_name_hint": next(
            (printable(body[i:i + 4]) for i in range(0, len(body) - 3, 4)
             if body[i:i + 4].isalpha()), None),
    }
    # Length-like u32s in the header area: (flags?, salt_len, digest_len).
    if len(body) >= 52:
        record["u32@40"], record["u32@44"], record["u32@48"] = struct.unpack_from(">III", body, 40)
    # Trailing payload: the last 48 bytes of these descriptors are 32+16.
    if len(body) >= 48:
        record["payload_tail_bytes"] = 48
        record["digest_candidate"] = body[-48:-16].hex()
        record["salt_candidate"] = body[-16:].hex()
    record["raw_body_hex"] = body.hex()
    return record


def verify_digest(image: bytes, descriptor: dict) -> dict:
    """Try to reproduce the stored digest under the documented layouts."""
    digest_hex = descriptor.get("digest_candidate")
    salt_hex = descriptor.get("salt_candidate")
    size = descriptor.get("image_size") or 0
    if not digest_hex or not size:
        return {"verified": False, "reason": "no digest candidate or image size"}
    digest = bytes.fromhex(digest_hex)
    salt = bytes.fromhex(salt_hex or "")
    data = image[:size]
    attempts = {
        "aosp": hashlib.sha256(salt + data).hexdigest(),
        "trailing-salt": hashlib.sha256(data + salt).hexdigest(),
        "no-salt": hashlib.sha256(data).hexdigest(),
    }
    for name, value in attempts.items():
        if value == digest_hex:
            return {"verified": True, "layout": name, "comparedBytes": size}
    return {
        "verified": False,
        "comparedBytes": size,
        "tried": sorted(attempts),
        "reason": "none of the AOSP/vendor layouts reproduce the stored digest; the "
                  "vendor avbtool writes a descriptor we cannot re-sign reproducibly",
    }


def cfi_hint(kernel: bytes | None) -> dict | None:
    if not kernel:
        return None
    needle = KCFI_TRAP.to_bytes(4, "little")
    traps, start = 0, 0
    while True:
        index = kernel.find(needle, start)
        if index < 0:
            break
        if index % 4 == 0:
            traps += 1
        start = index + 1
    return {"kcfi_traps": traps, "variant": "kcfi" if traps else "cfi-v1-or-none"}


def recommend(report: dict) -> dict:
    """Map the detected state onto one of the documented strategies."""
    vbmeta = report.get("vbmeta") or {}
    footer = report.get("footer") or {}
    coverage = report.get("coverage") or {}
    flags = vbmeta.get("flags")
    if not footer.get("present"):
        return {"strategy": "no-avb", "confidence": "high",
                "detail": "no AVB footer: the partition is not verified by AVB, a patched "
                          "boot image does not invalidate anything",
                "prerequisites": ["unlocked bootloader for flashing"],
                "risks": ["a bootloader-level signature check outside AVB would still apply"],
                "recovery": "flash the pristine boot.img back"}
    if vbmeta.get("verification_disabled"):
        return {"strategy": "already-disabled", "confidence": "high",
                "detail": "vbmeta flags already disable verification (%d); the hash "
                          "descriptor is not enforced at boot" % flags,
                "prerequisites": ["a build of the patch for this exact release"],
                "risks": ["flags can be reset by a vendor OTA"],
                "recovery": "flash the pristine boot.img back"}
    if not coverage.get("kernel_covered"):
        return {"strategy": "unverified-coverage", "confidence": "low",
                "detail": "the hash descriptor does not appear to cover the kernel bytes; "
                          "re-check before assuming a kernel edit is detected",
                "prerequisites": ["manual verification on the device"],
                "risks": ["wrong assumption either way"], "recovery": "flash pristine boot.img"}
    return {
        "strategy": "unlock-and-disable-verification",
        "confidence": "high",
        "detail": "boot carries an enabled AVB hash descriptor (flags=%d, %s) whose "
                  "covered range includes the kernel, so any kernel patch changes the "
                  "hashed bytes. Re-signing is not available: the descriptor layout is "
                  "vendor-specific and the key is OEM-only." % (flags, vbmeta.get("algorithm")),
        "prerequisites": [
            "bootloader unlocked (OEM unlock or the vendor's unlock tool)",
            "verification disabled before flashing: patch the embedded vbmeta flags to "
            "VERIFICATION_DISABLED|HASHTREE_DISABLED, or use the vendor's own "
            "--disable-verification flow if the model has a separate vbmeta partition",
            "pristine boot.img of the exact same build kept for recovery",
        ],
        "risks": [
            "an unsigned vbmeta is only tolerated while the bootloader is unlocked",
            "disabling verification weakens the device's boot integrity for every image, "
            "not just this one",
            "a vendor OTA or a relock restores verification and can leave the device "
            "unbootable until the pristine image is flashed back",
        ],
        "recovery": [
            "fastboot flash boot <pristine boot.img> from the same build",
            "if fastboot is unavailable, use the vendor's EDL/9008 recovery image",
        ],
        "selfSigning": "not-a-route: the OEM private key is unavailable and this avbtool "
                       "variant's hash descriptor cannot be reproduced byte-for-byte",
    }


def scan(boot_path: Path, kernel: bytes | None, kernel_range: tuple | None) -> dict:
    image = boot_path.read_bytes()
    report = {"image": boot_path.name, "bytes": len(image),
              "sha256": hashlib.sha256(image).hexdigest()}
    footer = find_footer(image)
    report["footer"] = footer
    vbmeta = {}
    if footer.get("present"):
        offset, size = footer["vbmeta_offset"], footer["vbmeta_size"]
        blob = image[offset:offset + size]
        vbmeta = parse_vbmeta(blob)
        if not vbmeta.get("present"):
            # Weaker detection: record that this is a scan, not the footer pointer.
            found = image.rfind(AVB_MAGIC, 0, len(image) - 64)
            if found >= 0:
                vbmeta = parse_vbmeta(image[found:found + min(size, len(image) - found)])
                vbmeta["foundBy"] = "scan@0x%x" % found
    report["vbmeta"] = vbmeta

    coverage = {"kernelOffset": None, "kernelBytes": None}
    if kernel_range:
        coverage["kernelOffset"], coverage["kernelBytes"] = kernel_range
    elif kernel is not None:
        # Locate the raw arm64 Image inside the partition (`ARM\x64` at +0x38).
        magic = image.find(b"ARM\x64")
        if magic >= 0x38:
            coverage["kernelOffset"] = magic - 0x38
            coverage["kernelBytes"] = len(kernel)
    hash_descriptors = [d for d in vbmeta.get("descriptors", []) if d.get("tag") == "hash"]
    if hash_descriptors:
        descriptor = hash_descriptors[0]
        covered = descriptor.get("image_size") or 0
        coverage["descriptorImageSize"] = covered
        coverage["coveredShareOfImage"] = round(covered / len(image), 4) if image else None
        if coverage["kernelOffset"] is not None and coverage["kernelBytes"] is not None:
            coverage["kernelEnd"] = coverage["kernelOffset"] + coverage["kernelBytes"]
            coverage["kernel_covered"] = coverage["kernelEnd"] <= covered
        coverage["descriptor"] = {key: descriptor.get(key) for key in
                                  ("image_size", "hash_algorithm", "partition_name_hint",
                                   "u32@40", "u32@44", "u32@48")}
        report["digest"] = verify_digest(image, descriptor)
    else:
        coverage["kernel_covered"] = None
        report["digest"] = {"verified": False, "reason": "no hash descriptor found"}
    report["coverage"] = coverage
    report["cfi"] = cfi_hint(kernel)
    report["recommendation"] = recommend(report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--boot", required=True, help="boot.img to inspect (read-only)")
    parser.add_argument("--kernel", default=None, help="raw arm64 Image for coverage + CFI")
    parser.add_argument("--kernel-range", default=None, help="off:size inside the partition")
    parser.add_argument("--json", default=None)
    args = parser.parse_args()

    kernel = Path(args.kernel).read_bytes() if args.kernel else None
    kernel_range = None
    if args.kernel_range:
        offset, _, size = args.kernel_range.partition(":")
        kernel_range = (int(offset, 0), int(size, 0))
    report = scan(Path(args.boot), kernel, kernel_range)
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                   encoding="utf-8", newline="\n")

    footer, vbmeta, coverage = report["footer"], report["vbmeta"], report["coverage"]
    print("image      : %s (%d bytes, sha256 %s)" % (report["image"], report["bytes"],
                                                     report["sha256"][:16]))
    print("AVB footer : %s" % ("yes, v%s orig=%d vbmeta=0x%x+%d" % (
        footer["version"], footer["original_image_size"], footer["vbmeta_offset"],
        footer["vbmeta_size"]) if footer.get("present") else "no (%s)" % footer.get("reason")))
    if vbmeta.get("present"):
        print("vbmeta     : %s flags=%d (verification_disabled=%s hashtree_disabled=%s) "
              "rollback=%d release=%r" % (
                  vbmeta["algorithm"], vbmeta["flags"], vbmeta["verification_disabled"],
                  vbmeta["hashtree_disabled"], vbmeta["rollback_index"],
                  vbmeta["release_string"]))
        print("descriptors: %s" % ", ".join(
            d["tag"] + ("(" + str(d.get("image_size")) + ")" if d.get("image_size") else "")
            for d in vbmeta["descriptors"]))
        print("pubkey     : sha256=%s" % vbmeta["public_key_sha256"][:32])
    print("coverage   : descriptor covers %s of the image; kernel %s" % (
        coverage.get("descriptorImageSize"),
        "inside" if coverage.get("kernel_covered") else "NOT proven inside"))
    digest = report["digest"]
    print("digest     : %s" % ("reproduced (%s)" % digest.get("layout")
                               if digest.get("verified") else "NOT reproducible - " +
                               str(digest.get("reason"))))
    if report.get("cfi"):
        print("cfi        : %s (%d KCFI traps)" % (report["cfi"]["variant"],
                                                   report["cfi"]["kcfi_traps"]))
    rec = report["recommendation"]
    print("strategy   : %s (%s confidence)" % (rec["strategy"], rec["confidence"]))
    print("  why      : %s" % rec["detail"])
    for key in ("prerequisites", "risks", "recovery"):
        for item in rec.get(key) or []:
            print("  %-12s %s" % (key, item))
    if rec.get("selfSigning"):
        print("  self-signing: %s" % rec["selfSigning"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
