#!/usr/bin/env python3
"""Verify all vivo payload bytes, the root-free companion, static init and optional APK."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
KSU = ROOT / "third_party/kernelsu"
KMIS = ["android12-5.10", "android13-5.15", "android14-6.1", "android15-6.6", "android16-6.12"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def elf(data):
    assert data[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", data, 18)[0] == 183
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    return header


def static_init(data):
    h = elf(data)
    assert h[1] in (2, 3), "init must be an executable"
    loads = 0
    for i in range(h[10]):
        p = struct.unpack_from("<IIQQQQQQ", data, h[5] + h[9] * i)
        assert p[0] != 3, "static init has an interpreter"
        if p[0] == 1:
            loads += 1
            assert p[7] >= 16384, "init has less than 16K alignment"
        if p[0] == 2:
            for at in range(p[2], p[2] + p[5], 16):
                tag, _ = struct.unpack_from("<qQ", data, at)
                if tag == 0:
                    break
                assert tag != 1, "static init has a DT_NEEDED dependency"
    assert loads


def companion(data):
    h = elf(data)
    assert h[1] == 1, "companion must be relocatable"
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, h[6] + i * h[11]) for i in range(h[12])]
    strings = sections[h[13]]
    names = data[strings[4]:strings[4] + strings[5]]
    modinfo = next(s for s in sections if names[s[0]:].split(b"\0", 1)[0] == b".modinfo")
    entries = data[modinfo[4]:modinfo[4] + modinfo[5]].split(b"\0")
    assert b"name=maplesu_vr" in entries
    symbols = set()
    for s in sections:
        if s[1] != 2:
            continue
        string_section = sections[s[6]]
        table = data[string_section[4]:string_section[4] + string_section[5]]
        for at in range(s[4], s[4] + s[5], s[9]):
            name = struct.unpack_from("<I", data, at)[0]
            symbols.add(table[name:].split(b"\0", 1)[0].decode())
    assert any(name.startswith("ksu_sys_init_module") for name in symbols)
    assert any(name.startswith("ksu_sys_finit_module") for name in symbols)
    assert not {"kernelsu_init", "ksu_supercalls_init", "ksu_allowlist_init", "ksu_syscall_dispatcher", "cleanup_module"} & symbols


def inflate(data, offset, maximum):
    decoder = zlib.decompressobj(-15)
    try:
        result = decoder.decompress(data[offset:], maximum + 1)
        return result if decoder.eof and len(result) <= maximum else None
    except zlib.error:
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--receipt", type=Path, default=ROOT / ".analysis/vivo-implementation-20261109/artifacts-verification.json")
    args = parser.parse_args()
    daemon = (ROOT / "manager/src/main/jniLibs/arm64-v8a/libksud_ksu.so").read_bytes()
    paths = [KSU / "artifacts" / name for name in ("ksuinit", "maplesu_vrinit")]
    paths += [KSU / "lkm" / f"{kmi}_{kind}.ko" for kmi in KMIS for kind in ("kernelsu", "maplesu_vr")]
    expected = {sha(p.read_bytes()): p for p in paths}
    assert len(expected) == 12
    for path in paths:
        payload = path.read_bytes()
        if path.name in {"ksuinit", "maplesu_vrinit"}:
            static_init(payload)
        elif path.name.endswith("maplesu_vr.ko"):
            companion(payload)
    found = {}
    if args.receipt.is_file():
        previous = json.loads(args.receipt.read_text(encoding="utf-8"))
        if previous["daemonSha256"] == sha(daemon):
            for item in previous["embedded"]:
                payload = inflate(daemon, item["offset"], max(p.stat().st_size for p in paths))
                if payload is not None and sha(payload) in expected:
                    found[sha(payload)] = item["offset"]
    if len(found) != len(expected):
        maximum = max(p.stat().st_size for p in paths)
        for offset in range(len(daemon) - 2):
            if (daemon[offset] & 6) == 6:
                continue
            try:
                head = zlib.decompressobj(-15).decompress(daemon[offset:offset + 512], 4)
            except zlib.error:
                continue
            if head != b"\x7fELF":
                continue
            payload = inflate(daemon, offset, maximum)
            if payload is not None and sha(payload) in expected:
                found[sha(payload)] = offset
            if len(found) == len(expected):
                break
    assert found.keys() == expected.keys(), f"missing embedded bytes: {[p.name for h, p in expected.items() if h not in found]}"
    receipt = {"schema": 1, "daemonSha256": sha(daemon), "embedded": [
        {"path": str(path.relative_to(ROOT)), "sha256": digest, "size": path.stat().st_size, "offset": found[digest]}
        for digest, path in expected.items()]}
    if args.apk:
        with zipfile.ZipFile(args.apk) as apk:
            assert apk.read("lib/arm64-v8a/libksud_ksu.so") == daemon
            assert "assets/ksu_manager_gen2" in apk.namelist()
        receipt["apk"] = {"path": str(args.apk.resolve()), "sha256": sha(args.apk.read_bytes()), "size": args.apk.stat().st_size}
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Verified 12 byte-identical embedded payloads, five root-free companions and two static 16K init binaries")
    if args.apk:
        print("Verified APK daemon bytes and manager generation marker")


if __name__ == "__main__":
    main()
