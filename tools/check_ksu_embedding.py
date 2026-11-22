"""Verify shipped Normal modules and Ultra companions against canonical assets.

build_userland.sh copies lkm/ into its isolated build tree, then RustEmbed
compresses those bytes into ksud. applied/ remains an upstream+patches tree.
Use --deep to inflate the embedded assets and compare every byte.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = ROOT / "third_party/kernelsu/ksu-payload.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require", action="store_true", help="fail if an asset is missing or stale")
    parser.add_argument("--kmi", default="android15-6.6")
    parser.add_argument("--all-kmis", action="store_true", help="check every KMI in the product contract")
    parser.add_argument("--deep", action="store_true", help="inflate and compare the embedded bytes")
    args = parser.parse_args()
    artifacts = json.loads(PAYLOAD.read_text(encoding="utf-8"))["artifacts"]
    by_name = {a["name"]: a for a in artifacts}
    ksud = by_name.get("libksud_ksu.so", {})
    binary = ROOT / ksud.get("path", "missing-ksud")
    data = binary.read_bytes() if binary.is_file() else b""
    binary_current = bool(data) and hashlib.sha256(data).hexdigest() == ksud.get("sha256")
    if not binary_current:
        print("FAIL binary: shipped ksud is missing or differs from the payload manifest")
    kmis = [args.kmi]
    if args.all_kmis:
        contract = ROOT / "jailbreak-providers/contracts/kmi-matrix.json"
        kmis = json.loads(contract.read_text(encoding="utf-8"))["required"]
    if args.deep:
        sys.path.insert(0, str(ROOT / "third_party/kernelsu/scripts"))
        from verify_embedded_asset import find_offset
    ready = 0
    for kmi in kmis:
        for mode in ("kernelsu", "maplesu_vr"):
            name = f"{kmi}_{mode}.ko"
            entry = by_name.get(name, {})
            source = ROOT / entry.get("path", "missing-asset")
            raw = source.read_bytes() if source.is_file() else b""
            source_current = (bool(raw) and entry.get("status") == "present"
                              and len(raw) == entry.get("size")
                              and hashlib.sha256(raw).hexdigest() == entry.get("sha256"))
            embedded = binary_current and name.encode() in data
            offset = None
            if source_current and embedded and args.deep:
                offset = find_offset(data, raw)
                embedded = offset is not None
            ok = source_current and embedded
            ready += int(ok)
            print(f"{'OK' if ok else 'MISSING'} {name}: source={source_current} embedded={embedded}"
                  + (f" deflateOffset={offset}" if offset is not None else ""))
    expected = len(kmis) * 2
    print(f"RESULT: {ready}/{expected} Normal and Ultra assets verified")
    return 0 if ready == expected or not args.require else 1


if __name__ == "__main__":
    sys.exit(main())
