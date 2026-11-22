"""Capture policy-loader metadata from a SHA-bound raw arm64 reference Image.

The temporary ELF is a read-only address mapping of the original bytes, not a
linked kernel or an executable deliverable. Its notes are the Image's real GNU
notes. Full in-image kallsyms are decoded again, including NOBITS/BSS addresses
that the historical TSV writer clipped at EOF.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import zlib

from policy_payload_target import capture

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.kallsyms import _Probe, decode


def capture_image(contract_path, output, source):
    contract = json.loads(contract_path.read_text())
    image_path = ROOT / contract["imagePath"]
    image = image_path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != contract["imageSha256"] or len(image) != contract["imageBytes"]:
        raise ValueError("reference Image digest/size mismatch")
    table = decode(image)
    layout = table.layout
    probe = _Probe(image)
    names = probe.read_names(int(layout["names"], 16), layout["num_syms"],
                             probe.read_tokens(int(layout["token_table"], 16)))
    addresses = probe.read_addresses(int(layout["offsets"], 16), layout["num_syms"],
                                     table.relative_base, layout["base_relative"])
    symbols = {}
    rows = []
    for address, name in zip(addresses, names):
        symbols.setdefault(name[1:], []).append(address)
        rows.append((address, name[0], name[1:]))

    # The existing persisted evidence must agree; never silently replace it.
    historical = ROOT / contract["symbolsPath"]
    for line in historical.read_text().splitlines():
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        offset, _, name = fields
        if table.text_base + int(offset) not in symbols.get(name, []):
            raise ValueError("historical symbol mismatch: " + name)

    def unique(name):
        values = set(symbols.get(name, []))
        if len(values) != 1:
            raise ValueError("missing/ambiguous symbol: " + name)
        return values.pop()

    start = unique("__start_notes") - table.text_base
    end = unique("__stop_notes") - table.text_base
    if not 0 <= start < end <= len(image):
        raise ValueError("invalid Image notes span")
    release = re.search(rb"Linux version ([^ ]+) ", image)
    if not release or release[1].decode() != contract["kernelRelease"]:
        raise ValueError("Image release mismatch")
    first = image.index(b"IKCFG_ST") + 8
    last = image.index(b"IKCFG_ED", first)
    config = zlib.decompress(image[first:last], 31)
    active = "\n".join(line for line in config.decode().splitlines() if line.startswith("CONFIG_")) + "\n"

    output.mkdir(parents=True, exist_ok=True)
    btf = contract["btf"]
    at, length = btf["magicOffset"], btf["blobBytes"]
    blob = image[at:at + length]
    if len(blob) != length or blob[:4] != b"\x9f\xeb\x01\0":
        raise ValueError("invalid reference BTF span")
    (output / "vmlinux.btf").write_bytes(blob)
    mapping = output / "raw-image-metadata"
    (mapping / "include/config").mkdir(parents=True, exist_ok=True)
    (mapping / "include/config/auto.conf").write_text(active, encoding="utf-8")
    (mapping / ".config").write_bytes(config)
    (mapping / "include/config/kernel.release").write_text(contract["kernelRelease"] + "\n")
    system_map = "\n".join(f"{address:016x} {kind} {name}" for address, kind, name in sorted(rows)) + "\n"
    (mapping / "System.map").write_text(system_map, encoding="utf-8")
    # Both PT_LOAD and PT_NOTE point into unmodified reference bytes. This
    # wrapper is only an input adapter for the common metadata/replay reader.
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
                         2, 183, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 5, 4096, table.text_base, table.text_base,
                       len(image), len(image), 4096)
    note = struct.pack("<IIQQQQQQ", 4, 4, 4096 + start, table.text_base + start,
                       table.text_base + start, end - start, end - start, 4)
    with (mapping / "vmlinux").open("wb") as stream:
        stream.write(header + load + note)
        stream.write(bytes(4096 - stream.tell()))
        stream.write(image)
    capture(mapping, output / "target-identity.json", source)
    (output / "System.map").write_text(system_map, encoding="utf-8")
    (output / "target.config").write_bytes(config)
    metadata = json.loads((output / "target-identity.json").read_text())
    metadata["rawImageReference"] = dict(path=str(image_path), sha256=digest,
        bytes=len(image), contractSha256=hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        symbolCount=len(rows), symbolsOutsideImage=len(rows) - len(table.rows),
        source="Actual Image notes, embedded config, kallsyms and instruction bytes; synthetic ELF mapping for read-only capture only")
    (output / "target-identity.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--kernel-source", required=True, type=Path)
    args = parser.parse_args()
    capture_image(args.contract, args.output, args.kernel_source)
