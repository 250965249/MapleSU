"""Kernel profile registry for MapleSU's built-in boot-image pipeline.

A profile is the machine-readable answer to "which kernel build am I patching,
where does every patch go, and what must the result look like".  One profile
covers one kernel build (uname string + kernel sha256); different kernel
versions get different profiles, the tooling and the patch semantics do not
change.

This module is shared by:

  * image-core/tools/build_flash_kernel.py  - builds <variant>-kernel.bin /
    <variant>-boot.img / <variant>-spec.txt from a profile + variant name.
  * image-core/tools/derive_sites.py        - re-derives the 12 site offsets
    for a kernel that has no profile yet.

It is stdlib only.  Java (image-core) does the actual image work; nothing here
re-implements the patcher.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

SCHEMA = "maplesu.kernel-profile/1"

#: canonical record order (the order the records must be *emitted* in).
#: It is ascending by offset except for the append package, which is emitted
#: last because it is an addition to the vendor set, not one of its sites.
DEFAULT_RECORD_ORDER = [
    "die", "die_c2", "arm64_notify_die", "free_initmem",
    "report_cfi_failure", "free_reserved_area", "do_execveat_common",
    "avc_denied", "cave_a_puts", "cave_b_printfn", "cave_b_reply",
    "cave_b_post", "cave_c_avc_island", "cave_d_dev_printk",
    "panic_key", "append",
]


class ProfileError(Exception):
    """A profile, or a profile/variant combination, that must not be built."""


# --------------------------------------------------------------------- helpers

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hex_bytes(text: str, what: str) -> bytes:
    text = text.strip()
    if len(text) % 2:
        raise ProfileError(f"{what}: odd hex length ({len(text)})")
    try:
        return bytes.fromhex(text)
    except ValueError as error:
        raise ProfileError(f"{what}: invalid hex ({error})") from error


def load(path: Path) -> dict:
    try:
        profile = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ProfileError(f"profile not found: {path}") from error
    except json.JSONDecodeError as error:
        raise ProfileError(f"profile is not valid JSON: {path}: {error}") from error
    return profile


# ------------------------------------------------------------------ boot image

def parse_boot_header(boot: bytes) -> dict:
    """Parse the parts of the Android boot header this pipeline depends on."""
    if len(boot) < 48:
        raise ProfileError(f"boot image too small ({len(boot)} B)")
    if boot[:8] != b"ANDROID!":
        raise ProfileError(f"boot image magic is {boot[:8]!r}, expected b'ANDROID!'")
    kernel_size, ramdisk_size, os_version, header_size = struct.unpack("<IIII", boot[8:24])
    header_version = struct.unpack("<I", boot[40:44])[0]
    page_size = 4096 if header_version >= 3 else struct.unpack("<I", boot[36:40])[0] or 2048
    header = {
        "magic": "ANDROID!",
        "header_version": header_version,
        "header_size": header_size,
        "header_sha256": sha256_bytes(boot[:header_size]),
        "page_size": page_size,
        "kernel_size": kernel_size,
        "ramdisk_size": ramdisk_size,
        "os_version": os_version,
        "signature_size": struct.unpack("<I", boot[header_size - 4:header_size])[0]
        if header_size >= 4 else 0,
        "total_size": len(boot),
    }
    header["kernel_offset"] = page_size
    header["ramdisk_offset"] = page_size + _align(kernel_size, page_size)
    header["second_offset"] = header["ramdisk_offset"] + _align(ramdisk_size, page_size)
    return header


def _align(value: int, page: int) -> int:
    return (value + page - 1) // page * page


def extract_kernel(boot: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size <= 0 or offset + size > len(boot):
        raise ProfileError(
            f"kernel window [{offset:#x}, {offset + size:#x}) is outside the {len(boot)} B image")
    return boot[offset:offset + size]


def same_geometry(actual: dict, expected: dict, keys: tuple[str, ...]) -> list[str]:
    problems = []
    for key in keys:
        want = expected.get(key)
        if want is None:
            continue
        if actual.get(key) != want:
            problems.append(f"geometry.{key}: image={actual.get(key)!r} profile={want!r}")
    return problems


# ------------------------------------------------------------------- validation

def validate(profile: dict, kernel: bytes | None = None, boot: bytes | None = None) -> list[str]:
    """Structural + (optionally) byte-level validation.

    Returns a list of human-readable problems; an empty list means the profile
    is internally consistent and its declared digests match the files supplied.
    """
    problems: list[str] = []
    if profile.get("schema") != SCHEMA:
        problems.append(f"schema: {profile.get('schema')!r} != {SCHEMA!r}")

    for key in ("profile_id", "kernel_version", "boot_geometry", "base_image",
                "sites", "caves", "append", "records", "variants"):
        if key not in profile:
            problems.append(f"missing top-level key: {key}")
    if problems:
        return problems

    version = profile["kernel_version"]
    geometry = profile["boot_geometry"]
    records = profile["records"]
    kernel_size = version.get("kernel_size")

    # --- boot geometry sanity
    for key in ("magic", "header_version", "header_size", "page_size",
                "kernel_offset", "kernel_size", "total_size"):
        if key not in geometry:
            problems.append(f"boot_geometry missing {key}")
    if geometry.get("kernel_offset") != geometry.get("page_size"):
        problems.append("boot_geometry: kernel_offset must equal page_size for this layout")
    if kernel_size and geometry.get("kernel_size") != kernel_size:
        problems.append("boot_geometry.kernel_size != kernel_version.kernel_size")
    expected_total = (geometry.get("second_offset", 0)
                      + _align(geometry.get("second_size", 0), geometry.get("page_size", 4096)))
    if expected_total and geometry.get("total_size") and geometry["total_size"] < expected_total:
        problems.append("boot_geometry.total_size is smaller than second_offset+second_size")

    # --- records
    for rid, record in records.items():
        try:
            offset = int(record["offset"])
            orig = hex_bytes(record["orig"], f"record {rid} orig")
            repl = hex_bytes(record["repl"], f"record {rid} repl")
        except (KeyError, TypeError, ProfileError) as error:
            problems.append(f"record {rid}: {error}")
            continue
        if len(orig) != len(repl):
            problems.append(f"record {rid}: orig {len(orig)} B != repl {len(repl)} B")
        if kernel_size and offset + max(len(orig), len(repl)) > kernel_size:
            problems.append(f"record {rid}: {offset:#x}+{len(orig)} exceeds the kernel")

    append = profile["append"]
    for form, blob in append.get("forms", {}).items():
        try:
            orig = hex_bytes(blob.get("orig", ""), f"append forms.{form}.orig")
            repl = hex_bytes(blob.get("repl", ""), f"append forms.{form}.repl")
        except ProfileError as error:
            problems.append(f"append forms.{form}: {error}")
            continue
        if len(orig) != int(form):
            problems.append(f"append forms.{form}: orig is {len(orig)} B")
        if len(orig) != len(repl):
            problems.append(f"append forms.{form}: orig {len(orig)} B != repl {len(repl)} B")
    if len(hex_bytes(append.get("replacement", ""), "append.replacement")) != append.get("length", -1):
        problems.append("append: replacement length != append.length")

    # --- sites
    if len(profile["sites"]) != 12:
        problems.append(f"sites: {len(profile['sites'])} entries, expected 12 vendor sites")
    seen_slots = set()
    for site in profile["sites"]:
        slot = site.get("slot")
        if slot in seen_slots:
            problems.append(f"site slot {slot} is duplicated")
        seen_slots.add(slot)
        rids = site.get("record_ids") or []
        if not rids:
            problems.append(f"site {site.get('symbol')}: no record_ids")
        for rid in rids:
            if rid not in records:
                problems.append(f"site {site.get('symbol')}: unknown record id {rid}")
        first = records.get(rids[0]) if rids else None
        if first:
            if int(first["offset"]) != int(site["offset"]):
                problems.append(f"site {site['symbol']}: site offset != first record offset")
            if len(hex_bytes(first["orig"], "site")) != int(site["length"]):
                problems.append(f"site {site['symbol']}: site length != first record orig length")
            digest = sha256_bytes(hex_bytes(first["orig"], "site"))
            if site.get("orig_sha256") and digest != site["orig_sha256"]:
                problems.append(f"site {site['symbol']}: orig_sha256 != sha256(record orig)")
        signature = site.get("signature") or {}
        words, masks = signature.get("words") or [], signature.get("masks") or []
        if len(words) != len(masks):
            problems.append(f"site {site['symbol']}: signature words/masks length mismatch")
        if len(words) < 12:
            problems.append(f"site {site['symbol']}: signature shorter than 12 instructions")

    # --- caves
    for name, cave in profile["caves"].items():
        if "offset" not in cave or "length" not in cave:
            problems.append(f"cave {name}: offset/length missing")
            continue
        if int(cave["offset"]) + int(cave["length"]) > (kernel_size or 1 << 40):
            problems.append(f"cave {name}: outside the kernel")

    # --- variants
    order = profile.get("record_order", DEFAULT_RECORD_ORDER)
    for rid in order:
        if rid not in records:
            problems.append(f"record_order: unknown record id {rid}")
    for name, variant in profile["variants"].items():
        overrides = variant.get("overrides") or {}
        for rid, override in overrides.items():
            if rid not in records:
                problems.append(f"variant {name}: override of unknown record {rid}")
                continue
            if "form" in override:
                if override["form"] not in append.get("forms", {}):
                    problems.append(f"variant {name}: record {rid} unknown form "
                                    f"{override['form']}")
                if rid != "append":
                    problems.append(f"variant {name}: form override only applies to the append record")
            if "repl" in override:
                was = len(hex_bytes(records[rid]["repl"], "record"))
                now = len(hex_bytes(override["repl"], "override"))
                if was != now:
                    problems.append(f"variant {name}: record {rid} override changes length "
                                    f"{was} -> {now} (not representable in one spec)")
        for extra in variant.get("extra") or []:
            try:
                orig = hex_bytes(extra["orig"], f"variant {name} extra {extra.get('id')}")
                repl = hex_bytes(extra["repl"], f"variant {name} extra {extra.get('id')}")
            except (KeyError, ProfileError) as error:
                problems.append(f"variant {name}: extra record: {error}")
                continue
            if len(orig) != len(repl):
                problems.append(f"variant {name}: extra record {extra.get('id')} length mismatch")
            if kernel_size and int(extra["offset"]) + len(orig) > kernel_size:
                problems.append(f"variant {name}: extra record {extra.get('id')} outside kernel")

    # --- byte-level checks
    if boot is not None:
        try:
            header = parse_boot_header(boot)
        except ProfileError as error:
            problems.append(f"base image: {error}")
            header = None
        if header:
            problems.extend(same_geometry(header, geometry, (
                "magic", "header_version", "header_size", "header_sha256", "page_size",
                "kernel_offset", "kernel_size", "ramdisk_offset", "ramdisk_size",
                "second_offset", "total_size")))
            if profile["base_image"].get("boot_sha256") and \
                    sha256_bytes(boot) != profile["base_image"]["boot_sha256"]:
                problems.append("base image: boot sha256 does not match base_image.boot_sha256")
    if kernel is not None:
        if version.get("kernel_sha256") and sha256_bytes(kernel) != version["kernel_sha256"]:
            problems.append("kernel: sha256 does not match kernel_version.kernel_sha256")
        if kernel_size and len(kernel) != kernel_size:
            problems.append(f"kernel: {len(kernel)} B, profile says {kernel_size} B")
        for rid, record in records.items():
            orig = hex_bytes(record["orig"], rid)
            offset = int(record["offset"])
            if offset + len(orig) > len(kernel):
                problems.append(f"record {rid}: outside the kernel")
            elif kernel[offset:offset + len(orig)] != orig:
                problems.append(f"record {rid}: orig bytes are not present at {offset:#x} "
                                f"in the pristine kernel")
    return problems


# ----------------------------------------------------------------- composition

def compose(profile: dict, variant_name: str) -> list[dict]:
    """Return the ordered record list for one variant.

    Each record: {id, offset, orig: bytes, repl: bytes, role, note, source}.
    """
    variants = profile.get("variants") or {}
    if variant_name not in variants:
        raise ProfileError(f"unknown variant {variant_name!r}; known: {', '.join(sorted(variants))}")
    variant = variants[variant_name]
    base_name = variant.get("base", "k7")
    if base_name not in variants:
        raise ProfileError(f"variant {variant_name}: unknown base {base_name!r}")
    base = variants[base_name]
    if base.get("base", "k7") != "k7":
        raise ProfileError(f"variant {base_name}: nested bases are not supported")

    order = profile.get("record_order", DEFAULT_RECORD_ORDER)
    records = profile["records"]
    overrides = dict(base.get("overrides") or {})
    overrides.update(variant.get("overrides") or {})
    append = profile["append"]

    composed: list[dict] = []
    for rid in order:
        record = records[rid]
        orig_hex = record["orig"]
        repl_hex = record["repl"]
        override = overrides.get(rid) or {}
        if "form" in override:
            form = append["forms"][override["form"]]
            orig_hex = form["orig"]
            repl_hex = form["repl"]
        if "orig" in override:
            orig_hex = override["orig"]
        if "repl" in override:
            repl_hex = override["repl"]
        orig = hex_bytes(orig_hex, f"record {rid} orig")
        repl = hex_bytes(repl_hex, f"record {rid} repl")
        if len(orig) != len(repl):
            raise ProfileError(f"record {rid}: composed lengths differ ({len(orig)} vs {len(repl)})")
        composed.append({
            "id": rid,
            "offset": int(record["offset"]),
            "orig": orig,
            "repl": repl,
            "role": record.get("role", "site" if rid != "append" else "append"),
            "note": override.get("note") or record.get("note", ""),
            "source": base_name if rid in order else variant_name,
        })

    for extra in variant.get("extra") or []:
        orig = hex_bytes(extra["orig"], f"extra {extra.get('id')} orig")
        repl = hex_bytes(extra["repl"], f"extra {extra.get('id')} repl")
        if len(orig) != len(repl):
            raise ProfileError(f"extra {extra.get('id')}: lengths differ")
        composed.append({
            "id": extra.get("id", f"extra_{len(composed)}"),
            "offset": int(extra["offset"]),
            "orig": orig,
            "repl": repl,
            "role": extra.get("role", "aux"),
            "note": extra.get("note", ""),
            "source": variant_name,
        })

    seen = set()
    for record in composed:
        if record["id"] in seen:
            raise ProfileError(f"variant {variant_name}: record id {record['id']} emitted twice")
        seen.add(record["id"])
    return composed


def record_digest(records: list[dict]) -> str:
    lines = [f"{record['offset']}|{record['orig'].hex()}|{record['repl'].hex()}"
             for record in records]
    return sha256_bytes("\n".join(lines).encode("ascii"))


def overlap_report(records: list[dict]) -> list[tuple[str, str, int]]:
    """Overlaps are legal (later records override earlier ones) - report them."""
    overlaps = []
    for i, first in enumerate(records):
        a0, a1 = first["offset"], first["offset"] + len(first["orig"])
        for second in records[i + 1:]:
            b0, b1 = second["offset"], second["offset"] + len(second["orig"])
            start, end = max(a0, b0), min(a1, b1)
            if start < end:
                overlaps.append((first["id"], second["id"], end - start))
    return overlaps


def unreachable_records(records: list[dict], kernel: bytes) -> list[str]:
    """Records whose `orig` window would never be checked because an earlier record
    replaced those bytes.  Legal for declared overrides, but worth surfacing."""
    notes = []
    for index, record in enumerate(records):
        start, end = record["offset"], record["offset"] + len(record["orig"])
        covered = 0
        for earlier in records[:index]:
            e0, e1 = earlier["offset"], earlier["offset"] + len(earlier["repl"])
            covered = max(covered, min(end, e1) - max(start, e0))
        if covered >= len(record["orig"]):
            notes.append(f"{record['id']} is fully covered by an earlier record")
    return notes


# ------------------------------------------------------------------------ spec

def render_spec(profile: dict, variant_name: str, records: list[dict],
                extra_comments: list[str] | None = None) -> str:
    variant = profile["variants"][variant_name]
    geometry = profile["boot_geometry"]
    lines = [
        f"#kernel={profile['kernel_version']['uname']}",
        f"#key={profile['kernel_version']['probe_key']}",
        "# " + "=" * 74,
        "# Generated by image-core/tools/build_flash_kernel.py - do not edit by hand.",
        f"# profile  : {profile.get('profile_id')}  (schema {profile.get('schema')}, "
        f"revision {profile.get('revision')})",
        f"# variant  : {variant_name}  status={variant.get('status')}  base={variant.get('base', 'k7')}",
        f"# summary  : {variant.get('summary', '')}",
        f"# kernel   : {profile['kernel_version']['kernel_sha256']}  "
        f"{profile['kernel_version']['kernel_size']} B",
        f"# base     : boot {profile['base_image']['boot_sha256']}  "
        f"{geometry['total_size']} B (page {geometry['page_size']}, "
        f"kernel@{geometry['kernel_offset']:#x})",
        f"# records  : {len(records)}  digest={record_digest(records)}",
        "# rule     : every orig must be present in the pristine kernel; any mismatch refuses the build.",
    ]
    for comment in extra_comments or []:
        lines.append(f"# {comment}")
    lines.append("# " + "=" * 74)
    for record in records:
        lines.append(f"{record['offset']}|{record['orig'].hex()}|{record['repl'].hex()}")
    return "\n".join(lines) + "\n"


def variant_summary(profile: dict, variant_name: str) -> dict:
    variant = profile["variants"][variant_name]
    records = compose(profile, variant_name)
    expected = (profile.get("validation", {}).get("expected_artifacts", {})
                .get(variant_name) or {})
    return {
        "variant": variant_name,
        "status": variant.get("status"),
        "summary": variant.get("summary", ""),
        "records": len(records),
        "record_digest": record_digest(records),
        "differing_capacity": sum(len(r["repl"]) for r in records),
        "overlaps": overlap_report(records),
        "expected": expected,
    }
