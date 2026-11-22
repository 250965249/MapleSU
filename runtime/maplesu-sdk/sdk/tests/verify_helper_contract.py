#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_helper_contract.py -- two-way dynamic-surface comparison of the
first-party boot helper against the frozen vendor reference.

Byte identity is explicitly **not** a goal (see sdk/notes/HELPER.md): the vendor
helper was built from a closed translation-unit set that is not on disk, so a
source rebuild necessarily produces different bytes.  What must hold is the
contract: a PIE AArch64 image that exports exactly the two privileged
primitives, only depends on base system libraries, and adds no import that is
not part of the documented duties.

The report records every difference in both directions instead of asserting
equality:

  exported_in_reference / exported_in_candidate
  imported_in_reference / imported_in_candidate
  needed_in_reference   / needed_in_candidate

Usage
    py runtime/maplesu-sdk/sdk/tests/verify_helper_contract.py
    py runtime/maplesu-sdk/sdk/tests/verify_helper_contract.py --candidate <path>

Exit codes: 0 contract holds (documented differences only), 1 a contract
violation, 2 the host cannot run the check (missing reference/candidate/readelf).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SDK = HERE.parent
REPO = SDK.parents[2]
if not (SDK / "tools/extract_payloads.py").is_file():
    REPO = HERE.parents[4]
    SDK = REPO / "runtime/maplesu-sdk/sdk"
REFERENCE = (REPO / "runtime/maplesu-sdk/maintenance/freeze" /
             "freeze-maplesu-pro-5.2.0-su-uid-isolation-20261114-20261114/helper/autorun_bootstrap")
CANDIDATE = SDK / "build" / "out" / "helper" / "autorun_bootstrap"
REPORT = SDK / "build" / "report" / "helper-contract.json"
NDK_BIN = Path("D:/Maple_Env/Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/"
               "windows-x86_64/bin")
REQUIRED_EXPORTS = ["maplesu_helper_su_exec", "maplesu_helper_su_write"]
ALLOWED_NEEDED = {"libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so"}
# Imports that are part of the documented duties (boot session files, process
# control, dynamic loading of the paired policy backend, exec/delivery).
EXPECTED_IMPORT_FAMILIES = {
    "open", "openat", "read", "write", "close", "fstat", "fstatat", "fsync",
    "fchmod", "fchown", "fsetxattr", "fgetxattr", "mkdirat", "renameat",
    "unlinkat", "dup", "fdopendir", "readdir", "closedir", "flock", "fork",
    "execve", "execl", "waitpid", "pipe2", "dup2", "setpgid", "_exit", "setsid",
    "readlink", "getuid", "geteuid", "getpid", "abort", "dlopen", "dlclose",
    "dlsym", "dlerror", "fprintf", "fflush", "snprintf", "vsnprintf",
    "lseek", "__errno", "memcpy", "strlen", "__libc_init", "__cxa_atexit",
}


def readelf(binary: Path, *args: str) -> str:
    tool = NDK_BIN / ("llvm-readelf.exe" if sys.platform == "win32" else "llvm-readelf")
    if not tool.is_file():
        raise SystemExit(f"llvm-readelf not found: {tool}")
    completed = subprocess.run([str(tool), *args, str(binary)], capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
    if completed.returncode != 0:
        raise RuntimeError(f"llvm-readelf {' '.join(args)} {binary}: {completed.stderr}")
    return completed.stdout


def describe(binary: Path) -> dict:
    header = readelf(binary, "-h")
    dynamic = readelf(binary, "-d")
    symbols = readelf(binary, "--dyn-syms")
    elf_type = ""
    machine = ""
    interpreter = ""
    for line in header.splitlines():
        stripped = line.strip()
        if stripped.startswith("Type:"):
            elf_type = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Machine:"):
            machine = stripped.split(":", 1)[1].strip()
    for line in readelf(binary, "-l").splitlines():
        if "Requesting program interpreter" in line:
            interpreter = line.split(":", 1)[1].strip().rstrip("]")
    needed = [line.split("[")[1].split("]")[0] for line in dynamic.splitlines()
              if "NEEDED" in line]
    exported: list[str] = []
    imported: list[str] = []
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].rstrip(":").isdigit():
            continue
        name = fields[7].split("@")[0]
        if fields[6] == "UND":
            imported.append(name)
        elif fields[4] in ("GLOBAL", "WEAK") and fields[5] == "DEFAULT":
            exported.append(name)
    return {
        "path": str(binary),
        "bytes": binary.stat().st_size,
        "sha256": subprocess.run(["sha256sum", str(binary)], capture_output=True, text=True)
        .stdout.split()[0] if sys.platform != "win32" else _sha256(binary),
        "elf_type": elf_type,
        "machine": machine,
        "interpreter": interpreter,
        "needed": sorted(needed),
        "exported": sorted(exported),
        "imported": sorted(set(imported)),
    }


def _sha256(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def diff(reference: list[str], candidate: list[str]) -> dict:
    reference_set = set(reference)
    candidate_set = set(candidate)
    return {
        "in_reference_only": sorted(reference_set - candidate_set),
        "in_candidate_only": sorted(candidate_set - reference_set),
        "shared": sorted(reference_set & candidate_set),
    }


def elf_parser():
    spec = importlib.util.spec_from_file_location("helper_attribution_elf",
                                                 SDK / "tools/extract_payloads.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def undefined(path: Path) -> set[str]:
    tool = NDK_BIN / ("llvm-nm.exe" if sys.platform == "win32" else "llvm-nm")
    done = subprocess.run([str(tool), "--undefined-only", "--format=posix", str(path)],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    if done.returncode:
        raise ValueError(f"object inspection failed: {path}: {done.stderr}")
    return {fields[0] for line in done.stdout.splitlines()
            if len(fields := line.split()) >= 2 and fields[1].upper() == "U"}


def checked_bytes(record: dict, cache: dict) -> bytes:
    path = Path(record["path"]).resolve()
    if path not in cache:
        raw = path.read_bytes()
        cache[path] = (raw, hashlib.sha256(raw).hexdigest())
    raw, sha = cache[path]
    if len(raw) != record["bytes"] or sha != record["sha256"]:
        raise ValueError(f"size/SHA256 mismatch: {path}")
    return raw


def archive_member(record: dict, archives: dict, cache: dict, elf):
    archive = archives[record["archive"]]
    raw = checked_bytes(archive, cache)
    key = ("members", Path(archive["path"]).resolve())
    if key not in cache:
        cache[key] = elf.parse_ar_members(raw)
    members = cache[key]
    ordinal = record["ordinal"]
    if type(ordinal) is not int or not 0 <= ordinal < len(members):
        raise ValueError(f"invalid archive ordinal: {ordinal}")
    member = members[ordinal]
    if (member.name != record["name"] or len(member.raw) != record["bytes"]
            or hashlib.sha256(member.raw).hexdigest() != record["sha256"]):
        raise ValueError(f"archive ordinal/name/size/SHA256 mismatch: {ordinal}:{record['name']}")
    return member, members


def verify_import_review(review: dict, candidate: dict, build: dict, required: list[str]) -> dict:
    result = {"unreviewed": list(required), "errors": [], "checkedObjects": 0,
              "traceMatched": False, "open": []}
    cache = {}
    try:
        if (review["schema"] != "maplesu-helper-import-attribution/2"
                or review["candidateSha256"] != candidate["sha256"]
                or review["candidateBytes"] != candidate["bytes"]):
            raise ValueError("import review candidate identity/schema mismatch")
        receipt = json.loads(checked_bytes(review["linkReport"], cache))
        final = receipt["final_archive_stability"]
        linked = final["helper"]
        trace = review["trace"]
        trace_raw = checked_bytes(trace, cache)
        if (not final["passed"] or not linked["identical"]
                or linked["file"]["sha256"] != candidate["sha256"]
                or linked["file"]["size"] != candidate["bytes"]
                or Path(linked["trace"]["path"]).resolve() != Path(trace["path"]).resolve()
                or linked["trace"]["size"] != trace["bytes"]
                or linked["trace"]["sha256"] != trace["sha256"]):
            raise ValueError("trace/final-link receipt is not bound to this candidate")
        lines = trace_raw.decode("utf-8").splitlines()
        if not lines or lines[0] != "reference\textracted\tsymbol":
            raise ValueError("invalid why-extract trace header")
        selected = set()
        for line in lines[1:]:
            fields = line.split("\t")
            if len(fields) != 3:
                raise ValueError("invalid why-extract trace row")
            match = re.fullmatch(r"(.+\.a)\(([^()]+)\)", fields[1])
            if match:
                selected.add((Path(match[1]).resolve(), match[2]))
        result["traceMatched"] = True
        elf = elf_parser()
        records = review["objectRecords"]
        archives = review["archives"]
        symbols = review["symbols"]
        refs = {}
        direct = ({Path(p).resolve() for p in build["objects"]}
                  & {Path(p).resolve() for p in receipt["source_helper"]["objects"]})
        for name, row in symbols.items():
            if name not in candidate["imported"]:
                raise ValueError(f"review symbol is not imported by candidate: {name}")
            if not isinstance(row["objects"], list):
                raise ValueError(f"object references must be a list: {name}")
            for label in row["objects"]:
                if label not in refs:
                    obj = records[label]
                    if "archive" in obj:
                        archive = archives[obj["archive"]]
                        member, members = archive_member(obj, archives, cache, elf)
                        if (Path(archive["path"]).resolve(), obj["name"]) not in selected:
                            raise ValueError(f"object absent from linked trace: {label}")
                        # why-extract names have no ordinal: duplicates need stronger link evidence.
                        if sum(m.name == obj["name"] for m in members) != 1:
                            raise ValueError(f"ambiguous trace archive member: {label}")
                        if Path(archive["path"]).resolve() == Path(final["archive"]["path"]).resolve() and (
                                archive["sha256"] != final["archive"]["sha256"]
                                or archive["bytes"] != final["archive"]["size"]):
                            raise ValueError("SDK archive differs from final-link receipt")
                        if "path" in obj:
                            if checked_bytes(obj, cache) != member.raw:
                                raise ValueError(f"object differs from archive member: {label}")
                            refs[label] = undefined(Path(obj["path"]))
                        else:
                            image = elf.ElfFile(member.raw)
                            refs[label] = {n for section in image.sections if section.type == 2
                                           for n, _, _, _, index in image.symbols(section)
                                           if n and index == 0}
                    else:
                        checked_bytes(obj, cache)
                        if Path(obj["path"]).resolve() not in direct:
                            raise ValueError(f"object absent from actual helper inputs: {label}")
                        refs[label] = undefined(Path(obj["path"]))
                    result["checkedObjects"] += 1
                if name not in refs[label]:
                    raise ValueError(f"object does not reference symbol {name}: {label}")
        result["unreviewed"] = [name for name in required
                                if not symbols.get(name, {}).get("objects")]
        result["open"] = [name for name in candidate["imported"]
                          if not symbols.get(name, {}).get("objects")]
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
        result["errors"].append(str(exc))
    return result


def _runtime_functions(image, wanted):
    for rel in image.sections:
        if rel.type != 4:
            continue
        syms = list(image.symbols(image.sections[rel.link]))
        dest = struct.unpack_from("<I", image.data, image.e_shoff + rel.index * image.e_shentsize + 44)[0]
        rows = list(struct.iter_unpack("<QQq", image.section_bytes(rel)))
        for name, value, size, info, index in syms:
            if index != dest or info & 15 != 2 or not size:
                continue
            local = [(off-value, tag & 0xffffffff, syms[tag >> 32][0], add)
                     for off, tag, add in rows if value <= off < value + size]
            targets = [(off, sym) for off, kind, sym, add in local if sym in wanted and kind in (282, 283) and any(n == sym and idx == 0 for n, _, _, _, idx in syms)]
            if targets:
                yield name, image.sections[dest], value, size, local, targets


def _runtime_find(image, section, value, size, relocs, final):
    src = image.section_bytes(section)[value:value+size]
    mask = bytearray(b"\xff" * size)
    for off, kind, sym, add in relocs:
        if kind not in {273, 274, 275, 277, 278, 279, 280, 282, 283, 284, 285, 286, 299, 311, 312}:
            return [], "unsupported relocation " + str(kind)
        mask[off:off+4] = b"\0" * 4
    longest = max((len(block), start) for start in range(0, size, 4)
                  if mask[start:start+4] == b"\xff"*4
                  for block in [bytes(src[start:next((x for x in range(start, size, 4) if mask[x:x+4] != b"\xff"*4),size)])])
    width, anchor = longest
    matches=[]
    for dst in final.sections:
        if not dst.flags & 4:
            continue
        raw=final.section_bytes(dst); pos=raw.find(src[anchor:anchor+width])
        while pos >= 0:
            base=pos-anchor
            if base >= 0 and base+size<=len(raw) and base%4 == 0 and all(not m or src[i]==raw[base+i] for i,m in enumerate(mask)):
                matches.append(dst.addr+base)
            pos=raw.find(src[anchor:anchor+width],pos+1)
    return matches, {"fixedBytes":sum(bool(m) for m in mask),"bytes":size,"relocations":len(relocs)}



def _runtime_at(image, address, size):
    for section in image.sections:
        if section.flags & 4 and section.addr <= address and address + size <= section.addr + section.size:
            offset = section.offset + address - section.addr
            return image.data[offset:offset + size]
    raise ValueError("runtime address is outside executable sections")


def _runtime_call_import(image, address, expected):
    instruction = struct.unpack("<I", _runtime_at(image, address, 4))[0]
    if instruction & 0xfc000000 not in (0x94000000, 0x14000000):
        raise ValueError("runtime reference is not a direct AArch64 call/branch")
    delta = instruction & 0x3ffffff
    if delta & (1 << 25):
        delta -= 1 << 26
    destination = address + delta * 4
    plt = next(section for section in image.sections if section.name == ".plt")
    if not plt.addr <= destination < plt.addr + plt.size:
        raise ValueError("runtime call does not reach PLT")
    adrp, ldr, add, branch = struct.unpack("<IIII", _runtime_at(image, destination, 16))
    if (adrp & 0x9f00001f != 0x90000010 or ldr & 0xffc003ff != 0xf9400211
            or add & 0xffc003ff != 0x91000210 or branch != 0xd61f0220):
        raise ValueError("unrecognized AArch64 PLT/GOT stub")
    page = ((adrp >> 5) & 0x7ffff) * 4 + ((adrp >> 29) & 3)
    if page & (1 << 20):
        page -= 1 << 21
    page = (destination & ~4095) + page * 4096
    got = page + ((ldr >> 10) & 4095) * 8
    if page + ((add >> 10) & 4095) != got:
        raise ValueError("PLT load/add GOT addresses differ")
    rel = next(section for section in image.sections if section.name == ".rela.plt")
    symbols = list(image.symbols(image.sections[rel.link]))
    matches = [symbols[tag >> 32] for offset, tag, addend in struct.iter_unpack("<QQq", image.section_bytes(rel))
               if offset == got and tag & 0xffffffff == 1026]
    if len(matches) != 1 or matches[0][0] != expected or matches[0][4] != 0:
        raise ValueError("runtime call/GOT relocation does not name the requested import")
    return {"callVaddr": address, "pltVaddr": destination, "gotVaddr": got,
            "relocation": "R_AARCH64_JUMP_SLOT", "import": expected}


def verify_runtime_review(review, component, candidate):
    wanted = {"helper": {"__libc_init"}, "resetprop": {"__assert2", "pthread_once", "snprintf"}}[component]
    result = {"verifiedSymbols": [], "open": sorted(wanted), "errors": [], "origins": []}
    cache = {}
    try:
        if review["schema"] != "maplesu-runtime-import-attribution/3":
            raise ValueError("runtime review schema mismatch")
        binding = review["components"][component]
        identity = binding["candidate"]
        if identity["sha256"] != candidate["sha256"] or identity["bytes"] != candidate["bytes"]:
            raise ValueError("runtime review candidate identity mismatch")
        elf = elf_parser()
        final = elf.ElfFile(checked_bytes(identity, cache))
        if final.e_type != 3 or final.e_machine != 183:
            raise ValueError("runtime proof requires AArch64 PIE/DYN")
        receipt = json.loads(checked_bytes(binding["receipt"], cache))
        if component == "helper":
            surface = receipt["surface"]
        else:
            surface = next(row["built"] for row in receipt["programs"] if row["name"] == component)
        if surface["sha256"] != identity["sha256"] or surface["bytes"] != identity["bytes"]:
            raise ValueError("runtime candidate differs from actual build receipt")
        checked_bytes(binding["linkLog"], cache)
        rows = [row for row in review["origins"] if row["component"] == component]
        if len({row["symbol"] for row in rows}) != len(rows):
            raise ValueError("duplicate runtime origin symbol")
        for row in rows:
            name = row["symbol"]
            if name not in wanted or name not in final.imports(limit=100000):
                raise ValueError("runtime symbol is outside the requested candidate imports")
            source = row["input"]
            if "archive" in source:
                member, _ = archive_member(source, review["archives"], cache, elf)
                raw = member.raw
            else:
                raw = checked_bytes(source, cache)
            image = elf.ElfFile(raw)
            if image.e_type != 1 or image.e_machine != 183:
                raise ValueError("runtime input is not an AArch64 relocatable object")
            found = [info for info in _runtime_functions(image, {name}) if info[0] == row["function"]]
            if len(found) != 1:
                raise ValueError("runtime source function does not reference requested import")
            _, section, value, size, relocs, calls = found[0]
            matches, detail = _runtime_find(image, section, value, size, relocs, final)
            if len(matches) != 1 or matches[0] != row["linkedVaddr"] or detail["fixedBytes"] < 32:
                raise ValueError("runtime retained function is absent, changed or ambiguous")
            if component == "helper":
                starts = [(s, sym) for s in image.sections if s.type == 2 for sym in image.symbols(s)
                          if sym[0] == "_start" and sym[4] != 0]
                if len(starts) != 1:
                    raise ValueError("CRT entry symbol is absent or ambiguous")
                _, (_, start, start_size, _, index) = starts[0]
                prefix = image.section_bytes(image.sections[index])[start:start + start_size]
                if (not prefix or _runtime_at(final, final.e_entry, start_size) != prefix
                        or row["linkedVaddr"] != final.e_entry + value - start):
                    raise ValueError("CRT function is not bound to actual candidate entry")
            routes = [_runtime_call_import(final, row["linkedVaddr"] + offset, name) for offset, symbol in calls]
            provider = elf.ElfFile(checked_bytes(row["provider"], cache))
            definitions = [sym for sec in provider.sections if sec.type == 11 for sym in provider.symbols(sec)
                           if sym[0] == name and sym[4] != 0 and sym[3] >> 4 in (1, 2)]
            sonames = []
            for dynamic in provider.sections:
                if dynamic.type == 6:
                    strings = provider.section_bytes(provider.sections[dynamic.link])
                    sonames.extend(strings[offset:strings.find(b"\0", offset)].decode()
                                   for tag, offset in struct.iter_unpack("<QQ", provider.section_bytes(dynamic))
                                   if tag == 14)
            if (provider.e_machine != 183 or len(definitions) != 1
                    or sonames != [row["neededLibrary"]]
                    or row["neededLibrary"] not in final.needed()):
                raise ValueError("runtime provider lacks the required dynamic definition/NEEDED")
            result["verifiedSymbols"].append(name)
            result["origins"].append({"symbol": name, "function": row["function"],
                "linkedVaddr": matches[0], **detail, "routes": routes,
                "definition": list(definitions[0]),
                "selectionProof": "unique retained function plus actual call/PLT/GOT import relocation",
                "historicalWholeObjectByteIdentityProven": False})
        result["open"] = sorted(wanted - set(result["verifiedSymbols"]))
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, StopIteration, struct.error) as exc:
        result["errors"].append(str(exc))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, default=CANDIDATE)
    parser.add_argument("--reference", type=Path, default=REFERENCE)
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--manifest", type=Path, default=SDK / "src/helper/manifest.json")
    parser.add_argument("--build-report", type=Path, default=SDK / "build/report/helper-build.json")
    parser.add_argument("--import-review", type=Path)
    parser.add_argument("--runtime-review", type=Path)
    args = parser.parse_args(argv)
    for path in (args.reference, args.candidate):
        if not path.is_file():
            print(f"[verify-helper] missing input: {path}", file=sys.stderr)
            return 2
    try:
        reference = describe(args.reference)
        candidate = describe(args.candidate)
    except (RuntimeError, OSError) as exc:
        print(f"[verify-helper] inspection failed: {exc}", file=sys.stderr)
        return 2

    manifest_path = args.manifest
    declared = json.loads(manifest_path.read_text(encoding="utf-8"))
    declared_exports = sorted(declared.get("exportedSymbols") or [])
    declared_needed = sorted(declared.get("neededLibraries") or [])

    problems: list[str] = []
    if candidate["exported"] != declared_exports:
        problems.append(f"candidate exports {candidate['exported']} != manifest declaration "
                        f"{declared_exports}")
    if sorted(candidate["needed"]) != declared_needed:
        problems.append(f"candidate NEEDED {sorted(candidate['needed'])} != manifest declaration "
                        f"{declared_needed}")
    if candidate["elf_type"] != "DYN (Shared object file)":
        problems.append(f"candidate is not a PIE/DYN image: {candidate['elf_type']}")
    if candidate["machine"] != "AArch64":
        problems.append(f"candidate machine is {candidate['machine']}")
    if candidate["interpreter"] != "/system/bin/linker64":
        problems.append(f"candidate interpreter is {candidate['interpreter']!r}")
    if candidate["exported"] != REQUIRED_EXPORTS:
        problems.append(f"candidate exports {candidate['exported']} != {REQUIRED_EXPORTS}")
    unexpected_needed = sorted(set(candidate["needed"]) - ALLOWED_NEEDED)
    if unexpected_needed:
        problems.append(f"candidate declares non-base libraries: {unexpected_needed}")
    historical_import_review = sorted(
        name.split("@")[0] for name in candidate["imported"]
        if name.split("@")[0] not in EXPECTED_IMPORT_FAMILIES
        and not name.startswith("__")
    )
    # Full helpers now link the SDK; the early POSIX-only heuristic is historical.
    build_binding = {"path": str(args.build_report), "matched": False}
    build = {}
    try:
        build = json.loads(args.build_report.read_text(encoding="utf-8"))
        surface = build["surface"]
        build_binding["matched"] = (
            surface["sha256"] == candidate["sha256"]
            and surface["bytes"] == candidate["bytes"]
            and sorted(surface["undefined"]) == candidate["imported"]
            and sorted(surface["exported"]) == candidate["exported"]
            and sorted(surface["needed"]) == candidate["needed"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        build_binding["error"] = str(exc)
    if not build_binding["matched"]:
        problems.append("candidate dynamic surface is not bound to its actual helper build report")
    review_result = {"unreviewed": historical_import_review, "errors": [],
                     "traceMatched": False, "checkedObjects": 0, "open": candidate["imported"]}
    if args.import_review:
        try:
            import_review = json.loads(args.import_review.read_text(encoding="utf-8"))
            review_result = verify_import_review(import_review, candidate, build,
                                                 historical_import_review)
        except (OSError, ValueError, TypeError) as exc:
            review_result["errors"].append(str(exc))
    if review_result["unreviewed"] or review_result["errors"]:
        problems.append(f"imports need exact linked-object attribution: {review_result}")

    runtime_result = None
    if args.runtime_review:
        try:
            runtime_data = json.loads(args.runtime_review.read_text(encoding="utf-8"))
            runtime_result = verify_runtime_review(runtime_data, "helper", candidate)
        except (OSError, ValueError, TypeError) as exc:
            runtime_result = {"verifiedSymbols": [], "open": ["__libc_init"], "errors": [str(exc)]}
        if runtime_result["errors"] or runtime_result["open"]:
            problems.append(f"runtime import attribution is incomplete: {runtime_result}")

    report = {
        "runtimeImportReview": runtime_result,
        "schema": "maplesu-sdk-helper-contract/1",
        "byteIdentity": False,
        "scope": "Dynamic ABI and exact build-output binding; function/device acceptance remains separate",
        "buildBinding": build_binding,
        "historicalPosixHeuristicImports": historical_import_review,
        "importReview": {"path": str(args.import_review), **review_result},
        "note": "vendor bytes are a behaviour reference only; byte identity is not an "
                "acceptance criterion (see notes/HELPER.md)",
        "contract": {
            "requiredExports": REQUIRED_EXPORTS,
            "allowedNeeded": sorted(ALLOWED_NEEDED),
            "exportedSymbolsMatch": candidate["exported"] == REQUIRED_EXPORTS,
            "neededLibrariesAllowed": not unexpected_needed,
            "manifestDeclaredExports": declared_exports,
            "manifestDeclaredNeeded": declared_needed,
            "manifestConsistent": (candidate["exported"] == declared_exports
                                   and sorted(candidate["needed"]) == declared_needed),
        },
        "reference": reference,
        "candidate": candidate,
        "differences": {
            "exports": diff(reference["exported"], candidate["exported"]),
            "imports": diff(reference["imported"], candidate["imported"]),
            "needed": diff(reference["needed"], candidate["needed"]),
        },
        "documentedDifferences": [
            "candidate exports the two privileged primitives; the vendor helper exports none",
            "full source helper links the SDK archive; every raw import difference remains in differences",
            "liblog/libz are explicit dependencies of the source helper SDK link",
            "the exact source build report binds the observed imports, exports, libraries and file identity",
        ],
        "problems": problems,
        "passed": not problems,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print(f"[verify-helper] reference {reference['bytes']:,d} B exports={reference['exported']}")
    print(f"[verify-helper] candidate {candidate['bytes']:,d} B exports={candidate['exported']} "
          f"needed={candidate['needed']}")
    print(f"[verify-helper] imports: shared={len(report['differences']['imports']['shared'])} "
          f"candidate_only={len(report['differences']['imports']['in_candidate_only'])} "
          f"reference_only={len(report['differences']['imports']['in_reference_only'])}")
    for problem in problems:
        print(f"[verify-helper] PROBLEM {problem}", file=sys.stderr)
    print(f"[verify-helper] report: {args.report}")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
