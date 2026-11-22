#!/usr/bin/env python3
"""Build-time receipts for explicit inputs and compiler-reported non-system files."""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path

import sdk_common as S

SCHEMA = "maplesu-sdk-source-provenance/2"
IR_SUFFIXES = {".ll", ".bc"}


def canonical_path(path: Path | str, root: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def file_record(path: Path | str, root: Path) -> dict:
    path = Path(path)
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return {"path": canonical_path(path, root), "size": size, "sha256": digest.hexdigest()}


def depfile_path(object_path: Path) -> Path:
    return Path(str(object_path) + ".d")


def dependency_flags(source: Path, object_path: Path) -> list[str]:
    if source.suffix.lower() in IR_SUFFIXES:
        return []
    return ["-MMD", "-MF", str(depfile_path(object_path)), "-MT", "maplesu_object"]


def parse_depfile(text: str) -> list[str]:
    """Parse one -MMD rule; -MT fixes the target, so drive colons stay in paths."""
    text = re.sub(r"\\\r?\n", " ", text)
    target, separator, text = text.partition(":")
    if not separator or target.strip() != "maplesu_object":
        raise ValueError("depfile target is not maplesu_object")
    tokens: list[str] = []
    token: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "#":
            break
        if char == "\\" and index + 1 < len(text) and text[index + 1] in " \t#\\:":
            token.append(text[index + 1])
            index += 2
            continue
        if char == "$" and text[index:index + 2] == "$$":
            token.append("$")
            index += 2
            continue
        if char.isspace():
            if token:
                tokens.append("".join(token))
                token = []
        else:
            token.append(char)
        index += 1
    if token:
        tokens.append("".join(token))
    return list(dict.fromkeys(tokens))


def precompile_snapshot(argv: list[str], source: Path, object_path: Path,
                        cwd: Path, root: Path, *, include_system: bool = False,
                        excluded_roots: tuple[Path, ...] = ()) -> dict:
    """Observe compiler inputs before compilation; this is not an atomic freeze.

    The preprocessor scan and actual compiler use the same source and flags.
    Before/after hashes detect persistent edits, not an A -> B -> A edit between
    observations. The default omits system headers; the backend includes them
    while explicitly excluding the NDK tree, matching its actual Ninja depfile.
    """
    errors: list[str] = []
    scan_command: list[str] = []
    dependencies: list[dict] = []
    source = source.resolve()
    try:
        source_before = file_record(source, root)
        if source.suffix.lower() in IR_SUFFIXES:
            dependencies = [source_before]
        else:
            # Use a separate depfile so a failed actual compile cannot inherit
            # the scanner's successful output as its own dependency evidence.
            scan_depfile = Path(str(object_path) + ".precompile.d")
            scan_depfile.parent.mkdir(parents=True, exist_ok=True)
            scan_depfile.unlink(missing_ok=True)
            raw = list(map(str, argv))
            index = 0
            while index < len(raw):
                flag = raw[index]
                if flag in ("-o", "-MF", "-MT", "-MQ", "-MJ"):
                    index += 2
                    continue
                if flag in ("-c", "-S", "-E", "-emit-llvm", "-MD", "-MMD", "-M", "-MM", "-MP"):
                    index += 1
                    continue
                if any(flag.startswith(prefix) and flag != prefix
                       for prefix in ("-MF", "-MT", "-MQ", "-MJ")):
                    index += 1
                    continue
                scan_command.append(flag)
                index += 1
            scan_command += ["-MD" if include_system else "-MMD",
                             "-MF", str(scan_depfile), "-MT", "maplesu_object",
                             "-E", "-o", os.devnull]
            done = S.run(scan_command, cwd=cwd)
            if done.returncode:
                raise ValueError(f"precompile dependency scan failed (exit {done.returncode}): "
                                 + (done.stderr or done.stdout or "")[-2000:])
            raw_paths = parse_depfile(scan_depfile.read_text(encoding="utf-8"))
            paths = [(Path(raw) if Path(raw).is_absolute() else cwd / raw).resolve()
                     for raw in raw_paths]
            paths = [path for path in paths if not any(path.is_relative_to(Path(excluded).resolve())
                     for excluded in excluded_roots)]
            if source not in paths:
                raise ValueError("precompile depfile does not contain the compiled source")
            dependencies = [file_record(path, root) for path in dict.fromkeys(paths)]
            if source_before != next(item for item in dependencies
                                     if item["path"] == source_before["path"]):
                errors.append("source changed during precompile dependency scan: "
                              + source_before["path"])
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        errors.append(str(exc))
    return {"schema": "maplesu-sdk-precompile-inputs/1",
            "source": canonical_path(source, root), "object": canonical_path(object_path, root),
            "command": list(map(str, argv)), "cwd": canonical_path(cwd, root),
            "scan_command": scan_command,
            "dependency_scope": "compiler-reported-inputs-excluding-toolchain" if include_system
                                else "non-system-preprocessor-inputs-and-explicit-ir",
            "excluded_roots": [canonical_path(path, root) for path in excluded_roots],
            "inputs": sorted(dependencies, key=lambda row: row["path"]),
            "complete": not errors, "errors": errors,
            "stability_scope": "before-after-observation-not-atomic-freeze"}


def precompile_comparison(precompile: dict | None, source: Path, object_path: Path,
                          dependencies: list[dict], root: Path) -> dict:
    errors: list[str] = []
    if not precompile:
        errors.append("precompile input snapshot missing")
    else:
        if precompile.get("schema") != "maplesu-sdk-precompile-inputs/1":
            errors.append("precompile input snapshot schema differs")
        if not precompile.get("complete", False):
            errors += precompile.get("errors") or ["precompile input snapshot incomplete"]
        if (precompile.get("source") != canonical_path(source, root)
                or precompile.get("object") != canonical_path(object_path, root)):
            errors.append("precompile source/object selection differs")
        before = {row["path"]: row for row in precompile.get("inputs") or []}
        after = {row["path"]: row for row in dependencies}
        if set(before) != set(after):
            errors.append("compiler dependencies differ from precompile snapshot")
        for path in set(before) & set(after):
            if before[path] != after[path]:
                errors.append("input changed during compilation: " + path)
    return {"precompile": precompile, "precompile_complete": not errors,
            "precompile_errors": errors}


def dependency_receipt(source: Path, object_path: Path, cwd: Path, root: Path,
                       precompile: dict | None = None) -> dict:
    kind = "ir-source" if source.suffix.lower() in IR_SUFFIXES else "compiler-mmd"
    errors: list[str] = []
    paths = [source.resolve()]
    if kind == "compiler-mmd":
        try:
            raw_paths = parse_depfile(depfile_path(object_path).read_text(encoding="utf-8"))
            if not raw_paths:
                raise ValueError("depfile contains no inputs")
            compiled_paths = [(Path(raw) if Path(raw).is_absolute() else cwd / raw).resolve()
                              for raw in raw_paths]
            if source.resolve() not in compiled_paths:
                raise ValueError("depfile does not contain the compiled source")
            paths += compiled_paths
        except (OSError, ValueError) as exc:
            errors.append(f"{canonical_path(object_path, root)}: {exc}")
    dependencies = []
    for path in dict.fromkeys(paths):
        try:
            dependencies.append(file_record(path, root))
        except OSError as exc:
            errors.append(f"{canonical_path(path, root)}: {exc}")
    result = {"dependencies": sorted(dependencies, key=lambda row: row["path"]),
            "dependency_kind": kind, "dependency_complete": not errors,
            "dependency_errors": errors}
    if precompile is not None:
        result.update(precompile_comparison(precompile, source, object_path, result["dependencies"], root))
    return result


def toolchain_record(tc, root: Path, versions: dict | None = None) -> dict:
    observed = dict(versions or {})
    for name in ("clang", "llvm-ar", "ld.lld"):
        if name in observed:
            continue
        if name not in tc.versions:
            done = S.run([tc.tool(name), "--version"], timeout=30)
            lines = ((done.stdout or "") + (done.stderr or "")).strip().splitlines()
            tc.versions[name] = lines[0] if done.returncode == 0 and lines else "unavailable"
        observed[name] = tc.versions[name]
    return {"ndk_root": canonical_path(tc.ndk, root), "ndk_version": tc.ndk.name,
            "target": "aarch64-linux-android21", "versions": observed}


def snapshot_inputs(inputs: list[tuple[Path, str]], root: Path) -> list[dict]:
    """Capture selected explicit inputs before their build/generator executes."""
    return [{**file_record(path if Path(path).is_absolute() else root / path, root),
             "roles": [role]} for path, role in inputs]


def build_receipt(units: list[dict], inputs: list[tuple[Path, str]], root: Path,
                  toolchain: dict | None = None, children: list[dict] = (),
                  incomplete: list[str] = (), input_snapshots: list[dict] = ()) -> dict:
    """Keep the compile rows and top-level closure backed by the same snapshots."""
    by_path: dict[str, dict] = {}
    translation_units: list[dict] = []
    errors = list(incomplete)

    def add_record(record: dict, roles: list[str]) -> None:
        path = record["path"]
        previous = by_path.get(path)
        if previous:
            if (previous["size"], previous["sha256"]) != (record["size"], record["sha256"]):
                errors.append(f"input changed between build snapshots: {path}")
            previous["roles"] = sorted(set(previous["roles"]) | set(roles))
        else:
            by_path[path] = {**record, "roles": sorted(set(roles))}

    def add_file(path: Path | str, role: str) -> None:
        path = Path(path)
        if not path.is_absolute():
            path = root / path
        try:
            add_record(file_record(path, root), [role])
        except OSError as exc:
            errors.append(f"{canonical_path(path, root)}: {exc}")

    input_snapshots = list(input_snapshots)
    for record in input_snapshots:
        add_record(record, record.get("roles") or [])
    for path, role in inputs:
        add_file(path, role)
    for unit in units:
        for key in ("source", "build_source"):
            if unit.get(key):
                add_file(unit[key], "tu")
        dependencies = unit.get("dependencies") or []
        source_paths = {unit.get("source"), unit.get("build_source")}
        for record in dependencies:
            add_record(record, ["tu" if record["path"] in source_paths else "header"])
        if not unit.get("dependency_complete", False):
            errors += unit.get("dependency_errors") or [
                f"dependency receipt missing: {unit.get('object')}"]
        compile_steps = unit.get("compile_steps") or []
        for step in compile_steps:
            for record in step.get("dependencies") or []:
                add_record(record, ["tu" if record["path"] in
                           {step.get("source"), step.get("build_source")} else "header"])
            if not step.get("dependency_complete", False):
                errors += step.get("dependency_errors") or [
                    f"dependency receipt missing: {step.get('object')}"]
        row = {key: unit[key] for key in ("source", "build_source", "object", "program", "stage", "bytes", "sha256")
               if key in unit}
        if "idx" in unit:
            row["member_idx"] = unit["idx"]
        if "name" in unit:
            row["member"] = unit["name"]
        row.update({"dependencies": [record["path"] for record in dependencies],
                    "dependency_kind": unit.get("dependency_kind", "not-captured"),
                    "precompile": unit.get("precompile"),
                    "precompile_complete": unit.get("precompile_complete", False),
                    "precompile_errors": unit.get("precompile_errors") or []})
        if compile_steps:
            row["compile_steps"] = compile_steps
        translation_units.append(row)
    for child in children:
        for record in child.get("inputs") or []:
            add_record(record, record.get("roles") or [])
        translation_units += child.get("translation_units") or []
        errors += child.get("incomplete_reasons") or []
        if not child.get("closure_complete", False) and not child.get("incomplete_reasons"):
            errors.append("child build has no complete dependency receipt")

    def verify_snapshot(record: dict, kind: str) -> None:
        path = Path(record["path"])
        if not path.is_absolute():
            path = root / path
        try:
            current = file_record(path, root)
        except OSError as exc:
            errors.append(f"{kind} {record['path']}: {exc}")
            return
        if (current["size"], current["sha256"]) != (record["size"], record["sha256"]):
            errors.append(f"{kind} changed since build snapshot: {record['path']}")

    for record in by_path.values():
        verify_snapshot(record, "input")
    for unit in translation_units:
        for step in [unit, *(unit.get("compile_steps") or [])]:
            source = Path(step.get("build_source") or step.get("source") or "")
            obj = Path(step.get("object") or "")
            observed = []
            for dependency in step.get("dependencies") or []:
                record = dependency if isinstance(dependency, dict) else by_path.get(dependency)
                if record is not None:
                    observed.append({key: record[key] for key in ("path", "size", "sha256")})
            comparison = precompile_comparison(step.get("precompile"),
                source if source.is_absolute() else root / source,
                obj if obj.is_absolute() else root / obj, observed, root)
            errors += comparison["precompile_errors"]
            if not step.get("precompile_complete", False):
                errors += step.get("precompile_errors") or [
                    f"precompile input snapshot missing: {step.get('object')}"]
            for record in (step.get("precompile") or {}).get("inputs") or []:
                verify_snapshot(record, "precompile input")
            if not all(key in step for key in ("object", "bytes", "sha256")):
                errors.append(f"object identity receipt missing: {step.get('object')}")
                continue
            verify_snapshot({"path": step["object"], "size": step["bytes"],
                             "sha256": step["sha256"]}, "object")
    if toolchain and "unavailable" in toolchain.get("versions", {}).values():
        errors.append("toolchain version query was incomplete")
    return {"schema": SCHEMA, "inputs": [by_path[key] for key in sorted(by_path)],
            "input_snapshots": input_snapshots,
            "translation_units": translation_units, "toolchain": toolchain,
            "closure_complete": not errors, "incomplete_reasons": sorted(set(errors)),
            "dependency_scope": ("compiler-reported-inputs-excluding-toolchain-and-explicit-ir"
                if any((unit.get("precompile") or {}).get("dependency_scope") ==
                       "compiler-reported-inputs-excluding-toolchain" for unit in translation_units)
                else "non-system-preprocessor-inputs-and-explicit-ir"),
            "input_stability": "before-after-observation-not-atomic-freeze",
            "runtime_acceptance": False}
