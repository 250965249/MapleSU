#!/usr/bin/env python3
"""P0 gates for jailbreak-providers/maplesu-ghostlock (host-only, zero device).

    G-P0-1  the artifact compiles (NDK clang syntax + host syntax, no kernel headers)
    G-P0-2  no undefined symbol outside the memcpy/memset/strlen allowlist
    G-P0-3  host unit tests pass (C harness driven by python -m unittest)
    G-P0-4  the production gate still reports checks=26 and exits 0
    G-P0-5  the directory contains no device/kernel action or reference material

Every gate writes a log under gates/out/ and the run writes gates/out/summary.json.
Exit status is non-zero when any gate fails.

Usage:
    python gates/run_gates.py [--only G-P0-1] [--verbose]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import time

import toolchain

ROOT = toolchain.ROOT
REPO = toolchain.REPO
OUT = toolchain.GATES_OUT
INVARIANT_GATE = REPO / "jailbreak-providers" / "check_traceless_invariants.py"
TESTS = ROOT / "tests"


def _join(*parts: str) -> str:
    """Assemble a forbidden token so this scanner contains no literal of it."""
    return "".join(parts)


# Device / kernel action surface: none of these may appear anywhere in the dir.
SURFACE_PATTERNS = [
    _join("init", "_module"),
    _join("finit", "_module"),
    _join("ins", "mod"),
    _join("rm", "mod"),
    _join("delete", "_module"),
    _join("/dev/", "block"),
    _join("/dev/", "df"),
    _join("selinux/", "enforce"),
    _join("selinux/", "checkreqprot"),
    _join("exec", "ve"),
    _join("exec", "v("),
    _join("exec", "l("),
    _join("po", "pen"),
    _join("sys", "tem("),
    _join("for", "k("),
    _join("clo", "ne("),
    _join("pt", "race("),
    _join("io", "ctl("),
    _join("sys", "call("),
    _join("set", "con"),
    _join("set", "enforce"),
    _join("restore", "con"),
    _join("mount", "("),
    _join("umount", "("),
]

# Reference-implementation identifiers: interface facts live in docs, never here.
REFERENCE_PATTERNS = [
    _join("root", "Key"),
    _join("libcve2026", "_43499"),
    _join("COMPACT", "_WAITER"),
    _join("module_su", "_redirect"),
    _join("sk", "_spec/"),
    _join("ghostleaf", "_"),
    _join("permission", "manager"),
    _join("SkBoot", "Patcher"),
    _join("\x73\x6b\x72\x6f\x6f\x74", ".sdk"),
]

# Whole-word tokens: a privilege command name must not appear at all.
WORD_PATTERNS = [
    _join("ad", "b"),
    _join("fast", "boot"),
    _join("mag", "isk"),
    _join("ks", "ud"),
    _join("s", "u"),
]

TEXT_SUFFIXES = {".c", ".h", ".py", ".md", ".txt", ".json", ".sh", ".cmake", ""}
SKIP_DIRECTORIES = {"out", "__pycache__"}


class Gate:
    def __init__(self, identifier: str, title: str):
        self.identifier = identifier
        self.title = title
        self.ok = False
        self.details = []
        self.commands = []
        self.artifacts = []
        self.started = time.time()
        self.duration_ms = 0

    def log(self, message: str) -> None:
        self.details.append(message)

    def finish(self) -> None:
        self.duration_ms = int((time.time() - self.started) * 1000)

    def as_dict(self) -> dict:
        return {
            "gate": self.identifier,
            "title": self.title,
            "ok": self.ok,
            "duration_ms": self.duration_ms,
            "commands": self.commands,
            "artifacts": [str(path.relative_to(ROOT)) for path in self.artifacts],
            "details": self.details,
        }


def _record(gate: Gate, name: str, code: int, stdout: str, stderr: str) -> pathlib.Path:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / name
    toolchain.write_log(
        path,
        "exit=%d\n\n--- stdout ---\n%s\n--- stderr ---\n%s\n" % (code, stdout, stderr),
    )
    gate.artifacts.append(path)
    return path


def _python() -> str:
    return sys.executable


def gate_compile() -> Gate:
    gate = Gate("G-P0-1", "artifact compiles (syntax only, no kernel headers)")
    sources = [str(path) for path in toolchain.SOURCES]
    ndk = toolchain.find_ndk()

    if ndk is not None:
        clang = toolchain.ndk_tool(ndk, "clang")
        command = [
            clang,
            "--target=aarch64-linux-android29",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsyntax-only",
            "-I",
            str(toolchain.INCLUDE),
            *sources,
        ]
        gate.commands.append(" ".join(map(str, command)))
        code, stdout, stderr = toolchain.run(command, cwd=REPO)
        _record(gate, "G-P0-1.ndk-clang.log", code, stdout, stderr)
        if code != 0:
            gate.log("NDK clang syntax check failed")
            gate.finish()
            return gate
        gate.log("NDK clang --target=aarch64-linux-android29 -fsyntax-only: OK")
    else:
        gate.log("NDK not found: falling back to the host compiler for G-P0-1")

    host = toolchain.find_host_cc()
    command = [
        host,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-fsyntax-only",
        "-I",
        str(toolchain.INCLUDE),
        *sources,
    ]
    gate.commands.append(" ".join(map(str, command)))
    code, stdout, stderr = toolchain.run(
        command, cwd=REPO, env=toolchain.host_environment(host)
    )
    _record(gate, "G-P0-1.host.log", code, stdout, stderr)
    if code != 0:
        gate.log("host compiler syntax check failed")
        gate.finish()
        return gate
    gate.log("host %s -fsyntax-only -pedantic: OK" % host.name)
    gate.ok = True
    gate.finish()
    return gate


def _build_ndk_archive(gate: Gate, ndk: pathlib.Path) -> tuple[set, set, str]:
    clang = toolchain.ndk_tool(ndk, "clang")
    ar = toolchain.ndk_tool(ndk, "llvm-ar")
    nm = toolchain.ndk_tool(ndk, "llvm-nm")
    build = OUT / "ndk-build"
    build.mkdir(parents=True, exist_ok=True)
    objects = []
    transcript = []
    for source in toolchain.SOURCES:
        obj = build / (source.stem + ".o")
        command = [
            clang,
            "--target=aarch64-linux-android29",
            "-std=c11",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-pic",
            "-fno-plt",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(toolchain.INCLUDE),
            "-c",
            str(source),
            "-o",
            str(obj),
        ]
        transcript.append(" ".join(map(str, command)))
        code, stdout, stderr = toolchain.run(command, cwd=REPO)
        if code != 0:
            transcript.append(stdout + stderr)
            raise toolchain.ToolchainError("NDK compile failed for %s" % source)
        objects.append(obj)
    archive = build / "libmsk.a"
    command = [ar, "rcs", str(archive), *map(str, objects)]
    transcript.append(" ".join(map(str, command)))
    code, stdout, stderr = toolchain.run(command, cwd=REPO)
    if code != 0:
        raise toolchain.ToolchainError("llvm-ar failed")
    command = [nm, "-u", str(archive)]
    transcript.append(" ".join(map(str, command)))
    code, undefined_text, stderr = toolchain.run(command, cwd=REPO)
    if code != 0:
        raise toolchain.ToolchainError("llvm-nm -u failed")
    command = [nm, "-g", "--defined-only", str(archive)]
    transcript.append(" ".join(map(str, command)))
    code, defined_text, stderr = toolchain.run(command, cwd=REPO)
    if code != 0:
        raise toolchain.ToolchainError("llvm-nm --defined-only failed")
    undefined, defined = toolchain.parse_nm(undefined_text)
    _, defined_extra = toolchain.parse_nm(defined_text)
    defined |= defined_extra

    combined = build / "combined.o"
    linker = toolchain.ndk_tool(ndk, "ld.lld")
    command = [linker, "-r", "-o", str(combined), *map(str, objects)]
    transcript.append(" ".join(map(str, command)))
    code, stdout, stderr = toolchain.run(command, cwd=REPO)
    if code != 0:
        toolchain.write_log(OUT / "G-P0-2.nm.log", "\n".join(transcript))
        gate.artifacts.append(OUT / "G-P0-2.nm.log")
        raise toolchain.ToolchainError("ld.lld -r failed: %s" % (stdout + stderr))
    command = [nm, "-u", str(combined)]
    transcript.append(" ".join(map(str, command)))
    code, combined_text, stderr = toolchain.run(command, cwd=REPO)
    if code != 0:
        raise toolchain.ToolchainError("llvm-nm -u combined.o failed")
    toolchain.write_log(OUT / "G-P0-2.nm.log", "\n".join(transcript))
    gate.artifacts.append(OUT / "G-P0-2.nm.log")
    return undefined, defined, combined_text


def _build_host_objects(gate: Gate) -> tuple[set, set]:
    host = toolchain.find_host_cc()
    build = OUT / "host-build"
    build.mkdir(parents=True, exist_ok=True)
    objects = []
    transcript = []
    for source in toolchain.SOURCES:
        obj = build / (source.stem + ".o")
        command = [
            host,
            "-std=c11",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(toolchain.INCLUDE),
            "-c",
            str(source),
            "-o",
            str(obj),
        ]
        transcript.append(" ".join(map(str, command)))
        code, stdout, stderr = toolchain.run(
            command, cwd=REPO, env=toolchain.host_environment(host)
        )
        if code != 0:
            raise toolchain.ToolchainError("host compile failed for %s" % source)
        objects.append(obj)
    nm = host.parent / "nm.exe"
    if not nm.is_file():
        nm = host.parent / "nm"
    if not nm.is_file():
        raise toolchain.ToolchainError("host nm not found next to the compiler")
    undefined = set()
    defined = set()
    for obj in objects:
        command = [nm, "-u", str(obj)]
        code, stdout, stderr = toolchain.run(command, cwd=REPO)
        found, _ = toolchain.parse_nm(stdout)
        undefined |= found
        command = [nm, "--defined-only", str(obj)]
        code, stdout, stderr = toolchain.run(command, cwd=REPO)
        _, found_defined = toolchain.parse_nm(stdout)
        defined |= found_defined
        transcript.append("nm %s" % obj.name)
    toolchain.write_log(OUT / "G-P0-2.host-nm.log", "\n".join(transcript))
    gate.artifacts.append(OUT / "G-P0-2.host-nm.log")
    return undefined, defined


def gate_symbols() -> Gate:
    gate = Gate("G-P0-2", "undefined symbols stay inside the memcpy/memset/strlen allowlist")
    OUT.mkdir(parents=True, exist_ok=True)
    allowed = toolchain.ALLOWED_EXTERNAL_SYMBOLS
    ndk = toolchain.find_ndk()
    external = set()
    defined = set()
    combined_text = ""

    if ndk is not None:
        try:
            undefined, defined, combined_text = _build_ndk_archive(gate, ndk)
        except toolchain.ToolchainError as error:
            gate.log(str(error))
            gate.finish()
            return gate
        external = undefined - defined
        gate.log(
            "NDK archive: undefined=%d, internally resolved=%d"
            % (len(undefined), len(undefined & defined))
        )
        gate.log("NDK external references: %s" % (sorted(external) or "[]"))
        combined_undefined, _ = toolchain.parse_nm(combined_text)
        gate.log(
            "relocatable link (ld.lld -r) undefined: %s"
            % (sorted(combined_undefined) or "[]")
        )
        if not combined_undefined.issubset(allowed):
            gate.log("combined object has disallowed undefined symbols")
            gate.finish()
            return gate
    else:
        gate.log("NDK not found: falling back to host objects for G-P0-2")

    try:
        host_undefined, host_defined = _build_host_objects(gate)
    except toolchain.ToolchainError as error:
        gate.log(str(error))
        gate.finish()
        return gate
    host_external = host_undefined - host_defined
    gate.log("host external references: %s" % (sorted(host_external) or "[]"))
    external |= host_external

    if not external.issubset(allowed):
        gate.log("disallowed external symbols: %s" % sorted(external - allowed))
        gate.finish()
        return gate
    missing = toolchain.PUBLIC_API_SYMBOLS - defined
    if ndk is not None and missing:
        gate.log("public API symbol missing from the archive: %s" % sorted(missing))
        gate.finish()
        return gate
    gate.log("allowlist respected: %s" % (sorted(external) or "[] (no libc, no device)"))
    gate.ok = True
    gate.finish()
    return gate


def gate_unit_tests() -> Gate:
    gate = Gate("G-P0-3", "host unit tests pass (python -m unittest discover)")
    command = [
        _python(),
        "-m",
        "unittest",
        "discover",
        "-s",
        str(TESTS),
        "-v",
    ]
    gate.commands.append(" ".join(map(str, command)))
    environment = dict()
    environment.update(toolchain.host_environment(toolchain.find_host_cc()))
    code, stdout, stderr = toolchain.run(
        command, cwd=REPO, env=environment, timeout=600
    )
    _record(gate, "G-P0-3.unittest.log", code, stdout, stderr)
    combined = stdout + stderr
    match = re.search(r"Ran (\d+) tests?", combined)
    count = int(match.group(1)) if match else 0
    gate.log("tests run: %d" % count)
    if code != 0:
        gate.log("unittest exited %d" % code)
        gate.finish()
        return gate
    if count < 12:
        gate.log("expected at least 12 test methods, saw %d" % count)
        gate.finish()
        return gate
    if "\nOK" not in combined and "OK (" not in combined:
        gate.log("unittest did not report OK")
        gate.finish()
        return gate
    gate.log("unittest: OK (%d methods)" % count)
    gate.ok = True
    gate.finish()
    return gate


def gate_production() -> Gate:
    gate = Gate("G-P0-4", "production gate unchanged: checks=26, exit 0")
    if not INVARIANT_GATE.is_file():
        gate.log("missing %s" % INVARIANT_GATE)
        gate.finish()
        return gate
    digest = hashlib.sha256(INVARIANT_GATE.read_bytes()).hexdigest()
    gate.log("check_traceless_invariants.py sha256=%s" % digest)
    gate.log("(recorded for audit: this P0 track must not modify the file)")
    command = [_python(), str(INVARIANT_GATE)]
    gate.commands.append(" ".join(map(str, command)))
    code, stdout, stderr = toolchain.run(command, cwd=REPO, timeout=300)
    _record(gate, "G-P0-4.invariants.log", code, stdout, stderr)
    output = (stdout + stderr).strip()
    gate.log(output)
    if code != 0:
        gate.log("production gate exited %d" % code)
        gate.finish()
        return gate
    if "checks=26" not in output:
        gate.log("production gate no longer reports checks=26")
        gate.finish()
        return gate
    gate.ok = True
    gate.finish()
    return gate


def _text_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative_parts = set(path.relative_to(ROOT).parts)
        if relative_parts & SKIP_DIRECTORIES:
            continue
        if path.suffix == ".pyc":
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        yield path


def scan_forbidden(text: str):
    """Return [(kind, token, line_number)] for every forbidden token hit."""
    hits = []
    lines = text.splitlines()
    for line_number, line in enumerate(lines, 1):
        for token in SURFACE_PATTERNS:
            if token in line:
                hits.append(("surface", token, line_number))
        for token in REFERENCE_PATTERNS:
            if token in line:
                hits.append(("reference", token, line_number))
        for token in WORD_PATTERNS:
            if re.search(r"\b%s\b" % re.escape(token), line, re.IGNORECASE):
                hits.append(("word", token, line_number))
    return hits


def _scanner_self_test(gate: Gate) -> bool:
    """Prove the scanner actually detects a token it can never contain itself."""
    sample = "prefix " + _join("init", "_module") + " suffix"
    hits = scan_forbidden(sample)
    if not any(kind == "surface" and token == _join("init", "_module") for kind, token, _ in hits):
        gate.log("scanner self-test failed: synthetic surface token not detected")
        return False
    sample = "prefix " + _join("root", "Key") + " suffix"
    hits = scan_forbidden(sample)
    if not any(kind == "reference" for kind, _, _ in hits):
        gate.log("scanner self-test failed: synthetic reference token not detected")
        return False
    return True


def gate_surface() -> Gate:
    gate = Gate("G-P0-5", "zero device/kernel action and zero reference material")
    if not _scanner_self_test(gate):
        gate.finish()
        return gate
    violations = []
    scanned = 0
    for path in _text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            gate.log("non-UTF-8 file in tree: %s" % path.relative_to(ROOT))
            violations.append((path, "encoding", 0))
            continue
        scanned += 1
        for kind, token, line_number in scan_forbidden(text):
            violations.append((path, "%s:%s" % (kind, token), line_number))
    lines = ["scanned %d text files" % scanned]
    for path, detail, line_number in violations:
        lines.append("%s:%d %s" % (path.relative_to(ROOT), line_number, detail))
    report = "\n".join(lines) + "\n"
    toolchain.write_log(OUT / "G-P0-5.surface.log", report)
    gate.artifacts.append(OUT / "G-P0-5.surface.log")
    gate.log("scanned %d text files" % scanned)
    if violations:
        gate.log("violations: %d (see G-P0-5.surface.log)" % len(violations))
        gate.finish()
        return gate
    gate.log("surface scan: clean (patterns assembled at runtime, so this file "
             "contains no literal of them)")
    gate.ok = True
    gate.finish()
    return gate


GATES = {
    "G-P0-1": gate_compile,
    "G-P0-2": gate_symbols,
    "G-P0-3": gate_unit_tests,
    "G-P0-4": gate_production,
    "G-P0-5": gate_surface,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", action="append", default=None,
                        help="run only the named gate (repeatable)")
    parser.add_argument("--verbose", action="store_true")
    arguments = parser.parse_args()

    selected = list(GATES.items())
    if arguments.only:
        wanted = list(arguments.only)
        unknown = [name for name in wanted if name not in GATES]
        if unknown:
            print("unknown gate selection: %s" % unknown)
            return 2
        selected = [(name, GATES[name]) for name in wanted]

    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    for name, function in selected:
        try:
            gate = function()
        except toolchain.ToolchainError as error:
            gate = Gate(name, "toolchain failure")
            gate.log(str(error))
            gate.finish()
        except Exception as error:  # noqa: BLE001 - a gate crash is a gate failure
            gate = Gate(name, "unexpected gate error")
            gate.log("%s: %s" % (type(error).__name__, error))
            gate.finish()
        results.append(gate)
        status = "PASS" if gate.ok else "FAIL"
        print("%s %s  %s (%d ms)" % (status, gate.identifier, gate.title, gate.duration_ms))
        for detail in gate.details:
            for line in detail.splitlines():
                print("      %s" % line)
        if arguments.verbose:
            for command in gate.commands:
                print("      $ %s" % command)
        if not gate.ok:
            break

    overall = all(gate.ok for gate in results) and len(results) == len(selected)
    try:
        host_cc = str(toolchain.find_host_cc())
    except toolchain.ToolchainError:
        host_cc = None
    try:
        ndk = toolchain.find_ndk()
        ndk_bin = str(ndk) if ndk else None
    except toolchain.ToolchainError:
        ndk_bin = None
    summary = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "commit_context": "no git metadata in this workspace",
        "root": str(ROOT.relative_to(REPO)),
        "python": sys.version.split()[0],
        "host_cc": host_cc,
        "ndk_bin": ndk_bin,
        "gates": [gate.as_dict() for gate in results],
        "ok": overall,
    }
    (OUT / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print("\nSUMMARY %s (%d/%d gates)  evidence: %s"
          % ("PASS" if overall else "FAIL",
             sum(1 for gate in results if gate.ok), len(results),
             (OUT / "summary.json").relative_to(REPO)))
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
