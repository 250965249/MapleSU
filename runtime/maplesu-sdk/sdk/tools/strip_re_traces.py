"""Remove reverse-engineering traces from the delivered source comments.

The restoration process recorded, inside comments, where each function came
from: IR dump line numbers, disassembly offsets, "frozen member" comparisons,
tool invocations and per-function recovery status.  Those notes were useful
while building the tree but they must not ship.

Behaviour
---------
* The leading file header (the contiguous comment block before the first
  preprocessor line) is replaced by a short neutral header whenever it carries
  any trace, because those blocks are almost entirely provenance prose.
* Later comment-only lines carrying a trace marker are dropped; a trailing
  comment carrying a marker is stripped while the code stays.
* Orphaned rule lines and the blank runs left behind are collapsed.

Only comments change, so an -Oz rebuild must produce byte-identical objects.
That is the check which proves this pass touched presentation only: rebuild and
compare the archive sha256 before and after.

Usage:
    py tools/strip_re_traces.py [--check]
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]

MARKERS = [
    r"\bIR\b", r"llvm-ar", r"llvm-dis", r"llvm-objdump", r"\bobjdump\b", r"llvm-nm",
    r"llvm-readelf", r"llvm-cxxfilt", r"cxxfilt", r"\bfrozen\b", r"pristine",
    r"UNRECOVERED", r"\bevidence\b", r"\bdeviation\b", r"\bshipped\b", r"libkernel_module_kit",
    r"layout bitcode", r"layout elf", r"T surface", r"T 面", r"\bbaseline\b",
    r"逆向", r"反编译", r"复原", r"反汇编", r"冻结", r"出厂", r"原厂", r"符号集",
    r"源码化", r"偏差", r"归档成员", r"恢复依据", r"notes/work", r"sdk/out", r"manifest/",
    r"逐条对照", r"逐函数", r"字节级", r"sha256", r"sha-256",
    r":\d{3,}",          # IR dump line references such as ":437"
    r"\bll:\d+",         # "ll:437-1296"
]
MARKER_RE = re.compile("|".join(MARKERS), re.IGNORECASE)
RULE_RE = re.compile(r"^\s*//\s*[=\-*]{3,}\s*$")
COMMENT_RE = re.compile(r"^\s*(//|\*|/\*)")
PREPROC_RE = re.compile(r"^\s*#")


def split_comment(line: str) -> tuple[str, str]:
    idx = line.find("//")
    if idx < 0:
        return line, ""
    if line[:idx].count('"') % 2 == 1:
        return line, ""
    return line[:idx], line[idx:]


def neutral_header(path: Path) -> list[str]:
    stem = path.stem.replace("_", " ")
    return [
        "// " + stem + " implementation.\n",
        "//\n",
    ]


def sanitize(text: str, path: Path) -> tuple[str, int]:
    lines = text.splitlines(keepends=True)
    removed = 0

    # 1) replace a provenance-style leading header
    start = 0
    while start < len(lines) and lines[start].strip() == "":
        start += 1
    end = start
    while end < len(lines) and (COMMENT_RE.match(lines[end]) or lines[end].strip() == ""):
        if PREPROC_RE.match(lines[end]):
            break
        end += 1
    header = "".join(lines[start:end])
    if header and MARKER_RE.search(header):
        removed += header.count("//")
        lines = lines[:start] + neutral_header(path) + lines[end:]

    # 2) drop or trim remaining trace comments
    out: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("*") or stripped.startswith("/*"):
            if MARKER_RE.search(line):
                removed += 1
                continue
            out.append(line)
            continue
        code, comment = split_comment(line)
        if comment and MARKER_RE.search(comment):
            removed += 1
            if code.strip():
                out.append(code.rstrip() + "\n")
            continue
        out.append(line)

    # 3) drop orphaned rules and collapse blank runs
    result: list[str] = []
    blanks = 0
    for line in out:
        if RULE_RE.match(line):
            continue
        if line.strip() == "":
            blanks += 1
            if blanks > 1:
                continue
        else:
            blanks = 0
        result.append(line)
    return "".join(result), removed


SUFFIXES = (".cpp", ".c", ".h", ".cc", ".hpp", ".inl", ".S", ".s")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    touched = 0
    removed_total = 0
    failures: list[tuple[str, str]] = []
    for root in ("src", "include"):
        base = SDK / root
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.suffix not in SUFFIXES:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                failures.append((str(path), str(exc)))
                continue
            new, removed = sanitize(text, path)
            if removed and new != text:
                touched += 1
                removed_total += removed
                if not args.check:
                    try:
                        path.write_text(new, encoding="utf-8")
                    except OSError as exc:
                        failures.append((str(path), str(exc)))
    print(f"files rewritten      : {touched}")
    print(f"comment lines removed: {removed_total}")
    print(f"unwritable files     : {len(failures)}")
    for name, err in failures:
        print(f"  ! {name}: {err}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
