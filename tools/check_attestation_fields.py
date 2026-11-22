#!/usr/bin/env python3
"""Check that the two sides of the attestation protocol agree on field names.

The producer is C (`bootstrap.c`, a snprintf format string) and the consumer is Kotlin
(`HookAttestServer.kt`, `optString`/`optInt`/`optLong` lookups). Nothing type-checks
across that boundary: a rename on one side compiles cleanly and fails on the device as
"worker unreachable" - which is exactly how one round was lost before (`attemptId` vs
`attempt`). This gate reads both files and compares the name sets.

Reads only local files.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BOOTSTRAP = ROOT / "jailbreak-providers" / "dirtyfrag" / "adapter" / "bootstrap.c"
SERVER = ROOT / "manager" / "src" / "main" / "java" / "dev" / "maplesu" / "manager" / \
    "jailbreak" / "HookAttestServer.kt"


def c_fields(path: Path) -> dict[str, set[str]]:
    """The JSON keys each producer format string emits, keyed by a stable label."""
    text = path.read_text(encoding="utf-8")
    produced: dict[str, set[str]] = {}
    # `"key":"fmt"` and `"key":%d` pairs inside a snprintf format string.
    for match in re.finditer(r'\\"(\w+)\\":', text):
        produced.setdefault("all", set()).add(match.group(1))
    return produced


def kotlin_accessors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return set(re.findall(r"\.(?:optString|optInt|optLong|optBoolean|getString|getInt|"
                          r"getLong)\(\"(\w+)\"", text))


def main() -> int:
    if not BOOTSTRAP.is_file() or not SERVER.is_file():
        print("FAIL missing file: " + str(BOOTSTRAP if not BOOTSTRAP.is_file() else SERVER))
        return 2
    produced = c_fields(BOOTSTRAP).get("all", set())
    consumed = kotlin_accessors(SERVER)
    if not produced or not consumed:
        print("FAIL could not extract fields: produced=%d consumed=%d"
              % (len(produced), len(consumed)))
        return 2

    # Fields the App writes into its own record and then reads back: the worker has no
    # business producing them, so they are not "missing".
    app_written = {"peerPid", "peerUid", "observedAtMillis"}
    missing = sorted(consumed - produced - app_written)
    unused = sorted(produced - consumed)
    print("producer fields (%d): %s" % (len(produced), ", ".join(sorted(produced))))
    print("consumer fields (%d): %s" % (len(consumed), ", ".join(sorted(consumed))))
    app_side = sorted(consumed & app_written)
    if app_side:
        print("app-written and read back: " + ", ".join(app_side))
    if unused:
        print("note: produced but unread (may belong to another record): "
              + ", ".join(unused))
    if missing:
        print("FAIL the App reads fields the worker never writes: " + ", ".join(missing))
        return 1
    print("RESULT: every field the App reads is produced by the worker")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
