"""Repair manifest records whose free-form fields violate the member schema.

Two classes of defects were found by `build.py --gen-manifest`:

1. `compose` written as a prose string instead of a list of build steps
   (idx 25, 81).  The prose is preserved in `notes`, and `compose` becomes a
   real step list.
2. `recovery.unrecovered` used as a scratch pad for *payload asset* notes
   rather than function names (idx 49, 50), which trips the
   `unrecovered > functions` consistency check.  Those notes move to
   `notes`, the list is left with real function-level gaps, and the missing
   payload source is recorded in `blockedBy`.

The script is idempotent and only touches the four records named above.
Run with `py`.
"""

from __future__ import annotations

import json
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
MANIFEST = SDK / "manifest"


def load(name: str) -> tuple[Path, dict]:
    path = MANIFEST / name
    return path, json.loads(path.read_text(encoding="utf-8"))


def save(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def fix_compose(name: str, steps: list[str]) -> str:
    path, data = load(name)
    compose = data.get("compose")
    if isinstance(compose, list):
        return f"{name}: compose already a list, untouched"
    notes = data.get("notes", "")
    if isinstance(compose, str) and compose and compose not in notes:
        notes = (notes + "\n\n" if notes else "") + "compose 说明（原文保留）：\n" + compose
    data["notes"] = notes
    data["compose"] = steps
    save(path, data)
    return f"{name}: compose prose -> notes, compose = {len(steps)} step(s)"


def fix_unrecovered(name: str, keep: list[str], blocked: list[str]) -> str:
    path, data = load(name)
    rec = data.setdefault("recovery", {})
    old = rec.get("unrecovered") or []
    notes = data.get("notes", "")
    moved = [item for item in old if item not in keep]
    if moved:
        notes = (notes + "\n\n" if notes else "") + "资产/许可说明（从 recovery.unrecovered 移出）：\n" + "\n".join(
            f"- {item}" for item in moved
        )
    data["notes"] = notes
    rec["unrecovered"] = keep
    rec["recovered"] = rec.get("recovered", 0)
    rec["functions"] = max(rec.get("functions", 0), rec["recovered"] + len(keep))
    existing = data.get("blockedBy") or []
    data["blockedBy"] = sorted(set(existing) | set(blocked))
    data["status"] = "partial"
    save(path, data)
    return f"{name}: unrecovered {len(old)} -> {len(keep)}, blockedBy +{len(blocked)}"


def main() -> int:
    out = []
    out.append(
        fix_compose(
            "0025_module_base_kernel_func_executor.o.json",
            [
                "clang++ -c src/module_base/module_base_kernel_func_executor.cpp -o part1.o",
                "clang++ -c src/module_base/executor_restore.cpp -o part2.o   # part2 not yet recovered; see notes",
                "ld.lld -r part1.o part2.o -o module_base_kernel_func_executor.o",
            ],
        )
    )
    out.append(
        fix_compose(
            "0081_module_su_redirect.o.json",
            [
                "clang++ -c src/module/module_su_redirect.cpp -o part1.o",
                "clang++ -c ../../ultra/authorization/su_allowlist_writer.cpp -o part2.o   # not yet wired",
                "clang++ -c ../../ultra/authorization/su_auth_transaction.cpp -o part3.o   # not yet wired",
                "clang++ -c ../../ultra/authorization/su_exec_context.cpp -o part4.o       # not yet wired",
                "ld.lld -r part1.o part2.o part3.o part4.o -o module_su_redirect.o",
            ],
        )
    )
    out.append(
        fix_unrecovered(
            "0049_maplesu_unsafe_resetprop_install.o.json",
            keep=[],
            blocked=["payload source not in repository: resetprop payload is the Magisk v30.6 libmagisk.so image"],
        )
    )
    out.append(
        fix_unrecovered(
            "0050_maplesu_unsafe_webui_loader_install.o.json",
            keep=[],
            blocked=["payload source not in repository: webui_loader payload shipped as sdk/assets/webui_loader.bin"],
        )
    )
    for line in out:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
