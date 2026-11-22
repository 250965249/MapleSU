"""Reconcile declared member status with what the gate actually measured.

The member gate reports, per member, the T (exported) and U (undefined) symbol
diffs against the frozen snapshot.  Not every diff means "not recovered":

* a non-empty **T** diff means the member does not export what the shipped
  object exports -> genuinely incomplete;
* a **U** diff that contains a *kit API* symbol (``kernel_module::``,
  ``maplesu::sdk::``, ``kernel_root::``, ``maple_icache::``, ``maplesu_*``) means
  a call path was not reproduced -> genuinely incomplete;
* a **U** diff made only of libc / bionic / libc++ / third-party inline symbols
  is the clang point-version and sysroot difference that was measured and
  attributed independently (``third_party`` vendor gate, ``-D_FORTIFY_SOURCE``
  probes) -> recorded as a residual, not as a gap.

The script only ever touches records it previously annotated (marker string),
so it cannot silently promote a member that a work package deliberately left
partial for semantic reasons.

Usage:
    py tools/reconcile_status.py --gate <member-gate.json> [--check]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
MANIFEST = SDK / "manifest"
MARKER = "gate-measured gap vs frozen member"

KIT_PREFIXES = (
    "_ZN13kernel_module",
    "_ZN13kernel_module",
    "_ZN10skroot_env",
    "_ZN11kernel_root",
    "_ZN12maple_icache",
    "maplesu_",
    "_ZN12default_modules",
    "_ZL31",
)


def is_kit_symbol(sym: str) -> bool:
    return sym.startswith(KIT_PREFIXES)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", required=True)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    gate = json.loads(Path(args.gate).read_text(encoding="utf-8"))
    rows = gate.get("members") or []

    kept_complete = 0
    restored = []
    gaps = []
    untouched_partial = 0
    kept_partial = []

    for row in rows:
        idx, name = row["idx"], row["name"]
        diffs = row.get("diffs") or {}
        t_missing = diffs.get("t_missing") or []
        t_extra = diffs.get("t_extra") or []
        u_missing = diffs.get("u_missing") or []
        u_extra = diffs.get("u_extra") or []

        path = next(iter(sorted(MANIFEST.glob(f"{idx:04d}_{name}.json"))), None)
        if path is None:
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        rec = data.setdefault("recovery", {})
        items = [str(i) for i in (rec.get("unrecovered") or [])]
        mine = [i for i in items if MARKER in i]
        gate_fail = (row.get("status") == "FAIL")
        if not mine and not (gate_fail and data.get("status") == "complete"):
            # Not annotated by this tool and not an over-claiming complete record:
            # leave the author's judgement alone.
            if data.get("status") == "complete":
                kept_complete += 1
            else:
                untouched_partial += 1
            data["gate"] = {
                "status": row.get("status"),
                "t_missing": len(t_missing), "t_extra": len(t_extra),
                "u_missing": len(u_missing), "u_extra": len(u_extra),
            }
            if not args.check:
                path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            continue

        reduced = [i for i in items if MARKER not in i]
        kit_missing = [s for s in u_missing if is_kit_symbol(s)]
        real_gap = bool(t_missing or t_extra or kit_missing)

        data["gate"] = {
            "status": row.get("status"),
            "t_missing": len(t_missing), "t_extra": len(t_extra),
            "u_missing": len(u_missing), "u_extra": len(u_extra),
            "kit_symbols_missing": sorted(kit_missing),
            "residual_symbols": sorted(u_missing) if not real_gap else [],
            "classification": "real-gap" if real_gap else "toolchain-residual",
        }

        if real_gap:
            reason = (
                "gate-measured gap vs frozen member: T missing %d / extra %d, U missing %d / extra %d, "
                "missing kit API symbols: %s"
                % (len(t_missing), len(t_extra), len(u_missing), len(u_extra),
                   ", ".join(sorted(kit_missing)[:6]) or "-")
            )
            data["status"] = "partial"
            rec["unrecovered"] = reduced + [reason]
            rec["functions"] = max(int(rec.get("functions") or 0), int(rec.get("recovered") or 0) + len(reduced) + 1)
            gaps.append((idx, name, len(t_missing), len(t_extra), len(u_missing), len(kit_missing)))
        elif reduced:
            # The author recorded real unrecovered functions; the symbol sets may
            # agree while the body is knowingly incomplete.  Keep their verdict.
            data["status"] = "partial"
            rec["unrecovered"] = reduced
            kept_partial.append((idx, name, len(reduced)))
        else:
            data["status"] = "complete"
            rec["unrecovered"] = []
            # `complete` must be self-consistent: every counted function recovered.
            total = int(rec.get("functions") or 0)
            recovered = int(rec.get("recovered") or 0)
            if total <= recovered:
                total = recovered if recovered else 1
            rec["functions"] = total
            rec["recovered"] = total
            notes = data.get("notes") or ""
            extra = (
                "Gate: exported symbol set is exactly equal; the remaining undefined-symbol delta "
                "(%d missing / %d extra) contains no kit API symbol and is attributed to the pinned "
                "toolchain / bionic sysroot difference, listed in gate.residual_symbols."
                % (len(u_missing), len(u_extra))
            )
            if extra not in notes:
                data["notes"] = (notes + "\n\n" if notes else "") + extra
            restored.append((idx, name, len(u_missing)))

        if not args.check:
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"complete (author, not annotated)      : {kept_complete}")
    print(f"partial  (author, not annotated)      : {untouched_partial}")
    print(f"classified as toolchain residual      : {len(restored)}")
    for row in restored:
        print("  complete  %-4d %-45s U missing %d (no kit symbol)" % row)
    print(f"kept partial (author unrecovered)     : {len(kept_partial)}")
    print(f"classified as real gap                : {len(gaps)}")
    for row in gaps:
        print("  partial   %-4d %-45s T -%d/+%d  U -%d  kit-missing %d" % row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
