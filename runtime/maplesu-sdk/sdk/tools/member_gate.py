#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""member_gate.py -- per-member T/U/layout gate: built archive vs frozen epoch.

What is compared, for each archive member (addressed by ordinal, so the three
different ``patch_base.o`` bodies stay distinct):

* **layout** -- ``bitcode`` vs ``elf`` flip;
* **T set**  -- strong *defined external* symbols (``llvm-nm`` kinds T/D/B/R/A/S/G/C;
  weak W/V/w/v and local t/d/b symbols are excluded on purpose, they are TU-private);
* **U set**  -- strong *undefined external* symbols;
* **ordinal sequence** -- same names in the same order, duplicates included;
* **missing / extra members** -- by (name, occurrence), never by name alone.

Empty-set semantics: symbol sets are parsed into Python sets and compared with
``!=``/``-``. A member with no defined and no undefined symbols compared against
another member with none yields zero diffs and PASSES. Nothing here uses
``grep -q``, ``test -s`` or "non-empty output" as a proxy for "symbol exists".

Allowlist: ``sdk/notes/gate-allow.json`` (absent by default). Each entry
suppresses one exact measured difference, never a whole member::

    {"entries": [
      {"member": "zip_close.o", "category": "U", "symbol": "_ZdlPv",
       "reason": "operator delete is provided by libc++_shared on device"}
    ]}

Exit codes: 0 gate PASS, 7 gate FAIL, 2 usage/environment.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

TOOLS_DIR = Path(__file__).resolve().parent
SDK_DIR = TOOLS_DIR.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import sdk_common as S  # noqa: E402

GATE_SCHEMA = "maplesu-member-gate/1"
DEFAULT_OUT = SDK_DIR / "build" / "report" / "member-gate.json"
DEFAULT_ALLOW = SDK_DIR / "notes" / "gate-allow.json"
DEFAULT_BASELINE = SDK_DIR / "notes" / "gate-symbol-baseline.json"
DEFAULT_MANIFEST = SDK_DIR / "manifest.jsonl"
EXPECTED_MEMBERS = 260  # Fallback before the selected freeze archive is read.
ALLOW_CATEGORIES = ("T", "U", "layout", "missing", "extra", "ordinal")


# --------------------------------------------------------------------------- #
# Allowlist
# --------------------------------------------------------------------------- #


@dataclass
class AllowList:
    path: Path | None = None
    entries: list[dict[str, Any]] = field(default_factory=list)
    by_key: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    invalid: list[str] = field(default_factory=list)
    applied: set[tuple[int, str, str, str]] = field(default_factory=set)
    unused: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None) -> "AllowList":
        allow = cls(path=path)
        if path is None or not Path(path).is_file():
            return allow
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            allow.invalid.append(str(exc))
            return allow
        entries = raw.get("entries") if isinstance(raw, dict) else raw
        if not isinstance(entries, list):
            allow.invalid.append("expected a list or {\"entries\": [...]}")
            return allow
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                allow.invalid.append(f"entry {index}: not an object")
                continue
            member = entry.get("member")
            category = str(entry.get("category", ""))
            symbol = str(entry.get("symbol", ""))
            if not member or category not in ALLOW_CATEGORIES:
                allow.invalid.append(
                    f"entry {index}: needs member and category in {ALLOW_CATEGORIES}")
                continue
            if category in ("T", "U") and not symbol:
                allow.invalid.append(f"entry {index}: T/U entries need an exact symbol")
                continue
            entry = dict(entry)
            allow.entries.append(entry)
            allow.by_key[(str(member), category, symbol)] = entry
        allow.unused = list(allow.entries)
        return allow

    def allow(self, member: str, category: str, symbol: str = "") -> bool:
        entry = self.by_key.get((member, category, symbol))
        if entry is None:
            return False
        key = (id(entry), member, category, symbol)
        if key not in self.applied:
            self.applied.add(key)
            if entry in self.unused:
                self.unused.remove(entry)
        return True

    @property
    def applied_count(self) -> int:
        return len({key[0] for key in self.applied})

    def summary(self) -> dict[str, Any]:
        return {
            "path": S.rel(self.path) if self.path else None,
            "entries": len(self.entries),
            "applied": self.applied_count,
            "unused": len(self.unused),
            "invalid": self.invalid,
            "unused_entries": self.unused[:40],
        }


@dataclass
class SymbolBaseline:
    """Declared toolchain baseline (sdk/notes/gate-symbol-baseline.json).

    Scope is *llvm-bitcode members only*: the reference bitcode was produced by a
    different clang point build (r487747e) than the pinned NDK (r487747d), which
    materialises a few libc++ COMDAT symbols into the reference object. Native-ELF
    members get **zero** allowance. T sets are never excused by this file: the
    hard rules of the baseline forbid it.
    """

    path: Path | None = None
    scope: str = ""
    reason: str = ""
    missing: dict[str, dict[str, Any]] = field(default_factory=dict)
    extra: dict[str, dict[str, Any]] = field(default_factory=dict)
    consumed: dict[str, int] = field(default_factory=dict)
    invalid: list[str] = field(default_factory=list)

    ALLOWED_LAYOUTS = ("bitcode",)

    @classmethod
    def load(cls, path: Path | None) -> "SymbolBaseline":
        baseline = cls(path=path)
        if path is None or not Path(path).is_file():
            return baseline
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            baseline.invalid.append(str(exc))
            return baseline
        baseline.scope = str(raw.get("scope") or "")
        baseline.reason = str(raw.get("reason") or "")
        for key, target in (("uMissing", baseline.missing), ("uExtra", baseline.extra)):
            entries = raw.get(key) or []
            if not isinstance(entries, list):
                baseline.invalid.append(f"{key} is not a list")
                continue
            for entry in entries:
                if not isinstance(entry, dict) or not entry.get("symbol"):
                    baseline.invalid.append(f"{key}: entry without a symbol")
                    continue
                target[str(entry["symbol"])] = entry
        return baseline

    def _entry_allows(self, entry: dict[str, Any], layout: str, member_idx: int | None) -> bool:
        """A declared allowance applies only where it says it applies.

        Entries without `applies_to` keep the historical behaviour: they are
        generic toolchain allowances and only apply to bitcode members.  An
        entry with `applies_to` names the member indices it covers; an entry may
        also carry an explicit `layout` when the underlying cause was measured
        on a native-ELF member (for example declaration-only dead code kept in
        the reference object).  Evidence is mandatory for scoped entries.
        """
        scoped = entry.get("applies_to")
        entry_layout = str(entry.get("layout") or "")
        if scoped is None:
            return layout in self.ALLOWED_LAYOUTS and not entry_layout
        if member_idx is None or int(member_idx) not in {int(i) for i in scoped}:
            return False
        if entry_layout and entry_layout != layout:
            return False
        if not str(entry.get("evidence") or "").strip():
            return False
        return True

    def allows_missing(self, symbol: str, layout: str, member_idx: int | None = None) -> bool:
        entry = self.missing.get(symbol)
        return bool(entry) and self._entry_allows(entry, layout, member_idx)

    def allows_extra(self, symbol: str, layout: str, member_idx: int | None = None) -> bool:
        entry = self.extra.get(symbol)
        return bool(entry) and self._entry_allows(entry, layout, member_idx)

    def consume(self, symbol: str) -> None:
        self.consumed[symbol] = self.consumed.get(symbol, 0) + 1

    def summary(self) -> dict[str, Any]:
        return {
            "path": S.rel(self.path) if self.path else None,
            "present": bool(self.path and Path(self.path).is_file()),
            "scope": self.scope,
            "allowed_layouts": list(self.ALLOWED_LAYOUTS),
            "entries": len(self.missing) + len(self.extra),
            "consumed_total": sum(self.consumed.values()),
            "consumed": dict(sorted(self.consumed.items())),
            "unused": sorted(set(self.missing) - set(self.consumed)),
            "invalid": self.invalid,
            "reason": self.reason[:400],
        }


# --------------------------------------------------------------------------- #
# Symbol comparison (pure logic, unit-testable)
# --------------------------------------------------------------------------- #


def compare_symbol_sets(ref_t: Iterable[str], ref_u: Iterable[str],
                        new_t: Iterable[str], new_u: Iterable[str],
                        ) -> dict[str, list[str]]:
    """Set-difference both directions; empty sets are equal, not "missing output"."""
    ref_t, ref_u = set(ref_t), set(ref_u)
    new_t, new_u = set(new_t), set(new_u)
    return {
        "t_missing": sorted(ref_t - new_t),
        "t_extra": sorted(new_t - ref_t),
        "u_missing": sorted(ref_u - new_u),
        "u_extra": sorted(new_u - ref_u),
    }


def self_test() -> list[dict[str, Any]]:
    """Direct tests of the empty-set rule, independent of any archive."""
    checks: list[dict[str, Any]] = []

    def check(name: str, got: bool, wanted: bool) -> None:
        checks.append({"check": name, "pass": got == wanted,
                       "detail": f"got {got}, wanted {wanted}"})

    empty = compare_symbol_sets([], [], [], [])
    check("empty-vs-empty yields zero diffs", all(not v for v in empty.values()), True)
    check("empty-vs-empty verdict is PASS", verdict_of(empty, [], []) == "PASS", True)
    one = compare_symbol_sets(["_Z3foov"], [], [], [])
    check("ref-with-a-symbol vs empty is FAIL", verdict_of(one, [], []) == "FAIL", True)
    check("missing set is reported", one["t_missing"] == ["_Z3foov"], True)
    extra = compare_symbol_sets([], [], [], ["_ZdlPv"])
    check("extra undefined is reported", extra["u_extra"] == ["_ZdlPv"], True)
    both = compare_symbol_sets(["_A"], ["_B"], ["_A"], ["_B"])
    check("identical non-empty sets yield zero diffs", all(not v for v in both.values()), True)
    return checks


def verdict_of(symbol_diffs: dict[str, list[str]], other_problems: Sequence[str],
               deferred: Sequence[str] = ()) -> str:
    if any(symbol_diffs.get(key) for key in ("t_missing", "t_extra", "u_missing", "u_extra")):
        return "FAIL"
    if other_problems:
        return "FAIL"
    return "PASS"


# --------------------------------------------------------------------------- #
# Measurement
# --------------------------------------------------------------------------- #


@dataclass
class MemberFacts:
    idx: int
    name: str
    occurrence: int
    sha256: str
    bytes: int
    layout: str
    t: frozenset[str] = frozenset()
    u: frozenset[str] = frozenset()
    w_defined: frozenset[str] = frozenset()
    w_undefined: frozenset[str] = frozenset()
    weak: int = 0
    local: int = 0
    nm_error: str = ""

    @property
    def key(self) -> tuple[str, int]:
        return (self.name, self.occurrence)


def measure_archive(tc: S.Toolchain, archive: S.Archive, work_dir: Path,
                    jobs: int = 8, side: str = "new") -> dict[tuple[str, int], MemberFacts]:
    """Extract every member once and measure its layout + T/U sets."""
    side_dir = work_dir / side
    if side_dir.exists():
        shutil.rmtree(side_dir)
    side_dir.mkdir(parents=True, exist_ok=True)

    occurrences: dict[str, int] = {}
    tasks: list[tuple[S.ArchiveMember, int, Path]] = []
    for member in archive.members:
        occ = occurrences.get(member.name, 0)
        occurrences[member.name] = occ + 1
        path = side_dir / f"{member.idx:04d}__{member.name}"
        path.write_bytes(member.data)
        tasks.append((member, occ, path))

    def one(task: tuple[S.ArchiveMember, int, Path]) -> MemberFacts:
        member, occ, path = task
        facts = MemberFacts(idx=member.idx, name=member.name, occurrence=occ,
                            sha256=member.sha256, bytes=member.size,
                            layout=member.layout)
        try:
            table = S.nm_symbols(tc, path)
            facts.t = table.defined
            facts.u = table.undefined
            facts.w_defined = table.weak_defined
            facts.w_undefined = table.weak_undefined
            facts.weak = len(table.weak_defined) + len(table.weak_undefined)
            facts.local = len(table.local_defined)
        except S.ArchiveError as exc:
            facts.nm_error = str(exc)[:400]
        return facts

    measured: dict[tuple[str, int], MemberFacts] = {}
    if jobs <= 1:
        results = [one(task) for task in tasks]
    else:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(one, tasks))
    for facts in results:
        measured[facts.key] = facts
    return measured


# --------------------------------------------------------------------------- #
# Manifest scope
# --------------------------------------------------------------------------- #


def load_scope(manifest_path: Path | None
               ) -> tuple[list[int] | None, int, dict[int, str], list[dict[str, Any]]]:
    """Return (in-scope indices, archive expectation, status per idx, no-source list).

    A ``partial`` member with no ``sources`` is *blocked* (declared blockedBy): it
    cannot be built, so it is deferred from the gate instead of being reported as a
    missing member. ``vendor-copy`` without sources stays in scope because it is
    materialised from the freeze.
    """
    if manifest_path is None or not Path(manifest_path).is_file():
        return None, EXPECTED_MEMBERS, {}, []
    indices: list[int] = []
    status: dict[int, str] = {}
    no_source: list[dict[str, Any]] = []
    for line in Path(manifest_path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        idx = record.get("idx")
        if not isinstance(idx, int) or isinstance(idx, bool):
            continue
        state = str(record.get("status") or "?")
        sources = record.get("sources") or []
        if state == S.STATUS_PARTIAL and not sources:
            no_source.append({"idx": idx, "name": record.get("name"),
                              "blockedBy": record.get("blockedBy") or []})
            continue
        indices.append(idx)
        status[idx] = state
    return sorted(set(indices)), EXPECTED_MEMBERS, status, no_source


# --------------------------------------------------------------------------- #
# Gate
# --------------------------------------------------------------------------- #


def run_gate(
    new_archive: Path | str,
    ref_archive: Path | str | None = None,
    out_path: Path | str | None = None,
    allow_path: Path | str | None = None,
    baseline_path: Path | str | None = None,
    manifest_path: Path | str | None = None,
    scope: str = "auto",
    allow_partial: bool = False,
    work_dir: Path | str | None = None,
    jobs: int = 8,
    quiet: bool = False,
    ndk: str | None = None,
) -> dict[str, Any]:
    new_path = Path(new_archive)
    started = time.monotonic()
    out_path = Path(out_path) if out_path else DEFAULT_OUT
    allow = AllowList.load(Path(allow_path) if allow_path else DEFAULT_ALLOW)
    baseline = SymbolBaseline.load(Path(baseline_path) if baseline_path else DEFAULT_BASELINE)

    result: dict[str, Any] = {
        "schema": GATE_SCHEMA,
        "tool": "runtime/maplesu-sdk/sdk/tools/member_gate.py",
        "status": "FAIL",
        "scope": scope,
        "expected_members": EXPECTED_MEMBERS,
        "inputs": {},
        "allowlist": allow.summary(),
        "baseline": baseline.summary(),
        "summary": {},
        "problems": [],
        "members": [],
        "deferred_idx": [],
    }

    def fail(message: str) -> dict[str, Any]:
        result["problems"].append(message)
        result["summary"] = {"pass": 0, "fail": 1, "deferred": 0}
        if not quiet:
            print(f"[gate] FAIL: {message}", file=sys.stderr)
        S.write_json(out_path, S.jsonable(result))
        return result

    try:
        tc = S.resolve_toolchain(ndk)
    except S.ToolchainMissing as exc:
        return fail(f"toolchain: {exc}")
    try:
        snapshot = S.find_freeze(str(ref_archive) if ref_archive else None)
        ref = S.read_archive(snapshot.archive)
    except (S.FreezeError, S.ArchiveError) as exc:
        return fail(f"reference archive: {exc}")
    expected_members = len(ref.members)
    result["expected_members"] = expected_members
    if not new_path.is_file():
        return fail(f"new archive not found: {S.rel(new_path)} (build it with build.py --pack)")
    try:
        new = S.read_archive(new_path)
    except S.ArchiveError as exc:
        return fail(f"new archive is unreadable: {exc}")

    declared, _total, declared_status, no_source = load_scope(
        Path(manifest_path) if manifest_path else DEFAULT_MANIFEST)
    full_expected = declared is None or len(declared) >= expected_members
    effective_scope = scope
    if scope == "auto":
        effective_scope = "full" if (full_expected and not allow_partial) else "partial"
    result["scope"] = effective_scope
    result["inputs"] = {
        "new": {"path": S.rel(new_path), "sha256": new.sha256, "bytes": new.size,
                "members": len(new.members),
                "layout_counts": _layout_counts(new)},
        "ref": {"path": S.rel(ref.path), "sha256": ref.sha256, "bytes": ref.size,
                "members": len(ref.members), "layout_counts": _layout_counts(ref),
                "snapshot": S.rel(snapshot.root)},
        "manifest": S.rel(Path(manifest_path)) if manifest_path else None,
        "declared_members": len(declared) if declared is not None else expected_members,
    }

    work = Path(work_dir) if work_dir else (out_path.parent / "gate-work")
    ref_facts = measure_archive(tc, ref, work, jobs=jobs, side="ref")
    new_facts = measure_archive(tc, new, work, jobs=jobs, side="new")

    in_scope: set[int] = set(declared) if (declared is not None and effective_scope == "partial") \
        else set(range(expected_members))
    result["deferred_idx"] = sorted(set(range(expected_members)) - in_scope)
    result["deferred_no_source"] = [
        row for row in no_source if row["idx"] not in (in_scope if declared else set())]

    # --- ordinal sequence ------------------------------------------------
    ref_names = [S.active_member_name(name) for name in ref.names]
    new_names = new.names
    if effective_scope == "full":
        if new_names != ref_names:
            first = next((i for i, (a, b) in enumerate(zip(ref_names, new_names)) if a != b),
                         min(len(ref_names), len(new_names)))
            result["problems"].append(
                f"ordinal sequence differs at index {first}: expected "
                f"{ref_names[first] if first < len(ref_names) else '<end>'!r}, got "
                f"{new_names[first] if first < len(new_names) else '<end>'!r} "
                f"({len(new_names)} members vs {len(ref_names)})")

    # --- membership ------------------------------------------------------
    # Occurrence numbering for the reference is computed *within the scope*, so a
    # partial build that omits two of the three patch_base.o bodies still pairs the
    # remaining body with the remaining frozen body instead of reporting a phantom
    # missing/extra pair. In full scope this is identical to the global ordinal.
    ref_members: dict[tuple[str, int], MemberFacts] = {}
    occurrence: dict[str, int] = {}
    for facts in sorted(ref_facts.values(), key=lambda f: f.idx):
        if facts.idx not in in_scope:
            continue
        name = S.active_member_name(facts.name)
        occ = occurrence.get(name, 0)
        occurrence[name] = occ + 1
        ref_members[(name, occ)] = facts
    new_members = dict(new_facts)
    missing = [key for key in ref_members if key not in new_members]
    extra = [key for key in new_members if key not in ref_members]
    for key in sorted(missing, key=lambda k: ref_members[k].idx):
        facts = ref_members[key]
        if allow.allow(facts.name, "missing"):
            continue
        result["problems"].append(
            f"member missing: idx {facts.idx} {facts.name}"
            + (f" (occurrence {facts.occurrence})" if facts.occurrence else ""))
    for key in sorted(extra, key=lambda k: new_members[k].idx):
        facts = new_members[key]
        if allow.allow(facts.name, "extra"):
            continue
        result["problems"].append(
            f"member extra: idx {facts.idx} {facts.name}"
            + (f" (occurrence {facts.occurrence})" if facts.occurrence else ""))

    # --- duplicate-name ordering (patch_base.o x3) -----------------------
    for name, idxs in ref.duplicate_groups().items():
        ref_seq = [ref_members[key].sha256
                   for key in sorted(ref_members, key=lambda k: ref_members[k].idx)
                   if key[0] == name]
        new_seq = [facts.sha256 for facts in sorted(new_facts.values(), key=lambda f: f.idx)
                   if facts.name == name]
        if ref_seq and new_seq and len(ref_seq) == len(new_seq) and ref_seq != new_seq:
            if sorted(ref_seq) == sorted(new_seq):
                # Same bodies, wrong ordinals: the archive misplaces the duplicates.
                if not all(allow.allow(name, "ordinal", str(i)) for i in range(len(ref_seq))):
                    result["problems"].append(
                        f"duplicate-name order differs for {name}: the same {len(ref_seq)} "
                        "bodies are present but at different ordinals")
            else:
                # Different bytes are expected for a reconstruction; bytes are not the
                # gate criterion (T/U/layout is). Record it as information only.
                result.setdefault("informational", []).append(
                    f"duplicate-name bodies rebuilt (not byte-identical) for {name}: "
                    f"{len(set(ref_seq) ^ set(new_seq))} of {len(ref_seq)} body/bodies differ")

    # --- per-member T/U/layout ------------------------------------------
    rows: list[dict[str, Any]] = []
    clean = 0
    empty_pairs = 0
    failing_members = 0
    fail_complete = 0
    fail_partial = 0
    for key in sorted(ref_members, key=lambda k: ref_members[k].idx):
        ref_f = ref_members[key]
        new_f = new_members.get(key)
        if new_f is None:
            rows.append({"idx": ref_f.idx, "name": ref_f.name,
                         "occurrence": ref_f.occurrence, "status": "MISSING"})
            continue
        problems: list[str] = []
        raw = compare_symbol_sets(ref_f.t, ref_f.u, new_f.t, new_f.u)
        # 1) baseline: U-only, bitcode-only, never T (hard rule of the baseline).
        used: list[str] = []
        member_idx = ref_f.idx
        raw_u_missing = list(raw["u_missing"])
        raw_u_extra = list(raw["u_extra"])
        u_missing = []
        for symbol in raw_u_missing:
            if baseline.allows_missing(symbol, ref_f.layout, member_idx):
                baseline.consume(symbol)
                used.append(symbol)
            else:
                u_missing.append(symbol)
        u_extra = []
        for symbol in raw_u_extra:
            if baseline.allows_extra(symbol, ref_f.layout, member_idx):
                baseline.consume(symbol)
                used.append(symbol)
            else:
                u_extra.append(symbol)
        # 2) explicit per-member allowlist on top of the baseline.
        t_missing = [s for s in raw["t_missing"] if not allow.allow(ref_f.name, "T", s)]
        t_extra = [s for s in raw["t_extra"] if not allow.allow(ref_f.name, "T", s)]
        u_missing = [s for s in u_missing if not allow.allow(ref_f.name, "U", s)]
        u_extra = [s for s in u_extra if not allow.allow(ref_f.name, "U", s)]
        diffs = {"t_missing": t_missing, "t_extra": t_extra,
                 "u_missing": u_missing, "u_extra": u_extra}
        # W symbols are informational only (baseline hard rule 3): report, never gate.
        w_missing = sorted((ref_f.w_defined | ref_f.w_undefined)
                           - (new_f.w_defined | new_f.w_undefined))
        w_extra = sorted((new_f.w_defined | new_f.w_undefined)
                         - (ref_f.w_defined | ref_f.w_undefined))
        layout_flip = ref_f.layout != new_f.layout
        if layout_flip and not allow.allow(ref_f.name, "layout", new_f.layout):
            problems.append(f"layout {ref_f.layout} -> {new_f.layout}")
        if t_missing:
            problems.append(f"T missing {len(t_missing)}")
        if t_extra:
            problems.append(f"T extra {len(t_extra)}")
        if u_missing:
            problems.append(f"U missing {len(u_missing)}")
        if u_extra:
            problems.append(f"U extra {len(u_extra)}")
        if ref_f.nm_error or new_f.nm_error:
            problems.append("llvm-nm failed: " + (ref_f.nm_error or new_f.nm_error)[:160])
        if not ref_f.t and not ref_f.u and not new_f.t and not new_f.u:
            empty_pairs += 1
        status = "PASS" if not problems else "FAIL"
        if status == "PASS":
            clean += 1
        else:
            failing_members += 1
            declared = declared_status.get(ref_f.idx, "?")
            if declared == S.STATUS_COMPLETE:
                fail_complete += 1
            else:
                fail_partial += 1
        row = {
            "idx": ref_f.idx,
            "name": new_f.name,
            "occurrence": key[1],
            "declared_status": declared_status.get(ref_f.idx, "?"),
            "status": status,
            "layout": {"ref": ref_f.layout, "new": new_f.layout},
            "sets": {"ref": {"t": len(ref_f.t), "u": len(ref_f.u),
                             "weak": ref_f.weak, "local": ref_f.local},
                     "new": {"t": len(new_f.t), "u": len(new_f.u),
                             "weak": new_f.weak, "local": new_f.local}},
            "diffs": {"t_missing": t_missing, "t_extra": t_extra,
                      "u_missing": u_missing, "u_extra": u_extra},
            "raw_diffs": {"t_missing": raw["t_missing"], "t_extra": raw["t_extra"],
                          "u_missing": raw_u_missing, "u_extra": raw_u_extra},
            "baseline_consumed": used,
            "w_diffs": {"w_missing": w_missing, "w_extra": w_extra},
            "w_missing_count": len(w_missing),
            "same_bytes": ref_f.sha256 == new_f.sha256,
            "problems": problems,
        }
        if problems:
            result["problems"].extend([f"{new_f.name}: {p}" for p in problems])
        rows.append(row)

    def total(field_name: str, key: str) -> int:
        return sum(len((row.get(field_name) or {}).get(key) or []) for row in rows)

    summary = {
        "pass": clean,
        "fail": failing_members,
        "missing": len(missing),
        "extra": len(extra),
        "deferred": len(result["deferred_idx"]),
        "compared": len([r for r in rows if r.get("status") != "MISSING"]),
        "layout_flips": len([r for r in rows if r.get("layout", {}).get("ref") != r.get(
            "layout", {}).get("new")]),
        "t_missing_total": total("diffs", "t_missing"),
        "t_extra_total": total("diffs", "t_extra"),
        "u_missing_total": total("diffs", "u_missing"),
        "u_extra_total": total("diffs", "u_extra"),
        "raw_t_missing_total": total("raw_diffs", "t_missing"),
        "raw_t_extra_total": total("raw_diffs", "t_extra"),
        "raw_u_missing_total": total("raw_diffs", "u_missing"),
        "raw_u_extra_total": total("raw_diffs", "u_extra"),
        "w_missing_total_informational": sum(r.get("w_missing_count") or 0 for r in rows),
        "w_missing_members": sum(1 for r in rows if r.get("w_missing_count")),
        "baseline_consumed_total": sum(baseline.consumed.values()),
        "baseline_entries": len(baseline.missing) + len(baseline.extra),
        "baseline_unused_entries": sorted(set(baseline.missing) - set(baseline.consumed)),
        "empty_symbol_pairs": empty_pairs,
        "fail_complete_members": fail_complete,
        "fail_partial_members": fail_partial,
        "declared_status_counts": _counts(declared_status.values()),
        "allowlist_applied": allow.applied_count,
    }
    verdict = "PASS" if not result["problems"] else "FAIL"
    result["status"] = verdict
    result["summary"] = summary
    result["members"] = rows
    result["allowlist"] = allow.summary()
    result["baseline"] = baseline.summary()
    result["exit_code"] = S.EXIT_OK if verdict == "PASS" else S.EXIT_GATE
    result["seconds"] = round(time.monotonic() - started, 2)
    S.write_json(out_path, S.jsonable(result))

    if not quiet:
        _print_summary(result, out_path)
    return result


def _counts(values: Iterable[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def _layout_counts(archive: S.Archive) -> dict[str, int]:
    counts: dict[str, int] = {}
    for member in archive.members:
        counts[member.layout] = counts.get(member.layout, 0) + 1
    return dict(sorted(counts.items()))


def _print_summary(result: dict[str, Any], out_path: Path) -> None:
    summary = result.get("summary", {})
    inputs = result.get("inputs", {})
    new_in = inputs.get("new", {})
    ref_in = inputs.get("ref", {})
    print(f"[gate] scope={result.get('scope')}  new={new_in.get('path')} "
          f"({new_in.get('members')} members)  ref={ref_in.get('members')} members")
    print(f"[gate] compared={summary.get('compared')}  pass={summary.get('pass')}  "
          f"fail={summary.get('fail')}  missing={summary.get('missing')}  "
          f"extra={summary.get('extra')}  deferred={summary.get('deferred')}")
    print(f"[gate] W (weak) missing {summary.get('w_missing_total_informational')} symbol(s) "
          f"in {summary.get('w_missing_members')} member(s) — informational only, not gated")
    if result.get("deferred_no_source"):
        print(f"[gate] deferred (partial-no-source, declared blockedBy): "
              f"{len(result['deferred_no_source'])} member(s)")
    print(f"[gate] failing members by declared status: complete={summary.get('fail_complete_members')} "
          f"partial={summary.get('fail_partial_members')}")
    print(f"[gate] raw diffs: T missing={summary.get('raw_t_missing_total')} "
          f"extra={summary.get('raw_t_extra_total')} | U missing={summary.get('raw_u_missing_total')} "
          f"extra={summary.get('raw_u_extra_total')}")
    print(f"[gate] adjusted:  T missing={summary.get('t_missing_total')} "
          f"extra={summary.get('t_extra_total')} | U missing={summary.get('u_missing_total')} "
          f"extra={summary.get('u_extra_total')} | layout flips={summary.get('layout_flips')} "
          f"| empty-pair members={summary.get('empty_symbol_pairs')}")
    baseline_info = result.get("baseline", {})
    print(f"[gate] baseline: {baseline_info.get('entries')} entries "
          f"({baseline_info.get('path') or 'absent'}), consumed "
          f"{baseline_info.get('consumed_total')} "
          f"{dict(baseline_info.get('consumed') or {})}, unused "
          f"{baseline_info.get('unused')}")
    allow = result.get("allowlist", {})
    print(f"[gate] allowlist: {allow.get('entries')} entries, {allow.get('applied')} applied, "
          f"{allow.get('unused')} unused, {len(allow.get('invalid') or [])} invalid"
          + (f"  ({allow.get('path')})" if allow.get("path") else "  (sdk/notes/gate-allow.json absent)"))
    problems = result.get("problems") or []
    for problem in problems[:20]:
        print(f"[gate]   ! {problem}")
    if len(problems) > 20:
        print(f"[gate]   … {len(problems) - 20} more problem(s) in the JSON")
    print(f"[gate] {result.get('status')} — report: {S.rel(out_path)}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="member_gate.py",
        description="Compare a built SDK archive against the frozen epoch member by member "
                    "(layout, T set, U set, ordinal sequence, duplicates).",
        epilog="exit codes: 0 gate PASS, 7 gate FAIL, 2 usage/environment.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--new", required=False, help="built archive to check")
    parser.add_argument("--ref", default=None,
                        help="frozen residual archive (default: the freeze snapshot)")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="JSON report path")
    parser.add_argument("--allow", default=None,
                        help="allowlist JSON (default sdk/notes/gate-allow.json when present)")
    parser.add_argument("--baseline", default=None,
                        help="declared toolchain baseline (default "
                             "sdk/notes/gate-symbol-baseline.json)")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST),
                        help="manifest.jsonl used to decide the member scope")
    parser.add_argument("--scope", choices=("auto", "full", "partial"), default="auto",
                        help="auto: full when the manifest declares all frozen members")
    parser.add_argument("--allow-partial", action="store_true",
                        help="compare only the members declared in the manifest")
    parser.add_argument("--work-dir", default=None, help="where members are extracted for llvm-nm")
    parser.add_argument("--jobs", type=int, default=8, help="parallel llvm-nm workers (default 8)")
    parser.add_argument("--ndk", default=None, help="override the NDK root")
    parser.add_argument("--json", action="store_true", help="print the gate JSON to stdout")
    parser.add_argument("--quiet", action="store_true", help="only write the report")
    parser.add_argument("--self-test", action="store_true",
                        help="run the empty-set/comparator self-tests and exit")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(list(argv if argv is not None else sys.argv[1:]))

    if args.self_test:
        checks = self_test()
        failed = [c for c in checks if not c["pass"]]
        for check in checks:
            print(f"  [{'PASS' if check['pass'] else 'FAIL'}] {check['check']}: {check['detail']}")
        if not args.new:
            print(f"self-test: {len(checks) - len(failed)}/{len(checks)} passed")
            return S.EXIT_OK if not failed else S.EXIT_GATE

    if not args.new:
        print("error: --new is required (or use --self-test)", file=sys.stderr)
        return S.EXIT_TOOLCHAIN

    try:
        result = run_gate(
            new_archive=args.new, ref_archive=args.ref, out_path=args.out,
            allow_path=args.allow, baseline_path=args.baseline,
            manifest_path=args.manifest, scope=args.scope,
            allow_partial=args.allow_partial, work_dir=args.work_dir, jobs=args.jobs,
            quiet=args.quiet or args.json, ndk=args.ndk,
        )
    except S.ToolchainMissing as exc:
        print(f"error: {exc}", file=sys.stderr)
        return S.EXIT_TOOLCHAIN
    if args.json:
        print(json.dumps(S.jsonable(result), ensure_ascii=False, indent=2))
    if args.self_test:
        failed = [c for c in self_test() if not c["pass"]]
        if failed:
            return S.EXIT_GATE
    return int(result.get("exit_code", S.EXIT_GATE))


if __name__ == "__main__":
    sys.exit(main())
