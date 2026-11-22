#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_manifest.py -- collect ``sdk/manifest/*.json`` into the build manifest.

The member metadata contract
----------------------------
One JSON file per archive member, named ``<idx4>_<member-name>.json``::

    {"idx": 29, "name": "module_base_kernel_func_hook.o",
     "group": "core", "layout": "bitcode", "kind": "SINGLE",
     "sources": ["src/func_hook/module_base_kernel_func_hook.cpp"],
     "flagsProfile": "core-oz-bitcode", "status": "complete",
     "recovery": {"functions": 10, "recovered": 10, "unrecovered": []},
     "original": {"sha256": "...", "bytes": 209096},
     "evidence": ["notes/recon/..."], "selfCheck": {"tDiff": [], "uDiff": [], "note": ""},
     "notes": "..."}

This tool is the *only* producer of ``manifest.jsonl``. It validates every record
against the frozen reference archive (ordinal -> name, size, sha256, layout) and
refuses to silently drop anything:

* a missing index is listed explicitly, never skipped;
* ``--allow-partial`` is the explicit "interim health check" switch: outputs are
  written, the run succeeds, and every consumer sees the missing indices in the
  coverage report;
* without ``--allow-partial`` an incomplete manifest exits 3 and is **not**
  written, so a partial result can never be mistaken for the final one.

``layout`` describes the current build output. An explicit ``original.layout``
must match the frozen header and records a source format conversion when the
output differs. Without it, the output must still match the frozen layout.
Neither form replaces the actual-output check or the member symbol/layout gate.

Exit codes: 0 ok, 2 environment/toolchain, 3 manifest.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

TOOLS_DIR = Path(__file__).resolve().parent
SDK_DIR = TOOLS_DIR.parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import sdk_common as S  # noqa: E402

MANIFEST_SCHEMA = "maplesu-sdk-member/2"
MANIFEST_JSONL = SDK_DIR / "manifest.jsonl"
MANIFEST_DIR = SDK_DIR / "manifest"
COVERAGE_MD = SDK_DIR / "notes" / "MANIFEST-COVERAGE.md"
CATALOG_MD = SDK_DIR / "notes" / "work" / "ARCH" / "MANIFEST-CATALOG.md"

EXPECTED_MEMBERS = 258   # fallback; overridden from the frozen archive at run time


_EXPECTED_CACHE: int | None = None


def expected_members(default: int = EXPECTED_MEMBERS) -> int:
    """Member count of the reference archive actually in use.

    The build input grew from 258 to 260 members when the SDK was fixed at a
    later build id, so the contract follows the snapshot instead of a constant.

    This function must NOT call load_reference(): load_reference() validates the
    count with this function, so doing so recurses forever and the exception
    guard silently degrades to the old constant.
    """
    global _EXPECTED_CACHE
    if _EXPECTED_CACHE is not None:
        return _EXPECTED_CACHE
    try:
        snapshot = S.find_freeze(None)
        _EXPECTED_CACHE = len(S.read_archive(snapshot.archive).members)
    except Exception:
        _EXPECTED_CACHE = default
    return _EXPECTED_CACHE


MEMBER_FILE_RE = re.compile(r"^\d{4}_.*\.json$")
KNOWN_KINDS = {"SINGLE", "MULTI", "COMPOSED", "VENDOR", "EMBEDDED", "FROM_IR", "IR", "ASSET"}
REQUIRED_KEYS = ("idx", "name", "status")
GROUP_FALLBACK = "ungrouped"


# --------------------------------------------------------------------------- #
# Issues
# --------------------------------------------------------------------------- #


@dataclass
class Issue:
    level: str          # "error" | "warning"
    code: str
    message: str
    idx: int | None = None
    origin: str = ""

    def render(self) -> str:
        where = f"idx {self.idx}" if self.idx is not None else "manifest"
        if self.origin:
            where += f" ({self.origin})"
        return f"[{self.level}] {where}: {self.code}: {self.message}"

    def as_dict(self) -> dict[str, Any]:
        return {"level": self.level, "code": self.code, "message": self.message,
                "idx": self.idx, "origin": S.rel(self.origin) if self.origin else ""}


@dataclass
class RefIndex:
    """The frozen epoch, indexed by ordinal and by (name, sha256)."""

    by_idx: dict[int, dict[str, Any]] = field(default_factory=dict)
    by_name: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    @classmethod
    def build(cls, facts: dict[int, dict[str, Any]]) -> "RefIndex":
        index = cls(by_idx=dict(facts))
        for fact in facts.values():
            index.by_name.setdefault(S.active_member_name(fact["name"]), []).append(fact)
        return index

    def resolve(self, name: str, sha256: str | None) -> tuple[dict[str, Any] | None, str]:
        """Resolve a record to its frozen member by name, disambiguated by sha256.

        ``patch_base.o`` exists three times with three different bodies, so a name
        alone is ambiguous. The claimed index is *not* authoritative: the frozen
        ordinal is. Returns (fact, reason) where reason is one of
        ``exact-name``, ``unique-name``, ``sha-disambiguated``, ``ambiguous``,
        ``unknown-name``, ``sha-mismatch``.
        """
        candidates = self.by_name.get(name, [])
        if not candidates:
            return None, "unknown-name"
        if len(candidates) == 1:
            fact = candidates[0]
            if sha256 and sha256.lower() != fact["sha256"]:
                return None, "sha-mismatch"
            return fact, "unique-name"
        if sha256:
            matching = [c for c in candidates if c["sha256"] == sha256.lower()]
            if len(matching) == 1:
                return matching[0], "sha-disambiguated"
            if not matching:
                return None, "sha-mismatch"
            return None, "ambiguous"
        return None, "ambiguous"


@dataclass
class MemberRecord:
    idx: int
    name: str
    status: str
    layout: str
    sources: list[str] = field(default_factory=list)
    flags_profile: str = ""
    group: str = GROUP_FALLBACK
    kind: str = "SINGLE"
    recovery: dict[str, Any] = field(default_factory=dict)
    original: dict[str, Any] = field(default_factory=dict)
    evidence: list[Any] = field(default_factory=list)
    self_check: dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    extra_flags: list[str] = field(default_factory=list)
    origin: str = "manifest-json"     # "manifest-json" | "legacy-manifest.jsonl"
    source_file: str = ""
    idx_claimed: int | None = None    # set when the claimed idx was normalised
    compose: list[dict[str, Any]] = field(default_factory=list)
    blocked_by: list[str] = field(default_factory=list)
    recipe: dict[str, Any] = field(default_factory=dict)
    reference_input: dict[str, Any] | None = None
    header_inputs: dict[str, list[str]] = field(default_factory=dict)

    def producer(self) -> dict[str, Any]:
        """How this member is produced by the build entry.

        Recorded per member because the contract asks for it: the tool, the
        compile profile and whether the member is a single translation unit or
        a composition of several.
        """
        profile = str(self.flags_profile or "")
        if "vendor" in profile:
            tool = "clang(++), vendored source"
        elif self.kind == "COMPOSED":
            tool = "clang++, then ld.lld -r"
        else:
            tool = "clang++"
        return {
            "tool": tool,
            "profile": profile,
            "container": self.layout,
            "kind": self.kind,
        }

    def to_jsonl(self) -> dict[str, Any]:
        record: OrderedDict[str, Any] = OrderedDict()
        record["idx"] = self.idx
        if self.idx_claimed is not None and self.idx_claimed != self.idx:
            record["idxClaimed"] = self.idx_claimed
        record["name"] = self.name
        record["group"] = self.group
        record["layout"] = self.layout
        record["kind"] = self.kind
        record["sources"] = list(self.sources)
        record["flagsProfile"] = self.flags_profile
        record["producer"] = self.producer()
        record["status"] = self.status
        record["recovery"] = {
            "functions": int(self.recovery.get("functions", 0) or 0),
            "recovered": int(self.recovery.get("recovered", 0) or 0),
            "unrecovered": list(self.recovery.get("unrecovered") or []),
        }
        record["original"] = {
            "sha256": str(self.original.get("sha256", "")),
            "bytes": int(self.original.get("bytes", 0) or 0),
        }
        if "layout" in self.original:
            record["original"]["layout"] = self.original["layout"]
        record["evidence"] = list(self.evidence)
        record["selfCheck"] = {
            "tDiff": list(self.self_check.get("tDiff") or []),
            "uDiff": list(self.self_check.get("uDiff") or []),
            "note": str(self.self_check.get("note", "")),
        }
        record["notes"] = self.notes
        record["extraFlags"] = list(self.extra_flags)
        if self.compose:
            record["compose"] = list(self.compose)
        if self.blocked_by:
            record["blockedBy"] = list(self.blocked_by)
        if self.recipe:
            record["recipe"] = dict(self.recipe)
        if self.reference_input is not None:
            record["referenceInput"] = dict(self.reference_input)
        for key, paths in self.header_inputs.items():
            record[key] = list(paths)
        record["origin"] = self.origin
        if self.source_file:
            record["sourceFile"] = self.source_file
        return record


@dataclass
class Result:
    records: list[MemberRecord] = field(default_factory=list)
    errors: list[Issue] = field(default_factory=list)
    warnings: list[Issue] = field(default_factory=list)
    missing_idx: list[int] = field(default_factory=list)
    written: list[str] = field(default_factory=list)
    frozen: dict[str, Any] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=lambda: {s: 0 for s in S.STATUS_ALL})
    tier_counts: dict[str, int] = field(default_factory=dict)
    tier_members: dict[str, list[str]] = field(default_factory=dict)
    unrecovered_by_tier: dict[str, int] = field(default_factory=dict)
    group_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    profile_counts: dict[str, int] = field(default_factory=dict)
    legacy_count: int = 0
    normalized: list[dict[str, Any]] = field(default_factory=list)
    idx_mode: str = "auto"
    metadata_files: int = 0
    skipped_records: list[dict[str, Any]] = field(default_factory=list)
    non_member_files: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def complete(self) -> bool:
        return self.ok and not self.missing_idx

    def summary(self) -> dict[str, Any]:
        return {
            "schema": MANIFEST_SCHEMA,
            "ok": self.ok,
            "complete": self.complete,
            "members": len(self.records),
            "expected": expected_members(),
            "metadata_files": self.metadata_files,
            "counts": self.counts,
            "tiers": self.tier_counts,
            "tier_members": self.tier_members,
            "unrecovered_by_tier": self.unrecovered_by_tier,
            "group_counts": self.group_counts,
            "profile_counts": self.profile_counts,
            "missing_idx": self.missing_idx,
            "missing_members": [
                {"idx": idx, "name": getattr(self, "_missing_names", {}).get(idx, "?")}
                for idx in self.missing_idx
            ],
            "legacy_count": self.legacy_count,
            "idx_mode": self.idx_mode,
            "normalized": self.normalized,
            "skipped_records": self.skipped_records,
            "non_member_files": self.non_member_files,
            "errors": [issue.as_dict() for issue in self.errors],
            "warnings": [issue.as_dict() for issue in self.warnings],
            "frozen": self.frozen,
            "written": self.written,
        }


# --------------------------------------------------------------------------- #
# Frozen reference
# --------------------------------------------------------------------------- #


def load_reference(archive_override: str | None = None) -> tuple[Any, Any, dict[str, Any], list[Issue]]:
    """Return (snapshot, parsed archive, member facts by idx, issues)."""
    issues: list[Issue] = []
    try:
        snapshot = S.find_freeze(archive_override)
        archive = S.read_archive(snapshot.archive)
    except (S.FreezeError, S.ArchiveError) as exc:
        issues.append(Issue("error", "freeze-unavailable", str(exc)))
        return None, None, {}, issues
    facts: dict[int, dict[str, Any]] = {}
    for member in archive.members:
        facts[member.idx] = {
            "idx": member.idx,
            "name": member.name,
            "bytes": member.size,
            "sha256": member.sha256,
            "layout": member.layout,
        }
    if len(archive.members) != expected_members():
        issues.append(Issue(
            "error", "freeze-member-count",
            f"frozen archive has {len(archive.members)} members, contract expects "
            f"{expected_members()}",
        ))
    frozen = snapshot.describe()
    frozen["members"] = len(archive.members)
    frozen["duplicate_names"] = archive.duplicate_groups()
    return snapshot, archive, facts, issues


# --------------------------------------------------------------------------- #
# Path resolution
# --------------------------------------------------------------------------- #


def resolve_source(raw: str) -> Path | None:
    """Resolve a member source path: relative to sdk/, then to the repo root."""
    if not raw or not isinstance(raw, str):
        return None
    candidate = Path(raw)
    if candidate.is_absolute():
        candidate = candidate.resolve()
        try:
            candidate.relative_to(S.SDK_DIR)
        except ValueError:
            try:
                candidate.relative_to(S.REPO_ROOT)
            except ValueError:
                return None
        return candidate.resolve()
    # SDK shorthand and repository-relative paths are both public manifest inputs.
    bases = (S.SDK_DIR, S.REPO_ROOT)
    for base in bases:
        probe = (base / candidate).resolve()
        try:
            probe.relative_to(S.REPO_ROOT)
        except ValueError:
            continue
        if probe.is_file():
            return probe
    # Preserve a contained missing path so callers report a missing input, not an escape.
    probe = (bases[0] / candidate).resolve()
    return probe if probe.is_relative_to(S.REPO_ROOT.resolve()) else None


# --------------------------------------------------------------------------- #
# Record validation
# --------------------------------------------------------------------------- #


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def reference_input_error(reference_input: Any, sources: Sequence[Path]) -> tuple[str, str] | None:
    if reference_input is None:
        return None
    if (not isinstance(reference_input, dict) or len(sources) != 1
            or not re.fullmatch(r"[0-9a-f]{64}", str(reference_input.get("sha256", "")))
            or type(reference_input.get("bytes")) is not int
            or reference_input["bytes"] <= 0):
        return "bad-reference-input", "referenceInput requires one source, positive bytes and SHA-256"
    source = sources[0]
    if (not source.is_file() or source.stat().st_size != reference_input["bytes"]
            or S.sha256_file(source) != reference_input["sha256"]):
        return "reference-input-mismatch", "pinned reference source bytes changed"
    return None


def validate_record(raw: dict[str, Any], origin_file: str, ref: "RefIndex",
                    idx_mode: str = "auto",
                    ) -> tuple[MemberRecord | None, list[Issue]]:
    issues: list[Issue] = []

    def err(code: str, message: str, idx: int | None = None) -> None:
        issues.append(Issue("error", code, message, idx, origin_file))

    def warn(code: str, message: str, idx: int | None = None) -> None:
        issues.append(Issue("warning", code, message, idx, origin_file))

    missing = [key for key in REQUIRED_KEYS if key not in raw]
    if missing:
        err("missing-keys", f"required keys missing: {missing}")
        return None, issues

    claimed_idx = _as_int(raw.get("idx"))
    if claimed_idx is None or claimed_idx < 0:
        err("bad-idx", f"idx must be a non-negative integer, got {raw.get('idx')!r}")
        return None, issues
    if claimed_idx >= expected_members():
        err("idx-range", f"idx {claimed_idx} is outside 0..{expected_members() - 1}", claimed_idx)
        return None, issues

    name = raw.get("name")
    if not isinstance(name, str) or not name:
        err("bad-name", f"name must be a non-empty string, got {name!r}", claimed_idx)
        return None, issues

    raw_original = raw.get("original") or {}
    claimed_sha = None
    if isinstance(raw_original, dict) and isinstance(raw_original.get("sha256"), str):
        claimed_sha = raw_original["sha256"].strip().lower()

    # The frozen ordinal is authoritative; the claimed idx is advisory and may be
    # normalised (loudly) while authors migrate 1-based numbering.
    fact, reason = ref.resolve(name, claimed_sha)
    if fact is None:
        hint = ""
        at_claimed = ref.by_idx.get(claimed_idx)
        if at_claimed is not None:
            hint = (f"; the frozen member at ordinal {claimed_idx} is "
                    f"{at_claimed['name']!r}")
        nearby = ref.by_idx.get(claimed_idx - 1) or ref.by_idx.get(claimed_idx + 1)
        if reason in ("ambiguous", "sha-mismatch"):
            hint += ("; this member name occurs more than once in the freeze, so "
                     "original.sha256 must disambiguate it")
        err("name-mismatch", f"cannot resolve name {name!r} in the freeze "
                             f"(reason: {reason}){hint}", claimed_idx)
        return None, issues

    idx = int(fact["idx"])
    if idx != claimed_idx:
        text = (f"idx {claimed_idx} does not address {name!r}; the frozen ordinal is {idx} "
                f"(off by {claimed_idx - idx:+d})")
        if idx_mode == "strict":
            err("idx-mismatch", text + "; --idx-base strict refuses normalisation", claimed_idx)
            return None, issues
        warn("idx-normalized", text + "; normalised to the frozen ordinal", claimed_idx)

    if claimed_idx != idx and ref.by_idx[claimed_idx]["name"] != name:
        # nothing else to check: the name/sha resolution already tied us to idx
        pass

    status = raw.get("status")
    if status not in S.VALID_STATUS:
        err("bad-status", f"status must be one of {list(S.VALID_STATUS)}, got {status!r}", idx)
        return None, issues

    layout = raw.get("layout")
    if layout is None:
        layout = fact["layout"]
        warn("layout-default", f"layout absent; using the frozen layout {fact['layout']!r}", idx)
    elif layout not in ("bitcode", "elf"):
        err("bad-layout", f"layout must be 'bitcode' or 'elf', got {layout!r}", idx)
        return None, issues
    layout_transition = False
    if isinstance(raw_original, dict) and "layout" in raw_original:
        original_layout = raw_original["layout"]
        if original_layout not in ("bitcode", "elf"):
            err("bad-original-layout",
                f"original.layout must be 'bitcode' or 'elf', got {original_layout!r}", idx)
        elif original_layout != fact["layout"]:
            err("original-layout-mismatch",
                f"original.layout {original_layout!r} != frozen layout {fact['layout']!r}", idx)
        elif layout != original_layout:
            layout_transition = True
            warn("layout-transition",
                 f"current output layout {layout!r} differs from frozen original.layout "
                 f"{original_layout!r}; actual output and member gate still apply", idx)
    elif layout != fact["layout"]:
        err("layout-mismatch",
            f"layout {layout!r} != frozen layout {fact['layout']!r} at ordinal {idx}", idx)

    profile = raw.get("flagsProfile") or raw.get("flags_profile")
    if profile is None:
        profile = S.DEFAULT_PROFILE_BY_LAYOUT.get(fact["layout"], "core-oz-elf")
        warn("profile-default", f"flagsProfile absent; derived {profile!r} from layout", idx)
    elif profile not in S.FLAG_PROFILES:
        err("bad-profile", f"unknown flagsProfile {profile!r}; known: {list(S.PROFILE_NAMES)}", idx)

    extra_flags = raw.get("extraFlags") or raw.get("extra_flags") or []
    if not isinstance(extra_flags, list) or any(not isinstance(f, str) for f in extra_flags):
        err("bad-extraFlags", "extraFlags must be a list of strings", idx)
        extra_flags = []

    # ``recipe`` carries the measured build recipe that reproduces the frozen
    # member (build.py: {stages: 2} = optimised IR pass, then ELF pass).  An
    # empty dict means the single-pass recipe.
    raw_recipe = raw.get("recipe")
    recipe: dict[str, Any] = {}
    if raw_recipe:
        if not isinstance(raw_recipe, dict):
            err("bad-recipe", "recipe must be an object", idx)
        else:
            stages = raw_recipe.get("stages", 1)
            if not isinstance(stages, int) or isinstance(stages, bool) or stages < 1:
                err("bad-recipe-stages", "recipe.stages must be a positive integer", idx)
            else:
                recipe = {"stages": stages,
                          **{k: v for k, v in raw_recipe.items() if k != "stages"}}

    raw_sources = raw.get("sources")
    if raw_sources is None and raw.get("source") is not None:
        raw_sources = [raw.get("source")]
        warn("legacy-source-field", "single 'source' accepted; prefer 'sources': [..]", idx)
    sources: list[str] = []
    if raw_sources is not None:
        if not isinstance(raw_sources, list) or any(not isinstance(s, str) for s in raw_sources):
            err("bad-sources", "sources must be a list of strings", idx)
            raw_sources = []
        else:
            for entry in raw_sources:
                resolved = resolve_source(entry)
                if resolved is None:
                    err("source-outside-repo",
                        f"source {entry!r} does not resolve inside the repository", idx)
                    continue
                if not resolved.is_file():
                    err("source-missing", f"source {entry!r} does not exist ({S.rel(resolved)})", idx)
                    continue
                if resolved.stat().st_size == 0:
                    err("source-empty", f"source {entry!r} is empty", idx)
                    continue
                sources.append(entry)
    reference_input = raw.get("referenceInput")
    reference_error = reference_input_error(reference_input, [resolve_source(s) for s in sources])
    if reference_error:
        err(*reference_error, idx)
    blocked_by = raw.get("blockedBy") or []
    if not isinstance(blocked_by, list) or any(not isinstance(b, str) or not b.strip()
                                               for b in blocked_by):
        err("bad-blockedBy", "blockedBy must be a list of non-empty strings", idx)
        blocked_by = []
    if not sources:
        if layout_transition:
            err("layout-transition-no-source",
                "a format conversion requires source; a reference copy keeps its frozen layout", idx)
        if status == S.STATUS_COMPLETE:
            # A complete member must be built from source; "no source" cannot be complete.
            err("complete-no-source",
                "status complete requires at least one existing source file", idx)
        elif status == S.STATUS_PARTIAL:
            # A blocked member may declare *why* it has no source: either a
            # blockedBy[] reason or a non-empty recovery.unrecovered list. Only a
            # record that claims to be partial, has no source and lists no gap at
            # all is an error.
            raw_recovery = raw.get("recovery")
            pending_unrecovered = list(
                (raw_recovery or {}).get("unrecovered") or []) if isinstance(
                    raw_recovery, dict) else []
            if blocked_by or pending_unrecovered:
                warn("partial-no-source-blocked",
                     "status partial without a source; "
                     + ("blockedBy: " + "; ".join(blocked_by) if blocked_by
                        else f"unrecovered lists {len(pending_unrecovered)} gap(s)"),
                     idx)
            else:
                err("sources-missing",
                    "status partial with no source must declare blockedBy[] or a "
                    "non-empty recovery.unrecovered", idx)
        elif status == S.STATUS_VENDOR_COPY:
            warn("vendor-copy-no-source",
                 "status vendor-copy without a source is a temporary tier; delivery requires 0",
                 idx)

    # --- original: must equal the frozen member when present -----------------
    original = raw.get("original") or {}
    orig_issues: list[Issue] = []
    if original:
        if not isinstance(original, dict):
            orig_issues.append(Issue("error", "bad-original", "original must be an object",
                                     idx, origin_file))
            original = {}
        else:
            sha = original.get("sha256")
            nbytes = original.get("bytes")
            if sha is not None and (not isinstance(sha, str) or len(sha) != 64
                                    or any(c not in "0123456789abcdef" for c in sha.lower())):
                orig_issues.append(Issue("error", "bad-original-sha",
                                         f"original.sha256 is not a hex sha256: {sha!r}",
                                         idx, origin_file))
            elif isinstance(sha, str) and sha.lower() != fact["sha256"]:
                orig_issues.append(Issue(
                    "error", "original-sha-mismatch",
                    f"original.sha256 {sha[:16]}... != frozen member sha256 {fact['sha256'][:16]}...",
                    idx, origin_file))
            if nbytes is not None:
                if not isinstance(nbytes, int) or isinstance(nbytes, bool) or nbytes <= 0:
                    orig_issues.append(Issue("error", "bad-original-bytes",
                                             f"original.bytes must be a positive integer: {nbytes!r}",
                                             idx, origin_file))
                elif nbytes != fact["bytes"]:
                    orig_issues.append(Issue(
                        "error", "original-bytes-mismatch",
                        f"original.bytes {nbytes} != frozen member {fact['bytes']}", idx, origin_file))
    else:
        if status == S.STATUS_COMPLETE:
            err("original-missing",
                "status complete requires original.{sha256,bytes} verified against the freeze", idx)
        else:
            warn("original-missing", "original.{sha256,bytes} absent; not cross-checked", idx)

    # --- recovery self-consistency ------------------------------------------
    recovery = raw.get("recovery") or {}
    if not isinstance(recovery, dict):
        err("bad-recovery", "recovery must be an object", idx)
        recovery = {}
    functions = _as_int(recovery.get("functions"))
    recovered = _as_int(recovery.get("recovered"))
    unrecovered = recovery.get("unrecovered") or []
    if not isinstance(unrecovered, list):
        err("bad-recovery-unrecovered", "recovery.unrecovered must be a list", idx)
        unrecovered = []
    if recovery and (functions is None or recovered is None):
        err("bad-recovery-counts",
            "recovery.functions/recovered must be integers", idx)
        functions, recovered = 0, 0
    if functions is not None and functions < 0:
        err("bad-recovery", "recovery.functions must be >= 0", idx)
    if recovered is not None and functions is not None and recovered > functions:
        err("recovery-overflow",
            f"recovery.recovered {recovered} > functions {functions}", idx)
    if functions is not None and len(unrecovered) > functions:
        err("recovery-unrecovered-overflow",
            f"{len(unrecovered)} unrecovered names > functions {functions}", idx)
    if functions is not None and recovered is not None:
        implied = recovered + len(unrecovered)
        if functions < implied:
            warn("recovery-functions-normalized",
                 f"recovery.functions={functions} is below recovered+unrecovered={implied}; "
                 f"normalised to the lower bound {implied}", idx)
            recovery["functions"] = implied
            recovery["functionsNormalizedFrom"] = functions
            functions = implied
    if status == S.STATUS_COMPLETE:
        if functions is not None and recovered is not None and recovered != functions:
            err("complete-recovery-gap",
                f"status complete but recovered {recovered}/{functions}", idx)
        if unrecovered:
            err("complete-unrecovered",
                f"status complete but {len(unrecovered)} unrecovered function(s) listed", idx)

    # --- evidence / selfCheck ------------------------------------------------
    evidence = raw.get("evidence") or []
    if not isinstance(evidence, list):
        err("bad-evidence", "evidence must be a list", idx)
        evidence = []
    if status == S.STATUS_COMPLETE and not evidence:
        warn("complete-no-evidence",
             "status complete without an evidence entry; add the file:line / disassembly "
             "reference that proves the reconstruction", idx)

    self_check = raw.get("selfCheck") or raw.get("self_check") or {}
    if not isinstance(self_check, dict):
        err("bad-selfCheck", "selfCheck must be an object", idx)
        self_check = {}
    t_diff = self_check.get("tDiff") or []
    u_diff = self_check.get("uDiff") or []
    if not isinstance(t_diff, list) or not isinstance(u_diff, list):
        err("bad-selfCheck-diff", "selfCheck.tDiff/uDiff must be lists", idx)
        t_diff, u_diff = [], []
    if status == S.STATUS_COMPLETE and (t_diff or u_diff):
        # The author's own T/U self-check is documentation, not the verdict: the
        # authoritative comparison is member_gate.py, which measures the built
        # archive against the freeze. Record the claim loudly instead of blocking.
        warn("complete-selfcheck-diff",
             f"status complete but the member's own selfCheck reports "
             f"tDiff={len(t_diff)} uDiff={len(u_diff)} symbols; member_gate must "
             f"reproduce or allowlist them", idx)

    if status == S.STATUS_PARTIAL and functions and recovered == functions and not unrecovered:
        warn("partial-looks-complete",
             "status partial but recovery reports full coverage; set status complete "
             "when that is actually proven", idx)

    if profile in S.FLAG_PROFILES and layout in ("bitcode", "elf"):
        if bool(S.FLAG_PROFILES[profile]["emit_llvm"]) != (layout == "bitcode"):
            warn("profile-layout-conflict",
                 f"flagsProfile {profile!r} emits "
                 f"{'bitcode' if S.FLAG_PROFILES[profile]['emit_llvm'] else 'elf'} but the "
                 f"member layout is {layout!r}; build.py follows the layout, the profile "
                 f"should be corrected", idx)

    kind = raw.get("kind") or "SINGLE"
    if not isinstance(kind, str) or not kind:
        err("bad-kind", f"kind must be a non-empty string, got {kind!r}", idx)
        kind = "SINGLE"
    elif kind.upper() not in KNOWN_KINDS:
        warn("unknown-kind", f"kind {kind!r} is not one of {sorted(KNOWN_KINDS)}", idx)

    compose = raw.get("compose") or []
    if compose:
        if not isinstance(compose, list):
            err("bad-compose", "compose must be a list of steps", idx)
            compose = []
        else:
            for step_index, step in enumerate(compose):
                if not isinstance(step, dict):
                    err("bad-compose-step", f"compose[{step_index}] is not an object", idx)
                    continue
                argv = step.get("argv")
                if not isinstance(argv, list) or any(not isinstance(a, str) for a in argv):
                    err("bad-compose-argv",
                        f"compose[{step_index}].argv must be a list of strings", idx)
                if not step.get("tool"):
                    err("bad-compose-tool", f"compose[{step_index}] has no tool", idx)
    if kind.upper() == "COMPOSED" and len(sources) < 2 and not compose:
        warn("composed-without-multi-tu",
             "kind COMPOSED but fewer than two sources and no compose steps", idx)

    group = raw.get("group") or GROUP_FALLBACK
    if not isinstance(group, str) or not group:
        warn("bad-group", f"group must be a non-empty string, got {group!r}", idx)
        group = GROUP_FALLBACK

    notes = raw.get("notes") or ""
    if not isinstance(notes, str):
        warn("bad-notes", "notes must be a string", idx)
        notes = str(notes)

    header_inputs: dict[str, list[str]] = {}
    for key in ("headers", "privateHeaders"):
        if key not in raw:
            continue
        paths = raw[key]
        if not isinstance(paths, list) or any(not isinstance(path, str) or not path.strip()
                                              for path in paths):
            err("bad-headers", f"{key} must be a list of non-empty strings", idx)
        else:
            header_inputs[key] = list(paths)

    issues.extend(orig_issues)
    record = MemberRecord(
        idx=idx, name=name, status=status, layout=layout, sources=sources,
        flags_profile=str(profile), group=group, kind=kind, recovery=dict(recovery),
        original={"sha256": (original or {}).get("sha256") or fact["sha256"],
                  "bytes": (original or {}).get("bytes") or fact["bytes"],
                  **({"layout": original["layout"]} if "layout" in original else {})},
        evidence=list(evidence), self_check={"tDiff": list(t_diff), "uDiff": list(u_diff),
                                            "note": str(self_check.get("note", ""))},
        notes=notes, extra_flags=list(extra_flags), origin="manifest-json",
        source_file=S.rel(Path(origin_file)),
        idx_claimed=None if claimed_idx == idx else claimed_idx,
        compose=list(compose),
        blocked_by=list(blocked_by),
        recipe=dict(recipe),
        reference_input=reference_input,
        header_inputs=header_inputs,
    )
    return record, issues


# --------------------------------------------------------------------------- #
# Scan
# --------------------------------------------------------------------------- #


def scan_manifest_dir(manifest_dir: Path, ref: "RefIndex", idx_mode: str = "auto",
                      skip_invalid: bool = False,
                      ) -> tuple[dict[int, MemberRecord], list[Issue], list[Issue], list[str],
                                 list[dict[str, Any]], list[str]]:
    records: dict[int, MemberRecord] = {}
    errors: list[Issue] = []
    warnings: list[Issue] = []
    seen_files: list[str] = []
    skipped: list[dict[str, Any]] = []
    non_member: list[Path] = []

    if not manifest_dir.is_dir():
        warnings.append(Issue("warning", "manifest-dir-missing",
                              f"no member metadata directory at {S.rel(manifest_dir)}"))
        return records, errors, warnings, seen_files, skipped, non_member

    all_json = sorted(p for p in manifest_dir.glob("*.json") if not p.name.startswith("_"))
    files = [p for p in all_json if MEMBER_FILE_RE.match(p.name)]
    non_member = [p for p in all_json if not MEMBER_FILE_RE.match(p.name)]
    for path in files:
        seen_files.append(S.rel(path))
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(Issue("error", "bad-json", str(exc), None, S.rel(path)))
            continue
        if not isinstance(raw, dict):
            errors.append(Issue("error", "not-an-object", "expected a JSON object", None, S.rel(path)))
            continue
        expected_prefix = f"{raw.get('idx'):04d}_" if isinstance(raw.get("idx"), int) else ""
        record, issues = validate_record(raw, str(path), ref, idx_mode)
        file_errors = [i for i in issues if i.level == "error"]
        if skip_invalid and file_errors:
            # Interim health check: a record that cannot be built is excluded from
            # the manifest, but never silently -- every skipped file is listed.
            skipped.append({
                "file": S.rel(path),
                "idx": record.idx if record is not None else raw.get("idx"),
                "name": record.name if record is not None else raw.get("name"),
                "codes": sorted({i.code for i in file_errors}),
                "messages": [i.message for i in file_errors][:4],
            })
            warnings.extend(Issue("warning", "record-skipped", i.message, i.idx, S.rel(path))
                            for i in file_errors)
            continue
        errors.extend(file_errors)
        warnings.extend(i for i in issues if i.level == "warning")
        if record is None:
            continue
        if expected_prefix and not path.name.startswith(expected_prefix):
            warnings.append(Issue(
                "warning", "filename-mismatch",
                f"file name does not start with {expected_prefix!r} for idx {record.idx}",
                record.idx, S.rel(path)))
        if record.idx in records:
            other = records[record.idx]
            errors.append(Issue(
                "error", "duplicate-idx",
                f"idx {record.idx} already provided by {other.source_file}", record.idx,
                S.rel(path)))
            continue
        records[record.idx] = record
    return records, errors, warnings, seen_files, skipped, non_member


# --------------------------------------------------------------------------- #
# Legacy carry-over
# --------------------------------------------------------------------------- #


def load_legacy(path: Path, facts: dict[int, dict[str, Any]]) -> tuple[dict[int, MemberRecord], list[Issue]]:
    """Carry over entries from an existing manifest.jsonl.

    This keeps the four already-reconstructed sample members compilable while
    their owners publish ``manifest/<idx4>_<name>.json``. Legacy entries are
    marked ``origin=legacy-manifest.jsonl`` and count as ``partial`` (they carry
    no recovery measurement), never as ``complete``.
    """
    records: dict[int, MemberRecord] = {}
    issues: list[Issue] = []
    if not path.is_file():
        return records, issues
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            issues.append(Issue("warning", "legacy-bad-json", f"line {lineno} ignored"))
            continue
        idx = rec.get("idx")
        if not isinstance(idx, int) or idx not in facts:
            issues.append(Issue("warning", "legacy-bad-idx", f"line {lineno} ignored", idx))
            continue
        fact = facts[idx]
        name = rec.get("name")
        if name != S.active_member_name(fact["name"]):
            issues.append(Issue(
                "warning", "legacy-name-mismatch",
                f"line {lineno}: name {name!r} != frozen {fact['name']!r}; skipped",
                idx, S.rel(path)))
            continue
        source = rec.get("source")
        sources = [source] if isinstance(source, str) and resolve_source(source) else []
        extra = rec.get("extra_flags") or []
        layout = fact["layout"]
        profile = S.DEFAULT_PROFILE_BY_LAYOUT.get(layout, "core-oz-elf")
        if "-fexceptions" in extra and layout == "elf":
            profile = "core-oz-elf-fexceptions"
        elif "-fexceptions" in extra and layout == "bitcode":
            profile = "core-oz-bitcode-fexceptions"
        status = S.STATUS_PARTIAL
        records[idx] = MemberRecord(
            idx=idx, name=name, status=status, layout=layout, sources=sources,
            flags_profile=profile, group="sample-chain", kind="SINGLE",
            recovery={"functions": 0, "recovered": 0, "unrecovered": []},
            original={"sha256": fact["sha256"], "bytes": fact["bytes"]},
            evidence=[f"legacy:{S.rel(path)}#{idx}"],
            self_check={"tDiff": [], "uDiff": [], "note": "legacy entry: no self-check recorded"},
            notes=str(rec.get("notes", "")), extra_flags=list(extra),
            origin="legacy-manifest.jsonl", source_file=S.rel(path),
        )
        issues.append(Issue(
            "warning", "legacy-entry",
            "carried over from manifest.jsonl; publish manifest/%04d_%s.json to replace"
            % (idx, fact["name"]), idx, S.rel(path)))
    return records, issues


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render_coverage(result: Result, command: str, source_files: list[str]) -> str:
    counts = result.counts
    total = EXPECTED_MEMBERS
    covered = len(result.records)
    lines: list[str] = []
    lines.append(f"# MANIFEST-COVERAGE — {expected_members()} 成员元数据覆盖报告")
    lines.append("")
    lines.append("> 本文件由 `sdk/tools/gen_manifest.py` 生成，请勿手改。")
    lines.append("> “覆盖 complete”只表示元数据齐全且已对冻结基线自证；**不等于实现正确**。")
    lines.append("")
    lines.append("```bash")
    lines.append(command)
    lines.append("```")
    lines.append("")
    lines.append("## 基线")
    lines.append("")
    frozen = result.frozen
    lines.append("| 项 | 值 |")
    lines.append("|---|---|")
    lines.append(f"| 冻结快照 | `{frozen.get('root', '?')}` |")
    lines.append(f"| 归档 | `{frozen.get('archive', '?')}` |")
    lines.append(f"| 归档 sha256 | `{frozen.get('archive_sha256', '?')}` |")
    lines.append(f"| 归档字节 | {frozen.get('archive_bytes', '?')} |")
    lines.append(f"| 成员数 | {frozen.get('members', '?')} |")
    dups = frozen.get("duplicate_names") or {}
    dup_text = "; ".join(f"`{n}` @ {idxs}" for n, idxs in dups.items()) or "无"
    lines.append(f"| 同名成员 | {dup_text} |")
    lines.append(f"| 元数据文件 | {len(source_files)} 个（`sdk/manifest/*.json`） |")
    lines.append(f"| 已登记 | {covered}/{total} |")
    lines.append(f"| 未登记 | {len(result.missing_idx)} |")
    lines.append("")
    lines.append("## 覆盖总览")
    lines.append("")
    ready = (counts.get(S.STATUS_COMPLETE, 0) == total and not result.missing_idx
             and not result.errors)
    tiers = result.tier_counts or {}
    lines.append("```text")
    lines.append(f"{expected_members()} = complete {tiers.get('complete', 0)}"
                 f" + partial-with-source {tiers.get('partial-with-source', 0)}"
                 f" + partial-no-source {tiers.get('partial-no-source', 0)}"
                 f" + vendor-copy {tiers.get('vendor-copy', 0)}"
                 f" + missing {len(result.missing_idx)}")
    lines.append("```")
    lines.append("")
    lines.append(f"| 档位 | 成员数 | 占 {expected_members()} | 含义 |")
    lines.append("|---|---:|---:|---|")
    lines.append(f"| complete | {tiers.get('complete', 0)} | "
                 f"{tiers.get('complete', 0) / total:.1%} | 源码 + 元数据齐全，"
                 "original/selfCheck 对冻结基线自证 |")
    lines.append(f"| partial-with-source | {tiers.get('partial-with-source', 0)} | "
                 f"{tiers.get('partial-with-source', 0) / total:.1%} | 有源码，恢复未完成或未自证 |")
    lines.append(f"| partial-no-source | {tiers.get('partial-no-source', 0)} | "
                 f"{tiers.get('partial-no-source', 0) / total:.1%} | 无源码且已声明 `blockedBy`；"
                 "**不参与编译与门禁**，单独计数 |")
    lines.append(f"| vendor-copy | {tiers.get('vendor-copy', 0)} | "
                 f"{tiers.get('vendor-copy', 0) / total:.1%} | 尚未源码化，"
                 "按冻结字节回填；**交付时必须为 0** |")
    lines.append(f"| 未登记 | {len(result.missing_idx)} | {len(result.missing_idx) / total:.1%} | "
                 "没有任何 `manifest/*.json`（或 legacy 行） |")
    lines.append("")
    partial_no_source = (result.tier_members or {}).get("partial-no-source") or []
    if result.non_member_files:
        lines.append(f"### 非成员元数据（不参与 {expected_members()} 校验）")
        lines.append("")
        for path in result.non_member_files:
            lines.append(f"- `{path}`（文件名不匹配 `^\\d{{4}}_.*\\.json$`）")
        lines.append("")
    lines.append("### partial-no-source 成员名单（单列，不并入 partial）")
    lines.append("")
    if partial_no_source:
        idx_by_name = {record.name: record.idx for record in result.records
                       if not record.sources}
        for name in partial_no_source:
            idx = idx_by_name.get(name, -1)
            reason = ""
            for record in result.records:
                if record.name == name and not record.sources:
                    reason = "; ".join(record.blocked_by)
                    break
            lines.append(f"- idx {idx} `{name}` — {reason or '（无 blockedBy 理由）'}")
    else:
        lines.append("无。")
    lines.append("")
    lines.append("### partial 成员的 unrecovered 条数（逐条登记证据）")
    lines.append("")
    rollup = result.unrecovered_by_tier or {}
    if rollup:
        lines.append("| 档位 | unrecovered 条数合计 |")
        lines.append("|---|---:|")
        for tier, count in rollup.items():
            lines.append(f"| {tier} | {count} |")
        lines.append("")
        lines.append("逐成员明细：")
        lines.append("")
        lines.append("| idx | 成员 | 档位 | unrecovered |")
        lines.append("|---:|---|---|---:|")
        for record in result.records:
            if record.status == S.STATUS_COMPLETE:
                continue
            tier = ("vendor-copy" if record.status == S.STATUS_VENDOR_COPY
                    else ("partial-with-source" if record.sources else "partial-no-source"))
            lines.append(f"| {record.idx} | `{record.name}` | {tier} | "
                         f"{len(list(record.recovery.get('unrecovered') or []))} |")
    else:
        lines.append("无。")
    lines.append("")
    verdict = "READY" if ready else "NOT READY"
    lines.append(f"**Manifest gate: {verdict}** — "
                 f"{covered}/{total} 已登记，complete {counts.get(S.STATUS_COMPLETE, 0)}，"
                 f"vendor-copy {counts.get(S.STATUS_VENDOR_COPY, 0)}，"
                 f"未登记 {len(result.missing_idx)}。")
    lines.append("")
    lines.append("## idx 规范化")
    lines.append("")
    if result.normalized:
        lines.append(f"共 {len(result.normalized)} 条元数据文件的 `idx` 与冻结序号不一致，"
                     f"已按 `(name, original.sha256)` 定位到冻结序号（模式 `{result.idx_mode}`）。"
                     "文件内的 `idx` 与文件名**不是**权威来源。")
        lines.append("")
        lines.append("| 文件 | 写的 idx | 冻结 idx | 偏差 | 成员 |")
        lines.append("|---|---:|---:|---:|---|")
        for row in result.normalized[:60]:
            lines.append(f"| `{row['sourceFile']}` | {row['claimedIdx']} | {row['idx']} | "
                         f"{row['delta']:+d} | `{row['name']}` |")
        if len(result.normalized) > 60:
            lines.append(f"| … | | | | 其余 {len(result.normalized) - 60} 条 |")
    else:
        lines.append("无：所有元数据文件的 `idx` 与冻结序号一致"
                     "（`--require-normalized` 可把这条变成硬门禁）。")
    lines.append("")
    lines.append("## 逐组统计")
    lines.append("")
    lines.append("| 组 | 成员 | complete | partial | vendor-copy | 未登记 |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    group_totals: dict[str, int] = {}
    for record in result.records:
        group_totals[record.group] = group_totals.get(record.group, 0) + 1
    ordered_groups = sorted(group_totals, key=lambda g: (-group_totals[g], g))
    for group in ordered_groups:
        row = result.group_counts.get(group, {})
        lines.append(f"| `{group}` | {group_totals[group]} | "
                     f"{row.get(S.STATUS_COMPLETE, 0)} | {row.get(S.STATUS_PARTIAL, 0)} | "
                     f"{row.get(S.STATUS_VENDOR_COPY, 0)} | {row.get('missing', 0)} |")
    missing_by_group = result.group_counts.get("__missing__", {})
    if missing_by_group:
        lines.append(f"| _未登记_ | {sum(missing_by_group.values())} | 0 | 0 | 0 | "
                     f"{sum(missing_by_group.values())} |")
    lines.append("")
    lines.append("## flagsProfile 分布")
    lines.append("")
    lines.append("| flagsProfile | 成员数 |")
    lines.append("|---|---:|")
    for profile, count in sorted(result.profile_counts.items()):
        lines.append(f"| `{profile}` | {count} |")
    lines.append("")
    lines.append("## 未登记 idx 明细")
    lines.append("")
    if result.missing_idx:
        lines.append(f"共 {len(result.missing_idx)} 个。逐个列出（idx → 期望成员名 → 期望元数据文件）：")
        lines.append("")
        lines.append("```text")
        for idx in result.missing_idx:
            lines.append(f"{idx:3d}  {result._missing_names.get(idx, '?'):45s} "
                         f"manifest/{idx:04d}_{result._missing_names.get(idx, '?')}.json")
        lines.append("```")
    else:
        lines.append(f"无：{expected_members()} 个 idx 全部有元数据。")
    lines.append("")
    lines.append("## 已跳过（--skip-invalid）的记录")
    lines.append("")
    if result.skipped_records:
        lines.append(f"共 {len(result.skipped_records)} 个元数据文件因校验错误被排除；"
                     "它们既不在 `manifest.jsonl` 里，也不计入任何档位。")
        lines.append("")
        lines.append("| 文件 | idx | 成员 | 错误码 |")
        lines.append("|---|---:|---|---|")
        for row in result.skipped_records[:80]:
            lines.append(f"| `{row['file']}` | {row['idx']} | `{row['name']}` | "
                         f"{', '.join(row['codes'])} |")
        if len(result.skipped_records) > 80:
            lines.append(f"| … | | | 其余 {len(result.skipped_records) - 80} 条 |")
    else:
        lines.append("无（未启用 `--skip-invalid`，或没有无效记录）。")
    lines.append("")
    lines.append("## 校验错误")
    lines.append("")
    if result.errors:
        lines.append(f"共 {len(result.errors)} 条。**存在错误时 manifest.jsonl 不会被写出。**")
        lines.append("")
        for issue in result.errors:
            lines.append(f"- `{issue.code}` {issue.render()}")
    else:
        lines.append("无。")
    lines.append("")
    lines.append("## 校验警告")
    lines.append("")
    if result.warnings:
        lines.append(f"共 {len(result.warnings)} 条（不阻塞，但需要作者确认）。")
        lines.append("")
        seen: Counter[str] = Counter()
        for issue in result.warnings:
            seen[issue.code] += 1
        lines.append("| code | 条数 |")
        lines.append("|---|---:|")
        for code, count in sorted(seen.items()):
            lines.append(f"| `{code}` | {count} |")
        lines.append("")
        for issue in result.warnings[:80]:
            lines.append(f"- `{issue.code}` {issue.render()}")
        if len(result.warnings) > 80:
            lines.append(f"- … 其余 {len(result.warnings) - 80} 条见 `--json` 输出")
    else:
        lines.append("无。")
    lines.append("")
    lines.append("## 边界")
    lines.append("")
    lines.append("- 覆盖度是**元数据**结论，不是实现等价结论；`complete` 只说明作者提交了"
                 "可交叉验证的源码、原始 sha/bytes、selfCheck 空差集。")
    lines.append("- `partial` 可以编译、可以进归档，但 `build.py` 会在报告里如实标注缺口。")
    lines.append("- 未登记 idx 不会被静默跳过：`manifest.jsonl` 不写、`build.py` 退出码 3。")
    lines.append("")
    return "\n".join(lines)


def render_catalog(facts: dict[int, dict[str, Any]], records: dict[int, MemberRecord],
                   result: Result) -> str:
    lines = [f"# MANIFEST-CATALOG — {expected_members()} 成员登记目录（自动生成）", "",
             "> 由 `gen_manifest.py` 生成。作者按本表建 `sdk/manifest/<idx4>_<name>.json`。",
             "> `sha256`/`bytes` 是**冻结归档里该序号的原始字节**，直接填进 `original` 字段即可。",
             "", "| idx | 成员 | 字节 | 原始 sha256（前 16） | 布局 | 状态 | 期望文件 |",
             "|---:|---|---:|---|---|---|---|"]
    for idx in sorted(facts):
        fact = facts[idx]
        record = records.get(idx)
        status = record.status if record else "—"
        origin = record.origin if record else ""
        cell = status + ("（legacy）" if origin == "legacy-manifest.jsonl" else "")
        lines.append(f"| {idx} | `{fact['name']}` | {fact['bytes']} | `{fact['sha256'][:16]}` | "
                     f"{fact['layout']} | {cell} | `manifest/{idx:04d}_{fact['name']}.json` |")
    lines.append("")
    lines.append(f"未登记：{len(result.missing_idx)} 个；完整覆盖需 {expected_members()} 个。")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Generation entry point
# --------------------------------------------------------------------------- #


def generate(
    manifest_dir: Path | None = None,
    out_path: Path | None = None,
    coverage_path: Path | None = None,
    catalog_path: Path | None = None,
    allow_partial: bool = False,
    no_legacy: bool = False,
    allow_shrink: bool = False,
    write: bool = True,
    archive_override: str | None = None,
    idx_mode: str = "auto",
    require_normalized: bool = False,
    skip_invalid: bool = False,
    quiet: bool = False,
) -> Result:
    manifest_dir = Path(manifest_dir) if manifest_dir else MANIFEST_DIR
    out_path = Path(out_path) if out_path else MANIFEST_JSONL
    coverage_path = Path(coverage_path) if coverage_path else COVERAGE_MD
    catalog_path = Path(catalog_path) if catalog_path else CATALOG_MD

    result = Result(idx_mode=idx_mode)
    snapshot, archive, facts, ref_issues = load_reference(archive_override)
    result.errors.extend(i for i in ref_issues if i.level == "error")
    result.warnings.extend(i for i in ref_issues if i.level == "warning")
    result.frozen = snapshot.describe() if snapshot else {}
    if archive is not None:
        result.frozen["members"] = len(archive.members)
        result.frozen["duplicate_names"] = archive.duplicate_groups()
    if not facts:
        return result

    ref = RefIndex.build(facts)
    records, errors, warnings, source_files, skipped, non_member = scan_manifest_dir(
        manifest_dir, ref, idx_mode, skip_invalid=skip_invalid)
    result.errors.extend(errors)
    result.warnings.extend(warnings)
    result.metadata_files = len(source_files)
    result.skipped_records = skipped
    result.non_member_files = [S.rel(path) for path in non_member]

    # A normalised record means the author's file still carries a non-canonical
    # idx (or a 1-based filename). ``--require-normalized`` is the integration
    # gate that refuses to proceed while any such file remains.
    for record in records.values():
        if record.idx_claimed is not None and record.idx_claimed != record.idx:
            result.normalized.append({
                "sourceFile": record.source_file,
                "claimedIdx": record.idx_claimed,
                "idx": record.idx,
                "name": record.name,
                "delta": record.idx_claimed - record.idx,
            })
    if require_normalized and result.normalized:
        result.errors.append(Issue(
            "error", "not-normalized",
            f"{len(result.normalized)} metadata file(s) still carry a non-canonical idx; "
            "run sdk/tools/normalize_manifest.py or fix idx/file name by hand",
        ))
    for record in records.values():
        if require_normalized and record.source_file:
            canonical = f"manifest/{record.idx:04d}_{record.name}.json"
            if not record.source_file.endswith(canonical):
                result.errors.append(Issue(
                    "error", "filename-not-normalized",
                    f"{record.source_file} should be {canonical}",
                    record.idx, record.source_file))

    legacy_records: dict[int, MemberRecord] = {}
    if not no_legacy and out_path.is_file():
        legacy_records, legacy_issues = load_legacy(out_path, facts)
        result.warnings.extend(legacy_issues)
        for idx, record in legacy_records.items():
            if idx not in records:
                records[idx] = record
                result.legacy_count += 1

    # Shrink guard: an existing manifest.jsonl with more members than the new
    # result means metadata went missing (deleted file / renamed idx). Refuse
    # instead of silently dropping already-validated members.
    if out_path.is_file() and not allow_shrink:
        existing = _count_jsonl(out_path)
        if existing > len(records):
            result.errors.append(Issue(
                "error", "manifest-shrink",
                f"the existing {S.rel(out_path)} has {existing} members but the new "
                f"result has {len(records)}; pass --allow-shrink only if that is intended",
            ))

    result.records = [records[idx] for idx in sorted(records)]
    for idx in range(EXPECTED_MEMBERS):
        if idx not in records:
            result.missing_idx.append(idx)

    counts: Counter[str] = Counter(record.status for record in records.values())
    result.counts = {status: counts.get(status, 0) for status in S.STATUS_ALL}

    # Four delivery tiers: complete / partial-with-source / partial-no-source /
    # vendor-copy. "partial-no-source" is never folded into partial: those members
    # are blocked, they are not merely unfinished.
    tiers: dict[str, list[str]] = {"complete": [], "partial-with-source": [],
                                   "partial-no-source": [], "vendor-copy": []}
    unrecovered: Counter[str] = Counter()
    for record in result.records:
        if record.status == S.STATUS_COMPLETE:
            tier = "complete"
        elif record.status == S.STATUS_VENDOR_COPY:
            tier = "vendor-copy"
        else:
            tier = "partial-with-source" if record.sources else "partial-no-source"
        tiers[tier].append(record.name)
        if record.status != S.STATUS_COMPLETE:
            unrecovered[tier] += len(list(record.recovery.get("unrecovered") or []))
    result.tier_members = tiers
    result.tier_counts = {tier: len(names) for tier, names in tiers.items()}
    result.unrecovered_by_tier = dict(sorted(unrecovered.items()))
    group_counts: dict[str, dict[str, int]] = {}
    for record in records.values():
        row = group_counts.setdefault(record.group, {s: 0 for s in S.STATUS_ALL})
        row[record.status] = row.get(record.status, 0) + 1
    for idx in result.missing_idx:
        group_counts.setdefault("__missing__", {})["missing"] = \
            group_counts.get("__missing__", {}).get("missing", 0) + 1
    result.group_counts = group_counts
    profile_counts: Counter[str] = Counter(record.flags_profile for record in records.values())
    result.profile_counts = dict(sorted(profile_counts.items()))

    # Attach the frozen names so the coverage renderer can name missing slots.
    result._missing_names = {idx: facts[idx]["name"] for idx in result.missing_idx}

    command = "py runtime/maplesu-sdk/sdk/tools/gen_manifest.py" + (
        " --allow-partial" if allow_partial else "")
    coverage_text = render_coverage(result, command, source_files)
    catalog_text = render_catalog(facts, records, result)

    if write and result.ok:
        payload = "".join(
            json.dumps(record.to_jsonl(), ensure_ascii=False, separators=(",", ":")) + "\n"
            for record in result.records
        )
        S.write_text(out_path, payload)
        result.written.append(S.rel(out_path))
        S.write_text(coverage_path, coverage_text)
        result.written.append(S.rel(coverage_path))
        if catalog_path is not None:
            S.write_text(catalog_path, catalog_text)
            result.written.append(S.rel(catalog_path))
    elif write and not result.ok:
        # Never overwrite a good manifest with a known-bad one; still refresh the
        # coverage report so the failure is visible on disk.
        S.write_text(coverage_path, coverage_text)
        result.written.append(S.rel(coverage_path))
        if catalog_path is not None:
            S.write_text(catalog_path, catalog_text)
            result.written.append(S.rel(catalog_path))

    if not quiet:
        print(f"[manifest] reference: {S.rel(archive.path) if archive else '?'} "
              f"sha256={archive.sha256[:16] if archive else '?'} members={len(archive.members) if archive else 0}")
        print(f"[manifest] metadata files: {len(source_files)}; legacy carried: {result.legacy_count}")
        print(f"[manifest] covered {len(result.records)}/{expected_members()}: "
              f"complete={result.counts.get(S.STATUS_COMPLETE, 0)} "
              f"partial={result.counts.get(S.STATUS_PARTIAL, 0)} "
              f"vendor-copy={result.counts.get(S.STATUS_VENDOR_COPY, 0)} "
              f"missing={len(result.missing_idx)}")
        if result.errors:
            for issue in result.errors:
                print("  " + issue.render(), file=sys.stderr)
        if result.missing_idx:
            preview = ", ".join(str(i) for i in result.missing_idx[:24])
            more = "" if len(result.missing_idx) <= 24 else f", … (+{len(result.missing_idx) - 24})"
            print(f"[manifest] missing idx: {preview}{more}")
        for path in result.written:
            print(f"[manifest] wrote {path}")
    return result


def _count_jsonl(path: Path) -> int:
    count = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if isinstance(json.loads(line), dict):
                count += 1
        except json.JSONDecodeError:
            continue
    return count


# gen_manifest.Result gains this attribute in generate(); declared here so the
# dataclass field list stays readable.
Result._missing_names = {}  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="gen_manifest.py",
        description="Collect sdk/manifest/*.json into manifest.jsonl + coverage report.",
        epilog="exit codes: 0 ok, 2 environment, 3 manifest (invalid or incomplete without "
               "--allow-partial).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--manifest-dir", default=None, help="member metadata dir (default sdk/manifest)")
    parser.add_argument("--out", default=None, help="output manifest.jsonl (default sdk/manifest.jsonl)")
    parser.add_argument("--coverage", default=None, help="coverage markdown (default sdk/notes/MANIFEST-COVERAGE.md)")
    parser.add_argument("--catalog", default=None, help="per-member catalog markdown")
    parser.add_argument("--allow-partial", action="store_true",
                        help="accept <258 covered members (interim health check)")
    parser.add_argument("--idx-base", choices=("auto", "strict"), default="auto",
                        help="auto: resolve the frozen ordinal from (name, original.sha256) and "
                             "warn when the file's idx disagrees; strict: refuse such files")
    parser.add_argument("--skip-invalid", action="store_true",
                        help="exclude records with errors from manifest.jsonl and list them "
                             "(interim health check; use with --allow-partial)")
    parser.add_argument("--require-normalized", action="store_true",
                        help="fail (exit 3) when any file name or idx is non-canonical")
    parser.add_argument("--check", action="store_true", help="validate only, write nothing")
    parser.add_argument("--json", action="store_true", help="print the JSON summary to stdout")
    parser.add_argument("--no-legacy", action="store_true",
                        help="do not carry over entries from an existing manifest.jsonl")
    parser.add_argument("--allow-shrink", action="store_true",
                        help="allow the new manifest to have fewer members than the existing one")
    parser.add_argument("--archive", default=None,
                        help="frozen residual archive override (default: the freeze snapshot)")
    parser.add_argument("--quiet", action="store_true", help="suppress progress lines")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(list(argv if argv is not None else sys.argv[1:]))
    try:
        result = generate(
            manifest_dir=args.manifest_dir,
            out_path=args.out,
            coverage_path=args.coverage,
            catalog_path=None if args.check else (args.catalog or CATALOG_MD),
            allow_partial=args.allow_partial,
            no_legacy=args.no_legacy,
            allow_shrink=args.allow_shrink,
            write=not args.check,
            archive_override=args.archive,
            idx_mode=args.idx_base,
            require_normalized=args.require_normalized,
            skip_invalid=args.skip_invalid,
            quiet=args.quiet or args.json,
        )
    except S.ToolchainMissing as exc:
        print(f"error: {exc}", file=sys.stderr)
        return S.EXIT_TOOLCHAIN
    except S.FreezeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return S.EXIT_TOOLCHAIN

    summary = result.summary()
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not result.ok:
        if not args.quiet:
            print(f"gen_manifest: {len(result.errors)} error(s); nothing written to manifest.jsonl",
                  file=sys.stderr)
        return S.EXIT_MANIFEST
    if result.missing_idx and not args.allow_partial:
        if not args.json:
            print(f"gen_manifest: {len(result.missing_idx)} of {EXPECTED_MEMBERS} indices are "
                  f"unregistered; re-run with --allow-partial for an interim health check",
                  file=sys.stderr)
        if not result.written:
            print(json.dumps(summary, ensure_ascii=False, indent=2) if args.json else "",
                  file=sys.stdout)
        return S.EXIT_MANIFEST
    if not args.quiet and not args.json:
        verdict = "READY" if result.complete else "PARTIAL"
        print(f"gen_manifest: {verdict} — covered {len(result.records)}/{expected_members()}, "
              f"complete {result.counts.get(S.STATUS_COMPLETE, 0)}, "
              f"vendor-copy {result.counts.get(S.STATUS_VENDOR_COPY, 0)}, "
              f"missing {len(result.missing_idx)}")
    return S.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
