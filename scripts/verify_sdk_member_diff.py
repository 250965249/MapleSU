#!/usr/bin/env python3
"""Independent recomputation of the Ultra SDK archive member diff gate.

This script is deliberately standalone (Python standard library only) and is NOT
imported by the PowerShell builder: it re-parses both GNU ``ar`` containers from
raw bytes and recomputes the per-member (name, size, sha256) table on its own, so
the evidence written by the builder is never trusted on its own word.

Contract (MapleSU 5.0.5 Ultra SDK, outer-layer repair):
  baseline  = old production archive ``libkernel_module_kit_static.a``
  candidate = rebuilt archive that must differ in exactly the members
              ord 24 ``module_base_kernel_mem.o``
              ord 29 ``module_base_kernel_func_hook.o``
              ord 34 ``module_base_cpu_icache_sync.o``
  and must have 0 added members, 0 removed members, identical member order,
  an unchanged embedded-bootstrap member (``maplesu_autorun_bootstrap_install.o``)
  and a freshly generated, non-empty archive symbol index.

Usage:
  verify_sdk_member_diff.py --baseline <old.a> --candidate <new.a>
                            [--claim sdk/member-diff.json]
                            [--sdk-build sdk-build.json]
                            [--expect-ordinals 24,29,34]
                            [--expect-names a.o,b.o,c.o]
                            [--json-out <path>] [--quiet]

Exit codes (strict):
  0  every check passed
  1  gate failure (archive diff, claim mismatch, identity mismatch, ...)
  2  usage error (bad arguments, missing/unreadable files)
  3  internal error (unexpected exception while parsing)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

DEFAULT_ORDINALS = "24,29,34,53"
DEFAULT_NAMES = (
    "module_base_kernel_mem.o,"
    "module_base_kernel_func_hook.o,"
    "module_base_cpu_icache_sync.o,"
    "maplesu_installer.o"
)
DEFAULT_REPAIRS = "m024,m029,m034"
BOOTSTRAP_MEMBER = "maplesu_autorun_bootstrap_install.o"
AR_MAGIC = b"!<arch>\n"
GNU_SPECIAL_NAMES = ("/", "//", "/SYM64/")


class GateError(Exception):
    """A check that must make the process exit non-zero (exit code 1)."""


class UsageError(Exception):
    """Bad invocation or unreadable input (exit code 2)."""


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _decode_gnu_long_name(table, offset):
    end = table.find(b"/\n", offset)
    if end < 0:
        raise GateError("corrupt GNU long-name table: unterminated entry at %d" % offset)
    return table[offset:end].decode("utf-8", "surrogateescape")


def _normalise_gnu_name(raw):
    name = raw[:-1] if raw.endswith("/") else raw
    if not name:
        raise GateError("empty member name in archive header")
    return name


def parse_ar(path):
    """Parse a GNU/BSD ``ar`` archive into its real members.

    Returns a dict with:
      members        list of {ord, name, size, sha256, body_offset, raw_name}
      member_count   number of real members (special entries excluded)
      special        list of special entries seen ('/', '//', '/SYM64/')
      symbol_index   {present: bool, size: int, name: str|None}
      long_name_table_size
    """
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        raise UsageError("cannot read archive %s: %s" % (path, exc))

    if not data.startswith(AR_MAGIC):
        raise GateError("%s is not a GNU ar archive (bad magic)" % path)

    offset = len(AR_MAGIC)
    long_names = b""
    raw_entries = []
    special = []
    symbol_index = {"present": False, "size": 0, "name": None}

    while offset + 60 <= len(data):
        header = data[offset:offset + 60]
        if header[58:60] != b"`\n":
            raise GateError(
                "corrupt ar header at offset %d (missing terminator)" % offset
            )
        raw_name = header[0:16].decode("latin-1").rstrip()
        try:
            size = int(header[48:58].decode("latin-1").strip())
        except ValueError:
            raise GateError(
                "corrupt ar header at offset %d (bad size field %r)"
                % (offset, header[48:58])
            )
        if size < 0:
            raise GateError("negative member size at offset %d" % offset)
        body_offset = offset + 60
        body_end = body_offset + size
        if body_end > len(data):
            raise GateError(
                "member at offset %d declares %d bytes but archive ends at %d"
                % (offset, size, len(data))
            )
        body = data[body_offset:body_end]

        if raw_name in GNU_SPECIAL_NAMES:
            special.append(raw_name)
            if raw_name == "//":
                long_names = body
            elif raw_name == "/":
                symbol_index = {"present": True, "size": size, "name": "/"}
            elif raw_name == "/SYM64/":
                symbol_index = {"present": True, "size": size, "name": "/SYM64/"}
        else:
            raw_entries.append(
                {"raw_name": raw_name, "size": size, "body": body,
                 "body_offset": body_offset}
            )

        offset = body_end
        if offset % 2:
            offset += 1

    members = []
    for index, entry in enumerate(raw_entries):
        raw_name = entry["raw_name"]
        body = entry["body"]
        size = entry["size"]

        if raw_name.startswith("#1/"):
            # BSD long name: the name is stored at the front of the member body.
            try:
                name_len = int(raw_name[3:])
            except ValueError:
                raise GateError("bad BSD long name header %r" % raw_name)
            if name_len < 0 or name_len > len(body):
                raise GateError("BSD long name length %d exceeds member body" % name_len)
            name = body[:name_len].decode("utf-8", "surrogateescape").rstrip("\x00")
            payload = body[name_len:]
            payload_offset = entry["body_offset"] + name_len
            payload_size = size - name_len
        elif raw_name.startswith("/") and raw_name[1:].isdigit():
            name = _decode_gnu_long_name(long_names, int(raw_name[1:]))
            payload = body
            payload_offset = entry["body_offset"]
            payload_size = size
        else:
            name = _normalise_gnu_name(raw_name)
            payload = body
            payload_offset = entry["body_offset"]
            payload_size = size

        if not name:
            raise GateError("member %d resolved to an empty name" % index)

        members.append(
            {
                "ord": index,
                "name": name,
                "size": payload_size,
                "sha256": sha256_bytes(payload),
                "body_offset": payload_offset,
            }
        )

    return {
        "path": os.path.abspath(path),
        "file_sha256": sha256_file(path),
        "file_size": len(data),
        "members": members,
        "member_count": len(members),
        "special": special,
        "symbol_index": symbol_index,
        "long_name_table_size": len(long_names),
    }


def compare_members(baseline, candidate):
    """Compare two parsed archives by ordinal; return the diff structure."""
    old = baseline["members"]
    new = candidate["members"]

    if baseline["member_count"] != candidate["member_count"]:
        raise GateError(
            "member count changed: baseline=%d candidate=%d"
            % (baseline["member_count"], candidate["member_count"])
        )

    changed, added, removed, order_errors = [], [], [], []
    for index in range(max(len(old), len(new))):
        left = old[index] if index < len(old) else None
        right = new[index] if index < len(new) else None
        if left is None:
            added.append({"ord": index, "name": right["name"],
                          "candidateSha256": right["sha256"]})
            continue
        if right is None:
            removed.append({"ord": index, "name": left["name"],
                            "baselineSha256": left["sha256"]})
            continue
        if left["name"] != right["name"]:
            order_errors.append(
                {"ord": index, "baselineName": left["name"],
                 "candidateName": right["name"]}
            )
            continue
        if left["sha256"] != right["sha256"] or left["size"] != right["size"]:
            changed.append(
                {
                    "ord": index,
                    "name": left["name"],
                    "baselineSha256": left["sha256"],
                    "candidateSha256": right["sha256"],
                    "baselineSize": left["size"],
                    "candidateSize": right["size"],
                }
            )

    return {
        "changed": changed,
        "added": added,
        "removed": removed,
        "orderErrors": order_errors,
        "unchanged": baseline["member_count"] - len(changed),
    }


def expect_ordinals(text):
    try:
        values = [int(part) for part in text.split(",") if part.strip() != ""]
    except ValueError:
        raise UsageError("--expect-ordinals must be a comma separated integer list")
    if not values:
        raise UsageError("--expect-ordinals must not be empty")
    if len(values) != len(set(values)):
        raise UsageError("--expect-ordinals contains duplicates")
    return sorted(values)


def expect_names(text):
    names = [part.strip() for part in text.split(",") if part.strip() != ""]
    if not names:
        raise UsageError("--expect-names must not be empty")
    if len(names) != len(set(names)):
        raise UsageError("--expect-names contains duplicates")
    return names


def load_json(path, what):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise UsageError("cannot read %s %s: %s" % (what, path, exc))
    except json.JSONDecodeError as exc:
        raise GateError("%s %s is not valid JSON: %s" % (what, path, exc))


def require(condition, message):
    if not condition:
        raise GateError(message)


def check_archive_shape(baseline, candidate, expected_ordinals, expected_names,
                        checks):
    """Core gate: exactly the expected members changed, nothing added/removed."""
    if not candidate["symbol_index"]["present"]:
        raise GateError("candidate archive has no archive symbol index (not regenerated)")
    require(
        candidate["symbol_index"]["size"] > 0,
        "candidate archive symbol index is empty",
    )
    checks.append("symbol-index present size=%d" % candidate["symbol_index"]["size"])
    checks.append("long-name-table b=%d c=%d" % (
        baseline["long_name_table_size"], candidate["long_name_table_size"]))

    diff = compare_members(baseline, candidate)
    require(
        not diff["orderErrors"],
        "member order/name mismatch at ordinals %s"
        % [item["ord"] for item in diff["orderErrors"]],
    )
    require(not diff["added"], "members added: %s" % diff["added"])
    require(not diff["removed"], "members removed: %s" % diff["removed"])

    changed_ordinals = sorted(item["ord"] for item in diff["changed"])
    require(
        changed_ordinals == expected_ordinals,
        "changed ordinals %s != expected %s" % (changed_ordinals, expected_ordinals),
    )
    changed_names = [item["name"] for item in diff["changed"]]
    require(
        sorted(changed_names) == sorted(expected_names),
        "changed member names %s != expected %s" % (changed_names, expected_names),
    )
    for item in diff["changed"]:
        require(
            item["baselineSha256"] != item["candidateSha256"],
            "member %s at ord %d reported changed but digests are equal"
            % (item["name"], item["ord"]),
        )

    by_name = {item["name"]: item for item in diff["changed"]}
    for name in expected_names:
        require(name in by_name, "expected changed member %s did not change" % name)

    checks.append("changed=%d added=0 removed=0 total=%d"
                  % (len(diff["changed"]), candidate["member_count"]))
    for item in diff["changed"]:
        checks.append(
            "changed ord=%d %s %d->%d"
            % (item["ord"], item["name"], item["baselineSize"], item["candidateSize"])
        )

    # The embedded bootstrap carrier member must be bit-for-bit untouched.
    boot_old = [m for m in baseline["members"] if m["name"] == BOOTSTRAP_MEMBER]
    boot_new = [m for m in candidate["members"] if m["name"] == BOOTSTRAP_MEMBER]
    require(len(boot_old) == 1, "baseline lacks unique member %s" % BOOTSTRAP_MEMBER)
    require(len(boot_new) == 1, "candidate lacks unique member %s" % BOOTSTRAP_MEMBER)
    require(
        boot_old[0]["sha256"] == boot_new[0]["sha256"],
        "embedded bootstrap member changed: %s -> %s"
        % (boot_old[0]["sha256"], boot_new[0]["sha256"]),
    )
    checks.append("bootstrap-member unchanged ord=%d sha256=%s"
                  % (boot_new[0]["ord"], boot_new[0]["sha256"]))

    # Duplicate member names must survive the rebuild (patch_base.o appears 3x).
    dupes = {}
    for member in candidate["members"]:
        dupes[member["name"]] = dupes.get(member["name"], 0) + 1
    duplicate_names = sorted(name for name, count in dupes.items() if count > 1)
    for name in duplicate_names:
        require(
            dupes[name] == sum(1 for m in baseline["members"] if m["name"] == name),
            "duplicate member %s count changed" % name,
        )
    checks.append("duplicate-names preserved=%s" % duplicate_names)

    return diff, boot_new[0]


def check_claim(claim_path, diff, baseline, candidate, boot_member, checks,
                expected_ids):
    claim = load_json(claim_path, "member-diff claim")
    require(isinstance(claim, dict), "member-diff claim must be a JSON object")

    if "schemaVersion" in claim:
        require(claim["schemaVersion"] == 1,
                "member-diff schemaVersion must be 1, got %r" % claim["schemaVersion"])

    base_claim = claim.get("baseline", {})
    cand_claim = claim.get("candidate", {})
    if isinstance(base_claim, dict) and "sha256" in base_claim:
        require(base_claim["sha256"] == baseline["file_sha256"],
                "claim baseline sha256 does not match the real baseline file")
    if isinstance(cand_claim, dict) and "sha256" in cand_claim:
        require(cand_claim["sha256"] == candidate["file_sha256"],
                "claim candidate sha256 does not match the real candidate file")
    if isinstance(base_claim, dict) and "memberCount" in base_claim:
        require(base_claim["memberCount"] == baseline["member_count"],
                "claim baseline memberCount mismatch")
    if isinstance(cand_claim, dict) and "memberCount" in cand_claim:
        require(cand_claim["memberCount"] == candidate["member_count"],
                "claim candidate memberCount mismatch")

    claimed_members = claim.get("members")
    require(isinstance(claimed_members, list) and claimed_members,
            "claim has no members[] array")
    require(len(claimed_members) == candidate["member_count"],
            "claim members[] length %d != archive member count %d"
            % (len(claimed_members), candidate["member_count"]))

    real = {}
    for left, right in zip(baseline["members"], candidate["members"]):
        status = "unchanged"
        if left["sha256"] != right["sha256"] or left["size"] != right["size"]:
            status = "changed"
        real[left["ord"]] = {
            "ord": left["ord"],
            "name": left["name"],
            "baselineSha256": left["sha256"],
            "candidateSha256": right["sha256"],
            "status": status,
        }

    for entry in claimed_members:
        require(isinstance(entry, dict), "claim member entry must be an object")
        ord_value = entry.get("ord", entry.get("index"))
        require(isinstance(ord_value, int),
                "claim member entry lacks integer ord: %r" % entry)
        require(ord_value in real, "claim references unknown ordinal %d" % ord_value)
        expected = real[ord_value]
        require(entry.get("name") == expected["name"],
                "claim name mismatch at ord %d: %r != %r"
                % (ord_value, entry.get("name"), expected["name"]))
        require(entry.get("status") == expected["status"],
                "claim status mismatch at ord %d: %r != %r"
                % (ord_value, entry.get("status"), expected["status"]))
        for key in ("baselineSha256", "candidateSha256"):
            if key in entry:
                require(entry[key] == expected[key],
                        "claim %s mismatch at ord %d" % (key, ord_value))

    changed_claim = claim.get("changed")
    if isinstance(changed_claim, list):
        require(len(changed_claim) == len(diff["changed"]),
                "claim changed[] length %d != recomputed %d"
                % (len(changed_claim), len(diff["changed"])))
        real_changed = {(item["ord"], item["name"]): item for item in diff["changed"]}
        for item in changed_claim:
            ord_value = item.get("ord", item.get("memberOrdinal"))
            key = (ord_value, item.get("name"))
            require(key in real_changed,
                    "claim changed[] entry not found in recomputation: %r" % (key,))
            require(item.get("baselineSha256", item.get("beforeSha256"))
                    == real_changed[key]["baselineSha256"],
                    "claim changed[] baseline digest mismatch at %r" % (key,))
            require(item.get("candidateSha256", item.get("afterSha256"))
                    == real_changed[key]["candidateSha256"],
                    "claim changed[] candidate digest mismatch at %r" % (key,))

    for key in ("added", "removed"):
        value = claim.get(key, [])
        require(isinstance(value, list) and not value,
                "claim %s[] must be empty, got %r" % (key, value))

    ids = claim.get("changedObjectIds")
    if ids is not None:
        require(sorted(ids) == expected_ids,
                "claim changedObjectIds must be %r, got %r"
                % (expected_ids, sorted(ids)))

    summary = claim.get("summary")
    if isinstance(summary, dict):
        for key, value in (("changed", len(diff["changed"])),
                           ("added", 0), ("removed", 0),
                           ("totalMembers", candidate["member_count"])):
            if key in summary:
                require(summary[key] == value,
                        "claim summary.%s=%r != %d" % (key, summary[key], value))

    claim_boot = claim.get("bootstrapMember")
    if claim_boot is not None:
        require(isinstance(claim_boot, dict),
                "claim bootstrapMember must be an object")
        for key in ("baselineSha256", "candidateSha256", "sha256"):
            if key in claim_boot:
                require(claim_boot[key] == boot_member["sha256"],
                        "claim bootstrapMember.%s does not match the untouched member"
                        % key)
        if "changed" in claim_boot:
            require(claim_boot["changed"] is False,
                    "claim bootstrapMember.changed must be false")
    checks.append("claim %s consistent with recomputation" % os.path.basename(claim_path))


def resolve_evidence_path(base_dir, value):
    if not isinstance(value, str) or not value:
        return None
    if os.path.isabs(value):
        return value
    return os.path.normpath(os.path.join(base_dir, value))


def check_sdk_build(sdk_build_path, diff, candidate, checks, expected_ids,
                    expected_repair_ids, expected_stamp_ids):
    """Cross-check the build manifest against the recomputed archive diff."""
    build = load_json(sdk_build_path, "sdk-build manifest")
    require(isinstance(build, dict), "sdk-build must be a JSON object")
    checks.append("sdk-build %s" % os.path.basename(sdk_build_path))

    if "sdkSha256" in build:
        require(build["sdkSha256"] == candidate["file_sha256"],
                "sdk-build.sdkSha256 does not match the candidate archive")
    artifacts = build.get("artifacts") or {}
    if isinstance(artifacts, dict):
        archive = artifacts.get("archive") or {}
        if isinstance(archive, dict) and "sha256" in archive:
            require(archive["sha256"] == candidate["file_sha256"],
                    "sdk-build.artifacts.archive.sha256 does not match the candidate")

    member_diff = build.get("memberDiff") or {}
    if isinstance(member_diff, dict):
        if "totalMembers" in member_diff:
            require(member_diff["totalMembers"] == candidate["member_count"],
                    "sdk-build.memberDiff.totalMembers mismatch")
        for key in ("added", "removed"):
            value = member_diff.get(key, [])
            require(isinstance(value, list) and not value,
                    "sdk-build.memberDiff.%s[] must be empty" % key)
        changed = member_diff.get("changed")
        if isinstance(changed, list):
            require(len(changed) == len(diff["changed"]),
                    "sdk-build.memberDiff.changed length mismatch")
            real = {(item["ord"], item["name"]): item for item in diff["changed"]}
            for item in changed:
                ord_value = item.get("ordinal", item.get("memberOrdinal", item.get("ord")))
                require((ord_value, item.get("name")) in real,
                        "sdk-build.memberDiff.changed entry not recomputed: %r"
                        % ((ord_value, item.get("name")),))
                expected = real[(ord_value, item.get("name"))]
                require(item.get("baselineSha256", item.get("beforeSha256"))
                        == expected["baselineSha256"],
                        "sdk-build.memberDiff changed baseline digest mismatch")
                require(item.get("newSha256", item.get("afterSha256",
                                                       item.get("candidateSha256")))
                        == expected["candidateSha256"],
                        "sdk-build.memberDiff changed candidate digest mismatch")
        ids = member_diff.get("changedObjectIds")
        if ids is not None:
            require(sorted(ids) == expected_ids,
                    "sdk-build.memberDiff.changedObjectIds must be %r, got %r"
                    % (expected_ids, sorted(ids)))



    stamps = build.get("versionStamps")
    if stamps is not None:
        require(isinstance(stamps, list) and stamps,
                "sdk-build.versionStamps must be a non-empty array")
        stamp_ids = sorted(item.get("objectId") for item in stamps
                           if isinstance(item, dict))
        require(stamp_ids == expected_stamp_ids,
                "sdk-build.versionStamps must describe exactly %r, got %r"
                % (expected_stamp_ids, stamp_ids))
        real_by_id = {"m%03d" % item["ord"]: item for item in diff["changed"]}
        for item in stamps:
            require(isinstance(item, dict), "versionStamps entry must be an object")
            object_id_value = item.get("objectId")
            require(object_id_value in real_by_id,
                    "versionStamps entry %r is not a changed member"
                    % (object_id_value,))
            real = real_by_id[object_id_value]
            require(item.get("memberName") == real["name"],
                    "versionStamps memberName mismatch at %s" % object_id_value)
            require(item.get("memberOrdinal") == real["ord"],
                    "versionStamps memberOrdinal mismatch at %s" % object_id_value)
            require(item.get("beforeSha256") == real["baselineSha256"],
                    "versionStamps beforeSha256 mismatch at %s" % object_id_value)
            require(item.get("afterSha256") == real["candidateSha256"],
                    "versionStamps afterSha256 mismatch at %s" % object_id_value)
            reason = item.get("reason")
            require(isinstance(reason, str) and reason.strip(),
                    "versionStamps reason must be non-empty")
            require(item.get("isRepair") is False,
                    "versionStamps entry must not be marked as a repair")
        checks.append("sdk-build.versionStamps consistent (%s)" % ",".join(stamp_ids))

    bootstrap = build.get("bootstrap") or {}
    if isinstance(bootstrap, dict):
        require(bootstrap.get("changed") is False,
                "sdk-build.bootstrap.changed must be false for this build")
        reason = bootstrap.get("reason")
        require(isinstance(reason, str) and reason.strip(),
                "sdk-build.bootstrap.reason must be a non-empty string")

    repairs = build.get("repairs")
    if isinstance(repairs, list):
        ids = sorted(item.get("id") for item in repairs if isinstance(item, dict))
        require(ids == expected_repair_ids,
                "sdk-build.repairs must be exactly %r, got %r"
                % (expected_repair_ids, ids))
        for item in repairs:
            require(item.get("memberOrdinal") in (24, 29, 34),
                    "sdk-build.repairs.entry has unexpected memberOrdinal")
        for item in repairs:
            require(item.get("memberOrdinal") in (24, 29, 34),
                    "sdk-build.repairs.entry has unexpected memberOrdinal")
            require(isinstance(item.get("baselineSha256"), str)
                    and len(item["baselineSha256"]) == 64,
                    "sdk-build.repairs.entry baselineSha256 malformed")
            require(isinstance(item.get("newSha256"), str)
                    and len(item["newSha256"]) == 64,
                    "sdk-build.repairs.entry newSha256 malformed")
            require(item["baselineSha256"] != item["newSha256"],
                    "sdk-build.repairs.entry did not change: %s" % item.get("id"))


def main(argv):
    parser = argparse.ArgumentParser(
        prog="verify_sdk_member_diff.py",
        description="Independent recomputation gate for the Ultra SDK member diff.",
    )
    parser.add_argument("--baseline", required=True,
                        help="old production archive (libkernel_module_kit_static.a)")
    parser.add_argument("--candidate", required=True,
                        help="rebuilt archive to verify")
    parser.add_argument("--claim", default=None,
                        help="member-diff.json produced by the builder")
    parser.add_argument("--sdk-build", default=None,
                        help="sdk-build.json produced by the builder")
    parser.add_argument("--evidence-root", default=None,
                        help="root used to resolve relative sdk-build artifact paths")
    parser.add_argument("--expect-ordinals", default=DEFAULT_ORDINALS,
                        help="comma separated ordinals that must be the only changes")
    parser.add_argument("--expect-names", default=DEFAULT_NAMES,
                        help="comma separated member names that must change")
    parser.add_argument("--expect-repairs", default=DEFAULT_REPAIRS,
                        help="comma separated object ids that are repairs "
                             "(the remainder of the changed members are version stamps)")
    parser.add_argument("--json-out", default=None,
                        help="optional path for a machine readable report")
    parser.add_argument("--quiet", action="store_true", help="suppress PASS lines")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.baseline):
        raise UsageError("baseline archive not found: %s" % args.baseline)
    if not os.path.isfile(args.candidate):
        raise UsageError("candidate archive not found: %s" % args.candidate)
    expected_ordinals = expect_ordinals(args.expect_ordinals)
    expected_names = expect_names(args.expect_names)
    expected_ids = sorted("m%03d" % value for value in expected_ordinals)
    expected_repair_ids = sorted(part.strip() for part in args.expect_repairs.split(",")
                                 if part.strip())
    if not set(expected_repair_ids) <= set(expected_ids):
        raise UsageError("--expect-repairs must be a subset of --expect-ordinals")
    expected_stamp_ids = sorted(set(expected_ids) - set(expected_repair_ids))
    if len(expected_ordinals) != len(expected_names):
        raise UsageError("--expect-ordinals and --expect-names must have equal length")

    checks = []
    baseline = parse_ar(args.baseline)
    candidate = parse_ar(args.candidate)
    checks.append("parsed baseline members=%d candidate members=%d"
                  % (baseline["member_count"], candidate["member_count"]))

    # Ordinal order is part of the contract: fail before comparing contents.
    if baseline["member_count"] != candidate["member_count"]:
        raise GateError("member count changed: %d -> %d"
                        % (baseline["member_count"], candidate["member_count"]))

    diff, boot_member = check_archive_shape(
        baseline, candidate, expected_ordinals, expected_names, checks
    )

    # Ordinal-derived object ids, used by the evidence manifests.
    changed_ids = ["m%03d" % item["ord"] for item in diff["changed"]]
    checks.append("changed-object-ids %s" % ",".join(changed_ids))

    if args.claim:
        check_claim(args.claim, diff, baseline, candidate, boot_member, checks,
                    expected_ids)
    if args.sdk_build:
        check_sdk_build(args.sdk_build, diff, candidate, checks, expected_ids,
                        expected_repair_ids, expected_stamp_ids)

    report = {
        "schemaVersion": 1,
        "tool": "scripts/verify_sdk_member_diff.py",
        "baseline": {
            "path": os.path.abspath(args.baseline),
            "sha256": baseline["file_sha256"],
            "size": baseline["file_size"],
            "memberCount": baseline["member_count"],
        },
        "candidate": {
            "path": os.path.abspath(args.candidate),
            "sha256": candidate["file_sha256"],
            "size": candidate["file_size"],
            "memberCount": candidate["member_count"],
        },
        "changed": diff["changed"],
        "added": diff["added"],
        "removed": diff["removed"],
        "unchanged": diff["unchanged"],
        "changedObjectIds": changed_ids,
        "bootstrapMember": {
            "name": BOOTSTRAP_MEMBER,
            "ord": boot_member["ord"],
            "sha256": boot_member["sha256"],
        },
        "symbolIndex": candidate["symbol_index"],
        "result": "PASS",
        "checks": checks,
    }

    if args.json_out:
        directory = os.path.dirname(os.path.abspath(args.json_out))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, ensure_ascii=True, indent=2, sort_keys=False)
            handle.write("\n")

    if not args.quiet:
        for line in checks:
            sys.stdout.write("MEMBER-DIFF-CHECK %s\n" % line)
        for item in diff["changed"]:
            sys.stdout.write(
                "MEMBER-DIFF-CHANGED ord=%d %s %d->%d %s->%s\n"
                % (item["ord"], item["name"], item["baselineSize"],
                   item["candidateSize"], item["baselineSha256"][:16],
                   item["candidateSha256"][:16])
            )
        sys.stdout.write(
            "MEMBER-DIFF-PASS baseline=%s candidate=%s total=%d changed=%d "
            "added=0 removed=0 changedObjectIds=%s\n"
            % (baseline["file_sha256"][:16], candidate["file_sha256"][:16],
               candidate["member_count"], len(diff["changed"]),
               ",".join(changed_ids))
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except UsageError as error:
        sys.stderr.write("MEMBER-DIFF-USAGE: %s\n" % error)
        sys.exit(2)
    except GateError as error:
        sys.stderr.write("MEMBER-DIFF-FAIL: %s\n" % error)
        sys.exit(1)
    except SystemExit:
        raise
    except BaseException as error:  # noqa: BLE001 - internal error bucket
        sys.stderr.write("MEMBER-DIFF-INTERNAL: %s: %s\n"
                         % (type(error).__name__, error))
        sys.exit(3)
