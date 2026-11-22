#!/usr/bin/env python3
"""Structural guard for the provider traceless invariants.

Every rule below is a *code shape* that must exist for the corresponding
invariant recorded in contracts/detection-baseline.json.  The guard
runs the real derivation into a temporary directory, so it checks the code that
would actually be compiled - not just a comment somewhere.

  TR-1  snapshot before write + read-back verification + failure report
  TR-2  restore in reverse snapshot order
  TR-3  disarm proof published only after verification; the init re-entry guard is
        kept for the rest of the boot (removing it re-arms the hook and panics
        this kernel: DEV-88) and is cleared by the reboot
  TR-4  entry policy written back and read back, after the marker handshake
  TR-5  detached root executor is reaped
  TR-6  App waits for the native stage to exit before judging
  TR-9  every detection point has a verdict with evidence (no point left out)
  TR-11 the Root executor owns the lease after handover; only failures reap

Exit status is non-zero when any shape is missing; the build task treats that as
a hard failure so the cleanup cannot be dropped silently in a later edit.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CONSUMER = HERE / "lease" / "src" / "root_consumer.cpp"
BASELINE = HERE / "contracts" / "detection-baseline.json"

ALLOWED_VERDICTS = {"CLEAN", "WINDOW_ONLY", "PERSISTENT", "UNRESOLVED"}
REQUIRED_FIELDS = ("id", "name", "observation", "skrootBaseline", "maplesuJailbreak",
                   "evidence", "note")
# The detector exposes the KernelSU-traits card as this many sub-points; a list
# shorter than that cannot be complete.
MINIMUM_POINTS = 19

# (rule, needle, human description)
EXP_CHECKS = [
    ("TR-1", "struct RestoreRegion", "snapshot record"),
    ("TR-1", "snapshot_region(kCrashDump, 0, len, 0)", "helper region snapshotted before patching"),
    ("TR-1", "memcmp(check, region->orig, region->len) != 0", "read-back comparison"),
    ("TR-1", "restore: %s MISMATCH after write-back", "mismatch is reported"),
    ("TR-1", "maplesu-restore: failures=", "failure count published to the App"),
    ("TR-2", "for (int i = g_region_count - 1; i >= 0; --i)", "reverse-order restoration"),
    ("TR-3", "maplesu-disarmed", "disarm proof"),
    ("TR-3", "if (g_restore_failures == 0)", "disarm only after verified restoration"),
    ("TR-8", "is evict-only", "unreadable vendor page is declared, not faked"),
]

BOOTSTRAP_CHECKS = [
    # TR-12 (S09): every bootstrap failure after the transient owns a teardown.
    ("TR-12", "emergency_teardown", "bootstrap failure teardown"),
    ("TR-12", "maplesu-teardown", "teardown result readable by the App"),
    ("TR-12", "access(MAPLESU_DISARM", "disarm proof gates the guard removal"),
]

CONSUMER_CHECKS = [
    ("TR-3", "maplesu-disarmed", "waits for the disarm proof"),
    ("TR-3", "guard kept for this boot", "guard retained until reboot (DEV-88)"),
    ("TR-4", 'write_one_byte("/sys/fs/selinux/enforce"', "policy written back"),
    ("TR-4", "restore readback enforcing=", "policy read back"),
    ("TR-5", "reap_detached_executor", "detached root executor reaped"),
    ("TR-5", 'dev.maplesu.manager:root:', "reap identity is the package, not a wildcard"),
    ("TR-1", "evict_restored_pages", "page eviction after restoration"),
    ("TR-8", "shell exec domain u:r:shell:s0", "shell leaves the kernel domain"),
    # TR-11: the launcher exits on handover; only a failed attempt reaps.
    ("TR-11", "kHandoverFrame", "explicit handover frame"),
    ("TR-11", "if (!handed_over) {", "group kill and reap only without handover"),
    ("TR-11", "started < g_self_starttime", "reaper is scoped to this attempt"),
]


def derive(destination: pathlib.Path) -> str:
    subprocess.run(
        [sys.executable, "-X", "utf8", str(HERE / "dirtyfrag" / "derive.py"),
         "--output", str(destination)],
        check=True, capture_output=True, text=True,
    )
    exp = destination / "app" / "src" / "main" / "jni" / "exp.c"
    return exp.read_text(encoding="utf-8")


def check(text: str, table, label: str) -> list[str]:
    failures = []
    for rule, needle, description in table:
        if needle not in text:
            failures.append(f"{rule} {label}: missing {description!r} ({needle!r})")
    return failures


def order_checks(exp: str, consumer: str) -> list[str]:
    failures = []
    # TR-4: the enforce write must come after the marker handshake in the source.
    handshake = consumer.find("maplesu-disarmed")
    enforce = consumer.find('write_one_byte("/sys/fs/selinux/enforce"')
    if handshake < 0 or enforce < 0 or enforce < handshake:
        failures.append("TR-4 root_consumer.cpp: policy write-back must follow the disarm handshake")
    # TR-3 (updated 2026-10-28, DEV-88): the guard must NOT be removed. Removing it
    # re-arms init's one-shot hook, which re-runs insmod/dfroot_init inside the
    # restored window and panicked this kernel; keeping it is what the device run with
    # "keep-guard" proved safe. The consumer must say so explicitly and must not count
    # the guard as attempt residue.
    if consumer.find('unlink("/dev/df")') >= 0:
        failures.append("TR-3 root_consumer.cpp: /dev/df must be kept for the boot, not removed")
    if consumer.find("guard kept for this boot") < 0:
        failures.append("TR-3 root_consumer.cpp: the kept guard must be reported")
    # TR-2: the vendor write-back must not consume the helper region first.
    reverse = exp.find("for (int i = g_region_count - 1; i >= 0; --i)")
    if reverse < 0:
        failures.append("TR-2 exp.c: reverse-order restore loop missing")
    return failures


def baseline_checks() -> list[str]:
    """TR-9: the detection-point inventory must be complete and decided."""
    if not BASELINE.is_file():
        return [f"TR-9 baseline missing at {BASELINE}"]
    try:
        document = json.loads(BASELINE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        return [f"TR-9 baseline is not valid JSON: {error}"]
    points = document.get("points")
    if not isinstance(points, list):
        return ["TR-9 baseline has no points array"]
    failures = []
    if len(points) < MINIMUM_POINTS:
        failures.append(f"TR-9 baseline has {len(points)} points, "
                        f"fewer than the detector's {MINIMUM_POINTS}")
    seen = set()
    for index, point in enumerate(points):
        label = point.get("id") or f"#{index}"
        for field in REQUIRED_FIELDS:
            if field not in point or point[field] in (None, ""):
                if field == "note":
                    continue
                failures.append(f"TR-9 {label}: missing {field}")
        verdict = point.get("maplesuJailbreak")
        if verdict not in ALLOWED_VERDICTS:
            failures.append(f"TR-9 {label}: verdict {verdict!r} not in {sorted(ALLOWED_VERDICTS)}")
        if verdict in ("UNRESOLVED", "PERSISTENT") and not point.get("note"):
            failures.append(f"TR-9 {label}: {verdict} requires a note")
        identity = point.get("id")
        if identity in seen:
            failures.append(f"TR-9 duplicate point id {identity}")
        seen.add(identity)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="keep the derivation directory")
    arguments = parser.parse_args()

    if not CONSUMER.is_file():
        print(f"FAIL TR-*: consumer source missing at {CONSUMER}")
        return 2
    consumer = CONSUMER.read_text(encoding="utf-8")
    bootstrap = (HERE / "dirtyfrag" / "adapter" / "bootstrap.c").read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="maplesu-invariants-") as temporary:
        exp = derive(pathlib.Path(temporary))
        failures = check(exp, EXP_CHECKS, "exp.c") + check(consumer, CONSUMER_CHECKS, "consumer")
        failures += check(bootstrap, BOOTSTRAP_CHECKS, "bootstrap.c")
        failures += order_checks(exp, consumer)
        failures += baseline_checks()
        if failures:
            print("TRACELESS INVARIANTS VIOLATED")
            for failure in failures:
                print("  -", failure)
            return 1
        print(f"TRACELESS INVARIANTS OK checks="
              f"{len(EXP_CHECKS) + len(CONSUMER_CHECKS) + len(BOOTSTRAP_CHECKS) + 3} "
              f"points={MINIMUM_POINTS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
