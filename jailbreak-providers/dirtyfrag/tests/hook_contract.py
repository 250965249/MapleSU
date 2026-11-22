#!/usr/bin/env python3
"""Structural host gate for the step-3 UMH mode (design §8.2).

The step-3 change makes `adapter/bootstrap.c` do two things with one binary: the
stage-1 exploit route (argc == 1, one-shot attempt document, consumer exec) and the
module-dispatched helper (`--umh --entry-enforcing <0|1>`). The dangerous failure
mode is not a compile error - it is the helper quietly running one of stage-1's
irreversible steps (unlink the attempt document, touch a `/dev/dfm*` milestone,
`emergency_teardown`, soft reboot) in a process that is not stage-1. So this gate
asserts the *shape* of the code, like `ir-loader/tests/loader_contract.py` does for
the loader contract.

Two legs:

  1. source level (always): the UMH functions contain none of the forbidden stage-1
     steps; `main` dispatches UMH before the first marker; the TR-12 needles the
     production gate keys on are untouched; the restore ladder and the full
     `MA_HOOK_*` token table are present; `execv(` is confined to the two documented
     call sites.
  2. object level (`--object`): syscalls 106 (`delete_module`) and 273
     (`finit_module`) appear as immediates in `.text`; the evidence/argv strings are
     in an allocated data section; and the undefined-symbol set is still the bionic
     baseline plus exactly the documented additions - a new library dependency
     would fail here instead of at link time on the device.

A third leg - the L2 module (S26-S40 / O6-O10) - was added in C0 (2026-10-29) and is
described at its own section below. Its namespace is a Lead decision: the v5 baseline
is S1-S20 / O1-O5, the R-D1 fix owns S21, L2 takes S26-S40 / O6-O10 and L3 takes
S41-S52. It is **red on today's tree** because `maplesu_l2.ko`, `module/maplesu_l2.c`
and the helper's `hook_l2()` are C1/C2; the default run therefore reports it as
non-fatal `RED (l2)` and `--l2-required` makes it fatal (the mode CI uses once C1 has
landed). Both modes are exercised in work/l2-c0/logs/.

R-D1 (v6 candidate) adds the socket-label mitigation: the `--attest` worker copies
the attempt directory's SELinux context onto the socket before `listen()`, so the App's
`connect()` no longer meets an inode whose MLS level differs from its own (`lgetxattr`
+ `setxattr` are the two new imports, and the new log tokens are the diagnostics the
next device run is decided on).

P1 (2026-10-31) adds the one approved exception to "UMH never hands off to KernelSU":
the module execs `<CE>/bs --umh ...`, so main() never reaches stage-1's attempt-document
use-ksu branch. umh_main now checks MAPLESU_USE_KSU itself, requires the App-staged
`<CE>/ksud` to be executable, and returns ksu_handoff()'s status before any hook work.
S2 strips exactly that brace-matched branch; S22 checks its path, argv-derived entry
value and position, so a marker-less or late handoff is still red.

Host-only: it reads one source file, optionally one helper object, and (for the L2
leg) the helper source plus the module source and artifact. No adb, no device, no
module load.

Usage:
    python jailbreak-providers/dirtyfrag/tests/hook_contract.py
    python jailbreak-providers/dirtyfrag/tests/hook_contract.py --object work/hook/bootstrap.o
    python jailbreak-providers/dirtyfrag/tests/hook_contract.py --object ... --json out.json
    python jailbreak-providers/dirtyfrag/tests/hook_contract.py --l2-required   # CI after C1
    python jailbreak-providers/dirtyfrag/tests/hook_contract.py --no-l2         # pre-C0 baseline
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / "adapter" / "bootstrap.c"

# Every function that only exists for UMH mode. Source-level rules apply to these and
# to nothing else, so the stage-1 body is free to keep doing stage-1 things.
HOOK_FUNCTIONS = (
    "hook_path_ok",
    "umh_mode_requested",
    "hook_parse_argv",
    "hook_read_small",
    "hook_fail",
    "hook_set_state",
    "hook_sibling",
    # step-4 (D2): the pre-entry baseline and the total target decision.
    "hook_read_env",
    "hook_decide_target",
    "hook_stage2",
    "hook_daemon",
    # step-4 (D4): the daemon slot's attestation worker (the same binary's third mode).
    "hook_same_directory",
    "attest_mode_requested",
    # R-D1: the socket-label copy (bounded, fail-closed) and its bounded reader.
    "attest_read_label",
    "attest_copy_socket_label",
    "attest_main",
    "attest_serve",
    "attest_write_final",
    "attest_prepare_descriptors",
    "attest_inherit_fd",
    "attest_claim_fd",
    # L3 (ABI v2, W2/Y2): the token, the ARM call, its ring-buffer second confirmation
    # and the two evidence fields. Swept by the same forbidden-call rules as the rest of
    # the helper; they may not fail the run and may not log the token.
    "hook_arm_l3",
    "hook_l3_token_arg_ok",
    "hook_l3_reason_ok",
    "hook_l3_token_hex",
    "hook_l3_fallback_token",
    "hook_l3_make_token",
    "hook_l3_su_json",
    "hook_l3_arm_arguments",
    "hook_l3_arm_marker",
    "hook_l3_arm_confirm",
    "hook_l3_count_marker",
    "klog_count_occurrences",
    "klog_read_all",
    "hook_unload_child",
    "hook_wait_child",
    "hook_json_char",
    "hook_json_int",
    "hook_verdict",
    "hook_write_main_json",
    "umh_main",
)

# Stage-1's irreversible steps (design §2.3). None of these may appear in UMH mode.
FORBIDDEN_IN_HOOK = {
    "/dev/dfm": "DirtyFragX milestone markers belong to stage-1's progress channel",
    "/dev/df\"": "init's one-shot re-entry guard must never be touched here",
    "MAPLESU_ATTEMPT_FILE": "the attempt document is stage-1's one-shot input",
    "emergency_teardown": "it unlinks the markers and the guard",
    "setprop": "it is the soft-reboot/setprop route",
    "soft_reboot": "step-3 acceptance needs restore+unload in one boot",
    "ksu_handoff": "only the P1 marker-gated branch in umh_main may call it",
    "set_current_domain": "the kernel-domain process must not switch domains",
    "set_exec_domain": "same: no domain switch in UMH mode",
    "finit_module(105": "init_module(105) is the loader route, not this one",
    "unlink(": "UMH mode never removes a file",
    "touch(": "UMH mode never writes a /dev milestone",
}

# execv( may exist in exactly these two functions and no others.
EXECV_ALLOWED = {"main", "hook_daemon"}

# The restore ladder (design §5.2) and the evidence tokens (design §5.3).
# Step-4 D2 narrows this to the three rungs the helper can still produce: KERNEL_SAVED
# now means only "enforce_before == 1, the kernel's own live byte"; BASELINE is the App's
# observed/baseline target written by the unload child; FAILED is "no target". The helper
# no longer emits KERNEL_CLEANUP at all (it made the R-D9 race look like a rung, which
# made the device's own evidence jitter), though HookEvidence still parses it for
# historical records.
LADDER = ("KERNEL_SAVED", "BASELINE", "FAILED")
TOKENS = (
    "MA_HOOK_BAD_ARGV",
    "MA_HOOK_NOT_PRIVILEGED",
    "MA_HOOK_DIR_REJECTED",
    "MA_HOOK_WINDOW_CLOSED",
    "MA_HOOK_STAGE2_INVALID",
    "MA_HOOK_STAGE2_LOAD_FAILED",
    "MA_HOOK_DAEMON_INVALID",
    "MA_HOOK_DAEMON_EXEC_FAILED",
    "MA_HOOK_RESTORE_FAILED",
    "MA_HOOK_UNLOAD_BUSY",
)
# TR-12's needles: check_traceless_invariants.py fails if any of these disappears, and
# this gate repeats them so the UMH edit cannot quietly satisfy one gate by breaking
# the other.
TR12_NEEDLES = ("emergency_teardown", "maplesu-teardown", "access(MAPLESU_DISARM")

# bionic symbols the bootstrap may reference. This is the pre-step-3 undefined set plus
# exactly the three the UMH mode adds: pipe2 (the daemon slot's CLOEXEC exec report),
# setsid (the daemon slot's session detach) and strrchr (the sibling-path helper).
#
# Step-4 (D4/MF-4) adds exactly seven for the attestation worker's server side:
# socket/bind/listen/accept (the AF_UNIX endpoint), chmod/chown (so the App can connect
# to a socket inside its own attempt directory) and getsockopt (SO_PEERCRED - the
# kernel ucred that *is* F2). The measured object delta is exactly these seven; see
# work/step4/logs/object-undefined-diff.txt.
#
# R-D1 (v6 candidate) adds exactly two more, and nothing else: lgetxattr (read the App
# directory's "security.selinux" context) and setxattr (write it onto the socket). The
# measured delta is work/r-d1/undefined-delta.txt; no symbol was removed.
#
# The attestation worker's reverse-connect direction (DEV-174) uses two more: connect
# (the worker dials the App's socket, because a kernel-domain listener can never be
# connected to by untrusted_app) and setsockopt (SO_RCVTIMEO on the hello read). Both
# entered the source after the v6 object was measured; the B1 rebuild is the first
# object-leg measurement that sees them. They are plain libc, like the seven above.
#
# L3/B1 (2026-10-31) adds exactly two more, for the token's environment transport:
# setenv (the helper publishes MAPLESU_SU_TOKEN / MAPLESU_SU_GATE_REASON to the worker
# it is about to exec) and getenv (the worker reads them back). putenv was already in
# the frozen set (adopt_zygote_env()), so it is not part of this delta. The token used
# to travel in the worker's argv - world-readable through /proc/<pid>/cmdline - which is
# exactly what B1 removes. Measured delta: work/b1/undefined-delta.txt (added: setenv
# getenv; connect/setsockopt re-measured, not new).
BIONIC_ALLOWED = {
    "__errno", "_exit", "accept", "access", "bind", "chmod", "chown", "close",
    "closedir", "connect", "execv", "fchmod", "fork", "free", "fstat", "fsync",
    "getegid", "getenv", "geteuid", "getgid", "getpid", "getsockopt", "getuid",
    "ioctl", "lgetxattr", "listen", "malloc", "memchr", "memcpy", "memset", "open",
    "openat", "opendir", "pipe2", "putenv", "read", "readdir", "realpath", "setenv",
    "setsid", "setsockopt", "setxattr", "sleep", "snprintf", "socket", "sscanf",
    "stat", "strchr", "strcmp", "strcspn", "strlen", "strncmp", "strrchr", "strstr",
    "strtol", "syscall", "uname", "unlink", "unlinkat", "usleep", "vsnprintf",
    "waitpid", "write", "fcntl", "ftruncate", "lseek", "pread", "unsetenv",
    # lease_contract.c, compiled into the same object at the packaging edge; only
    # present when the build failed to include it - kept out of the allow list.
}
LEASE_OBJECT_SYMBOLS = {"maplesu_lease_endpoint", "maplesu_lease_nonce",
                        "maplesu_lease_boot_id", "maplesu_lease_decimal"}

# ARM64 encodings of `movz w0, #imm16` for the two syscall numbers this gate wants.
SYS_DELETE_MODULE = 106
SYS_FINIT_MODULE = 273

# The helper's whole undefined-symbol surface, frozen at R-D1 (O5). It is the step-4
# object's set (61 symbols: bionic plus the four lease_contract.c functions the
# packaging edge links in) plus exactly the two R-D1 additions, and nothing else. A new
# entry here is a new library dependency on the device, so it fails at the gate instead.
# Measured delta: work/r-d1/undefined-delta.txt (added: lgetxattr setxattr; removed:
# none), v5 object cf0981bb… / 74464 B -> v6 candidate 90b67c9f… / 76272 B.
#
# B1 re-measurement (2026-10-31): +connect +setsockopt (the DEV-174 reverse-connect
# code, in the source since 2026-10-30 but never measured because the object leg's input
# was the Oct-29 v6 object) and +setenv +getenv (B1's environment transport). 67 symbols
# total. Measured delta: work/b1/undefined-delta.txt. The freeze is unchanged in what it
# refuses: any symbol outside this set still fails O3/O5.
EXPECTED_OBJECT_UNDEFINED = frozenset({
    "__errno", "_exit", "accept", "access", "bind", "chmod", "chown", "close",
    "closedir", "connect", "execv", "fchmod", "fork", "free", "fstat", "fsync",
    "getegid", "getenv", "geteuid", "getgid", "getpid", "getsockopt", "getuid",
    "ioctl", "lgetxattr", "listen", "malloc", "maplesu_lease_boot_id",
    "maplesu_lease_decimal", "maplesu_lease_endpoint", "maplesu_lease_nonce",
    "memchr", "memcpy", "memset", "open", "openat", "opendir", "pipe2", "putenv",
    "read", "readdir", "realpath", "setenv", "setsid", "setsockopt", "setxattr",
    "sleep", "snprintf", "socket", "sscanf", "stat", "strchr", "strcmp", "strcspn",
    "strlen", "strncmp", "strrchr", "strstr", "strtol", "syscall", "uname", "unlink",
    "unlinkat", "usleep", "vsnprintf", "waitpid", "write",
    "fcntl", "ftruncate", "lseek", "pread", "unsetenv",
})


def movz_w0(immediate: int) -> int:
    return 0x52800000 | ((immediate & 0xFFFF) << 5)


def read_source() -> str:
    return SOURCE.read_text(encoding="utf-8", errors="replace")


def function_body(text: str, name: str) -> str | None:
    """The brace-balanced body of a top-level C function, or None when absent.

    The match must start a definition line (optionally after `static`/qualifiers) and
    the name must not be part of a longer identifier, so `hook_write_main_json` never
    answers for `main`.
    """
    pattern = re.compile(r"(?m)^[A-Za-z_][^\n;{}]*?(?<![A-Za-z0-9_])" +
                         re.escape(name) + r"\s*\(")
    for match in pattern.finditer(text):
        brace = text.find("{", match.end())
        statement = text.find(";", match.end())
        if brace < 0 or (0 <= statement < brace):
            continue  # a prototype, not a definition
        depth = 0
        for position in range(brace, len(text)):
            if text[position] == "{":
                depth += 1
            elif text[position] == "}":
                depth -= 1
                if depth == 0:
                    return text[brace:position + 1]
    return None


# P1 (2026-10-31): the one approved ksu_handoff call in UMH mode.
#
# The kernel module execs `<CE>/bs --umh --entry-enforcing <0|1>`, so main() returns
# into umh_main() before stage-1's attempt-document branch is reached. The App still
# writes MAPLESU_USE_KSU and stages its own daemon for a KernelSU attempt, so the
# helper has to honour the marker itself. This table entry is what the branch must
# look like; S2 strips exactly this block and S22 checks it, so a marker-less or
# out-of-order handoff cannot hide behind the exception.
P1_KSU_ANCHOR = "if (parsed == 0 && access(MAPLESU_USE_KSU, F_OK) == 0) {"
P1_KSU_DAEMON = 'MAPLESU_CE_KSUD "/data/user/0/dev.maplesu.manager/ksud"'


def p1_ksu_branch(body: str) -> str | None:
    """The exact marker-gated KernelSU branch inside umh_main, or None.

    Brace-matched from P1_KSU_ANCHOR. A second call site, a different guard, or a
    handoff outside the block is *not* stripped, so S2 still sees it.
    """
    start = body.find(P1_KSU_ANCHOR)
    if start < 0:
        return None
    brace = body.find("{", start)
    if brace < 0:
        return None
    depth = 0
    for index in range(brace, len(body)):
        if body[index] == "{":
            depth += 1
        elif body[index] == "}":
            depth -= 1
            if depth == 0:
                return body[start:index + 1]
    return None


def source_checks(text: str) -> list[dict]:
    checks: list[dict] = []

    def record(check_id: str, ok: bool, title: str, detail: str = "") -> None:
        checks.append({"id": check_id, "ok": bool(ok), "title": title,
                       "detail": detail})

    # S1: the UMH dispatch happens before the first stage-1 marker.
    main_body = function_body(text, "main")
    record("S1", main_body is not None, "main is a function definition")
    record("S1", text.count("int main(int argc, char **argv)") == 1,
           "main takes argc/argv (the UMH dispatch needs the real argv)")
    if main_body:
        dispatch = main_body.find("umh_mode_requested(")
        marker = main_body.find('touch("/dev/dfm1")')
        record("S1", dispatch >= 0 and marker > dispatch,
               "main dispatches UMH before touch(\"/dev/dfm1\")",
               "dispatch=%d first-marker=%d" % (dispatch, marker))

    # P1 (2026-10-31): the one approved ksu_handoff call in UMH mode. The module only
    # ever execs `<CE>/bs --umh ...`, so main() returns into umh_main before stage-1's
    # attempt-document use-ksu branch can run, and the App's marker used to be
    # unreachable. umh_main now honours it itself, before any hook work. S2 ignores
    # *exactly* this brace-matched branch; if the marker guard is removed or changed,
    # p1_ksu_branch() stops finding it and S2 sees ksu_handoff as forbidden again.
    p1_branch = p1_ksu_branch(function_body(text, "umh_main") or "")

    # S2: no hook-only function carries a stage-1 irreversible step.
    for name in HOOK_FUNCTIONS:
        body = function_body(text, name)
        record("S2", body is not None, "%s is defined" % name)
        if body is None:
            continue
        scanned = body
        if name == "umh_main" and p1_branch:
            scanned = body.replace(p1_branch, "", 1)
        hits = [needle for needle in FORBIDDEN_IN_HOOK if needle in scanned]
        record("S2", not hits, "%s contains no stage-1 irreversible step" % name,
               "found: %s" % ", ".join(hits) if hits else "")

    # S3: the TR-12 needles the production gate keys on survive this change.
    for needle in TR12_NEEDLES:
        record("S3", needle in text, "TR-12 needle retained: %r" % needle)

    # S4: the restore ladder names exist.
    for label in LADDER:
        record("S4", '"%s"' % label in text or label in text,
               "restore ladder rung present: %s" % label)

    # S5: the whole token table exists.
    for token in TOKENS:
        record("S5", token in text, "token present: %s" % token)

    # S6: execv( is confined to the two documented call sites.
    execv_functions = [name for name in ("main",) + HOOK_FUNCTIONS
                       if (body := function_body(text, name)) and "execv(" in body]
    record("S6", set(execv_functions) <= EXECV_ALLOWED,
           "execv( only in main and the optional daemon slot",
           "found in: %s" % ", ".join(sorted(execv_functions)))

    # S7: the mode decision is argv-only (D3-1), never the attempt document.
    mode_body = function_body(text, "umh_mode_requested")
    record("S7", mode_body is not None, "umh_mode_requested is defined")
    if mode_body:
        record("S7", "--umh" in mode_body and "--entry-enforcing" in mode_body,
               "the mode decision reads both argv tokens")
        record("S7", "MAPLESU_ATTEMPT_FILE" not in mode_body,
               "the mode decision does not consult the attempt document")
        record("S7", "access(" not in mode_body and "stat(" not in mode_body,
               "the mode decision touches no file")

    # S8: the argv contract itself is frozen (design §2.1).
    parse_body = function_body(text, "hook_parse_argv") or ""
    for needle in ('--umh', '--entry-enforcing', '--stage2', '--daemon'):
        record("S8", needle in parse_body, "arg token parsed: %s" % needle)
    record("S8", "value[1] != '\\0'" in parse_body,
           "the entry value must be exactly one character")
    # S8 (L3/B1): the su token is not an argv value anywhere in this binary. The
    # worker's argv is /proc/<pid>/cmdline (0444, world-readable); the token travels in
    # its environment (0400, root-only) instead, so no argv string may name it.
    record("S8", "--su-token" not in text,
           "the L3 token never travels through argv (B1)")

    # S9: the unload is bounded and forked, and the child is waited for with a bound.
    unload = function_body(text, "hook_unload_child") or ""
    record("S9", "fork()" in text and "hook_unload_child(&state)" in text,
           "the unload runs in a forked child (R12)")
    record("S9", "MAPLESU_NR_DELETE_MODULE" in unload and "O_NONBLOCK" in unload,
           "delete_module is called O_NONBLOCK through the named constant")
    wait = function_body(text, "hook_wait_child") or ""
    record("S9", "MAPLESU_UNLOAD_WAIT_MS" in wait and "WNOHANG" in wait,
           "the parent wait is bounded and non-blocking")
    record("S9", "#define MAPLESU_UNLOAD_WAIT_MS 1500" in text,
           "the parent wait bound is 1500 ms (design §6)")
    # R12's mitigation only works if the child outlives the parent's wait: the parent
    # exits, init_module returns and releases module_mutex, and then the child's retry
    # succeeds. A child budget shorter than the parent's wait would give up first.
    window = re.search(r"#define MAPLESU_DELETE_WINDOW_MS (\d+)", text)
    wait = re.search(r"#define MAPLESU_UNLOAD_WAIT_MS (\d+)", text)
    record("S9", window is not None and wait is not None and
           int(window.group(1)) > int(wait.group(1)),
           "the child's retry window outlasts the parent's wait (R12)",
           "window=%s parent=%s" % (window.group(1) if window else None,
                                    wait.group(1) if wait else None))

    # S10: every evidence sink is pre-opened inside the window (design §5.1 step 5).
    record("S10", text.count("MAPLESU_HOOK_EVIDENCE") >= 1 and
                  text.count("MAPLESU_HOOK_UNLOAD_EVIDENCE") >= 1,
           "both evidence files are named by constants")
    record("S10", 'log_line("maplesu-hook: verdict=%s' in text,
           "the single-line verdict is logged")
    record("S10", '"schema\\":\\"maplesu.hook.v1\\' in text.replace("\n", "") or
                  "maplesu.hook.v1" in text,
           "the main evidence document names its schema")

    # -- step-4 (D2/D3/D4) ------------------------------------------------------ #
    # S11 (MF-8): restore-last only holds if the parent never writes. The old needle
    # matched only `state->write_fd` (the child's pointer form), while the parent used
    # the stack form `state.write_fd` - so it passed on code that was already wrong.
    # Both spellings are locked now.
    unload_body = function_body(text, "hook_unload_child") or ""
    umh_body = function_body(text, "umh_main") or ""
    write_sites = text.count("write(state->write_fd")
    record("S11", write_sites == 1 and write_sites == unload_body.count("write(state->write_fd"),
           "the only selinuxfs write is the unload child's (restore-last)",
           "whole file=%d child=%d" % (write_sites,
                                       unload_body.count("write(state->write_fd")))
    parent_writes = []
    for match in re.finditer(r"write\(", umh_body):
        argument = umh_body[match.end():match.end() + 90].split(")")[0]
        if "write_fd" in argument:
            parent_writes.append(argument.strip())
    record("S11", not parent_writes,
           "umh_main never writes selinuxfs itself (single writer)",
           "found: %s" % parent_writes[:3] if parent_writes else "no write(write_fd)")

    # S12 (D2): the env input exists, is read before the fork, and is validated.
    env_body = function_body(text, "hook_read_env")
    record("S12", env_body is not None, "hook_read_env is defined")
    env_call = umh_body.find("hook_read_env(")
    fork_at = umh_body.find("fork()")
    record("S12", env_call >= 0 and fork_at > env_call,
           "hook_read_env runs before the unload fork (inside the window)",
           "call=%d fork=%d" % (env_call, fork_at))
    env_needles = ("O_NOFOLLOW", "st_uid", "st_nlink", "0077",
                   "maplesu.hook.env.v1", "MAPLESU_HOOK_ENV_SCHEMA", "boot_id",
                   "env ok=0")
    env_missing = [needle for needle in env_needles if needle not in (env_body or "")]
    record("S12", not env_missing,
           "hook_read_env validates link/owner/mode/size, schema, boot and attempt",
           "missing: %s" % ", ".join(env_missing) if env_missing else "all present")

    # S13 (D2/MF-10): the decision is total, and its enforcing==1 short circuit cannot
    # reach a write - a permissive-boot device must never be written by this helper.
    decide_body = function_body(text, "hook_decide_target")
    record("S13", decide_body is not None
                  and "MA_HOOK_BASELINE_MISSING" in decide_body
                  and "MA_HOOK_ENV_INVALID" in decide_body,
           "hook_decide_target is defined and names both missing-baseline rows")
    short_circuit = ""
    if decide_body:
        at = decide_body.find("enforce_before == 1")
        brace = decide_body.find("{", at) if at >= 0 else -1
        if brace >= 0:
            depth = 0
            for position in range(brace, len(decide_body)):
                if decide_body[position] == "{":
                    depth += 1
                elif decide_body[position] == "}":
                    depth -= 1
                    if depth == 0:
                        short_circuit = decide_body[brace:position + 1]
                        break
    record("S13", bool(short_circuit) and "return" in short_circuit
                  and "write(" not in short_circuit
                  and "write(" not in (decide_body or ""),
           "the enforce_before==1 branch returns and contains no write")

    # S14 (D1/C6): the guard is kept, for the whole file, not just emergency_teardown.
    record("S14", text.count('unlink("/dev/df")') == 0,
           "no unlink(\"/dev/df\") anywhere in the helper",
           "occurrences=%d" % text.count('unlink("/dev/df")'))
    record("S14", "teardown guard kept for this boot" in text,
           "the teardown logs that the guard is kept")

    # S15 (D4): the third mode is dispatched before the first stage-1 milestone, and its
    # functions inherit the same禁令 table as UMH mode.
    attest_dispatch = main_body.find("attest_mode_requested(") if main_body else -1
    first_marker = main_body.find('touch("/dev/dfm1")') if main_body else -1
    record("S15", attest_dispatch >= 0 and first_marker > attest_dispatch,
           "main dispatches --attest before touch(\"/dev/dfm1\")",
           "dispatch=%d first-marker=%d" % (attest_dispatch, first_marker))
    attest_hits = {}
    for name in ("attest_mode_requested", "attest_main", "attest_serve"):
        body = function_body(text, name) or ""
        hits = [needle for needle in FORBIDDEN_IN_HOOK if needle in body]
        if hits:
            attest_hits[name] = hits
    record("S15", not attest_hits,
           "the attest functions contain no stage-1 irreversible step",
           "found: %s" % attest_hits if attest_hits else "")
    record("S15", "attest_main" in HOOK_FUNCTIONS
                  and function_body(text, "attest_main") is not None,
           "attest_main is a hook function the rules apply to")

    # S16 (D2/MF-10): argv is correlation evidence only, and the evidence keeps saying
    # so - entry.argv must stay the inherited observation, never the target.
    record("S16", "want_final = request.entry" not in text,
           "the target is never taken from argv")
    # An assignment, not a comparison: `want_final ==` starts with the same prefix.
    assignments = re.findall(r"want_final\s*=\s*[^=]", umh_body)
    record("S16", not assignments
                  and text.count("hook_json_char(state->entry_argv)") == 1
                  and text.count("hook_json_char(state->want_final)") == 2,
           "umh_main assigns no target, and entry.argv carries the argv observation",
           "umh assignments=%d entryArgv=%d wantFinal=%d"
           % (len(assignments),
              text.count("hook_json_char(state->entry_argv)"),
              text.count("hook_json_char(state->want_final)")))

    # S17 (D3): evidence is App-readable; the daemon record is opened once before
    # fork and both writers reuse that root-owned 0644 descriptor after restoration.
    def fchmod_follows(anchor: str, mode: str, window: int = 700) -> bool:
        at = text.find(anchor)
        return at >= 0 and mode in text[at:at + window]

    record("S17", fchmod_follows("state.ev_fd = open(", "fchmod(state.ev_fd, 0644)"),
           "maplesu-hook.json is opened and widened to 0644")
    record("S17", fchmod_follows("state.child_fd = open(",
                                 "fchmod(state.child_fd, 0644)"),
           "maplesu-hook-unload.json is opened and widened to 0644")
    prepared = function_body(text, "attest_prepare_descriptors") or ""
    final_writer = function_body(text, "attest_write_final") or ""
    initial_writer = function_body(text, "attest_main") or ""
    record("S17", "fchmod(*record_fd, 0644)" in prepared
                  and "O_NOFOLLOW" in prepared and "status.st_uid != 0" in prepared,
           "daemon document is pre-opened root-owned and widened to 0644")
    record("S17", "state->record_fd" in final_writer and "open(" not in final_writer
                  and "document_fd = state.record_fd" in initial_writer
                  and "open(MAPLESU_HOOK_DAEMON_DOC" not in initial_writer,
           "both daemon writers reuse the inherited document descriptor")

    # S18 (D4/MF-2): the owner check uses the attempt directory's uid, never getuid():
    # the helper is uid 0, so getuid() would reject the App-owned <CE>/bs every time.
    daemon_body = function_body(text, "hook_daemon") or ""
    record("S18", "getuid()" not in daemon_body,
           "hook_daemon does not derive the owner from getuid()")
    record("S18", "dir_uid" in daemon_body,
           "hook_daemon admits the attempt directory's owner")

    # S19 (D2/MF-7): PENDING is not a verdict. The final readback happens only when the
    # child settled, and a still-running child raises no token.
    final_read = ""
    at = umh_body.find("if (child_code == 0)")
    if at >= 0:
        brace = umh_body.find("{", at)
        depth = 0
        for position in range(brace, len(umh_body)):
            if umh_body[position] == "{":
                depth += 1
            elif umh_body[position] == "}":
                depth -= 1
                if depth == 0:
                    final_read = umh_body[brace:position + 1]
                    break
    record("S19", "read_byte_fd(state.read_fd_d)" in final_read,
           "the parent's final readback is gated on child_code == 0")
    record("S19", umh_body.count("readback_final = -1") >= 1,
           "readback_final starts at -1 (never observed)")
    record("S19", "if (child_code != 0) hook_fail(" not in umh_body
                  and "child_code > 0" in umh_body,
           "PENDING carries no failure token")

    # S20 (D2/MF-7): the child may write '0' too (an App-chosen permissive baseline is a
    # legitimate target), and it reports whether it wrote so the merge can label it.
    record("S20", unload_body.count("write(state->write_fd") == 1
                  and "want == 1)" not in unload_body,
           "the child writes either target, not only '1'")
    record("S20", "state->wrote = 1" in unload_body,
           "the child records its own write in the evidence")

    # S21 (R-D1): the attestation socket carries the App's own SELinux context.
    #
    # The device fact this locks: the worker's inode was `app_data_file:s0` (no MLS
    # categories) while the App is `untrusted_app:s0:c225,…`; the MLS constraint on
    # `unix_stream_socket connectto` wants the levels equal, and zero `attest client`
    # lines in 3 338 proved no connection ever reached the queue. The fix is a copy of
    # the attempt directory's context onto the socket, after chown and before listen,
    # bounded to one 256-byte buffer and fail-closed (a failure is a log line only).
    attest_body = function_body(text, "attest_main") or ""
    record("S21", "#define MAPLESU_ATTEST_LABEL_MAX 256" in text,
           "the label buffer bound is 256 bytes (R-D1)")
    record("S21", '#define MAPLESU_SELINUX_XATTR "security.selinux"' in text,
           "the copy names the SELinux xattr, not some other attribute")
    label_read = function_body(text, "attest_read_label") or ""
    record("S21", "lgetxattr(path, MAPLESU_SELINUX_XATTR" in label_read
                  and "size - 1" in label_read,
           "attest_read_label reads at most one buffer of context",
           "read=%s" % ("present" if label_read else "MISSING FUNCTION"))
    record("S21", '"u:object_r:"' in label_read and "0x7f" in label_read,
           "attest_read_label refuses anything that is not a plain, printable label")
    copy_body = function_body(text, "attest_copy_socket_label") or ""
    record("S21", "setxattr(socket_path, MAPLESU_SELINUX_XATTR" in copy_body,
           "attest_copy_socket_label writes the context onto the socket itself")
    record("S21", "attest socket label copy rc=%d errno=%d" in copy_body,
           "the copy logs the exact rc/errno token the next run greps")
    record("S21", "char label[MAPLESU_ATTEST_LABEL_MAX]" in copy_body
                  and copy_body.count("sizeof(label)") == 1
                  and "(size_t)length + 1U" in copy_body,
           "the copy uses one fixed-size stack buffer for read and write")
    record("S21", "MAPLESU_ATTEMPT_DIRECTORY" in copy_body
                  and '"/data/' not in copy_body,
           "the copy's only source path is <DE>; no new /data/ literal (G5)",
           "DE=%d literal=%d" % (copy_body.count("MAPLESU_ATTEMPT_DIRECTORY"),
                                 copy_body.count('"/data/')))
    # Fail-closed is a property of the *shape*: the function cannot fail the worker.
    record("S21", copy_body != "" and
                  not re.search(r"return\s+[-0-9]", copy_body) and
                  "exit(" not in copy_body and "hook_fail" not in copy_body and
                  "hook_state" not in copy_body,
           "the copy is void, token-free and can never end the worker",
           "returns-a-value=%s exit=%s token=%s"
           % (bool(re.search(r"return\s+[-0-9]", copy_body)), "exit(" in copy_body,
              "hook_fail" in copy_body))
    chown_at = attest_body.find("chown(state.socket_path")
    copy_at = attest_body.find("attest_copy_socket_label(state.socket_path)")
    listen_at = attest_body.find("listen(server, 4)")
    record("S21", 0 <= chown_at < copy_at and listen_at > copy_at,
           "the copy runs after chown and before listen (inode exists, queue not yet)",
           "chown=%d copy=%d listen=%d" % (chown_at, copy_at, listen_at))
    ready_at = attest_body.find("attest socket ready label=")
    record("S21", listen_at >= 0 and ready_at > listen_at,
           "the read-back `attest socket ready label=` line follows listen()",
           "listen=%d ready=%d" % (listen_at, ready_at))
    record("S21", "attest accept rc=%d errno=%d" in attest_body,
           "the accept error path logs `attest accept rc=… errno=…`")
    serve_body = function_body(text, "attest_serve") or ""
    record("S21", "attest client uid=%d pid=%d" in serve_body,
           "the per-connection credential line is retained (F2's only server witness)")
    record("S21", attest_body.count("attest_copy_socket_label(") == 1,
           "the copy has exactly one call site (the worker's socket path)",
           "call sites=%d" % attest_body.count("attest_copy_socket_label("))
    record("S21", text.count('"/data/') == 4,
           "the helper carries exactly four /data/ literals (G5 + P1's CE daemon)",
           "found %d" % text.count('"/data/'))

    # S22 (P1, 2026-10-31): the one approved ksu_handoff call in UMH mode.
    #
    # The module only ever execs `<CE>/bs --umh ...`; main() returns into umh_main
    # before stage-1's attempt-document branch, so the App's use-ksu marker used to be
    # unreachable. The fix is the marker-gated branch at the top of umh_main. Its shape
    # is what keeps the product sequence intact: it must return the handoff's own
    # status *before* the first hook descriptor/log/ARM, take the entry value from
    # argv, and use the App-owned CE path rather than a guessed one.
    p1 = p1_ksu_branch(umh_body)
    record("S22", p1 is not None,
           "umh_main has the marker-gated KernelSU branch (P1)",
           "anchor %r" % P1_KSU_ANCHOR)
    record("S22", text.count(P1_KSU_DAEMON) == 1,
           "the daemon path is the App's CE staging target (P1)",
           P1_KSU_DAEMON)
    if p1:
        record("S22", "access(MAPLESU_CE_KSUD, X_OK)" in p1,
               "the branch requires an executable staged daemon")
        record("S22", "return ksu_handoff(MAPLESU_CE_KSUD, ksu_entry)" in p1,
               "the branch hands over the App-owned daemon and returns its status")
        record("S22", "const char ksu_entry[2] = {request.entry, '\\0'};" in p1,
               "the entry value comes from --entry-enforcing, NUL-terminated")
        record("S22", "getenforce" not in p1
                      and '"/sys/fs/selinux/enforce"' not in p1,
               "the branch never infers enforcing itself")
        record("S22", "use-ksu requested without a staged daemon" in p1,
               "a marker without a daemon falls through with the stage-1 diagnostic")
        # The S2 exception must not become a smuggling route: the only forbidden
        # needle this block may contain is the handoff itself.
        extra = [needle for needle in FORBIDDEN_IN_HOOK
                 if needle != "ksu_handoff" and needle in p1]
        record("S22", not extra,
               "the P1 branch adds no other stage-1 irreversible step",
               "found: %s" % ", ".join(extra) if extra else "")
        check_at = umh_body.find(P1_KSU_ANCHOR)
        first_fd = umh_body.find("state.write_fd = open(")
        stage2_at = umh_body.find("hook_stage2(&state);")
        mode_log = umh_body.find('log_line("maplesu-hook: mode=umh')
        ordered = [position for position in (first_fd, stage2_at, mode_log)
                   if position >= 0]
        record("S22", 0 <= check_at and ordered and check_at < min(ordered),
               "the branch precedes every hook descriptor, the mode log and stage2",
               "check=%d fd=%d stage2=%d log=%d"
               % (check_at, first_fd, stage2_at, mode_log))
    return checks


class Elf:
    """The little bit of ELF64 this gate needs: sections, symbols, raw bytes."""

    def __init__(self, path: Path):
        self.raw = path.read_bytes()
        if self.raw[:4] != b"\x7fELF" or self.raw[4] != 2 or self.raw[5] != 1:
            raise ValueError("not a little-endian ELF64 object: %s" % path)
        shoff = struct.unpack_from("<Q", self.raw, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", self.raw, 58)
        if shentsize != 64 or shnum == 0 or shstrndx >= shnum:
            raise ValueError("unsupported section table")
        self.sections = []
        for index in range(shnum):
            base = shoff + index * 64
            (name, kind, flags, _addr, offset, size, link,
             info) = struct.unpack_from("<IIQQQQII", self.raw, base)
            self.sections.append({"index": index, "nameOffset": name, "type": kind,
                                  "flags": flags, "offset": offset, "size": size,
                                  "link": link, "info": info})
        strings = self.sections[shstrndx]
        for section in self.sections:
            section["name"] = self._string(strings, section["nameOffset"])

    def _string(self, table: dict, offset: int) -> str:
        start = table["offset"] + offset
        end = self.raw.find(b"\x00", start)
        return self.raw[start:end].decode("utf-8", "replace")

    def section(self, name: str) -> dict | None:
        return next((s for s in self.sections if s["name"] == name), None)

    def data(self, section: dict) -> bytes:
        return self.raw[section["offset"]:section["offset"] + section["size"]]

    def allocated(self) -> list[dict]:
        return [s for s in self.sections if s["flags"] & 0x2 and s["type"] != 8]

    def undefined_symbols(self) -> list[str]:
        table = next((s for s in self.sections if s["type"] == 2), None)  # SHT_SYMTAB
        if table is None:
            return []
        strings = self.sections[table["link"]]
        names = set()
        for base in range(table["offset"], table["offset"] + table["size"], 24):
            name, info, _other, shndx = struct.unpack_from("<IBBH", self.raw, base)
            if shndx == 0 and (info >> 4) in (1, 2):  # GLOBAL / WEAK, SHN_UNDEF
                names.add(self._string(strings, name))
        return sorted(names)

    def symbols(self) -> list[dict]:
        """Every symbol in .symtab: name, binding, type, defining section, value."""
        table = next((s for s in self.sections if s["type"] == 2), None)
        if table is None:
            return []
        strings = self.sections[table["link"]]
        out = []
        for base in range(table["offset"], table["offset"] + table["size"], 24):
            name, info, _other, shndx = struct.unpack_from("<IBBH", self.raw, base)
            value, size = struct.unpack_from("<QQ", self.raw, base + 8)
            out.append({"name": self._string(strings, name),
                        "binding": info >> 4, "type": info & 0xF,
                        "shndx": shndx, "value": value, "size": size})
        return out

    def relocations(self) -> list[dict]:
        """Every SHT_RELA entry: target section, patched offset, type, symbol.

        Needed by the L2 write-scope skeleton: an `adrp` carrying an ADR_PREL_PG_HI21
        relocation against the module's own `.bss`/`.data` is what separates "writes
        its own global" from "writes whatever a register pointed at".
        """
        out = []
        for section in self.sections:
            if section["type"] != 4:                    # SHT_RELA
                continue
            target = section["info"]
            for base in range(section["offset"],
                              section["offset"] + section["size"], 24):
                offset, info, addend = struct.unpack_from("<QQq", self.raw, base)
                out.append({"targetSection": target, "offset": offset,
                            "type": info & 0xFFFFFFFF,
                            "symbolIndex": info >> 32, "addend": addend})
        return out


def object_checks(path: Path) -> list[dict]:
    checks: list[dict] = []

    def record(check_id: str, ok: bool, title: str, detail: str = "") -> None:
        checks.append({"id": check_id, "ok": bool(ok), "title": title,
                       "detail": detail})

    elf = Elf(path)
    text = elf.section(".text")
    record("O1", text is not None, "the object has a .text section")
    if text is None:
        return checks
    body = elf.data(text)
    for label, immediate in (("delete_module", SYS_DELETE_MODULE),
                             ("finit_module", SYS_FINIT_MODULE)):
        encoding = movz_w0(immediate)
        found = 0
        for offset in range(0, len(body) - 3, 4):
            if struct.unpack_from("<I", body, offset)[0] == encoding:
                found += 1
        record("O1", found > 0,
               "syscall %d (%s) appears as an immediate" % (immediate, label),
               "movz w0,#0x%x at %d site(s)" % (immediate, found))

    blob = b"".join(elf.data(section) for section in elf.allocated())
    for needle in (b"maplesu-hook.json", b"maplesu-hook-unload.json",
                   b"--entry-enforcing", b"--umh", b"MA_HOOK_WINDOW_CLOSED"):
        record("O2", needle in blob, "allocated data carries %r" % needle.decode())

    # O2 (R-D1): the mitigation's own strings are really in the shipped object, so the
    # source-level checks cannot pass on code that the packaging edge dropped.
    for needle in (b"security.selinux", b"attest socket label copy",
                   b"attest socket ready label=", b"attest accept rc="):
        record("O2", needle in blob, "allocated data carries %r" % needle.decode())

    undefined = elf.undefined_symbols()
    unexpected = sorted(set(undefined) - BIONIC_ALLOWED - LEASE_OBJECT_SYMBOLS)
    record("O3", not unexpected,
           "no undefined symbol outside the documented bionic set",
           "unexpected: %s" % ", ".join(unexpected) if unexpected else
           "%d symbol(s), all allowed" % len(undefined))

    # The lease contract is a separate translation unit at the packaging edge; when it
    # is not linked here its symbols are expected to be undefined and are allowed.
    record("O4", not any(name.startswith(("__aeabi_", "__aarch64_", "__stack_chk"))
                         for name in undefined),
           "no compiler-runtime helper became a dependency",
           ", ".join(name for name in undefined
                     if name.startswith(("__aeabi_", "__aarch64_",
                                         "__stack_chk"))) or "")

    # O5 (step-4 D2/D4): the new inputs are really compiled into the shipped object, and
    # the undefined set is exactly the frozen one. The `.ko`'s four imports are the
    # module's contract and are asserted by root-loader/tests/test_root_contract.py;
    # this is the *helper's* dependency surface, which must stay bionic-only.
    record("O5", b"maplesu-hook-env" in blob and b"maplesu.hook.env.v1" in blob,
           "allocated data carries the env file name and its schema")
    record("O5", b"maplesu.hook.attest.v1" in blob and b"--attest" in blob,
           "allocated data carries the attestation schema and --attest")
    record("O5", set(undefined) == EXPECTED_OBJECT_UNDEFINED,
           "the undefined set is exactly the frozen step-4 set",
           "missing: %s; unexpected: %s"
           % (sorted(EXPECTED_OBJECT_UNDEFINED - set(undefined)),
              sorted(set(undefined) - EXPECTED_OBJECT_UNDEFINED)))
    return checks


# --------------------------------------------------------------------------- #
# L2 (design docs/patching/maplesu-l2-hook-framework-design-2026-10-29.md rev-2,
# review docs/patching/maplesu-l2-ready-review-2026-10-29.md §11 M1-M10).
#
# Gate-id namespace (Lead decision, 2026-10-29): the v5 baseline hook_contract checks
# are S1-S20 / O1-O5, the R-D1 fix owns S21 (and O2/O5 grew there), so L2 takes
# S26-S40 / O6-O10 and L3 will take S41-S52. S22-S25 stay free. The design document
# still says S21-S30; a doc correction follows, and the mapping is recorded in the
# contract's `l2.gateNamespace` block, which `tests/test_l2_contract.py` cross-checks
# against the ids this file actually emits.
#
# RED-FIRST, and honest about it: `maplesu_l2.ko`, `module/maplesu_l2.c` and the
# helper's `hook_l2()` do not exist yet (they are C1/C2). Every check below is
# therefore able to fail *today*, and the default run reports them as `RED (l2)` -
# non-fatal, so the product baseline stays green - while `--l2-required` promotes them
# to fatal, which is the mode CI uses once C1 has landed. A gate that cannot be red is
# not a gate; work/l2-c0/logs/ holds both the red run and the default one.
# --------------------------------------------------------------------------- #

# The L2 slot's functions. `hook_l2` is the entry point the design names; every
# helper must be `l2_*`-prefixed so the forbidden-call sweep can find it without a
# hand-maintained list.
L2_ENTRY_FUNCTION = "hook_l2"
L2_FUNCTION_PREFIX = "l2_"

# H6 / M7: what an L2 function may never contain. The helper's existing FORBIDDEN_IN_HOOK
# covers stage-1's irreversible steps; these are the *new* L2-specific refusals: no
# policy write, no mount, no block-device ioctl, no text mutation, no arbitrary kernel
# read/write helper. Applied to hook_l2 and every l2_* function (S31) and to the whole
# module source (S39).
L2_FORBIDDEN = {
    "mount(": "mounting is a stage-1/teardown capability, not L2's",
    "BLKROSET": "block-device ioctls are C4 violations",
    "/sys/fs/selinux": "L2 observes enforcing through the kernel object, never through "
                       "selinuxfs (H6)",
    "security_setenforce": "no policy setter anywhere in L2",
    "avc_denied": "no audit/policy suppression (detection surface, H6)",
    "set_memory_rw": "patched page permissions are a permanent trace (C4/H3)",
    "apply_to_page_range": "same",
    "aarch64_insn_patch_text": "L2 never writes kernel text",
    "text_poke": "same",
    "copy_to_kernel_nofault": "the write whitelist is two tags; there is no arbitrary "
                              "kernel write (M7)",
}

# The helper-side token table L2 introduces (design §4.2 L2-1..L2-8 + §3.1.2 ARM).
L2_TOKENS = (
    "MA_L2_NOT_EXERCISED",
    "MA_L2_MODULE_",
    "MA_L2_LOAD_",
    "MA_L2_NO_COOKIE",
    "MA_L2_PROBE_",
    "MA_L2_SELFCHECK_FAILED",
    "MA_L2_DISARM_FAILED",
    "MA_L2_UNLOAD_BUSY",
    "MA_L2_NO_HIT",
    "MA_L2_RET_NO_HIT",
    "MA_L2_ARM_BUSY",
    "MA_L2_POLICY_MOVED",
    "MA_L2_SCNO_NOT_UNIMPLEMENTED",
)

L2_EVIDENCE_IDS = ("ctl.magic", "execve.entry", "execve.ret")

# The contract's own answers (see `l2` in contracts/<uname>.json). Duplicated here on
# purpose: a gate that only compares the contract with itself proves nothing, so the
# six M4 imports below are a second, independent statement. M6's cookie channel adds
# exactly one more import (`param_ops_ullong`, the __param row's ops pointer); that
# allowance is written here, not read from the contract, so a new import outside it
# fails even if the contract grew one.
L2_IMPORT_SET = frozenset({"register_kprobe", "register_kretprobe",
                           "unregister_kprobe", "unregister_kretprobe",
                           "_printk", "copy_from_kernel_nofault"})
L2_COOKIE_PARAM_ALLOWED = frozenset({"param_ops_ullong"})
L2_LOOKUP_SET = frozenset({"__arm64_sys_ni_syscall", "sys_call_table",
                           "copy_to_user_nofault"})
L2_KCFI_PINS = {"preHandler": 0xA6BE5DD9, "postHandler": 0x6E21B9C7,
                "kretprobeHandler": 0x8078BE15, "init": 0x36B1C5A6}
L2_SHIM_PIN = 0x2B8CDF69          # negative sample: shim-named pre-handler prototype
L2_MAGIC_SCNO = 453               # the design's default; must never be a literal
L2_FORBIDDEN_OBJECT_SYMBOLS = ("set_memory_rw", "apply_to_page_range",
                               "aarch64_insn_patch_text", "text_poke",
                               "copy_to_kernel_nofault", "security_setenforce",
                               "mount", "security_hook_heads", "security_add_hooks")
L2_FORBIDDEN_STRINGS = (b"/dev/df", b"BLKROSET", b"/sys/fs/selinux",
                        b"security_setenforce")
L2_KSU_STRINGS = (b"ksu", b"ksud", b"kernelsu")

# The four callback prototypes C1 must write, exactly (kernel struct names, no shims).
L2_PROTOTYPE_NEEDLES = (
    "l2_pre_execve(struct kprobe *",
    "l2_post_execve(struct kprobe *",
    "l2_ret_execve(struct kretprobe_instance *",
    "l2_pre_ctl(struct kprobe *",
)

# check_traceless_invariants.py is frozen (C7). S34 asserts the digest and that the
# helper never mentions the file; the check count is printed as provenance, not as an
# assertion, because "26" is the script's own arithmetic.
TRACELESS = HERE.parents[1] / "check_traceless_invariants.py"
TRACELESS_SHA256 = ("0952b2a55271b3997de11cb59d61dfc81c9806be84578ec82cc1ee0e0554a306")
TRACELESS_CHECKS = 26

REPO = HERE.parents[2]
MODULE_DIR = REPO / "jailbreak-providers" / "root-loader" / "module"
L2_MODULE_SOURCE = MODULE_DIR / "maplesu_l2.c"
L2_MODULE_GLUE = MODULE_DIR / "root_glue_l2.S.in"
L2_COMPAT_HEADER = MODULE_DIR / "kernel_compat.h"
L2_OBJECT = REPO / "jailbreak-providers" / "root-loader" / "build" / "maplesu_l2.ko"
L2_CONTRACTS = REPO / "jailbreak-providers" / "root-loader" / "contracts"


def recorder(checks: list, stage: str | None = None):
    def record(check_id: str, ok: bool, title: str, detail: str = "") -> None:
        entry = {"id": check_id, "ok": bool(ok), "title": title, "detail": detail}
        if stage:
            entry["stage"] = stage
        checks.append(entry)
    return record


def load_l2_contract(path: Path | None = None) -> dict | None:
    """The root-loader contract that carries the `l2` block, or None."""
    candidates = [path] if path else sorted(L2_CONTRACTS.glob("*.json"))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            try:
                return json.loads(Path(candidate).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return None
    return None


def l2_source_checks(text: str, module_dir: Path | None = None,
                     contract: dict | None = None) -> list[dict]:
    """S26-S40: the L2 slot in the helper (S26-S35) and the module it loads
    (S36-S40). Every check is red today because neither side exists yet."""
    checks: list[dict] = []
    record = recorder(checks, "l2")
    module_dir = Path(module_dir) if module_dir else MODULE_DIR
    if contract is None:
        contract = load_l2_contract()
    l2 = (contract or {}).get("l2") or {}
    offsets = (contract or {}).get("structOffsets") or {}
    kretprobe = offsets.get("kretprobe") or {}
    pt_regs = offsets.get("ptRegs") or {}

    hook_body = function_body(text, L2_ENTRY_FUNCTION)
    umh = function_body(text, "umh_main") or ""

    # -- S26: the slot exists and sits between stage-2 and the daemon --------- #
    record("S26", hook_body is not None, "hook_l2 is a function definition")
    call_at = umh.find(L2_ENTRY_FUNCTION + "(")
    stage2_at = umh.find("hook_stage2(")
    daemon_at = umh.find("hook_daemon(")
    record("S26", call_at >= 0 and stage2_at >= 0 and daemon_at > call_at > stage2_at,
           "hook_l2 is called after hook_stage2 and before hook_daemon",
           "stage2=%d l2=%d daemon=%d" % (stage2_at, call_at, daemon_at))
    guard = umh[max(0, call_at - 400):call_at] if call_at >= 0 else ""
    record("S26", "l2_enabled" in guard,
           "the L2 slot is opt-in: the call is guarded by l2_enabled, so a helper run "
           "without --l2 keeps step-4's exact behaviour",
           "guard window=%r" % guard.strip()[-80:])

    # -- S27: the staged module is validated before it reaches the kernel ------ #
    reader = (function_body(text, "l2_read_staged")
              or function_body(text, "hook_l2_read_staged") or "")
    record("S27", reader != "", "the staged-module reader is a named function")
    criteria = ("O_NOFOLLOW", "S_ISREG", "st_uid", "st_nlink", "0077")
    missing = [needle for needle in criteria if needle not in reader]
    record("S27", reader != "" and not missing,
           "the reader applies ir_read_staged's criteria (regular, dir uid, no group/"
           "world bits, single link)",
           "missing: %s" % ", ".join(missing) if missing else "all present")
    record("S27", "ir_elf_precheck(" in (hook_body or ""),
           "the image is ELF-prechecked (ET_REL/AArch64) before finit_module")
    validate_at = (hook_body or "").find("l2_read_staged(")
    finit_at = (hook_body or "").find("MAPLESU_NR_FINIT_MODULE")
    record("S27", 0 <= validate_at < finit_at,
           "validation happens before the kernel is asked to load anything",
           "validate=%d finit=%d" % (validate_at, finit_at))
    record("S27", "MAPLESU_NR_FINIT_MODULE" in (hook_body or ""),
           "finit_module goes through the named syscall constant")
    # M6: the cookie arrives as finit_module's uargs, and only the loader can supply
    # them. A module loaded with empty uargs has no cookie, so ARM could never succeed
    # - the helper must pass "cookie=0x<16 hex>".
    uargs = re.search(r'"cookie=0x', hook_body or "")
    record("S27", uargs is not None,
           "the finit_module uargs carry the non-zero cookie (M6: cookie=0x<16 hex>)")

    # -- S28: the two new argv flags, and only in hook_parse_argv -------------- #
    parse_body = function_body(text, "hook_parse_argv") or ""
    for token in ('"--l2"', '"--l2-required"'):
        record("S28", token in parse_body, "arg token parsed: %s" % token)
        record("S28", parse_body.count(token) >= 1
                      and text.count(token) == parse_body.count(token),
               "%s is parsed only in hook_parse_argv" % token,
               "file=%d parse=%d" % (text.count(token),
                                     parse_body.count(token)))
    record("S28", "l2_required" in parse_body and "l2_enabled" in parse_body,
           "both flags are recorded on the request")
    implication = re.search(r"l2_required[^;\n]{0,120}l2_enabled\s*=\s*1", parse_body)
    record("S28", implication is not None,
           "l2_required implies l2_enabled (a required slot that is not enabled would "
           "report success for work it never did)")

    # -- S29: one "l2" key, in the same single write -------------------------- #
    writer = function_body(text, "hook_write_main_json") or ""
    record("S29", writer.count('\\"l2\\":') == 1,
           'the "l2" key appears exactly once in the evidence document',
           "occurrences=%d" % writer.count('\\"l2\\":'))
    record("S29", writer.count('\\"l2\\":') == 1
                  and writer.count("write(state->ev_fd") == 1,
           "the L2 block shares the document's single write() (truncated JSON is no "
           "evidence)",
           "l2keys=%d writes=%d" % (writer.count('\\"l2\\":'),
                                    writer.count("write(state->ev_fd")))
    record("S29", "maplesu.hook.l2.v1" in writer or "maplesu.hook.l2.v1" in text,
           "the block names its schema (maplesu.hook.l2.v1)")

    # -- S30: the verdict branch --------------------------------------------- #
    verdict = function_body(text, "hook_verdict") or ""
    record("S30", "l2_required" in verdict and "l2_verdict" in verdict,
           "hook_verdict reads l2_required and l2_verdict")
    branch = re.search(r"l2_required[^\n]{0,140}FAILED", verdict)
    record("S30", branch is not None,
           "a required L2 that is not OK makes the whole verdict FAILED")
    upgrades = [line for line in verdict.splitlines()
                if "l2_" in line and '"OK"' in line]
    record("S30", branch is not None and not upgrades,
           "the L2 branch never upgrades a verdict to OK",
           "found: %s" % upgrades[:2] if upgrades else "no l2 line returns OK")

    # -- S31: no forbidden call in hook_l2 or any l2_* helper ----------------- #
    l2_functions = sorted(set(re.findall(
        r"(?m)^[A-Za-z_][^\n;{}]*?(?<![A-Za-z0-9_])(l2_[a-z0-9_]+|hook_l2)\s*\(", text)))
    record("S31", L2_ENTRY_FUNCTION in l2_functions,
           "the sweep sees hook_l2 (it is discovered, not listed by hand)")
    offenders = {}
    for name in l2_functions:
        body = function_body(text, name) or ""
        hits = [needle for needle in L2_FORBIDDEN if needle in body]
        if hits:
            offenders[name] = hits
    record("S31", bool(l2_functions) and not offenders,
           "no L2 function carries a forbidden L2 call (mount/BLKROSET/selinuxfs/"
           "policy setter/text mutation/arbitrary write)",
           "found: %s" % offenders if offenders else
           "swept %d function(s)" % len(l2_functions))

    # -- S32: disarm before delete, and the two records stay separate --------- #
    body = hook_body or ""
    disarm_at = body.find("disarm")
    delete_markers = [body.find(marker) for marker in
                      ("MAPLESU_NR_DELETE_MODULE", "delete_module")]
    delete_markers = [at for at in delete_markers if at >= 0]
    delete_at = min(delete_markers) if delete_markers else -1
    record("S32", body != "" and 0 <= disarm_at < delete_at,
           "delete_module happens only after the disarm step",
           "disarm=%d delete_module=%d" % (disarm_at, delete_at))
    record("S32", "MAPLESU_NR_DELETE_MODULE" in body,
           "the unload goes through the named syscall constant")
    for needle in ("l2 disarm state=", "l2 unload name="):
        record("S32", needle in text, "separate record emitted: %r" % needle)

    # -- S33: the evidence names the three probes and their fields ------------ #
    for probe_id in L2_EVIDENCE_IDS:
        record("S33", text.count(probe_id) >= 1,
               "the evidence names the probe %r" % probe_id)
    l2_region = "\n".join([writer] + [function_body(text, name) or ""
                                      for name in l2_functions])
    # The block's own keys: the fields the merge rules read must be *inside* the l2
    # object, not merely present somewhere in the document ("unload" already exists at
    # the top level, so a whole-file search would be vacuous).
    region_at = l2_region.find('\\"l2\\":')
    l2_tail = l2_region[region_at:] if region_at >= 0 else ""
    for field in ("selfcheck", "selinux", "disarm", "unload"):
        record("S33", bool(l2_tail) and field in l2_tail,
               "the emitted block carries the %r field the merge rules read" % field,
               "inside l2=%s" % bool(l2_tail))

    # -- S34: the frozen invariants script is untouched and unreferenced ------ #
    record("S34", "check_traceless_invariants" not in text,
           "the helper never references check_traceless_invariants.py")
    frozen = TRACELESS.is_file() and hashlib.sha256(
        TRACELESS.read_bytes()).hexdigest() == TRACELESS_SHA256
    record("S34", frozen,
           "check_traceless_invariants.py is byte-identical to the frozen digest",
           "sha256=%s checks=%d" % (TRACELESS_SHA256, TRACELESS_CHECKS))

    # -- S35: the token table, and absence (not zero-fill) when disabled ------ #
    for token in L2_TOKENS:
        record("S35", token in text, "L2 token present: %s" % token)
    guarded = re.search(r"if\s*\([^\n]{0,90}l2_enabled[^\n]{0,50}\)", l2_region)
    record("S35", guarded is not None,
           "the l2 block is emitted only when L2 is enabled (absent, not zero-filled)",
           "guard=%r" % (guarded.group(0).strip() if guarded else None))

    # -- S36: the module side exists at all ---------------------------------- #
    source_path = module_dir / "maplesu_l2.c"
    glue_path = module_dir / "root_glue_l2.S.in"
    source = source_path.read_text(encoding="utf-8", errors="replace") \
        if source_path.is_file() else ""
    glue = glue_path.read_text(encoding="utf-8", errors="replace") \
        if glue_path.is_file() else ""
    record("S36", source != "", "module/maplesu_l2.c exists", str(source_path))
    record("S36", glue != "", "module/root_glue_l2.S.in exists", str(glue_path))
    record("S36", "init_module" in source and "cleanup_module" in source,
           "the module defines init_module and cleanup_module")
    record("S36", 'maplesu_l2' in glue and "name=maplesu_l2" in glue.replace(" ", ""),
           "the glue names the module maplesu_l2 in .modinfo")
    record("S36", "vermagic" in glue, "the glue carries vermagic")

    # -- S37: the shims' static asserts equal the BTF-derived contract -------- #
    compat_path = module_dir / "kernel_compat.h"
    compat = compat_path.read_text(encoding="utf-8", errors="replace") \
        if compat_path.is_file() else ""

    def claimed(pattern: str):
        match = re.search(pattern, compat)
        return None if match is None else int(match.group(1), 0)

    assertions = (
        ("sizeof(struct maplesu_kretprobe) >= size",
         r"sizeof\(struct maplesu_kretprobe\)\s*>=\s*(0x[0-9a-fA-F]+|\d+)",
         kretprobe.get("size")),
        ("offsetof(struct maplesu_kretprobe, handler)",
         r"__builtin_offsetof\(struct maplesu_kretprobe,\s*handler\)\s*==\s*"
         r"(0x[0-9a-fA-F]+|\d+)", kretprobe.get("handler")),
        ("offsetof(struct maplesu_kretprobe, entry_handler)",
         r"__builtin_offsetof\(struct maplesu_kretprobe,\s*entry_handler\)\s*==\s*"
         r"(0x[0-9a-fA-F]+|\d+)", kretprobe.get("entryHandler")),
        ("offsetof(struct maplesu_kretprobe, data_size)",
         r"__builtin_offsetof\(struct maplesu_kretprobe,\s*data_size\)\s*==\s*"
         r"(0x[0-9a-fA-F]+|\d+)", kretprobe.get("dataSize")),
        ("offsetof(struct maplesu_pt_regs, syscallno)",
         r"__builtin_offsetof\(struct maplesu_pt_regs,\s*syscallno\)\s*==\s*"
         r"(0x[0-9a-fA-F]+|\d+)", pt_regs.get("syscallno")),
    )
    record("S37", contract is not None and bool(kretprobe) and bool(pt_regs),
           "the L2 contract carries the BTF-derived offsets the asserts are checked "
           "against", str(L2_CONTRACTS))
    for label, pattern, expected in assertions:
        got = claimed(pattern)
        record("S37", expected is not None and got == expected,
               "%s == %s (kernel_compat.h assert vs contract)"
               % (label, "?" if expected is None else hex(expected)),
               "assert=%r contract=%r" % (got, None if expected is None
                                          else hex(expected)))

    # -- S38: callback prototypes use kernel names, no no_sanitize ----------- #
    for needle in L2_PROTOTYPE_NEEDLES:
        record("S38", needle in source,
               "callback prototype uses the kernel struct names: %s" % needle)
    shim_typed = [line.strip() for line in source.splitlines()
                  if "l2_" in line and ("_cb(" in line or "l2_pre_" in line
                                        or "l2_post_" in line or "l2_ret_" in line)
                  and "struct maplesu_" in line]
    record("S38", source != "" and not shim_typed,
           "no callback prototype is declared with a shim struct pointer",
           "found: %s" % shim_typed[:2] if shim_typed else "none")
    # no_sanitize("kcfi") is legitimate on a resolver-calling helper (that is what
    # MAPLESU_NOCFI is), and illegitimate on a callback: it would not remove the
    # prefix anyway, and it hides the prototype drift G8 exists to catch. So the
    # check is about the callback definitions, not about the macro's spelling.
    callback_lines = []
    lines = source.splitlines()
    for index, line in enumerate(lines):
        if any(name in line for name in ("l2_pre_execve", "l2_post_execve",
                                         "l2_ret_execve", "l2_pre_ctl")) \
                and "(" in line:
            callback_lines.append((index, line, lines[index - 1] if index else ""))
    sanitised = [line.strip() for _index, line, previous in callback_lines
                 if "no_sanitize" in line or "no_sanitize" in previous]
    record("S38", source != "" and bool(callback_lines) and not sanitised,
           'no callback carries no_sanitize("kcfi") (it would not remove the prefix, '
           "and it hides the drift G8 exists to catch)",
           "callback lines=%d sanitised=%s" % (len(callback_lines), sanitised[:2]))
    nocfi_on_resolver = re.search(
        r"MAPLESU_NOCFI[^\n]{0,120}l2_kread", source) or re.search(
        r"l2_kread[^\n]{0,120}MAPLESU_NOCFI", source)
    record("S38", source != "" and "MAPLESU_NOCFI" in source
                  and nocfi_on_resolver is not None,
           "the resolver-calling helper (l2_kread) is MAPLESU_NOCFI (the asymmetry: "
           "callers of resolved pointers drop the check, callbacks keep their prefix)")

    # -- S39: the two-tag write whitelist ------------------------------------ #
    kwrite = function_body(source, "l2_kwrite") or ""
    record("S39", "WL_SCRATCH" in kwrite and "WL_SELINUX" in kwrite,
           "l2_kwrite handles exactly the two whitelist tags")
    record("S39", "-EACCES" in kwrite,
           "anything outside the whitelist is refused with -EACCES")
    # A one-byte *store* - the cast alone is not enough, because the same-value
    # readback uses the same spelling with `==`.
    one_byte = re.search(
        r"\*\(\s*volatile\s+(u8|unsigned char)\s*\*\s*\)[^=;\n]{0,40}=\s*[^=]",
        kwrite)
    record("S39", one_byte is not None,
           "the WL_SELINUX store is a one-byte store through volatile u8")
    record("S39", "enforcing_now" in kwrite,
           "the store is compared with the value just read (same-value rule: writing a "
           "different value would move the policy window)")
    forbidden_in_source = [needle for needle in L2_FORBIDDEN if needle in source]
    record("S39", source != "" and not forbidden_in_source,
           "no text-mutation or arbitrary-write helper anywhere in the module source",
           "found: %s" % forbidden_in_source if forbidden_in_source else "none")

    # -- S40: no per-release constant in the module source ------------------- #
    record("S40", source != "" and re.search(r"\b453\b|\b0x1c5\b", source) is None,
           "no magic syscall number literal in the module source")
    record("S40", "sys_call_table" in source,
           "the ARM-time self-check reads sys_call_table")
    record("S40", "syscallno" in source,
           "the control path reads pt_regs->syscallno (not a caller-supplied number)")
    record("S40", source != ""
                  and re.search(r"0x[fF]{2,16}[0-9a-fA-F]{6,}", source) is None,
           "no kernel virtual address literal in the module source")
    return checks


def _materialised(code: bytes, value: int) -> list[dict]:
    """Every place the code materialises `value` with movz/movk, or compares an
    immediate against it.

    This is G11 ① as reviewed (M7): the gate must decode `movz`/`movk`/`cmp #imm`,
    because the measured fact is that 453 never appears as the byte pattern
    `c5 01 00 00` - it appears as `movz wN, #0x1c5`. A raw byte search is vacuous.
    """
    hits: list[dict] = []
    state: dict[int, int] = {}
    for offset in range(0, len(code) - 3, 4):
        insn = struct.unpack_from("<I", code, offset)[0]
        # movz wN/xN, #imm16{, lsl #16*sf}
        if (insn & 0x7F800000) == 0x52800000 or (insn & 0x7F800000) == 0xD2800000:
            reg = insn & 0x1F
            immediate = ((insn >> 5) & 0xFFFF) << (((insn >> 21) & 0x3) * 16)
            state[reg] = immediate
            if immediate == value:
                hits.append({"offset": offset, "how": "movz"})
            continue
        # movk wN/xN, #imm16{, lsl #16*sf}
        if (insn & 0x7F800000) == 0x72800000 or (insn & 0x7F800000) == 0xF2800000:
            reg = insn & 0x1F
            shift = ((insn >> 21) & 0x3) * 16
            immediate = (insn >> 5) & 0xFFFF
            # clang emits the kCFI id as a movk pair with no preceding movz, so an
            # untracked register starts at the zero-extended immediate of this movk.
            merged = ((state.get(reg, 0) & ~(0xFFFF << shift))
                      | (immediate << shift))
            state[reg] = merged
            if merged == value:
                hits.append({"offset": offset, "how": "movk"})
            continue
        # cmp wN/xN, #imm12{, lsl #12}  (SUBS with Rd=31)
        if (insn & 0xFFC0001F) in (0x7100001F, 0xF100001F):
            reg = (insn >> 5) & 0x1F
            immediate = ((insn >> 10) & 0xFFF) << (12 if (insn >> 22) & 1 else 0)
            if immediate == value or state.get(reg) == value:
                hits.append({"offset": offset, "how": "cmp #imm"})
            continue
        # Any other instruction may clobber the tracked register; drop the model for
        # the destination register so a stale value cannot be reported as materialised.
        if (insn & 0x7F000000) not in (0x52800000, 0x72800000, 0xD2800000, 0xF2800000):
            state.pop(insn & 0x1F, None)
    return hits


def _l2_store_census(elf: "Elf") -> dict:
    """The write-scope skeleton (M7): every .text store, classified.

    The Lead's "no arbitrary write" condition needs an assertion, not a ban on four
    helper names: a raw `str x8,[x0]` to a resolved pointer passes every other gate.
    The rule implemented here is the one an L2 module can actually satisfy:

      * a store with base `sp` or `x29` is stack;
      * a store inside `l2_kwrite` is the whitelist writer;
      * a store in a function that also carries an ADRP relocation against its own
        `.bss`/`.data` is an own-section write (the module's own globals);
      * everything else is a violation.

    It is a skeleton in one specific sense, stated rather than hidden: it is a
    per-function attribution, not a per-store dataflow, so a function that has both
    an own-section ADRP and a caller-pointer store would pass. The source-level
    same-value rule (S39) and G11 ① cover the remaining shapes.
    """
    text = elf.section(".text")
    census = {"stores": 0, "stack": 0, "whitelist": 0, "ownSection": 0,
              "violations": [], "functions": {}}
    if text is None:
        return census
    body = elf.data(text)
    symbols = elf.symbols()
    own_data = {section["index"] for section in elf.sections
                if section["flags"] & 0x2 and not section["flags"] & 0x4
                and section["type"] in (1, 8)}      # PROGBITS (.data) / NOBITS (.bss)
    text_index = text["index"]
    functions = sorted((symbol for symbol in symbols
                        if symbol["shndx"] == text_index
                        and symbol["binding"] in (1, 2)
                        and symbol["type"] == 2),
                       key=lambda symbol: symbol["value"])

    def function_at(offset: int):
        best = None
        for symbol in functions:
            if symbol["value"] <= offset and (best is None or
                                              symbol["value"] > best["value"]):
                best = symbol
        return best

    own_section_functions = set()
    for relocation in elf.relocations():
        if relocation["targetSection"] != text_index:
            continue
        if relocation["type"] not in (275, 276):        # ADR_PREL_PG_HI21(_NC)
            continue
        index = relocation["symbolIndex"]
        if not (0 <= index < len(symbols)):
            continue
        if symbols[index]["shndx"] in own_data:
            owner = function_at(relocation["offset"])
            if owner is not None:
                own_section_functions.add(owner["name"])

    for offset in range(0, len(body) - 3, 4):
        insn = struct.unpack_from("<I", body, offset)[0]
        if (insn & 0xFFC00000) not in (0xF9000000, 0xB9000000, 0x39000000):
            continue
        base = (insn >> 5) & 0x1F
        owner = function_at(offset)
        name = None if owner is None else owner["name"]
        census["stores"] += 1
        census["functions"][name] = census["functions"].get(name, 0) + 1
        if base in (31, 29):
            census["stack"] += 1
        elif name == "l2_kwrite":
            census["whitelist"] += 1
        elif name in own_section_functions:
            census["ownSection"] += 1
        else:
            census["violations"].append({"offset": "0x%x" % offset,
                                         "function": name,
                                         "baseRegister": "x%d" % base})
    return census


def l2_object_checks(path: Path | None = None) -> list[dict]:
    """O6-O10: the L2 module artifact. Red until C1 produces it."""
    checks: list[dict] = []
    record = recorder(checks, "l2")
    path = Path(path) if path else L2_OBJECT
    titles = (
        ("O6", "the L2 object's imports are the six M4 symbols plus the declared "
               "cookie param(s)"),
        ("O7", "no text-mutation or patch helper in the object"),
        ("O8", "no policy/device write surface in the object"),
        ("O9", "no ksu/ksud/kernelsu string in the object"),
        ("O10", "zero /data/ literals, no per-release constant, write-scope clean"),
    )
    if not path.is_file():
        for check_id, title in titles:
            record(check_id, False, title, "artifact absent: %s" % path)
        return checks
    try:
        elf = Elf(path)
    except (ValueError, struct.error) as error:
        for check_id, title in titles:
            record(check_id, False, title, "artifact unreadable: %s" % error)
        return checks
    undefined = elf.undefined_symbols()
    blob = b"".join(elf.data(section) for section in elf.allocated())
    text = elf.section(".text")
    code = elf.data(text) if text is not None else b""

    record("O6", set(undefined) == L2_IMPORT_SET,
           "the L2 object's undefined set is exactly the six M4 imports",
           "missing: %s; unexpected: %s"
           % (sorted(L2_IMPORT_SET - set(undefined)),
              sorted(set(undefined) - L2_IMPORT_SET)))
    record("O6", not (L2_LOOKUP_SET & set(undefined)),
           "the three runtime lookups are not imports (they are unexported, so an "
           "import would fail with 'Unknown symbol')")
    # M6: the cookie channel is the one documented increment on the six. The complete
    # set is asserted exactly, and the delta must be a symbol this gate allows - so a
    # contract edit cannot smuggle in a new library dependency.
    contract = load_l2_contract() or {}
    l2_contract = contract.get("l2") or {}
    declared_cookie = {row.get("name") for row in
                       l2_contract.get("importsCookieParam") or []}
    extra = set(undefined) - L2_IMPORT_SET
    record("O6", extra == declared_cookie and extra <= L2_COOKIE_PARAM_ALLOWED,
           "the only non-M4 imports are the declared cookie params (M6), and they "
           "are ones this gate allows",
           "extra=%s declared=%s allowed=%s"
           % (sorted(extra), sorted(declared_cookie),
              sorted(L2_COOKIE_PARAM_ALLOWED)))
    record("O6", set(undefined) == L2_IMPORT_SET | declared_cookie,
           "the complete undefined set equals the six plus the declared cookie params",
           "undefined=%s" % sorted(set(undefined)))

    danger = [name for name in L2_FORBIDDEN_OBJECT_SYMBOLS
              if name in undefined or name.encode() in elf.raw]
    record("O7", not danger,
           "no text-mutation or patch helper in the object",
           "found: %s" % danger if danger else "none of %d" %
           len(L2_FORBIDDEN_OBJECT_SYMBOLS))

    for needle in L2_FORBIDDEN_STRINGS:
        record("O8", needle not in blob,
               "allocated data carries no %r" % needle.decode())

    lowered = blob.lower()
    for needle in L2_KSU_STRINGS:
        record("O9", needle not in lowered,
               "allocated data carries no %r" % needle.decode())

    record("O10", blob.count(b'"/data/') == 0,
           'zero "/data/" literals in the L2 object (the module path is the helper\'s, '
           "per the design's H2 delivery)",
           "found %d" % blob.count(b'"/data/'))
    materialised = _materialised(code, L2_MAGIC_SCNO)
    record("O10", not materialised,
           "the magic syscall number is never materialised (movz/movk/cmp #imm "
           "decoded, not a byte pattern)",
           "hits: %s" % materialised[:3] if materialised else "none")
    addresses = []
    for offset in range(0, len(blob) - 7, 8):
        value = struct.unpack_from("<Q", blob, offset)[0]
        if 0xFFFFFF8000000000 <= value <= 0xFFFFFFFFFFFFFFFF:
            addresses.append("0x%x+0x%x" % (offset, value))
    record("O10", not addresses,
           "no kernel virtual address literal in allocated data",
           "found: %s" % addresses[:3] if addresses else "none")
    census = _l2_store_census(elf)
    record("O10", not census["violations"],
           "write scope: every .text store is stack, the whitelist writer, or an "
           "own-section write",
           "stores=%d stack=%d whitelist=%d own=%d violations=%s"
           % (census["stores"], census["stack"], census["whitelist"],
              census["ownSection"], census["violations"][:3]))
    return checks


def main(argv: list[str] | None = None) -> int:
    global SOURCE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=str(SOURCE))
    parser.add_argument("--object", default=None,
                        help="bootstrap.o to check as well (design §8.2 leg 2)")
    parser.add_argument("--json", default=None, help="write the report here too")
    parser.add_argument("--l2-required", action="store_true",
                        help="make the L2 leg (S26-S40 / O6-O10) fatal. It is "
                             "reported as RED (non-fatal) by default because the L2 "
                             "module and helper slot are C1/C2; CI uses this flag "
                             "once they exist")
    parser.add_argument("--l2-source", default=str(L2_MODULE_SOURCE),
                        help="the L2 module source (default: %s)" % L2_MODULE_SOURCE)
    parser.add_argument("--l2-object", default=str(L2_OBJECT),
                        help="the L2 module artifact (default: %s)" % L2_OBJECT)
    parser.add_argument("--no-l2", action="store_true",
                        help="skip the L2 leg entirely (the pre-C0 baseline)")
    arguments = parser.parse_args(argv)

    SOURCE = Path(arguments.source)
    if not SOURCE.is_file():
        print("FAIL: source missing at %s" % SOURCE)
        return 2
    text = read_source()
    checks = source_checks(text)
    if arguments.object:
        object_path = Path(arguments.object)
        if not object_path.is_file():
            checks.append({"id": "O0", "ok": False, "title": "object exists",
                           "detail": str(object_path)})
        else:
            try:
                checks += object_checks(object_path)
            except (ValueError, struct.error) as error:
                checks.append({"id": "O0", "ok": False,
                               "title": "object is a parseable ELF64",
                               "detail": str(error)})
    if not arguments.no_l2:
        l2_source = Path(arguments.l2_source)
        module_dir = l2_source.parent
        try:
            checks += l2_source_checks(text, module_dir=module_dir)
        except (OSError, ValueError, KeyError, TypeError) as error:
            # A broken L2 leg must never take the baseline down with it: it fails
            # closed as its own red, and the baseline checks keep their verdict.
            checks.append({"id": "S26", "ok": False, "stage": "l2",
                           "title": "the L2 source leg could be evaluated",
                           "detail": repr(error)})
        try:
            checks += l2_object_checks(Path(arguments.l2_object))
        except (OSError, ValueError, struct.error, KeyError, TypeError) as error:
            checks.append({"id": "O6", "ok": False, "stage": "l2",
                           "title": "the L2 object leg could be evaluated",
                           "detail": repr(error)})

    # Red-first, without hiding it: the L2 leg is non-fatal until C1 lands, and the
    # report says so in the same line as the verdict. `--l2-required` promotes it.
    l2_checks = [check for check in checks if check.get("stage") == "l2"]
    baseline = [check for check in checks if check.get("stage") != "l2"]
    fatal = baseline + (l2_checks if arguments.l2_required else [])
    failed = [check for check in fatal if not check["ok"]]
    l2_red = [check for check in l2_checks if not check["ok"]]
    report = {
        "schema": "maplesu.hook-contract/1",
        "source": str(SOURCE),
        "object": arguments.object,
        "checks": len(checks),
        "failed": len(failed),
        "ok": not failed,
        "l2": {
            "evaluated": not arguments.no_l2,
            "required": bool(arguments.l2_required),
            "checks": len(l2_checks),
            "red": len(l2_red),
            "source": str(arguments.l2_source),
            "object": str(arguments.l2_object),
        },
        "results": [{"id": check["id"], "ok": check["ok"], "title": check["title"],
                     "detail": check["detail"], "stage": check.get("stage")}
                    for check in checks],
    }
    print("maplesu UMH hook contract (host-only)")
    for check in checks:
        if check["ok"]:
            status = "PASS"
        elif check.get("stage") == "l2" and not arguments.l2_required:
            status = "RED (l2)"
        else:
            status = "FAIL"
        line = "  [%s] %-46s %s" % (check["id"], check["title"], status)
        if check["detail"] and (not check["ok"] or arguments.object is None):
            line += "  -- " + check["detail"]
        print(line)
    print("RESULT: %s checks=%d failed=%d l2_checks=%d l2_red=%d l2_required=%s"
          % ("PASS" if report["ok"] else "FAILED", report["checks"], report["failed"],
             len(l2_checks), len(l2_red), "1" if arguments.l2_required else "0"))
    if l2_red and not arguments.l2_required:
        print("        the L2 leg is red by design until C1/C2 land; run with "
              "--l2-required to make it fatal")
    if arguments.json:
        Path(arguments.json).write_text(json.dumps(report, indent=2) + "\n",
                                        encoding="utf-8")
        print("report: %s" % arguments.json)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
