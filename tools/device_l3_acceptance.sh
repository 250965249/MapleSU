#!/usr/bin/env bash
#
# MapleSU L3 (ABI v2) device acceptance driver.
#
# Drives exactly one thing on the device: the instrumentation test
#
#   dev.maplesu.manager.jailbreak.L3SuGateAndroidTest#gateArmsAndSuRuns
#
# and records the before/after evidence around it. The test itself performs the
# hook attempt, the three deploySu calls and the forged-token negative probe; this
# script must not add a second attempt (one boot admits exactly one hook attempt).
#
# Results:
#   PASS       device reachable, instrumentation OK, same boot, SELinux back to
#              enforcing, $(1,$2,$3) mount projection unchanged, evidence JSON
#              says DAEMON_READY and an armed gate
#   HOST_ONLY  no reachable device (adb missing/offline/unauthorized): only the
#              host-side log under .analysis/l3-acceptance-<ts>/ exists
#   FAIL       the device ran (or was reachable) and a criterion failed, including
#              REBOOTED_DURING_ATTEMPT
#
# This script DOES mutate the device (installs APKs when --install is given and
# runs one root attempt). Run it only on the retained acceptance device, and only
# on a freshly booted device: the hook window is per boot.
#
# Usage:
#   tools/device_l3_acceptance.sh [--install]
#
# Environment:
#   ANDROID_SERIAL  serial of the device under test (see adb devices); required
#
set -u

SERIAL="${ANDROID_SERIAL:-}"
ADB="adb -s $SERIAL"
PKG="dev.maplesu.manager"
RUNNER="$PKG.test/androidx.test.runner.AndroidJUnitRunner"
TEST_CLASS="$PKG.jailbreak.L3SuGateAndroidTest#gateArmsAndSuRuns"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
APK="$ROOT/manager/build/outputs/apk/debug/manager-debug.apk"
TEST_APK="$ROOT/manager/build/outputs/apk/androidTest/debug/manager-debug-androidTest.apk"

EVIDENCE_EXTERNAL="/sdcard/Android/data/$PKG/files/jailbreak-evidence/l3-su-gate.json"
EVIDENCE_FILES="/data/user/0/$PKG/files/jailbreak-evidence/l3-su-gate.json"
ATTEMPT_DIR="/data/user_de/0/$PKG"

usage() {
    cat <<'EOF'
Usage: tools/device_l3_acceptance.sh [--install]

  --install   install manager-debug.apk and manager-debug-androidTest.apk
              before running the instrumentation

Runs dev.maplesu.manager.jailbreak.L3SuGateAndroidTest#gateArmsAndSuRuns
once, on a freshly booted device (one attempt per boot), and collects the
before/after boot id, SELinux mode, /proc/mounts projection and evidence.

Environment:
  ANDROID_SERIAL   serial of the device under test (see adb devices); required

Exit: 0 PASS, 1 FAIL, 2 HOST_ONLY.
EOF
}

DO_INSTALL=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --install) DO_INSTALL=1 ;;
        -h|--help) usage; exit 0 ;;
        *)
            printf 'unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 64
            ;;
    esac
    shift
done

if [ -z "$SERIAL" ]; then
    printf 'set ANDROID_SERIAL to the device serial (see adb devices)\n' >&2
    exit 64
fi

TS="$(date +%Y%m%d-%H%M%S)"
OUT="$ROOT/.analysis/l3-acceptance-$TS"
if ! mkdir -p "$OUT"; then
    printf 'cannot create artifact directory: %s\n' "$OUT" >&2
    exit 1
fi
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"

log() {
    printf '%s\n' "$*" | tee -a "$SUMMARY"
}

DEVICE_READY=0
INSTALL_OK=1
INSTALL_FAILED=0
INSTR_OK=0
INSTR_RC=255
BOOT_BEFORE=""
BOOT_AFTER=""
BOOT_UNCHANGED=0
ENFORCING_BEFORE=""
ENFORCING_AFTER=""
ENFORCING_OK=0
MOUNTS_SAME=0
EVIDENCE_OK=0
EVIDENCE_STAGE=0
EVIDENCE_ARMED=0
PS_CLEAN=0
REBOOTED=0
RESULT=""
REASONS=""

fail_reason() {
    RESULT="FAIL"
    if [ -n "$REASONS" ]; then
        REASONS="$REASONS; $1"
    else
        REASONS="$1"
    fi
}

finalize() {
    if [ -z "$RESULT" ]; then
        RESULT="PASS"
        if [ "$DEVICE_READY" -ne 1 ]; then
            RESULT="HOST_ONLY"
        else
            [ "$REBOOTED" -eq 1 ] && fail_reason "REBOOTED_DURING_ATTEMPT"
            [ "$INSTALL_FAILED" -eq 1 ] && fail_reason "install failed"
            [ "$INSTR_OK" -ne 1 ] && fail_reason "instrumentation not OK (rc=$INSTR_RC)"
            [ "$BOOT_UNCHANGED" -ne 1 ] && fail_reason "boot id unreadable or changed"
            [ "$ENFORCING_OK" -ne 1 ] && fail_reason "SELinux not enforcing after the attempt"
            [ "$MOUNTS_SAME" -ne 1 ] && fail_reason "mount projection changed within the boot"
            [ "$EVIDENCE_OK" -ne 1 ] && fail_reason "evidence JSON not collected"
            [ "$EVIDENCE_STAGE" -ne 1 ] && fail_reason "evidence stage is not DAEMON_READY"
            [ "$EVIDENCE_ARMED" -ne 1 ] && fail_reason "evidence gate is not armed"
            [ "$PS_CLEAN" -ne 1 ] && fail_reason "evidence shows a uid-0 manager process"
        fi
    fi

    log ""
    log "=== L3 SU GATE ACCEPTANCE: $RESULT ==="
    log "device:        $SERIAL"
    log "boot:          before=$BOOT_BEFORE after=$BOOT_AFTER unchanged=$BOOT_UNCHANGED"
    log "selinux:       before=$ENFORCING_BEFORE after=$ENFORCING_AFTER enforcing=$ENFORCING_OK"
    log "mounts:        projection_same=$MOUNTS_SAME"
    log "instrument:    ok=$INSTR_OK rc=$INSTR_RC"
    log "evidence:      collected=$EVIDENCE_OK daemon_ready=$EVIDENCE_STAGE armed=$EVIDENCE_ARMED ps_clean=$PS_CLEAN"
    log "artifacts:     $OUT"
    if [ -n "$REASONS" ]; then
        log "reasons:       $REASONS"
    fi
    if [ "$REBOOTED" -eq 1 ]; then
        log "WARNING: REBOOTED_DURING_ATTEMPT - the scene was kept at $OUT"
    fi

    case "$RESULT" in
        PASS) exit 0 ;;
        HOST_ONLY) exit 2 ;;
        *) exit 1 ;;
    esac
}

# --- host tooling -----------------------------------------------------------

if ! command -v adb >/dev/null 2>&1; then
    log "HOST_ONLY: adb is not on PATH; no device-side check was attempted"
    RESULT="HOST_ONLY"
    finalize
fi
if ! command -v timeout >/dev/null 2>&1; then
    log "HOST_ONLY: GNU timeout is not on PATH; refusing to run unbounded device commands"
    RESULT="HOST_ONLY"
    finalize
fi

log "L3 acceptance $TS"
log "adb:   $ADB"
log "out:   $OUT"

# --- device reachability ----------------------------------------------------

STATE="$(timeout 30 $ADB get-state 2>&1 | tr -d '\r' | head -n 1)"
if [ "$STATE" != "device" ]; then
    log "HOST_ONLY: device $SERIAL is not available (get-state='$STATE')"
    printf '%s\n' "$STATE" > "$OUT/get-state.txt"
    RESULT="HOST_ONLY"
    finalize
fi
DEVICE_READY=1

# --- optional install -------------------------------------------------------

install_apk() {
    local apk="$1"
    local tag="$2"
    local rc=0
    local last=""
    if [ ! -f "$apk" ]; then
        log "INSTALL_MISSING $tag: $apk"
        return 1
    fi
    timeout 300 $ADB install -r -g "$apk" > "$OUT/install-$tag.txt" 2>&1 || rc=$?
    last="$(tr -d '\r' < "$OUT/install-$tag.txt" | tail -n 1)"
    if [ "$rc" -eq 0 ] && printf '%s' "$last" | grep -q "Success"; then
        log "INSTALL_OK $tag ($(wc -c < "$apk" | tr -d ' ') bytes)"
        return 0
    fi
    log "INSTALL_FAILED $tag rc=$rc: $last"
    return 1
}

if [ "$DO_INSTALL" -eq 1 ]; then
    log "installing $APK"
    install_apk "$APK" "manager" || { INSTALL_OK=0; INSTALL_FAILED=1; }
    log "installing $TEST_APK"
    install_apk "$TEST_APK" "androidTest" || { INSTALL_OK=0; INSTALL_FAILED=1; }
else
    log "install skipped (pass --install to install both APKs)"
fi

# --- before -----------------------------------------------------------------

capture_shell() {
    local name="$1"
    local cmd="$2"
    local rc=0
    timeout 60 $ADB shell "$cmd" > "$OUT/$name.txt" 2> "$OUT/$name.err" || rc=$?
    if [ "$rc" -ne 0 ]; then
        log "SHELL_FAILED $name rc=$rc: $(tr '\n' ' ' < "$OUT/$name.err" | cut -c1-300)"
    fi
    return 0
}

trim_file() {
    tr -d '\r\n' < "$1" 2>/dev/null || true
}

normalize_mounts() {
    local src="$1"
    local dst="$2"
    tr -d '\r' < "$src" 2>/dev/null \
        | awk 'NF >= 3 { print $1" "$2" "$3 }' \
        | LC_ALL=C sort > "$dst"
}

capture_shell "boot_id.before" "cat /proc/sys/kernel/random/boot_id"
capture_shell "getenforce.before" "getenforce"
capture_shell "mounts.before" "cat /proc/mounts"
BOOT_BEFORE="$(trim_file "$OUT/boot_id.before.txt")"
ENFORCING_BEFORE="$(trim_file "$OUT/getenforce.before.txt")"
log "before: boot=$BOOT_BEFORE getenforce=$ENFORCING_BEFORE"

# --- the one attempt --------------------------------------------------------

log "RUN instrument: $TEST_CLASS"
log "timeout: 600s"
timeout 600 $ADB shell am instrument -w -e class "$TEST_CLASS" "$RUNNER" \
    2>&1 | tee "$OUT/instrument.txt"
INSTR_RC="${PIPESTATUS[0]}"
log "instrument exit=$INSTR_RC"

if [ "$INSTR_RC" -eq 0 ] \
    && grep -q "OK (1 test)" "$OUT/instrument.txt" \
    && ! grep -q "FAILURES!!!" "$OUT/instrument.txt"; then
    INSTR_OK=1
fi
if grep -q "REBOOTED_DURING_ATTEMPT" "$OUT/instrument.txt"; then
    REBOOTED=1
fi

# --- after ------------------------------------------------------------------

capture_shell "boot_id.after" "cat /proc/sys/kernel/random/boot_id"
capture_shell "getenforce.after" "getenforce"
capture_shell "mounts.after" "cat /proc/mounts"
capture_shell "ps.after" "ps -A -o UID,NAME"
BOOT_AFTER="$(trim_file "$OUT/boot_id.after.txt")"
ENFORCING_AFTER="$(trim_file "$OUT/getenforce.after.txt")"

if [ -n "$BOOT_BEFORE" ] && [ -n "$BOOT_AFTER" ] && [ "$BOOT_BEFORE" = "$BOOT_AFTER" ]; then
    BOOT_UNCHANGED=1
fi
if [ -n "$BOOT_BEFORE" ] && [ -n "$BOOT_AFTER" ] && [ "$BOOT_BEFORE" != "$BOOT_AFTER" ]; then
    REBOOTED=1
    log "REBOOTED_DURING_ATTEMPT: before=$BOOT_BEFORE after=$BOOT_AFTER"
    log "REBOOTED_DURING_ATTEMPT: keeping the scene at $OUT"
fi
if [ "$ENFORCING_AFTER" = "1" ]; then
    ENFORCING_OK=1
fi

normalize_mounts "$OUT/mounts.before.txt" "$OUT/mounts.before.norm"
normalize_mounts "$OUT/mounts.after.txt" "$OUT/mounts.after.norm"
if cmp -s "$OUT/mounts.before.norm" "$OUT/mounts.after.norm"; then
    MOUNTS_SAME=1
else
    diff -u "$OUT/mounts.before.norm" "$OUT/mounts.after.norm" > "$OUT/mounts.diff" || true
    log "MOUNTS_CHANGED ($(grep -c '^[+-][^+-]' "$OUT/mounts.diff" 2>/dev/null || true) diff lines)"
fi

# --- evidence files ---------------------------------------------------------

# run-as first (the app's own data is the intended reader), then plain shell.
collect_runas() {
    local name="$1"
    local path="$2"
    local rc=0
    : > "$OUT/$name"
    : > "$OUT/$name.err"
    timeout 60 $ADB shell run-as "$PKG" cat "$path" \
        > "$OUT/$name" 2>> "$OUT/$name.err" || rc=$?
    if [ "$rc" -eq 0 ] && [ -s "$OUT/$name" ]; then
        log "COLLECTED $path (run-as) -> $name"
        return 0
    fi
    rc=0
    timeout 60 $ADB shell cat "$path" \
        > "$OUT/$name" 2>> "$OUT/$name.err" || rc=$?
    if [ "$rc" -eq 0 ] && [ -s "$OUT/$name" ]; then
        log "COLLECTED $path (shell) -> $name"
        return 0
    fi
    log "UNAVAILABLE $path"
    return 1
}

# The privileged helper writes with uid 0; the app may not be able to read it.
collect_root_file() {
    local name="$1"
    local path="$2"
    local rc=0
    : > "$OUT/$name"
    : > "$OUT/$name.err"
    timeout 60 $ADB shell cat "$path" \
        > "$OUT/$name" 2>> "$OUT/$name.err" || rc=$?
    if [ "$rc" -eq 0 ] && [ -s "$OUT/$name" ]; then
        log "COLLECTED $path (shell) -> $name"
        return 0
    fi
    rc=0
    timeout 60 $ADB shell run-as "$PKG" cat "$path" \
        > "$OUT/$name" 2>> "$OUT/$name.err" || rc=$?
    if [ "$rc" -eq 0 ] && [ -s "$OUT/$name" ]; then
        log "COLLECTED $path (run-as) -> $name"
        return 0
    fi
    log "UNAVAILABLE $path"
    return 1
}

collect_runas "maplesu-hook.json" "$ATTEMPT_DIR/maplesu-hook.json"
collect_runas "maplesu-hook-daemon.json" "$ATTEMPT_DIR/maplesu-hook-daemon.json"

PROVIDER_OK=0
if collect_root_file "provider.log" "$ATTEMPT_DIR/maplesu-provider.log"; then
    PROVIDER_OK=1
elif collect_root_file "provider.log" "/dev/maplesu-provider.log"; then
    PROVIDER_OK=1
fi
if [ "$PROVIDER_OK" -eq 1 ]; then
    tail -n 200 "$OUT/provider.log" > "$OUT/provider.tail.txt"
    grep -Ein "l3 arm|armed|suGate|suToken" "$OUT/provider.log" \
        > "$OUT/provider.l3-grep.txt" || true
    log "provider log: tail=$(wc -l < "$OUT/provider.tail.txt" | tr -d ' ') lines, l3 matches=$(wc -l < "$OUT/provider.l3-grep.txt" | tr -d ' ')"
else
    : > "$OUT/provider.tail.txt"
    : > "$OUT/provider.l3-grep.txt"
fi

if timeout 120 $ADB pull "$EVIDENCE_EXTERNAL" "$OUT/l3-su-gate.json" \
        > "$OUT/evidence-pull.log" 2>&1 && [ -s "$OUT/l3-su-gate.json" ]; then
    EVIDENCE_OK=1
    log "COLLECTED $EVIDENCE_EXTERNAL (adb pull)"
else
    rm -f "$OUT/l3-su-gate.json"
    log "adb pull failed; trying shell/run-as fallbacks"
    if collect_runas "l3-su-gate.json" "$EVIDENCE_EXTERNAL"; then
        EVIDENCE_OK=1
    elif collect_runas "l3-su-gate.json" "$EVIDENCE_FILES"; then
        EVIDENCE_OK=1
    fi
fi

if [ "$EVIDENCE_OK" -eq 1 ]; then
    if grep -q '"stage"[[:space:]]*:[[:space:]]*"DAEMON_READY"' "$OUT/l3-su-gate.json"; then
        EVIDENCE_STAGE=1
    fi
    if grep -q '"armed"[[:space:]]*:[[:space:]]*true' "$OUT/l3-su-gate.json"; then
        EVIDENCE_ARMED=1
    fi
    if grep -q '"psUid0Manager"[[:space:]]*:[[:space:]]*\[\]' "$OUT/l3-su-gate.json"; then
        PS_CLEAN=1
    fi
fi

# dmesg is diagnostic only: a denial is recorded and never fails the run.
timeout 60 $ADB shell dmesg > "$OUT/dmesg.txt" 2> "$OUT/dmesg.err" || true
grep -E "maplesu_l3" "$OUT/dmesg.txt" > "$OUT/dmesg-maplesu_l3.txt" || true
if [ -s "$OUT/dmesg-maplesu_l3.txt" ]; then
    log "dmesg: $(wc -l < "$OUT/dmesg-maplesu_l3.txt" | tr -d ' ') maplesu_l3 lines"
elif grep -qiE "permission denied|not permitted|operation not permitted" \
        "$OUT/dmesg.err" "$OUT/dmesg.txt" 2>/dev/null; then
    log "dmesg: unavailable (permission denied); not a failure"
else
    log "dmesg: no maplesu_l3 lines readable; not a failure"
fi

# A last snapshot of the device-side process table, for the report.
if [ -s "$OUT/ps.after.txt" ]; then
    grep -E "dev\.maplesu\.manager" "$OUT/ps.after.txt" > "$OUT/ps.after.manager.txt" || true
fi

finalize
