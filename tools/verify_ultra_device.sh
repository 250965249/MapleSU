#!/usr/bin/env bash
# =============================================================================
# tools/verify_ultra_device.sh -- read-only device checks for the Ultra build.
#
# The script never installs, reboots, toggles or writes anything.  It only runs
#   adb shell tail -n 200 /data/local/tmp/soter_inject.log
#   adb logcat -d -v epoch
# and asserts:
#   C1  the last 3 heartbeats are selftest=[tx=3 value=1 hook=LIVE]
#   C2  no MPL-SOTER hook=MISSING in the last 5 minutes
#   C3  "scope loaded n=" is present with n > 0
#   C4  MPL-BUILD is present (which dex is actually running)
#   C5  PASS/FAIL summary, raw lines on every failure
#
# Usage (git-bash / Linux / macOS):
#   bash tools/verify_ultra_device.sh
#   bash tools/verify_ultra_device.sh --serial <serial> --minutes 5
#
# Exit code: 0 when all four assertions PASS, 1 otherwise.
# =============================================================================
set -u

# Allow `sh tools/verify_ultra_device.sh` too: re-exec under bash for arrays.
if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

ADB=${ADB:-adb}
SERIAL=${SERIAL:-${ANDROID_SERIAL:-}}
SOTER_LOG=${SOTER_LOG:-/data/local/tmp/soter_inject.log}
WINDOW_MIN=${WINDOW_MIN:-5}
TAIL_LINES=${TAIL_LINES:-200}
VERBOSE=0

usage() {
    awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
    cat <<EOF

Options:
  --adb PATH      adb binary (default: $ADB, or \$ADB)
  --serial SN     device serial (default: \$SERIAL, then \$ANDROID_SERIAL)
  --log PATH      on-device heartbeat log (default: $SOTER_LOG)
  --minutes N     C2 observation window in minutes (default: $WINDOW_MIN)
  --tail N        heartbeat lines pulled from the log (default: $TAIL_LINES)
  -v, --verbose   print all collected timestamps/counts
  -h, --help      this help
EOF
}

while [ $# -gt 0 ]; do
    case $1 in
        --adb) ADB=$2; shift 2 ;;
        --serial) SERIAL=$2; shift 2 ;;
        --log) SOTER_LOG=$2; shift 2 ;;
        --minutes) WINDOW_MIN=$2; shift 2 ;;
        --tail) TAIL_LINES=$2; shift 2 ;;
        -v|--verbose) VERBOSE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -z "$SERIAL" ]; then
    echo "pass --serial SN or set ANDROID_SERIAL (see adb devices)" >&2
    exit 2
fi

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); printf '[PASS] %-5s %s\n' "$1" "$2"; }
skip() { SKIP=$((SKIP + 1)); printf '[SKIP] %-5s %s\n' "$1" "$2"; }
fail() {
    FAIL=$((FAIL + 1))
    printf '[FAIL] %-5s %s\n' "$1" "$2"
    shift 2
    for line in "$@"; do
        printf '         %s\n' "$line"
    done
}
note() { printf '         %s\n' "$*"; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/verify-ultra.XXXXXX") || {
    echo "FATAL: mktemp failed" >&2
    exit 2
}
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

echo "=================================================================="
echo " C. Ultra device verification (read-only)"
echo "=================================================================="
echo "adb       : $ADB"
echo "serial    : $SERIAL"
echo "heartbeats: $SOTER_LOG (tail -n $TAIL_LINES)"
echo "logcat    : last $WINDOW_MIN minutes (epoch filter)"
echo

# --- C0: device must be online ---------------------------------------------
state=$("$ADB" -s "$SERIAL" get-state 2>"$TMP/state.err" | tr -d '\r')
if [ "$state" != "device" ]; then
    fail C0 "device $SERIAL is online" \
        "adb get-state -> '${state:-<empty>}'" \
        "$(cat "$TMP/state.err" 2>/dev/null | head -3)"
    echo
    echo "SUMMARY: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
    exit 1
fi
model=$("$ADB" -s "$SERIAL" shell getprop ro.product.model 2>/dev/null | tr -d '\r')
rel=$("$ADB" -s "$SERIAL" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')
sdk=$("$ADB" -s "$SERIAL" shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
printf 'device    : %s  Android %s (SDK %s)\n\n' "$model" "$rel" "$sdk"

# --- collect inputs (read-only) --------------------------------------------
collect_inject=0
# Pass the remote command as one string: on MSYS/git-bash an argv that starts
# with "/" would otherwise be rewritten into a local C:/... path.
if "$ADB" -s "$SERIAL" shell "tail -n $TAIL_LINES '$SOTER_LOG'" \
        >"$TMP/inject.raw" 2>"$TMP/inject.err"; then
    collect_inject=1
fi
tr -d '\r' < "$TMP/inject.raw" > "$TMP/inject.txt" 2>/dev/null || : > "$TMP/inject.txt"
if [ ! -s "$TMP/inject.txt" ]; then
    collect_inject=0
fi

"$ADB" -s "$SERIAL" logcat -d -v epoch >"$TMP/logcat.raw" 2>"$TMP/logcat.err"
tr -d '\r' < "$TMP/logcat.raw" > "$TMP/logcat.txt" 2>/dev/null || : > "$TMP/logcat.txt"
if [ ! -s "$TMP/logcat.txt" ]; then
    echo "FATAL: adb logcat -d produced no output: $(head -3 "$TMP/logcat.err" 2>/dev/null)" >&2
    echo "SUMMARY: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
    exit 1
fi

# Reference clock: latest device log timestamp (immune to host/device skew).
ref=$(awk '$1 ~ /^[0-9]+\./ { v = int($1); if (v > m) m = v } END { print m + 0 }' "$TMP/logcat.txt")
now=$(date +%s)
[ "$ref" -gt 0 ] 2>/dev/null || ref=$now
delta=$((now - ref))
[ "$delta" -lt 0 ] && delta=$((-delta))
[ "$VERBOSE" = 1 ] && note "clock: host=$now device_log_latest=$ref delta=${delta}s"

# --- C1: last 3 heartbeats are hook=LIVE -----------------------------------
if [ "$collect_inject" != 1 ]; then
    fail C1 "last 3 heartbeats are selftest=[tx=3 value=1 hook=LIVE]" \
        "cannot read $SOTER_LOG (adb shell tail failed or file is empty)" \
        "$(head -3 "$TMP/inject.err" 2>/dev/null)"
else
    hb=$(grep -a 'selftest=' "$TMP/inject.txt" | tail -n 3)
    hb_count=$(printf '%s\n' "$hb" | grep -c 'selftest=' || true)
    if [ "$hb_count" -lt 3 ]; then
        fail C1 "last 3 heartbeats are selftest=[tx=3 value=1 hook=LIVE]" \
            "only $hb_count heartbeat line(s) in the last $TAIL_LINES lines" \
            "last lines: $(tail -n 3 "$TMP/inject.txt" | tr '\n' '|')"
    else
        bad=0
        bad_lines=()
        ok_lines=()
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            case $line in
                *'selftest=[tx=3 value=1 hook=LIVE]'*) ok_lines+=("$line") ;;
                *) bad=1; bad_lines+=("$line") ;;
            esac
        done <<< "$hb"
        if [ "$bad" -eq 0 ]; then
            pass C1 "last 3 heartbeats are selftest=[tx=3 value=1 hook=LIVE]"
            for line in "${ok_lines[@]}"; do note "$line"; done
        else
            fail C1 "last 3 heartbeats are selftest=[tx=3 value=1 hook=LIVE]" \
                "${#bad_lines[@]} of 3 heartbeat(s) do not match" "${bad_lines[@]}"
        fi
    fi
fi

# --- C2: no hook=MISSING in the last N minutes -----------------------------
win=$((WINDOW_MIN * 60))
awk -v ref="$ref" -v win="$win" \
    '$1 ~ /^[0-9]+\./ && ($1 + 0) >= (ref - win)' \
    "$TMP/logcat.txt" > "$TMP/recent.txt"
mpl_count=$(grep -a -c 'MPL-SOTER' "$TMP/recent.txt" 2>/dev/null || true)
[ -n "$mpl_count" ] || mpl_count=0
missing_count=$(grep -a 'MPL-SOTER' "$TMP/recent.txt" 2>/dev/null | grep -a -c 'hook=MISSING' || true)
[ -n "$missing_count" ] || missing_count=0

if [ "$delta" -gt 900 ]; then
    fail C2 "no MPL-SOTER hook=MISSING in the last $WINDOW_MIN min" \
        "cannot prove absence: latest device log line is ${delta}s old (stale)" \
        "heartbeats should arrive every ~15s; check the module/daemon and re-run"
elif [ "$mpl_count" -eq 0 ]; then
    fail C2 "no MPL-SOTER hook=MISSING in the last $WINDOW_MIN min" \
        "0 MPL-SOTER records in the window: absence cannot be proven" \
        "window ref=$ref ($(date -d "@$ref" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "epoch $ref"))"
elif [ "$missing_count" -gt 0 ]; then
    raw=$(grep -a 'MPL-SOTER' "$TMP/recent.txt" | grep -a 'hook=MISSING' | tail -n 5)
    fail C2 "no MPL-SOTER hook=MISSING in the last $WINDOW_MIN min" \
        "$missing_count of $mpl_count MPL-SOTER line(s) contain hook=MISSING" \
        "$raw"
else
    last_ok=$(grep -a 'MPL-SOTER' "$TMP/recent.txt" | tail -n 1)
    pass C2 "no MPL-SOTER hook=MISSING in the last $WINDOW_MIN min ($mpl_count records)"
    note "$last_ok"
fi

# --- C3: scope loaded n= with n > 0 ---------------------------------------
scope_last=$(grep -a -h 'scope loaded n=' "$TMP/logcat.txt" "$TMP/inject.txt" 2>/dev/null | tail -n 1)
if [ -z "$scope_last" ]; then
    scope_ctx=$(grep -a -h 'scope ' "$TMP/logcat.txt" "$TMP/inject.txt" 2>/dev/null | tail -n 3)
    [ -n "$scope_ctx" ] || scope_ctx="(no 'scope ' lines in logcat or $SOTER_LOG)"
    fail C3 "scope loaded n= appears with n > 0" \
        "no 'scope loaded n=' in logcat or $SOTER_LOG" \
        "expected after the WebUI scope list loads a non-empty selection" \
        "default all-allowed logs 'scope none src=default' instead, which does not satisfy this assertion" \
        "$scope_ctx"
else
    n=$(printf '%s\n' "$scope_last" | sed -n 's/.*scope loaded n=\([0-9][0-9]*\).*/\1/p' | tail -n 1)
    if [ -z "$n" ]; then
        fail C3 "scope loaded n= appears with n > 0" \
            "could not parse n from: $scope_last"
    elif [ "$n" -le 0 ]; then
        fail C3 "scope loaded n= appears with n > 0" \
            "scope loaded n=$n (expected n > 0)" "$scope_last"
    else
        pass C3 "scope loaded n=$n (> 0)"
        note "$scope_last"
    fi
fi

# --- C4: MPL-BUILD marker -------------------------------------------------
build_lines=$(grep -a 'MPL-BUILD' "$TMP/logcat.txt" 2>/dev/null | tail -n 3)
if [ -z "$build_lines" ]; then
    mpl_ctx=$(grep -a 'MPL-' "$TMP/logcat.txt" 2>/dev/null | tail -n 3)
    [ -n "$mpl_ctx" ] || mpl_ctx="(no MPL-* line at all)"
    fail C4 "MPL-BUILD marker is present in logcat" \
        "no MPL-BUILD line: the running dex build is unknown" \
        "if the device has been up for a long time the boot-time marker may have rotated out; reboot/reload the module and re-run" \
        "last MPL-* context:" "$mpl_ctx"
else
    pass C4 "MPL-BUILD marker is present in logcat"
    while IFS= read -r line; do [ -n "$line" ] && note "$line"; done <<< "$build_lines"
fi

# --- summary ---------------------------------------------------------------
echo
echo "=================================================================="
echo "SUMMARY: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
echo "=================================================================="
[ "$FAIL" -eq 0 ] || exit 1
exit 0
