#!/usr/bin/env bash
# Full acceptance pass in one go: attempt + attestation evidence + mount/enforcing
# comparison across a reboot (D3, D4, D6).
#
# The device is flaky and reboots by itself during attempts, so every step here
# tolerates a missing device and reports instead of aborting.
#
#   tools/device_acceptance.sh            # attempt on the current boot, then compare
#   tools/device_acceptance.sh --reboot   # reboot first (one attempt per boot)
set -u

ADB="adb"
PKG=dev.maplesu.manager
TEST_PKG=dev.maplesu.manager.test
RUNNER=androidx.test.runner.AndroidJUnitRunner
CLASS='dev.maplesu.manager.jailbreak.RootHookAndroidTest#hookHandsOverAndUnloads'
DE="/data/user_de/0/$PKG"
OUT=".analysis/acceptance-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

sh_dev() { $ADB shell "$@" 2>/dev/null | tr -d '\r'; }
alive() { $ADB devices 2>/dev/null | tail -n +2 | grep -q device; }

wait_boot() {
    for _ in $(seq 1 90); do
        [ "$(sh_dev getprop sys.boot_completed)" = "1" ] && return 0
        sleep 5
    done
    return 1
}

snapshot() {  # $1 = label
    sh_dev "cat /proc/mounts" > "$OUT/mounts-$1.txt" 2>/dev/null
    sh_dev "cat /sys/fs/selinux/enforce" > "$OUT/enforce-$1.txt" 2>/dev/null
    sh_dev "cat /proc/sys/kernel/random/boot_id" > "$OUT/boot-$1.txt" 2>/dev/null
    echo "  $1: mounts=$(wc -l < "$OUT/mounts-$1.txt" 2>/dev/null | tr -d ' ') " \
         "enforce=$(cat "$OUT/enforce-$1.txt" 2>/dev/null) " \
         "boot=$(cat "$OUT/boot-$1.txt" 2>/dev/null)"
}

if ! alive; then
    echo "FAIL no device attached"
    exit 2
fi

if [ "${1:-}" = "--reboot" ]; then
    $ADB reboot >/dev/null 2>&1
    sleep 10
    $ADB wait-for-device 2>/dev/null
    wait_boot || { echo "FAIL device did not boot"; exit 3; }
fi

echo "=== before ==="
snapshot before

$ADB logcat -c >/dev/null 2>&1
echo "=== attempt ==="
timeout 300 $ADB shell am instrument -w -e class "$CLASS" "$TEST_PKG/$RUNNER" 2>&1 \
    | tee "$OUT/instrument.txt" | head -12

echo "=== after (same boot, if it survived) ==="
if alive; then
    snapshot after
else
    echo "  device went away during the attempt (this is the known flakiness)"
fi

echo "=== kernel verdict ==="
sh_dev "run-as $PKG cat $DE/maplesu-provider.log" | grep -aE \
    'maplesu-hook: (verdict|attest reverse|attest final|restore)' | tail -8 | tee "$OUT/verdict.txt"

echo "=== attestation evidence ==="
sh_dev "run-as $PKG cat $DE/maplesu-hook-attest.json" | tee "$OUT/attest.json" | head -c 400; echo
sh_dev "run-as $PKG cat $DE/maplesu-hook-daemon.json" | tee "$OUT/daemon.json" | head -c 400; echo

echo "=== app-side decision ==="
$ADB logcat -d -s MapleSUHookAttest:W MapleSUHookWorker:W 2>/dev/null | tail -8 | tee "$OUT/applog.txt"

echo "=== reboot and compare (D4, D6) ==="
if alive; then
    $ADB reboot >/dev/null 2>&1
    sleep 10
    $ADB wait-for-device 2>/dev/null
    if wait_boot; then
        snapshot postboot
        if [ -s "$OUT/mounts-before.txt" ] && [ -s "$OUT/mounts-postboot.txt" ]; then
            if diff -q <(awk '{print $1, $2, $3}' "$OUT/mounts-before.txt") \
                       <(awk '{print $1, $2, $3}' "$OUT/mounts-postboot.txt") \
                    > "$OUT/mounts-diff.txt"; then
                echo "  D6: no new mounts after reboot"
            else
                echo "  D6: mount table changed — see $OUT/mounts-diff.txt"
            fi
        fi
        echo "  D4: enforcing after reboot = $(cat "$OUT/enforce-postboot.txt" 2>/dev/null)"
    else
        echo "  device did not boot again"
    fi
fi

echo "=== summary ==="
echo "  artefacts: $OUT"
echo "  D3 needs: 'attest reverse connect ok' OR 'attest final enforcing=1' + app log 'no ucred'"
echo "  D4 needs: enforce-postboot.txt = 1"
echo "  D6 needs: no lines in mounts-diff.txt"
