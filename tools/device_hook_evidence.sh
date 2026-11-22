#!/usr/bin/env bash
# One-shot hook attempt + evidence collection.
#
# The device is flaky: it reboots during attempts and sometimes stays away for a
# while. This script therefore never assumes a boot; it waits, reports, and prints the
# kernel-side verdict lines that decide whether the jailbreak chain worked.
#
#   tools/device_hook_evidence.sh            # run the attempt on the current boot
#   tools/device_hook_evidence.sh --reboot   # reboot first (one attempt per boot)
set -u

SERIAL="${MAPLESU_SERIAL:-}"
ADB="adb"
if [ -n "$SERIAL" ]; then ADB="adb -s $SERIAL"; fi
PKG=dev.maplesu.manager
TEST_PKG=dev.maplesu.manager.test
RUNNER=androidx.test.runner.AndroidJUnitRunner
CLASS='dev.maplesu.manager.jailbreak.RootHookAndroidTest#hookHandsOverAndUnloads'
DE="/data/user_de/0/$PKG"

wait_boot() {
    for _ in $(seq 1 60); do
        if $ADB shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' | grep -q '^1$'; then
            return 0
        fi
        sleep 5
    done
    return 1
}

if ! $ADB devices 2>/dev/null | tail -n +2 | grep -q device; then
    echo "FAIL no device attached (adb devices is empty)"
    exit 2
fi

if [ "${1:-}" = "--reboot" ]; then
    before=$($ADB shell cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r')
    $ADB reboot >/dev/null 2>&1
    sleep 10
    $ADB wait-for-device 2>/dev/null
    wait_boot || { echo "FAIL device did not finish booting"; exit 3; }
    after=$($ADB shell cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r')
    echo "boot: $before -> $after"
else
    echo "boot: $($ADB shell cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r')"
fi

$ADB logcat -c >/dev/null 2>&1
echo "=== attempt ==="
timeout 300 $ADB shell am instrument -w -e class "$CLASS" "$TEST_PKG/$RUNNER" 2>&1 | head -12

echo "=== kernel verdict ==="
$ADB shell "run-as $PKG cat $DE/maplesu-provider.log 2>/dev/null" \
    | grep -aE 'maplesu-hook: (verdict|attest reverse|restore)' | tail -6

echo "=== attestation record ==="
$ADB shell "run-as $PKG cat $DE/maplesu-hook-attest.json 2>/dev/null" | head -c 400; echo

echo "=== daemon record ==="
$ADB shell "run-as $PKG cat $DE/maplesu-hook-daemon.json 2>/dev/null" | head -c 300; echo

echo "=== app-side attestation log ==="
$ADB logcat -d -s MapleSUHookAttest:W MapleSUHookWorker:W 2>/dev/null | tail -6

echo "=== device alive? ==="
$ADB shell cat /proc/sys/kernel/random/boot_id 2>&1 | tr -d '\r'
