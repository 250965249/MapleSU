#!/usr/bin/env bash
# End-to-end verification for the non-resident root work.
# One command, one evidence bundle. Requires an authorized device.
set -u

SERIAL="${SERIAL:-${ANDROID_SERIAL:-}}"
[ -n "$SERIAL" ] || { echo "set SERIAL or ANDROID_SERIAL to the device serial (see adb devices)" >&2; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/.analysis/root-nonresident-20261027/measures"
APK="$ROOT/manager/build/outputs/apk/debug/manager-debug.apk"
TEST_APK="$ROOT/manager/build/outputs/apk/androidTest/debug/manager-debug-androidTest.apk"
RUNNER="dev.maplesu.manager.test/androidx.test.runner.AndroidJUnitRunner"
ADB="adb -s $SERIAL"

# gradle needs a JDK 21 (the build targets source release 21) and the SDK. When JAVA_HOME points at
# an older JDK, javac fails with "invalid source release: 21"; set MAPLESU_JAVA_HOME to a JDK 21 and
# it wins over JAVA_HOME. The SDK comes from ANDROID_HOME or ANDROID_SDK_ROOT.
JAVA_HOME="${MAPLESU_JAVA_HOME:-${JAVA_HOME:-}}"
ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
[ -n "$JAVA_HOME" ] || { echo "set MAPLESU_JAVA_HOME or JAVA_HOME to a JDK 21" >&2; exit 2; }
[ -n "$ANDROID_HOME" ] || { echo "set ANDROID_HOME or ANDROID_SDK_ROOT" >&2; exit 2; }
export JAVA_HOME ANDROID_HOME

mkdir -p "$OUT"
summary="$OUT/verify-summary.txt"
: > "$summary"

log() { echo "$*" | tee -a "$summary"; }

log "== verification $(date -u +%Y-%m-%dT%H:%M:%SZ) device=$SERIAL =="

# gradle on this host occasionally fails a task while another daemon still holds the build
# directory; the failure is not reproducible and the same command succeeds immediately
# afterwards. Retrying once, with the full log kept, distinguishes that from a real error.
gradle_task() {
  local name="$1"; shift
  local log_file="$OUT/gradle-$name.log"
  local attempt=1
  while [ "$attempt" -le 2 ]; do
    if (cd "$ROOT" && ./gradlew.bat "$@" --offline --no-configuration-cache --console=plain \
        -PmaplesuPython="${MAPLESU_PYTHON:-python}" \
        ${MAPLESU_PROVIDER_NDK:+"-PmaplesuProviderNdk=$MAPLESU_PROVIDER_NDK"}) >"$log_file" 2>&1; then
      log "  $name: $(grep -E 'BUILD (SUCCESSFUL|FAILED)' "$log_file" | tail -1)"
      return 0
    fi
    log "  $name: attempt $attempt failed ($(grep -E 'FAILED|error:' "$log_file" | head -1))"
    attempt=$((attempt + 1))
    sleep 3
  done
  return 1
}

# Host-side checks run first: they need no device, so a failure here is never blamed on the
# hardware, and a green run is the cheapest evidence that the build is coherent.
log "-- host unit tests"
gradle_task unit-tests :manager:testDebugUnitTest
log "-- build"
gradle_task build :manager:assembleDebug :manager:assembleDebugAndroidTest

if ! $ADB get-state >/dev/null 2>&1; then
  log "DEVICE UNAVAILABLE: the host checks above are the only evidence this run can produce"
  exit 1
fi

log "-- install"
$ADB install -r -d --no-streaming "$APK" 2>&1 | tail -1 | tee -a "$summary"
$ADB install -r -d --no-streaming "$TEST_APK" 2>&1 | tail -1 | tee -a "$summary"

log "-- settle"
$ADB shell am start -W -n dev.maplesu.manager/com.maplesu.core.ui.MainActivity >/dev/null 2>&1
sleep 12

run_test() {
  local cls="$1" name="$2"
  $ADB logcat -c
  local result
  result=$(timeout 420 $ADB shell am instrument -w \
    -e verifyMapleSuBoot true -e verifySuPolicyMutations true \
    -e class "$cls" "$RUNNER" 2>&1 | grep -E "OK \(|FAILURES|Process crashed" | head -1)
  log "  $name -> ${result:-no result}"
}

log "-- tests"
run_test dev.maplesu.manager.runtime.DeliveredSessionAndroidTest "session(streams/exit/fds/cancel)"
run_test dev.maplesu.manager.runtime.ZeroLibRootAndroidTest "zero-library root"
run_test dev.maplesu.manager.runtime.AuthorizeDeliversAndroidTest "authorize delivers / revoke withdraws"
run_test dev.maplesu.manager.runtime.SuperuserListCostAndroidTest "list cost"

log "-- invariants"
log "  enforcing=$($ADB shell getenforce | tr -d '\r')"
log "  publication_mounts=$($ADB shell 'cat /proc/self/mountinfo' | grep -cE ' /data/[0-9a-f]{16}/su ')"
log "  resident_root=$($ADB shell 'ps -A -o USER,NAME' | grep -E '^root +dev\.maplesu|^root +libmaplesu' | grep -vc daemon)"

log "-- evidence"
grep -h "MAPLESU_EVIDENCE" "$OUT"/*.txt 2>/dev/null | tail -8 | tee -a "$summary"
log "== done =="
