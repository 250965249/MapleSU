#!/bin/sh
# Run with Alpine BusyBox in an isolated container; no Android device or build.
set -eu

assets=${1:?module assets directory}
sample=${2:-}
suite=$(mktemp -d)
trap 'rm -rf "$suite"' EXIT
passed=0
failed=0

fixture() {
  root=$(mktemp -d "$suite/case.XXXXXX")
  export TEST_ROOT="$root" MAPLESU_BIN="$root/adb/maplesu/bin"
  mkdir -p "$MAPLESU_BIN" "$root/adb/modules/fixture" "$root/bin"
  ln -s "${MAPLESU_TEST_BUSYBOX:-/bin/busybox}" "$MAPLESU_BIN/busybox"
  printf '#!/bin/sh\necho 36\n' > "$root/bin/getprop"
  chmod 755 "$root/bin/getprop"
  for name in run.sh runner.sh legacy-install.sh ui-print.sh; do
    [ -f "$assets/$name" ] || continue
    sed -e "s|/system/bin/getprop|$root/bin/getprop|g" \
        -e 's|/system/bin/sh|/bin/sh|g' \
        -e "s|/data/adb|$root/adb|g" \
        -e "s|/sys/fs/cgroup|$root/cgroups/unified|g" \
        -e "s|/dev/cg2_bpf|$root/cgroups/bpf|g" \
        -e "s|/dev/memcg/apps|$root/cgroups/memcg|g" \
        -e "s|/acct|$root/cgroups/acct|g" \
        "$assets/$name" > "$root/$name"
  done
  if [ -f "$root/ui-print.sh" ]; then
    cp "$root/ui-print.sh" "$MAPLESU_BIN/ui_print"
    chmod 755 "$MAPLESU_BIN/ui_print"
  fi
  printf 'id=fixture\nname=Fixture\nversionCode=1\n' > "$root/adb/modules/fixture/module.prop"
  export PATH="/usr/bin:/bin:$MAPLESU_BIN"
}

wait_file() {
  tries=0
  while [ ! -s "$1" ] && [ "$tries" -lt 100 ]; do
    sleep .02
    tries=$((tries + 1))
  done
  [ -s "$1" ]
}

constant_service() {
  cat > "$root/adb/modules/fixture/$1.sh" <<'SCRIPT'
MODDIR=${0%/*}
printf '%s\n' "$$" > "$TEST_ROOT/service.pid"
printf '%s|%s|%s|%s\n' "$0" "$PWD" "$KSU" "$KSU_MODULE" > "$TEST_ROOT/identity"
trap 'echo stopped > "$TEST_ROOT/stopped"' EXIT
while [ ! -e "$MODDIR/disable" ] && [ ! -e "$MODDIR/remove" ]; do
  echo beat >> "$TEST_ROOT/beats"
  echo SERVICE_STDOUT
  echo SERVICE_STDERR >&2
  sleep .02
done
SCRIPT
}

background_survives_owner() {
  fixture
  stage=$1
  wait_ms=$2
  if [ "$wait_ms" != 0 ]; then wait_ms=$(awk -v wait="$wait_ms" '{printf "%.0f", $1 * 1000 + wait}' /proc/uptime); fi
  constant_service "$stage"
  # The production Root owner kills the launcher's process group when it closes.
  setsid /bin/sh -c '
    echo $$ > "$TEST_ROOT/owner.pid"
    /bin/sh "$TEST_ROOT/run.sh" "$TEST_ROOT/adb/modules/fixture" "$1" "$2" > "$TEST_ROOT/output" 2> "$TEST_ROOT/error"
    echo $? > "$TEST_ROOT/launch.code"
    sleep 30
  ' fixture "$stage" "$wait_ms" &
  launcher=$!
  if ! wait_file "$root/launch.code"; then
    kill -KILL -- "-$launcher" 2>/dev/null || :
    echo "$stage blocked dispatch instead of returning after launch" >&2
    return 1
  fi
  kill -KILL -- "-$launcher" 2>/dev/null || :
  [ "$(cat "$root/launch.code")" = 0 ] || { cat "$root/launch.code" "$root/output" "$root/error" >&2; return 1; }
  grep -qx MAPLESU_SCRIPT_STARTED "$root/output" || return 1
  [ ! -s "$root/error" ] || { cat "$root/error" >&2; return 1; }
  wait_file "$root/beats" || return 1
  before=$(wc -l < "$root/beats")
  sleep .15
  after=$(wc -l < "$root/beats")
  [ "$after" -gt "$before" ] || return 1
  grep -q "fixture/$stage.sh|$root/adb/modules/fixture|true|fixture" "$root/identity" || return 1
  touch "$root/adb/modules/fixture/disable"
  wait_file "$root/stopped"
}

ui_print_in_nested_uninstall() {
  fixture
  cat > "$root/adb/modules/fixture/uninstall.sh" <<'SCRIPT'
set -e
MODDIR=${0%/*}
test "$PWD" = "$MODDIR"
trap 'echo exit-trap > "$TEST_ROOT/trap"' EXIT
ui_print 'main uninstall'
"$MAPLESU_BIN/busybox" sh "$MODDIR/nested.sh"
SCRIPT
  printf 'ui_print "nested uninstall"\n' > "$root/adb/modules/fixture/nested.sh"
  /bin/sh "$root/run.sh" "$root/adb/modules/fixture" uninstall > "$root/output" || return 1
  [ "$(cat "$root/output")" = "$(printf 'main uninstall\nnested uninstall')" ] || return 1
  grep -qx exit-trap "$root/trap"
}

ui_print_in_provider() {
  fixture
  mkdir -p "$root/adb/metamodule"
  printf 'id=provider\nmetamodule=true\n' > "$root/adb/metamodule/module.prop"
  cat > "$root/adb/metamodule/metauninstall.sh" <<'SCRIPT'
set -e
test "$MODULE_ID" = fixture
test "$KSU_MODULE" = provider
test "$PWD" = "${0%/*}"
ui_print provider
SCRIPT
  printf 'ui_print own\n' > "$root/adb/modules/fixture/uninstall.sh"
  /bin/sh "$root/run.sh" "$root/adb/modules/fixture" uninstall > "$root/output" || return 1
  [ "$(cat "$root/output")" = "$(printf 'provider\nown')" ]
}

ui_print_upgrade_bootstrap() {
  fixture
  rm -f "$MAPLESU_BIN/ui_print"
  printf 'ui_print upgraded\n' > "$root/adb/modules/fixture/uninstall.sh"
  /bin/sh "$root/run.sh" "$root/adb/modules/fixture" uninstall > "$root/output" || return 1
  [ -x "$MAPLESU_BIN/ui_print" ] && grep -qx upgraded "$root/output"
}

foreground_exit_code() {
  fixture
  printf 'exit 23\n' > "$root/adb/modules/fixture/post-fs-data.sh"
  code=0
  deadline_ms=$(awk '{printf "%.0f", $1 * 1000 + 1000}' /proc/uptime)
  /bin/sh "$root/run.sh" "$root/adb/modules/fixture" post-fs-data "$deadline_ms" > "$root/output" 2> "$root/error" || code=$?
  [ "$code" = 23 ]
}

public_script_contract() {
  fixture
  mkdir -p "$root/adb/service.d"
  cat > "$root/adb/service.d/fixture.sh" <<'SCRIPT'
test -z "${KSU_MODULE:-}" || exit 31
test "$KSU" = true || exit 32
test "$PWD" = "${0%/*}" || exit 33
ui_print ignored
echo ready > "$TEST_ROOT/public"
SCRIPT
  KSU_MODULE=inherited /bin/sh "$root/run.sh" "$root/adb/service.d" service 0 fixture.sh > "$root/output" || return 1
  wait_file "$root/public" || return 1
  grep -qx MAPLESU_SCRIPT_STARTED "$root/output"
}

missing_script_fails() {
  fixture
  code=0
  /bin/sh "$root/run.sh" "$root/adb/modules/fixture" service > "$root/output" 2> "$root/error" || code=$?
  [ "$code" != 0 ] && ! grep -q MAPLESU_SCRIPT_STARTED "$root/output"
}

early_receipt_prevents_duplicate() {
  fixture
  mkdir -p "$root/adb/modules/fixture/zygisk" "$root/adb/maplesu_zygisk"
  cat /proc/sys/kernel/random/boot_id > "$root/adb/maplesu_zygisk/early.boot"
  printf 'echo run >> "$TEST_ROOT/count"\n' > "$root/adb/modules/fixture/service.sh"
  /bin/sh "$root/run.sh" "$root/adb/modules/fixture" service > "$root/one" || return 1
  /bin/sh "$root/run.sh" "$root/adb/modules/fixture" service > "$root/two" || return 1
  wait_file "$root/count" || return 1
  [ "$(wc -l < "$root/count")" = 1 ] || return 1
  grep -qx MAPLESU_SCRIPT_STARTED "$root/one" && grep -qx MAPLESU_SCRIPT_STARTED "$root/two"
}

shared_deadline_is_not_restarted() {
  fixture
  constant_service post-fs-data
  constant_service post-mount
  deadline_ms=$(awk '{printf "%.0f", $1 * 1000 + 100}' /proc/uptime)
  /bin/sh "$root/run.sh" "$root/adb/modules/fixture" post-fs-data "$deadline_ms" > "$root/first" || return 1
  # The budget is already exhausted; a second stage must still launch and return.
  timeout -s KILL 1 /bin/sh "$root/run.sh" "$root/adb/modules/fixture" post-mount "$deadline_ms" > "$root/second" || return 1
  grep -qx MAPLESU_SCRIPT_STARTED "$root/first" && grep -qx MAPLESU_SCRIPT_STARTED "$root/second" || return 1
  touch "$root/adb/modules/fixture/remove"
}

failed_shell_launch_is_not_success() {
  fixture
  printf 'exit 0\n' > "$root/adb/modules/fixture/service.sh"
  rm "$MAPLESU_BIN/busybox"
  cat > "$MAPLESU_BIN/busybox" <<'SCRIPT'
#!/bin/sh
if [ "$1" = setsid ]; then exit 71; fi
exec /bin/busybox "$@"
SCRIPT
  chmod 755 "$MAPLESU_BIN/busybox"
  code=0
  /bin/sh "$root/run.sh" "$root/adb/modules/fixture" service > "$root/output" 2> "$root/error" || code=$?
  [ "$code" != 0 ] && ! grep -q MAPLESU_SCRIPT_STARTED "$root/output"
}

cgroup_and_umask_contract() {
  fixture
  for group in acct bpf unified memcg; do
    mkdir -p "$root/cgroups/$group"
    : > "$root/cgroups/$group/cgroup.procs"
  done
  printf 'umask > "$TEST_ROOT/umask"\n' > "$root/adb/modules/fixture/post-fs-data.sh"
  deadline_ms=$(awk '{printf "%.0f", $1 * 1000 + 1000}' /proc/uptime)
  /bin/sh "$root/run.sh" "$root/adb/modules/fixture" post-fs-data "$deadline_ms" > "$root/output" || return 1
  for group in acct bpf unified memcg; do [ -s "$root/cgroups/$group/cgroup.procs" ] || return 1; done
  test "$(cat "$root/umask")" = 0000
}

coregate_uninstall() {
  fixture
  [ -f "$sample/uninstall.sh" ] || return 1
  mkdir -p "$root/adb/CoreGate" "$root/local/CoreGate"
  echo fixture > "$root/adb/CoreGate/config.json"
  sed -e "s|/data/adb|$root/adb|g" -e "s|/data/local/tmp|$root/local|g" \
      -e "s|/sys/|$root/sys/|g" "$sample/uninstall.sh" > "$root/adb/modules/fixture/uninstall.sh"
  /bin/sh "$root/run.sh" "$root/adb/modules/fixture" uninstall > "$root/output" 2> "$root/error" || return 1
  [ ! -d "$root/adb/CoreGate" ] && [ ! -d "$root/local/CoreGate" ] && [ ! -s "$root/error" ]
}

check() {
  name=$1; shift
  if ( "$@" ); then
    passed=$((passed + 1)); printf 'PASS %s\n' "$name"
  else
    failed=$((failed + 1)); printf 'FAIL %s\n' "$name"
  fi
}

check ui_print_nested ui_print_in_nested_uninstall
check ui_print_metamodule ui_print_in_provider
check ui_print_existing_install_upgrade ui_print_upgrade_bootstrap
check service_detaches background_survives_owner service 0
check completion_detaches background_survives_owner boot-completed 0
check post_fs_deadline_does_not_kill background_survives_owner post-fs-data 100
check post_mount_deadline_does_not_kill background_survives_owner post-mount 100
check early_exit_code foreground_exit_code
check public_script_environment public_script_contract
check missing_script_is_failure missing_script_fails
check early_host_deduplicates early_receipt_prevents_duplicate
check early_stages_share_deadline shared_deadline_is_not_restarted
check failed_shell_is_failure failed_shell_launch_is_not_success
check cgroups_and_umask cgroup_and_umask_contract
if [ -n "$sample" ]; then check coregate_uninstall coregate_uninstall; fi
printf 'Passed: %s; failed: %s\n' "$passed" "$failed"
test "$failed" = 0
