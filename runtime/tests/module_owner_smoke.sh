#!/bin/sh
# Root-only Linux fixture; use a separately compiled MAPLESU_OWNER_TEST binary.
set -eu
binary=$1
probe=$2
base=/tmp/maplesu-owner-test
test "$(id -u)" = 0
# Never overwrite an existing fixture or active owner.
test ! -e "$base"
umask 077
mkdir -m 700 "$base" "$base/modules" "$base/modules/alpha" "$base/modules/beta"
cleanup() { "$binary" shutdown >/dev/null 2>&1 || true; }
trap cleanup EXIT
for id in alpha beta; do
    cat > "$base/modules/$id/service.sh" <<'SCRIPT'
echo launch >> launches
# The daemon deliberately escapes the stage's original process group/session.
setsid sh -c 'sh -c '\''echo $$ > daemon.pid; while :; do echo beat >> beats; sleep 0.1; done'\'' &' &
exit 0
SCRIPT
    chmod 700 "$base/modules/$id/service.sh"
done
"$binary" ensure
"$binary" start alpha service
"$binary" start beta service
sleep 1
alpha_pid=$(cat "$base/modules/alpha/daemon.pid")
beta_pid=$(cat "$base/modules/beta/daemon.pid")
kill -0 "$alpha_pid" "$beta_pid"
"$binary" status | tee "$base/initial-status"
grep 'alpha service running .*leader_exit=0' "$base/initial-status"
grep 'beta service running .*leader_exit=0' "$base/initial-status"
before=$(wc -l < "$base/modules/alpha/beats")
sleep 0.4
after=$(wc -l < "$base/modules/alpha/beats")
test "$after" -gt "$before"
echo 'PASS detached descendants survive stage and launching CLI exit'
"$binary" ensure
"$binary" start alpha service | grep 'already-recorded'
test "$(wc -l < "$base/modules/alpha/launches")" = 1
echo 'PASS same-boot start deduplication'
"$binary" stop alpha service
sleep 0.5
if kill -0 "$alpha_pid" 2>/dev/null; then echo 'FAIL alpha survived stop'; exit 1; fi
kill -0 "$beta_pid"
"$binary" status alpha service | grep 'stopped'
echo 'PASS stop targets only owned task including setsid descendants'
"$binary" shutdown
sleep 0.5
if kill -0 "$beta_pid" 2>/dev/null; then echo 'FAIL beta survived shutdown'; exit 1; fi
echo 'PASS normal owner shutdown cleans remaining tasks'
"$binary" ensure
"$binary" start alpha service | grep 'already-recorded'
test "$(wc -l < "$base/modules/alpha/launches")" = 1
echo 'PASS ledger survives owner restart without executing a stage twice'
mkdir -m 700 "$base/modules/invalid"
ln -s ../beta/service.sh "$base/modules/invalid/service.sh"
if "$binary" start invalid service; then echo 'FAIL symlink script accepted'; exit 1; fi
rm "$base/modules/invalid/service.sh"
cp "$base/modules/beta/service.sh" "$base/modules/invalid/service.sh"
chmod 777 "$base/modules/invalid"
if "$binary" start invalid service; then echo 'FAIL writable module accepted'; exit 1; fi
chmod 700 "$base/modules/invalid"
touch "$base/modules/invalid/disable"
if "$binary" start invalid service; then echo 'FAIL disabled module accepted'; exit 1; fi
echo 'PASS symlink, writable directory and disable marker checks'
# su is a local fixture utility, unrelated to the MapleSU product session path.
if su -s /bin/sh nobody -c "'$binary' status" > "$base/nonroot-output" 2>&1; then
    echo 'FAIL nonroot caller accepted'; exit 1
fi
grep 'real and effective Root required' "$base/nonroot-output"
echo 'PASS nonroot CLI rejected'
"$probe"
echo 'PASS IPC rejects nonroot real UID even with effective Root'
# A killed owner still triggers each independent supervisor's parent-death cleanup.
mkdir -m 700 "$base/modules/gamma"
cp "$base/modules/beta/service.sh" "$base/modules/gamma/service.sh"
"$binary" start gamma service
sleep 0.4
gamma_pid=$(cat "$base/modules/gamma/daemon.pid")
owner_pid=$("$binary" status | head -n 1 | sed -n 's/.* owner=\([0-9]*\).*/\1/p')
kill -KILL "$owner_pid"
sleep 0.5
if kill -0 "$gamma_pid" 2>/dev/null; then echo 'FAIL task survived killed owner'; exit 1; fi
"$binary" ensure
"$binary" status gamma service | grep interrupted
"$binary" start gamma service | grep already-recorded
test "$(wc -l < "$base/modules/gamma/launches")" = 1
echo 'PASS abrupt owner death cleans task and interrupted journal prevents replay'
"$binary" shutdown
sleep 0.3
trap - EXIT
echo "PASS fixture retained for inspection at $base"
