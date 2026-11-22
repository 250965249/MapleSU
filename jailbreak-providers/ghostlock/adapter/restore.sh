# Derived from pinned Ghostlock attack/ops.cpp (Apache-2.0).
# Only upstream serialization repair and original boolean restoration precede
# the MapleSU consumer. No third-party service, modules or partition operations.
[ "$(id -u)" = 0 ] || exit 70
# W1 changes the enforcement variable directly, without updating the status
# page. Read that page here, before our first policy reload. App EACCES must
# not discard the only observable pre-repair history.
maplesu_status_snapshot() {
  for STATUS_TRY in 1 2 3 4; do
    STATUS_WORDS=$(od -An -v -tu4 -N20 /sys/fs/selinux/status 2>/dev/null) || continue
    set -- $STATUS_WORDS
    [ "$#" = 5 ] || continue
    case "$1:$2:$3:$4:$5" in *[!0-9:]*) continue ;; esac
    [ "$1" = 1 ] && [ "$(( $2 & 1 ))" = 0 ] &&
      [ "$3" = 1 ] && [ "$5" -le 1 ] || continue
    STATUS_AGAIN=$(od -An -v -tu4 -N20 /sys/fs/selinux/status 2>/dev/null) || continue
    [ "$STATUS_WORDS" = "$STATUS_AGAIN" ] || continue
    printf '%s,%s,%s,%s,%s' "$1" "$2" "$3" "$4" "$5"
    return 0
  done
  return 1
}
SELINUX_WINDOW_BEFORE=$(maplesu_status_snapshot) || SELINUX_WINDOW_BEFORE=
echo 'maplesu-ghostlock: root worker entered serialization repair' >&2
# Interpreter already owns its open script; remove nonce-bearing directory entry.
rm -f "$HOME_DIR/.ghostlock_root.sh" || exit 70
POLICY=$(mktemp "$HOME_DIR/.maplesu_policy.XXXXXX") || exit 71
trap 'rm -f "$POLICY"' EXIT
prepare_policy() {
  cat /sys/fs/selinux/policy >"$POLICY" || return 1
  HEADER=$(od -An -tx1 -N24 "$POLICY" | tr -d ' \n')
  case "$HEADER" in
    8cff7cf9080000005345204c696e7578????????????????) ;;
    *) return 1 ;;
  esac
  # Upstream repair of Android netlink configuration bits in byte 23.
  CONFIG=$(od -An -tu1 -j23 -N1 "$POLICY") || return 1
  [ -n "$CONFIG" ] || return 1
  CONFIG=$(printf '\\0%03o' "$((CONFIG | 192))") || return 1
  printf '%b' "$CONFIG" | dd of="$POLICY" bs=1 seek=23 count=1 conv=notrunc
}
# The upstream stage changes checkreqprot before serialized policy repair.
# Capture came from the ordinary-App process before starting that stage.
# -2 is a proven absence: never create the entry upstream would write. The
# rooted preamble resolves App EACCES/EPERM to -2 only when absence is proven;
# an unresolved -1 still requires writing and reading the documented baseline 0.
case "$BASELINE_CHECKREQPROT" in
  -2) ;;
  0|1|-1) echo 0 > /sys/fs/selinux/checkreqprot || exit 72 ;;
  *) echo 'maplesu-ghostlock: invalid checkreqprot baseline' >&2; exit 72 ;;
esac
FIXUP_RC=1
for i in $(seq 1 10); do
  echo "maplesu-ghostlock: policy repair attempt=$i/10" >&2
  if ! prepare_policy; then
    echo 'maplesu-ghostlock: policy preparation failed; retrying' >&2
    sleep 2
    continue
  fi
  BEFORE=$(od -An -tu4 -j12 -N4 /sys/fs/selinux/status | tr -d ' ')
  echo "maplesu-ghostlock: policy load begin status=$BEFORE" >&2
  load_policy "$POLICY" &
  LPID=$!
  (sleep 8; kill -9 "$LPID" 2>/dev/null) &
  SPID=$!
  wait "$LPID" 2>/dev/null
  FIXUP_RC=$?
  kill "$SPID" 2>/dev/null
  # Match upstream: cancel the watchdog without waiting for its termination.
  # Only the policy loader's status is part of the serialization repair verdict.
  echo "maplesu-ghostlock: policy load exit=$FIXUP_RC" >&2
  if [ "$FIXUP_RC" = 0 ]; then
    AFTER=$(od -An -tu4 -j12 -N4 /sys/fs/selinux/status | tr -d ' ')
    echo "maplesu-ghostlock: policyload before=$BEFORE after=$AFTER" >&2
    if [ -n "$BEFORE" ] && [ -n "$AFTER" ] && [ "$BEFORE" != "$AFTER" ]; then break; fi
    FIXUP_RC=1
  fi
  sleep 2
done
# Preserve upstream failure behavior: do not assert policy restoration or
# enable enforcing over an unsuccessful serialization repair.
[ "$FIXUP_RC" = 0 ] || { echo 'maplesu-ghostlock: serialization repair failed' >&2; exit 73; }
echo 'maplesu-ghostlock: serialization repair complete' >&2
# 0/1: observed, restore exactly and verify. -2: the App proved ENOENT, so
# assert the entry is still absent. -1: the App domain could not read the path,
# so apply the documented Android baseline 0 and say explicitly that
# this is a baseline, never an observed entry value.
case "$BASELINE_CHECKREQPROT" in
  0|1)
    echo "$BASELINE_CHECKREQPROT" > /sys/fs/selinux/checkreqprot || exit 74
    [ "$(cat /sys/fs/selinux/checkreqprot)" = "$BASELINE_CHECKREQPROT" ] || exit 74
    ;;
  -2)
    [ ! -e /sys/fs/selinux/checkreqprot ] || exit 74
    ;;
  -1)
    echo 0 > /sys/fs/selinux/checkreqprot || exit 74
    [ "$(cat /sys/fs/selinux/checkreqprot)" = 0 ] || exit 74
    echo 'maplesu-ghostlock: checkreqprot baseline 0 applied; not the observed entry value (app domain could not read it)' >&2
    ;;
  *)
    echo 'maplesu-ghostlock: invalid checkreqprot baseline' >&2
    exit 74
    ;;
esac
rm -f "$POLICY" || exit 75
trap - EXIT
# 0/1: observed, restore exactly and verify. -1: the entry exists but the App
# domain could not read it. -2: the entry does not exist. For both unobservable
# cases the documented Android baseline (verified boot, enforcing=1) is applied
# and the caller records that the value is a baseline, never the observed value.
NOTE=
case "$BASELINE_ENFORCING" in
  0|1) TARGET_ENFORCING=$BASELINE_ENFORCING ;;
  -1)
    TARGET_ENFORCING=1
    NOTE='maplesu-ghostlock: enforcing baseline 1 applied; not the observed entry value (app domain could not read it)'
    ;;
  -2)
    TARGET_ENFORCING=1
    NOTE='maplesu-ghostlock: enforcing baseline 1 applied; not the observed entry value (entry absent from the app domain)'
    ;;
  *)
    echo 'maplesu-ghostlock: invalid enforcing baseline' >&2
    exit 76
    ;;
esac
# Publish before the helper re-enables enforcing; afterwards this shell may
# lose pathname access. A missing/unstable page is handled by the explicitly
# labelled kernel default, never by substituting guessed device counters.
SELINUX_WINDOW_AFTER=$(maplesu_status_snapshot) || SELINUX_WINDOW_AFTER=
SELINUX_RESTORE_FROM=$(cat /sys/fs/selinux/enforce 2>/dev/null)
if [ -n "$SELINUX_WINDOW_BEFORE" ] && [ -n "$SELINUX_WINDOW_AFTER" ] &&
   [ -n "$SELINUX_ATTEMPT_ID" ] && [ -n "$SELINUX_BOOT_ID" ]; then
  case "$SELINUX_RESTORE_FROM" in
    0|1)
      (umask 077
       printf '{"schema":"maplesu.selinux.window.v1","provider":"ghostlock","bootId":"%s","attempt":"%s","before":[%s],"after":[%s],"restoreFrom":%s,"restoreTo":%s}\n' \
         "$SELINUX_BOOT_ID" "$SELINUX_ATTEMPT_ID" "$SELINUX_WINDOW_BEFORE" \
         "$SELINUX_WINDOW_AFTER" "$SELINUX_RESTORE_FROM" "$TARGET_ENFORCING" \
         >"$HOME_DIR/selinux-window.json.tmp" &&
       chmod 0644 "$HOME_DIR/selinux-window.json.tmp" &&
       mv -f "$HOME_DIR/selinux-window.json.tmp" "$HOME_DIR/selinux-window.json") ||
        echo 'maplesu-ghostlock: status window persistence failed; kernel default required' >&2
      ;;
  esac
fi
# Backend loading belongs after Ghostlock's serialization repair and before
# enforcement is restored. A load failure still goes through the restore tail.
HANDOVER_RC=0
if command -v maplesu_handover_pre >/dev/null 2>&1; then
  echo 'maplesu-ghostlock: backend handover begin' >&2
  maplesu_handover_pre || HANDOVER_RC=$?
  echo "maplesu-ghostlock: backend handover exit=$HANDOVER_RC" >&2
fi
# A freshly loaded KSU already restores enforcing. Its policy may revoke this
# shell's write permission, so require a write only when the value differs.
if [ "$(cat /sys/fs/selinux/enforce)" != "$TARGET_ENFORCING" ]; then
  echo "$TARGET_ENFORCING" > /sys/fs/selinux/enforce || exit 76
fi
[ "$(cat /sys/fs/selinux/enforce)" = "$TARGET_ENFORCING" ] || exit 76
echo "maplesu-ghostlock: enforcing restored=$TARGET_ENFORCING" >&2
[ -z "$NOTE" ] || echo "$NOTE" >&2
# Boolean readback is not a policy-identity proof. The App still applies the
# separate restoration and daemon gates after authenticated lease delivery.

# The manager checks the attempt-bound backend receipt independently. A backend
# failure must not turn a verified SELinux restore into a restoration failure.
[ "$HANDOVER_RC" = 0 ] || echo "maplesu-ghostlock: handover failed rc=$HANDOVER_RC" >&2
# Diagnostic transport is not a restoration verdict; all required readbacks passed.
exit 0
