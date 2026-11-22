#!/system/bin/sh
# MapleSU module stage script launcher.
#
# Executed as: <runner> <directory> <stage> [early-deadline-ms] [common-script-name]
# The runner then execs `<module-dir>/<stage>.sh` the way the pinned KSU userspace
# does, instead of sourcing it:
#
#   module.rs:343-344   Command::new(BUSYBOX_PATH).arg("sh").arg(<script path>)
#   module.rs:340       current_dir = script.parent()
#   module.rs:344       envs = get_common_script_envs(module_id)
#
# Why this file exists rather than `sh <script>` directly: it reproduces the exact
# upstream script contract that module installers depend on -
#
#   * `$0` is the script's own absolute path, so `MODDIR=${0%/*}` resolves to the
#     module directory. Sourcing the script instead (the previous behaviour) made
#     `$0` the runner, which silently broke every module that derives MODDIR that way.
#   * cwd is the module directory.
#   * PATH is the caller's PATH with the MapleSU tool directory appended, matching
#     `format!("{}:{}", env_var("PATH"), BINARY_DIR)` - appended, not prepended.
#
# Lifecycle scripts receive the same KSU compatibility environment as installers.
set -u

module_dir="${1:-}"
stage="${2:-}"
if [ -z "$module_dir" ] || [ -z "$stage" ]; then
  printf 'maplesu-module-runner: usage: run.sh <module-dir> <stage>\n' >&2
  exit 64
fi

common_script="${4:-}"
if [ "$stage" = hot-install ]; then
  case "$common_script" in ''|/*|*/../*|../*|*/..|..|*/./*|./*|*/.|.|*//*) exit 64 ;; esac
  resolved=$(readlink -f "$module_dir/$common_script") || exit 66
  case "$resolved" in "$module_dir"/*) [ -f "$resolved" ] || exit 66 ;; *) exit 73 ;; esac
else
  case "$common_script" in */*|.|..) exit 64 ;; esac
fi
script="$module_dir/${common_script:-$stage.sh}"
if [ ! -f "$script" ] && [ "$stage" != uninstall ]; then
  printf 'maplesu-module-runner: no %s.sh in %s\n' "$stage" "$module_dir" >&2
  exit 66
fi

# MapleSU tool directory, appended so a module cannot shadow platform tools.
MAPLESU_BIN=${MAPLESU_BIN:-/data/adb/maplesu/bin}
export PATH="${PATH:-/system/bin:/system/xbin}:$MAPLESU_BIN"
# Existing installations may reach a hook before the upgraded APK republishes its
# tools. Bootstrap only the missing helper, including in the early host path.
if [ ! -x "$MAPLESU_BIN/ui_print" ] && [ -x "$MAPLESU_BIN/busybox" ]; then
  ui_print_tmp=$("$MAPLESU_BIN/busybox" mktemp "$MAPLESU_BIN/.ui_print.XXXXXX") || exit 73
  cat > "$ui_print_tmp" <<'MAPLESU_UI_PRINT'
#!/system/bin/sh
printf '%s\n' "$*"
MAPLESU_UI_PRINT
  chmod 0755 "$ui_print_tmp" && mv -f "$ui_print_tmp" "$MAPLESU_BIN/ui_print" || exit 73
fi
if [ "$stage" = metamount ] || [ "$stage" = hot-install ]; then
  export MODULE_DIR=/data/adb/modules
  # Metamodule mounts must be visible from init and newly started applications.
  if [ "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)" ]; then
    exec "$MAPLESU_BIN/busybox" nsenter -t 1 -m -- /system/bin/sh "$0" "$@"
  fi
fi

# KSU exports this for every script it runs (module.rs:63-88); BusyBox ash reads it
# to run in standalone mode instead of expecting an applet-symlink layout.
export ASH_STANDALONE=1

# Compatibility variables select the module contract implemented by this backend.
export MAPLESU=true
export MAPLESU_BACKEND=module_v1
export KSU=true
maplesu_require_runtime_facts() {
  case "${KSU_VER_CODE:-}" in ''|*[!0-9]*) return 75 ;; esac
  case "${KSU_KERNEL_VER_CODE:-}" in ''|*[!0-9]*) return 75 ;; esac
  case "${KSU_UAPI_VER:-}" in ''|*[!0-9]*) return 75 ;; esac
  [ -n "${KSU_VER:-}" ] || return 75
  case "${KSU_FACT_SOURCE:-}" in
    legacy)
      # This Root transport has no installation-mode fact. Preserve that unknown.
      [ "${MAPLESU_RUNTIME_MODE:-}" = unknown ] || return 75
      [ -z "${KSU_RUNTIME_MODE+x}" ] && [ -z "${KSU_LATE_LOAD+x}" ] || return 75
      [ "${KSU_KERNEL_VER_CODE}" = 0 ] && [ "${KSU_UAPI_VER}" = 0 ] || return 75
      [ "${MAPLESU_KSU_COMPAT:-}" = 1 ] || return 75
      return 0 ;;
    hook)
      [ "${MAPLESU_RUNTIME_MODE:-}" = hotload ] && [ "${KSU_RUNTIME_MODE:-}" = late-load ] || return 75
      [ "${KSU_KERNEL_VER_CODE}" = 0 ] && [ "${KSU_UAPI_VER}" = 0 ] || return 75
      [ "${MAPLESU_KSU_COMPAT:-}" = 1 ] || return 75 ;;
    '') ;;
    *) return 75 ;;
  esac
  case "${KSU_RUNTIME_MODE:-}" in built-in|lkm|late-load) ;; *) return 75 ;; esac
  if [ "${KSU_RUNTIME_MODE}" = late-load ]; then
    [ "${KSU_LATE_LOAD:-}" = 1 ] || return 75
  else
    [ -z "${KSU_LATE_LOAD+x}" ] || [ "${KSU_LATE_LOAD}" = 0 ] || return 75
    unset KSU_LATE_LOAD
  fi
  return 0
}
if ! maplesu_require_runtime_facts; then
  printf '%s\n' 'maplesu: authenticated KSU runtime facts missing or invalid' >&2
  exit 75
fi
export MAPLESU_STAGE="$stage"
export BOOTMODE=true
# Module id is derivable from the path exactly like KSU does it, and is only
# exported when it is a plain single path segment.
module_id="${module_dir##*/}"
case "$module_id" in
  ''|*/*|.|..) ;;
  *) export MAPLESU_MODULE="$module_id" KSU_MODULE="$module_id" ;;
esac
if [ -n "$common_script" ] && [ "$stage" != hot-install ]; then
  # KSU common scripts share the shell environment, but belong to no module.
  unset MAPLESU_MODULE KSU_MODULE
fi

# Platform facts, read rather than assumed.
export API="$(/system/bin/getprop ro.build.version.sdk 2>/dev/null)"
export ARCH=arm64
export IS64BIT=true

cd "$module_dir" || exit 70

# Match KSU switch_cgroups: a module daemon must outlive its launching app.
for group in /acct /dev/cg2_bpf /sys/fs/cgroup; do
  if [ -f "$group/cgroup.procs" ]; then
    { printf '%s' "$$" >> "$group/cgroup.procs"; } 2>/dev/null || :
  fi
done
if [ "$(/system/bin/getprop ro.config.per_app_memcg 2>/dev/null)" != false ] &&
    [ -f /dev/memcg/apps/cgroup.procs ]; then
  { printf '%s' "$$" >> /dev/memcg/apps/cgroup.procs; } 2>/dev/null || :
fi

# Only the early boot stages wait, sharing KSU's absolute 35 second deadline.
# Their timeout stops waiting, never the script. Late stages acknowledge launch
# after setsid, close their stdio, and run independently of the Root IPC owner.
run_boot_script() {
  [ -x "$MAPLESU_BIN/busybox" ] || return 69
  wait_ms=0
  case "$stage" in
    post-fs-data|post-mount)
      now_ms=$("$MAPLESU_BIN/busybox" awk '{printf "%.0f", $1 * 1000}' /proc/uptime)
      deadline_ms=${1:-$((now_ms + 35000))}
      case "$deadline_ms" in ''|*[!0-9]*) return 64 ;; esac
      wait_ms=$((deadline_ms - now_ms))
      [ "$wait_ms" -gt 0 ] || wait_ms=0
      ;;
  esac
  start_detached() {
    "$MAPLESU_BIN/busybox" setsid "$MAPLESU_BIN/busybox" sh -c '
      exec 3>&1 1>/dev/null 2>&1
      printf "MAPLESU_BOOT_READY\n" >&3 || exit 74
      wait_ms=$1; shift
      if [ "$wait_ms" = 0 ]; then exec "$0" sh "$@" 3>&-; fi
      "$0" sh "$@" 3>&-
      code=$?
      # A deadline may already have closed the reader. The script has finished;
      # a broken result pipe must not affect it or any daemon it started.
      printf "MAPLESU_BOOT_EXIT:%s\n" "$code" >&3 2>/dev/null || :
    ' "$MAPLESU_BIN/busybox" "$wait_ms" "$script" </dev/null 2>/dev/null &
  }
  if [ "$wait_ms" = 0 ]; then
    result=$(start_detached | "$MAPLESU_BIN/busybox" head -n 1)
    reader_code=$?
  else
    wait_seconds=$(printf '%d.%03d' "$((wait_ms / 1000))" "$((wait_ms % 1000))")
    # ash reports a normally timed-out reader as "Terminated"; keep that internal.
    result=$(start_detached | "$MAPLESU_BIN/busybox" timeout "$wait_seconds" "$MAPLESU_BIN/busybox" cat) 2>/dev/null
    reader_code=$?
  fi
  case "$result" in
    "$(printf 'MAPLESU_BOOT_READY\nMAPLESU_BOOT_EXIT:')"*)
      code=${result##*MAPLESU_BOOT_EXIT:}
      case "$code" in ''|*[!0-9]*) return 70 ;; esac
      return "$code"
      ;;
    MAPLESU_BOOT_READY)
      # NoWait, or Until with a script still running at the shared deadline.
      if [ "$wait_ms" = 0 ] || [ "$reader_code" = 143 ] || [ "$reader_code" = 124 ]; then
        printf 'MAPLESU_SCRIPT_STARTED\n'
        return 0
      fi
      ;;
  esac
  printf 'maplesu-module-runner: background launch was not acknowledged\n' >&2
  return 70
}

# Same root-only module-mounts receipt channel as module-mount.sh. This wrapper
# runs after metamount's existing PID1 nsenter, around its real synchronous exit.
# No installed metamodule file is rewritten and no launch acknowledgement is used.
run_metamount() (
  umask 077
  local state=/data/adb/maplesu/module-mounts boot ledger work code=0 writer=0
  [ "$(id -u)" = 0 ] || exit 77
  boot=$(cat /proc/sys/kernel/random/boot_id) || exit 74
  for parent in /data /data/adb /data/adb/maplesu "$state"; do
    [ ! -L "$parent" ] || exit 73
    if [ -e "$parent" ]; then
      [ -d "$parent" ] || exit 73
      owner=$(stat -c '%u' "$parent") || exit 73
      mode=$(stat -c '%a' "$parent") || exit 73
      group=$(stat -c '%g' "$parent") || exit 73
      case "$owner" in 0|1000) ;; *) exit 73 ;; esac
      [ "$((0$mode & 2))" = 0 ] || exit 73
      if [ "$((0$mode & 16))" != 0 ]; then
        case "$group" in 0|1000) ;; *) exit 73 ;; esac
      fi
    fi
  done
  mkdir -p "$state" && chown 0:0 "$state" && chmod 0700 "$state" || exit 73
  ledger=$state/ledger
  for file in "$ledger" "$state/boot"; do
    [ ! -L "$file" ] || exit 73
    if [ -e "$file" ]; then
      [ -f "$file" ] && [ "$(stat -c '%u' "$file")" = 0 ] || exit 73
      mode=$(stat -c '%a' "$file") || exit 73
      [ "$((0$mode & 18))" = 0 ] || exit 73
    fi
  done
  if [ -s "$ledger" ]; then
    [ "$(cat "$state/boot" 2>/dev/null)" = "$boot" ] || exit 75
  fi
  work=$(mktemp -d "$state/.metamount.XXXXXX") || exit 73
  chmod 0700 "$work" || exit 73
  # Keep failed snapshots for the owner to inspect. Success removes only this
  # exact mktemp directory's files, never the module tree or unrelated state.
  snapshot() {
    cat /proc/self/mountinfo > "$1" || return 74
    [ "$(wc -c < "$1")" -le 1048576 ] || return 7
  }
  if [ -e "$ledger" ]; then cp "$ledger" "$work/ledger.before" || exit 73
  else : > "$work/ledger.before" || exit 73; fi
  # A previous unknown run stays closed; validate its existing receipt before
  # starting a new metamount, without inventing a new success/pending wire.
  "$MAPLESU_BIN/busybox" awk '
    NF!=2 || $1 !~ /^[1-9][0-9]*$/ || $1+0>2147483647 || $2 !~ /^\// ||
    $2=="/" || $2 ~ /[\\[:space:]]/ || $2 ~ /\/\// || $2 ~ /\/$/ ||
    $2 ~ /\/(\.|\.\.)(\/|$)/ { exit 73 }
    END { if(NR>1024)exit 7 }' "$work/ledger.before" || exit $?
  snapshot "$work/mounts.before" || exit $?
  printf '%s\n' "$boot" > "$work/boot" && chown 0:0 "$work/boot" && chmod 0600 "$work/boot" &&
    mv -f "$work/boot" "$state/boot" || exit 73
  # Preserve all previous receipts, then append an intentionally invalid ID.
  # During execution i_writecount closes source admission. If killed before a
  # verified after-snapshot, this invalid ledger stays closed instead of being
  # mistaken for a completed metamount. Final published format is unchanged.
  cat "$work/ledger.before" > "$work/ledger.pending" && printf '0 /\n' >> "$work/ledger.pending" &&
    chown 0:0 "$work/ledger.pending" && chmod 0600 "$work/ledger.pending" &&
    mv -f "$work/ledger.pending" "$ledger" || exit 73
  exec 8>> "$ledger" || exit 73
  if [ -x "$MAPLESU_BIN/busybox" ]; then
    (umask 000; exec "$MAPLESU_BIN/busybox" sh "$script" 8>&-) || code=$?
  else
    (umask 000; exec /system/bin/sh "$script" 8>&-) || code=$?
  fi
  # A nonzero script may still have created real mounts. Record those actual
  # effects but preserve its original nonzero status. No before/after proof =>
  # keep pending and return a writer error, never success for unknown effects.
  snapshot "$work/mounts.after" || writer=$?
  if [ "$writer" = 0 ]; then
    "$MAPLESU_BIN/busybox" awk '
      function valid(id,path) {
        return id ~ /^[1-9][0-9]*$/ && id+0 <= 2147483647 && path ~ /^\// &&
          path != "/" && path !~ /[\\[:space:]]/ && path !~ /\/\// && path !~ /\/$/ &&
          path !~ /\/(\.|\.\.)(\/|$)/
      }
      FILENAME==ARGV[1] { old[$1]=$5; next }
      FILENAME==ARGV[2] { if(NF!=2 || !valid($1,$2))bad=1; owned[$1]=1; kept[++n]=$0; next }
      FILENAME==ARGV[3] {
        if($1 !~ /^[1-9][0-9]*$/ || $5=="" || seen[$1]++) { bad=1; next }
        present[$1]=$5
        if(!($1 in old) || (($1 in owned) && old[$1]!=$5)) {
          if(!valid($1,$5))bad=1
          added[++count]=$1 " " $5
        }
      }
      END {
        if(bad)exit 73
        for(i=1;i<=n;i++) {
          split(kept[i],v," ")
          if(present[v[1]]==v[2]) { print kept[i]; emitted[v[1]]=1; total++ }
        }
        for(i=1;i<=count;i++) {
          split(added[i],v," ")
          if(!emitted[v[1]]++) { print added[i]; total++ }
        }
        if(total>1024)exit 7
      }' "$work/mounts.before" "$work/ledger.before" "$work/mounts.after" > "$work/ledger.next" || writer=$?
  fi
  if [ "$writer" = 0 ]; then
    [ "$(wc -c < "$work/ledger.next")" -le 262144 ] || writer=7
  fi
  if [ "$writer" = 0 ]; then
    chown 0:0 "$work/ledger.next" && chmod 0600 "$work/ledger.next" &&
      mv -f "$work/ledger.next" "$ledger" || writer=73
  fi
  exec 8>&-
  if [ "$writer" != 0 ]; then printf 'MAPLESU_METAMOUNT_LEDGER_FAILED:%s\n' "$writer" >&2; fi
  if [ "$writer" = 0 ]; then
    rm -f -- "$work/ledger.before" "$work/mounts.before" "$work/mounts.after" && rmdir -- "$work" || :
  fi
  if [ "$code" != 0 ]; then exit "$code"; fi
  exit "$writer"
)

# exec, not source: the script keeps its own $0, its own `set -e`, its own traps and
# its own exit status, all of which sourcing would have taken over.
# Standalone BusyBox supplies the module shell/applications used by KSU, including
# unshare --propagation (Android toybox unshare does not implement that option).
run_script() {
  # Match the module shell contract, not the SDK owner's private umask.
  case "$stage" in
    post-fs-data|post-mount|service|boot-completed|metamount|uninstall|hot-install) umask 000 ;;
    *) umask 022 ;;
  esac
  # The early dispatcher opts in only the compatible LSPosed revision/boot.
  if [ "$module_id" = zygisk_lsposed ] && { [ "$stage" = service ] || [ "$stage" = post-fs-data ]; }; then
    state=/data/adb/maplesu_zygisk/shared-context
    context_boot=; context_device=; context_inode=; context_library=
    if [ -r "$state" ]; then read -r context_boot context_device context_inode context_library < "$state" || :; fi
    if [ -n "$context_library" ] && [ "$context_boot" = "$(cat /proc/sys/kernel/random/boot_id)" ] &&
        [ "$context_device $context_inode" = "$(stat -Lc '%d %i' "$module_dir")" ] && [ -r "$context_library" ]; then
      export MAPLESU_LSP_PRELOAD="${LD_PRELOAD:-}"
      export LD_PRELOAD="$context_library${LD_PRELOAD:+:$LD_PRELOAD}"
    fi
  fi
  if [ "$stage" = uninstall ]; then
    meta=/data/adb/metamodule
    is_meta=$(sed -n 's/^metamodule=//p' "$module_dir/module.prop" | tail -n1 | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
    case "$is_meta" in
      1|true) ;;
      *)
        if [ -f "$meta/metauninstall.sh" ] && [ ! -e "$meta/disable" ]; then
          (
            export MODULE_ID="$module_id"
            KSU_MODULE=$(sed -n 's/^id=//p' "$meta/module.prop" | tail -n1 | tr -d '[:space:]')
            export KSU_MODULE
            cd "$meta" || exit 70
            if [ -x "$MAPLESU_BIN/busybox" ]; then
              exec "$MAPLESU_BIN/busybox" sh "$meta/metauninstall.sh"
            fi
            exec /system/bin/sh "$meta/metauninstall.sh"
          ) || printf 'MAPLESU_METAUNINSTALL_WARNING:%s\n' "$?" >&2
        fi
        ;;
    esac
    [ -f "$script" ] || return 0
  fi
  case "$stage" in
    post-fs-data|post-mount|service|boot-completed) run_boot_script "${early_deadline:-}"; return $? ;;
  esac
  if [ "$stage" = metamount ]; then run_metamount; return $?; fi
  if [ -x "$MAPLESU_BIN/busybox" ]; then
    exec "$MAPLESU_BIN/busybox" sh "$script"
  fi
  exec /system/bin/sh "$script"
}

early_deadline=${3:-}

# SDK events and the existing early Zygisk dispatcher share one per-boot receipt.
# A Manager operation observing the same tree/stage never launches it a second time.
case "$stage" in
  post-fs-data|post-mount|service|boot-completed)
    boot="$(cat /proc/sys/kernel/random/boot_id)"
    if [ -x "$MAPLESU_BIN/busybox" ]; then
      receipts="/data/adb/maplesu/module-boot/$(stat -Lc '%d-%i' "$module_dir")"
      receipt_stage="$stage${common_script:+.$common_script}"
      for parent in /data/adb /data/adb/maplesu /data/adb/maplesu/module-boot "$receipts"; do
        [ ! -L "$parent" ] || exit 73
      done
      mkdir -p "$receipts" || exit 73
      chmod 0700 "$receipts" || exit 73
      [ ! -L "$receipts/$receipt_stage.lock" ] && [ ! -L "$receipts/$receipt_stage" ] || exit 73
      if [ -e "$receipts/$receipt_stage" ] && [ ! -f "$receipts/$receipt_stage" ]; then exit 73; fi
      (
        "$MAPLESU_BIN/busybox" flock -n 9 || {
          # Another owner is still handling this exact revision/stage. Preserve
          # its in-progress state; no completed receipt has been observed.
          printf 'MAPLESU_SCRIPT_STARTED\n'
          exit 0
        }
        saved_boot=; saved_code=; saved_state=
        if [ -f "$receipts/$receipt_stage" ]; then read -r saved_boot saved_code saved_state < "$receipts/$receipt_stage" || :; fi
        if [ "$saved_boot" = "$boot" ]; then
          case "$saved_code" in ''|*[!0-9]*) exit 73 ;; esac
          [ "$saved_code" -le 255 ] || exit 73
          case "$saved_state" in started|ok) ;; *) exit 73 ;; esac
          if [ "$saved_state" = started ]; then printf 'MAPLESU_SCRIPT_STARTED\n'; fi
          exit "$saved_code"
        fi
        # Keep the lock in the wrapper only. Native background daemons inherit
        # neither this FD nor the host's readiness pipe.
        output=$( (run_script) 9>&- )
        code=$?
        [ -z "$output" ] || printf '%s\n' "$output"
        saved_state=ok
        if [ "$output" = MAPLESU_SCRIPT_STARTED ]; then saved_state=started; fi
        temporary=$(mktemp "$receipts/.stage.XXXXXX") || exit 73
        printf '%s %s %s\n' "$boot" "$code" "$saved_state" > "$temporary" &&
          chmod 0600 "$temporary" && mv -f "$temporary" "$receipts/$receipt_stage" || exit 73
        exit "$code"
      ) 9> "$receipts/$receipt_stage.lock"
      exit $?
    fi ;;
esac
run_script
