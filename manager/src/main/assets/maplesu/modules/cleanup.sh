#!/system/bin/sh
set -eu

adb=/data/adb
bb=${MAPLESU_CLEANUP_BUSYBOX:?}
test "$(id -u)" = 0
test -x "$bb"

# Never traverse a redirected parent while removing the fixed module paths.
check_parent() {
  p=$1
  while [ "$p" != / ]; do
    [ ! -L "$p" ] || { printf 'MODULE_CLEANUP_PATH_CONFLICT\n' >&2; exit 73; }
    p=${p%/*}
    [ -n "$p" ] || p=/
  done
}

detach_mounts() {
  # Descendants first. Only mountpoints inside the exact removal tree are detached.
  for mount in $(awk -v p="$1" '$5 == p || index($5,p "/") == 1 {print $5}' /proc/self/mountinfo | sort -r); do
    mount=$(printf '%b' "$mount")
    "$bb" umount -l "$mount"
  done
}

remove_tree() {
  target=$1
  check_parent "${target%/*}"
  if [ ! -L "$target" ]; then detach_mounts "$target"; fi
  "$bb" rm -rf -- "$target"
  test ! -e "$target" && test ! -L "$target"
}

is_meta() {
  [ -f "$1/module.prop" ] &&
    grep -Eiq '^[[:space:]]*metamodule[[:space:]]*=[[:space:]]*(1|true)[[:space:]]*$' "$1/module.prop"
}

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
}

case "${1:-}" in
  list)
    for dir in "$adb/modules" "$adb/modules_update" "$adb/ksu/module_configs" \
        "$adb/ksu/hot_install_trash" "$adb/maplesu/module-transactions"; do
      check_parent "$dir"
    done
    for root in "$adb/modules" "$adb/modules_update"; do
      for module in "$root"/* "$root"/.[!.]* "$root"/..?*; do
        [ -d "$module" ] && [ -f "$module/module.prop" ] || continue
        id=${module##*/}
        case "$id" in ''|.|..|*[!a-zA-Z0-9._-]*) continue ;; esac
        # An unactivated update of an installed module has not run; uninstall its live version once.
        if [ "$root" = "$adb/modules_update" ] && [ -d "$adb/modules/$id" ]; then continue; fi
        rank=0
        if is_meta "$module"; then rank=1; fi
        printf 'MODULE\t%s\t%s\n' "$rank" "$module"
      done
    done
    ;;
  uninstall)
    module=${2:?}
    case "$module" in "$adb/modules/"*|"$adb/modules_update/"*) ;; *) exit 64 ;; esac
    id=${module##*/}
    case "$id" in ''|.|..|*[!a-zA-Z0-9._-]*) exit 64 ;; esac
    test "$module" = "$adb/modules/$id" || test "$module" = "$adb/modules_update/$id"
    check_parent "${module%/*}"
    [ -d "$module" ] || exit 0
    export ASH_STANDALONE=1 BOOTMODE=true MAPLESU=true MAPLESU_BACKEND=module_v1
    maplesu_require_runtime_facts || exit 75
    export KSU=true
    export KSU_MODULE="$id" MAPLESU_MODULE="$id" MAPLESU_STAGE=uninstall
    export PATH="${PATH:-/system/bin:/system/xbin}:$adb/ksu/bin:$adb/maplesu/bin"
    # Migration can run before MapleSU's shared tools have been published.
    # An executable survives the independent shells used by all uninstall hooks.
    helpers=$("$bb" mktemp -d "$adb/.maplesu-uninstall.XXXXXX")
    trap '"$bb" rm -rf -- "$helpers"' EXIT
    cat > "$helpers/ui_print" <<'MAPLESU_UI_PRINT'
#!/system/bin/sh
printf '%s\n' "$*"
MAPLESU_UI_PRINT
    chmod 0755 "$helpers/ui_print"
    export PATH="$helpers:$PATH"
    export API="$(/system/bin/getprop ro.build.version.sdk)"
    case "$(/system/bin/getprop ro.product.cpu.abi)" in
      arm64-v8a) export ARCH=arm64 IS64BIT=true ;;
      armeabi*) export ARCH=arm IS64BIT=false ;;
      x86_64) export ARCH=x64 IS64BIT=true ;;
      *) export ARCH=x86 IS64BIT=false ;;
    esac
    # KSU prune_modules: provider hook, module uninstaller, config, directory.
    # Provider removal runs last, so all ordinary modules can use its hook.
    run_hook() {
      script=$1
      [ -f "$script" ] || return 0
      code=0
      (cd "${script%/*}" && "$bb" timeout -s KILL 30 "$bb" sh "$script" </dev/null >/dev/null 2>&1) || code=$?
      if [ "$code" -ne 0 ]; then printf 'MODULE_UNINSTALL_WARNING\t%s\t%s\n' "$id" "$code"; fi
    }
    meta="$adb/metamodule"
    meta_target=$(readlink -f "$meta" 2>/dev/null || :)
    if [ "$meta_target" != "$adb/modules/${meta_target##*/}" ] &&
        [ "$meta_target" != "$adb/modules_update/${meta_target##*/}" ]; then meta_target=; fi
    # KSU also discovers the provider from module.prop if the pointer is missing.
    if [ -z "$meta_target" ]; then
      for candidate in "$adb/modules"/* "$adb/modules"/.[!.]* "$adb/modules"/..?*; do
        if is_meta "$candidate"; then meta=$candidate; meta_target=$candidate; break; fi
      done
    fi
    if is_meta "$module"; then
      remove_tree "$adb/metamodule"
    elif [ ! -e "$meta/disable" ]; then
      case "$meta_target" in
        "$adb/modules/"*|"$adb/modules_update/"*)
          (export MODULE_ID="$id"; KSU_MODULE=${meta_target##*/}; export KSU_MODULE
           run_hook "$meta/metauninstall.sh") ;;
      esac
    fi
    run_hook "$module/uninstall.sh"
    remove_tree "$adb/ksu/module_configs/$id"
    remove_tree "$module"
    if [ "$module" = "$adb/modules/$id" ]; then remove_tree "$adb/modules_update/$id"; fi
    ;;
  finish)
    # Include malformed/stale entries and hidden files; rm never follows child symlinks.
    check_parent "$adb/modules"
    for child in "$adb/modules"/* "$adb/modules"/.[!.]* "$adb/modules"/..?*; do
      [ -e "$child" ] || [ -L "$child" ] || continue
      remove_tree "$child"
    done
    for target in "$adb/modules_update" "$adb/metamodule" "$adb/modules.img" "$adb/modules_update.img" \
        "$adb/ksu/module_configs" "$adb/ksu/hot_install_trash" "$adb/maplesu/module-transactions"; do
      remove_tree "$target"
    done
    # These are generated from module initrc/preinit content, not root grants or boot backups.
    for base in /metadata/vold/ksu /metadata/watchdog/ksu /metadata/ksu; do
      for name in modules.rc .modules.rc.tmp preinit; do remove_tree "$base/$name"; done
    done
    # Old releases could park module copies in a mode slot; prevent their later resurrection.
    for mode in LITE KSU; do
      base="$adb/maplesu-workmode/modes/$mode/data/data/adb"
      for name in modules modules_update metamodule ksu/module_configs ksu/hot_install_trash; do
        remove_tree "$base/$name"
      done
    done
    printf 'MODULE_CLEANUP_OK\n'
    ;;
  *) exit 64 ;;
esac
