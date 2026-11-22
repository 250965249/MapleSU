#!/system/bin/sh
# MapleSU legacy module installer bridge.
#
# Executed as: <this> <module-dir> <archive>
#
# Reproduces the legacy `install.sh` contract from the pinned KSU userspace
# (installer.sh:392-410) instead of treating install.sh as a standalone script:
#
#   unzip -oj "$ZIPFILE" module.prop install.sh uninstall.sh 'common/*' -d $TMPDIR
#   . $TMPDIR/install.sh
#   print_modname
#   on_install
#   $SKIPMOUNT  && touch $MODPATH/skip_mount
#   $PROPFILE   && cp -af $TMPDIR/system.prop    $MODPATH/system.prop
#   $POSTFSDATA && cp -af $TMPDIR/post-fs-data.sh $MODPATH/post-fs-data.sh
#   $LATESTARTSERVICE && cp -af $TMPDIR/service.sh $MODPATH/service.sh
#   set_permissions
#
# The three callbacks are defined *by install.sh itself* (Magisk legacy contract),
# which is why this must source it rather than exec it. Exiting 0 without having
# run a defined callback would silently accept a module that never installed, so a
# missing callback is reported as a failure.
set -u

module_dir="${1:-}"
archive="${2:-}"
if [ -z "$module_dir" ] || [ -z "$archive" ]; then
  printf 'maplesu-legacy-installer: usage: legacy-install.sh <module-dir> <archive>\n' >&2
  exit 64
fi

script="$module_dir/install.sh"
if [ ! -f "$script" ]; then
  printf 'maplesu-legacy-installer: no install.sh in %s\n' "$module_dir" >&2
  exit 66
fi

# Installer-scope variables, as installer.sh:378-383 + 486-493 set them.
MODPATH="$module_dir"
export MODPATH
ZIPFILE="$archive"
export ZIPFILE
TMPDIR="$module_dir/.maplesu-tmp"
mkdir -p "$TMPDIR" || exit 70
export TMPDIR
NVBASE=/data/adb
MODULEROOT=${MODPATH%/*}
BOOTMODE=true
OUTFD=1
export BOOTMODE OUTFD NVBASE MODULEROOT

MAPLESU_BIN=${MAPLESU_BIN:-/data/adb/maplesu/bin}
export PATH="${PATH:-/system/bin:/system/xbin}:$MAPLESU_BIN"

# Same module-script compatibility environment as the modern installer.
export MAPLESU=true
export MAPLESU_BACKEND=legacy_installer
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
export ASH_STANDALONE=1
unset MAGISK
export MAGISK_VER=25.2 MAGISK_VER_CODE=25200
export API="$(/system/bin/getprop ro.build.version.sdk 2>/dev/null)"
export ARCH=arm64
export IS64BIT=true
module_id="${module_dir##*/}"
case "$module_id" in
  ''|*/*|.|..) ;;
  *) export MAPLESU_MODULE="$module_id" KSU_MODULE="$module_id" ;;
esac

# Legacy flags default to false, exactly like installer.sh:486-493.
SKIPMOUNT=false
PROPFILE=false
POSTFSDATA=false
LATESTARTSERVICE=false
REPLACE=""
REMOVE=""

ui_print() { printf '%s\n' "$*"; }
# Legacy callbacks run in this shell and need the same XZ support as customize.sh.
unzip() { "$MAPLESU_BIN/busybox" unzip "$@"; }
abort() {
  printf '! %s\n' "$*" >&2
  # installer.sh:55-61: abort removes the module path and the temp dir.
  rm -rf "$MODPATH" "$TMPDIR"
  exit 1
}

# Magisk-compatible permission helpers. A context argument applies an existing
# SELinux type only; declaring new types belongs to the module policy loader.
set_perm() {
  [ "$#" -eq 4 ] || [ "$#" -eq 5 ] || abort "set_perm requires target uid gid mode [context]"
  chown "$2:$3" "$1" || return 1
  chmod "$4" "$1" || return 1
  chcon "${5:-u:object_r:system_file:s0}" "$1" || return 1
  return 0
}
set_perm_recursive() {
  [ "$#" -eq 5 ] || [ "$#" -eq 6 ] || abort "set_perm_recursive requires target uid gid dirmode filemode [context]"
  chown -R "$2:$3" "$1" || return 1
  find "$1" -type d -exec chmod "$4" '{}' ';' || return 1
  find "$1" -type f -exec chmod "$5" '{}' ';' || return 1
  find "$1" -exec chcon "${6:-u:object_r:system_file:s0}" '{}' ';' || return 1
  return 0
}
grep_prop() {
  local REGEX="$1"
  sed -n "s/^$REGEX=//p" "$MODPATH/module.prop" 2>/dev/null | tail -n1
}

mark_remove() {
  mkdir -p "${1%/*}" || return $?
  mknod "$1" c 0 0 || return $?
  chmod 0644 "$1"
}

# Default set_permissions callback when install.sh does not define one: the same
# default recursive modes installer.sh applies for modern modules.
default_permissions() {
  set_perm_recursive "$MODPATH" 0 0 0755 0644
  [ -d "$MODPATH/system/bin" ] && set_perm_recursive "$MODPATH/system/bin" 0 2000 0755 0755
  [ -d "$MODPATH/system/xbin" ] && set_perm_recursive "$MODPATH/system/xbin" 0 2000 0755 0755
  [ -d "$MODPATH/system/system_ext/bin" ] && set_perm_recursive "$MODPATH/system/system_ext/bin" 0 2000 0755 0755
  [ -d "$MODPATH/system/vendor" ] && set_perm_recursive "$MODPATH/system/vendor" 0 2000 0755 0755 u:object_r:vendor_file:s0
  return 0
}

cd "$module_dir" || exit 70
# KSU flattens common/* into its installer TMPDIR before sourcing install.sh.
# Legacy on_install callbacks and PROPFILE/POSTFSDATA/LATESTARTSERVICE read there.
unzip -oj "$ZIPFILE" module.prop install.sh uninstall.sh 'common/*' -d "$TMPDIR" >&2
# KSU does not impose nounset on module code; optional manager variables may be
# absent. The selected script keeps control of its own shell options.
set +u
# shellcheck disable=SC1090
. "$TMPDIR/install.sh" || exit $?

# Callbacks, in installer.sh order. install.sh defines them; a missing definition
# means the module did not follow the legacy contract, which must fail loudly.
if command -v print_modname >/dev/null 2>&1; then print_modname; fi
if ! command -v on_install >/dev/null 2>&1; then
  printf 'maplesu-legacy-installer: install.sh does not define on_install\n' >&2
  exit 68
fi
on_install || exit $?

# Flag-driven file publication, installer.sh:402-407.
[ -f "$TMPDIR/uninstall.sh" ] && cp -af "$TMPDIR/uninstall.sh" "$MODPATH/uninstall.sh"
if [ "${SKIPMOUNT:-false}" = true ]; then touch "$MODPATH/skip_mount"; fi
if [ "${PROPFILE:-false}" = true ] && [ -f "$TMPDIR/system.prop" ]; then
  cp -af "$TMPDIR/system.prop" "$MODPATH/system.prop"
fi
cp -af "$TMPDIR/module.prop" "$MODPATH/module.prop" || exit $?
if [ "${POSTFSDATA:-false}" = true ] && [ -f "$TMPDIR/post-fs-data.sh" ]; then
  cp -af "$TMPDIR/post-fs-data.sh" "$MODPATH/post-fs-data.sh"
fi
if [ "${LATESTARTSERVICE:-false}" = true ] && [ -f "$TMPDIR/service.sh" ]; then
  cp -af "$TMPDIR/service.sh" "$MODPATH/service.sh"
fi

ui_print "- Setting permissions"
if command -v set_permissions >/dev/null 2>&1; then
  set_permissions || exit $?
else
  default_permissions || exit $?
fi

for TARGET in $REPLACE; do
  mkdir -p "$MODPATH$TARGET" || exit 1
  touch "$MODPATH$TARGET/.replace" || exit 1
done
for TARGET in ${REMOVE:-}; do
  mark_remove "$MODPATH$TARGET" || exit $?
done

# The module opts in; an archive's pre-existing marker grants no hot request.
if [ "${MODULE_HOT_INSTALL_REQUEST:-false}" = true ]; then
  printf '%s\n' "${MODULE_HOT_RUN_SCRIPT:-}" > "$MODPATH/.ksu_hot_install" || exit $?
else
  rm -f "$MODPATH/.ksu_hot_install" || exit $?
fi

rm -rf "$TMPDIR"
exit 0
