#!/system/bin/sh
# Invoked only by the authenticated Lite executor, with literal argv paths.
set -e
MODDIR="$1"
MODPATH="$MODDIR"
SCRIPT="$2"
ZIPFILE="$3"
LEGACY_INSTALLER="${4:-}"
TMPDIR="$MODDIR/.maplesu-tmp"
export MODDIR MODPATH ZIPFILE TMPDIR
export NVBASE=/data/adb MODULEROOT="${MODPATH%/*}" OUTFD=1
export ASH_STANDALONE=1

# `magisk` is a compatibility shim (LSPosed calls the command directly), but KSU-native
# installers abort when `which magisk` succeeds - measured: Zygisk Next prints "Multiple
# root implementation is NOT supported!". KSU ships no magisk binary, so the shim lives in
# BINARY_DIR/compat and only installers that actually invoke it get that directory on PATH.
if [ -d /data/adb/maplesu/bin/compat ]; then
  for _f in "$MODDIR"/*.sh; do
    # Include sourced helpers (LSPosed's util_functions.sh), but not probes such
    # as `which magisk`: exposing the shim there reports a second Root manager.
    if [ -f "$_f" ] && /system/bin/sed '/^[[:space:]]*#/d' "$_f" | /system/bin/grep -qE '(^|[^[:alnum:]_/])magisk[[:space:]]+(-[^[:space:];|&)]+|version)([[:space:];|&)]|$)'; then
      PATH="/data/adb/maplesu/bin/compat:$PATH"
      export PATH
      break
    fi
  done
fi
export MAPLESU=true MAPLESU_BACKEND=lite_script BOOTMODE=true
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

# KSU appends BINARY_DIR to PATH for every script it runs (module.rs:63-88), so a
# customize.sh can call `sepolicy` / `resetprop` / `ksud` by bare name. Append, never
# prepend: platform binaries keep priority. Without this the helpers silently report
# "sepolicy checker is unavailable" even though the tool was published.
export PATH="${PATH:-/system/bin:/system/xbin}:/data/adb/maplesu/bin"

# Module policy and filesystem projections are dispatched by separate boot tasks.
# This runner only executes the selected script; publishing tools alone creates
# neither mounts nor base policy. The mount task honors skip_mount and delegates
# to an installed metamodule, or uses overlayfs/tmpfs plus bind mounts on demand.
# These managers are detected by nonempty variables in several module installers.
# Manager identity. KSU-native module installers do not merely read these for display:
# they select the KSU code path with them and abort otherwise (Zygisk Next prints
# "Please install from KernelSU or Magisk app", LSPosed prints "Please install Magisk
# v27+"). MapleSU implements the KSU module contract, so it declares the KSU identity
# that contract defines. This is a compatibility declaration, not a claim that a
# KernelSU kernel driver is loaded. Like KSU installer.sh, preserve the legacy
# Magisk version variables for shared installers, while leaving MAGISK unset.
export KSU_MODULE="${MODDIR##*/}"
unset MAGISK
export MAGISK_VER=25.2 MAGISK_VER_CODE=25200
export API="$(getprop ro.build.version.sdk)" ARCH=arm64 IS64BIT=true
mkdir -p "$TMPDIR"
ui_print() { printf '%s\n' "$*"; }
abort() { printf '! %s\n' "$*" >&2; exit 1; }
# Platform unzip can reject XZ (method 95); use the bundled KSU-compatible applet.
unzip() { /data/adb/maplesu/bin/busybox unzip "$@"; }
set_perm() {
  # 4 args = target uid gid mode; 5 args adds an SELinux context. Applying an
  # *existing* type with chcon changes no policy and loads no rule, so it is allowed
  # here; declaring a new type still belongs to the policy loader.
  [ "$#" -eq 4 ] || [ "$#" -eq 5 ] || abort 'set_perm requires target uid gid mode [context]'
  chown "$2:$3" "$1"
  chmod "$4" "$1"
  chcon "${5:-u:object_r:system_file:s0}" "$1"
}
set_perm_recursive() {
  # 5 args = target uid gid directory-mode file-mode; 6 args adds a context.
  [ "$#" -eq 5 ] || [ "$#" -eq 6 ] || abort 'set_perm_recursive requires target uid gid directory-mode file-mode [context]'
  chown -R "$2:$3" "$1"
  find "$1" -type d -exec chmod "$4" '{}' ';'
  find "$1" -type f -exec chmod "$5" '{}' ';'
  find "$1" -exec chcon "${6:-u:object_r:system_file:s0}" '{}' ';'
}
# Installer helpers the pinned packages actually call. Measured offline from the
# three fixed ZIPs: grep_prop and check_sepolicy are both expected from the installer
# (Zygisk Next: grep_prop x1, check_sepolicy x1; LSPosed: grep_prop x1; TEESimulator:
# grep_prop x1), and neither used to exist here.
grep_prop() {
  # Magisk semantics: regex on the key, last match wins, optional file argument.
  [ -n "${1:-}" ] || return 1
  _gp_file="${2:-$MODPATH/module.prop}"
  /system/bin/sed -n "s/^$1=//p" "$_gp_file" 2>/dev/null | /system/bin/tail -n1
}
check_sepolicy() {
  # Read-only syntax/semantic check through the published loader entry. It never
  # writes /sys/fs/selinux/load, so calling it changes no policy.
  [ -n "${1:-}" ] || return 1
  if ! command -v sepolicy >/dev/null 2>&1; then
    ui_print '! sepolicy checker is unavailable'
    return 1
  fi
  sepolicy check "$1"
}
mark_remove() {
  mkdir -p "${1%/*}" || return $?
  mknod "$1" c 0 0 || return $?
  chmod 0644 "$1"
}
install_module() {
cd "$MODPATH" || return 1
if [ -f "$MODPATH/install.sh" ]; then
  [ -f "$LEGACY_INSTALLER" ] || abort 'Legacy installer helper is missing'
  /data/adb/maplesu/bin/busybox sh "$LEGACY_INSTALLER" "$MODPATH" "$ZIPFILE"
  return $?
fi
# KSU's installer extracts module.prop into TMPDIR before running customize.sh, and
# real modules read it from there (TEESimulator: grep_prop version "$TMPDIR/module.prop").
# Without this staging the version reads as empty and version-gated installers take the
# wrong branch. Staged, not moved: the module tree keeps its own copy.
[ -f "$MODDIR/module.prop" ] && cp -f "$MODDIR/module.prop" "$TMPDIR/module.prop"
# KSU applies defaults before customize.sh, and SKIPUNZIP installers own their
# extraction and permissions. A later recursive pass removes executable bits
# set by frameworks such as Vector and prevents their daemons from starting.
if ! grep -q '^SKIPUNZIP=1$' "$MODPATH/$SCRIPT" 2>/dev/null; then
  set_perm_recursive "$MODPATH" 0 0 0755 0644
  [ -d "$MODPATH/system/bin" ] && set_perm_recursive "$MODPATH/system/bin" 0 2000 0755 0755
  [ -d "$MODPATH/system/xbin" ] && set_perm_recursive "$MODPATH/system/xbin" 0 2000 0755 0755
  [ -d "$MODPATH/system/system_ext/bin" ] && set_perm_recursive "$MODPATH/system/system_ext/bin" 0 2000 0755 0755
  [ -d "$MODPATH/system/vendor" ] && set_perm_recursive "$MODPATH/system/vendor" 0 2000 0755 0755 u:object_r:vendor_file:s0
fi
# Module installers use explicit abort/exit and ordinary false condition tests.
# Inherit Magisk/KSU source semantics instead of imposing errexit on their code.
set +e
_script_status=0
if [ -f "$MODPATH/$SCRIPT" ]; then
  . "$MODPATH/$SCRIPT"
  _script_status=$?
fi
set -e
[ "$_script_status" -eq 0 ] || exit "$_script_status"

# Preserve the explicit callback supported by earlier MapleSU installers.
if command -v set_permissions >/dev/null 2>&1; then
  set_permissions || exit $?
fi
for TARGET in ${REPLACE:-}; do
  mkdir -p "$MODPATH$TARGET" || return 1
  touch "$MODPATH$TARGET/.replace" || return 1
done
for TARGET in ${REMOVE:-}; do
  mark_remove "$MODPATH$TARGET" || return $?
done
# The module opts in; an archive's pre-existing marker grants no hot request.
if [ "${MODULE_HOT_INSTALL_REQUEST:-false}" = true ]; then
  printf '%s\n' "${MODULE_HOT_RUN_SCRIPT:-}" > "$MODPATH/.ksu_hot_install" || exit $?
else
  rm -f "$MODPATH/.ksu_hot_install" || exit $?
fi

rm -f "$MODPATH/customize.sh" "$MODPATH/README.md"
rm -rf "$TMPDIR"
}

# Like KSU get_install_script(), the selected metainstall owns the call to
# install_module. It can wrap the default installer, or provide its own installer.
# A metamodule update always uses the default installer to avoid calling itself.
_meta=/data/adb/metamodule
_is_meta=$(grep_prop metamodule "$MODPATH/module.prop" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
case "$_is_meta" in
  1|true) install_module ;;
  *)
    if [ -f "$_meta/metainstall.sh" ]; then
      for _marker in disable remove update; do
        [ ! -e "$_meta/$_marker" ] || abort "METAMODULE_INSTALL_BLOCKED: $_marker"
      done
      cd "$MODPATH" || exit 70
      . "$_meta/metainstall.sh"
    else
      install_module
    fi
    ;;
esac
