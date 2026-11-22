#!/system/bin/sh
# Project only installed modules. No boot/init_boot writes and no manager base mount.
set -u
state=/data/adb/maplesu/module-mounts
busybox=/data/adb/maplesu/bin/busybox

# With no requested modules and no previous mounts there is nothing to change.
[ "$#" -gt 0 ] || [ -f "$state/ledger" ] || exit 0
if [ "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)" ]; then
  exec "$busybox" nsenter -t 1 -m -- /system/bin/sh "$0" "$@"
fi
boot=$(cat /proc/sys/kernel/random/boot_id) || exit 1
[ ! -L "$state" ] || exit 1
mkdir -p "$state" || exit 1
chmod 0700 "$state" || exit 1
ledger="$state/ledger"
touch "$ledger" || exit 1
chmod 0600 "$ledger" || exit 1

# Mount IDs belong to one kernel boot. Reverse order unwinds only our top layers.
if [ "$(cat "$state/boot" 2>/dev/null)" = "$boot" ]; then
  "$busybox" tac "$ledger" > "$state/reverse" || exit 1
  : > "$state/kept"
  while IFS=' ' read -r own_id target; do
    [ -n "$own_id" ] || continue
    top=$(awk -v path="$target" '$5 == path { id=$1 } END { print id }' /proc/self/mountinfo)
    if [ "$top" = "$own_id" ]; then
      if ! umount "$target"; then
        printf '%s %s\n' "$own_id" "$target" >> "$state/kept"
      fi
    elif awk -v id="$own_id" '$1 == id { found=1 } END { exit !found }' /proc/self/mountinfo; then
      # A later foreign mount covers ours: preserve its layer and retain our receipt.
      printf '%s %s\n' "$own_id" "$target" >> "$state/kept"
    fi
  done < "$state/reverse"
  if [ -s "$state/kept" ]; then
    "$busybox" tac "$state/kept" > "$ledger"
    printf 'MAPLESU_MOUNT_RESET_FAILED\n' >&2
    exit 1
  fi
fi
: > "$ledger"
printf '%s\n' "$boot" > "$state/boot"
[ ! -L "$state/views" ] || exit 1
rm -rf -- "$state/views"
mkdir -p "$state/views" || exit 1

record_mount() (
  target=$1
  own_id=$(awk -v path="$target" '$5 == path { id=$1 } END { print id }' /proc/self/mountinfo)
  [ -n "$own_id" ] || return 1
  printf '%s %s\n' "$own_id" "$target" >> "$ledger"
)

# Recursive binds clone child mounts too. Record every cloned ID for exact teardown.
record_tree() {
  awk -v path="$1" '$5 == path || index($5, path "/") == 1 { print $1, $5 }' /proc/self/mountinfo >> "$ledger"
}

# Keep labels explicitly chosen by installers; replace only generic staging labels.
label_module() (
  source=$1
  reference=$2
  [ ! -L "$source" ] || return 0
  label=$(ls -Zd "$source" | awk '{print $1}')
  case "$label" in
    *:app_data_file:*|*:shell_data_file:*|*:unlabeled:*)
      chcon "$(ls -Zd "$reference" | awk '{print $1}')" "$source" || return 1 ;;
  esac
  if [ -d "$source" ]; then
    for child in "$source"/* "$source"/.[!.]* "$source"/..?*; do
      [ -e "$child" ] || [ -L "$child" ] || continue
      base="$reference/${child##*/}"
      [ -e "$base" ] || base=$reference
      label_module "$child" "$base" || return 1
    done
  fi
)

# Build only changed directory levels in tmpfs. Unchanged subtrees remain bind mounts
# of the original filesystem, so adding a file never copies an entire partition.
populate() (
  source=$1
  lower=$2
  target=$3
  split_system=${4:-0}
  reference=$source
  merge_lower=0
  if [ -d "$lower" ] && [ ! -L "$lower" ] && [ ! -f "$source/.replace" ]; then
    reference=$lower
    merge_lower=1
  fi
  chmod "$(stat -c %a "$reference")" "$target" || return 1
  chown "$(stat -c %u:%g "$reference")" "$target" || return 1
  chcon "$(ls -Zd "$reference" | awk '{print $1}')" "$target" || return 1
  if [ "$merge_lower" -eq 1 ]; then
  for child in "$lower"/* "$lower"/.[!.]* "$lower"/..?*; do
    [ -e "$child" ] || [ -L "$child" ] || continue
    name=${child##*/}
    split_entry=0
    if [ "$split_system" -eq 1 ]; then
      case "$name" in vendor|product|system_ext|odm|oem) split_entry=1 ;; esac
    fi
    if [ "$split_entry" -eq 0 ]; then
      [ ! -e "$source/$name" ] && [ ! -L "$source/$name" ] || continue
    fi
    if [ -L "$child" ]; then
      cp -a "$child" "$target/$name" || return 1
    else
      if [ -d "$child" ]; then mkdir "$target/$name"; else touch "$target/$name"; fi
      mount --rbind "$child" "$target/$name" || return 1
      record_tree "$target/$name"
    fi
  done
  fi
  for child in "$source"/* "$source"/.[!.]* "$source"/..?*; do
    [ -e "$child" ] || [ -L "$child" ] || continue
    name=${child##*/}
    [ "$name" != .replace ] || continue
    if [ "$split_system" -eq 1 ]; then
      case "$name" in vendor|product|system_ext|odm|oem) continue ;; esac
    fi
    if [ ! -L "$child" ] && [ -c "$child" ]; then
      device=$(stat -c %t:%T "$child") || return $?
      [ "$device" != 0:0 ] || continue
    fi
    if [ -L "$child" ]; then
      cp -a "$child" "$target/$name" || return 1
    elif [ -d "$child" ]; then
      mkdir "$target/$name" || return 1
      child_lower="$lower/$name"
      [ "$merge_lower" -eq 1 ] || child_lower=$child
      populate "$child" "$child_lower" "$target/$name" || return 1
    else
      reference="$lower/$name"
      [ -e "$reference" ] || reference=$lower
      label_module "$child" "$reference" || return 1
      if [ -d "$child" ]; then mkdir "$target/$name"; else touch "$target/$name"; fi
      mount --bind "$child" "$target/$name" && record_mount "$target/$name" || return 1
    fi
  done
)

mirror() (
  source=$1
  target=$2
  view=$(mktemp -d "$state/views/merged-XXXXXX") || return 1
  view=$(readlink -f "$view") || return 1
  mount -t tmpfs -o mode=0755 tmpfs "$view" && record_mount "$view" || return 1
  populate "$source" "$target" "$view" "${3:-0}" || return $?
  # Publish only the completed view. A failed build leaves the system untouched.
  awk '{print $1}' /proc/self/mountinfo > "$view.mounts" || return 1
  mount --rbind "$view" "$target" || return 1
  awk -v path="$target" 'NR == FNR { old[$1]=1; next }
    !old[$1] && ($5 == path || index($5, path "/") == 1) { print $1, $5 }' \
    "$view.mounts" /proc/self/mountinfo >> "$ledger"
)

# Each call is a subshell: recursive fallback keeps its own source/target variables.
project() (
  source=$1
  target=$2
  [ -e "$source" ] || [ -L "$source" ] || return 0
  if [ ! -L "$source" ] && [ -c "$source" ]; then
    device=$(stat -c %t:%T "$source") || return $?
    if [ "$device" = 0:0 ]; then
      [ -e "$target" ] || [ -L "$target" ] || return 0
      project "${source%/*}" "${target%/*}"
      return "$?"
    fi
  fi
  # Ledger targets are partition paths. Never split escaped mountinfo names incorrectly.
  case "$target" in *' '*|*'\'*|*'
'*) printf 'MAPLESU_MOUNT_PATH:%s\n' "$target" >&2; return 1 ;; esac
  if [ ! -e "$target" ]; then
    project "${source%/*}" "${target%/*}"
    return "$?"
  fi
  target=$(readlink -f "$target") || return 1
  if [ -d "$source" ] && [ -d "$target" ]; then
    if [ -f "$source/.replace" ]; then
      label_module "$source" "$target" || return 1
      mirror "$source" "$target"
      return "$?"
    fi
    # A parent projection must not absorb the separately mounted partitions.
    if [ "$source" = "$directory/system" ]; then
      mirror "$source" "$target" 1
      return "$?"
    fi
    label_module "$source" "$target" || return 1
    if mount -t overlay overlay -o "ro,lowerdir=$source:$target" "$target"; then
      record_mount "$target" || return 1
      # Overlay unions keep original entries; .replace explicitly replaces a subtree.
      find "$source" -name .replace -type f | while IFS= read -r marker; do
        directory=${marker%/.replace}
        relative=${directory#"$source"}
        [ -n "$relative" ] || continue
        mirror "$directory" "$target$relative" || exit $?
      done
      return "$?"
    fi
    mirror "$source" "$target"
    return "$?"
  fi
  label_module "$source" "$target" || return 1
  mount --bind "$source" "$target" && record_mount "$target"
)

overall=0
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || exit 2
  module=$1
  directory=$2
  shift 2
  code=0
  if [ ! -f "$directory/skip_mount" ]; then
    # Keep split partitions separate: /system/vendor may itself be a mount/symlink.
    if [ -d "$directory/system" ]; then
      if [ -f "$directory/system/.replace" ]; then
        project "$directory/system" /system || code=1
      else
      for child in "$directory/system"/* "$directory/system"/.[!.]* "$directory/system"/..?*; do
        [ -e "$child" ] || [ -L "$child" ] || continue
        case "${child##*/}" in
          vendor|product|system_ext|odm|oem|.replace) continue ;;
        esac
        project "$child" "/system/${child##*/}" || code=1
      done
      fi
    fi
    for partition in vendor product system_ext odm oem; do
      for source in "$directory/system/$partition" "$directory/$partition"; do
        [ -d "$source" ] || continue
        project "$source" "/$partition" || code=1
      done
    done
  fi
  printf 'MAPLESU_MOUNT_RESULT:%s:%s\n' "$module" "$code"
  [ "$code" -eq 0 ] || overall=1
done
exit "$overall"
