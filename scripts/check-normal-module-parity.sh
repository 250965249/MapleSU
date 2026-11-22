#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# MapleSU Normal (=KSU) 模块子系统设备判据（开发文档 §7.2 / T13）。
# 在**设备上**以 root 执行；输出 "PASS|FAIL <id> <title>" 与 "raw: ..." 行。
# 退出码：0 = 全 PASS；1 = 有 FAIL；2 = 前置不满足（无 root / ksud 不可用）。
#
# 与文档的差异（以真机事实为准，见 evidence/normal-ksu-parity-20261102/T0-verdict.md）：
#  · P8 不用 `grep ' KSU ' /proc/mounts`：mountify 的挂载源是 overlay/mountify，恒为 0，
#    会把健康设备误判成失败；改为“metamodule 指针 + 有 lowerdir 指向 /data/adb”。
#  · P3 同时校验 uapi==7 与 version>0。

KSUD=/data/adb/ksud
LOGDIR=/data/adb/ksu/log
FAILS=0

say()  { echo "$@"; }
raw()  { echo "raw: $*"; }
pass() { echo "PASS $1 $2"; }
fail() { echo "FAIL $1 $2  code=$3"; FAILS=$((FAILS+1)); }

# ── 前置 ────────────────────────────────────────────────────────────────
[ "$(id -u)" = "0" ] || { echo "FAIL PRE-0 root-unavailable"; exit 2; }
[ -x "$KSUD" ]      || { echo "FAIL PRE-1 ksud-missing"; exit 2; }

NOW=$(date +%s)
# 本次开机时刻 = now - uptime。判据是"产物 mtime 晚于开机"（±90 s 容差），
# **不是**"距今多少秒内"——后者会让开机 15 分钟后跑检查的健康设备误判成失败。
UPTIME=$(/system/bin/cut -d' ' -f1 /proc/uptime | /system/bin/cut -d. -f1)
BOOT_EPOCH=$((NOW - UPTIME))

check_after_boot() { # $1=id $2=title $3=path $4=code
    if [ ! -e "$3" ]; then
        fail "$1" "$2" "$4"; raw "missing: $3"; return
    fi
    MT=$(/system/bin/stat -c %Y "$3" 2>/dev/null)
    if [ -z "$MT" ]; then
        fail "$1" "$2" "$4"; raw "stat failed: $3"; return
    fi
    if [ "$MT" -ge $((BOOT_EPOCH - 90)) ]; then
        pass "$1" "$2"
    else
        fail "$1" "$2" "$4"
    fi
    raw "mtime=$MT boot_epoch=$BOOT_EPOCH delta=$((MT - BOOT_EPOCH))s path=$3"
}

# P1 / P2 / P7：开机阶段产物必须晚于本次开机
check_after_boot P1 "boot-log-refreshed"    "$LOGDIR/logcat.log"   BOOT_LOG_NOT_REFRESHED
check_after_boot P2 "boot-dmesg-refreshed"  "$LOGDIR/dmesg.log"    BOOT_DMESG_NOT_REFRESHED
check_after_boot P7 "preinit-generated"     "/data/adb/ksu/preinit_status" PREINIT_NOT_GENERATED

# P3：版本配对（G5）
INFO=$("$KSUD" debug info 2>&1)
UAPI=$(echo "$INFO" | /system/bin/sed -n 's/^uapi_version: *\([0-9]*\).*/\1/p')
VER=$(echo "$INFO"  | /system/bin/sed -n 's/^version: *\([0-9]*\).*/\1/p')
if [ "${UAPI:-0}" = "7" ] && [ "${VER:-0}" -gt 0 ] 2>/dev/null; then
    pass P3 "ksud-uapi-version-matched"
else
    fail P3 "ksud-uapi-version-matched" KSUD_VERSION_MISMATCH
fi
raw "$(echo "$INFO" | tr '\n' ' ')"

# P4：module list 可解析
LIST=$("$KSUD" module list 2>&1)
if echo "$LIST" | /system/bin/grep -q '"id"'; then
    pass P4 "module-list-available"; raw "entries=$(echo "$LIST" | /system/bin/grep -c '"id"')"
else
    fail P4 "module-list-available" MODULE_LIST_UNAVAILABLE; raw "$(echo "$LIST" | head -3 | tr '\n' ' ')"
fi

# P5：模块脚本真跑
EXECN=$(/system/bin/grep -c 'ksud::module: exec /data/adb/modules/' "$LOGDIR/logcat.log" 2>/dev/null)
if [ "${EXECN:-0}" -gt 0 ] 2>/dev/null; then
    pass P5 "module-scripts-executed"; raw "exec lines=$EXECN"
else
    fail P5 "module-scripts-executed" MODULE_SCRIPTS_NOT_EXECUTED; raw "exec lines=${EXECN:-0}"
fi

# P6：启用集合 ⊆ exec 集合
ENABLED=""
for d in /data/adb/modules/*; do
    [ -d "$d" ] || continue
    [ -e "$d/disable" ] && continue
    [ -e "$d/remove" ] && continue
    ENABLED="$ENABLED $(basename "$d")"
done
EXECUTED=$(/system/bin/grep -o 'ksud::module: exec /data/adb/modules/[^/]*' "$LOGDIR/logcat.log" 2>/dev/null \
           | /system/bin/sed 's#.*/##' | sort -u | tr '\n' ' ')
MISSING=""
for m in $ENABLED; do
    case " $EXECUTED " in *" $m "*) ;; *) MISSING="$MISSING $m";; esac
done
if [ -z "$MISSING" ]; then
    pass P6 "enabled-modules-all-executed"
else
    fail P6 "enabled-modules-all-executed" MODULE_EXEC_PARTIAL
fi
raw "enabled=$(echo $ENABLED | wc -w) missing:${MISSING:-none}"

# P8：metamodule（条件判据；适配 mountify）
#   · 没有 metamodule 指针        → 不适用（PASS，注明）
#   · 有指针但**没有任何模块带 system/ 载荷** → 不适用（没有东西可挂，mountify 会自报
#     "no modules mounted"，此时判失败是假绿的反面：假红）
#   · 有指针且有 system/ 载荷     → 必须有 lowerdir 指向 /data/adb 的挂载
SYS_PAYLOAD=""
for d in /data/adb/modules/*; do
    if [ -d "$d/system" ] && [ -n "$(ls -A "$d/system" 2>/dev/null)" ]; then
        SYS_PAYLOAD="$SYS_PAYLOAD $(basename "$d")"
    fi
done
if [ -L /data/adb/metamodule ] || [ -d /data/adb/metamodule ]; then
    MNT=$(/system/bin/grep -c 'lowerdir=.*data/adb' /proc/mounts 2>/dev/null)
    if [ -z "$SYS_PAYLOAD" ]; then
        pass P8 "metamodule-mounted"
        raw "pointer=$(readlink -f /data/adb/metamodule) 但没有模块带 system/ 载荷 -> not applicable (lowerdir mounts=${MNT:-0})"
    elif [ "${MNT:-0}" -gt 0 ] 2>/dev/null; then
        pass P8 "metamodule-mounted"; raw "lowerdir mounts=$MNT payloads=$SYS_PAYLOAD"
    else
        fail P8 "metamodule-mounted" METAMODULE_NOT_MOUNTED
        raw "pointer=$(readlink -f /data/adb/metamodule) lowerdir-mounts=0 payloads=$SYS_PAYLOAD"
    fi
else
    if [ -z "$SYS_PAYLOAD" ]; then
        pass P8 "metamodule-mounted"; raw "no metamodule pointer, no system payloads -> not applicable"
    else
        fail P8 "metamodule-mounted" METAMODULE_NOT_MOUNTED
        raw "no metamodule pointer but system payloads exist:$SYS_PAYLOAD"
    fi
fi

# P9：zygisk 守护（条件判据）
if [ -d /data/adb/modules/zygisksu ]; then
    ZN=$(pgrep -c -f zn-daemon 2>/dev/null)
    if [ "${ZN:-0}" -gt 0 ] 2>/dev/null; then
        pass P9 "zygisk-daemon-present"; raw "zn-daemon=$ZN"
    else
        fail P9 "zygisk-daemon-present" ZYGISK_DAEMON_ABSENT; raw "zn-daemon=0"
    fi
else
    pass P9 "zygisk-daemon-present"; raw "zygisksu not installed -> not applicable"
fi

# P10：busybox
/data/adb/ksu/bin/busybox true 2>/dev/null
if [ $? -eq 0 ]; then pass P10 "busybox-usable"; else fail P10 "busybox-usable" BUSYBOX_UNUSABLE; fi

# G6：部署内容寻址（给了期望摘要才校验）
if [ -n "$MAPLESU_EXPECTED_KSUD_SHA256" ]; then
    ACTUAL=$(sha256sum "$KSUD" 2>/dev/null | /system/bin/cut -d' ' -f1)
    if [ "$ACTUAL" = "$MAPLESU_EXPECTED_KSUD_SHA256" ]; then
        pass G6 "ksud-digest-matched"
    else
        fail G6 "ksud-digest-matched" KSUD_DIGEST_MISMATCH
    fi
    raw "actual=$ACTUAL expected=$MAPLESU_EXPECTED_KSUD_SHA256"
fi

# G7：Action 命令形态（无 -g 必须 rc=0；带 -g 必须 rc=2 且报 unexpected argument）
ACT_MOD=""
for d in /data/adb/modules/*; do
    if [ -f "$d/action.sh" ] && [ ! -e "$d/disable" ]; then ACT_MOD=$(basename "$d"); break; fi
done
if [ -n "$ACT_MOD" ]; then
    "$KSUD" module action "$ACT_MOD" >/dev/null 2>&1
    RC_OK=$?
    ERR=$("$KSUD" module action "$ACT_MOD" -g 2>&1); RC_G=$?
    if [ $RC_OK -eq 0 ]; then pass G7a "action-without-dash-g ($ACT_MOD)"; else fail G7a "action-without-dash-g ($ACT_MOD)" ACTION_FAILED; fi
    raw "no-g rc=$RC_OK"
    if [ $RC_G -ne 0 ] && echo "$ERR" | /system/bin/grep -q "unexpected argument"; then
        pass G7b "action-with-dash-g-rejected"
    else
        fail G7b "action-with-dash-g-rejected" ACTION_DASH_G_ACCEPTED
    fi
    raw "with-g rc=$RC_G err=$(echo "$ERR" | head -1)"
else
    pass G7a "action-without-dash-g"; raw "no module with action.sh -> not applicable"
    pass G7b "action-with-dash-g-rejected"; raw "not applicable"
fi

echo ""
if [ $FAILS -eq 0 ]; then echo "== ALL PASS =="; exit 0; else echo "== $FAILS FAILED =="; exit 1; fi
