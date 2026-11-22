#!/system/bin/sh
# root_dispatcher.sh —— 命令分发循环（被 setsid 拉起，环境 PATH 不可靠）
#
# 设计（2.7.0 起）：唤醒驱动 + 1 秒心跳
#   · 用 O_RDWR 打开 chan/wake 拿到一个常驻读端，然后 `read -r -t 1` 阻塞在内核 wait 队列里
#     —— 没有人写 wake 时它也在内核里睡满 1 秒（0 CPU），有人写就立即醒来处理 chan/run。
#   · 为什么不用 `read` 无限阻塞：万一 App 侧写入失败，没人唤醒就会一直卡到重启；
#     给 1 秒超时等价于「低频心跳」，既能被唤醒即时响应，又不会因为丢一次写而永久停止。
#   · 为什么所有命令都写绝对路径：setsid 拉起时 PATH 里可能没有 /system/bin，
#     裸 `sleep 1` 会是 `not found` 立即返回 → while 变成死循环 → 单核 100%。

CHAN=/data/local/tmp/chan
WAKE="$CHAN/wake"
MODE=poll

/system/bin/mkdir -p "$CHAN" 2>/dev/null
/system/bin/rm -f "$WAKE" 2>/dev/null
if /system/bin/mkfifo "$WAKE" 2>/dev/null && /system/bin/chmod 666 "$WAKE" 2>/dev/null && exec 3<>"$WAKE" 2>/dev/null; then
  MODE=wake
fi

echo "[fake] dispatcher ready (mode=$MODE)"

# 兜底延时：仅在 wake FIFO 不可用时使用（全绝对路径 + 多重保底）
pause() {
  /system/bin/sleep 1 2>/dev/null && return 0
  /system/bin/toybox sleep 1 2>/dev/null && return 0
  /system/bin/busybox sleep 1 2>/dev/null && return 0
  /system/bin/usleep 1000000 2>/dev/null && return 0
  /system/bin/ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1 && return 0
  return 0
}

while true; do
  if [ -f "$CHAN/run" ]; then
    # mv 成功才执行：并发实例 / run 在检查与 mv 之间被删掉时 mv 会失败，
    # 不能拿残留的 busy 去跑，否则同一条命令可能被执行两次。
    if /system/bin/mv "$CHAN/run" "$CHAN/busy" 2>/dev/null; then
      /system/bin/sh "$CHAN/busy" 2>&1
      /system/bin/rm -f "$CHAN/busy"
    fi
  fi
  if [ "$MODE" = wake ]; then
    read -r -t 1 _ <&3 2>/dev/null
  else
    pause
  fi
done