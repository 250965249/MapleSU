package me.yuki.fina.adbroot.flow

/** 设备端固定路径。 */
object Device {
    const val TMP = "/data/local/tmp"
    const val CHAN = "$TMP/chan"

    /** Work directory of the per-kernel plant engine (batch, wrapper, plant). */
    const val PLANT = "$TMP/maplesu-93260"

    /** 漏洞程序在设备上的文件名（可改，避免被特征匹配；内部靠 /proc/self/exe 自举，与文件名无关）。 */
    const val EXP = "louise"
    const val EXP_PATH = "$TMP/$EXP"

    /** 旧版本用过的名字，残留检测与收尾要一并处理。 */
    val EXP_LEGACY = listOf("gandalfr", "tpd_calib", "timer98260")

    const val LOG = "$TMP/louise.log"

    /** 旧版本的日志名。 */
    val LOG_LEGACY = listOf("$TMP/gandalfr.log", "$TMP/tpd_calib.log", "$TMP/fakeR.log")

    const val KALL = "$TMP/kall"

    val FILES = listOf(
        EXP to EXP_PATH,
        "louise_cmd.sh" to "$TMP/louise_cmd.sh",
        "probe" to "$TMP/probe",
    )

    /** 收尾时该删掉的临时文件（新旧名字都删，避免上一版残留）。 */
    val CLEAN_FILES = buildList {
        add(EXP_PATH)
        EXP_LEGACY.forEach { add("$TMP/$it") }
        add("$TMP/louise_cmd.sh")
        add("$TMP/fake_shell.sh")  // 旧名，留给老版本残留
        add("$TMP/probe")
        add(LOG)
        LOG_LEGACY.forEach { add(it) }
    }

    /**
     * 我们会在 /data/local/tmp 留下的全部东西（专有名字）。
     *
     * 为什么需要一个集中清单：清理代码原先只写在「root 批次末尾」，
     * 只要批次没跑到（推送失败 / 漏洞没命中 / 用户中途退出），残留就会一直躺着，
     * 而且旧清单里漏了 kall、mgr_ksud_path、ksu_stage.sh、mgr_*.apk 这些后加的文件。
     */
    val TMP_JUNK = buildList {
        add(EXP_PATH)
        add(LOG)
        add("$TMP/louise_cmd.sh")
        add("$TMP/fake_shell.sh")  // 旧名，留给老版本残留
        add("$TMP/kall")
        add("$TMP/mgr_ksud_path")
        add("$TMP/ksu_stage.sh")
        add("$TMP/PD2546-symbols.json")
        // 更早版本（v1.x / 2.0.x）留下的名字与中间产物
        add("$TMP/ksud_p")
        add("$TMP/drv.ko")
        add("$TMP/drv2.ko")
        add("$TMP/drv3.ko")
        add("$TMP/drv_fixed.ko")
        add("$TMP/ins.log")
        add("$TMP/ki.log")
        add("$TMP/ks1.log")
        add("$TMP/ks2.log")
        add("$TMP/ks3.log")
        add("$TMP/stop.sh")
        add("$TMP/.rf_wtest")
        add("$TMP/kallsyms.json")
        EXP_LEGACY.forEach { add("$TMP/$it"); add("$TMP/$it.log") }
        LOG_LEGACY.forEach { add(it) }
    }

    /**
     * 名字太通用、必须按「尺寸对得上」才删的文件。
     *
     * 场景：别人的工具也可能在 /data/local/tmp 放名叫 `probe` 或 `ksud` 的东西，
     * 无条件 rm 会误伤。这里只认我们历史上真正用过的尺寸。
     */
    val TMP_JUNK_GUARDED: Map<String, List<Long>> = mapOf(
        // kprobe_trigger：一直是 1,059,616 B
        "$TMP/probe" to listOf(1_059_616L),
        // 内置 ksud：官方 6,614,808 / 6,518,008；各家管理器自带的也见过这些尺寸
        "$TMP/ksud" to listOf(
            6_614_808L, 6_518_008L, 5_173_696L, 7_561_328L, 6_093_280L,
            5_953_680L, 5_383_728L, 5_169_344L,
        ),
    )

    /**
     * 清理脚本：先停住上一轮的 dispatcher（只 SIGSTOP，绝不 kill），再删文件与目录。
     * 只清理 /data/local/tmp 里面的东西，永不删 /data/local/tmp 本身。
     * 既能在 shell（Shizuku）下跑，也能在 root 批次里跑；su 不存在时那半句会被忽略。
     */
    val CLEAN_SCRIPT = buildString {
        // 先冻住漏洞本体（louise fake / exe wait fake 同名）与上一轮的 dispatcher：
        // 只 SIGSTOP，绝不 kill —— kill 掉会让父进程 waitpid 返回、释放 fake cred 页 → 内核 panic。
        append("for n in $EXP ")
        EXP_LEGACY.forEach { append("$it ") }
        append("; do for p in ${'$'}(pidof ${'$'}n 2>/dev/null); do ")
        append("kill -STOP ${'$'}p 2>/dev/null; done; done; ")
        append("for p in ${'$'}(ps -A -o PID,ARGS 2>/dev/null | grep -E 'louise_cmd.sh|fake_shell.sh' | grep -v grep | awk '{print ${'$'}1}'); do ")
        append("kill -STOP ${'$'}p 2>/dev/null; done; ")

        // 核心清理：专有名字直接删，通用名字按尺寸删，最后删目录
        val core = buildString {
            append("rm -f $EXP_PATH $LOG $TMP/louise_cmd.sh $TMP/probe $KALL $TMP/PD2546-symbols.json $TMP/.rf_wtest 2>/dev/null; ")
            append("rm -rf $CHAN 2>/dev/null; ")
            append("rm -rf $PLANT 2>/dev/null; ")
        }
        // 先用 shell 身份跑一遍，再让 root 跑一遍（旧版本有些文件是 root 属主）
        append(core)
        append("/system/bin/su -c \"" + core + "\" >/dev/null 2>&1; ")
        append("echo RF_CLEANED")
    }
}
