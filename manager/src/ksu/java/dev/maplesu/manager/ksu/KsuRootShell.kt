// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.File
import java.util.Collections
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeoutException

/**
 * KSU 命令面的**提权接缝**（2026-11-01 收尾）。
 *
 * 背景（审计 §D0「KSU 命令后端不提权」）：`KsuCommandBackend` 原来用 [LibsuShellRunner]
 * 以 **app uid** 起 ksud 进程，于是 `ksud module list` / `feature get` 读
 * `/data/adb/modules`、`/data/adb/ksu/.feature_config` 时被内核拒绝（0700 root），
 * 表现为"列表为空 / 设置读不到"，看上去像成功。
 *
 * 现在分成两层：
 * 1. [KsuRootShellExecutor]：装配层注入的"起一条已认证 root shell 跑一行命令"能力
 *    （生产实现由 `KsuBackendRegistry` 用 [KsuRootChannel] 装配；主机测试注入 fake）；
 * 2. [RootShellKsuRunner]：把 `List<String>` token 拼成一整行（[KsuInstallProducer.shellJoin]
 *    的引号规则）后交给上面那层 —— **不**再以 app uid 起进程。
 *
 * 未装配时 [KsuRootShell.runner] 返回的 runner **显式失败**（code=-1 +
 * `KSU_ROOT_SHELL_UNAVAILABLE:...`），不会静默降级成 app uid 执行。
 */
fun interface KsuRootShellExecutor {
    /** 在一条已认证 root shell 里执行 [commandLine]；实现方负责开/关 shell。 */
    fun exec(commandLine: String): KsuShellResult

    /** 旧实现沿用原调用；生产实现显式覆盖以执行调用方期限。 */
    fun exec(commandLine: String, timeoutMs: Long): KsuShellResult = exec(commandLine)

    fun readFeatureBatch(commandLines: List<String>, timeoutMs: Long): List<KsuShellResult> {
        val deadline = System.nanoTime() + timeoutMs.coerceAtLeast(1L) * 1_000_000L
        return commandLines.map { command ->
            val remaining = (deadline - System.nanoTime()) / 1_000_000L
            if (remaining <= 0L) KsuShellResult(-1, emptyList(), listOf("FEATURE_READ_TIMEOUT"))
            else exec(command, remaining)
        }
    }

    /**
     * 在**全局挂载命名空间**的 root shell 里执行 [commandLine]（模块 Action 用）。
     *
     * 默认实现 = [exec]（保持既有 fake/SAM 替身可用）；生产实现由装配层提供
     * `KsuRootChannel.openShell(globalMnt = true)`，对应上游 `withNewRootShell(true)`
     * （`upstream/manager/.../ui/util/KsuCli.kt:282-285`）。
     */
    fun execInGlobalMount(commandLine: String): KsuShellResult = exec(commandLine)

    fun execInGlobalMount(commandLine: String, timeoutMs: Long): KsuShellResult =
        execInGlobalMount(commandLine)

    fun execStreaming(
        commandLine: String, timeoutMs: Long, globalMnt: Boolean,
        onStdout: (String) -> Unit, onStderr: (String) -> Unit,
    ): KsuShellResult = (if (globalMnt) execInGlobalMount(commandLine, timeoutMs)
        else exec(commandLine, timeoutMs)).also {
        it.out.forEach(onStdout)
        it.err.forEach(onStderr)
    }
}

/**
 * 一次路径探测（`/data/adb` 是 0700 root，app uid 读不到）。
 *
 * 两个问题要分开回答，因为答案不同：`libadbroot.so` 只是库（`-e` 就够），
 * `ksud` 必须可执行（`-x`）。合并成一个 `isFile` 会让"部署了但没执行位"被判成成功。
 */
interface KsuPathProbe {
    fun exists(path: String): Boolean

    /** 默认等于 [exists]；部署/启动器路径的实现必须真的检查执行位。 */
    fun canExecute(path: String): Boolean = exists(path)

    companion object {
        /** APK 自带路径的本地探测（app 可读，无进程）。 */
        val LOCAL: KsuPathProbe = object : KsuPathProbe {
            override fun exists(path: String): Boolean =
                runCatching { File(path).isFile }.getOrDefault(false)

            override fun canExecute(path: String): Boolean =
                runCatching { File(path).let { it.isFile && it.canExecute() } }.getOrDefault(false)
        }
    }
}

/**
 * 进程内 root shell 装配点：`KsuBackendRegistry` 在模式激活为 KSU 后调用 [install]。
 *
 * 这里是"进程级单例接缝"，因为 `KsuCommandBackend` 由 `KsuBackends` 在任意位置构造，
 * 拿不到 `Context`；把 `Context` 相关的东西留在装配层，后端保持可主机测试。
 */
object KsuRootShell {

    @Volatile
    private var executor: KsuRootShellExecutor? = null

    @Volatile
    private var probe: KsuPathProbe? = null

    fun install(executor: KsuRootShellExecutor?, probe: KsuPathProbe? = null) {
        this.executor = executor
        this.probe = probe
    }

    fun resetForTest() {
        executor = null
        probe = null
    }

    fun isInstalled(): Boolean = executor != null

    /** 生产 runner：未装配 → 每次命令都显式失败（绝不 app uid 执行）。 */
    fun runner(globalMnt: Boolean = false): KsuShellRunner = RootShellKsuRunner(
        object : KsuRootShellExecutor {
            override fun exec(commandLine: String): KsuShellResult =
                dispatch(commandLine, globalMnt = false)

            override fun exec(commandLine: String, timeoutMs: Long): KsuShellResult =
                dispatch(commandLine, globalMnt = false, timeoutMs = timeoutMs)

            override fun readFeatureBatch(commandLines: List<String>, timeoutMs: Long): List<KsuShellResult> {
                val installed = executor ?: return commandLines.map {
                    KsuShellResult(-1, emptyList(), listOf("$UNAVAILABLE:not wired"))
                }
                return installed.readFeatureBatch(commandLines, timeoutMs)
            }

            override fun execInGlobalMount(commandLine: String): KsuShellResult =
                dispatch(commandLine, globalMnt = true)

            override fun execInGlobalMount(commandLine: String, timeoutMs: Long): KsuShellResult =
                dispatch(commandLine, globalMnt = true, timeoutMs = timeoutMs)

            override fun execStreaming(
                commandLine: String, timeoutMs: Long, globalMnt: Boolean,
                onStdout: (String) -> Unit, onStderr: (String) -> Unit,
            ): KsuShellResult = dispatch(commandLine, globalMnt, timeoutMs, onStdout, onStderr)

            private fun dispatch(
                commandLine: String, globalMnt: Boolean, timeoutMs: Long? = null,
                onStdout: ((String) -> Unit)? = null, onStderr: ((String) -> Unit)? = null,
            ): KsuShellResult {
                val installed = executor ?: return KsuShellResult(
                    -1, emptyList(), listOf("$UNAVAILABLE:not wired"),
                ).also { it.err.forEach { line -> onStderr?.invoke(line) } }
                return if (onStdout != null && onStderr != null && timeoutMs != null) {
                    installed.execStreaming(commandLine, timeoutMs, globalMnt, onStdout, onStderr)
                } else if (globalMnt) {
                    if (timeoutMs == null) installed.execInGlobalMount(commandLine)
                    else installed.execInGlobalMount(commandLine, timeoutMs)
                } else {
                    if (timeoutMs == null) installed.exec(commandLine)
                    else installed.exec(commandLine, timeoutMs)
                }
            }
        },
        globalMnt = globalMnt,
    )

    /** 部署路径（`/data/adb/...`）的存在性探针；未装配时退回本地 File 探测。 */
    fun pathProbe(): KsuPathProbe = probe ?: KsuPathProbe.LOCAL

    const val UNAVAILABLE = "KSU_ROOT_SHELL_UNAVAILABLE"
}

/** [KsuShellRunner] 的 root shell 实现：token 列表 → 一行命令 → 已认证 root shell。 */
class RootShellKsuRunner(
    private val executor: KsuRootShellExecutor,
    /** `true` = 走 [KsuRootShellExecutor.execInGlobalMount]（模块 Action / one-shot）。 */
    private val globalMnt: Boolean = false,
) : KsuShellRunner {
    override fun readFeatureBatch(commands: List<List<String>>, timeoutMs: Long): List<KsuShellResult> =
        if (globalMnt) super<KsuShellRunner>.readFeatureBatch(commands, timeoutMs) else runCatching {
            executor.readFeatureBatch(commands.map { KsuInstallProducer.shellJoin(it) }, timeoutMs)
        }.getOrElse { error ->
            commands.map { KsuShellResult(-1, emptyList(), listOf("${KsuRootShell.UNAVAILABLE}:${error.javaClass.simpleName}")) }
        }

    override fun run(command: List<String>, timeoutMs: Long): KsuShellResult {
        if (command.isEmpty()) {
            return KsuShellResult(-1, emptyList(), listOf("EMPTY_COMMAND"))
        }
        val line = KsuInstallProducer.shellJoin(command)
        return try {
            if (globalMnt) executor.execInGlobalMount(line, timeoutMs) else executor.exec(line, timeoutMs)
        } catch (error: Exception) {
            KsuShellResult(-1, emptyList(), listOf(commandFailure(error)))
        }
    }

    override fun runStreaming(
        command: List<String>, timeoutMs: Long,
        onStdout: (String) -> Unit, onStderr: (String) -> Unit,
    ): KsuShellResult {
        if (command.isEmpty()) {
            onStderr("EMPTY_COMMAND")
            return KsuShellResult(-1, emptyList(), listOf("EMPTY_COMMAND"))
        }
        val out = Collections.synchronizedList(mutableListOf<String>())
        val err = Collections.synchronizedList(mutableListOf<String>())
        return try {
            executor.execStreaming(KsuInstallProducer.shellJoin(command), timeoutMs, globalMnt,
                { out.add(it); onStdout(it) }, { err.add(it); onStderr(it) })
        } catch (error: Exception) {
            val message = commandFailure(error)
            onStderr(message)
            KsuShellResult(-1, synchronized(out) { out.toList() }, synchronized(err) { err.toList() } + message)
        }
    }

    private fun commandFailure(error: Exception): String {
        val causes = generateSequence(error as Throwable) { it.cause }.take(8).toList()
        if (causes.any { it is InterruptedException }) Thread.currentThread().interrupt()
        val code = when {
            causes.any { it is TimeoutException } -> "KSU_COMMAND_TIMEOUT"
            causes.any { it is InterruptedException } -> "KSU_COMMAND_INTERRUPTED"
            causes.any { it is CancellationException } -> "KSU_COMMAND_CANCELLED"
            else -> KsuRootShell.UNAVAILABLE
        }
        val message = "$code:" + causes.joinToString(" <- ") { "${it.javaClass.simpleName}:${it.message.orEmpty()}" }
        KsuLog.record("root-shell-error", message)
        return message
    }
}

/**
 * 带 TTL 的路径探针缓存：`daemonExists()` 在列表/设置路径上被反复调用，
 * 每次都起一条 root shell 是不可接受的；`ttlMs = 0` 表示不缓存（默认，测试用）。
 */
class CachingKsuPathProbe(
    private val delegate: KsuPathProbe,
    private val ttlMs: Long = 5_000L,
    private val clock: () -> Long = { System.nanoTime() / 1_000_000L },
) : KsuPathProbe {
    private val lock = Any()
    private val cache = HashMap<String, Pair<Long, Boolean>>()

    private fun cached(key: String, probe: () -> Boolean): Boolean {
        if (ttlMs <= 0L) return probe()
        synchronized(lock) {
            val now = clock()
            val hit = cache[key]
            if (hit != null && now - hit.first in 0 until ttlMs) return hit.second
        }
        val fresh = probe()
        synchronized(lock) { cache[key] = clock() to fresh }
        return fresh
    }

    override fun exists(path: String): Boolean = cached("e:$path") { delegate.exists(path) }

    override fun canExecute(path: String): Boolean =
        cached("x:$path") { delegate.canExecute(path) }

    fun invalidate() = synchronized(lock) { cache.clear() }
}

/**
 * 生产探针：在已认证 root shell 里 `test -x <path>`。
 *
 * 为什么不用 `File(path)`：`/data/adb` 是 0700 root，Manager 进程（非 root）连
 * `stat` 都不行；用本地 File 判定会让**已正确部署**的 ksud 被判成"不存在"。
 */
fun rootShellPathProbe(executor: KsuRootShellExecutor): KsuPathProbe = object : KsuPathProbe {
    private fun test(flag: String, path: String): Boolean {
        val quoted = "'" + path.replace("'", "'\\''") + "'"
        val result = runCatching {
            executor.exec("/system/bin/test $flag $quoted && /system/bin/echo MAPLESU_PROBE_OK")
        }.getOrNull()
        return result != null && result.code == 0 &&
            result.out.any { it.trim() == "MAPLESU_PROBE_OK" }
    }

    override fun exists(path: String): Boolean = test("-e", path)

    override fun canExecute(path: String): Boolean = test("-x", path)
}
