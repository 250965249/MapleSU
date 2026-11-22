// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

/**
 * KSU 后端公共设施：日志、超时、拒绝语义。
 *
 * 设计约束：
 * - 本包（`src/ksu`）只在 KSU 模式或被集成轮显式调用时触碰；LITE 路径不得加载 native。
 * - unavailable 语义统一为「返回无能力默认值 + 一条日志」，**不抛异常、不起进程**。
 * - 日志走可注入 sink：JVM 单测里没有 `android.util.Log`，直接调用会在单测中抛
 *   `RuntimeException: Method ... not mocked`，因此这里默认写内存环形缓冲，App 启动时
 *   由集成层把 sink 接到 `android.util.Log`。
 */
object KsuLog {
    private const val MAX_RECORDS = 256
    private val records = ArrayDeque<String>(MAX_RECORDS)
    private val lock = Any()

    /** 集成层在 Application.onCreate 里接到 android.util.Log.i；默认不输出。 */
    @Volatile
    var sink: ((String) -> Unit)? = null

    fun record(event: String, detail: String) {
        val line = "ksu.$event: $detail"
        synchronized(lock) {
            if (records.size >= MAX_RECORDS) records.removeFirst()
            records.addLast(line)
        }
        sink?.invoke(line)
    }

    fun unavailable(component: String, reason: String) {
        record("unavailable", "$component reason=$reason")
    }

    fun rejected(component: String, token: String) {
        record("rejected", "$component token=$token")
    }

    /** 仅供测试/诊断：返回缓冲快照（最旧→最新）。 */
    fun snapshot(): List<String> = synchronized(lock) { records.toList() }

    fun clear() = synchronized(lock) { records.clear() }
}

/** 超时集中定义，禁止各处魔法数。 */
object KsuTimeouts {
    const val COMMAND_MS = 30_000L
    const val BOOT_PATCH_MS = 180_000L
    // Zero waits for the installer to exit, matching KernelSU's module installation.
    const val MODULE_INSTALL_MS = 0L
    const val BOOT_RESTORE_MS = 180_000L
    const val DEBUG_INFO_MS = 30_000L
}

/** ksud 命令构造被拒绝（参数级硬拒绝，不是文档约束）。 */
class KsuCommandRejectedException(
    val token: String,
    message: String,
) : IllegalArgumentException(message)

/** 本机/运行时不可用（native 未加载、ksud 不存在、未认主）。 */
class KsuUnavailableException(val component: String, message: String) :
    IllegalStateException(message)
