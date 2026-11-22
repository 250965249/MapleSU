package dev.maplesu.manager.parasite

import kotlinx.serialization.Serializable

/**
 * 寄生宿主记录（规格 §4.2 的最小字段；本阶段只做可主机验证的持久化）。
 *
 * 刻意**不包含**：原始 rootKey、管理 Binder、命令字符串、客户端自报 UID。
 * 状态与"四结果"分开保存：失败不得被某个 success 布尔覆盖（规格 §4.3）。
 */
@Serializable
data class ParasiteHostRecord(
    val schemaVersion: Int = SCHEMA,
    /** 一次显式接入的身份；解除后失效。 */
    val registrationId: String,
    val hostPackage: String,
    val hostUid: Int,
    /** 系统查询到的签名集合（排序后的 sha256；不落明文证书）。 */
    val hostSignerSha256: List<String> = emptyList(),
    /** 宿主正常构建中的入口组件。 */
    val entryComponent: String = "",
    /** 当前 MapleSU 安装身份引用（不含凭据）。 */
    val managerPackage: String = "",
    /** 目标进程 cmdline（做寄生定位用；不含密钥）。 */
    val targetPidCmdline: String,
    /** 被植入的 so 绝对路径（原库路径）。 */
    val originalSoPath: String,
    /** su 环境目录（`parasite_implant_su_env` 的 su_dir_path）。 */
    val suDirPath: String = "",
    /** 当前状态 wire 值（[ParasiteState]）。 */
    val state: String = ParasiteState.N0_IDLE.name,
    /** 四结果独立状态位，禁止合并成"成功"。 */
    val capabilities: ParasiteCapabilities = ParasiteCapabilities(),
    /** 临时模式来源（boot/attempt 引用）；普通模式为空。 */
    val runtimeOrigin: String = "",
    val bootId: String = "",
    val createdAt: Long = 0,
    val updatedAt: Long = 0,
    val lastResult: ParasiteLastResult? = null,
) {
    companion object { const val SCHEMA = 1 }

    fun stateEnum(): ParasiteState? =
        ParasiteState.entries.firstOrNull { it.name == state }
}

/** 四结果拆分（规格 §4.3 / 本轮任务第 5 条）：各自独立，可单独失败/重试。 */
@Serializable
data class ParasiteCapabilities(
    /** so 已加载进目标进程（implantApp 实际生效）。 */
    val soLoaded: Boolean = false,
    /** 网页资源实际可访问（HTTP/入口验证通过）。 */
    val webReachable: Boolean = false,
    /** 承载服务实际建立（会话/服务目录握手通过）。 */
    val serviceEstablished: Boolean = false,
    /** root 命令实际执行成功（不是"有管理入口"）。 */
    val rootCommandOk: Boolean = false,
) {
    /** 仅用于展示/验收汇总；不得作为状态机跃迁的唯一条件。 */
    val allFour: Boolean get() = soLoaded && webReachable && serviceEstablished && rootCommandOk
}

@Serializable
data class ParasiteLastResult(
    val at: Long,
    val phase: String,
    val code: String = "",
    val retryable: Boolean = false,
)

/** 状态常量（N0–N6）。 */
enum class ParasiteState(val wire: String) {
    N0_IDLE("N0_IDLE"),
    N1_PRECHECKED("N1_PRECHECKED"),
    N2_IMPLANTED("N2_IMPLANTED"),
    N3_HOST_LAUNCHED("N3_HOST_LAUNCHED"),
    N4_WEB_SERVING("N4_WEB_SERVING"),
    N5_RECOVERABLE("N5_RECOVERABLE"),
    N6_UNINSTALLED("N6_UNINSTALLED"),
    ;

    /** 终态：解除接入/卸载完成后不可再前进（只允许记录性 reset 供重新接入）。 */
    val terminal: Boolean get() = this == N6_UNINSTALLED
}
