package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.workmode.switch.ModeSwitchController
import dev.maplesu.manager.workmode.switch.ModeSwitchRecoveryUiState
import dev.maplesu.manager.workmode.switch.ModeSwitchRequest
import dev.maplesu.manager.workmode.switch.ModeSwitchRun
import dev.maplesu.manager.workmode.switch.ModeSwitchStatus
import dev.maplesu.manager.workmode.switch.RecoveryRun
import dev.maplesu.manager.workmode.switch.S0Report
import java.io.File

/**
 * W08 切换编排的 App 侧门面（供 UI/ViewModel/BootReceiver 调用）。
 *
 * 所有方法都是纯转发：无 Android 依赖，便于在主机单测里直接驱动
 * `ModeSwitchController`（Fake 端口）。真实依赖在 [ModeSwitchBindings] 组装。
 */
class ModeSwitchService internal constructor(
    private val controller: ModeSwitchController,
) {

    /** S0：只读预检（不改磁盘、不写 switch.json）。 */
    fun preflight(request: ModeSwitchRequest): S0Report = controller.preflight(request)

    /** S0→S4g。成功返回 [ModeSwitchRun.AwaitingReboot]；失败/需恢复按 [ModeSwitchRun] 分类。 */
    suspend fun begin(request: ModeSwitchRequest): ModeSwitchRun = controller.begin(request)

    /** S5：固定重启请求（先持久化 REBOOT_REQUESTED）。 */
    suspend fun requestReboot(switchId: String): ModeSwitchRun = controller.requestReboot(switchId)

    /** S6：重启后验证与收敛。 */
    suspend fun verifyAfterBoot(switchId: String): ModeSwitchRun = controller.verifyAfterBoot(switchId)

    /** 启动/手动恢复（journal 重放 + 读回判定）。 */
    suspend fun recover(switchId: String? = null): RecoveryRun = controller.recover(switchId)

    /** 用户显式回滚（仅 QUERY/恢复页动作调用）。 */
    suspend fun rollback(switchId: String): ModeSwitchRun = controller.rollback(switchId)

    /** 预写阶段中止（仅 BEGIN/SNAPSHOT/PRODUCE）。 */
    suspend fun abort(switchId: String): ModeSwitchRun = controller.abort(switchId)

    fun status(switchId: String? = null): ModeSwitchStatus? = controller.status(switchId)

    fun recoveryUiState(switchId: String? = null): ModeSwitchRecoveryUiState? =
        controller.recoveryUiState(switchId)

    /** 是否有未完成切换（阻断普通模块/设置写入；恢复入口豁免）。 */
    fun isSwitchPending(): Boolean = controller.status()?.pending == true

    /** 诊断导出（journal + recovery 文本）。 */
    fun exportDiagnostics(switchId: String, destination: File): File? =
        controller.exportDiagnostics(switchId, destination)
}
