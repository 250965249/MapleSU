package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootCapability
import dev.maplesu.manager.workmode.WorkMode
import java.io.File

/**
 * 客户端种类（用于诊断与测试断言；不改 UI 契约）。
 */
enum class ModeSwitchClientKind {
    /** 既有实现：libsu `RootService` + AIDL（Normal / KSU 与未判定态的可执行后端）。 */
    SERVICE,

    /** Ultra 根通道实现：[UltraRootModeSwitchClient]（Ultra = `WorkMode.LITE` + Ultra 环境可执行）。 */
    ULTRA_ROOT,
}

/**
 * 选择策略（纯函数，主机可测）：
 *
 * 只有同时满足 **Ultra 模式** 与 **Ultra 根后端可用** 才走 Ultra 根通道；其余一律保持
 * [ServiceClientModeSwitchClient] 的现行为（失败时仍是原 blocker，不新增假成功）。
 *
 * 判据说明：
 * - `RootExec.capability()` 在 Ultra 下由 [dev.maplesu.manager.runtime.RootExecutionRouter]
 *   先试 Ultra（`UltraEnvironmentProbe` 严格 Running）再试 Lite 内核凭据；因此
 *   `backend == ULTRA_ENV && available` 等价于"Ultra `run_root_cmd` 现在真的能执行"。
 * - 不看 `UltraEnvironmentProbe` 缓存之外的其它状态，也不读 prefs（避免第二套判据）。
 */
object ModeSwitchClientPolicy {
    fun select(activeMode: WorkMode?, capability: RootCapability): ModeSwitchClientKind {
        if (activeMode != WorkMode.LITE) return ModeSwitchClientKind.SERVICE
        if (!capability.available) return ModeSwitchClientKind.SERVICE
        if (capability.backend != RootBackend.ULTRA_ENV) return ModeSwitchClientKind.SERVICE
        return ModeSwitchClientKind.ULTRA_ROOT
    }
}

/**
 * 延迟选择 + 单向钉扎的 [ModeSwitchClient] 代理。
 *
 * 为什么不能只在装配时选一次：`ModeSwitchRuntime.initialize` 在 `Application.onCreate`
 * 早期执行，此时 `ModeRuntime.active` 往往还是 null（模式判定在 root 取证之后）。若那时
 * 就固定成 SERVICE，Ultra 会永远走 libsu（起不来）→ 原缺陷不变。
 *
 * 语义：
 * - 每次调用重新评估 [usePro]（`RootExec.capability()` 自带 2s 缓存，`ModeRuntime.active`
 *   是 volatile，成本可忽略）；
 * - 一旦 Ultra 被选中就**钉扎**（`Ultra` 无法再退回 SERVICE）：切换事务跨多次调用，后端不能
 *   在中途翻转；Ultra 真的坏掉时由 [UltraRootModeSwitchClient] 返回结构化 `SWITCH_ROOT_UNAVAILABLE`；
 * - 未选中 Ultra 之前始终返回 [service]（= 改造前的行为，不改变任何既有失败码）。
 */
class SelectingModeSwitchClient(
    private val service: ModeSwitchClient,
    private val ultraFactory: () -> ModeSwitchClient,
    private val usePro: () -> Boolean,
) : ModeSwitchClient {

    @Volatile
    private var pinnedPro: ModeSwitchClient? = null

    @Volatile
    private var lastKind: ModeSwitchClientKind = ModeSwitchClientKind.SERVICE

    /** 诊断用：当前生效种类（ULTRA_ROOT 一旦出现不再回退）。 */
    fun selectedKind(): ModeSwitchClientKind = if (pinnedPro != null) {
        ModeSwitchClientKind.ULTRA_ROOT
    } else {
        lastKind
    }

    @Synchronized
    private fun current(): ModeSwitchClient {
        pinnedPro?.let { return it }
        val wantPro = runCatching { usePro() }.getOrDefault(false)
        if (!wantPro) {
            lastKind = ModeSwitchClientKind.SERVICE
            return service
        }
        val created = runCatching { ultraFactory() }.getOrNull()
        if (created == null) {
            lastKind = ModeSwitchClientKind.SERVICE
            return service
        }
        pinnedPro = created
        lastKind = ModeSwitchClientKind.ULTRA_ROOT
        return created
    }

    override suspend fun preflight(switchId: String, planFields: Map<String, String>): ClientResult =
        current().preflight(switchId, planFields)

    override suspend fun begin(
        switchId: String,
        planFields: Map<String, String>,
        superuserJson: File,
        settingsMirrorJson: File,
    ): ClientResult = current().begin(switchId, planFields, superuserJson, settingsMirrorJson)

    override suspend fun snapshot(switchId: String): ClientResult = current().snapshot(switchId)

    override suspend fun exportImage(
        switchId: String,
        kind: String,
        partition: String,
        destination: File,
    ): Boolean = current().exportImage(switchId, kind, partition, destination)

    override suspend fun submitCandidate(
        switchId: String,
        partition: String,
        candidate: File,
        candidateSha256: String,
    ): ClientResult = current().submitCandidate(switchId, partition, candidate, candidateSha256)

    override suspend fun commit(switchId: String): ClientResult = current().commit(switchId)

    override suspend fun rollback(switchId: String): ClientResult = current().rollback(switchId)

    override suspend fun abort(switchId: String): ClientResult = current().abort(switchId)

    override fun status(switchId: String): ClientStatus? = current().status(switchId)

    override fun statusExact(switchId: String): ClientStatus? = current().statusExact(switchId)

    override suspend fun verify(switchId: String): ClientResult = current().verify(switchId)

    override suspend fun markRebootRequested(switchId: String): Boolean =
        current().markRebootRequested(switchId)

    override suspend fun exportLog(switchId: String, destination: File): File? =
        current().exportLog(switchId, destination)
}
