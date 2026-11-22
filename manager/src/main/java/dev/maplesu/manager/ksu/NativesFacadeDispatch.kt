// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import com.maplesu.core.Natives.Profile
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import java.util.concurrent.atomic.AtomicInteger

/**
 * `com.maplesu.core.Natives` 的门面分派桥。
 *
 * 为什么这个文件在 `src/main` 而不是 `src/ksu`：
 * - 它属于**集成层 glue**（任务 W11b 的写作用域），不是 KSU JNI 后端本体；
 * - JNI 后端（`KsuNatives`/`KsuNativesBackend`/`KsuCommandBackend`）仍只在
 *   `manager/src/ksu/java/dev/maplesu/manager/ksu/`，由 wm-ksu 持有（本文件只 **读取** 它）。
 * 边界由 `KsuSourceIsolationTest` 机器校验（见该测试的 glue 白名单）。
 *
 * 分派规则（硬约束，禁止 `?: LITE` 兜底）：
 * | `ModeRuntime.active` | 请求性质 | 目标 |
 * |---|---|---|
 * | `WorkMode.LITE` | 任何 | [NativesFacadeTarget.LITE]（原 Lite 表达式） |
 * | `WorkMode.KSU` | 任何 | [NativesFacadeTarget.KSU]（JNI 后端） |
 * | `null`（未判定）| [ModeIntent.IMPLICIT]（静默后台任务）| [NativesFacadeTarget.BLOCKED]：无能力默认值，不碰 Lite 探测、不碰 JNI |
 * | `null`（未判定）| [ModeIntent.EXPLICIT_LITE]（用户在安装页显式点安装）| [NativesFacadeTarget.LITE]：继续原 Lite 安装实现 |
 *
 * 注：`ModeRuntime.active` 是进程内唯一模式事实；本桥**不缓存**模式，
 * 因此切换/激活后无需失效任何缓存。
 */

/** 门面分派目标。三值齐全；`BLOCKED` 是"未判定 + 静默任务禁止执行"的表达。 */
enum class NativesFacadeTarget { LITE, KSU, BLOCKED }

/**
 * 未判定态下调用方的**显式意图**。
 *
 * - [IMPLICIT]：静默后台任务（开机服务、自检、组合期探测、自动部署）。未判定时必须阻断，
 *   否则会在用户还没有确认模式时偷偷执行某个模式专属动作（主文档 D15 / §7.4 纪律 3）。
 * - [EXPLICIT_LITE]：用户在安装页显式点了"安装/自修补"。这是用户的直接动作，未判定态
 *   不代表用户不能继续用 Lite 自装；按 D15「禁止**默认**执行 Lite」的正确语义放行。
 */
enum class ModeIntent { IMPLICIT, EXPLICIT_LITE }

/**
 * `Natives` 后端端口（28 个成员）。
 *
 * 与 `com.maplesu.core.Natives` 的公开签名一一对应；`Natives` 只做
 * `when (target(request.intent)) { LITE -> 原表达式; KSU -> port; BLOCKED -> blockedPort }`。
 */
interface NativesFacadePort {
    val version: Int
    val isSafeMode: Boolean
    val isLkmMode: Boolean
    val isLkmBundled: Boolean
    val isLateLoadMode: Boolean
    val isManager: Boolean
    val isPrBuild: Boolean
    val kernelUAPIVersion: Int
    val managerUAPIVersion: Int
    fun uidShouldUmount(uid: Int): Boolean
    fun appLockState(): Int
    fun appLockAuth(hash: ByteArray): Boolean
    fun appLockSet(hash: ByteArray, disable: Boolean): Boolean
    fun stealthState(): Int
    fun stealthSet(enabled: Boolean): Boolean
    fun getAppProfile(key: String?, uid: Int): Profile?
    fun setAppProfile(profile: Profile?): Boolean
    fun isSuEnabled(): Boolean
    fun setSuEnabled(enabled: Boolean): Boolean
    fun isKernelUmountEnabled(): Boolean
    fun setKernelUmountEnabled(enabled: Boolean): Boolean
    fun isSelinuxHideEnabled(): Boolean
    fun setSelinuxHideEnabled(enabled: Boolean): Int
    fun getUserName(uid: Int): String?
    fun getSuperuserCount(): Int
    fun setDefaultUmountModules(enabled: Boolean): Boolean
    fun isDefaultUmountModules(): Boolean
    fun isFullFeatured(): Boolean
}

/**
 * 未判定态的无能力端口（03 §3.4.2 右列，全部常量）。
 *
 * 刻意**不读取**任何环境：`isManager=false` 而不是去问 Lite 的 Ultra/凭据探测，
 * 否则「未判定」会被 Lite 的探测结果悄悄变成「Lite 已激活」。
 */
object BlockedNativesFacadePort : NativesFacadePort {
    override val version: Int = -1
    override val isSafeMode: Boolean = false
    override val isLkmMode: Boolean = false
    override val isLkmBundled: Boolean = false
    override val isLateLoadMode: Boolean = false
    override val isManager: Boolean = false
    override val isPrBuild: Boolean = false
    override val kernelUAPIVersion: Int = -1
    override val managerUAPIVersion: Int = -1
    override fun uidShouldUmount(uid: Int): Boolean = false
    override fun appLockState(): Int = -1
    override fun appLockAuth(hash: ByteArray): Boolean = false
    override fun appLockSet(hash: ByteArray, disable: Boolean): Boolean = false
    override fun stealthState(): Int = -1
    override fun stealthSet(enabled: Boolean): Boolean = false
    // 与 7K JNI 的 useDefaultProfile 分支同形：默认 profile 不是"拒绝过"（03 §3.9）。
    override fun getAppProfile(key: String?, uid: Int): Profile = Profile(key ?: "", uid)
    override fun setAppProfile(profile: Profile?): Boolean = false
    override fun isSuEnabled(): Boolean = false
    override fun setSuEnabled(enabled: Boolean): Boolean = false
    override fun isKernelUmountEnabled(): Boolean = false
    override fun setKernelUmountEnabled(enabled: Boolean): Boolean = false
    override fun isSelinuxHideEnabled(): Boolean = false
    override fun setSelinuxHideEnabled(enabled: Boolean): Int = -1
    override fun getUserName(uid: Int): String? = null
    override fun getSuperuserCount(): Int = -1
    override fun setDefaultUmountModules(enabled: Boolean): Boolean = false
    override fun isDefaultUmountModules(): Boolean = true
    override fun isFullFeatured(): Boolean = false
}

/**
 * KSU 端口：把 `src/ksu` 的 [KsuNativesBackend] 适配成门面端口。
 *
 * 延迟装配：只有第一次真正读取 KSU 成员时才触碰 `KsuBackends`（会加载 native）。
 * 因此 LITE/BLOCKED 分支不可能因为本类而加载 `libmaplesu_ksu.so`（03 §3.2 R5）。
 */
internal class KsuNativesFacadePort(
    private val backendFactory: () -> KsuNativesBackend = { KsuBackends.natives() },
) : NativesFacadePort {
    private val backend: KsuNativesBackend by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { backendFactory() }

    override val version: Int get() = backend.version
    override val isSafeMode: Boolean get() = backend.isSafeMode
    override val isLkmMode: Boolean get() = backend.isLkmMode
    override val isLkmBundled: Boolean get() = backend.isLkmBundled
    override val isLateLoadMode: Boolean get() = backend.isLateLoadMode
    override val isManager: Boolean get() = backend.isManager
    override val isPrBuild: Boolean get() = backend.isPrBuild
    override val kernelUAPIVersion: Int get() = backend.kernelUAPIVersion
    override val managerUAPIVersion: Int get() = backend.managerUAPIVersion
    override fun uidShouldUmount(uid: Int): Boolean = backend.uidShouldUmount(uid)
    override fun appLockState(): Int = backend.appLockState()
    override fun appLockAuth(hash: ByteArray): Boolean = backend.appLockAuth(hash)
    override fun appLockSet(hash: ByteArray, disable: Boolean): Boolean =
        backend.appLockSet(hash, disable)
    override fun stealthState(): Int = backend.stealthState()
    override fun stealthSet(enabled: Boolean): Boolean = backend.stealthSet(enabled)
    override fun getAppProfile(key: String?, uid: Int): Profile? = backend.getAppProfile(key, uid)
    override fun setAppProfile(profile: Profile?): Boolean = backend.setAppProfile(profile)
    override fun isSuEnabled(): Boolean = backend.isSuEnabled()
    override fun setSuEnabled(enabled: Boolean): Boolean = backend.setSuEnabled(enabled)
    override fun isKernelUmountEnabled(): Boolean = backend.isKernelUmountEnabled()
    override fun setKernelUmountEnabled(enabled: Boolean): Boolean =
        backend.setKernelUmountEnabled(enabled)
    override fun isSelinuxHideEnabled(): Boolean = backend.isSelinuxHideEnabled()
    override fun setSelinuxHideEnabled(enabled: Boolean): Int = backend.setSelinuxHideEnabled(enabled)
    override fun getUserName(uid: Int): String? = backend.getUserName(uid)
    override fun getSuperuserCount(): Int = backend.getSuperuserCount()
    override fun setDefaultUmountModules(enabled: Boolean): Boolean =
        backend.setDefaultUmountModules(enabled)
    override fun isDefaultUmountModules(): Boolean = backend.isDefaultUmountModules()
    override fun isFullFeatured(): Boolean = backend.isFullFeatured()
}

/**
 * 分派决策与端口供给（`Natives` 的唯一依赖）。
 *
 * 测试注入：`installForTest`（`internal` + 命名带 ForTest）；生产代码不得调用。
 * 计数器 [ksuPortRequests] 用来证明 LITE/未判定分支**一次都没有**请求 KSU 端口；
 * [explicitLiteEscalations] 用来证明"未判定 + 显式 Lite"确实按显式放行而非默认 LITE。
 */
object NativesFacade {
    /**
     * KSU 分支的 `MINIMAL_SUPPORTED_KERNEL`（applied 上游 `Natives.kt:27`）。
     *
     * 它**不再**通过 `com.maplesu.core.Natives.MINIMAL_SUPPORTED_KERNEL` 暴露：
     * 后者按审计要求保持 `const val`（静态字段，LITE 值），旧调用点字节语义不变。
     */
    internal const val KSU_MINIMAL_SUPPORTED_KERNEL = 32513

    /** KSU 分支的 SELinux 域（applied 上游 `Natives.kt:29`）；用途仅 `Profile.context` 默认值。 */
    internal const val KSU_KERNEL_SU_DOMAIN = "u:r:ksu:s0"

    private val portRequests = AtomicInteger(0)
    private val explicitLiteEscalations = AtomicInteger(0)

    @Volatile
    private var ksuPortOverride: NativesFacadePort? = null

    @Volatile
    private var ksuPortInstance: NativesFacadePort? = null

    /** 测试注入的"当前激活模式"覆盖；[activeModeOverridden] = true 时生效。 */
    @Volatile
    private var activeModeOverride: WorkMode? = null

    @Volatile
    private var activeModeOverridden = false

    /** 每次分派回调（诊断/测试用；生产默认不挂）。 */
    @Volatile
    var observer: ((NativesFacadeTarget) -> Unit)? = null

    /**
     * 解析当前分派目标。
     *
     * [intent] 只影响"未判定"这一种情况：静默任务默认 [ModeIntent.IMPLICIT]（BLOCKED），
     * 用户显式动作传 [ModeIntent.EXPLICIT_LITE]（放行到原 Lite 实现）。
     * 一旦模式已激活，[intent] 不改变结果（已激活模式优先）。
     */
    fun target(intent: ModeIntent = ModeIntent.IMPLICIT): NativesFacadeTarget {
        val resolved = when (activeMode()) {
            WorkMode.LITE -> NativesFacadeTarget.LITE
            WorkMode.KSU -> NativesFacadeTarget.KSU
            null -> when (intent) {
                ModeIntent.EXPLICIT_LITE -> {
                    explicitLiteEscalations.incrementAndGet()
                    KsuLog.record("mode-gating", "explicit-lite while unresolved; continue original Ultra implementation")
                    NativesFacadeTarget.LITE
                }
                ModeIntent.IMPLICIT -> NativesFacadeTarget.BLOCKED
            }
        }
        observer?.invoke(resolved)
        return resolved
    }

    private fun activeMode(): WorkMode? =
        if (activeModeOverridden) activeModeOverride else ModeRuntime.active

    /**
     * `Progress`/模板类默认的 SELinux 域。
     *
     * `Natives.KERNEL_SU_DOMAIN` 保持 `const val ""`（旧静态字段不变）；KSU 模式新建
     * Profile 需要 `u:r:ksu:s0`，因此只把 **Profile 默认参数**切到本访问器，LITE 下仍为 ""。
     */
    fun kernelDomainForProfile(): String = when (target()) {
        NativesFacadeTarget.LITE -> ""
        NativesFacadeTarget.KSU -> KSU_KERNEL_SU_DOMAIN
        NativesFacadeTarget.BLOCKED -> ""
    }

    /** KSU 端口（延迟装配；每次调用计数，测试用 [ksuPortRequests] 断言未触达）。 */
    fun ksuPort(): NativesFacadePort {
        portRequests.incrementAndGet()
        ksuPortOverride?.let { return it }
        return ksuPortInstance ?: KsuNativesFacadePort().also { ksuPortInstance = it }
    }

    fun blockedPort(): NativesFacadePort = BlockedNativesFacadePort

    internal fun ksuPortRequests(): Int = portRequests.get()

    internal fun explicitLiteEscalations(): Int = explicitLiteEscalations.get()

    /**
     * 测试注入。`target == null` 或 [NativesFacadeTarget.BLOCKED] 都表示"未判定"：
     * - `null`：完全未判定；
     * - `BLOCKED`：兼容旧测试写法（未判定 + 静默任务的期望结果）。
     */
    internal fun installForTest(
        target: NativesFacadeTarget? = null,
        ksuPort: NativesFacadePort? = null,
    ) {
        activeModeOverridden = true
        activeModeOverride = when (target) {
            NativesFacadeTarget.LITE -> WorkMode.LITE
            NativesFacadeTarget.KSU -> WorkMode.KSU
            NativesFacadeTarget.BLOCKED, null -> null
        }
        ksuPortOverride = ksuPort
        ksuPortInstance = null
        portRequests.set(0)
        explicitLiteEscalations.set(0)
        observer = null
    }

    internal fun resetForTest() {
        installForTest(null, null)
    }
}
