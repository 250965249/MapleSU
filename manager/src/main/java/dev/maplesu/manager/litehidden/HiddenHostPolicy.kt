package dev.maplesu.manager.litehidden

import dev.maplesu.manager.workmode.WorkMode

/**
 * 宿主选择纯策略（JVM 可测）：把 PackageManager 读到的**原始事实**判成可寄生/不可寄生。
 *
 * 过滤规则（缺一即排除；顺序固定，测试锁定）：
 * 1. 包名非法 → [HostReject.INVALID_PACKAGE]；
 * 2. MapleSU 自身 → [HostReject.SELF]（自己不能当载体）；
 * 3. 系统应用/系统更新应用 → [HostReject.SYSTEM_APP]；
 * 4. 非 arm64 → [HostReject.NO_ARM64]（32 位无法寄生）；
 * 5. 无 native 库 → [HostReject.NO_NATIVE_LIB]（没有 so 可改写）。
 *
 * 本文件不碰 Android API、不读图标、不含凭据/命令；Android 侧只负责把
 * PackageManager 结果映射成 [HostAppFacts]。
 */
data class HostAppFacts(
    val packageName: String,
    val label: String = "",
    val isSystem: Boolean = false,
    /** 该 App 的 ABI（取自 primaryCpuAbi + nativeLibraryDir 目录名）。 */
    val abis: List<String> = emptyList(),
    /** nativeLibraryDir 下确有 `.so`（不是"目录存在"）。 */
    val hasNativeLib: Boolean = false,
)

/** 不可作为宿主的原因（wire 码用于诊断/日志；UI 列表默认只展示可寄生项）。 */
enum class HostReject(val wire: String) {
    INVALID_PACKAGE("HOST_INVALID_PACKAGE"),
    SELF("HOST_SELF"),
    SYSTEM_APP("HOST_SYSTEM_APP"),
    NO_ARM64("HOST_NO_ARM64"),
    NO_NATIVE_LIB("HOST_NO_NATIVE_LIB"),
    ;

    companion object {
        fun fromWire(code: String?): HostReject? = entries.firstOrNull { it.wire == code }
    }
}

/** 可寄生宿主（只保留 UI 需要的字段；不含图标/凭据/路径）。 */
data class HostCandidate(
    val packageName: String,
    val label: String = "",
) {
    /** 列表展示名：名称为空回退包名（不伪造名称）。 */
    val displayName: String get() = label.trim().ifEmpty { packageName }
}

/** 单个 App 的判定结果（保留被排除原因，便于测试与诊断）。 */
sealed interface HostDecision {
    data class Eligible(val candidate: HostCandidate) : HostDecision

    data class Rejected(val packageName: String, val reason: HostReject) : HostDecision
}

object HiddenHostPolicy {

    const val ARM64 = "arm64-v8a"

    /** MapleSU 自身包名（自身永远不能当宿主）。 */
    val SELF_PACKAGES: Set<String> = setOf("dev.maplesu.manager")

    /** 宿主选择页文案（测试锁定长度与禁用词）。 */
    const val PICKER_TITLE = "选择寄生应用"
    const val PICKER_SUBTITLE = "作为管理入口的启动载体"
    const val RISK_HINT = "会修改该应用原生库，可解除"

    private val PACKAGE_PATTERN = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")

    fun isValidPackage(packageName: String): Boolean = PACKAGE_PATTERN.matches(packageName)

    fun isArm64(abis: List<String>): Boolean = abis.any { it.equals(ARM64, ignoreCase = true) }

    /** 单 App 判定（规则顺序固定；先命中先返回）。 */
    fun evaluate(facts: HostAppFacts, selfPackages: Set<String> = SELF_PACKAGES): HostDecision {
        val packageName = facts.packageName.trim()
        val reject = when {
            !isValidPackage(packageName) -> HostReject.INVALID_PACKAGE
            packageName in selfPackages -> HostReject.SELF
            facts.isSystem -> HostReject.SYSTEM_APP
            !isArm64(facts.abis) -> HostReject.NO_ARM64
            !facts.hasNativeLib -> HostReject.NO_NATIVE_LIB
            else -> null
        }
        return if (reject == null) {
            HostDecision.Eligible(HostCandidate(packageName, facts.label))
        } else {
            HostDecision.Rejected(packageName, reject)
        }
    }

    /**
     * 候选列表：只保留可寄生项，按展示名排序（同名按包名），并去重。
     * 输入顺序不影响结果（列表稳定 → UI 不抖动）。
     */
    fun candidates(
        facts: List<HostAppFacts>,
        selfPackages: Set<String> = SELF_PACKAGES,
    ): List<HostCandidate> = facts
        .map { evaluate(it, selfPackages) }
        .filterIsInstance<HostDecision.Eligible>()
        .map { it.candidate }
        .distinctBy { it.packageName }
        .sortedWith(compareBy({ it.displayName.lowercase() }, { it.packageName }))

    /** 被排除项（诊断/测试用；UI 默认不展示排除列表）。 */
    fun rejected(
        facts: List<HostAppFacts>,
        selfPackages: Set<String> = SELF_PACKAGES,
    ): List<HostDecision.Rejected> = facts
        .map { evaluate(it, selfPackages) }
        .filterIsInstance<HostDecision.Rejected>()

    /** 用户确认前再判一次选中的包（防止列表过期/注入伪造包名）。 */
    fun isEligible(packageName: String, facts: List<HostAppFacts>, selfPackages: Set<String> = SELF_PACKAGES): Boolean =
        facts.any { it.packageName.trim() == packageName.trim() && evaluate(it, selfPackages) is HostDecision.Eligible }

    /** 选择寄生应用页入口：与隐藏设置入口同一可见性（A/B 都显示，隐藏生效后消失）。 */
    fun canOpenHostPicker(mode: WorkMode?, state: LiteHiddenState): Boolean =
        HiddenModePolicy.cardVisible(mode, state)

    /**
     * 「解除寄生」入口可见性：已记录宿主且当前**未**处于隐藏生效态。
     *
     * 隐藏生效后 App 内所有入口按策略消失（恢复走 WebUI）；入口在这里可见的真实场景是
     * 激活中途失败（宿主 so 已改写但状态未写入）与恢复之后清理残留。
     */
    fun deactivateVisible(activeHost: String?, hidden: Boolean): Boolean =
        !hidden && !activeHost.isNullOrBlank()
}
