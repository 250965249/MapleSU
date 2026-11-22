package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.ultra.model.MapleSuModInstalledItem
import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient

interface UltraModuleHost {

    fun environmentState(): NativeReceipt

    /** `parse_module_desc_from_zip_file`：由宿主读取归档并给出 id32/版本/minSdk。 */
    fun parseModuleDescriptor(zipPath: String): NativeReceipt

    /** `install_module` / `install_module_dev_run_once`：**会执行模块原生代码**。 */
    fun installModule(zipPath: String, devRunOnce: Boolean): NativeReceipt

    /** `uninstall_module`。 */
    fun uninstallModule(id32: String): NativeReceipt

    fun moduleControl(id32: String): NativeReceipt = NativeReceipt.bridgeFailure(
        "get_module_control", "MAPLESU_MODULE_CONTROL_UNSUPPORTED", "Host has no module control API",
    )

    fun setModuleEnabled(id32: String, enabled: Boolean): NativeReceipt = NativeReceipt.bridgeFailure(
        "set_module_enabled", "MAPLESU_MODULE_CONTROL_UNSUPPORTED", "Host has no module control API",
    )

    /** `get_all_modules_list` 解码后的行；读取失败返回空列表（与 `UltraRuntimeClient.modules()` 一致）。 */
    fun modules(): List<MapleSuModInstalledItem>

    /** Raw list receipt: a failed read must never confirm that an uninstalled module is absent. */
    fun moduleList(): NativeReceipt = NativeReceipt.bridgeFailure(
        "get_all_modules_list", "MAPLESU_MODULE_LIST_UNAVAILABLE", "Host has no module list receipt",
    )

    /** `start_module_web_ui_server_async`：由模块自己把页面拉起来，**会执行模块原生代码**。 */
    fun openModuleWebUI(id32: String): NativeReceipt
}

/**
 * 默认真实实现：把 [UltraModuleHost] 的每个方法一对一转发给现有 [UltraRuntimeClient]。
 *
 * 刻意不做任何包装：不改参数、不改回执、不吞异常、不缓存。这样「注入替身后行为不同」只可能来自
 * 替身本身，而不是来自这层适配。
 *
 * [client] 故意暴露为 `val`：`MapleSuModuleBackend` 需要继续用同一个客户端做只读能力快照
 * （`capabilities()` / `moduleList()`），换了实例会让 `environmentGeneration` 这类缓存各算一份。
 */
class UltraRuntimeModuleHost(val client: UltraRuntimeClient) : UltraModuleHost {

    override fun environmentState(): NativeReceipt = client.environmentState()

    override fun parseModuleDescriptor(zipPath: String): NativeReceipt =
        client.parseModuleDescriptor(zipPath)

    override fun installModule(zipPath: String, devRunOnce: Boolean): NativeReceipt =
        client.installModule(zipPath, devRunOnce)

    override fun uninstallModule(id32: String): NativeReceipt = client.uninstallModule(id32)

    override fun moduleControl(id32: String): NativeReceipt = client.moduleControl(id32)

    override fun setModuleEnabled(id32: String, enabled: Boolean): NativeReceipt = client.setModuleEnabled(id32, enabled)

    override fun modules(): List<MapleSuModInstalledItem> = client.modules()

    override fun moduleList(): NativeReceipt = client.moduleList()

    override fun openModuleWebUI(id32: String): NativeReceipt = client.openModuleWebUi(id32)
}

/**
 * 兼容门对一次动作的结论，直接使用 [UltraModuleCompatibilityVerdict]：
 *  - [blocked] 只在 `KNOWN_INCOMPATIBLE` 为 true，沿用 `blocksNativeExecution` 的定义；
 *  - [blockingText] 是给用户/日志的中文文案（见 [UltraModuleCompatibilityGate.blockingText]）。
 *
 * UNVERIFIED 状态放行，但不代表已验证兼容。兼容门只拦截已确认不兼容的组合；
 * 调用方必须展示「未验证」，并保留原因码。
 */
data class UltraModuleGateDecision(val verdict: UltraModuleCompatibilityVerdict) {

    val action: UltraModuleAction get() = verdict.action

    val reasonCodes: List<String> get() = verdict.reasonCodes

    val blocked: Boolean get() = verdict.blocksNativeExecution

    val blockingText: String get() = UltraModuleCompatibilityGate.blockingText(verdict)
}

/**
 * 一次「过了门之后的宿主执行」结果。
 *
 * [Blocked] 是防御性返回：`UltraModuleExecutionGate` 在决策被拦时**不调用**宿主，直接把决策带回来。
 * 调用方应该在这之前就 return；这里保留这个分支是为了让「被拦 → 一定没有宿主调用」成为类型层面的
 * 事实，而不是靠调用方记得先判断。
 */
sealed interface UltraModuleInstallExecution {

    data class Blocked(val decision: UltraModuleGateDecision) : UltraModuleInstallExecution

    data class Ran(
        val decision: UltraModuleGateDecision,
        val descriptor: NativeReceipt,
        val install: NativeReceipt,
    ) : UltraModuleInstallExecution
}

/**
 * 「兼容门 + 两个会执行模块的宿主调用」的唯一顺序契约（纯逻辑，宿主通过接缝注入）。
 *
 * 为什么单独成类而不是散在 `MapleSuModuleBackend.install` 里：安装事务里有 stage / journal /
 * commit 等一堆与兼容性无关的步骤，而 H1 要断言的恰恰是「判定 → 宿主调用」这一小段。把它抽出来，
 * 就能用计数型替身在 JVM 上证明：
 *
 *  - 被拦时 `parseModuleDescriptor` 与 `installModule` 都是 0 次（[executeInstall] 直接返回）；
 *  - 未被拦时它们各发生 1 次（顺序固定：descriptor → 回调 → install）；
 *  - 重复调用不共享隐藏状态（每次判定与每次执行都从头算）。
 *
 * 顺序刻意保持与 `MapleSuModuleBackend.install` 既有事务一致：**descriptor 先于 install**，
 * 且两者之间留一个回调（`onDescriptor`），因为既有实现要在这中间写一次 journal 回执
 * （`NEEDS_RECONCILIATION` + staged token）。回调抛异常会让 install 不再发生——这是有意的：
 * 记账失败时不应该继续执行模块。
 *
 * @param host 宿主接缝；默认实现是 [UltraRuntimeModuleHost]。
 * @param records 固定记录，默认取 [UltraModuleCompatibilityRegistry]；只有测试会注入合成记录。
 */
class UltraModuleExecutionGate(
    private val host: UltraModuleHost,
    private val records: List<UltraModuleCompatibilityRecord> = UltraModuleCompatibilityRegistry.records,
) {

    /** 只做判定，不碰宿主。任何一次泄漏到宿主的调用都会破坏 H1 的「次数为 0」。 */
    fun evaluate(
        identity: UltraModulePackageIdentity,
        facts: UltraModuleDeviceFacts,
        action: UltraModuleAction,
    ): UltraModuleGateDecision = UltraModuleGateDecision(
        UltraModuleCompatibility.evaluate(
            pkg = identity,
            sdk = facts.sdkIdentity,
            kernel = facts.kernelIdentity,
            action = action,
            records = records,
        ),
    )

    /**
     * 过了门之后执行安装。被拦时**不调用宿主**（返回 [UltraModuleInstallExecution.Blocked]）。
     *
     * @param stagedZipPath 已经 stage 到应用私有目录、即将交给宿主的归档路径。
     * @param onDescriptor 收到 descriptor 回执、**install 之前**的回调（调用方在这里记账）。
     */
    fun executeInstall(
        decision: UltraModuleGateDecision,
        stagedZipPath: String,
        devRunOnce: Boolean,
        onDescriptor: (NativeReceipt) -> Unit = {},
    ): UltraModuleInstallExecution {
        // Installation is an explicit user action. Compatibility records remain
        // diagnostics; the module host returns the actual installation result.
        if (decision.blocked && decision.action == UltraModuleAction.OPEN_WEBUI)
            return UltraModuleInstallExecution.Blocked(decision)
        val descriptor = host.parseModuleDescriptor(stagedZipPath)
        onDescriptor(descriptor)
        val install = host.installModule(stagedZipPath, devRunOnce)
        return UltraModuleInstallExecution.Ran(decision, descriptor, install)
    }

    /**
     * 打开 WebUI 的同一套契约：被拦时返回 null **且不调用宿主**。
     *
     * 这个动作同样执行模块原生代码（SDK `start_module_web_ui_server_async` 由模块把页面拉起来），
     * 所以它不是「只是看看」，不能成为绕过门的旁路。
     */
    fun openWebUiIfAllowed(decision: UltraModuleGateDecision, id32: String): NativeReceipt? =
        if (decision.blocked) null else host.openModuleWebUI(id32)
}
