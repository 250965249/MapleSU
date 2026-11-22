package dev.maplesu.manager.workmode.service

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.StatFs
import dev.maplesu.manager.installer.BaselineProvisioner
import dev.maplesu.manager.installer.InstallerServiceClient
import dev.maplesu.manager.installer.productionBaselineProvisioner
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.ProcBootIdSource
import dev.maplesu.manager.workmode.detect.WallClock
import dev.maplesu.manager.workmode.superuser.DirectRootScriptRunner
import dev.maplesu.manager.workmode.switch.BeginInputs
import dev.maplesu.manager.workmode.switch.BatteryFacts
import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.SwitchDeviceFacts
import java.io.File

/** S1 mirror 文件来源（superuser/settings 导出）；不可用 → fail-closed。 */
fun interface ModeSwitchMirrorProvider {
    fun provide(): BeginInputs

    companion object {
        val UNAVAILABLE = ModeSwitchMirrorProvider {
            BeginInputs(null, null, ModeSwitchCodes.PREPARE_EXPORT_FAILED)
        }
    }
}

/** App 进程可读的切换前置事实（不可得一律返回 null/保守值，由 facade fail-closed）。 */
interface ModeSwitchAppEnvironment {
    fun activeMode(): WorkMode?

    fun modeStateName(): String?

    fun bootId(): String

    /** 经现有 installer 只读通道观测；null = 读不到（不得猜）。 */
    fun deviceFacts(): SwitchDeviceFacts?

    fun battery(): BatteryFacts

    fun freeBytes(): Long

    fun beginInputs(): BeginInputs

    /**
     * 用户点一次切换时的 SELinux 自动恢复（P0-1 第 1 项）。
     *
     * 约定（默认实现 = 未接线 = 保持旧行为，测试 fake 无需改动）：
     * - **只允许** [dev.maplesu.manager.workmode.service.ModeSwitchFacade.startSwitch] 调用；
     *   `canSwitch` / [deviceFacts] 会被页面 `init` 与每次刷新走到
     *   （`WorkModeViewModel.kt:40-42,101`），在那里执行任何根命令都等于「每次打开设置页就改系统状态」。
     * - 返回 null = 未接线：不恢复、也不新增阻断。
     */
    fun selinuxRestorer(): SelinuxRestorer? = null

    /**
     * 用户点一次切换时的**基线自动获取**（P0-1 第 3 项）。
     *
     * 约定（默认实现 = 未接线 = 保持旧行为，测试 fake 无需改动）：
     * - **只允许** [dev.maplesu.manager.workmode.service.ModeSwitchFacade.startSwitch] 调用；
     *   `canSwitch`/`uiSupport` 会被页面 `init` 与每次刷新走到，在那里解压 12 MB 资产/写 104 MB
     *   基线等于"打开设置页就偷偷建基线"，违反"点一次才动作"。
     * - 返回 null = 未接线：不获取基线、不降低任何门槛、也不新增阻断。
     * - 非 null ⇒ CTA 的基线阻断会被降级为"可修复"（见 `ModeSwitchDeviceDelegate`
     *   的 `baselineProvisionable` 与 `ModeSwitchFacade` 的基线白名单）。
     */
    fun provisioner(): BaselineProvisioner? = null

    fun selectedImages(target: WorkMode, images: ModeSwitchImages): BaselineProvisioner? = null

    fun hasInitBoot(): Boolean = true
}

/**
 * 真实设备事实（W08 App 侧装配）。
 *
 * 数据来源仅为现有通道：`ModeRuntime`（进程内模式事实）、`/proc` boot_id、
 * `InstallerServiceClient.observeBootChain`（只读 AIDL，root 服务观测分区/槽/固件/SELinux）、
 * `BatteryManager`、`StatFs("/data")`。任一读不到时不伪造：`deviceFacts()` 返回 null、
 * `battery()` 返回 0/未充电（S0-10 会阻断）。
 */
class AndroidSwitchEnvironment(
    context: Context,
    private val mirrorProvider: ModeSwitchMirrorProvider = ModeSwitchMirrorProvider.UNAVAILABLE,
    private val bootIdSource: BootIdSource = ProcBootIdSource,
    private val clock: Clock = WallClock,
) : ModeSwitchAppEnvironment {

    private val appContext = context.applicationContext

    override fun activeMode(): WorkMode? = ModeRuntime.active

    override fun modeStateName(): String? = ModeRuntime.latestDetection?.state?.name

    override fun bootId(): String = runCatching { bootIdSource.read() }.getOrDefault("")

    /**
     * 设备事实：**优先本地可读来源**，installer 服务只作补充。
     *
     * 2026-10-31 真机缺陷：原实现只走 `InstallerServiceClient.observeBootChain`（libsu
     * RootService，需要 `su` 可用）。Ultra 模式的根通道是 Ultra `run_root_cmd`，libsu 起不来 →
     * `deviceFacts()` 恒 null → 切换页永远「device facts unavailable / 后端尚未接入」。
     * slot/firmware/kernel/SELinux 本来就能在 App 进程无 root 读到，不该被根服务绑架。
     */
    override fun deviceFacts(): SwitchDeviceFacts? = runCatching {
        val slot = readProp("ro.boot.slot_suffix").ifBlank { readProp("ro.boot.slot") }
        val firmware = android.os.Build.DISPLAY.ifBlank { android.os.Build.FINGERPRINT }
        val kernel = System.getProperty("os.version").orEmpty()
        val selinux = readSelinuxStatus()
        if (slot.isBlank() || kernel.isBlank()) return@runCatching null
        SwitchDeviceFacts(
            slot = slot,
            firmware = firmware,
            kernelRelease = kernel,
            selinux = selinux,
        )
    }.getOrNull()

    /** 只读取系统属性：`getprop` 是可执行文件，App 域可运行；失败返回空串（不猜）。 */
    private fun readProp(name: String): String = runCatching {
        val process = ProcessBuilder("/system/bin/getprop", name).redirectErrorStream(true).start()
        val value = process.inputStream.bufferedReader().use { it.readText() }.trim()
        if (process.waitFor() == 0) value else ""
    }.getOrDefault("")

    /**
     * SELinux 状态（**必须真实读到**，否则切换页会以 `Unknown` 误阻断）。
     *
     * M-4：这里传 `allowRoot = false` —— `deviceFacts()` 只被 `canSwitch`/页面刷新走到，
     * 而第⑤级探测在非主线程会起**根 shell**（`RootManagement.openShell` /
     * Ultra `runRootCmd`，见 `SELinuxChecker.kt:40-42`、`:93-95`）。切换页刷新不该有任何根调用；
     * SELinux 已不再是 blocker，最坏读到 `Unknown` 也不会误阻断（S-1 的自动恢复在 startSwitch 里）。
     * 根级别的读留给 [AndroidSelinuxRestorer]（它本来就跑在 IO 线程，需要最准的读数）。
     */
    private fun readSelinuxStatus(): String = readSelinuxStatusLocal(allowRoot = false)

    override fun battery(): BatteryFacts {
        val manager = runCatching {
            appContext.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
        }.getOrNull()
        val level = runCatching {
            manager?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY) ?: 0
        }.getOrDefault(0)
        val status = runCatching {
            appContext.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
                ?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        }.getOrDefault(-1)
        val charging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
            status == BatteryManager.BATTERY_STATUS_FULL
        return BatteryFacts(level.coerceIn(0, 100), charging)
    }

    override fun freeBytes(): Long = runCatching {
        StatFs("/data").availableBytes
    }.getOrElse {
        runCatching { File(appContext.filesDir.absolutePath).usableSpace }.getOrDefault(0L)
    }

    override fun beginInputs(): BeginInputs = runCatching { mirrorProvider.provide() }
        .getOrElse { BeginInputs(null, null, ModeSwitchCodes.PREPARE_EXPORT_FAILED) }

    /**
     * 生产 SELinux 恢复器（P0-1 第 1 项）：构造失败 → null（未接线 = 不做恢复、不加新阻断）。
     *
     * 只用 `lazy` 构造对象（`RootExec` 门面 + libsu runner 都是廉价的）；**不在这里执行任何
     * 根命令**——真正执行在 `ModeSwitchFacade.startSwitch` 的 IO 线程里。
     */
    override fun selinuxRestorer(): SelinuxRestorer? = runtimeSelinuxRestorer

    private val runtimeSelinuxRestorer: SelinuxRestorer? by lazy {
        runCatching { productionSelinuxRestorer(appContext) }.getOrNull()
    }

    /**
     * 生产基线获取器（P0-1 第 3 项）：随包 stock 资产 → App 私有暂存 → root 发布到控制面。
     *
     * 构造失败 → null（= 未接线：CTA 不降级，用户在点击后仍会得到既有 `BASELINE_MISSING`，
     * 而不是假成功）。**不在这里**做任何解压/写盘：真正执行在 startSwitch 的 IO 线程里。
     *
     * 设备事实直接复用本类的只读来源（`Build.DISPLAY` + `os.version` + `ro.boot.slot_*`）：
     * 与 root 侧 `LocalInstallerGateway.deviceFactsNow()` 读的是同一组值；万一不一致，
     * 基线校验会显式 `BASELINE_STALE`，不会假成功。
     */
    override fun provisioner(): BaselineProvisioner? = runtimeProvisioner

    private val imageCapture by lazy {
        dev.maplesu.manager.installer.RootScriptBaselineCapture(
            DirectRootScriptRunner(appContext), android.os.Process.myUid())
    }

    override fun hasInitBoot(): Boolean = imageCapture.probe()?.devices?.containsKey("init_boot") ?: true

    override fun selectedImages(target: WorkMode, images: ModeSwitchImages): BaselineProvisioner =
        dev.maplesu.manager.installer.SelectedBootBaselineProvisioner(
            bridge = dev.maplesu.manager.installer.RootScriptBaselineBridge(
                DirectRootScriptRunner(appContext), deviceSlot = { deviceFacts()?.slot.orEmpty() }),
            capture = imageCapture,
            stagingRoot = File(appContext.cacheDir, "switch-selected-images"),
            target = target,
            images = images,
        )

    private val runtimeProvisioner: BaselineProvisioner? by lazy {
        runCatching {
            productionBaselineProvisioner(
                context = appContext,
                runner = DirectRootScriptRunner(appContext),
                deviceFacts = {
                    val facts = deviceFacts()
                    DeviceBootFacts(
                        slot = facts?.slot.orEmpty(),
                        firmware = facts?.firmware.orEmpty(),
                        kernelRelease = facts?.kernelRelease.orEmpty(),
                    )
                },
                freeBytes = { freeBytes() },
            )
        }.getOrNull()
    }
}

/**
 * SELinux 状态五级只读探测（App 域；**不改任何系统状态**）。
 *
 * 提取为顶层 `internal` 供 [AndroidSelinuxRestorer] 复用：自动恢复必须先判「入口已 Enforcing
 * 就不动手」，那必须与切换页看到的是**同一份**读数。
 *
 * 来源（逐级降级，全部失败才 `Unknown`）：
 *  1. 已探测过的缓存（App/Ultra 的真实读数；主线程零成本）；
 *  2. `/sys/fs/selinux/enforce`（`1`/`0`）；
 *  3. `/system/bin/getenforce`（toybox；路径不存在时试 `toybox getenforce`）；
 *  4. `android.os.SELinux.isSELinuxEnforced()` 反射 —— 只信 `true`：App 域读不到 enforce 时
 *     该 API 会返回 false，不能据此判 Permissive（真机实测：系统 Enforcing，App 读到 false）；
 *  5. 后台线程**且允许根探测**（`allowRoot = true`，默认）才允许走 App 既有 SELinux 探测
 *      （Ultra 下经 MapleSU SDK `get_system_status`，非 Ultra 下会起根 shell）。
 *      `deviceFacts()`（页面刷新路径）显式传 `allowRoot = false` 把这一级隔离掉（M-4）；
 *      恢复器走默认值（它本来就只允许在 startSwitch 的 IO 线程执行）。
 */
internal fun readSelinuxStatusLocal(allowRoot: Boolean = true): String {
    // ① 已探测过的缓存（App/Ultra 的真实读数；主线程零成本）。
    runCatching { com.maplesu.core.ui.util.peekCachedSELinuxStatus() }.getOrNull()
        ?.takeIf { it == "Enforcing" || it == "Permissive" }
        ?.let { return it }
    // ② enforce 文件（部分设备 App 域可读）。
    runCatching {
        when (File("/sys/fs/selinux/enforce").readText().trim()) {
            "1" -> return "Enforcing"
            "0" -> return "Permissive"
        }
    }
    // ③ getenforce / toybox getenforce。
    for (command in listOf(listOf("/system/bin/getenforce"), listOf("/system/bin/toybox", "getenforce"))) {
        val value = runCatching {
            val process = ProcessBuilder(command).redirectErrorStream(true).start()
            val text = process.inputStream.bufferedReader().use { it.readText() }.trim()
            if (process.waitFor() == 0) text else ""
        }.getOrDefault("")
        if (value.startsWith("Enforcing")) return "Enforcing"
        if (value.startsWith("Permissive")) return "Permissive"
    }
    // ④ 反射只信 `true`（见 KDoc）。
    runCatching {
        val cls = Class.forName("android.os.SELinux")
        val enforced = cls.getMethod("isSELinuxEnforced").invoke(null) as? Boolean
        if (enforced == true) return "Enforcing"
    }
    // ⑤ 后台线程 **且允许根探测**时才走 App 既有 SELinux 探测（Ultra 下经 MapleSU SDK
    //    `get_system_status`，非 Ultra 下会起根 shell）。M-4：`canSwitch`/`deviceFacts` 路径传
    //    `allowRoot = false`，绝不在这里起根进程；恢复器用默认 true（已在 IO 线程）。
    if (allowRoot &&
        !android.os.Looper.myLooper().let { it != null && it == android.os.Looper.getMainLooper() }
    ) {
        runCatching { com.maplesu.core.ui.util.getSELinuxStatusRaw() }.getOrNull()
            ?.takeIf { it == "Enforcing" || it == "Permissive" }
            ?.let { return it }
    }
    return "Unknown"
}
