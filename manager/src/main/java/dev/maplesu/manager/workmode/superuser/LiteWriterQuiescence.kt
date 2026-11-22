package dev.maplesu.manager.workmode.superuser

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import dev.maplesu.manager.workmode.gating.ModeComponentIds
import dev.maplesu.manager.workmode.switch.HookResult
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 全局植入写者静默位（W19 / 02 §5.4 4a）。
 *
 * 切换开始时进入：`SuDelivery`/`SuPathWiring`/Ultra 预热/植入登记 全部在写之前检查
 * [isBlocked]，新写入被拒绝（`LITE_IMPLANT_QUIESCING`）；切换放弃/完成后 [leave]。
 * 幂等：重复 enter/leave 安全。
 */
object LiteImplantQuiesceGate {
    private val entered = AtomicBoolean(false)

    @Volatile
    private var enteredReason: String = ""

    fun tryEnter(reason: String = "mode-switch"): Boolean {
        val acquired = entered.compareAndSet(false, true)
        if (acquired) enteredReason = reason
        return acquired
    }

    fun leave() {
        entered.set(false)
        enteredReason = ""
    }

    fun isBlocked(): Boolean = entered.get()

    fun blockedCode(): String? = if (entered.get()) LiteImplantCodes.QUIESCING else null

    fun reason(): String = enteredReason

    fun resetForTest() = leave()
}

/** 一个可静默/可恢复的源模式写者。 */
interface LiteWriterStopper {
    fun stop(): HookResult
    fun restore(): HookResult
}

/** 只置门控位：挡住 runtime 侧的新投递/植入（不依赖 Android）。 */
object GateLiteWriterStopper : LiteWriterStopper {
    override fun stop(): HookResult {
        LiteImplantQuiesceGate.tryEnter()
        return HookResult.OK
    }

    override fun restore(): HookResult {
        LiteImplantQuiesceGate.leave()
        return HookResult.OK
    }
}

/**
 * 停用 Lite 模块 boot 的 receiver/service（防切换期间新 boot 写模块状态）。
 * 失败（PackageManager 异常）→ fail-closed：`LITE_IMPLANT_QUIESCE_FAILED`，
 * 调用方据此把切换置失败，绝不假装已停。
 */
class AndroidLiteComponentStopper(
    context: Context,
    private val components: List<String> = listOf(
        ModeComponentIds.COMPONENT_LITE_MODULE_BOOT_RECEIVER,
        ModeComponentIds.COMPONENT_LITE_MODULE_BOOT_SERVICE,
    ),
) : LiteWriterStopper {
    private val context = context.applicationContext
    private val disabled = mutableListOf<String>()

    override fun stop(): HookResult {
        val packageManager = context.packageManager
        val done = mutableListOf<String>()
        for (className in components) {
            val result = runCatching {
                val component = ComponentName(context.packageName, className)
                val previous = packageManager.getComponentEnabledSetting(component)
                packageManager.setComponentEnabledSetting(
                    component,
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                    PackageManager.DONT_KILL_APP,
                )
                previous
            }
            if (result.isFailure) {
                // 回滚本方法已停用的组件，然后 fail-closed。
                restoreComponents(done)
                return HookResult.failed(
                    LiteImplantCodes.QUIESCE_FAILED,
                    "component=$className ${result.exceptionOrNull()?.javaClass?.simpleName}",
                )
            }
            done += className
        }
        disabled += done
        return HookResult.OK
    }

    override fun restore(): HookResult {
        val failure = restoreComponents(disabled.toList())
        disabled.clear()
        return failure
    }

    private fun restoreComponents(names: List<String>): HookResult {
        val packageManager = context.packageManager
        var failure: HookResult? = null
        for (className in names) {
            val result = runCatching {
                packageManager.setComponentEnabledSetting(
                    ComponentName(context.packageName, className),
                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                    PackageManager.DONT_KILL_APP,
                )
            }
            if (result.isFailure && failure == null) {
                failure = HookResult.failed(
                    LiteImplantCodes.QUIESCE_FAILED,
                    "restore component=$className ${result.exceptionOrNull()?.javaClass?.simpleName}",
                )
            }
        }
        return failure ?: HookResult.OK
    }
}

/** 组合写者：stop 顺序执行，任一失败回滚已停项并 fail-closed；restore 逆序。 */
class CompositeLiteWriterStopper(
    private val stoppers: List<LiteWriterStopper>,
) : LiteWriterStopper {
    override fun stop(): HookResult {
        val stopped = mutableListOf<LiteWriterStopper>()
        for (stopper in stoppers) {
            val result = runCatching { stopper.stop() }
                .getOrElse { HookResult.failed(LiteImplantCodes.QUIESCE_FAILED, it.javaClass.simpleName) }
            if (!result.ok) {
                stopped.asReversed().forEach { runCatching { it.restore() } }
                return result
            }
            stopped += stopper
        }
        return HookResult.OK
    }

    override fun restore(): HookResult {
        var failure: HookResult? = null
        for (stopper in stoppers.asReversed()) {
            val result = runCatching { stopper.restore() }
                .getOrElse {
                    HookResult.failed(LiteImplantQuiesceHooks.RESTORE_WRITERS_FAILED, it.javaClass.simpleName)
                }
            if (!result.ok && failure == null) failure = result
        }
        return failure ?: HookResult.OK
    }
}

/** 设备默认写者集合：门控位 + Lite 模块 boot 组件。 */
fun defaultLiteWriterStopper(context: Context): LiteWriterStopper =
    CompositeLiteWriterStopper(listOf(GateLiteWriterStopper, AndroidLiteComponentStopper(context)))

/**
 * 门控位包装的记录器（安装到 [LiteImplantRecorderProvider] 后，静默期间新登记被拒）。
 * 与 [RegistryLiteImplantRecorder] 内部的检查双重保险（后者在无 wrapper 时也安全）。
 */
class GateGuardedLiteImplantRecorder(
    private val delegate: LiteImplantRecorder,
    private val gate: () -> Boolean = { LiteImplantQuiesceGate.isBlocked() },
) : LiteImplantRecorder {
    private fun rejection(): ImplantPreparation? =
        if (gate()) ImplantPreparation.failed(LiteImplantCodes.QUIESCING, "writes quiesced for mode switch") else null

    override fun beforeDelivery(
        packageName: String, uid: Int, deliverPath: String, deliverSha256: String,
        createdDirs: List<String>, now: Long,
    ): ImplantPreparation = rejection() ?: delegate.beforeDelivery(
        packageName, uid, deliverPath, deliverSha256, createdDirs, now,
    )

    override fun afterDelivery(preparation: ImplantPreparation) = delegate.afterDelivery(preparation)

    override fun beforeWiring(
        packageName: String, uid: Int, targetLibraryPath: String, deliverPath: String,
        deliverSha256: String, createdDirs: List<String>, now: Long,
    ): ImplantPreparation = rejection() ?: delegate.beforeWiring(
        packageName, uid, targetLibraryPath, deliverPath, deliverSha256, createdDirs, now,
    )

    override fun afterWiring(preparation: ImplantPreparation) = delegate.afterWiring(preparation)

    override fun recordPathInjection(
        packageName: String, uid: Int, deliverPath: String, deliverSha256: String, now: Long,
    ): ImplantPreparation = rejection() ?: delegate.recordPathInjection(
        packageName, uid, deliverPath, deliverSha256, now,
    )
}
