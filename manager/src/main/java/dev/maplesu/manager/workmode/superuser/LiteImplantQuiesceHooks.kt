package dev.maplesu.manager.workmode.superuser

import android.content.Context
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.switch.HookResult
import dev.maplesu.manager.workmode.switch.SwitchQuiesceHooks
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * W19 真实实现（02 §5.4 4a / 01 §6.7）：把 `SuDelivery`/`SuPathWiring` 的植入登记表
 * 变成切换可用的静默/撤回钩子。r3 的 `ModeSwitchBindings` 只需注入本类实例
 * （构造签名见 `createLiteImplantQuiesceHooks` / 报告）。
 *
 * 合同：
 * - [implantRestoreReady]：**所有**已登记植入都有可恢复证据才 true（空表 = true）；
 *   实现直接委托 [LiteImplantRegistry.hasOriginals]（损坏 → false，S0-15 阻断）。
 * - [quiesce]：置静默位 → 新的植入登记被 [guardedRecorder] 拒绝；可重复调用。
 * - [withdrawLiteImplants]：逐 App 撤回；缺原件 → `IMPLANT_RESTORE_MISSING`，执行失败 →
 *   `LITE_IMPLANT_REVERT_FAILED`；失败条目保留在登记表，**可重试**；全成功 = OK（幂等）。
 * - [restoreAfterFailure]：尽力恢复源模式写者并解除静默位（切换已放弃，后续植入恢复允许）。
 * - [restoreProducerSideEffects]：委托 producer 的差分清理（02 §9.4）。
 */
class LiteImplantQuiesceHooks(
    private val registry: LiteImplantRegistry,
    private val stopSourceWriters: (WorkMode) -> HookResult = { HookResult.OK },
    private val restoreSourceWriters: (WorkMode) -> HookResult = { HookResult.OK },
    private val producerSideEffectsCleanup: () -> HookResult = { HookResult.OK },
) : SwitchQuiesceHooks {

    private val quiescing = AtomicBoolean(false)

    fun isQuiescing(): Boolean = quiescing.get()

    override fun quiesce(fromMode: WorkMode): HookResult {
        // 4a：先静默（拒绝新植入），再停源模式写者。失败由调用方进 ROLLING_BACK；
        // 本方法可重复调用（幂等）。
        quiescing.set(true)
        return runCatching { stopSourceWriters(fromMode) }
            .getOrElse { HookResult.failed(QUIESCE_FAILED, it.javaClass.simpleName) }
    }

    override fun restoreAfterFailure(fromMode: WorkMode): HookResult {
        val result = runCatching { restoreSourceWriters(fromMode) }
            .getOrElse { HookResult.failed(RESTORE_WRITERS_FAILED, it.javaClass.simpleName) }
        // 切换已放弃：解除静默位，允许后续正常植入（尽力而为，不影响返回值）。
        quiescing.set(false)
        return result
    }

    override fun withdrawLiteImplants(): HookResult {
        val intents = runCatching { registry.pending() }.getOrElse {
            return HookResult.failed(LiteImplantCodes.IMPLANT_RESTORE_MISSING, "registry unreadable")
        }
        val packages = intents.map { it.packageName }.distinct().sorted()
        if (packages.isEmpty()) return HookResult.OK
        val missing = mutableListOf<String>()
        val failed = mutableListOf<String>()
        for (packageName in packages) {
            val report = runCatching { registry.revert(packageName) }.getOrElse {
                failed += packageName
                continue
            }
            when {
                report.ok -> Unit
                report.code == LiteImplantCodes.ORIGINAL_MISSING ||
                    report.code == LiteImplantCodes.REGISTRY_CORRUPT -> missing += packageName
                else -> failed += packageName
            }
        }
        return when {
            missing.isNotEmpty() -> HookResult.failed(
                LiteImplantCodes.IMPLANT_RESTORE_MISSING,
                "packages=${missing.joinToString(",")}",
            )
            failed.isNotEmpty() -> HookResult.failed(
                LiteImplantCodes.REVERT_FAILED,
                "packages=${failed.joinToString(",")}",
            )
            else -> HookResult.OK
        }
    }

    override fun implantRestoreReady(): Boolean =
        runCatching { registry.hasOriginals() }.getOrDefault(false)

    override fun restoreProducerSideEffects(): HookResult =
        runCatching { producerSideEffectsCleanup() }
            .getOrElse { HookResult.failed(PRODUCER_CLEANUP_FAILED, it.javaClass.simpleName) }

    /**
     * 静默期记录器包装：切换开始后（quiesce 置位）所有新的投递/植入登记被拒绝
     * （`LITE_IMPLANT_QUIESCING`），避免"撤回之后又出现新植入"。未静默时逐项委托。
     */
    fun guardedRecorder(delegate: LiteImplantRecorder): LiteImplantRecorder =
        GuardedLiteImplantRecorder(delegate, ::isQuiescing)

    companion object {
        const val QUIESCE_FAILED = "LITE_IMPLANT_QUIESCE_FAILED"
        const val RESTORE_WRITERS_FAILED = "LITE_IMPLANT_RESTORE_WRITERS_FAILED"
        const val PRODUCER_CLEANUP_FAILED = "LITE_IMPLANT_PRODUCER_CLEANUP_FAILED"
    }
}

/** 静默期拒绝新登记；非静默时透传。 */
private class GuardedLiteImplantRecorder(
    private val delegate: LiteImplantRecorder,
    private val quiescing: () -> Boolean,
) : LiteImplantRecorder {

    private fun rejection(): ImplantPreparation? =
        if (quiescing()) ImplantPreparation.failed(LiteImplantCodes.QUIESCING, "switch in progress") else null

    override fun beforeDelivery(
        packageName: String,
        uid: Int,
        deliverPath: String,
        deliverSha256: String,
        createdDirs: List<String>,
        now: Long,
    ): ImplantPreparation = rejection()
        ?: delegate.beforeDelivery(packageName, uid, deliverPath, deliverSha256, createdDirs, now)

    override fun afterDelivery(preparation: ImplantPreparation) = delegate.afterDelivery(preparation)

    override fun beforeWiring(
        packageName: String,
        uid: Int,
        targetLibraryPath: String,
        deliverPath: String,
        deliverSha256: String,
        createdDirs: List<String>,
        now: Long,
    ): ImplantPreparation = rejection()
        ?: delegate.beforeWiring(packageName, uid, targetLibraryPath, deliverPath, deliverSha256, createdDirs, now)

    override fun afterWiring(preparation: ImplantPreparation) = delegate.afterWiring(preparation)

    override fun recordPathInjection(
        packageName: String,
        uid: Int,
        deliverPath: String,
        deliverSha256: String,
        now: Long,
    ): ImplantPreparation = rejection()
        ?: delegate.recordPathInjection(packageName, uid, deliverPath, deliverSha256, now)
}

/**
 * 生产装配：`sharedDirectory` = `/data/adb/maplesu-workmode/shared`；
 * 返回的 hooks 可直接注入 `ModeSwitchBindings(hooks = ...)`。
 */
fun createLiteImplantQuiesceHooks(
    sharedDirectory: File,
    context: Context,
    registry: LiteImplantRegistry? = null,
    writerStopper: LiteWriterStopper? = null,
): LiteImplantQuiesceHooks {
    val runner = DirectRootScriptRunner(context)
    val actualRegistry = registry ?: FileLiteImplantRegistry(
        directory = sharedDirectory,
        originals = FileOriginalBackupStore(sharedDirectory),
        reverter = ScriptImplantReverter(runner),
    )
    // 真实写者静默：门控位（挡住 runtime 新投递/植入/Ultra 预热）+ 停用 Lite 模块 boot 组件。
    // 任一失败 → HookResult 失败码（QUIESCE_FAILED），切换据此 fail-closed，绝不假装已停。
    val stopper = writerStopper ?: defaultLiteWriterStopper(context)
    return LiteImplantQuiesceHooks(
        registry = actualRegistry,
        stopSourceWriters = { runCatching { stopper.stop() }.getOrElse {
            HookResult.failed(LiteImplantCodes.QUIESCE_FAILED, it.javaClass.simpleName)
        } },
        restoreSourceWriters = { runCatching { stopper.restore() }.getOrElse {
            HookResult.failed(LiteImplantQuiesceHooks.RESTORE_WRITERS_FAILED, it.javaClass.simpleName)
        } },
    )
}
