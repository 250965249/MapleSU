// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import android.content.Context
import android.net.Uri
import android.os.Looper
import com.maplesu.core.R
import com.topjohnwu.superuser.Shell
import dev.maplesu.manager.installer.DirectInstallCodes
import dev.maplesu.manager.installer.InstallCandidateImage
import dev.maplesu.manager.installer.InstallCommitCodes
import dev.maplesu.manager.installer.InstallCommitOutcome
import dev.maplesu.manager.installer.InstallConfirmationEvidence
import dev.maplesu.manager.installer.InstallPartition
import dev.maplesu.manager.installer.KsuInstallCodes
import dev.maplesu.manager.installer.PartitionExtractResult
import dev.maplesu.manager.installer.RootPartitionExtractor
import dev.maplesu.manager.installer.RootShellResult
import dev.maplesu.manager.installer.RootShellRunner
import dev.maplesu.manager.workmode.service.ModeSwitchRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.io.File

/**
 * 后端没有上报成功证据强度时的取值（M2）。
 *
 * 默认取 `state-only`：宁可把"只有状态证据"说小，也不猜"写后回读已核对"。
 */
private const val EVIDENCE_UNKNOWN = InstallConfirmationEvidence.STATE_ONLY

/**
 * KSU 安装的 Android 接线层（W12；主机单测只覆盖 [KsuInstallProducer] 与
 * [KsuInstallPolicy]，本类因依赖 `Context`/`Uri`/libsu 不参与 JVM 测试）。
 *
 * 分工：
 * - [KsuInstallPolicy]：参数语义校验（纯函数）；
 * - [KsuInstallProducer]：产候选 + 结构断言 + staging（纯文件逻辑）；
 * - 本类：`Uri` 落盘、`nativeLibraryDir` 定位 ksud、建 root shell、把候选交给
 *   **共用模式切换事务**（P0-1 第 4 项：`ModeSwitchFacade.installCommit` →
 *   `preflight/begin/snapshot/submit/commit` + 4b/4e 配置搬移）。
 *
 * 失败语义与 Lite 一致：不抛异常，返回 `FlashResult` 形态的 [Outcome]（code/err/reboot）。
 */
object KsuInstallGlue {

    /** 与 `com.maplesu.core.ui.util.FlashResult` 同形；门面负责包成 FlashResult。 */
    data class Outcome(
        val code: Int,
        val err: String,
        val rebootRequired: Boolean,
    )

    fun installBoot(
        context: Context,
        bootUri: Uri?,
        kmi: String?,
        lkmIsUri: Boolean,
        ota: Boolean,
        partition: String?,
        allowShell: Boolean,
        enableAdb: Boolean,
        forceBackup: Boolean,
        blockModules: String,
        onStdout: (String) -> Unit,
        onStderr: (String) -> Unit,
        /**
         * 本次 APK 内嵌的 KMI 目录（`ksud boot-info supported-kmis`）。
         *
         * `null` = 未上报（旧装配）：producer 不猜，交给 ksud 的内嵌资产查找硬失败；
         * 已知且缺该 KMI 的 `.ko` → `KSU_KMI_ARTIFACT_MISSING`（绝不换用别的 KMI）。
         */
        kmiCatalog: () -> Collection<String>? = { null },
    ): Outcome {
        // 直接安装 = 用户没有选文件：源镜像由 root 从**当前槽的目标分区**提取
        // （`RootPartitionExtractor`），之后与"选文件"走完全相同的修补/提交链。
        val directInstall = bootUri == null
        val decision = KsuInstallPolicy.evaluate(
            bootUriPresent = bootUri != null,
            kmi = kmi,
            lkmIsUri = lkmIsUri,
            ota = ota,
            partition = partition,
            allowShell = allowShell,
            enableAdb = enableAdb,
            forceBackup = forceBackup,
            blockModules = blockModules,
            directInstall = directInstall,
        )
        val options = when (decision) {
            is KsuInstallDecision.Rejected -> {
                val message = messageFor(context, decision.reason)
                onStderr(message)
                KsuLog.rejected("KsuInstallGlue", decision.reason.name)
                return Outcome(78, message, false)
            }
            is KsuInstallDecision.Allowed -> decision.options
        }

        onStdout(context.getString(R.string.install_image_analyzing))
        val daemon = KsuCommands.daemonPath(File(context.applicationInfo.nativeLibraryDir))
        if (!File(daemon).isFile) {
            // 用户态未部署（MODE_B_KERNEL_ONLY）：不能产候选，只能走修复/切换流程。
            val message = context.getString(R.string.install_root_required)
            onStderr(message)
            KsuLog.unavailable("KsuInstallGlue", "ksud missing: $daemon")
            return Outcome(78, message, false)
        }
        val runner = LibsuRootCommandRunner(daemon)

        // 源镜像：选文件 = 复制用户文件；直装 = root 读取当前槽分区。
        val source: File = if (bootUri != null) {
            copySourceImage(context, bootUri) ?: run {
                val message = context.getString(R.string.install_image_invalid)
                onStderr(message)
                return Outcome(1, message, false)
            }
        } else {
            when (val acquired = acquireDirectInstallSource(context, runner, options.partition, onStdout)) {
                is DirectSource.Ready -> acquired.image
                // 提取失败：显式错误码，**不进入刷写**（绝不拿半份/空镜像去修补）。
                is DirectSource.Failed -> {
                    onStderr(acquired.message)
                    return Outcome(1, acquired.message, false)
                }
            }
        }
        try {
            val producer = KsuInstallProducer(
                daemonPath = daemon,
                runner = runner,
                workRoot = KsuCandidateWorkspaces.install(context.filesDir),
                // 生产提交端口：默认 = 共用切换事务（`ModeSwitchFacade.installCommit`）。
                commit = ModeSwitchCommitPort(context.applicationContext),
                kmiCatalog = kmiCatalog,
                appUid = android.os.Process.myUid(),
            )
            return when (val result = producer.installBoot(source, options, onStdout, onStderr)) {
                is KsuInstallResult.Committed -> {
                    // 只有「事务 commit + 逐分区写后回读」都过了才会走到这里（producer 保证）。
                    onStdout(context.getString(R.string.install_image_installed))
                    // M2：把成功判据的**证据强度**照实记进日志（state-only ≠ 写后回读已核对）。
                    KsuLog.record(
                        "install-committed",
                        "${result.candidate.partition} sha=${result.candidate.sha256} " +
                            "evidence=${result.evidence.ifEmpty { EVIDENCE_UNKNOWN }}",
                    )
                    Outcome(0, "", true)
                }
                is KsuInstallResult.NeedsRecovery -> {
                    // 分区可能已写、回滚不可信：这是一个**失败**，且必须让用户知道要人工恢复。
                    val message = context.getString(R.string.install_image_recovery_required)
                    onStderr(message)
                    KsuLog.record(
                        "install-needs-recovery",
                        "${result.code} switch=${result.switchId} ${result.detail}",
                    )
                    Outcome(1, withCode(context, message, result.code), false)
                }
                is KsuInstallResult.Staged -> {
                    // 「候选已就绪但事务没有把它写完」：不是安装成功，也不给重启按钮。
                    onStdout(context.getString(R.string.install_image_saved, result.candidate.sha256))
                    val message = context.getString(R.string.install_image_patch_failed)
                    onStderr(message)
                    KsuLog.record(
                        "install-not-committed",
                        "${result.code} switch=${result.switchId.ifEmpty { "-" }}",
                    )
                    Outcome(1, withCode(context, message, result.code), false)
                }
                is KsuInstallResult.Failed -> {
                    val alreadyPatched = result.code.contains("ALREADY_PATCHED")
                    val message = context.getString(
                        when {
                            alreadyPatched -> R.string.install_image_already_patched
                            result.rolledBack -> R.string.install_image_restored
                            else -> R.string.install_image_patch_failed
                        },
                    )
                    onStderr(message)
                    KsuLog.record("install-failed", "${result.code} ${result.detail}")
                    val err = if (alreadyPatched) message else withCode(context, message, result.code)
                    Outcome(1, err, false)
                }
            }
        } finally {
            source.delete()
        }
    }

    /** 用户可见文案 + 稳定机器码（码是排障/定级的唯一依据，不静默吞掉）。 */
    private fun withCode(context: Context, message: String, code: String): String = when {
        code.isBlank() -> message
        // L2：这三个码有专属三语文案，不再把英文码拼进用户可见文案。
        code == InstallCommitCodes.COMMIT_NOT_CONFIRMED ->
            context.getString(R.string.install_commit_not_confirmed)
        code == InstallCommitCodes.MOVE_STAGE_UNWIRED ->
            context.getString(R.string.install_move_stage_unwired)
        code == InstallCommitCodes.PARTITION_ROLLBACK_FAILED ->
            context.getString(R.string.install_partition_rollback_failed)
        else -> "$message [$code]"
    }

    /** 「直接安装」源镜像的取得结果（只有 [Ready] 才允许进入修补/刷写）。 */
    private sealed interface DirectSource {
        data class Ready(val image: File) : DirectSource

        /** 已带稳定码的用户可见文案（**不进入刷写**）。 */
        data class Failed(val message: String) : DirectSource
    }

    /**
     * 直接安装：root 读取**当前槽的目标分区**（`RootPartitionExtractor`）作为修补源。
     *
     * 失败一律显式：文案里带稳定码，并写一行 `direct-install-extract-failed` 日志；
     * 绝不退回"让用户先选文件"，也绝不拿半份镜像继续。
     */
    private fun acquireDirectInstallSource(
        context: Context,
        runner: KsuRootCommandRunner,
        partition: String?,
        onStdout: (String) -> Unit,
    ): DirectSource {
        val target = InstallPartition.fromWire(partition)
            ?: return DirectSource.Failed(
                context.getString(
                    R.string.install_partition_extract_failed,
                    DirectInstallCodes.PARTITION_UNSUPPORTED,
                ),
            )
        onStdout(context.getString(R.string.install_partition_extract_start, target.wire))
        val extractor = RootPartitionExtractor(
            runner = RootShellRunner { command, timeoutMs -> runner.run(command, timeoutMs).toRootShellResult() },
            cacheDir = File(context.cacheDir, "ksu-direct-install"),
        )
        // 槽位：先问设备（`getprop ro.boot.slot_suffix`），读不到由 extractor 按规范 fallback `_a`。
        val slot = extractor.readSlotSuffix()
        return when (val result = extractor.extract(target, slot)) {
            is PartitionExtractResult.Extracted -> {
                onStdout(
                    context.getString(
                        R.string.install_partition_extract_done,
                        result.value.deviceNode,
                        result.value.size,
                        result.value.sha256,
                    ),
                )
                DirectSource.Ready(result.value.image)
            }
            is PartitionExtractResult.Failed -> {
                KsuLog.record(
                    "direct-install-extract-failed",
                    "${result.code} partition=${target.wire} slot=${slot.orEmpty()} ${result.detail}",
                )
                DirectSource.Failed(
                    context.getString(R.string.install_partition_extract_failed, result.code),
                )
            }
        }
    }

    /** `KsuShellResult` → 提取器的结果类型（同一个 root shell，两种数据形状）。 */
    private fun KsuShellResult.toRootShellResult(): RootShellResult =
        RootShellResult(code = code, out = out, err = err)

    private fun copySourceImage(context: Context, uri: Uri): File? {
        val dir = File(context.cacheDir, "ksu-install").apply { mkdirs() }
        val target = File(dir, "source-${System.nanoTime()}.img")
        return try {
            val input = context.contentResolver.openInputStream(uri) ?: return null
            input.use { ins -> target.outputStream().use { outs -> ins.copyTo(outs) } }
            if (target.length() <= 0L) {
                target.delete()
                null
            } else {
                target
            }
        } catch (t: Throwable) {
            KsuLog.record("source-copy-failed", "${t.javaClass.simpleName}: ${t.message}")
            target.delete()
            null
        }
    }

    private fun messageFor(context: Context, reason: KsuInstallRejectReason): String = when (reason) {
        KsuInstallRejectReason.BLOCK_MODULES_INVALID ->
            context.getString(R.string.install_block_modules_invalid)
        KsuInstallRejectReason.NO_SOURCE_IMAGE,
        KsuInstallRejectReason.LKM_URI_UNSUPPORTED,
        KsuInstallRejectReason.OTA_UNSUPPORTED,
        KsuInstallRejectReason.FORCE_BACKUP_UNSUPPORTED,
        KsuInstallRejectReason.PARTITION_UNSUPPORTED,
        -> context.getString(R.string.install_image_required)
    }
}

/**
 * 安装提交端口（**同步**，`KsuCandidateCommitPort` 是同步 `fun interface`）：把候选交给
 * 共用模式切换事务，并**阻塞等到事务写完**（`preflight → begin → snapshot → submit → commit`）。
 *
 * 关键不变量（P0-1 第 4 项）：
 * 1. 没有接上事务端口 → [KsuCommitResult.NoTransaction]（不写分区、也不谎报成功）；
 * 2. 事务只"接收"候选 → 只能是 [KsuCommitResult.Accepted]，由 producer 降级成 Staged；
 * 3. 只有事务走完 `commit` 且后端报 `REBOOT_REQUIRED`（= 逐分区回读通过）才返回
 *    [KsuCommitResult.Committed]。
 *
 * 线程：客户端是 `suspend`，这里用 [runBlocking] 桥接。调用链（
 * `InstallerFlashViewModel.attach` → `flashIt`）已经在 `Dispatchers.IO`；主线程调用会被
 * 显式拒绝（`KSU_INSTALL_MAIN_THREAD`），绝不 ANR。
 */
class ModeSwitchCommitPort(
    context: Context,
    private val transactor: KsuInstallTransactor? = FacadeInstallTransactor(context),
) : KsuCandidateCommitPort, KsuProgressCommitPort {

    override fun submit(candidate: KsuProducedCandidate, switchId: String?): KsuCommitResult =
        submitWithProgress(candidate, switchId) {}

    override fun submitWithProgress(
        candidate: KsuProducedCandidate,
        switchId: String?,
        onProgress: (String) -> Unit,
    ): KsuCommitResult {
        val tx = transactor
            ?: return KsuCommitResult.NoTransaction(
                KsuInstallCodes.NOT_ACTIVE,
                "no mode-switch commit port is wired; candidate kept in staging",
            )
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return KsuCommitResult.Failed(
                InstallCommitCodes.MAIN_THREAD,
                "mode-switch commit must not run on the main thread",
            )
        }
        return try {
            runBlocking {
                withContext(Dispatchers.IO) { tx.commitInstall(candidate, switchId, onProgress) }
            }
        } catch (error: Throwable) {
            if (error is Error) throw error
            KsuLog.record(
                "commit-failed",
                "switch=${switchId.orEmpty()} ${error.javaClass.simpleName}: ${error.message}",
            )
            KsuCommitResult.Failed(
                InstallCommitCodes.TX_FAILED,
                "${error.javaClass.simpleName}: ${error.message}",
            )
        }
    }
}

/** 把"安装候选"提交进共用切换事务的可注入接缝（生产 = [FacadeInstallTransactor]）。 */
interface KsuInstallTransactor {
    /**
     * 阻塞式提交：返回时事务已经 **commit 完成并回读通过**（或明确失败）。
     * 只能在后台线程调用。
     */
    suspend fun commitInstall(
        candidate: KsuProducedCandidate,
        requestedSwitchId: String?,
        onProgress: (String) -> Unit,
    ): KsuCommitResult
}

/**
 * 生产实现：`KsuInstallProducer` 的候选 → `ModeSwitchFacade.installCommit`。
 *
 * 为什么经由 facade 而不是自己编排 12 方法：facade 已经持有
 * 客户端（含 Ultra/SERVICE 选择）、环境（`beginInputs` 镜像、`activeMode`）、基线 provisioner、
 * 工作目录与 `workRoot`；自己再装配一套就会出现"两套事务入口"（红线 4 的反面）。
 */
class FacadeInstallTransactor(private val context: Context) : KsuInstallTransactor {

    override suspend fun commitInstall(
        candidate: KsuProducedCandidate,
        requestedSwitchId: String?,
        onProgress: (String) -> Unit,
    ): KsuCommitResult {
        // 安装页可能早于工作模式页：Runtime 未初始化时按同一套生产参数初始化（幂等）。
        val facade = ModeSwitchRuntime.facadeOrNull()
            ?: runCatching { ModeSwitchRuntime.initialize(context) }.getOrNull()
            ?: return KsuCommitResult.NoTransaction(
                KsuInstallCodes.NOT_ACTIVE,
                "mode-switch runtime is not available",
            )
        val outcome = facade.installCommit(
            candidate = InstallCandidateImage(
                image = candidate.candidate,
                sha256 = candidate.sha256,
                size = candidate.size,
                partition = candidate.partition,
            ),
            requestedSwitchId = requestedSwitchId,
            onProgress = onProgress,
        )
        return when (outcome) {
            is InstallCommitOutcome.AwaitingReboot -> KsuCommitResult.Committed(
                switchId = outcome.switchId,
                state = outcome.status?.state.orEmpty(),
                // M2：成功判据的证据强度原样上抛（SERVICE = state-only，Ultra = state+readback）。
                evidence = outcome.evidence,
            )
            is InstallCommitOutcome.Rejected -> if (outcome.requiresRecovery) {
                KsuCommitResult.RecoveryRequired(
                    code = outcome.code,
                    detail = outcome.detail,
                    switchId = outcome.switchId,
                )
            } else {
                KsuCommitResult.Failed(
                    code = outcome.code,
                    detail = outcome.detail,
                    rolledBack = outcome.rolledBack,
                )
            }
        }
    }
}

/**
 * 生产 root shell 执行器。
 *
 * 候选顺序：`<libksud_ksu.so> debug su [-g]`（自家、UAPI=7）→ 系统 `su -mm` → `su`。
 * 只接受 `isRoot` 的 shell；任何构建/执行失败都返回 code=-1（不抛，与 Lite 风格一致）。
 * 注：libsu 不提供单条命令超时；[timeoutMs] 由调用方的进程级看门狗保证（W12 验收项）。
 */
class LibsuRootCommandRunner(private val daemonPath: String) : KsuRootCommandRunner {
    override fun run(commandLine: String, timeoutMs: Long): KsuShellResult {
        val candidates: List<Array<String>> = listOf(
            arrayOf(daemonPath, "debug", "su"),
            arrayOf("su", "-mm"),
            arrayOf("su"),
        )
        for (candidate in candidates) {
            val shell = runCatching { Shell.Builder.create().build(*candidate) }.getOrNull() ?: continue
            try {
                if (!shell.isRoot) continue
                val out = mutableListOf<String>()
                val err = mutableListOf<String>()
                val result = shell.newJob().add(commandLine).to(out, err).exec()
                return KsuShellResult(result.code, out, err)
            } catch (t: Throwable) {
                KsuLog.record("root-shell-error", "${t.javaClass.simpleName}: ${t.message}")
            } finally {
                runCatching { shell.close() }
            }
        }
        return KsuShellResult(-1, emptyList(), listOf("no authenticated root shell"))
    }
}
