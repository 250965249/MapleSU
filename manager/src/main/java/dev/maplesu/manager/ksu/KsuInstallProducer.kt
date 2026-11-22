// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import com.maplesu.core.core.tasks.BootKernelVersion
import dev.maplesu.image.RamdiskInspector
import dev.maplesu.image.KernelCompression
import dev.maplesu.manager.installer.KsuKernelPreservation
import dev.maplesu.manager.installer.KsuKmiSelection
import dev.maplesu.manager.installer.KsuKmiSelector
import java.io.File
import java.io.RandomAccessFile
import java.security.MessageDigest

/** New app-owned roots avoid inheriting the legacy root-created ksu/work tree on upgrade. */
object KsuCandidateWorkspaces {
    fun install(filesDir: File): File = File(filesDir, "ksu-candidates-v2")
    fun switch(workDir: File): File = File(workDir, "normal-produce")
}

/**
 * KSU 候选生产者。
 *
 * **唯一职责：只产候选文件，绝不写分区。** 分区写入只允许
 * `InstallerPartitionService` + `BlockDeviceTransaction`；
 * 因此这里没有、也不允许出现 `--flash`/`-f`/`--backup`/`--ota`/`--restore`
 * 任何写分区路径。命令由 [KsuCommands.bootPatch] 构造（参数级硬拒绝在那一层），
 * 本类把构造好的命令交给调用方执行：选文件仅产候选使用普通进程，读取当前分区与
 * 写入事务使用已有 Root 会话。
 *
 * 校验链（任一失败即拒绝，候选不进入提交）：
 * 1. 源镜像存在且可解析；已修补输入交给 ksud 按实际格式处理；
 * 2. 目标分区必须在白名单内（`init_boot` / `boot`，D4）；
 * 3. ksud 退出码为 0；
 * 4. 候选存在、非空、SHA-256 可计算；
 * 5. 候选可被 [RamdiskInspector] 解析且满足 KSU LKM 形态
 *    （`init`/`init.real`/`kernelsu.ko`/`ksu_config`；`sevenk.ko` → FOREIGN）；
 * 6. **kernel 段逐字节未变**（[KsuKernelPreservation]）：`boot` 目标下与源镜像比对
 *    kernel 区间摘要，`init_boot` 目标下候选不许带 kernel 段 —— LKM 只改 ramdisk。
 *
 * 提交交给 [KsuCandidateCommitPort]：生产实现是"工作模式切换事务"的
 * `InstallerServiceClient.submitSwitchCandidate`（S3→S4 的唯一合法写入口）。
 */
fun interface KsuRootCommandRunner {
    /**
     * Execute the constructed candidate command using the caller's transport.
     * File-only patching uses an ordinary process; partition workflows supply a Root session.
     */
    fun run(commandLine: String, timeoutMs: Long): KsuShellResult

    fun run(argv: List<String>, timeoutMs: Long): KsuShellResult =
        run(KsuInstallProducer.shellJoin(argv), timeoutMs)
}

/** 生产者输出（候选文件 + 全部校验事实，供切换事务 manifest/evidence 使用）。 */
data class KsuProducedCandidate(
    val candidate: File,
    val size: Long,
    val sha256: String,
    val partition: String,
    val form: RamdiskInspector.Form,
    val ramdiskState: RamdiskState,
    /** 生产时使用的源镜像摘要；用于 S3/S4 之间的身份复核。 */
    val sourceSha256: String,
    /** 候选内嵌的 `kernelsu.ko` 条目摘要（缺失时为 null；供"内嵌 LKM 与固定产物一致"断言）。 */
    val kernelsuKoSha256: String?,
)

sealed class KsuProduceResult {
    data class Produced(val candidate: KsuProducedCandidate) : KsuProduceResult()

    /** 拒绝码是稳定的机器值（`PRODUCE_*`），UI 只做本地化映射，不做字符串匹配。 */
    data class Rejected(val code: String, val detail: String, val exitCode: Int? = null) : KsuProduceResult()
}

/** Actual boot-patch invocation and its separate output streams. */
data class KsuPatchCommandReceipt(val argv: List<String>, val result: KsuShellResult)

sealed class KsuCommitResult {
    /**
     * 切换事务已**接收**候选，但没有经过 `commit` + 逐分区回读确认。
     *
     * **绝不可当成功**（P0-1 第 4 项防谎报）：`KsuInstallProducer` 把它映射成
     * `Staged(code=KSU_INSTALL_COMMIT_NOT_CONFIRMED)`，绝不映射成 `Committed`。
     */
    data object Accepted : KsuCommitResult()

    /**
     * 事务走完 `preflight → begin → snapshot → submit → commit`，且后端报告
     * `REBOOT_REQUIRED`（该状态只在**逐分区写后回读通过**之后才写，见
     * `UltraRootModeSwitchClient.commitInternal` / 服务端 `ModeSwitchDeviceDelegate.commit`）。
     *
     * @param evidence 成功判据的证据强度（M2）：`state+readback` / `state-only`。
     *   SERVICE 通道只上报 `state`（`observedSha256` 恒空）⇒ `state-only`；
     *   日志/报告必须照实引用，不得说成"写后回读已核对"。
     */
    data class Committed(
        val switchId: String,
        val state: String = "",
        val evidence: String = "",
    ) : KsuCommitResult()

    data class Failed(
        val code: String,
        val detail: String,
        /** 分区是否已确认回滚到 PRE（或压根没写过）。 */
        val rolledBack: Boolean = false,
    ) : KsuCommitResult()

    /** 分区可能已写、回滚不完整 → 必须人工恢复（`RECOVERY_REQUIRED`）。 */
    data class RecoveryRequired(
        val code: String,
        val detail: String,
        val switchId: String,
    ) : KsuCommitResult()

    /** 没有进行中的切换事务（本版本 W08 未接线时的默认结果）：候选已落 staging，不写分区。 */
    data class NoTransaction(val code: String, val detail: String) : KsuCommitResult()
}

/** 共用事务的提交端口（测试注入替身；生产实现见 `KsuInstallGlue`）。 */
fun interface KsuCandidateCommitPort {
    fun submit(candidate: KsuProducedCandidate, switchId: String?): KsuCommitResult
}

/**
 * 可选能力：带进度的提交（生产实现 = `ModeSwitchCommitPort`）。
 *
 * 为什么做成**独立接口**而不是 `KsuCandidateCommitPort` 的默认方法：后者是 `fun interface`
 * （既有调用方用两参数 lambda，包含不在本轮授权范围的 `ModeSwitchRuntime`）。新增抽象方法会
 * 破坏 SAM 转换；做成可探测的额外能力，既有调用方一行都不用改。
 */
interface KsuProgressCommitPort {
    /** 生产实现会流式上报 S0b/S1/S2/4b/S3/S4/4e/4f。 */
    fun submitWithProgress(
        candidate: KsuProducedCandidate,
        switchId: String?,
        onProgress: (String) -> Unit,
    ): KsuCommitResult
}

/**
 * 进行中的切换事务 id（**遗留可选入口**）。
 *
 * 历史设计是"由 W08 的 `ModeSwitchController` 在 S1/S3 设置"，但该控制器在生产里没有构造点，
 * 因此这个字段**全仓库没有任何生产写入者**（只有 [resetForTest] 清零）——它恒为 `null`。
 *
 * P0-1 第 4 项之后安装路径**不再依赖它**：事务 id 由提交端口（生产 =
 * `ModeSwitchFacade.installCommit`）自己生成 canonical UUID。本字段只为兼容既有调用方保留：
 * 非空时仍原样传给 [KsuCandidateCommitPort]（可当作"续跑指定 id"的入口）。
 */
object KsuSwitchSession {
    @Volatile
    var activeSwitchId: String? = null

    fun resetForTest() {
        activeSwitchId = null
    }
}

sealed class KsuInstallResult {
    /** 候选已生成、已提交、且事务**写完分区并回读通过**（等待重启）。 */
    data class Committed(
        val candidate: KsuProducedCandidate,
        /** 成功证据强度（M2）：`state+readback` / `state-only`（SERVICE 通道恒为后者）。 */
        val evidence: String = "",
    ) : KsuInstallResult()

    /** 候选已生成并校验，但没有可用的切换事务：staged，未写分区。 */
    data class Staged(
        val candidate: KsuProducedCandidate,
        val code: String,
        val switchId: String = "",
    ) : KsuInstallResult()

    /** 失败且不需要人工恢复（未写分区，或已确认逆序回滚）。 */
    data class Failed(
        val code: String,
        val detail: String,
        val rolledBack: Boolean = false,
    ) : KsuInstallResult()

    /** 分区可能已写、回滚不可信 → 必须人工恢复（**不是**成功，也不是普通失败）。 */
    data class NeedsRecovery(
        val candidate: KsuProducedCandidate,
        val code: String,
        val detail: String = "",
        val switchId: String = "",
    ) : KsuInstallResult()
}

/**
 * @param daemonPath APK `nativeLibraryDir/libksud_ksu.so` 的绝对路径。
 * @param runner root shell 执行器（生产 = libsu + `ksud debug su`；测试 = 假执行器）。
 * @param workRoot 由 App 创建的候选/staging 根目录，只写 App 私有区。
 */
class KsuInstallProducer(
    private val daemonPath: String,
    private val runner: KsuRootCommandRunner,
    private val workRoot: File,
    private val commit: KsuCandidateCommitPort,
    private val switchSession: () -> String? = { KsuSwitchSession.activeSwitchId },
    private val clock: () -> Long = { System.currentTimeMillis() },
    /**
     * 本次 APK 内嵌的 KMI 清单（生产 = `ksud boot-info supported-kmis`；null = 未上报）。
     *
     * 上报了就按 KMI 选 `.ko`：缺该 KMI 的产物 → `KSU_KMI_ARTIFACT_MISSING`，
     * **绝不**静默换用别的 KMI（ksud 会按 `--kmi` 找 `<kmi>_kernelsu.ko`，缺了也硬失败）。
     */
    private val kmiCatalog: () -> Collection<String>? = { null },
    /** App owner of a root-produced candidate; null is for platform-independent callers. */
    private val appUid: Int? = null,
) {

    /** 产候选（不提交）。 */
    fun produceCandidate(
        source: File,
        options: KsuBootPatchOptions,
        onStdout: (String) -> Unit = {},
        onStderr: (String) -> Unit = {},
        onCommand: (KsuPatchCommandReceipt) -> Unit = {},
    ): KsuProduceResult {
        if (!source.isFile || source.length() <= 0L) {
            return KsuProduceResult.Rejected(
                "PRODUCE_SOURCE_MISSING",
                "source image missing or empty: ${source.absolutePath}",
            )
        }
        if (File(daemonPath).let { !it.isFile }) {
            return KsuProduceResult.Rejected(
                "PRODUCE_DAEMON_MISSING",
                "ksud executable missing: $daemonPath",
            )
        }
        if (options.partition !in ALLOWED_PARTITIONS) {
            return KsuProduceResult.Rejected(
                "PRODUCE_PARTITION_UNSUPPORTED",
                "Normal only accepts ${ALLOWED_PARTITIONS.sorted()}, got '${options.partition}'",
            )
        }

        // 1) 读取源镜像布局；已修补格式由实际 ksud 处理，空 ramdisk 候选仍需验证。
        val sourceReport = inspectOrNull(source)
            ?: return KsuProduceResult.Rejected(
                "PRODUCE_SOURCE_UNREADABLE",
                "source image cannot be inspected: ${source.absolutePath}",
            )
        val sourceWithoutRamdisk = options.partition == "boot" && sourceReport.errorCode == "EMPTY_RAMDISK"
        if (sourceReport.malformed && !sourceWithoutRamdisk) {
            return KsuProduceResult.Rejected(
                "PRODUCE_SOURCE_MALFORMED",
                "source ramdisk malformed: ${sourceReport.errorCode}",
            )
        }
        val knownEmptyRamdisk = options.partition == "boot" && !sourceReport.hasInitReal &&
            hasEmptyRamdiskOrigin(source, sourceReport)

        // boot 自带目标内核；init_boot 的 KMI 保留调用方明确目标或 ksud 当前设备默认。
        val targetOptions = if (options.partition == "boot") {
            val parsed = runCatching { BootKernelVersion.parseKmiFromBoot(source) }
            val targetKmi = parsed.getOrNull()?.takeIf { it.isNotBlank() }
                ?: return KsuProduceResult.Rejected(
                    "PRODUCE_TARGET_KMI_UNAVAILABLE",
                    "target boot KMI unavailable: ${source.absolutePath}" +
                        parsed.exceptionOrNull()?.let { ": ${it.javaClass.simpleName}: ${it.message}" }.orEmpty(),
                )
            onStdout("- kmi-source=target-kernel kmi=$targetKmi image=${source.absolutePath}")
            options.copy(kmi = targetKmi)
        } else {
            onStdout(if (options.kmi.isNullOrBlank()) "- kmi-source=ksud-current-default"
                else "- kmi-source=options kmi=${options.kmi}")
            options
        }
        val requestedKmi = targetOptions.kmi?.trim().orEmpty()
        if (requestedKmi.isNotEmpty()) {
            when (val selection = KsuKmiSelector.select(requestedKmi, kmiCatalog())) {
                is KsuKmiSelection.Ready ->
                    onStdout("- kmi=${selection.kmi} ko=${selection.artifactName}")
                is KsuKmiSelection.Missing -> return KsuProduceResult.Rejected(
                    selection.code, selection.detail,
                )
                // 目录未上报：交给 ksud 按同一目标 `--kmi` 查内嵌资产。
                is KsuKmiSelection.Unknown -> Unit
            }
        }

        // 2) 参数级硬拒绝 + 受控命令构造（03 §3.8.6）。
        val outDir = File(workRoot, "cand-${clock()}")
        val outName = "candidate.img"
        val command = try {
            KsuCommands.bootPatch(daemonPath, source, outDir, outName, targetOptions)
        } catch (t: Throwable) {
            return KsuProduceResult.Rejected(
                "PRODUCE_COMMAND_REJECTED",
                "${t.javaClass.simpleName}: ${t.message}",
            )
        }
        if (!outDir.isDirectory && !outDir.mkdirs()) {
            return KsuProduceResult.Rejected("PRODUCE_OUTPUT_DIRECTORY_FAILED", "candidate directory unavailable")
        }

        // 3) 交给调用方执行已构造好的 argv；文件进程直接启动，Root 通道保留 shell 传输。
        onStdout("- ${command.joinToString(" ")}")
        val result = runner.run(command, KsuTimeouts.BOOT_PATCH_MS)
        onCommand(KsuPatchCommandReceipt(command.toList(), result))
        result.out.forEach { onStdout(it) }
        result.err.forEach { onStderr(it) }
        if (result.code != 0) {
            return KsuProduceResult.Rejected(
                "PRODUCE_KSud_FAILED",
                "ksud boot-patch code=${result.code} output=${commandDetail(result)}",
                exitCode = result.code,
            )
        }

        // 4) ksud runs as root and creates mode-0600 output. Hand over this exact file before
        // any app-side read; no recursive ownership/mode changes and no permission broadening.
        val candidate = File(outDir, outName)
        appUid?.let { uid ->
            if (uid <= 0) return KsuProduceResult.Rejected("PRODUCE_OUTPUT_HANDOFF_FAILED", "invalid app uid")
            val transferred = runner.run(candidateHandoff(candidate, uid), KsuTimeouts.COMMAND_MS)
            if (transferred.code != 0) {
                return KsuProduceResult.Rejected("PRODUCE_OUTPUT_HANDOFF_FAILED",
                    "candidate handoff code=${transferred.code} output=${commandDetail(transferred)}",
                    exitCode = transferred.code)
            }
        }
        if (!candidate.isFile || candidate.length() <= 0L) {
            return KsuProduceResult.Rejected(
                "PRODUCE_OUTPUT_MISSING",
                "ksud reported success but no candidate at ${candidate.absolutePath}",
            )
        }
        if (!candidate.canRead()) {
            return KsuProduceResult.Rejected("PRODUCE_OUTPUT_UNREADABLE", "candidate not readable after root handoff")
        }
        val sha256 = sha256(candidate)
        val sourceSha256 = sha256(source)

        // 5) 候选结构断言（image-core 的只读解析器；候选是完整 init_boot 容器）。
        val candidateReport = inspectOrNull(candidate)
            ?: return KsuProduceResult.Rejected(
                "PRODUCE_CANDIDATE_MALFORMED",
                "candidate cannot be inspected: ${candidate.absolutePath}",
            )
        if (candidateReport.malformed) {
            return KsuProduceResult.Rejected(
                "PRODUCE_CANDIDATE_MALFORMED",
                "candidate ramdisk malformed: ${candidateReport.errorCode} " +
                    candidateReport.problems.joinToString { it.code },
            )
        }
        val verdict = candidateReport.requireKsuLkmForm()
        // GKI boot may have no original init; upstream ksuinit then uses /system/bin/init.
        val createdRamdisk = verdict.violations == listOf("init.real") &&
            (sourceWithoutRamdisk || knownEmptyRamdisk && hasEmptyRamdiskOrigin(candidate, candidateReport))
        if (!verdict.ok && !createdRamdisk) {
            return KsuProduceResult.Rejected(
                "PRODUCE_CANDIDATE_FORM_${verdict.code}",
                "candidate is not the KSU LKM form: ${verdict.detail} " +
                    verdict.violations.joinToString(),
            )
        }

        // 6) **内核不变**：LKM 补丁只准改 ramdisk。命令层禁掉 `--kernel` 只是"没传这个 flag"，
        //    真正的证明在字节层：boot 目标下候选的 kernel 段必须与源镜像逐字节相同；
        //    init_boot 目标下候选根本不该带 kernel 段（`KsuKernelPreservation`）。
        val preservation = KsuKernelPreservation.check(options.partition, source, candidate)
        if (preservation is KsuKernelPreservation.Verdict.Rejected) {
            return KsuProduceResult.Rejected(preservation.code, preservation.detail)
        }

        val form = if (createdRamdisk) RamdiskInspector.Form.KSU_LKM_COMPATIBLE else candidateReport.form()
        return KsuProduceResult.Produced(
            KsuProducedCandidate(
                candidate = candidate,
                size = candidate.length(),
                sha256 = sha256,
                partition = options.partition,
                form = form,
                ramdiskState = if (createdRamdisk) RamdiskState.COMPATIBLE else ramdiskStateOf(candidateReport),
                sourceSha256 = sourceSha256,
                kernelsuKoSha256 = candidateReport.entry(KsuRamdiskLayout.ENTRY_KERNELSU_KO)?.sha256,
            ),
        )
    }

    /**
     * 产候选 → 断言 → 交共用事务（**并等它写完**）。
     *
     * 只有 [KsuCommitResult.Committed]（= 事务 `commit` 完成且后端报 `REBOOT_REQUIRED`，
     * 即逐分区回读已过）才会映射成 [KsuInstallResult.Committed]。
     * 只是"被接收"（[KsuCommitResult.Accepted]）→ `Staged(code=KSU_INSTALL_COMMIT_NOT_CONFIRMED)`，
     * **绝不谎报安装成功**（P0-1 第 4 项的 R1）。
     */
    fun installBoot(
        source: File,
        options: KsuBootPatchOptions,
        onStdout: (String) -> Unit = {},
        onStderr: (String) -> Unit = {},
    ): KsuInstallResult {
        val produced = when (val result = produceCandidate(source, options, onStdout, onStderr)) {
            is KsuProduceResult.Rejected -> return KsuInstallResult.Failed(result.code, result.detail)
            is KsuProduceResult.Produced -> result.candidate
        }
        val staged = publishStaged(produced)
        onStdout("- candidate sha256=${produced.sha256} size=${produced.size} form=${produced.form}")
        onStdout("- staged candidate: ${staged.absolutePath}")
        // 有进度能力就带上（生产 = 12 方法事务会逐阶段上报）。
        val port = commit
        val result = if (port is KsuProgressCommitPort) {
            port.submitWithProgress(produced, switchSession(), onStdout)
        } else {
            port.submit(produced, switchSession())
        }
        // 取证/续跑：事务跑起来之后把 switchId 落到 staging provenance（幂等，只重写 json）。
        val switchId = switchIdOf(result)
        if (switchId.isNotEmpty()) {
            runCatching { publishStaged(produced, switchId) }
        }
        return when (result) {
            is KsuCommitResult.Committed -> KsuInstallResult.Committed(produced, result.evidence)
            is KsuCommitResult.RecoveryRequired ->
                KsuInstallResult.NeedsRecovery(produced, result.code, result.detail, result.switchId)
            // 「被接收」不等于「已写盘」：一律 staged + 显式码，调用方必须当失败处理。
            is KsuCommitResult.Accepted ->
                KsuInstallResult.Staged(produced, COMMIT_NOT_CONFIRMED_CODE)
            is KsuCommitResult.NoTransaction ->
                KsuInstallResult.Staged(produced, result.code)
            is KsuCommitResult.Failed ->
                KsuInstallResult.Failed(result.code, result.detail, result.rolledBack)
        }
    }

    private fun switchIdOf(result: KsuCommitResult): String = when (result) {
        is KsuCommitResult.Committed -> result.switchId
        is KsuCommitResult.RecoveryRequired -> result.switchId
        is KsuCommitResult.Accepted -> ""
        is KsuCommitResult.NoTransaction -> ""
        is KsuCommitResult.Failed -> ""
    }

    /**
     * 把候选 + provenance 落到稳定 staging 路径；返回候选副本。
     * 文件名带 SHA-256，内容单调（同摘要不会重复解析）；provenance 手写 JSON（无 Android 依赖）。
     *
     * @param switchId 已知时写进 provenance（事务 id 是续跑/取证的唯一键；空 = 尚未建事务）
     */
    fun publishStaged(candidate: KsuProducedCandidate, switchId: String = ""): File {
        val stagedDir = File(workRoot, "staged").apply { mkdirs() }
        val target = File(stagedDir, "${candidate.sha256}.img")
        if (!target.isFile || target.length() != candidate.size) {
            candidate.candidate.copyTo(target, overwrite = true)
        }
        val meta = File(stagedDir, "${candidate.sha256}.json")
        meta.writeText(
            buildString {
                append('{')
                append("\"sha256\":\"").append(candidate.sha256).append("\",")
                append("\"size\":").append(candidate.size).append(',')
                append("\"partition\":\"").append(candidate.partition).append("\",")
                append("\"form\":\"").append(candidate.form.name).append("\",")
                append("\"ramdiskState\":\"").append(candidate.ramdiskState.token).append("\",")
                append("\"sourceSha256\":\"").append(candidate.sourceSha256).append("\",")
                append("\"kernelsuKoSha256\":")
                append(candidate.kernelsuKoSha256?.let { "\"$it\"" } ?: "null").append(',')
                append("\"switchId\":\"").append(switchId).append("\",")
                append("\"stagedAt\":").append(clock())
                append('}')
            },
        )
        return target
    }

    private fun inspectOrNull(file: File): RamdiskInspector.Report? = runCatching {
        RamdiskInspector.inspect(file)
    }.getOrNull()

    /** A source fact written only when ksud created the original ramdisk from nothing. */
    private fun hasEmptyRamdiskOrigin(image: File, report: RamdiskInspector.Report): Boolean = runCatching {
        if (!report.hasMaplesuId || !report.hasInit || !report.hasKernelsuKo ||
            report.hasInitReal || report.hasSevenkKo || report.hasMagiskMarker) return false
        val entry = report.entry("ksu_config") ?: return false
        if (!entry.isRegularFile || report.ramdiskSize !in 1..RamdiskInspector.MAX_COMPONENT_BYTES) return false
        val encoded = ByteArray(report.ramdiskSize.toInt())
        RandomAccessFile(image, "r").use { file -> file.seek(report.ramdiskOffset); file.readFully(encoded) }
        val decoded = if (report.compression == "RAW") encoded else
            KernelCompression.decode(encoded, report.compression, RamdiskInspector.DEFAULT_MAX_BYTES.toInt())
        if (entry.offset < 0 || entry.size > decoded.size || entry.offset > decoded.size - entry.size) return false
        val config = decoded.copyOfRange(entry.offset.toInt(), (entry.offset + entry.size).toInt())
        val digest = MessageDigest.getInstance("SHA-256").digest(config)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        if (digest != entry.sha256) return false
        config.toString(Charsets.UTF_8).split(' ').filter { it.startsWith("maplesu_original_ramdisk=") } ==
            listOf("maplesu_original_ramdisk=empty-v1")
    }.getOrDefault(false)

    private fun commandDetail(result: KsuShellResult): String =
        (result.out + result.err).joinToString("\n").takeLast(4096)

    private fun candidateHandoff(candidate: File, uid: Int): String = buildString {
        appendLine("D=${shellQuote(candidate.parentFile!!.absolutePath)}")
        appendLine("F=${shellQuote(candidate.absolutePath)}")
        appendLine("[ -d \"\$D\" ] && [ ! -L \"\$D\" ] && [ -f \"\$F\" ] && [ ! -L \"\$F\" ] || exit 72")
        appendLine("/system/bin/chown $uid:$uid \"\$F\" || exit 73")
        appendLine("/system/bin/chmod 0600 \"\$F\" || exit 74")
        appendLine("/system/bin/restorecon \"\$F\" 2>/dev/null || true")
        appendLine("[ \"\$(/system/bin/stat -c '%u:%g:%a' \"\$F\")\" = '$uid:$uid:600' ] || exit 75")
        appendLine("C=\$(/system/bin/stat -c '%C' \"\$D\") || exit 76")
        appendLine("case \"\$C\" in u:object_r:*:s0*) ;; *) exit 76 ;; esac")
        appendLine("[ \"\$(/system/bin/stat -c '%C' \"\$F\")\" = \"\$C\" ] || exit 77")
    }

    private fun ramdiskStateOf(report: RamdiskInspector.Report): RamdiskState = when (report.form()) {
        RamdiskInspector.Form.KSU_LKM_OURS -> RamdiskState.OUR
        RamdiskInspector.Form.KSU_LKM_COMPATIBLE -> RamdiskState.COMPATIBLE
        RamdiskInspector.Form.FOREIGN_ARTIFACT -> RamdiskState.FOREIGN
        RamdiskInspector.Form.STOCK -> RamdiskState.STOCK
        RamdiskInspector.Form.UNKNOWN -> RamdiskState.UNKNOWN
    }

    companion object {
        /** 默认分区（独立 `init_boot` + LKM，D4）：`partition` 没给时用它。 */
        const val ALLOWED_PARTITION = "init_boot"

        /**
         * 允许修补/写入的分区（与 KernelSU 一致：`init_boot` 或 `boot`）。
         *
         * 候选的 `partition` 直接来自这里，并原样传给提交端口，因此**修补目标与刷写目标恒等**
         * ——不存在"补 `init_boot`、写 `boot`"的错位。
         */
        val ALLOWED_PARTITIONS: Set<String> = setOf("init_boot", "boot")

        /**
         * 「候选被接收但没有 commit/回读确认」的稳定码。
         *
         * 它与 `InstallCommitCodes.COMMIT_NOT_CONFIRMED` 同为 `KSU_INSTALL_COMMIT_NOT_CONFIRMED`
         * （同一个机器值：本包不 import `installer` 之外的常量对象也不需要，此处只保证字面一致）。
         */
        const val COMMIT_NOT_CONFIRMED_CODE = "KSU_INSTALL_COMMIT_NOT_CONFIRMED"

        fun sha256(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    digest.update(buffer, 0, read)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        }

        /**
         * 把已构造的 argv 拼成 shell 命令行。
         * 只在 [KsuCommands] 已做参数级拒绝后调用；引号处理保证含空格/特殊字符的路径不被拆分。
         */
        fun shellJoin(tokens: List<String>): String = tokens.joinToString(" ") { shellQuote(it) }

        private fun shellQuote(token: String): String {
            if (token.isNotEmpty() && token.all { it.isLetterOrDigit() || it in SAFE_CHARS }) return token
            return "'" + token.replace("'", "'\\''") + "'"
        }

        private const val SAFE_CHARS = "_-./:=+,@%"
    }
}
