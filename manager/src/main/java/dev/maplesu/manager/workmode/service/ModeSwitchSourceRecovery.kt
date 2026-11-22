package dev.maplesu.manager.workmode.service

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.UltraInitBootProducer
import dev.maplesu.manager.installer.KsuKernelPreservation
import dev.maplesu.manager.ksu.KsuBootInfoSubcommand
import dev.maplesu.manager.ksu.KsuCommands
import dev.maplesu.manager.ksu.KsuInstallProducer
import dev.maplesu.manager.ksu.KsuRootCommandRunner
import dev.maplesu.manager.ksu.KsuShellResult
import dev.maplesu.manager.ksu.KsuTimeouts
import dev.maplesu.manager.ksu.RamdiskState
import dev.maplesu.manager.ultrakernel.UltraKernelAssetSource
import dev.maplesu.manager.ultrakernel.UltraKernelOriginalRecovery
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.switch.CandidateResult
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.ModeSwitchHashes
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption

/** Builds only a recovered source copy; callers own partition snapshots and writes. */
internal class ModeSwitchSourceRecovery(
    private val assets: UltraKernelAssetSource,
    private val receiptsDirectory: File,
    private val retainedOriginals: List<File>,
    private val daemon: String,
    private val runner: KsuRootCommandRunner,
    private val logger: (String) -> Unit = {},
    /** App owner of a root-produced recovery; null is for non-root file callers. */
    private val appUid: Int? = null,
) {
    fun recover(from: WorkMode, partition: String, input: File, outputDir: File,
                sourceKnown: Boolean): CandidateResult = try {
        if (!Files.isRegularFile(input.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            failed("SOURCE_RECOVERY_INPUT_MISSING", input.path)
        } else if (partition !in setOf("boot", "init_boot")) {
            failed("SOURCE_RECOVERY_PARTITION_UNSUPPORTED", partition)
        } else {
            val before = BootImageInspector.inspect(input)
            when (from) {
                WorkMode.KSU -> normal(partition, input, outputDir, sourceKnown, before)
                WorkMode.LITE -> ultra(partition, input, outputDir, sourceKnown, before)
            }
        }
    } catch (error: CommandExecutionFailure) {
        failed("SOURCE_RECOVERY_COMMAND_FAILED", error.message.orEmpty())
    } catch (error: BootImageInspector.InvalidImageException) {
        failed("SOURCE_RECOVERY_CONTAINER_INVALID", error.code)
    } catch (error: IOException) {
        failed(error.message.orEmpty().substringBefore(':').takeIf { it.startsWith("ULTRA_INIT_") }
            ?: "SOURCE_RECOVERY_IO", error.message.orEmpty())
    } catch (error: Exception) {
        val code = if (error.message == ModeSwitchCodes.PRODUCE_OUTPUT_SIZE_INVALID)
            ModeSwitchCodes.PRODUCE_OUTPUT_SIZE_INVALID else "SOURCE_RECOVERY_FAILED"
        failed(code, error.message.orEmpty())
    }

    private fun normal(partition: String, input: File, outputDir: File, sourceKnown: Boolean,
                       before: BootImageInspector.Report): CandidateResult {
        if (partition == "boot" && before.ramdiskSize == 0L && !sourceKnown)
            return complete(input, input, before, "ksu:unchanged:no-ramdisk")

        val (query, queryDetail) = execute(KsuCommands.bootInfo(daemon,
            KsuBootInfoSubcommand.RAMDISK_STATE, input), KsuTimeouts.COMMAND_MS)
        if (query.code != 0) return failed("SOURCE_RECOVERY_COMMAND_FAILED", queryDetail)
        val token = query.out.map(String::trim).filter(String::isNotEmpty).singleOrNull()
        val state = RamdiskState.fromToken(token)
        when (state) {
            RamdiskState.UNKNOWN -> return failed("SOURCE_RECOVERY_STATE_UNKNOWN", queryDetail)
            RamdiskState.STOCK, RamdiskState.FOREIGN -> {
                if (sourceKnown) return failed("SOURCE_RECOVERY_STATE_MISMATCH", queryDetail)
                return complete(input, input, before, "ksu:unchanged:${state.token}")
            }
            RamdiskState.OUR, RamdiskState.COMPATIBLE -> Unit
        }

        val work = workspace(outputDir)
        val compact = File(work, "rebuilt.img")
        val (restore, restoreDetail) = execute(KsuCommands.bootRebuildCopy(daemon,
            input, work, compact.name), KsuTimeouts.BOOT_RESTORE_MS)
        if (restore.code != 0) return failed("SOURCE_RECOVERY_COMMAND_FAILED", restoreDetail)
        if (!Files.isRegularFile(compact.toPath(), LinkOption.NOFOLLOW_LINKS))
            return failed("SOURCE_RECOVERY_OUTPUT_MISSING", restoreDetail)
        appUid?.let { uid ->
            if (uid <= 0) return failed("SOURCE_RECOVERY_OUTPUT_HANDOFF_FAILED", "invalid app uid")
            val command = recoveredImageHandoff(compact, uid)
            val (transferred, detail) = try {
                executeCommand(command, KsuTimeouts.COMMAND_MS, "handoff=$command")
            } catch (error: CommandExecutionFailure) {
                return failed("SOURCE_RECOVERY_OUTPUT_HANDOFF_FAILED", error.message.orEmpty())
            }
            if (transferred.code != 0) return failed("SOURCE_RECOVERY_OUTPUT_HANDOFF_FAILED", detail)
        }
        if (!compact.canRead()) return failed("SOURCE_RECOVERY_OUTPUT_UNREADABLE", compact.path)
        BootImageInspector.inspect(compact)
        when (val kernel = KsuKernelPreservation.check(partition, input, compact)) {
            is KsuKernelPreservation.Verdict.Rejected -> return failed(kernel.code, kernel.detail)
            KsuKernelPreservation.Verdict.Ok -> Unit
        }
        val full = fullSizeSwitchCandidate(compact, File(work, "source-base.img"), before.fileSize)
        return complete(input, full, before, "ksu:file-only:${state.token}")
    }

    private fun ultra(partition: String, input: File, outputDir: File, sourceKnown: Boolean,
                      before: BootImageInspector.Report): CandidateResult {
        if (partition != "boot" || UltraInitBootProducer.recognizes(input)) {
            if (!UltraInitBootProducer.recognizes(input)) {
                if (sourceKnown) return failed("SOURCE_RECOVERY_UNAVAILABLE", "ultra:$partition")
                return complete(input, input, before, "ultra:unchanged:non-source")
            }
            val work = workspace(outputDir)
            val recovered = UltraInitBootProducer.restore(input, File(work, "restored.img"))
            val full = fullSizeSwitchCandidate(recovered, File(work, "source-base.img"), before.fileSize)
            return complete(input, full, before, "ultra:$partition:owned-writes-restored")
        }
        val work = workspace(outputDir)
        val recovery = UltraKernelOriginalRecovery(assets)
        val recovered = recovery.recover(input, receiptsDirectory, retainedOriginals, work)
            ?: recovery.recover(input, receiptsDirectory, emptyList(), work, generatedOnly = true)
        if (recovered == null) {
            if (sourceKnown) return failed("SOURCE_RECOVERY_UNAVAILABLE", "ultra:$partition")
            return complete(input, input, before, "ultra:unchanged:non-source")
        }
        val full = fullSizeSwitchCandidate(recovered.image, File(work, "source-base.img"), before.fileSize)
        return complete(input, full, before, "ultra:${recovered.source.name}")
    }

    private fun complete(input: File, candidate: File, before: BootImageInspector.Report,
                         evidence: String): CandidateResult {
        if (ModeSwitchHashes.sha256(input) != before.sha256)
            return failed("SOURCE_RECOVERY_INPUT_CHANGED", input.path)
        val report = if (candidate == input) before else BootImageInspector.inspect(candidate)
        return CandidateResult(candidate, report.sha256, report.fileSize, structureEvidence = evidence)
    }

    private fun workspace(outputDir: File): File {
        if (!outputDir.isDirectory && !outputDir.mkdirs()) throw IOException("SOURCE_RECOVERY_OUTPUT_CREATE_FAILED")
        return Files.createTempDirectory(outputDir.toPath(), "source-recovery-").toFile()
    }

    private fun recoveredImageHandoff(image: File, uid: Int): String = buildString {
        appendLine("D=${KsuInstallProducer.shellJoin(listOf(image.parentFile!!.absolutePath))}")
        appendLine("F=${KsuInstallProducer.shellJoin(listOf(image.absolutePath))}")
        appendLine("[ -d \"\$D\" ] && [ ! -L \"\$D\" ] && [ -f \"\$F\" ] && [ ! -L \"\$F\" ] || exit 72")
        appendLine("/system/bin/chown $uid:$uid \"\$F\" || exit 73")
        appendLine("/system/bin/chmod 0600 \"\$F\" || exit 74")
        appendLine("/system/bin/restorecon \"\$F\" 2>/dev/null || true")
        appendLine("[ \"\$(/system/bin/stat -c '%u:%g:%a' \"\$F\")\" = '$uid:$uid:600' ] || exit 75")
        appendLine("C=\$(/system/bin/stat -c '%C' \"\$D\") || exit 76")
        appendLine("case \"\$C\" in u:object_r:*:s0*) ;; *) exit 76 ;; esac")
        appendLine("[ \"\$(/system/bin/stat -c '%C' \"\$F\")\" = \"\$C\" ] || exit 77")
    }

    private fun execute(argv: List<String>, timeoutMs: Long): Pair<KsuShellResult, String> =
        executeCommand(KsuInstallProducer.shellJoin(argv), timeoutMs, "argv=$argv")

    private fun executeCommand(command: String, timeoutMs: Long, description: String): Pair<KsuShellResult, String> {
        val result = try {
            runner.run(command, timeoutMs)
        } catch (error: Exception) {
            val detail = redact("$description exception=${error.javaClass.simpleName}: ${error.message.orEmpty()}")
            logger(detail)
            throw CommandExecutionFailure(detail)
        }
        val detail = redact("$description code=${result.code} stdout=${result.outText} stderr=${result.errText}")
        logger(detail)
        return result to detail
    }

    private fun failed(code: String, detail: String) = CandidateResult(null, "", 0, code, redact(detail))

    private fun redact(text: String) = text.replace(KEY_LIKE, "<REDACTED-KEY>")

    private class CommandExecutionFailure(message: String) : Exception(message)

    private companion object {
        // Match the existing SDK logging rule without introducing an Android runtime dependency.
        val KEY_LIKE = Regex("(?<![A-Za-z0-9])[A-Za-z0-9]{48}(?![A-Za-z0-9])")
    }
}
