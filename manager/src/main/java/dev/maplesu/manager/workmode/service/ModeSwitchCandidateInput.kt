package dev.maplesu.manager.workmode.service

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.UltraInitBootProducer
import dev.maplesu.manager.ultrakernel.UltraKernelAssetSource
import dev.maplesu.manager.ultrakernel.UltraKernelDeploymentNamespace
import dev.maplesu.manager.ultrakernel.UltraKernelOriginalRecovery
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.switch.CandidateInput
import dev.maplesu.manager.workmode.switch.ModeSwitchHashes
import java.io.File
import java.io.InterruptedIOException
import java.nio.file.Files
import java.nio.file.LinkOption

/** Carries only verified image lineage; PRE exports use the existing transaction transport. */
internal class ModeSwitchCandidateInput(
    private val assets: UltraKernelAssetSource,
    private val receiptsDirectory: File,
) {
    fun readSource(input: File): UltraKernelDeploymentNamespace? =
        if (BootImageInspector.inspect(input).kernelSize == 0L || UltraInitBootProducer.recognizes(input)) {
            UltraInitBootProducer.readDeploymentNamespace(input)?.let(UltraKernelDeploymentNamespace::decode)
        } else {
            UltraKernelOriginalRecovery(assets).generatedKernelWithDeployment(input, receiptsDirectory)?.deploymentNamespace
        }

    suspend fun prepare(input: CandidateInput, status: ClientStatus, client: ModeSwitchClient): CandidateInput {
        if (input.toMode != WorkMode.LITE) return input
        check(status.switchId == input.switchId) { "SOURCE_RECOVERY_TRANSACTION_CHANGED" }
        val baseline = verified(input.baselineImage, input.baselineImage.length(), input.baselineSha256)
        if (baseline != null) return input.withDeploymentNamespace(baseline)
        val deployment = readCaptured(status.partitions, input.workDir) { name, destination ->
            client.exportImage(input.switchId, "PRE", name, destination)
        }
        return input.withDeploymentNamespace(deployment)
    }

    suspend fun readCaptured(
        rows: List<ClientPartition>,
        workDir: File,
        export: suspend (String, File) -> Boolean,
    ): UltraKernelDeploymentNamespace? {
        val sources = rows.filter { it.name in setOf("boot", "init_boot") }
        check(sources.isNotEmpty() && sources.map { it.name }.distinct().size == sources.size) {
            "SOURCE_RECOVERY_PRE_METADATA_INVALID"
        }
        check(Files.isDirectory(workDir.toPath(), LinkOption.NOFOLLOW_LINKS)) { "SOURCE_RECOVERY_WORKSPACE_FAILED" }
        var retained: UltraKernelDeploymentNamespace? = null
        for (row in sources) {
            if (Thread.currentThread().isInterrupted) throw InterruptedIOException("SOURCE_RECOVERY_CANCELLED")
            check(row.size > 0 && ModeSwitchHashes.isHash(row.preSha256)) { "SOURCE_RECOVERY_PRE_METADATA_INVALID" }
            val temporary = Files.createTempFile(workDir.toPath(), "lineage-${row.name}-", ".img")
            var failure: Throwable? = null
            try {
                check(export(row.name, temporary.toFile())) { "SOURCE_RECOVERY_LINEAGE_EXPORT_FAILED:${row.name}" }
                val found = verified(temporary.toFile(), row.size, row.preSha256)
                if (found != null) {
                    check(retained == null || retained.record().contentEquals(found.record())) {
                        "SOURCE_RECOVERY_DEPLOYMENT_CONFLICT"
                    }
                    retained = found
                }
            } catch (error: Throwable) {
                failure = error
                throw error
            } finally {
                try { Files.deleteIfExists(temporary) } catch (cleanup: Throwable) {
                    if (failure == null) throw cleanup else failure.addSuppressed(cleanup)
                }
            }
        }
        return retained
    }

    private fun verified(image: File, size: Long, sha256: String): UltraKernelDeploymentNamespace? {
        fun unchanged() = Files.isRegularFile(image.toPath(), LinkOption.NOFOLLOW_LINKS) &&
            image.length() == size && ModeSwitchHashes.sha256(image) == sha256
        check(ModeSwitchHashes.isHash(sha256) && unchanged()) { "SOURCE_RECOVERY_PRE_IMAGE_CHANGED" }
        val deployment = readSource(image)
        check(unchanged()) { "SOURCE_RECOVERY_PRE_IMAGE_CHANGED" }
        return deployment
    }
}
