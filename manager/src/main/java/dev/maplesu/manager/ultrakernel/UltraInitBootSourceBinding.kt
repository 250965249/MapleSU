package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.UltraInitBootProducer
import java.io.File
import java.nio.file.Files

/** Bind a selected input to live bytes, or the exact inverse recorded inside those live bytes. */
internal object UltraInitBootSourceBinding {
    fun requireSource(source: File, installedBytes: Long, installedSha256: String, workspace: File,
                      captureCurrent: () -> File): UltraKernelDeploymentNamespace? {
        check(source.isFile && source.length() in 1..UltraKernelCatalog.MAX_IMAGE_BYTES) {
            "ULTRA_INIT_PAIRED_BOOT_SOURCE_MISMATCH"
        }
        val selectedBytes = source.length()
        val selectedSha256 = UltraKernelSpec.sha256(source)
        if (selectedBytes == installedBytes && selectedSha256 == installedSha256) return null

        val current = captureCurrent()
        fun unchangedCurrent() {
            check(!Files.isSymbolicLink(current.toPath()) && current.isFile && current.length() == installedBytes &&
                UltraKernelSpec.sha256(current) == installedSha256) { "INSTALLER_IMAGE_CHANGED" }
        }
        unchangedCurrent()
        val work = Files.createTempDirectory(workspace.toPath(), "init-boot-source-")
        val restored = work.resolve("original.img").toFile()
        var failure: Throwable? = null
        try {
            // restore validates the owned recovery record, component hash and exact container hash.
            // Release strings, filenames and matching ramdisks are never lineage evidence.
            UltraInitBootProducer.restore(current, restored)
            check(restored.length() == selectedBytes && UltraKernelSpec.sha256(restored) == selectedSha256) {
                "ULTRA_INIT_PAIRED_BOOT_SOURCE_MISMATCH"
            }
            val deployment = UltraInitBootProducer.readDeploymentNamespace(current)
                ?.let(UltraKernelDeploymentNamespace::decode)
            unchangedCurrent()
            check(source.length() == selectedBytes && UltraKernelSpec.sha256(source) == selectedSha256) {
                "ULTRA_INIT_PAIRED_BOOT_SOURCE_MISMATCH"
            }
            return deployment
        } catch (error: Throwable) {
            failure = error
            throw error
        } finally {
            try {
                Files.deleteIfExists(restored.toPath())
                Files.deleteIfExists(work)
            } catch (cleanup: Throwable) {
                if (failure != null) failure.addSuppressed(cleanup) else throw cleanup
            }
        }
    }
}
