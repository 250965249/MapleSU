package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelPlan
import java.io.File
import java.util.concurrent.CancellationException

/** Private cached images supply candidates only; the running SDK still owns acceptance. */
internal object UltraImageIdentityRecovery {
    fun candidates(filesDir: File, extract: (ByteArray) -> List<String>): Sequence<String> = sequence {
        for (image in images(filesDir)) {
            if (Thread.currentThread().isInterrupted) return@sequence
            val keys = try {
                val kernel = UltraKernelPlan.readKernel(image)
                try { extract(kernel) } finally { kernel.fill(0) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return@sequence
            } catch (_: Exception) {
                continue
            }
            yieldAll(keys)
        }
    }

    internal fun images(filesDir: File): List<File> {
        val root = filesDir.canonicalFile
        val imageDirectory = File(root, "images")
        val imported = File(imageDirectory, "imported.img")
        val workspace = dev.maplesu.manager.compat.UltraStateStorage.flash(root)
        return (listOf(imported, File(workspace, "boot-current.img")) +
            workspace.listFiles { file -> file.name.startsWith("candidate-") && file.extension == "img" }
                .orEmpty().sortedByDescending(File::lastModified)).filter { image ->
            runCatching { image.isFile && image.canonicalFile.parentFile.let { it == imageDirectory || it == workspace } }
                .getOrDefault(false)
        }
    }
}
