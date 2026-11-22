package dev.maplesu.ghostlock.extract

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Runs the retained Rust implementation; only local images reach this process. */
class GhostlockNativeExtractor(private val executable: File) : KernelImageExtractor {
    companion object {
        const val REFERENCE_COMMIT = "b67359641c8663e5184abba73ecdf2c456dce3e7"
    }

    override fun extract(input: ExtractInput.BootImageFile, workDir: File,
                         onLog: (String) -> Unit): String {
        if (!executable.isFile || !executable.canExecute()) {
            throw IOException("GHOSTLOCK_EXTRACTOR_MISSING")
        }
        for (file in listOfNotNull(input.boot, input.xblConfig, input.uefi, input.vendorBoot)) {
            if (!file.isFile || file.length() > GhostlockExtractionPipeline.MAX_LOCAL_IMAGE_BYTES) {
                throw IOException("GHOSTLOCK_EXTRACTOR_INPUT_INVALID:${file.name}")
            }
        }
        workDir.mkdirs()
        val runDir = Files.createTempDirectory(workDir.toPath(), "reference-").toFile()
        val document = File(runDir, "profile.conf")
        val command = mutableListOf(executable.absolutePath, input.boot.absolutePath,
            "--format", "conf", "--out", document.absolutePath, "--work-dir", runDir.absolutePath)
        for ((option, file) in listOf("--xbl-config" to input.xblConfig, "--uefi" to input.uefi,
                "--vendor-boot" to input.vendorBoot)) {
            if (file != null) { command += option; command += file.absolutePath }
        }
        var process: Process? = null
        try {
            val child = ProcessBuilder(command).redirectErrorStream(true).start()
            process = child
            val readerFailure = AtomicReference<IOException?>()
            val tail = ArrayDeque<String>()
            val reader = Thread({
                try {
                    child.inputStream.bufferedReader().useLines { lines ->
                        lines.forEach { line ->
                            val bounded = line.take(2048)
                            synchronized(tail) {
                                if (tail.size == 16) tail.removeFirst()
                                tail.addLast(bounded)
                            }
                            runCatching { onLog(bounded) }
                        }
                    }
                } catch (error: IOException) { readerFailure.set(error) }
            }, "ghostlock-extractor-output").apply { isDaemon = true; start() }
            if (!child.waitFor(180, TimeUnit.SECONDS)) {
                child.destroyForcibly()
                throw IOException("GHOSTLOCK_EXTRACTOR_TIMEOUT")
            }
            reader.join(5000)
            if (reader.isAlive) throw IOException("GHOSTLOCK_EXTRACTOR_OUTPUT_TIMEOUT")
            readerFailure.get()?.let { throw it }
            val code = child.exitValue()
            if (code != 0) {
                val kind = when (code) {
                    3 -> FailureKind.INFEASIBLE
                    4 -> FailureKind.UNSUPPORTED
                    5 -> FailureKind.KALLSYMS
                    6 -> FailureKind.ALREADY_FIXED
                    else -> FailureKind.GENERIC
                }
                throw ExtractionException(kind,
                    "reference extractor exit=$code: " + synchronized(tail) { tail.joinToString("\n") })
            }
            if (!document.isFile || document.length() !in 1..(1024 * 1024)) {
                throw IOException("GHOSTLOCK_EXTRACTOR_OUTPUT_INVALID")
            }
            return document.readText()
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("GHOSTLOCK_EXTRACTOR_CANCELLED", error)
        } finally {
            process?.let { child ->
                if (child.isAlive) child.destroyForcibly()
                runCatching { child.inputStream.close() }
                runCatching { child.outputStream.close() }
                runCatching { child.errorStream.close() }
            }
            runDir.deleteRecursively()
        }
    }
}
