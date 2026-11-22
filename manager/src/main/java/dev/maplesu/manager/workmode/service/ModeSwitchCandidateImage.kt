package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.control.AtomicControlFile
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files

/** Match the transaction's full-partition digest to the installer's zero-filled write. */
internal fun fullSizeSwitchCandidate(source: File, destination: File, partitionSize: Long): File {
    val sourceSize = source.length()
    check(source.isFile && sourceSize in 1..partitionSize) { ModeSwitchCodes.PRODUCE_OUTPUT_SIZE_INVALID }
    destination.parentFile?.mkdirs()
    if (!destination.createNewFile()) throw FileAlreadyExistsException(source, destination)
    try {
        val copied = source.inputStream().use { input ->
            destination.outputStream().use { output -> input.copyTo(output) }
        }
        check(copied == sourceSize) { ModeSwitchCodes.PRODUCE_OUTPUT_SIZE_INVALID }
        RandomAccessFile(destination, "rw").use { it.setLength(partitionSize); it.fd.sync() }
        destination.absoluteFile.parentFile?.let(AtomicControlFile::syncDirectory)
        return destination
    } catch (error: Throwable) {
        try { Files.deleteIfExists(destination.toPath()) } catch (cleanupError: Throwable) {
            if (cleanupError !== error) error.addSuppressed(cleanupError)
        }
        throw error
    }
}
