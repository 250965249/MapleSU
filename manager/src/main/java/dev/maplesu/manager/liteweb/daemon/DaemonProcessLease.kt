package dev.maplesu.manager.liteweb.daemon

import java.io.Closeable
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions

/** The daemon owns its lock and publishes its PID only after its HTTP listener has started. */
internal class DaemonProcessLease private constructor(
    private val directory: File,
    private val pid: String,
    private val file: RandomAccessFile,
    private val lock: FileLock,
) : Closeable {
    fun publish() {
        val temporary = File(directory, "liteweb.pid.$pid.tmp")
        try {
            temporary.writeText("$pid\n")
            try {
                Files.setPosixFilePermissions(temporary.toPath(), PosixFilePermissions.fromString("rw-------"))
            } catch (_: UnsupportedOperationException) {
                // Windows host fixtures have no POSIX permissions; Android does.
            }
            Files.move(temporary.toPath(), File(directory, "liteweb.pid").toPath(),
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } finally {
            temporary.delete()
        }
    }

    override fun close() {
        try { lock.release() } finally { file.close() }
    }

    companion object {
        fun acquire(directory: File, pid: String): DaemonProcessLease? {
            require(pid.matches(Regex("[1-9][0-9]*")))
            val file = RandomAccessFile(File(directory, "liteweb.lock"), "rw")
            val lock = try { file.channel.tryLock() } catch (_: OverlappingFileLockException) { null }
                catch (error: Exception) { file.close(); throw error }
            if (lock == null) { file.close(); return null }
            return DaemonProcessLease(directory, pid, file, lock)
        }
    }
}
