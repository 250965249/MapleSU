package dev.maplesu.manager.installer

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.Closeable
import java.io.FileDescriptor
import java.io.IOException

/** Holds an authenticated device across write preparation, readback and rollback. */
internal class BlockPartitionAccess(
    private val path: String,
    private val writable: Boolean,
    private val verify: (FileDescriptor) -> Unit,
) : Closeable {
    private val readDescriptor = Os.open(path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
    private var writeDescriptor: FileDescriptor? = null
    private var restoreReadOnly = false
    // Readback always uses the held reader; the KSU-compatible writer is O_WRONLY.
    val descriptor: FileDescriptor get() = readDescriptor

    init {
        try { verify(readDescriptor) } catch (error: Throwable) {
            runCatching { Os.close(readDescriptor) }.exceptionOrNull()?.let(error::addSuppressed)
            throw error
        }
    }

    fun revalidate() {
        verify(readDescriptor)
        writeDescriptor?.let(verify)
    }

    fun writableDescriptor(): FileDescriptor {
        check(writable) { "INSTALLER_READ_ONLY" }
        writeDescriptor?.let { return it }
        verify(readDescriptor)
        try {
            restoreReadOnly = control(-1) == 1
            // An initially read-only device may reject opening a writer until cleared.
            if (restoreReadOnly) control(0)
            val output = Os.open(path, OsConstants.O_WRONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
            try {
                verify(output)
                // Like KSU, prepare the actual writer after open, even when BLKROGET
                // reports 0. Opening the driver must precede its final write preparation.
                control(0, output)
            } catch (error: Throwable) {
                runCatching { Os.close(output) }.exceptionOrNull()?.let(error::addSuppressed)
                throw error
            }
            writeDescriptor = output
            return output
        } catch (error: Throwable) {
            Log.e("InstallerBlockAccess", "prepare-write path=$path", error)
            runCatching { restoreFlag() }.exceptionOrNull()?.let(error::addSuppressed)
            throw error
        }
    }

    fun sync() = Os.fsync(writeDescriptor ?: readDescriptor)

    private fun control(desired: Int, descriptor: FileDescriptor = readDescriptor): Int {
        val result = ParcelFileDescriptor.dup(descriptor).use { BlockPartitionControl.readOnly(it.fd, desired) }
        if (result < 0) {
            val operation = if (desired < 0) "BLKROGET" else "BLKROSET($desired)"
            val error = ErrnoException(operation, -result)
            Log.e("InstallerBlockAccess", "$operation path=$path errno=${-result}", error)
            throw IOException("INSTALLER_PARTITION_WRITE_PREPARE_FAILED", error)
        }
        return result
    }

    private fun restoreFlag() {
        if (restoreReadOnly) {
            control(1, writeDescriptor ?: readDescriptor)
            restoreReadOnly = false
        }
    }

    override fun close() {
        var failure: Throwable? = null
        try {
            restoreFlag()
        } catch (error: Throwable) {
            failure = error
            Log.e("InstallerBlockAccess", "restore-readonly path=$path", error)
        }
        for (fd in listOfNotNull(writeDescriptor, readDescriptor)) {
            try { Os.close(fd) } catch (error: Throwable) {
                if (failure == null) failure = error else failure.addSuppressed(error)
            }
        }
        failure?.let { throw it }
    }
}

internal object BlockPartitionControl {
    init { System.loadLibrary("maplesu_bootstrap") }
    external fun readOnly(descriptor: Int, desired: Int): Int
}
