package dev.maplesu.manager.installer

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import dev.maplesu.installer.BlockDeviceTransaction
import dev.maplesu.installer.WritablePartition
import java.io.File
import java.io.FileDescriptor
import java.io.IOException
import java.security.MessageDigest

/**
 * Real `WritablePartition` for `boot` / `init_boot` (02-switch-contract §4.2).
 *
 * <p>All platform work stays here: held `O_RDONLY` and `O_WRONLY` descriptors with
 * `O_CLOEXEC|O_NOFOLLOW`, `fstat` block/rdev/ino/size
 * checks, canonical path and runtime-property revalidation. Partition bytes are still written only
 * by `BlockDeviceTransaction`: this class merely exposes the authenticated
 * [BlockDeviceTransaction.Device] that the single writer drives.
 *
 * <p>The initial access probe uses `O_WRONLY`; the authenticated writer also prepares and verifies
 * the kernel's block read-only flag, restoring its previous state after readback or rollback.
 */
internal class AndroidWritablePartition(
    private val snapshot: InstallerSnapshot,
    partitionName: String,
) : WritablePartition {
    private val partition: BootPartitionSnapshot
    private val identity: BootPartitionIdentity

    init {
        check(partitionName in WritablePartition.ALLOWED) { "SWITCH_PARTITION_FORBIDDEN" }
        partition = snapshot.partitions[partitionName]
            ?: throw IOException("SWITCH_PARTITION_LAYOUT_UNSUPPORTED")
        identity = requireNotNull(partition.identity) { "INSTALLER_DEVICE_IDENTITY_REQUIRED" }
    }

    override fun name(): String = partition.name

    override fun size(): Long = partition.size

    /** Whole-partition digest, read through a freshly authenticated O_RDONLY descriptor. */
    override fun sha256(): String = digest(full = true)

    /** Last `min(size, TAIL_PROBE_BYTES)` bytes (§4.5.1). */
    override fun tailSha256(): String = digest(full = false)

    override fun readOnly(): Boolean {
        val fd = try {
            Os.open(partition.resolvedPath,
                OsConstants.O_WRONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
        } catch (error: ErrnoException) {
            return when (error.errno) {
                OsConstants.EROFS, OsConstants.EACCES, OsConstants.EPERM -> true
                else -> throw IOException("INSTALLER_DEVICE_IO_FAILED", error)
            }
        }
        try {
            return false
        } finally {
            Os.close(fd)
        }
    }

    override fun open(): BlockDeviceTransaction.Device {
        val access = try {
            BlockPartitionAccess(partition.resolvedPath, true, ::verifyIdentity)
        } catch (error: ErrnoException) {
            if (error.errno == OsConstants.EROFS || error.errno == OsConstants.EACCES ||
                error.errno == OsConstants.EPERM) {
                throw IOException("SWITCH_PARTITION_READONLY", error)
            }
            throw IOException("INSTALLER_DEVICE_IO_FAILED", error)
        }
        val device = Device(access)
        try {
            device.revalidate()
            return device
        } catch (failure: Throwable) {
            runCatching { device.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }

    private fun digest(full: Boolean): String {
        val length = if (full) partition.size
        else minOf(partition.size, WritablePartition.TAIL_PROBE_BYTES.toLong())
        val offset = partition.size - length
        val digest = MessageDigest.getInstance("SHA-256")
        withReadDescriptor { fd ->
            val buffer = ByteArray(64 * 1024)
            var position = offset
            while (position < partition.size) {
                check(!Thread.currentThread().isInterrupted) { "INSTALLER_CANCELLED" }
                val count = Os.pread(fd, buffer, 0,
                    minOf(buffer.size.toLong(), partition.size - position).toInt(), position)
                check(count > 0) { "INSTALLER_DEVICE_READ_FAILED" }
                digest.update(buffer, 0, count)
                position += count
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun <T> withReadDescriptor(action: (FileDescriptor) -> T): T {
        val fd = try {
            Os.open(partition.resolvedPath,
                OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
        } catch (error: ErrnoException) {
            throw IOException("INSTALLER_DEVICE_IO_FAILED", error)
        }
        try {
            verifyIdentity(fd)
            return action(fd)
        } finally {
            Os.close(fd)
        }
    }

    /** Identity + length + canonical-path check, exactly the pre-existing installer discipline. */
    private fun verifyIdentity(fd: FileDescriptor) {
        val stat = Os.fstat(fd)
        val link = Os.stat(partition.path)
        check(OsConstants.S_ISBLK(stat.st_mode) && OsConstants.S_ISBLK(link.st_mode) &&
            stat.st_rdev == identity.deviceNumber && stat.st_ino == identity.inode &&
            stat.st_dev == identity.filesystem && link.st_rdev == stat.st_rdev &&
            link.st_ino == stat.st_ino && link.st_dev == stat.st_dev &&
            File(partition.path).canonicalPath == partition.resolvedPath &&
            Os.lseek(fd, 0, OsConstants.SEEK_END) == partition.size) {
            "INSTALLER_PARTITION_CHANGED"
        }
    }

    private inner class Device(private val access: BlockPartitionAccess) : BlockDeviceTransaction.Device {
        private val fd get() = access.descriptor
        override fun size(): Long = partition.size

        override fun revalidate() = io {
            access.revalidate()
            InstallerPartitionReader.verifyRuntime(snapshot, requireKernel = true)
        }

        override fun read(offset: Long, buffer: ByteArray, length: Int): Int =
            io { Os.pread(fd, buffer, 0, length, offset) }

        override fun write(offset: Long, buffer: ByteArray, start: Int, length: Int): Int =
            io { Os.pwrite(access.writableDescriptor(), buffer, start, length, offset) }

        override fun sync() = io { access.sync() }

        override fun close() = io { access.close() }

        private fun <T> io(action: () -> T): T = try {
            action()
        } catch (error: ErrnoException) {
            throw IOException("INSTALLER_DEVICE_IO_FAILED", error)
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("INSTALLER_CANCELLED", error)
        }
    }
}
