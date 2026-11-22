package dev.maplesu.manager.installer

import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.Closeable
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.channels.OverlappingFileLockException

/**
 * The single cross-process partition-write lock (02-switch-contract §5.5).
 *
 * <p>The writer lock lives outside the SDK cleanup tree. Unlinking an SDK directory must not
 * let a second process lock a new inode while the first writer still owns the old descriptor.
 *
 * <p>Lock order: (1) this file lock, (2) the service's in-process [java.util.concurrent.atomic.AtomicBoolean],
 * (3) the action. Persistent transaction state does not participate in writer exclusion.
 */
internal object InstallerDeviceLock {
    val defaultRoot = File("/data/adb/maplesu/installer")
    private val recoveryRoot = File("/data/local/maplesu-recovery")
    private val borrowed = ThreadLocal<File>()

    internal fun writerLockRoot(recovery: File) = File(recovery, "writer-lock")

    private fun lockRoot(root: File) = if (root.canonicalFile == defaultRoot.canonicalFile)
        writerLockRoot(recoveryRoot) else root

    /** Only the root lease owner calls this while its monitor and kernel lock stay held. */
    internal fun <T> withHeldLease(root: File, action: () -> T): T {
        check(borrowed.get() == null) { "INSTALLER_TRANSACTION_BUSY" }
        borrowed.set(root.canonicalFile)
        try { return action() } finally { borrowed.remove() }
    }

    /**
     * Ensures the private root directories exist, then runs [action] holding install.lock.
     *
     * @throws IOException INSTALLER_STATE_DIRECTORY_INVALID / INSTALLER_TRANSACTION_BUSY
     */
    fun <T> withDeviceLock(root: File = defaultRoot, action: () -> T): T {
        if (borrowed.get() == root.canonicalFile) return action()
        return acquire(root).use { withHeldLease(root, action) }
    }

    /** The root helper retains this same kernel lock across authenticated connections. */
    fun acquire(root: File = defaultRoot): Closeable {
        ensureStateDirectories(root)
        val directory = lockRoot(root)
        if (directory != root) {
            for (folder in listOf(recoveryRoot, directory)) {
                if (!folder.exists()) {
                    check(folder.mkdir()) { "INSTALLER_STATE_DIRECTORY_FAILED" }
                    Os.chmod(folder.path, 0x1c0)
                    syncDirectory(requireNotNull(folder.parentFile))
                }
                requirePrivateDirectory(folder)
            }
        }
        return acquireFile(directory, chmod = true)
    }

    /**
     * Lock-file mechanics only (no device-state directory validation). Host tests exercise this
     * exact method with a temporary directory; the service path above adds the Android checks.
     */
    internal fun <T> withLockFile(root: File, action: () -> T): T =
        acquireLockFile(root).use { action() }

    internal fun acquireLockFile(root: File): Closeable = acquireFile(root, chmod = false)

    /** Persistent journals do not own a writer. Only an open kernel lock excludes one. */
    internal fun assertNoActiveWriter(root: File) {
        if (borrowed.get() == root.canonicalFile) return
        if (root.canonicalFile == defaultRoot.canonicalFile) acquire(root).use { }
        else acquireLockFile(root).use { }
    }

    internal fun syncStateDirectory(directory: File) = syncDirectory(directory)

    private fun acquireFile(root: File, chmod: Boolean): Closeable {
        check(root.isDirectory || root.mkdirs()) { "INSTALLER_STATE_DIRECTORY_FAILED" }
        val lock = RandomAccessFile(File(root, "install.lock"), "rw")
        try {
            if (chmod) Os.fchmod(lock.fd, 0x180) // 0600 lock file, same as the boot-install path
            val held = lock.channel.tryLock() ?: throw IOException("INSTALLER_TRANSACTION_BUSY")
            return Closeable {
                try { held.release() } finally { lock.close() }
            }
        } catch (overlapping: OverlappingFileLockException) {
            lock.close()
            throw IOException("INSTALLER_TRANSACTION_BUSY", overlapping)
        } catch (error: Exception) {
            lock.close()
            throw error
        }
    }

    private fun ensureStateDirectories(root: File) {
        val adb = File("/data/adb")
        val adbStat = Os.lstat(adb.path)
        check(OsConstants.S_ISDIR(adbStat.st_mode) && adbStat.st_uid == 0 &&
            adbStat.st_mode and 0x12 == 0) { "INSTALLER_STATE_DIRECTORY_INVALID" }
        for (directory in listOf(File(adb, "maplesu"), root)) {
            if (!directory.exists()) {
                check(directory.mkdir()) { "INSTALLER_STATE_DIRECTORY_FAILED" }
                Os.chmod(directory.path, 0x1c0)
                syncDirectory(requireNotNull(directory.parentFile))
            }
            requirePrivateDirectory(directory)
        }
    }

    private fun requirePrivateDirectory(directory: File) {
        val stat = Os.lstat(directory.path)
        check(OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid == 0 && stat.st_mode and 0x3f == 0) {
            "INSTALLER_STATE_DIRECTORY_INVALID"
        }
    }

    private fun syncDirectory(directory: File) {
        val fd = Os.open(directory.path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or
            OsConstants.O_NOFOLLOW, 0)
        try {
            check(OsConstants.S_ISDIR(Os.fstat(fd).st_mode)) { "INSTALLER_STATE_DIRECTORY_INVALID" }
            Os.fsync(fd)
        } finally {
            Os.close(fd)
        }
    }
}
