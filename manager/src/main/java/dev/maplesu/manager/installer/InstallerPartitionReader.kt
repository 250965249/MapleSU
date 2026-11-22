package dev.maplesu.manager.installer

import android.os.Bundle
import android.os.Process
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructStat
import java.io.Closeable
import java.io.File
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/** Hold all allowlisted devices read-only throughout both observations. Never exports a device FD. */
internal object InstallerPartitionReader {
    fun observe(): Bundle = observe(null)

    fun observeSigning(names: Set<String>): Bundle = observe(null, names)

    internal fun verifyRuntime(snapshot: InstallerSnapshot, requireKernel: Boolean) {
        // SELinux is not compared here: it is a recorded fact, never a reason to stop a write.
        check(readProperty("ro.boot.slot_suffix") == snapshot.slotSuffix &&
            readProperty("ro.build.display.id") == snapshot.firmware &&
            (!requireKernel || Os.uname().release == snapshot.kernelRelease)) { "INSTALLER_DEVICE_CHANGED" }
    }

    fun openBootImage(directory: File): Pair<Bundle, ParcelFileDescriptor> = openPartitionImage(directory, "boot")

    fun openPartitionImage(directory: File, partition: String): Pair<Bundle, ParcelFileDescriptor> {
        require(partition in InstallPartition.ALLOWED_WIRE) { "INSTALLER_PARTITION_INVALID" }
        var image: ParcelFileDescriptor? = null
        try {
            val snapshot = observe(copyBoot = { boot, sha256 -> image = boot.copyReadOnly(directory, sha256) },
                copyPartition = partition)
            return snapshot to requireNotNull(image)
        } catch (error: Throwable) {
            image?.close()
            throw error
        }
    }

    /** Last-resort source only. The active slot and its PRE remain the write/rollback target. */
    internal fun captureAlternate(snapshot: InstallerSnapshot, directory: File): AlternateSlotImages? {
        check(Process.myUid() == 0) { "INSTALLER_ROOT_REQUIRED" }
        val slot = when (snapshot.slotSuffix) { "_a" -> "_b"; "_b" -> "_a"; else -> return null }
        verifyRuntime(snapshot, requireKernel = true)
        check(directory.mkdirs()) { "INSTALLER_SNAPSHOT_WRITE_FAILED" }
        Os.chmod(directory.path, 0x1c0)
        val handles = linkedMapOf<String, PartitionHandle>()
        try {
            for (name in listOf("boot", "init_boot", "vbmeta").filter { it in snapshot.partitions }) {
                try { Os.lstat(InstallerSnapshotParser.partitionPath(name, slot)) }
                catch (error: ErrnoException) { if (error.errno == OsConstants.ENOENT) return null else throw error }
                val handle = PartitionHandle(name, slot)
                handles[name] = handle
                check(handle.size == snapshot.partitions.getValue(name).size &&
                    snapshot.partitions.values.none { it.identity?.deviceNumber == handle.identity.st_rdev } &&
                    handles.filterKeys { it != name }.values.none { it.identity.st_rdev == handle.identity.st_rdev }) {
                    "INSTALLER_STOCK_SLOT_MISMATCH"
                }
            }
            val before = handles.mapValues { it.value.digest() }
            val images = handles.mapValues { (name, handle) ->
                val target = File(directory, "$name.img")
                ParcelFileDescriptor.AutoCloseInputStream(handle.copyReadOnly(directory, before.getValue(name))).use { input ->
                    FileOutputStream(target).use { output ->
                        Os.fchmod(output.fd, 0x180)
                        val digest = MessageDigest.getInstance("SHA-256")
                        val buffer = ByteArray(64 * 1024)
                        var length = 0L
                        while (true) {
                            check(!Thread.currentThread().isInterrupted) { "INSTALLER_CANCELLED" }
                            val count = input.read(buffer)
                            if (count < 0) break
                            check(count > 0 && count <= handle.size - length) { "INSTALLER_PARTITION_CHANGED" }
                            output.write(buffer, 0, count); digest.update(buffer, 0, count); length += count
                        }
                        check(length == handle.size && digest.digest().joinToString("") { "%02x".format(it) } ==
                            before.getValue(name)) { "INSTALLER_PARTITION_CHANGED" }
                        output.fd.sync()
                    }
                }
                target
            }
            handles.forEach { (name, handle) ->
                handle.revalidate()
                check(handle.digest() == before.getValue(name)) { "INSTALLER_PARTITION_CHANGED" }
                handle.revalidate()
            }
            verifyRuntime(snapshot, requireKernel = true)
            return AlternateSlotImages(slot, images)
        } finally { handles.values.forEach { it.close() } }
    }

    private fun observe(copyBoot: ((PartitionHandle, String) -> Unit)?, signingNames: Set<String> = emptySet(),
                        copyPartition: String = "boot"): Bundle {
        check(Process.myUid() == 0) { "INSTALLER_ROOT_REQUIRED" }
        val slot = InstallerSnapshotParser.slot(readProperty("ro.boot.slot_suffix"))
        val kernel = Os.uname().release
        val firmware = readProperty("ro.build.display.id")
        // Observation only (2026-11-01): the SELinux status is recorded as evidence, never a gate.
        val selinux = selinuxStatus()
        val handles = linkedMapOf<String, PartitionHandle>()
        try {
            for (name in InstallerSnapshotParser.partitionNames) {
                if (name in setOf("recovery", "vbmeta_system") && name !in signingNames) continue
                val path = InstallerSnapshotParser.partitionPath(name, slot)
                val exists = try { Os.lstat(path); true } catch (error: ErrnoException) {
                    if (error.errno == OsConstants.ENOENT && name in setOf("init_boot", "vendor_boot")) false else throw error
                }
                if (exists) handles[name] = PartitionHandle(name, slot)
            }
            check(handles.values.map { it.identity.st_rdev }.toSet().size == handles.size) {
                "INSTALLER_PARTITION_ALIASED"
            }
            val before = handles.mapValues { it.value.digest() }
            copyBoot?.invoke(handles[copyPartition] ?: error("INSTALLER_PARTITION_INVALID"), before.getValue(copyPartition))
            for ((name, handle) in handles) {
                handle.revalidate()
                check(handle.digest() == before.getValue(name)) { "INSTALLER_PARTITION_CHANGED" }
                handle.revalidate()
            }
            check(readProperty("ro.boot.slot_suffix") == slot && Os.uname().release == kernel &&
                readProperty("ro.build.display.id") == firmware) {
                "INSTALLER_DEVICE_CHANGED"
            }
            return Bundle().apply {
                putInt("serviceUid", Process.myUid())
                putInt("servicePid", Process.myPid())
                putString("kernelRelease", kernel)
                putString("firmware", firmware)
                putString("slotSuffix", slot)
                putString("selinux", selinux)
                putStringArrayList("partitions", ArrayList(handles.keys))
                for ((name, handle) in handles) putBundle(name, Bundle().apply {
                    putString("resolvedPath", handle.resolved)
                    putLong("size", handle.size)
                    putString("sha256", before.getValue(name))
                    putLong("deviceNumber", handle.identity.st_rdev)
                    putLong("inode", handle.identity.st_ino)
                    putLong("filesystem", handle.identity.st_dev)
                })
            }
        } finally {
            handles.values.forEach { it.close() }
        }
    }

    private fun readProperty(name: String): String {
        val process = ProcessBuilder("/system/bin/getprop", name).redirectErrorStream(true).start()
        try {
            check(process.waitFor(5, TimeUnit.SECONDS)) { "INSTALLER_PROPERTY_TIMEOUT" }
            val output = process.inputStream.bufferedReader().use { it.readText().trim() }
            check(process.exitValue() == 0) { "INSTALLER_PROPERTY_FAILED" }
            return output
        } finally {
            process.destroy()
        }
    }

    /**
     * The live SELinux status, read only to be recorded. "Unknown" when `/sys/fs/selinux/enforce`
     * cannot be read (an Ultra kernel may hide it); every value is accepted — writing a block device
     * does not depend on it.
     */
    private fun selinuxStatus(): String =
        when (runCatching { File("/sys/fs/selinux/enforce").readText().trim() }.getOrNull()) {
            "1" -> "Enforcing"
            "0" -> "Permissive"
            null -> "Unknown"
            else -> "Unknown"
        }

    private class PartitionHandle(name: String, slot: String) : Closeable {
        private val path = InstallerSnapshotParser.partitionPath(name, slot)
        val resolved = File(path).canonicalPath
        private val fd: FileDescriptor
        val identity: StructStat
        val size: Long

        init {
            // Validate the canonical path before opening; O_NOFOLLOW rejects a last-component race.
            InstallerSnapshotParser.partition(name, slot, resolved, "1", "${"0".repeat(64)}  $path")
            fd = Os.open(resolved, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
            try {
                identity = Os.fstat(fd)
                check(OsConstants.S_ISBLK(identity.st_mode)) { "INSTALLER_BLOCK_DEVICE_REQUIRED" }
                size = Os.lseek(fd, 0, OsConstants.SEEK_END)
                check(size in 1..InstallerSnapshotParser.maxPartitionBytes) { "INSTALLER_DEVICE_SIZE_INVALID" }
                revalidate()
            } catch (error: Throwable) {
                Os.close(fd)
                throw error
            }
        }

        fun revalidate() {
            check(File(path).canonicalPath == resolved && sameDevice(Os.stat(path)) &&
                sameDevice(Os.fstat(fd)) && Os.lseek(fd, 0, OsConstants.SEEK_END) == size) {
                "INSTALLER_PARTITION_CHANGED"
            }
        }

        private fun sameDevice(other: StructStat) = OsConstants.S_ISBLK(other.st_mode) &&
            identity.st_rdev == other.st_rdev && identity.st_dev == other.st_dev && identity.st_ino == other.st_ino

        fun digest(): String {
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(64 * 1024)
            var offset = 0L
            while (offset < size) {
                check(!Thread.currentThread().isInterrupted) { "INSTALLER_CANCELLED" }
                val count = Os.pread(fd, buffer, 0, minOf(buffer.size.toLong(), size - offset).toInt(), offset)
                check(count > 0) { "INSTALLER_DEVICE_READ_FAILED" }
                digest.update(buffer, 0, count)
                offset += count
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }

        fun copyReadOnly(directory: File, expectedSha256: String): ParcelFileDescriptor {
            val temporary = File.createTempFile("maplesu-boot-", ".tmp", directory)
            try {
                val output = Os.open(temporary.path, OsConstants.O_WRONLY or OsConstants.O_CLOEXEC or
                    OsConstants.O_NOFOLLOW, 0)
                try {
                    val created = Os.fstat(output)
                    check(OsConstants.S_ISREG(created.st_mode) && created.st_uid == 0 &&
                        created.st_nlink == 1L && created.st_size == 0L) { "INSTALLER_SNAPSHOT_INVALID" }
                    Os.fchmod(output, 0x180) // 0600 before writing any image bytes.
                    val digest = MessageDigest.getInstance("SHA-256")
                    val buffer = ByteArray(64 * 1024)
                    var offset = 0L
                    while (offset < size) {
                        check(!Thread.currentThread().isInterrupted) { "INSTALLER_CANCELLED" }
                        val count = Os.pread(fd, buffer, 0, minOf(buffer.size.toLong(), size - offset).toInt(), offset)
                        check(count > 0) { "INSTALLER_DEVICE_READ_FAILED" }
                        digest.update(buffer, 0, count)
                        var written = 0
                        while (written < count) {
                            val bytes = Os.write(output, buffer, written, count - written)
                            check(bytes > 0) { "INSTALLER_SNAPSHOT_WRITE_FAILED" }
                            written += bytes
                        }
                        offset += count
                    }
                    check(digest.digest().joinToString("") { "%02x".format(it) } == expectedSha256) {
                        "INSTALLER_PARTITION_CHANGED"
                    }
                    Os.fsync(output)
                    val result = ParcelFileDescriptor.open(temporary, ParcelFileDescriptor.MODE_READ_ONLY)
                    try {
                        val actual = Os.fstat(result.fileDescriptor)
                        check(OsConstants.S_ISREG(actual.st_mode) && actual.st_ino == created.st_ino &&
                            actual.st_dev == created.st_dev && actual.st_size == size) { "INSTALLER_SNAPSHOT_INVALID" }
                        check(temporary.delete()) { "INSTALLER_SNAPSHOT_CLEANUP_FAILED" }
                        return result
                    } catch (error: Throwable) {
                        result.close()
                        throw error
                    }
                } finally {
                    Os.close(output)
                }
            } finally {
                temporary.delete()
            }
        }

        override fun close() = Os.close(fd)
    }
}
