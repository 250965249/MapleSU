package android.system

import java.io.FileDescriptor
import java.util.IdentityHashMap

class ErrnoException(val functionName: String, val errno: Int) : Exception("$functionName errno=$errno")
class StructStat(val st_mode: Int = 0x6000, val st_rdev: Long = 5, val st_ino: Long = 7, val st_dev: Long = 9)
object OsConstants {
    const val O_RDONLY = 0; const val O_WRONLY = 1; const val O_RDWR = 2; const val O_ACCMODE = 3
    const val O_CLOEXEC = 0x80000; const val O_NOFOLLOW = 0x20000
    const val EROFS = 30; const val EACCES = 13; const val EPERM = 1; const val EIO = 5; const val EBADF = 9
    const val ENOTTY = 25; const val SEEK_END = 2
    fun S_ISBLK(mode: Int) = mode == 0x6000
}
object Os {
    data class Handle(val number: Int, val mode: Int) {
        val readable get() = mode != OsConstants.O_WRONLY
        val writable get() = mode != OsConstants.O_RDONLY
    }
    val descriptors = IdentityHashMap<FileDescriptor, Handle>()
    var bytes = ByteArray(0)
    var readOnly = 0
    var driverLocked = false
    var sets = 0
    var writes = 0
    var failWriteAt = -1
    var denyWriteOpen = false
    var denyReadWriteOpen = false
    var lockOnWriteOpen = false
    var requireWritableControl = false
    var writeControlError = 0
    var writeIdentityChanged = false
    var syncs = 0
    var failSyncAt = -1
    var queryError = 0
    var setError = 0
    private var nextFd = 10
    fun reset(flag: Int, locked: Boolean) {
        check(descriptors.isEmpty()) { "leaked partition descriptors" }
        bytes = ByteArray(131072) { 3 }; readOnly = flag; driverLocked = locked
        sets = 0; writes = 0; failWriteAt = -1; denyWriteOpen = false; queryError = 0; setError = 0
        denyReadWriteOpen = false; lockOnWriteOpen = false; requireWritableControl = false
        writeControlError = 0; writeIdentityChanged = false; syncs = 0; failSyncAt = -1
    }
    fun open(path: String, flags: Int, mode: Int): FileDescriptor {
        check(path.isNotEmpty() && mode == 0)
        val accessMode = flags and OsConstants.O_ACCMODE
        val write = accessMode != OsConstants.O_RDONLY
        if (write && readOnly == 1) throw ErrnoException("open", OsConstants.EROFS)
        if (write && denyWriteOpen) throw ErrnoException("open", OsConstants.EACCES)
        if (accessMode == OsConstants.O_RDWR && denyReadWriteOpen) throw ErrnoException("open", OsConstants.EACCES)
        if (write && lockOnWriteOpen) driverLocked = true
        return FileDescriptor().also { descriptors[it] = Handle(nextFd++, accessMode) }
    }
    fun duplicate(fd: FileDescriptor): FileDescriptor = FileDescriptor().also {
        descriptors[it] = Handle(nextFd++, requireNotNull(descriptors[fd]).mode)
    }
    fun number(fd: FileDescriptor) = requireNotNull(descriptors[fd]).number
    fun close(fd: FileDescriptor) { check(descriptors.remove(fd) != null) { "double close" } }
    fun fstat(fd: FileDescriptor): StructStat {
        val handle = requireNotNull(descriptors[fd])
        return StructStat(st_ino = if (writeIdentityChanged && handle.writable) 8 else 7)
    }
    fun stat(path: String): StructStat { check(path.isNotEmpty()); return StructStat() }
    fun lseek(fd: FileDescriptor, offset: Long, whence: Int): Long {
        check(fd in descriptors && offset == 0L && whence == OsConstants.SEEK_END); return bytes.size.toLong()
    }
    fun pread(fd: FileDescriptor, output: ByteArray, start: Int, length: Int, offset: Long): Int {
        if (descriptors[fd]?.readable != true) throw ErrnoException("pread", OsConstants.EBADF)
        val count = minOf(length, bytes.size - offset.toInt())
        bytes.copyInto(output, start, offset.toInt(), offset.toInt() + count); return count
    }
    fun pwrite(fd: FileDescriptor, input: ByteArray, start: Int, length: Int, offset: Long): Int {
        if (descriptors[fd]?.writable != true) throw ErrnoException("pwrite", OsConstants.EBADF)
        if (readOnly != 0 || driverLocked) throw ErrnoException("pwrite", OsConstants.EPERM)
        writes++
        if (writes == failWriteAt) throw ErrnoException("pwrite", OsConstants.EIO)
        val count = minOf(length, 16384) // Real transaction must also handle short writes.
        input.copyInto(bytes, offset.toInt(), start, start + count); return count
    }
    fun fsync(fd: FileDescriptor) {
        val handle = requireNotNull(descriptors[fd])
        check(writes == 0 || handle.writable) { "written partition must be synced through its write handle" }
        syncs++
        if (syncs == failSyncAt) throw ErrnoException("fsync", OsConstants.EIO)
    }
    fun control(number: Int, desired: Int): Int {
        val handle = descriptors.values.single { it.number == number }
        if (queryError != 0) return -queryError
        if (desired < 0) return readOnly
        if (requireWritableControl && !handle.writable) return -OsConstants.EBADF
        if (handle.writable && writeControlError != 0) return -writeControlError
        if (setError != 0) return -setError
        sets++; readOnly = desired; driverLocked = desired != 0
        return readOnly
    }
}
