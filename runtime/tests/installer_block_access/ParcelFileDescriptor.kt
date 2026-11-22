package android.os

import android.system.Os
import java.io.Closeable
import java.io.FileDescriptor

class ParcelFileDescriptor private constructor(private val descriptor: FileDescriptor) : Closeable {
    val fd: Int get() = Os.number(descriptor)
    override fun close() = Os.close(descriptor)
    companion object { fun dup(fd: FileDescriptor) = ParcelFileDescriptor(Os.duplicate(fd)) }
}
