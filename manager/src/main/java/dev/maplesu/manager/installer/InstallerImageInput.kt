package dev.maplesu.manager.installer

import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileOutputStream

/** Copies one complete regular image without consuming or closing the caller's descriptor. */
internal object InstallerImageInput {
    fun copy(input: ParcelFileDescriptor, destination: File, maximum: Long) {
        val fd = input.fileDescriptor
        val source = Os.fstat(fd)
        check(OsConstants.S_ISREG(source.st_mode) && source.st_size in 1..maximum) {
            "INSTALLER_IMAGE_SIZE_INVALID"
        }
        FileOutputStream(destination).use { output ->
            Os.fchmod(output.fd, 0x180)
            val buffer = ByteArray(64 * 1024)
            var offset = 0L
            while (offset < source.st_size) {
                val requested = minOf(buffer.size.toLong(), source.st_size - offset).toInt()
                val count = Os.pread(fd, buffer, 0, requested, offset)
                check(count in 1..requested) { "INSTALLER_IMAGE_SIZE_INVALID" }
                output.write(buffer, 0, count)
                offset += count
            }
            check(Os.pread(fd, buffer, 0, 1, offset) == 0 && Os.fstat(fd).st_size == source.st_size) {
                "INSTALLER_IMAGE_SIZE_INVALID"
            }
            output.fd.sync()
        }
    }
}
