package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageRecovery
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption
import java.security.MessageDigest

/** Host-only recovery data. It does not change the SDK request or the legacy inverse format. */
internal object UltraKernelRecoveryEnvelope {
    private val magic = byteArrayOf(77, 83, 85, 69, 78, 86, 0, 0)
    private const val HEADER_BYTES = 136
    const val MAX_BYTES = 192L * 1024 * 1024
    private const val MAX_SNAPSHOT_BYTES = 64L * 1024 * 1024
    private const val MAX_COMPONENT_BYTES = 128L * 1024 * 1024

    class CapacityException : IOException("ULTRA_KERNEL_RECOVERY_ENVELOPE_CAPACITY_LIMIT")

    class Payload internal constructor(
        val inverse: ByteArray,
        val snapshot: File?,
        val originalComponent: File?,
        private val directory: File? = null,
    ) : Closeable {
        override fun close() = cleanup(directory, originalComponent, snapshot)
    }

    fun write(inverse: ByteArray, snapshot: File, component: ByteArray?, workspace: File): File {
        val inverseBytes = inverse.clone()
        val decoded = UltraKernelRecoveryRecord.decode(inverseBytes)
        val metadata = BootImageRecovery.read(snapshot)
        val snapshotBytes = size(snapshot, MAX_SNAPSHOT_BYTES)
        val componentBytes = component?.size?.toLong() ?: 0
        check(metadata.target == BootImageRecovery.Component.KERNEL && componentBytes <= MAX_COMPONENT_BYTES &&
            (if (component == null) metadata.targetComponentBytes == decoded.kernelBytes.toLong()
            else componentBytes == metadata.targetComponentBytes && sha(component) == metadata.targetComponentSha256)) {
            "ULTRA_KERNEL_RECOVERY_COMPONENT_MISMATCH"
        }
        val total = HEADER_BYTES + inverseBytes.size.toLong() + snapshotBytes + componentBytes + 32
        if (total > MAX_BYTES) throw CapacityException()
        val snapshotSha = sha(snapshot)
        check(metadata.snapshotBytes == snapshotBytes && metadata.snapshotSha256 == snapshotSha) {
            "ULTRA_KERNEL_RECOVERY_ENVELOPE_SOURCE_CHANGED"
        }
        val header = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.LITTLE_ENDIAN).apply {
            put(magic).putInt(1).putInt(HEADER_BYTES)
            putLong(inverseBytes.size.toLong()).putLong(snapshotBytes).putLong(componentBytes)
            put(digest(inverseBytes)).put(unhex(snapshotSha)).put(digest(component ?: byteArrayOf()))
        }.array()
        ensureDirectory(workspace)
        val output = File.createTempFile("container-envelope-", ".bin", workspace)
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            FileChannel.open(output.toPath(), StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS).use { channel ->
                val stream = Channels.newOutputStream(channel)
                fun part(bytes: ByteArray, count: Int = bytes.size) {
                    digest.update(bytes, 0, count)
                    stream.write(bytes, 0, count)
                }
                part(header)
                part(inverseBytes)
                Files.newInputStream(snapshot.toPath(), StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { input -> copy(input, snapshotBytes, ::part) }
                if (component != null) {
                    var at = 0
                    while (at < component.size) {
                        cancelled()
                        val count = minOf(64 * 1024, component.size - at)
                        digest.update(component, at, count)
                        stream.write(component, at, count)
                        at += count
                    }
                }
                stream.write(digest.digest())
                channel.force(true)
            }
            check(size(snapshot, MAX_SNAPSHOT_BYTES) == snapshotBytes && sha(snapshot) == snapshotSha) {
                "ULTRA_KERNEL_RECOVERY_ENVELOPE_SOURCE_CHANGED"
            }
            read(output, workspace).use { verified ->
                check(verified.snapshot != null && verified.inverse.contentEquals(inverseBytes)) {
                    "ULTRA_KERNEL_RECOVERY_ENVELOPE_READBACK"
                }
            }
            return output
        } catch (error: Throwable) {
            try { cleanup(null, output) } catch (cleanupError: Throwable) { error.addSuppressed(cleanupError) }
            throw error
        }
    }

    /** Returns legacy data unchanged, or validated sections from one owned temporary directory. */
    fun read(record: File, workspace: File): Payload {
        val bytes = size(record, MAX_BYTES)
        var owned: Payload? = null
        try { Files.newInputStream(record.toPath(), StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { input ->
            val first = exact(input, 8)
            if (!first.contentEquals(magic)) {
                check(bytes <= UltraKernelRecoveryRecord.MAX_BYTES) { "ULTRA_KERNEL_RECOVERY_RECORD_SIZE" }
                val legacy = first + exact(input, (bytes - 8).toInt())
                check(input.read() == -1 && size(record, MAX_BYTES) == bytes && sha(record) == sha(legacy)) {
                    "ULTRA_KERNEL_RECOVERY_ENVELOPE_SOURCE_CHANGED"
                }
                UltraKernelRecoveryRecord.decode(legacy)
                return Payload(legacy, null, null)
            }
            check(bytes >= HEADER_BYTES + 32) { "ULTRA_KERNEL_RECOVERY_ENVELOPE_TRUNCATED" }
            val header = first + exact(input, HEADER_BYTES - 8)
            val fields = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN).apply { position(8) }
            check(fields.int == 1 && fields.int == HEADER_BYTES) { "ULTRA_KERNEL_RECOVERY_ENVELOPE_FORMAT" }
            val inverseBytes = fields.long
            val snapshotBytes = fields.long
            val componentBytes = fields.long
            check(inverseBytes in 1..UltraKernelRecoveryRecord.MAX_BYTES.toLong() &&
                snapshotBytes in 1..MAX_SNAPSHOT_BYTES && componentBytes in 0..MAX_COMPONENT_BYTES &&
                HEADER_BYTES + inverseBytes + snapshotBytes + componentBytes + 32 == bytes) {
                "ULTRA_KERNEL_RECOVERY_ENVELOPE_LENGTH"
            }
            val expected = List(3) { ByteArray(32).also(fields::get) }
            ensureDirectory(workspace)
            val directory = Files.createTempDirectory(workspace.toPath(), "container-read-").toFile()
            val snapshot = File(directory, "snapshot.bin")
            val component = if (componentBytes > 0) File(directory, "component.bin") else null
            try {
                val checksum = MessageDigest.getInstance("SHA-256").apply { update(header) }
                val recordHash = MessageDigest.getInstance("SHA-256").apply { update(header) }
                val inverse = exact(input, inverseBytes.toInt())
                checksum.update(inverse)
                recordHash.update(inverse)
                check(MessageDigest.isEqual(digest(inverse), expected[0])) {
                    "ULTRA_KERNEL_RECOVERY_ENVELOPE_CHECKSUM"
                }
                val decoded = UltraKernelRecoveryRecord.decode(inverse)
                fun section(file: File?, length: Long, hash: ByteArray) {
                    val sectionHash = MessageDigest.getInstance("SHA-256")
                    val output = file?.let { FileChannel.open(it.toPath(), StandardOpenOption.CREATE_NEW,
                        StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS) }
                    output.use {
                        copy(input, length, { buffer, count ->
                            checksum.update(buffer, 0, count)
                            recordHash.update(buffer, 0, count)
                            sectionHash.update(buffer, 0, count)
                            if (output != null) {
                                val data = ByteBuffer.wrap(buffer, 0, count)
                                while (data.hasRemaining()) {
                                    cancelled()
                                    if (output.write(data) <= 0) throw IOException("ULTRA_KERNEL_RECOVERY_ENVELOPE_WRITE_FAILED")
                                }
                            }
                        }, checkEnd = false)
                        output?.force(true)
                    }
                    check(MessageDigest.isEqual(sectionHash.digest(), hash)) {
                        "ULTRA_KERNEL_RECOVERY_ENVELOPE_CHECKSUM"
                    }
                }
                section(snapshot, snapshotBytes, expected[1])
                section(component, componentBytes, expected[2])
                val trailer = exact(input, 32)
                recordHash.update(trailer)
                check(MessageDigest.isEqual(checksum.digest(), trailer) && input.read() == -1 &&
                    size(record, MAX_BYTES) == bytes && sha(record) == hex(recordHash.digest())) {
                    "ULTRA_KERNEL_RECOVERY_ENVELOPE_CHECKSUM"
                }
                val metadata = BootImageRecovery.read(snapshot)
                check(metadata.target == BootImageRecovery.Component.KERNEL &&
                    (if (component == null) metadata.targetComponentBytes == decoded.kernelBytes.toLong()
                    else componentBytes == metadata.targetComponentBytes && sha(component) == metadata.targetComponentSha256)) {
                    "ULTRA_KERNEL_RECOVERY_COMPONENT_MISMATCH"
                }
                return Payload(inverse, snapshot, component, directory).also { owned = it }
            } catch (error: Throwable) {
                try { cleanup(directory, component, snapshot) } catch (cleanupError: Throwable) { error.addSuppressed(cleanupError) }
                throw error
            }
        } } catch (error: Throwable) {
            try { owned?.close() } catch (cleanupError: Throwable) { error.addSuppressed(cleanupError) }
            throw error
        }
    }

    private fun copy(input: InputStream, length: Long, write: (ByteArray, Int) -> Unit,
                     checkEnd: Boolean = true) {
        val buffer = ByteArray(64 * 1024)
        var remaining = length
        while (remaining > 0) {
            cancelled()
            val count = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
            if (count <= 0) throw IOException("ULTRA_KERNEL_RECOVERY_ENVELOPE_TRUNCATED")
            write(buffer, count)
            remaining -= count
        }
        if (checkEnd && input.read() != -1) throw IOException("ULTRA_KERNEL_RECOVERY_ENVELOPE_SOURCE_CHANGED")
    }

    private fun exact(input: InputStream, length: Int): ByteArray = ByteArray(length).also { bytes ->
        var at = 0
        while (at < bytes.size) {
            cancelled()
            val count = input.read(bytes, at, bytes.size - at)
            if (count <= 0) throw IOException("ULTRA_KERNEL_RECOVERY_ENVELOPE_TRUNCATED")
            at += count
        }
    }

    private fun size(file: File, maximum: Long): Long {
        val bytes = file.length()
        check(Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS) && bytes in 8..maximum) {
            "ULTRA_KERNEL_RECOVERY_ENVELOPE_SIZE"
        }
        return bytes
    }

    private fun ensureDirectory(directory: File) {
        check(directory.isDirectory || directory.mkdirs()) { "ULTRA_KERNEL_RECOVERY_OUTPUT_CREATE_FAILED" }
    }

    private fun sha(file: File) = MessageDigest.getInstance("SHA-256").let { digest ->
        check(Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS)) { "ULTRA_KERNEL_RECOVERY_ENVELOPE_SIZE" }
        val length = file.length()
        Files.newInputStream(file.toPath(), StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { input ->
            copy(input, length, { bytes, count -> digest.update(bytes, 0, count) })
        }
        hex(digest.digest())
    }
    fun cleanup(directory: File?, vararg files: File?, primary: Throwable? = null) {
        var failure: Throwable? = null
        for (file in files.filterNotNull() + listOfNotNull(directory)) {
            try { Files.deleteIfExists(file.toPath()) } catch (error: Throwable) {
                if (failure == null) failure = error else failure.addSuppressed(error)
            }
        }
        failure?.let {
            if (primary == null) throw it
            if (primary !== it) primary.addSuppressed(it)
        }
    }
    private fun sha(bytes: ByteArray) = hex(digest(bytes))
    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun unhex(value: String) = ByteArray(32) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun cancelled() {
        if (Thread.currentThread().isInterrupted) throw IOException("ULTRA_KERNEL_RECOVERY_CANCELLED")
    }
}
