package dev.maplesu.manager.patching

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.BootImageRebuilder
import dev.maplesu.image.KernelCompression
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import sun.misc.Unsafe

/** Calls the real private codec seam; native patch execution and Android UI are outside this test. */
class LiteKernelComponentTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun gzipTailSurvivesRealLiteEncodingAndRebuilding() = check("GZIP", true)

    @Test fun untailedGzipRawAndLz4KeepTheirEncodingBehavior() {
        for (format in listOf("GZIP", "RAW_ARM64", "LZ4_LEGACY", "LZ4_FRAME")) check(format, false)
    }

    private fun check(format: String, withTail: Boolean) {
        val directory = temporary.newFolder("$format-$withTail")
        val raw = ByteArray(8192).apply {
            "ARMd".toByteArray().copyInto(this, 56)
            "Linux version 6.6.89-lite-kernel-tail (test)".toByteArray().copyInto(this, 128)
        }
        val tail = if (!withTail) byteArrayOf() else ByteArray(64).apply {
            ByteBuffer.wrap(this).order(ByteOrder.BIG_ENDIAN).putInt(0xd00dfeed.toInt()).putInt(size)
            for (index in 40 until size) this[index] = index.toByte()
        }
        val component = KernelCompression.encode(raw, format) + tail
        val original = ByteArray(4096 + ((component.size + 4095) / 4096) * 4096)
        ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("ANDROID!".toByteArray()); putInt(8, component.size); putInt(20, 1584); putInt(40, 4)
        }
        component.copyInto(original, 4096)
        val source = File(directory, "source.img").apply { writeBytes(original) }
        val report = BootImageInspector.inspect(source)
        // Allocate without Android Context: this seam only uses file/codec methods.
        val unsafe = Unsafe::class.java.getDeclaredField("theUnsafe").apply { isAccessible = true }.get(null) as Unsafe
        val patcher = unsafe.allocateInstance(LiteBootPatcher::class.java)
        val decoder = LiteBootPatcher::class.java.declaredMethods.single { it.name == "decodeIdentity" }
            .apply { isAccessible = true }
        val identity = decoder.invoke(patcher, source, report, null)
        val changed = raw.clone().apply { this[1000] = 42 }
        val patchedRaw = File(directory, "patched.raw").apply { writeBytes(changed) }
        val encoded = File(directory, "kernel.component")
        val encoder = LiteBootPatcher::class.java.declaredMethods.single { it.name == "encodePatchedKernel" }
            .apply { isAccessible = true }
        encoder.invoke(patcher, patchedRaw, encoded, source, report, identity)
        assertArrayEquals("the real Lite codec must preserve the gzip component's appended DTB",
            KernelCompression.encode(changed, format) + tail, encoded.readBytes())
        val candidate = File(directory, "candidate.img")
        val rebuilt = BootImageRebuilder.rebuild(source, encoded, candidate)
        assertEquals(format, rebuilt.image.compression)
        val readback = ByteArray(rebuilt.image.kernelSize.toInt())
        RandomAccessFile(candidate, "r").use { it.seek(rebuilt.image.kernelOffset); it.readFully(readback) }
        assertArrayEquals(encoded.readBytes(), readback)
        assertArrayEquals(changed, KernelCompression.decode(readback, format, KernelCompression.MAX_KERNEL_BYTES))
        assertArrayEquals(original, source.readBytes())
    }
}
