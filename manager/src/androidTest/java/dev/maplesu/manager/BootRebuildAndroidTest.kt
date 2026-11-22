package dev.maplesu.manager

import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.image.BootImageInspector
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Executes the shared component writer through the production repository at the app UID. */
@RunWith(AndroidJUnit4::class)
class BootRebuildAndroidTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var repository: ImageRepository
    private lateinit var source: File
    private lateinit var kernel: File

    @Before fun setup() {
        File(context.filesDir, "images").deleteRecursively()
        repository = ImageRepository(context)
        source = File.createTempFile("rebuild-source-", ".img", context.cacheDir)
        kernel = File.createTempFile("rebuild-kernel-", ".bin", context.cacheDir)
        source.writeBytes(fixture())
        kernel.writeBytes(ByteArray(8193) { 0x4b })
        repository.import(Uri.fromFile(source))
    }

    @After fun cleanup() {
        Thread.interrupted()
        source.delete()
        kernel.delete()
        File(context.filesDir, "images").deleteRecursively()
    }

    @Test fun componentRebuildMatchesDesktopAndPreservesImportedImage() {
        val original = BootImageInspector.inspect(source).sha256
        var published: File? = null
        val hash = repository.withRebuiltKernel(Uri.fromFile(kernel)) { file, report ->
            published = file
            assertEquals("861eb56eb000412a9f5236857b13f622c3a3107cf232589316d745a273f9d782", report.image.sha256)
            assertEquals(report.image.sha256, BootImageInspector.inspect(file).sha256)
            assertEquals(8193L, report.image.kernelSize)
            assertEquals(16384L, report.image.ramdiskOffset)
            assertArrayEquals(ByteArray(53) { 0x72 }, file.readBytes().copyOfRange(16384, 16437))
            assertFalse(JSONObject(report.toJson()).getBoolean("flashableCandidate"))
            report.image.sha256
        }
        assertEquals(64, hash.length)
        assertFalse(requireNotNull(published).exists())
        assertEquals(original, BootImageInspector.inspect(source).sha256)
        assertEquals(original, repository.restore()!!.report.sha256)
        assertNoWorkFiles()
    }

    @Test fun failedExportDiscardsRebuildAndRetainsSource() {
        val original = repository.restore()!!.report.sha256
        val error = assertThrows(IOException::class.java) {
            repository.withRebuiltKernel(Uri.fromFile(kernel)) { _, _ -> throw IOException("EXPORT_INTERRUPTED") }
        }
        assertEquals("EXPORT_INTERRUPTED", error.message)
        assertEquals(original, repository.restore()!!.report.sha256)
        assertNoWorkFiles()
    }

    @Test fun noncanonicalInputNeverCallsConsumer() {
        val bytes = source.readBytes().apply { this[1584] = 1 }
        source.writeBytes(bytes)
        repository.import(Uri.fromFile(source))
        var invoked = false
        val error = assertThrows(IOException::class.java) {
            repository.withRebuiltKernel(Uri.fromFile(kernel)) { _, _ -> invoked = true }
        }
        assertEquals("NONCANONICAL_BOOT_PADDING", error.message)
        assertFalse(invoked)
        assertArrayEquals(bytes, source.readBytes())
        assertNoWorkFiles()
    }

    @Test fun cancelledRebuildRetainsInterruptAndSource() {
        val original = repository.restore()!!.report.sha256
        Thread.currentThread().interrupt()
        try {
            val error = assertThrows(IOException::class.java) {
                repository.withRebuiltKernel(Uri.fromFile(kernel)) { _, _ -> fail("Cancelled rebuild published") }
            }
            assertEquals("CANCELLED", error.message)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        assertEquals(original, repository.restore()!!.report.sha256)
        assertNoWorkFiles()
    }

    @Test fun restoreRemovesInterruptedComponentWorkFiles() {
        val directory = File(context.filesDir, "images")
        File(directory, "rebuild-interrupted.pending").writeBytes(ByteArray(4096))
        File(directory, "kernel-interrupted.pending").writeBytes(ByteArray(71))
        assertNotNull(ImageRepository(context).restore())
        assertNoWorkFiles()
    }

    private fun assertNoWorkFiles() {
        assertFalse(File(context.filesDir, "images").listFiles()!!.any {
            it.name.endsWith(".pending") || it.name.endsWith(".nonflashable.img")
        })
    }

    private fun fixture(): ByteArray {
        val bytes = ByteArray(12288)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("ANDROID!".toByteArray())
            putInt(8, 71).putInt(12, 53).putInt(16, 0x12345678).putInt(20, 1584).putInt(40, 4)
        }
        "console=ttyS0 test=\"two words\" 枫栖".toByteArray().copyInto(bytes, 44)
        bytes.fill(0x31, 4096, 4167)
        bytes.fill(0x72, 8192, 8245)
        return bytes
    }
}
