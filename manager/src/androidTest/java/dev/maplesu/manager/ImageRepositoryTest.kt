package dev.maplesu.manager

import android.content.ContentProvider
import android.content.ContentResolver
import android.content.ContentValues
import android.content.ContextWrapper
import android.content.pm.ProviderInfo
import android.database.Cursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.view.WindowManager
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.KernelCompression
import com.maplesu.core.ui.MainActivity
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.Assume.assumeTrue
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FilterInputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Runs the production repository/codecs on Android, including failure and restart behavior. */
@RunWith(AndroidJUnit4::class)
class ImageRepositoryTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var repository: ImageRepository
    private lateinit var source: File
    private var foregroundActivity: ActivityScenario<MainActivity>? = null

    @Before fun setup() {
        foregroundActivity = ActivityScenario.launch(MainActivity::class.java).also { scenario ->
            scenario.onActivity { it.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) }
        }
        File(context.filesDir, "images").deleteRecursively()
        repository = ImageRepository(context)
        source = File.createTempFile("test-only-", ".img", context.cacheDir)
        source.writeBytes(fixture())
    }

    @After fun cleanup() {
        Thread.interrupted()
        source.delete()
        File(context.filesDir, "images").deleteRecursively()
        foregroundActivity?.close()
        foregroundActivity = null
    }

    @Test fun importAndRestartPreserveSourceAndIdentity() {
        val hash = BootImageInspector.inspect(source).sha256
        val imported = repository.import(Uri.fromFile(source))
        assertEquals(hash, imported.report.sha256)
        assertEquals(hash, ImageRepository(context).restore()!!.report.sha256)
        assertEquals(hash, BootImageInspector.inspect(source).sha256)
    }

    @Test fun malformedImportRetainsPreviousImage() {
        val imported = repository.import(Uri.fromFile(source))
        source.writeBytes(ByteArray(100))
        try { repository.import(Uri.fromFile(source)); fail("malformed image accepted") }
        catch (expected: BootImageInspector.InvalidImageException) { assertEquals("INVALID_MAGIC", expected.code) }
        assertEquals(imported.report.sha256, repository.restore()!!.report.sha256)
        assertFalse(File(context.filesDir, "images").listFiles()!!.any { it.name.endsWith(".pending") })
    }

    @Test fun installedBootImportChecksSizeAndDigestBeforePublication() {
        val original = repository.import(Uri.fromFile(source))
        for ((size, hash) in listOf(source.length() - 1 to original.report.sha256,
            source.length() + 1 to original.report.sha256, source.length() to "0".repeat(64))) {
            source.inputStream().use { input ->
                val error = assertThrows(IOException::class.java) {
                    repository.importAndVerifyInstalledBoot(input, size, hash, "UNKNOWN")
                }
                assertEquals("INSTALLER_IMAGE_CHANGED", error.message)
            }
            assertEquals(original.report.sha256, repository.restore()!!.report.sha256)
            assertFalse(File(context.filesDir, "images").listFiles()!!.any { it.name.endsWith(".pending") })
        }
        source.inputStream().use { input ->
            val verified = repository.importAndVerifyInstalledBoot(input, source.length(), original.report.sha256, "UNKNOWN")
            assertEquals(original.report.sha256, verified.report.sha256)
            assertEquals(original.report.sha256,
                JSONObject(requireNotNull(verified.roundTripJson)).getJSONObject("image").getString("sha256"))
        }
    }

    @Test fun installedBootDecodeFailureRetainsPreviouslyVerifiedImage() {
        repository.import(Uri.fromFile(source))
        val previous = repository.verify()
        val damaged = fixture()
        // Keep a valid LZ4 magic and container but declare an impossible compressed block.
        ByteBuffer.wrap(damaged).order(ByteOrder.LITTLE_ENDIAN).putInt(4100, Int.MAX_VALUE)
        source.writeBytes(damaged)
        val damagedReport = BootImageInspector.inspect(source)
        assertNotEquals(previous.report.sha256, damagedReport.sha256)
        source.inputStream().use { input ->
            assertThrows(IOException::class.java) {
                repository.importAndVerifyInstalledBoot(input, source.length(), damagedReport.sha256, "UNKNOWN")
            }
        }
        val restored = requireNotNull(ImageRepository(context).restore())
        assertEquals(previous.report.sha256, restored.report.sha256)
        assertEquals(previous.roundTripJson, restored.roundTripJson)
        assertFalse(File(context.filesDir, "images").listFiles()!!.any { it.name.endsWith(".pending") })
    }

    @Test fun installedBootKernelReleaseIsVerifiedBeforePublication() {
        repository.import(Uri.fromFile(source))
        val previous = repository.verify()
        source.writeBytes(fixture("6.6.89-test"))
        val incoming = BootImageInspector.inspect(source)
        source.inputStream().use { input ->
            val error = assertThrows(IOException::class.java) {
                repository.importAndVerifyInstalledBoot(input, source.length(), incoming.sha256, "6.6.66-test")
            }
            assertEquals("INSTALLER_IMAGE_CHANGED", error.message)
        }
        val restored = requireNotNull(ImageRepository(context).restore())
        assertEquals(previous.report.sha256, restored.report.sha256)
        assertEquals(previous.roundTripJson, restored.roundTripJson)
        source.inputStream().use { input ->
            val verified = repository.importAndVerifyInstalledBoot(input, source.length(), incoming.sha256, "6.6.89-test")
            assertEquals(incoming.sha256, verified.report.sha256)
            assertEquals("6.6.89-test", JSONObject(requireNotNull(verified.roundTripJson)).getString("kernelRelease"))
            assertEquals(verified.roundTripJson, ImageRepository(context).restore()!!.roundTripJson)
        }
        assertEquals(incoming.sha256, BootImageInspector.inspect(source).sha256)
        assertFalse(File(context.filesDir, "images").listFiles()!!.any { it.name.endsWith(".pending") })
    }

    @Test fun installedBootImportAndVerificationHoldOneRepositoryOperation() {
        val original = BootImageInspector.inspect(source)
        val opened = CountDownLatch(1)
        val release = CountDownLatch(1)
        val replacementStarted = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val replacement = File.createTempFile("test-replacement-", ".img", context.cacheDir)
        replacement.writeBytes(source.readBytes() + byteArrayOf(1, 2, 3))
        val input = object : FilterInputStream(ByteArrayInputStream(source.readBytes())) {
            private var firstRead = true
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                if (firstRead) {
                    firstRead = false
                    opened.countDown()
                    check(release.await(10, TimeUnit.SECONDS)) { "Installed boot import fixture timed out" }
                }
                return super.read(buffer, offset, length)
            }
        }
        try {
            val installing = pool.submit<ImageResult> {
                input.use { ImageRepository(context).importAndVerifyInstalledBoot(it, source.length(), original.sha256, "UNKNOWN") }
            }
            assertTrue("Installed boot import never read its source", opened.await(5, TimeUnit.SECONDS))
            val replacing = pool.submit<ImageResult> {
                replacementStarted.countDown()
                ImageRepository(context).import(Uri.fromFile(replacement))
            }
            assertTrue(replacementStarted.await(5, TimeUnit.SECONDS))
            assertThrows(TimeoutException::class.java) { replacing.get(200, TimeUnit.MILLISECONDS) }
            release.countDown()
            val verified = installing.get(5, TimeUnit.SECONDS)
            assertEquals(original.sha256, verified.report.sha256)
            assertEquals(original.sha256,
                JSONObject(requireNotNull(verified.roundTripJson)).getJSONObject("image").getString("sha256"))
            val replaced = replacing.get(5, TimeUnit.SECONDS)
            assertNotEquals(original.sha256, replaced.report.sha256)
            val restored = requireNotNull(ImageRepository(context).restore())
            assertEquals(replaced.report.sha256, restored.report.sha256)
            assertNull(restored.roundTripJson)
        } finally {
            release.countDown()
            pool.shutdownNow()
            assertTrue("Installed boot workers did not stop", pool.awaitTermination(5, TimeUnit.SECONDS))
            input.close()
            replacement.delete()
        }
    }

    @Test fun lz4RoundTripAndRestartUseRealResults() {
        val imported = repository.import(Uri.fromFile(source))
        val result = repository.verify()
        val json = JSONObject(result.roundTripJson!!)
        assertEquals("LOSSLESS_ROUNDTRIP", json.getString("operation"))
        assertEquals(5017, json.getInt("decodedKernelSize"))
        assertTrue(json.getBoolean("containerByteIdentical"))
        assertFalse(json.getBoolean("flashableCandidate"))
        assertEquals(imported.report.sha256, result.report.sha256)
        assertEquals(result.roundTripJson, ImageRepository(context).restore()!!.roundTripJson)
        assertFalse(json.toString().contains(source.name))
    }

    @Test fun legacyBootLayoutsImportVerifyAndRestore() {
        val modern = fixture()
        val payloadSize = ByteBuffer.wrap(modern).order(ByteOrder.LITTLE_ENDIAN).getInt(8)
        val payload = modern.copyOfRange(4096, 4096 + payloadSize)
        for (version in 0..2) for (page in listOf(2048, 4096, 8192, 16384)) {
            val ramdisk = (page + payloadSize + page - 1) / page * page
            val second = ramdisk + page
            val dtbo = second + page
            val bytes = ByteArray(dtbo + page * 2 + 177) { 0x5a }
            val header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            header.put("ANDROID!".toByteArray())
            header.putInt(8, payloadSize).putInt(16, 71).putInt(24, 53)
                .putInt(36, page).putInt(40, version)
            if (version >= 1) header.putInt(1632, 31).putLong(1636, dtbo.toLong())
                .putInt(1644, if (version == 1) 1648 else 1660)
            if (version == 2) header.putInt(1648, 19)
            payload.copyInto(bytes, page)
            source.writeBytes(bytes)
            val imported = repository.import(Uri.fromFile(source))
            assertEquals(version, imported.report.headerVersion)
            assertEquals(page.toLong(), imported.report.kernelOffset)
            assertEquals(second.toLong(), imported.report.secondOffset)
            assertEquals(if (version >= 1) dtbo.toLong() else 0L, imported.report.recoveryDtboOffset)
            assertEquals(if (version == 2) (dtbo + page).toLong() else 0L, imported.report.dtbOffset)
            val verified = repository.verify()
            assertEquals(5017, JSONObject(verified.roundTripJson!!).getInt("decodedKernelSize"))
            assertEquals(verified.roundTripJson, ImageRepository(context).restore()!!.roundTripJson)
            assertArrayEquals(bytes, source.readBytes())
        }
    }

    @Test fun cancellationBeforePublicationRetainsPreviousImage() {
        val imported = repository.import(Uri.fromFile(source))
        source.appendBytes(byteArrayOf(1, 2, 3))
        Thread.currentThread().interrupt()
        try { repository.import(Uri.fromFile(source)); fail("cancelled import published") }
        catch (expected: IOException) { assertEquals("CANCELLED", expected.message) }
        finally { Thread.interrupted() }
        assertEquals(imported.report.sha256, repository.restore()!!.report.sha256)
    }

    @Test fun codecCancellationPreservesInputsAndInterruptStatus() {
        val raw = ByteArray(1024) { it.toByte() }
        for (format in listOf("RAW_ARM64", "GZIP", "LZ4_LEGACY")) {
            val encoded = KernelCompression.encode(raw, format)
            val original = encoded.copyOf()
            for (encoding in listOf(true, false)) {
                Thread.currentThread().interrupt()
                try {
                    if (encoding) KernelCompression.encode(raw, format)
                    else KernelCompression.decode(encoded, format, raw.size)
                    fail("$format cancellation ignored; encoding=$encoding")
                } catch (expected: IOException) {
                    assertEquals("CANCELLED", expected.message)
                    assertTrue(Thread.currentThread().isInterrupted)
                } finally {
                    Thread.interrupted()
                }
                assertArrayEquals(original, encoded)
                assertArrayEquals(ByteArray(1024) { it.toByte() }, raw)
            }
        }
    }

    @Test fun noKernelNeverEntersPatchPath() {
        val bytes = fixture()
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(8, 0)
        source.writeBytes(bytes)
        assertEquals(0L, repository.import(Uri.fromFile(source)).report.kernelSize)
        try { repository.verify(); fail("empty kernel accepted") }
        catch (expected: IOException) { assertEquals("NO_KERNEL", expected.message) }
    }

    @Test fun replacementClearsPriorVerification() {
        repository.import(Uri.fromFile(source))
        repository.verify()
        source.appendBytes(byteArrayOf(4, 5, 6))
        repository.import(Uri.fromFile(source))
        assertNull(ImageRepository(context).restore()!!.roundTripJson)
    }

    @Test fun exportContainsActualReportAndNoPrivatePath() {
        repository.import(Uri.fromFile(source))
        val result = repository.verify()
        val destination = File.createTempFile("test-report-", ".json", context.cacheDir)
        try {
            repository.export(Uri.fromFile(destination), result.roundTripJson!!)
            assertEquals(result.report.sha256, JSONObject(destination.readText()).getJSONObject("image").getString("sha256"))
            assertFalse(destination.readText().contains(context.filesDir.path))
        } finally { destination.delete() }
    }

    @Test fun interruptedImportIsDiscardedAfterProcessRestart() {
        repository.import(Uri.fromFile(source))
        val pending = File(context.filesDir, "images/interrupted.pending")
        pending.writeBytes(byteArrayOf(1, 2, 3))
        val restored = ImageRepository(context).restore()!!
        assertEquals(BootImageInspector.inspect(source).sha256, restored.report.sha256)
        assertFalse(pending.exists())
    }

    @Test fun damagedVerificationReportRetainsImportedImage() {
        val imported = repository.import(Uri.fromFile(source))
        File(context.filesDir, "images/roundtrip.json").writeText("{truncated")
        val restored = ImageRepository(context).restore()!!
        assertEquals(imported.report.sha256, restored.report.sha256)
        assertNull(restored.roundTripJson)
    }

    @Test fun incompatibleVerificationReportRetainsImportedImage() {
        val imported = repository.import(Uri.fromFile(source))
        File(context.filesDir, "images/roundtrip.json").writeText("{\"image\":[]}")
        val restored = ImageRepository(context).restore()!!
        assertEquals(imported.report.sha256, restored.report.sha256)
        assertNull(restored.roundTripJson)
    }

    @Test fun unsupportedVerificationSchemaIsNotRestored() {
        repository.import(Uri.fromFile(source))
        val report = JSONObject(repository.verify().roundTripJson!!).put("schemaVersion", 99)
        File(context.filesDir, "images/roundtrip.json").writeText(report.toString())
        assertNull(ImageRepository(context).restore()!!.roundTripJson)
    }

    @Test fun incompleteOrConflictingVerificationIsNotRestored() {
        val imported = repository.import(Uri.fromFile(source))
        val original = repository.verify().roundTripJson!!
        for ((key, value) in listOf("operation" to "PATCHED", "codecRoundTripVerified" to false,
                "containerByteIdentical" to false, "sourceUnchanged" to false, "flashableCandidate" to true,
                "decodedKernelSize" to 0, "decodedKernelSha256" to "truncated", "kernelRelease" to "")) {
            val report = JSONObject(original).put(key, value)
            File(context.filesDir, "images/roundtrip.json").writeText(report.toString())
            val restored = ImageRepository(context).restore()!!
            assertEquals(imported.report.sha256, restored.report.sha256)
            assertNull("Conflicting cached field: $key", restored.roundTripJson)
        }
    }

    @Test fun concurrentRestoreDoesNotDiscardAnActiveImport() {
        val original = repository.import(Uri.fromFile(source))
        source.appendBytes(byteArrayOf(4, 5, 6))
        val opened = CountDownLatch(1)
        val release = CountDownLatch(1)
        val restoreStarted = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(3)
        val provider = object : ContentProvider() {
            override fun onCreate() = true
            override fun getType(uri: Uri) = "application/octet-stream"
            override fun query(uri: Uri, projection: Array<out String>?, selection: String?,
                args: Array<out String>?, sort: String?): Cursor? = null
            override fun insert(uri: Uri, values: ContentValues?): Uri? = null
            override fun delete(uri: Uri, selection: String?, args: Array<out String>?) = 0
            override fun update(uri: Uri, values: ContentValues?, selection: String?, args: Array<out String>?) = 0
            override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
                val pipe = ParcelFileDescriptor.createPipe()
                pool.submit {
                    ParcelFileDescriptor.AutoCloseOutputStream(pipe[1]).use { output ->
                        val bytes = source.readBytes()
                        output.write(bytes, 0, 4096)
                        opened.countDown()
                        check(release.await(10, TimeUnit.SECONDS)) { "Import fixture timed out" }
                        output.write(bytes, 4096, bytes.size - 4096)
                    }
                }
                return pipe[0]
            }
        }
        provider.attachInfo(context, ProviderInfo().apply { authority = "dev.maplesu.test.image" })
        val wrappedContext = object : ContextWrapper(context) {
            override fun getContentResolver(): ContentResolver = ContentResolver.wrap(provider)
        }
        try {
            val importing = pool.submit<ImageResult> {
                ImageRepository(wrappedContext).import(Uri.parse("content://dev.maplesu.test.image/input"))
            }
            assertTrue("Import never opened source", opened.await(5, TimeUnit.SECONDS))
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (File(context.filesDir, "images").listFiles()!!.none {
                    it.name.endsWith(".pending") && it.length() >= 4096 } && System.nanoTime() < deadline) {
                Thread.sleep(5)
            }
            assertTrue("Import never wrote the first chunk", File(context.filesDir, "images").listFiles()!!.any {
                it.name.endsWith(".pending") && it.length() >= 4096 })
            val restoring = pool.submit<ImageResult?> {
                restoreStarted.countDown()
                ImageRepository(context).restore()
            }
            assertTrue(restoreStarted.await(5, TimeUnit.SECONDS))
            // A reader may wait, or return the previous committed snapshot; either is valid.
            try { restoring.get(200, TimeUnit.MILLISECONDS) }
            catch (_: TimeoutException) { /* Import is still active. */ }
            release.countDown()
            val imported = importing.get(5, TimeUnit.SECONDS)
            assertNotEquals(original.report.sha256, imported.report.sha256)
            val restoredHash = restoring.get(5, TimeUnit.SECONDS)!!.report.sha256
            assertTrue(restoredHash == original.report.sha256 || restoredHash == imported.report.sha256)
            assertEquals(imported.report.sha256, ImageRepository(context).restore()!!.report.sha256)
            assertEquals(imported.report.sha256, BootImageInspector.inspect(source).sha256)
        } finally {
            release.countDown()
            pool.shutdownNow()
            assertTrue("Import workers did not stop", pool.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test(timeout = 30_000) fun realOriginalReferenceOnAndroid() = checkReference("original",
        "65b7354f8e8b258f96d73d3701832cdf4141cdb4ec9a9897c08e2c1d28f547e3")

    @Test(timeout = 30_000) fun realPatchedReferenceOnAndroid() = checkReference("patched",
        "3a1c906b42db49fca72f4a36a69c92257a67f678d73561d0a11eab3b084475cc")

    private fun checkReference(name: String, expectedHash: String) {
        assumeTrue("Reference samples are optional and never bundled",
            InstrumentationRegistry.getArguments().getString("referenceSamples") == "true")
        // Reads only the explicitly staged fixture through the shell test harness.
        val descriptor = InstrumentationRegistry.getInstrumentation().uiAutomation
            .executeShellCommand("cat /data/local/tmp/maplesu-validation-$name.img")
        android.os.ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { input ->
            source.outputStream().use { output -> input.copyTo(output) }
        }
        val before = BootImageInspector.inspect(source).sha256
        assertEquals(expectedHash, before)
        repository.import(Uri.fromFile(source))
        val verified = repository.verify()
        assertEquals(expectedHash, verified.report.sha256)
        assertEquals(36387328, JSONObject(verified.roundTripJson!!).getInt("decodedKernelSize"))
        assertEquals(expectedHash, BootImageInspector.inspect(source).sha256)
        assertEquals(verified.roundTripJson, ImageRepository(context).restore()!!.roundTripJson)
    }

    companion object {
        fun fixture(kernelRelease: String? = null): ByteArray {
            val raw = ByteArray(5017) { (it * 31).toByte() }
            byteArrayOf(65, 82, 77, 100).copyInto(raw, 56)
            if (kernelRelease != null) "Linux version $kernelRelease ".toByteArray().copyInto(raw, 128)
            val payload = KernelCompression.encode(raw, "LZ4_LEGACY")
            val bytes = ByteArray((4096 + payload.size + 4095) / 4096 * 4096 + 177) { 0x5a }
            val header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            header.put("ANDROID!".toByteArray())
            header.putInt(8, payload.size).putInt(12, 0).putInt(20, 1584).putInt(40, 4).putInt(1580, 0)
            payload.copyInto(bytes, 4096)
            return bytes
        }
    }
}
