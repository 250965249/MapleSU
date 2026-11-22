package dev.maplesu.manager

import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.R
import com.maplesu.core.ui.util.LkmSelection
import com.maplesu.core.ui.util.downloadBoot
import dev.maplesu.image.BootImageInspector
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.concurrent.thread

@RunWith(AndroidJUnit4::class)
class DownloadedBootAndroidTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test(timeout = 30_000) fun downloadedBootUsesTheLocalImageValidationPath() {
        val image = ImageRepositoryTest.fixture("6.6.89-download-test")
        val archive = ByteArrayOutputStream().apply {
            ZipOutputStream(this).use { zip ->
                zip.putNextEntry(ZipEntry("boot.img"))
                zip.write(image)
                zip.closeEntry()
            }
        }.toByteArray()
        val output = mutableListOf<String>()
        val errors = mutableListOf<String>()
        try {
            serve(archive) { url ->
                val result = downloadBoot(url, "boot", LkmSelection.KmiNone,
                    false, false, false, "", output::add, errors::add)
                assertEquals(78, result.code)
                assertFalse(result.showReboot)
                assertEquals(context.getString(R.string.install_image_patch_failed), result.err)
                assertEquals(listOf(result.err), errors)
            }
            val restored = ImageRepository(context).restore()!!
            assertEquals(java.security.MessageDigest.getInstance("SHA-256").digest(image)
                .joinToString("") { "%02x".format(it) }, restored.report.sha256)
            assertTrue(output.contains(context.getString(R.string.install_image_analyzing)))
            assertTrue(output.contains(context.getString(R.string.install_image_verified)))
            assertFalse(JSONObject(restored.roundTripJson!!).getBoolean("flashableCandidate"))
            assertNoTemporaryDownload()
        } finally {
            File(context.filesDir, "images").deleteRecursively()
        }
    }

    @Test(timeout = 30_000) fun invalidDownloadKeepsThePreviousImageAndRemovesTemporaryFile() {
        val source = File.createTempFile("download-previous-", ".img", context.cacheDir)
        source.writeBytes(ImageRepositoryTest.fixture())
        try {
            ImageRepository(context).import(Uri.fromFile(source))
            val previousHash = BootImageInspector.inspect(source).sha256
            val errors = mutableListOf<String>()
            serve(ByteArray(64)) { url ->
                val result = downloadBoot(url, "boot", LkmSelection.KmiNone,
                    false, false, false, "", {}, errors::add)
                assertEquals(1, result.code)
                assertFalse(result.showReboot)
                assertEquals(context.getString(R.string.install_image_invalid), result.err)
                assertEquals(listOf(result.err), errors)
            }
            assertEquals(previousHash, ImageRepository(context).restore()!!.report.sha256)
            assertNoTemporaryDownload()
        } finally {
            source.delete()
            File(context.filesDir, "images").deleteRecursively()
        }
    }

    private fun assertNoTemporaryDownload() {
        assertTrue(context.cacheDir.listFiles()!!.none { it.name.startsWith("download-boot-") })
    }

    /** Serve the byte ranges used by the production downloader, without external network access. */
    private fun serve(bytes: ByteArray, action: (String) -> Unit) {
        val server = ServerSocket(0, 0, InetAddress.getByName("127.0.0.1"))
        val failure = AtomicReference<Throwable?>()
        val worker = thread(isDaemon = true, name = "download-boot-fixture") {
            try {
                while (!server.isClosed) server.accept().use { socket ->
                    socket.soTimeout = 5000
                    val reader = socket.getInputStream().bufferedReader(Charsets.US_ASCII)
                    var range: LongRange? = null
                    while (true) {
                        val line = reader.readLine() ?: error("Incomplete HTTP request")
                        if (line.isEmpty()) break
                        if (line.startsWith("Range:", ignoreCase = true)) {
                            val values = line.substringAfter("=").split('-')
                            range = values[0].toLong()..values[1].toLong()
                        }
                    }
                    val requested = requireNotNull(range)
                    val body = bytes.copyOfRange(requested.first.toInt(), requested.last.toInt() + 1)
                    socket.getOutputStream().apply {
                        write(("HTTP/1.1 206 Partial Content\r\nContent-Length: ${body.size}\r\n" +
                            "Content-Range: bytes ${requested.first}-${requested.last}/${bytes.size}\r\n" +
                            "Connection: close\r\n\r\n").toByteArray(Charsets.US_ASCII))
                        write(body)
                        flush()
                    }
                }
            } catch (error: Throwable) {
                if (!server.isClosed) failure.set(error)
            }
        }
        try {
            action("http://127.0.0.1:${server.localPort}/factory.zip")
        } finally {
            server.close()
            worker.join(6000)
            assertFalse("Fixture server did not stop", worker.isAlive)
            failure.get()?.let { throw AssertionError("Fixture server failed", it) }
        }
    }
}
