package dev.maplesu.manager

import android.net.Uri
import android.view.WindowManager
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.R
import com.maplesu.core.ui.MainActivity
import com.maplesu.core.ui.util.flashModule
import dev.maplesu.manager.modules.ModuleType
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlinx.coroutines.runBlocking

/** Runs the real package check and Manager install entry; never executes a module script. */
@RunWith(AndroidJUnit4::class)
class ModuleArchiveAndroidTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun zip(file: File, properties: String, extraName: String = "service.sh", extra: String = "exit 0") {
        ZipOutputStream(file.outputStream()).use { archive ->
            for ((name, value) in listOf("module.prop" to properties, extraName to extra)) {
                archive.putNextEntry(ZipEntry(name))
                archive.write(value.toByteArray(Charsets.UTF_8))
                archive.closeEntry()
            }
        }
    }

    @Test fun packagePreflightAndInstallFailurePreserveSourceAndExecuteNothing() {
        ActivityScenario.launch(MainActivity::class.java).use { foreground ->
            foreground.onActivity { it.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) }
            val directory = File(context.cacheDir, "module-preflight-${System.nanoTime()}")
            assertTrue(directory.mkdir())
            try {
                val marker = File(directory, "script-must-not-execute")
                val input = File(directory, "demo.zip")
                zip(input, "id=maple_demo\nname=枫栖示例\nversionCode=12\n", extra = "touch '${marker.absolutePath}'")
                val original = input.readBytes()
                val report = ModuleArchiveInspector.inspect(input)
                assertEquals("maple_demo", report.id)
                assertEquals("枫栖示例", report.properties["name"])
                assertEquals(setOf(ModuleArchiveInspector.Feature.SCRIPT), report.features)
                val output = mutableListOf<String>()
                val errors = mutableListOf<String>()
                val cachedBefore = context.cacheDir.list()!!.filter { it.startsWith("module-") }.toSet()
                val result = runBlocking {
                    flashModule(Uri.fromFile(input), output::add, errors::add, confirmType = { confirmation ->
                        assertEquals(ModuleType.KERNELSU, confirmation.evidence.type)
                        ModuleType.KERNELSU
                    })
                }
                assertNotEquals(0, result.code)
                assertFalse(result.showReboot)
                assertEquals(listOf(context.getString(R.string.module_archive_checking),
                    context.getString(R.string.module_archive_checked)), output)
                assertEquals(context.getString(R.string.root_install_required), result.err)
                assertTrue((output + errors).none { it.contains("MAPLESU_") || it.contains("MAPLESU_") || it.contains("features=") })
                assertArrayEquals(original, input.readBytes())
                assertFalse(marker.exists())
                assertEquals(cachedBefore, context.cacheDir.list()!!.filter { it.startsWith("module-") }.toSet())

                zip(input, "id=maple_demo\nid=other_demo\n")
                output.clear(); errors.clear()
                val invalid = runBlocking { flashModule(Uri.fromFile(input), output::add, errors::add) }
                assertEquals(1, invalid.code)
                assertFalse(invalid.showReboot)
                assertEquals(listOf(context.getString(R.string.module_archive_checking)), output)
                assertEquals(listOf(context.getString(R.string.module_archive_invalid)), errors)
                assertFalse(marker.exists())

                zip(input, "id=maple_demo\n", "../outside", "bad")
                try {
                    ModuleArchiveInspector.inspect(input)
                    fail("Archive traversal was accepted")
                } catch (expected: ModuleArchiveInspector.Failure) {
                    assertEquals("INVALID_ARCHIVE_PATH", expected.code)
                }
                assertFalse(File(directory.parentFile, "outside").exists())
            } finally { directory.deleteRecursively() }
        }
    }

    @Test fun installationRequiresConfirmationAndCancelRunsNoBackend() = runBlocking {
        val input = File.createTempFile("confirm-source-", ".zip", context.cacheDir)
        try {
            zip(input, "id=maple_demo\nname=Demo\n")
            val errors = mutableListOf<String>()
            val missing = flashModule(Uri.fromFile(input), {}, errors::add)
            assertEquals(context.getString(R.string.module_type_confirmation_required), missing.err)
            assertFalse(missing.showReboot)
            var confirmations = 0
            val cancelled = flashModule(Uri.fromFile(input), {}, errors::add, confirmType = { confirmation ->
                assertEquals(ModuleType.KERNELSU, confirmation.evidence.type)
                confirmations++
                null
            })
            assertEquals(1, confirmations)
            assertEquals(context.getString(R.string.module_install_cancelled), cancelled.err)
            assertFalse(cancelled.showReboot)
        } finally { input.delete() }
    }

    @Test fun changedStagedPackageIsRejectedAfterConfirmation() = runBlocking {
        val input = File.createTempFile("confirm-source-", ".zip", context.cacheDir)
        try {
            zip(input, "id=maple_demo\n")
            val existingFiles = context.cacheDir.listFiles()!!.toSet()
            val result = flashModule(Uri.fromFile(input), {}, {}, confirmType = {
                val staged = context.cacheDir.listFiles()!!.single {
                    it !in existingFiles && it.name.startsWith("module-") && it.extension == "zip"
                }
                staged.appendBytes(byteArrayOf(1))
                ModuleType.KERNELSU
            })
            assertEquals(context.getString(R.string.module_archive_invalid), result.err)
            assertFalse(result.showReboot)
        } finally { input.delete() }
    }
}
