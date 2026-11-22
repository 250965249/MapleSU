package dev.maplesu.manager.modules

import android.net.Uri
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.R
import com.maplesu.core.ui.util.flashModule
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class UnsupportedModuleAndroidTest {
    @Test fun nativePackageNeverReachesConfirmationOrInstallation() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val source = File.createTempFile("unsupported-native-", ".zip", context.cacheDir)
        try {
            ZipOutputStream(source.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("libmodule.so"))
                zip.write(ModuleCatalogAndroidTest.maplesuElf())
                zip.closeEntry()
            }
            val original = source.readBytes()
            var confirmed = false
            val errors = mutableListOf<String>()
            val result = flashModule(Uri.fromFile(source), {}, errors::add, confirmType = {
                confirmed = true
                ModuleType.KERNELSU
            })
            assertFalse(confirmed)
            assertEquals(1, result.code)
            assertFalse(result.showReboot)
            assertEquals(context.getString(R.string.module_maplesu_not_supported), result.err)
            assertEquals(listOf(result.err), errors)
            assertArrayEquals(original, source.readBytes())
        } finally {
            source.delete()
        }
    }
}
