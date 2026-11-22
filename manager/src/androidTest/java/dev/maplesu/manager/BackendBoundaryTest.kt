package dev.maplesu.manager

import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import com.maplesu.core.R
import com.maplesu.core.data.repository.ModuleRepositoryImpl
import com.maplesu.core.ui.util.LkmSelection
import com.maplesu.core.ui.util.downloadBoot
import com.maplesu.core.ui.util.getRootShell
import com.maplesu.core.ui.util.installBoot
import com.maplesu.core.ui.util.rootAvailable
import dev.maplesu.image.BootImageInspector
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** A copied UI must not acquire another provider's root or report unsupported work as success. */
@RunWith(AndroidJUnit4::class)
class BackendBoundaryTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun missingRuntimeDoesNotMasqueradeAsKernelSU() {
        assertFalse(Natives.isManager)
        assertFalse(Natives.isFullFeatured())
        assertFalse(rootAvailable())
        assertEquals(-1, Natives.version)
        assertEquals(-1, Natives.kernelUAPIVersion)
        assertEquals(-1, Natives.stealthState())
        assertFalse(Natives.setSelinuxHideEnabled(true) == 0)
        val uid = android.os.Process.myUid()
        val profile = requireNotNull(Natives.getAppProfile(context.packageName, uid))
        assertEquals(context.packageName, profile.name)
        assertEquals(uid, profile.currentUid)
        assertFalse(Natives.setAppProfile(profile.copy(allowSu = true)))
    }

    @Test fun unavailableCommandChannelExecutesNothing() {
        val marker = File(context.cacheDir, "backend-must-not-execute")
        marker.delete()
        try {
            val result = getRootShell().newJob().add("touch '${marker.absolutePath}'").exec()
            assertFalse(result.isSuccess)
            assertTrue(result.err.contains(context.getString(R.string.root_install_required)))
            assertTrue(result.err.none { it.contains("MAPLESU_") || it.contains("MAPLESU_") })
            assertFalse(marker.exists())
        } finally { marker.delete() }
    }

    @Test fun moduleCatalogIsReadableBeforeRootIsInstalled() = runBlocking {
        val result = ModuleRepositoryImpl().getModules()
        assertTrue(result.isSuccess)
        val catalog = dev.maplesu.manager.modules.ModuleCatalog(File(context.filesDir, "module-catalog"))
        assertEquals(catalog.list().size, result.getOrThrow().size)
    }

    @Test fun directInstallWithInvalidTargetIsRejectedBeforeAnyPartitionOperation() {
        val output = mutableListOf<String>()
        val result = installBoot(null, LkmSelection.KmiNone, false, "vendor_boot", false, false, false, "", output::add, {})
        assertEquals(78, result.code)
        assertFalse(result.showReboot)
        assertTrue(output.isEmpty())
        assertEquals(context.getString(R.string.install_partition_read_failed), result.err)
    }

    @Test fun kernelSuLkmInputIsRejectedBeforeReadingIt() {
        val result = installBoot(Uri.parse("content://missing/boot.img"), LkmSelection.KmiString("android15-6.6"),
            false, null, false, false, false, "", {}, {})
        assertEquals(78, result.code)
        assertFalse(result.showReboot)
    }

    @Test fun downloadedKernelSuLkmIsRejectedBeforeConnecting() {
        val output = mutableListOf<String>()
        val errors = mutableListOf<String>()
        val result = downloadBoot("http://127.0.0.1:1/must-not-connect.zip", "boot",
            LkmSelection.KmiString("android15-6.6"), false, false, false, "", output::add, errors::add)
        assertEquals(78, result.code)
        assertFalse(result.showReboot)
        assertTrue(output.isEmpty())
        assertEquals(listOf(context.getString(R.string.install_image_required)), errors)
    }

    @Test fun downloadedNonBootPartitionIsRejectedBeforeConnecting() {
        val output = mutableListOf<String>()
        val result = downloadBoot("http://127.0.0.1:1/must-not-connect.zip", "init_boot",
            LkmSelection.KmiNone, false, false, false, "", output::add, {})
        assertEquals(78, result.code)
        assertFalse(result.showReboot)
        assertTrue(output.isEmpty())
        assertEquals(context.getString(R.string.install_partition_read_failed), result.err)
    }

    @Test fun managerImagePathVerifiesWithoutPublishingAFlashableArtifact() {
        val image = File.createTempFile("ui-input-", ".img", context.cacheDir)
        image.writeBytes(ImageRepositoryTest.fixture())
        val originalHash = BootImageInspector.inspect(image).sha256
        val output = mutableListOf<String>()
        try {
            val result = installBoot(Uri.fromFile(image), LkmSelection.KmiNone, false, null,
                false, false, false, "", output::add, {})
            assertEquals(78, result.code)
            assertFalse(result.showReboot)
            assertTrue(result.err.isNotBlank())
            assertEquals(context.getString(R.string.install_image_analyzing), output.first())
            assertTrue(output.contains(context.getString(R.string.install_image_verified)))
            assertEquals(context.getString(R.string.install_image_patch_failed), result.err)
            assertTrue(output.none { it.contains("flashableCandidate") || it.contains("MAPLESU_") || it.contains("MAPLESU_") })
            assertFalse(org.json.JSONObject(ImageRepository(context).restore()!!.roundTripJson!!).getBoolean("flashableCandidate"))
            assertEquals(originalHash, BootImageInspector.inspect(image).sha256)
        } finally {
            image.delete()
            File(context.filesDir, "images").deleteRecursively()
        }
    }
}
