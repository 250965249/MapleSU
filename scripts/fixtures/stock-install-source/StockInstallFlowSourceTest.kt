package dev.maplesu.manager.installer

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import dev.maplesu.manager.workmode.Hashes
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** Host integration: real app flow/attempt, fake Android I/O and remote Root service only. */
class StockInstallFlowSourceTest {
    @get:Rule val temporary = TemporaryFolder()

    private fun install(target: InstallTargetMode, file: Boolean, restore: Boolean = false,
                        manager: String? = "other.manager", signed: Boolean = false): TestInstallerService {
        val root = temporary.newFolder()
        val context = Context(root, root, ContentResolver("user selected image".toByteArray()))
        val service = TestInstallerService(root)
        InstallerServiceClient.service = service
        val result = StockInstallFlow.install(context, "test", target, "boot",
            if (file) Uri("chosen") else null, restore, manager, false,
            onPrepared = {}, produce = { source ->
                val expected = when { file -> "user selected image"; restore -> "explicit stock image"; else -> "current partition PRE" }
                assertEquals(expected, source.readText())
                service.events += "produce"
                val output = File(root, "candidate.img").apply { writeText("patched:${source.readText()}") }
                InstallCandidateImage(output, Hashes.sha256(output), output.length(), "boot")
            }, onWriting = {}, signingOptions = LenovoSigningOptions(signed))
        assertEquals("REBOOT_REQUIRED", result.getString("state"))
        assertEquals(restore, service.restore)
        assertEquals(signed, service.signed)
        assertFalse(File(root, "native-source-test.img").exists())
        assertEquals(if (file) listOf("prepare", "produce", "commit") else listOf("prepare", "open", "produce", "commit"), service.events)
        return service
    }

    @Test fun normalAndUltraUseCurrentPreWithoutAnImplicitManagerRestore() {
        for (target in InstallTargetMode.entries) {
            assertEquals("", install(target, file = false).manager)
        }
    }

    @Test fun selectedFilesUseTheirOwnBytesWithoutAnImplicitManagerRestore() {
        for (target in InstallTargetMode.entries) {
            assertEquals("", install(target, file = true).manager)
        }
    }

    @Test fun signedPrepareDoesNotReintroduceAutomaticManagerResolution() {
        assertEquals("", install(InstallTargetMode.ULTRA, file = false, signed = true).manager)
    }

    @Test fun anExplicitStockRestoreKeepsItsSelectedManager() {
        for (target in InstallTargetMode.entries) {
            assertEquals("chosen.manager", install(target, file = false, restore = true, manager = "chosen.manager").manager)
        }
    }

    @Test fun explicitRestoreFailureKeepsItsMeaningAndNeverBuildsOrWrites() {
        val root = temporary.newFolder()
        val context = Context(root, root, ContentResolver(ByteArray(0)))
        val service = TestInstallerService(root).apply {
            prepareFailure = IllegalStateException("INSTALLER_STOCK_BACKUP_AMBIGUOUS")
        }
        InstallerServiceClient.service = service
        val error = assertThrows(IllegalStateException::class.java) {
            StockInstallFlow.install(context, "test", InstallTargetMode.NORMAL, "boot", null,
                true, "chosen.manager", false, {}, { error("unexpected producer") }, {})
        }
        assertEquals("INSTALLER_STOCK_BACKUP_AMBIGUOUS", error.message)
        assertEquals(listOf("prepare", "cancel"), service.events)
    }
}
