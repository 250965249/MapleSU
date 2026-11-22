package dev.maplesu.manager.installer

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class InstallerSignedPendingTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test fun signedRecoveryJournalsSurviveSdkRemovalWithoutExcludingNewWriters() {
        val installer = tmp.newFolder("sdk-installer")
        val recovery = tmp.newFolder("durable-recovery")
        val task = File(InstallerPending.signedInstallRoot(recovery), "signed-task").apply { mkdirs() }
        val record = File(task, "record.json")
        assertFalse(task.toPath().startsWith(installer.toPath()))
        assertEquals(true, installer.deleteRecursively())
        for (state in listOf("PREPARED", "WRITING", "RECOVERY_REQUIRED")) {
            record.writeText("""{"state":"$state"}""")
            InstallerPending.assertNoPendingInstall(installer, recoveryRoot = recovery)
            assertEquals("""{"state":"$state"}""", record.readText())
        }
        record.writeText("""{"state":"RESTORED"}""")
        InstallerPending.assertNoPendingInstall(installer, recoveryRoot = recovery)
    }
}
