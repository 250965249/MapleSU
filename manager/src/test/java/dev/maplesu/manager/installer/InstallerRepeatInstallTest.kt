package dev.maplesu.manager.installer

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Run the real cross-process entry check against journals that survive an APK reinstall. */
class InstallerRepeatInstallTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test fun aFreshManagerCanInstallOverEveryInterruptedOrCompletedTask() {
        val installer = tmp.newFolder("installer")
        val recovery = tmp.newFolder("recovery")
        for (parent in listOf(installer, InstallerPending.signedInstallRoot(recovery))) {
            for (state in listOf("PREPARING", "PREPARED", "WRITING", "RESTORING", "RECOVERY_REQUIRED",
                    "REBOOT_REQUIRED", "REBOOT_REQUESTED", "BOOT_IMAGE_VERIFIED")) {
                val task = File(parent, state).apply { mkdirs() }
                val record = File(task, "record.json").apply { writeText("""{"state":"$state"}""") }
                InstallerPending.assertNoPendingInstall(installer, recoveryRoot = recovery)
                assertEquals("The old journal remains available for recovery", """{"state":"$state"}""", record.readText())
            }
        }
    }

    @Test fun aTasksOwnPreparationDoesNotBlockItsWriteLease() {
        val installer = tmp.newFolder("installer-own")
        val recovery = tmp.newFolder("recovery-own")
        val id = "11111111-1111-4111-8111-111111111111"
        val task = File(InstallerPending.signedInstallRoot(recovery), id).apply { mkdirs() }
        File(task, "record.json").writeText("""{"taskId":"$id","state":"PREPARED"}""")
        InstallerPending.assertNoPendingInstall(installer, id, recovery)
    }

    @Test fun anUnrelatedUnreadableJournalIsNotAnInstallationPrerequisite() {
        val installer = tmp.newFolder("installer-corrupt")
        val recovery = tmp.newFolder("recovery-corrupt")
        File(installer, "interrupted").apply { mkdirs() }.resolve("record.json").writeText("{")
        InstallerPending.assertNoPendingInstall(installer, recoveryRoot = recovery)
    }

    @Test fun everyHistoricalSwitchStateAllowsANewExplicitInstallation() {
        val installer = tmp.newFolder("installer-switch")
        val control = tmp.newFolder("control")
        for (state in InstallerPending.switchPendingStates) {
            val content = """{"switchId":"old-task","state":"$state"}"""
            val journal = File(control, "switch.json").apply { writeText(content) }
            InstallerPending.assertNoPendingSwitch(control, installerRoot = installer)
            assertEquals(content, journal.readText())
        }
        File(control, "switch.json").writeText("{")
        InstallerPending.assertNoPendingSwitch(control, installerRoot = installer)
    }

    @Test fun aLiveKernelLockStillExcludesAnUnrelatedWriterAndReleasesAfterFailure() {
        val installer = tmp.newFolder("installer-live")
        InstallerDeviceLock.withLockFile(installer) {
            val error = assertThrows(java.io.IOException::class.java) {
                InstallerPending.assertNoPendingInstall(installer)
            }
            assertEquals("INSTALLER_TRANSACTION_BUSY", error.message)
        }
        InstallerPending.assertNoPendingInstall(installer)
    }
}
