package dev.maplesu.manager.installer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.IOException
import java.nio.file.Files

/** The single install.lock mechanics; host tests use a temp directory instead of /data/adb. */
class InstallerDeviceLockTest {
    @Test
    fun sdkCleanupDoesNotReplaceTheActiveWriterLock() {
        val workspace = Files.createTempDirectory("maplesu-persistent-lock-").toFile()
        val sdk = File(workspace, "sdk/installer").apply { mkdirs() }
        val lockRoot = InstallerDeviceLock.writerLockRoot(File(workspace, "recovery"))
        try {
            InstallerDeviceLock.withLockFile(lockRoot) {
                assertTrue(requireNotNull(sdk.parentFile).deleteRecursively())
                assertTrue(sdk.mkdirs())
                try {
                    InstallerDeviceLock.withLockFile(lockRoot) { fail("second writer accepted after cleanup") }
                    fail("second writer accepted after cleanup")
                } catch (error: IOException) {
                    assertEquals("INSTALLER_TRANSACTION_BUSY", error.message)
                }
            }
            assertEquals("next writer", InstallerDeviceLock.withLockFile(lockRoot) { "next writer" })
        } finally { workspace.deleteRecursively() }
    }

    @Test
    fun aHeldLeaseReusesItsLockWithoutExcludingItsOwnPreparation() {
        val root = Files.createTempDirectory("maplesu-borrowed-lock-").toFile()
        try {
            InstallerDeviceLock.withLockFile(root) {
                InstallerDeviceLock.withHeldLease(root) {
                    InstallerPending.assertNoPendingInstall(root)
                    InstallerPending.assertNoPendingSwitch(File(root, "control"), installerRoot = root)
                    assertEquals("same task", InstallerDeviceLock.withDeviceLock(root) { "same task" })
                }
            }
            InstallerPending.assertNoPendingInstall(root)
        } finally { root.deleteRecursively() }
    }

    @Test
    fun lockFileIsCreatedAndActionRuns() {
        val root = Files.createTempDirectory("maplesu-install-lock-").toFile()
        try {
            val value = InstallerDeviceLock.withLockFile(root) { "ran" }
            assertEquals("ran", value)
            assertTrue(File(root, "install.lock").isFile)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun sameProcessSecondLockIsBusy() {
        val root = Files.createTempDirectory("maplesu-install-lock-").toFile()
        try {
            InstallerDeviceLock.withLockFile(root) {
                try {
                    InstallerDeviceLock.withLockFile(root) { fail("nested lock accepted") }
                    fail("nested lock accepted")
                } catch (error: IOException) {
                    assertEquals("INSTALLER_TRANSACTION_BUSY", error.message)
                }
            }
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun lockIsReleasedAfterFailure() {
        val root = Files.createTempDirectory("maplesu-install-lock-").toFile()
        try {
            try {
                InstallerDeviceLock.withLockFile<Unit>(root) { throw IllegalStateException("boom") }
            } catch (_: IllegalStateException) {
                // expected
            }
            assertEquals("reacquired", InstallerDeviceLock.withLockFile(root) { "reacquired" })
        } finally {
            root.deleteRecursively()
        }
    }
}
