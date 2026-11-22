package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.installer.InstallerDeviceLock
import dev.maplesu.manager.installer.InstallerPending
import java.io.File
import java.io.IOException
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ModeSwitchRootLeaseTest {
    @get:Rule val tmp = TemporaryFolder()
    private val id = "0f8fad5b-d9cb-469f-a165-708677289501"
    private val other = "0f8fad5b-d9cb-469f-a165-708677289502"
    private val root get() = File(tmp.root, "installer").apply { mkdirs() }
    private val control get() = File(tmp.root, "control")
    private val recovery get() = File(tmp.root, "recovery")
    private val marker get() = File(root, InstallerPending.MODE_SWITCH_LEASE_FILE)
    private val durable get() = File(recovery, InstallerPending.MODE_SWITCH_LEASE_FILE)
    private fun lease() = ModeSwitchRootLease(root,
        acquireLock = { InstallerDeviceLock.acquireLockFile(root) }, syncDirectory = {}, recoveryRoot = recovery)

    @Test
    fun acquiringTheLeasePreservesTheNativePreparationAndRecoveryEvidence() {
        val directory = File(root, "install-fixture").apply { mkdirs() }
        val record = File(directory, "record.json").apply { writeText("""{"state":"RECOVERY_REQUIRED"}""") }
        val lease = lease()
        try {
            assertTrue(lease.acquire(id).ok)
            assertEquals("""{"state":"RECOVERY_REQUIRED"}""", record.readText())
            assertTrue(lease.release(id).ok)
        } finally { lease.close() }
    }

    @Test
    fun oneTransactionKeepsTheSharedLockAcrossRepeatedRequestsAndReleasesOnCompletion() {
        val lease = lease()
        try {
            assertTrue(lease.acquire(id).ok)
            assertTrue(lease.isHeld())
            assertTrue(lease.acquire(id).ok)
            assertEquals(id, InstallerPending.modeSwitchLeaseId(root))
            assertEquals(ModeSwitchRootLease.BUSY, lease.acquire(other).code)
            assertEquals(ModeSwitchRootLease.BUSY, lease.release(other).code)
            val busy = runCatching { InstallerDeviceLock.withLockFile(root) {} }.exceptionOrNull()
            assertTrue(busy is IOException)
            assertEquals(ModeSwitchRootLease.BUSY, busy!!.message)
            assertTrue(lease.release(id).ok)
            assertFalse(lease.isHeld())
            assertFalse(marker.exists())
            assertFalse(durable.exists())
            InstallerDeviceLock.withLockFile(root) {}
            assertTrue(lease.release(id).ok)
        } finally { lease.close() }
    }

    @Test
    fun signedImageOperationsBorrowOnlyTheirOwnHeldLeaseAndKeepOtherWritersExcluded() {
        val lease = lease()
        try {
            assertTrue(lease.acquire(id).ok)
            val result = lease.withInstallLock(id) {
                InstallerDeviceLock.withDeviceLock(root) {
                    assertEquals(ModeSwitchRootLease.BUSY, probe())
                    "signed-commit"
                }
            }
            assertEquals("signed-commit", result)
            val otherFailure = runCatching {
                lease.withInstallLock(other) { InstallerDeviceLock.withLockFile(root) {} }
            }.exceptionOrNull()
            assertEquals(ModeSwitchRootLease.BUSY, otherFailure?.message)
            runCatching { lease.withInstallLock(id) { throw IOException("fixture-failure") } }
            assertEquals("retried", lease.withInstallLock(id) { InstallerDeviceLock.withDeviceLock(root) { "retried" } })
            assertTrue(lease.release(id).ok)
            InstallerDeviceLock.withLockFile(root) {}
        } finally { lease.close() }
    }

    @Test
    fun managerDeathWaitsForAnAcceptedSignedImageOperationToFinish() {
        val lease = lease()
        val entered = java.util.concurrent.CountDownLatch(1)
        val closed = java.util.concurrent.CountDownLatch(1)
        assertTrue(lease.acquire(id).ok)
        val closer = Thread {
            entered.countDown()
            lease.close()
            closed.countDown()
        }
        try {
            lease.withInstallLock(id) {
                closer.start()
                assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS))
                assertFalse(closed.await(100, java.util.concurrent.TimeUnit.MILLISECONDS))
                assertEquals(ModeSwitchRootLease.BUSY, probe())
            }
            assertTrue(closed.await(5, java.util.concurrent.TimeUnit.SECONDS))
            InstallerDeviceLock.withLockFile(root) {}
        } finally { lease.close(); closer.join(5_000) }
    }

    @Test
    fun theActualFileLockExcludesAnotherJvmUntilTheHelperClosesItsDescriptor() {
        assertEquals("ACQUIRED", probe())
        val lease = lease()
        assertTrue(lease.acquire(id).ok)
        try { assertEquals(ModeSwitchRootLease.BUSY, probe()) }
        finally { lease.close() }
        assertEquals("ACQUIRED", probe())
        assertEquals(id, InstallerPending.modeSwitchLeaseId(root))
    }

    @Test
    fun helperDeathKeepsEvidenceAndAllowsTheNextExplicitTransaction() {
        val original = lease()
        assertTrue(original.acquire(id).ok)
        original.close()
        InstallerDeviceLock.withLockFile(root) {}
        InstallerPending.assertNoPendingInstall(root)
        InstallerPending.assertNoPendingSwitch(control, installerRoot = root)
        val recovered = lease()
        try {
            assertTrue(recovered.acquire(other).ok)
            assertTrue(recovered.release(other).ok)
            assertTrue(recovered.acquire(id).ok)
            assertTrue(recovered.release(id).ok)
            InstallerPending.assertNoPendingInstall(root)
            InstallerPending.assertNoPendingSwitch(control, installerRoot = root)
        } finally { recovered.close() }
    }

    @Test
    fun anExistingPreparedBootInstallDoesNotBlockAnExplicitLease() {
        val directory = File(root, "install-fixture").apply { mkdirs() }
        File(directory, "record.json").writeText("""{"state":"PREPARED"}""")
        val lease = lease()
        try {
            val result = lease.acquire(id)
            assertTrue(result.ok)
            assertTrue(lease.isHeld())
            assertEquals("""{"state":"PREPARED"}""", File(directory, "record.json").readText())
            assertTrue(marker.exists())
            assertTrue(lease.release(id).ok)
            InstallerDeviceLock.withLockFile(root) {}
        } finally { lease.close() }
    }

    @Test
    fun anExistingSwitchHeadAllowsANewTransactionWithoutDeletingTheOldJournal() {
        control.mkdirs()
        File(control, "switch.json").writeText("""{"state":"COMMIT","switchId":"$id"}""")
        val lease = lease()
        try {
            assertTrue(lease.acquire(other).ok)
            assertTrue(lease.release(other).ok)
            assertEquals("""{"state":"COMMIT","switchId":"$id"}""", File(control, "switch.json").readText())
            assertTrue(lease.acquire(id).ok)
            assertTrue(lease.release(id).ok)
        } finally { lease.close() }
    }

    @Test
    fun aDamagedHistoricalLeaseDoesNotOwnTheWriterLock() {
        marker.writeText("switchId=broken\n")
        val lease = lease()
        try {
            assertTrue(lease.acquire(id).ok)
            assertTrue(lease.isHeld())
            assertEquals(id, InstallerPending.modeSwitchLeaseId(root, recovery))
            assertTrue(lease.release(id).ok)
            InstallerDeviceLock.withLockFile(root) {}
        } finally { lease.close() }
    }

    @Test
    fun aSymbolicLeaseIsReplacedWithoutFollowingItsTarget() {
        val target = File(tmp.root, "external-fixture.properties").apply { writeText("switchId=$id\n") }
        Files.createSymbolicLink(marker.toPath(), target.toPath())
        val lease = lease()
        try {
            assertTrue(lease.acquire(id).ok)
            assertEquals("switchId=$id\n", target.readText())
        } finally { lease.close() }
    }

    @Test
    fun freshHelperReleaseCanRetireADeadHelpersLeaseUnderTheKernelLock() {
        val original = lease()
        assertTrue(original.acquire(id).ok)
        original.close()
        val fresh = lease()
        try {
            assertTrue(fresh.release(other).ok)
            assertFalse(fresh.isHeld())
            assertFalse(marker.exists())
            assertTrue(fresh.release(id).ok)
            assertFalse(marker.exists())
        } finally { fresh.close() }
    }

    @Test
    fun aFailedRecoveryMarkerCleanupStillReleasesTheCompletedWriter() {
        var failSync = false
        val lease = ModeSwitchRootLease(root = root,
            acquireLock = { InstallerDeviceLock.acquireLockFile(root) },
            syncDirectory = { if (failSync) throw java.io.IOException("sync failed") },
            recoveryRoot = recovery)
        assertTrue(lease.acquire(id).ok)
        failSync = true
        assertFalse(lease.release(id).ok)
        assertFalse(lease.isHeld())
        InstallerDeviceLock.withLockFile(root) { }
    }

    @Test
    fun invalidIdsNeverAcquireOrPublishTheLock() {
        val lease = lease()
        assertEquals("INSTALLER_TASK_INVALID", lease.acquire("../outside").code)
        assertEquals("INSTALLER_TASK_INVALID", lease.release("../outside").code)
        assertFalse(marker.exists())
        assertFalse(File(root, "install.lock").exists())
    }

    @Test
    fun externalPendingIntentSurvivesDeletionOfTheEntireSdkInstallerTree() {
        val original = lease()
        assertTrue(original.acquire(id).ok)
        // The SDK can unlink a held lock on Unix. Host closes first because Windows denies it.
        original.close()
        assertTrue(root.deleteRecursively())
        assertTrue(durable.isFile)
        InstallerPending.assertNoPendingInstall(root, recoveryRoot = recovery)
        InstallerPending.assertNoPendingSwitch(control, installerRoot = root, recoveryRoot = recovery)
        val resumed = lease()
        try {
            assertTrue(resumed.acquire(other).ok)
            assertTrue(resumed.release(other).ok)
            assertTrue(resumed.acquire(id).ok)
            assertTrue(marker.isFile)
            assertTrue(resumed.release(id).ok)
            assertFalse(marker.exists())
            assertFalse(durable.exists())
        } finally { resumed.close() }
    }

    @Test
    fun legacyOnlyPendingIntentIsUpgradedWithoutBlockingItsOwnRecovery() {
        marker.writeText("switchId=$id\n")
        assertFalse(durable.exists())
        val resumed = lease()
        try {
            assertTrue(resumed.acquire(id).ok)
            assertTrue(durable.isFile)
            assertEquals(id, InstallerPending.modeSwitchLeaseId(root, recovery))
            assertTrue(resumed.release(id).ok)
        } finally { resumed.close() }
    }

    @Test
    fun conflictingHistoricalLeaseMarkersAreReplacedUnderTheKernelLock() {
        marker.writeText("switchId=$id\n")
        recovery.mkdirs()
        durable.writeText("switchId=$other\n")
        val resumed = lease()
        try {
            assertTrue(resumed.acquire(id).ok)
            assertEquals(id, InstallerPending.modeSwitchLeaseId(root, recovery))
        } finally { resumed.close() }
    }

    private fun probe(): String {
        val windows = System.getProperty("os.name", "").orEmpty().startsWith("Windows")
        val java = File(System.getProperty("java.home"), if (windows) "bin/java.exe" else "bin/java").absolutePath
        // The full Android test classpath exceeds Windows' process command-line limit.
        val arguments = File.createTempFile("lock-probe-", ".args", tmp.root)
        try {
            arguments.writeText(listOf("-cp", "\"${System.getProperty("java.class.path").replace('\\', '/')}\"",
                LockProbe::class.java.name, "\"${root.absolutePath.replace('\\', '/')}\"").joinToString("\n"))
            val process = ProcessBuilder(java, "@${arguments.absolutePath}").redirectErrorStream(true).start()
            val result = process.inputStream.bufferedReader().readText().trim()
            assertEquals(result, 0, process.waitFor())
            return result
        } finally { arguments.delete() }
    }

    object LockProbe {
        @JvmStatic fun main(args: Array<String>) {
            try { InstallerDeviceLock.withLockFile(File(args.single())) { println("ACQUIRED") } }
            catch (error: IOException) { println(error.message) }
        }
    }
}
