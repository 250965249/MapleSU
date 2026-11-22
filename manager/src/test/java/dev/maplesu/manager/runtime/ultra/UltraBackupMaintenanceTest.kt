package dev.maplesu.manager.runtime.ultra

import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

class UltraBackupMaintenanceTest {
    private val identity = UltraBackupMaintenance.Identity("fingerprint", "boot", "dev.maplesu.manager", 10123)
    private val verified = UltraRecoveryKeyStore.BackupOutcome(true, false, "BACKED_UP;IDENTITY_READY")

    @Test fun transientBackupFailureRetriesWithoutWaitingForAnotherAppLaunch() {
        var calls = 0
        val pauses = mutableListOf<Long>()
        val result = UltraBackupMaintenance.refresh({ true }, {
            if (++calls < 3) verified.copy(ok = false, reason = "UNREADABLE") else verified
        }, { pauses += it })
        assertEquals(verified, result)
        assertEquals(3, calls)
        assertEquals(listOf(250L, 750L), pauses)
    }

    @Test fun backupRetriesAreBoundedAndCancelWhenIdentityChanges() {
        var calls = 0
        UltraBackupMaintenance.refresh({ true }, { calls++; verified.copy(ok = false) }, {})
        assertEquals(3, calls)
        var eligible = true
        calls = 0
        UltraBackupMaintenance.refresh({ eligible }, { calls++; verified.copy(ok = false) }, { eligible = false })
        assertEquals(1, calls)
    }

    @Test fun sequentialStartupPathsReuseOnlyACompleteSuccess() {
        val maintenance = UltraBackupMaintenance { 0 }
        var calls = 0
        assertEquals(verified, maintenance.ensure({ identity }) { calls++; verified })
        val cached = maintenance.ensure({ identity }) { calls++; error("duplicate SDK maintenance") }!!
        assertTrue(cached.ok)
        assertTrue(cached.skipped)
        assertEquals("RECENTLY_VERIFIED;${verified.reason}", cached.reason)
        assertEquals(1, calls)
    }

    @Test fun concurrentSelfHealAndPairingShareOneRealMaintenance() {
        val maintenance = UltraBackupMaintenance { 0 }
        val workers = Executors.newFixedThreadPool(3)
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        try {
            val first = workers.submit<UltraRecoveryKeyStore.BackupOutcome?> {
                maintenance.ensure({ identity }) {
                    calls.incrementAndGet(); started.countDown()
                    check(release.await(5, TimeUnit.SECONDS)); verified
                }
            }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            val peers = (1..2).map { workers.submit<UltraRecoveryKeyStore.BackupOutcome?> {
                maintenance.ensure({ identity }) { calls.incrementAndGet(); verified }
            } }
            release.countDown()
            assertEquals(verified, first.get(5, TimeUnit.SECONDS))
            peers.forEach { assertEquals("RECENTLY_VERIFIED;${verified.reason}", it.get(5, TimeUnit.SECONDS)!!.reason) }
            assertEquals(1, calls.get())
        } finally { release.countDown(); workers.shutdownNow() }
    }

    @Test fun keyBootPackageAndUidChangesEachRequireRealWork() {
        val maintenance = UltraBackupMaintenance { 0 }
        var calls = 0
        val identities = listOf(identity, identity.copy(keyFingerprint = "new"), identity.copy(bootId = "new"),
            identity.copy(packageName = "new"), identity.copy(uid = 10124))
        identities.forEach { next ->
            assertEquals(verified, maintenance.ensure({ next }) { calls++; verified })
        }
        assertEquals(identities.size, calls)
    }

    @Test fun ttlExpiresFromCompletionAndClockRollbackDoesNotReuseSuccess() {
        var at = 100L
        val maintenance = UltraBackupMaintenance { at }
        var calls = 0
        maintenance.ensure({ identity }) { calls++; at = 1000; verified }
        at = 60_999
        maintenance.ensure({ identity }) { error("still valid from completion") }
        at = 61_000
        maintenance.ensure({ identity }) { calls++; verified }
        at = 60_999
        maintenance.ensure({ identity }) { calls++; verified }
        assertEquals(3, calls)
    }

    @Test fun forceAlwaysExecutesAndFailureRemovesThePreviousSuccess() {
        val maintenance = UltraBackupMaintenance { 0 }
        maintenance.ensure({ identity }) { verified }
        assertEquals(verified, maintenance.ensure({ identity }, force = true) { verified })
        val failure = verified.copy(ok = false, reason = "IDENTITY_ROOT_NOT_VERIFIED")
        assertEquals(failure, maintenance.ensure({ identity }, force = true) { failure })
        var calls = 0
        maintenance.ensure({ identity }) { calls++; verified }
        assertEquals(1, calls)
    }

    @Test fun nullFailureAndExceptionNeverBecomeASuccessReceipt() {
        for (failure in listOf<UltraRecoveryKeyStore.BackupOutcome?>(null,
            verified.copy(ok = false, reason = "BACKUP_READ_FAILED"),
            verified.copy(ok = false, reason = "BACKED_UP;IDENTITY_DEPLOY_FAILED"))) {
            val maintenance = UltraBackupMaintenance { 0 }
            var calls = 0
            repeat(2) { assertEquals(failure, maintenance.ensure({ identity }) { calls++; failure }) }
            assertEquals(verified, maintenance.ensure({ identity }) { calls++; verified })
            assertEquals(3, calls)
        }
        val maintenance = UltraBackupMaintenance { 0 }
        maintenance.ensure({ identity }) { verified }
        try {
            maintenance.ensure({ identity }, force = true) { throw IllegalStateException("fixture") }
            fail("exception was swallowed")
        } catch (_: IllegalStateException) { }
        assertEquals(verified, maintenance.ensure({ identity }) { verified })
    }

    @Test fun unknownIdentityNeverCachesOrReusesKnownSuccess() {
        val maintenance = UltraBackupMaintenance { 0 }
        maintenance.ensure({ identity }) { verified }
        var calls = 0
        repeat(2) { maintenance.ensure({ null }) { calls++; verified } }
        maintenance.ensure({ identity }) { calls++; verified }
        assertEquals(3, calls)
    }

    @Test fun scopeChangingDuringWorkDoesNotCacheAnObsoleteSuccess() {
        val maintenance = UltraBackupMaintenance { 0 }
        var current: UltraBackupMaintenance.Identity? = identity
        maintenance.ensure({ current }) { current = null; verified }
        current = identity
        var calls = 0
        maintenance.ensure({ current }) { calls++; verified }
        assertEquals(1, calls)
    }

    @Test fun queuedCallerChecksCurrentEligibilityAfterAcquiringTheMonitor() {
        val maintenance = UltraBackupMaintenance { 0 }
        val current = java.util.concurrent.atomic.AtomicReference<UltraBackupMaintenance.Identity?>(identity)
        val workers = Executors.newFixedThreadPool(2)
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        try {
            val first = workers.submit<UltraRecoveryKeyStore.BackupOutcome?> {
                maintenance.ensure({ current.get() }) {
                    calls.incrementAndGet(); started.countDown()
                    check(release.await(5, TimeUnit.SECONDS)); verified
                }
            }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            val peer = workers.submit<UltraRecoveryKeyStore.BackupOutcome?> {
                maintenance.ensure({ current.get() }) { calls.incrementAndGet(); verified }
            }
            current.set(null); release.countDown()
            assertEquals(verified, first.get(5, TimeUnit.SECONDS))
            assertEquals(verified, peer.get(5, TimeUnit.SECONDS))
            assertEquals(2, calls.get())
        } finally { release.countDown(); workers.shutdownNow() }
    }

    @Test fun productionRoutesBothStartupPathsThroughCompleteBackupAndIdentityMaintenance() {
        val manager = File(System.getProperty("user.dir") ?: ".").let {
            if (File(it, "src/main/java").isDirectory) it else File(it, "manager")
        }
        val source = File(manager, "src/main/java/dev/maplesu/manager/runtime/ultra/UltraEnvironmentInstaller.kt").readText()
        val body = source.substringAfter("fun backupKey(")
        assertTrue(body.contains("backupMaintenance.ensure("))
        assertTrue(body.indexOf("UltraRecoveryKeyStore.ensureBackup(") > body.indexOf("backupMaintenance.ensure("))
        assertTrue(body.indexOf("UltraIdentityRecovery.ensure(") > body.indexOf("backupMaintenance.ensure("))
        assertTrue(body.contains("force = forceIdentity"))
        assertTrue(body.contains("!UltraIdentityRecovery.blocked("))
        assertTrue(body.contains("UltraRootKeyStore.read(context) == resolved"))
    }
}
