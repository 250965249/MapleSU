package dev.maplesu.manager.runtime.ultra

import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import org.junit.Assert.*
import org.junit.Test

class UltraBootAuthorizationRestoreTest {
    @Test fun brokerBackgroundRetryRestoresIdentityAfterPackageManagerBecomesReadable() {
        val name = "dev.maplesu.manager"
        val trust = UltraReinstallTrust(name, 0, setOf("a".repeat(64)))
        var identity: ApplicationIdentity? = null
        var packages = listOf(name, "other.app")
        var grants = 0
        var revokes = 0
        var refreshes = 0
        val pauses = mutableListOf<Long>()
        val state = UltraBootAuthorizationRestore {
            pauses += it
            if (pauses.size == 3) identity = ApplicationIdentity(10999, name, listOf(name),
                setOf("a".repeat(64)), 10, 11, "/data/app/reinstalled/base.apk")
        }
        assertEquals("OK", state.ensureWhenIdentityAvailable("boot", "key", { false }) {
            UltraManagerSignatureAuthorization.refresh(trust, { identity }, { packages },
                { grants++; packages = (packages + name).distinct(); "OK" },
                { revokes++; packages = packages - name; "OK" }, { refreshes++; "OK" })
        })
        assertEquals(List(3) { 1_000L }, pauses)
        assertEquals(1, grants)
        assertEquals(1, revokes)
        assertEquals(0, refreshes)
        assertEquals("OK", state.ensure("boot", "key") { error("already restored") })
    }

    @Test fun longIdentityUnavailabilityDoesNotRepeatedlyPublishSuTables() {
        val name = "dev.maplesu.manager"
        val trust = UltraReinstallTrust(name, 0, setOf("a".repeat(64)))
        var packages = listOf(name, "other.app")
        var pauses = 0
        var revokes = 0
        var reads = 0
        val state = UltraBootAuthorizationRestore { pauses++ }
        assertEquals("SUSPENDED", state.ensureWhenIdentityAvailable("boot", "key", { pauses == 2_000 }) {
            UltraManagerSignatureAuthorization.refresh(trust, { null }, { reads++; packages },
                { error("unknown identity must not grant") },
                { revokes++; packages = packages - name; "OK" },
                { error("unknown identity must not rebuild") })
        })
        assertEquals(2_000, pauses)
        assertEquals(2_001, reads)
        assertEquals(1, revokes)
    }

    @Test fun disabledBrokerStopsBeforeStartingOrAfterItsPendingPause() {
        for (disabledAtStart in listOf(true, false)) {
            var disabled = disabledAtStart
            var calls = 0
            val state = UltraBootAuthorizationRestore { disabled = true }
            assertEquals("SUSPENDED", state.ensureWhenIdentityAvailable("boot", "key", { disabled }) {
                calls++; "MANAGER_IDENTITY_PENDING"
            })
            assertEquals(if (disabledAtStart) 0 else 1, calls)
        }
    }

    @Test fun interruptedIdentityPausePreservesTheFlagAndDoesNotCacheSuccess() {
        val state = UltraBootAuthorizationRestore { throw InterruptedException() }
        var calls = 0
        try {
            assertEquals("MAPLESU_SDK_INTERRUPTED", state.ensureWhenIdentityAvailable("boot", "key", { false }) {
                calls++; "MANAGER_IDENTITY_PENDING"
            })
            assertEquals(1, calls)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        assertEquals("OK", state.ensure("boot", "key") { calls++; "OK" })
        assertEquals(2, calls)
    }

    @Test fun alreadyInterruptedBrokerDoesNotReadIdentityOrWriteAuthorization() {
        val state = UltraBootAuthorizationRestore { error("unexpected pause") }
        try {
            Thread.currentThread().interrupt()
            assertEquals("MAPLESU_SDK_INTERRUPTED", state.ensureWhenIdentityAvailable("boot", "key",
                { error("interrupted scope") }) { error("interrupted write") })
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    @Test fun backgroundLoopDoesNotReplayDefiniteFailuresOrCompletedRevocation() {
        for (result in listOf("OK", "ERR_MODULE_PARAM", "MANAGER_AUTH_REVOKE_UNVERIFIED", "SUSPENDED")) {
            var calls = 0
            val state = UltraBootAuthorizationRestore { error("unexpected identity retry") }
            assertEquals(result, state.ensureWhenIdentityAvailable("boot", "key", { false }) { calls++; result })
            assertEquals(1, calls)
        }
    }

    @Test fun unreadablePackageIdentityNeverCachesSuccessBeforePackageManagerRecovers() {
        val name = "dev.maplesu.manager"
        val trust = UltraReinstallTrust(name, 0, setOf("a".repeat(64)))
        var identity: ApplicationIdentity? = null
        var packages = listOf(name, "other.app")
        var grants = 0
        var revokes = 0
        var refreshes = 0
        fun restore() = UltraManagerSignatureAuthorization.refresh(trust, { identity }, { packages },
            { grants++; packages = (packages + name).distinct(); "OK" },
            { revokes++; packages = packages - name; "OK" }, { refreshes++; "OK" })
        val state = UltraBootAuthorizationRestore { error("identity retry belongs to the background loop") }
        repeat(3) {
            assertEquals("MANAGER_IDENTITY_PENDING", state.ensure("boot", "key", ::restore))
        }
        identity = ApplicationIdentity(10999, name, listOf(name), setOf("a".repeat(64)),
            10, 11, "/data/app/current/base.apk")
        assertEquals("OK", state.ensure("boot", "key", ::restore))
        assertEquals("OK", state.ensure("boot", "key") { error("already verified") })
        assertEquals(1, grants)
        assertEquals(1, revokes)
        assertEquals(0, refreshes)
        assertEquals(setOf(name, "other.app"), packages.toSet())
    }

    @Test fun temporarilyUnavailableUidMappingsRecoverWithoutAnotherUserAction() {
        val pauses = mutableListOf<Long>()
        val state = UltraBootAuthorizationRestore { pauses += it }
        var calls = 0
        assertEquals("OK", state.ensure("boot", "key") {
            calls++
            if (calls == 1) "ERR_MODULE_SU_LIST_NOT_FOUND" else "OK"
        })
        assertEquals(2, calls)
        assertEquals(listOf(250L), pauses)
        assertEquals("OK", state.ensure("boot", "key") { error("already restored") })
    }

    @Test fun exhaustedTransientFailuresStayUncachedAndCanRecoverOnTheNextRequest() {
        val pauses = mutableListOf<Long>()
        val state = UltraBootAuthorizationRestore { pauses += it }
        var calls = 0
        assertEquals("MAPLESU_SDK_BUSY", state.ensure("boot", "key") { calls++; "MAPLESU_SDK_BUSY" })
        assertEquals(3, calls)
        assertEquals(listOf(250L, 750L), pauses)
        assertEquals("OK", state.ensure("boot", "key") { calls++; "OK" })
        assertEquals(4, calls)
    }

    @Test fun permanentFailuresAndSuspensionNeverReplayTheOperation() {
        for (failure in listOf("SUSPENDED", "ERR_MODULE_NO_ROOT", "ERR_MODULE_PARAM", "READBACK_MISMATCH")) {
            val state = UltraBootAuthorizationRestore { error("unexpected retry") }
            var calls = 0
            assertEquals(failure, state.ensure("boot", "key") { calls++; failure })
            assertEquals(1, calls)
        }
    }

    @Test fun suspensionBetweenRetriesStopsBeforeAnotherRefresh() {
        var suspended = false
        var calls = 0
        val state = UltraBootAuthorizationRestore { suspended = true }
        assertEquals("SUSPENDED", state.ensure("boot", "key") {
            calls++
            if (suspended) "SUSPENDED" else "ERR_MODULE_SU_LIST_NOT_FOUND"
        })
        assertEquals(2, calls)
    }

    @Test fun interruptedBackoffPreservesCancellationAndNeverCachesSuccess() {
        val state = UltraBootAuthorizationRestore { throw InterruptedException() }
        var calls = 0
        try {
            assertEquals("MAPLESU_SDK_INTERRUPTED", state.ensure("boot", "key") { calls++; "MAPLESU_SDK_BUSY" })
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(1, calls)
        } finally { Thread.interrupted() }
        assertEquals("OK", state.ensure("boot", "key") { calls++; "OK" })
        assertEquals(2, calls)
    }

    @Test fun reOpeningManagerKeepsTheSuccessfulBootAndKeyRestoration() {
        val state = UltraBootAuthorizationRestore()
        var calls = 0
        repeat(5) { assertEquals("OK", state.ensure("boot", "fingerprint") { calls++; "OK" }) }
        assertEquals(1, calls)
    }

    @Test fun failedRefreshRetriesAndNeverCachesAnEarlierDifferentScope() {
        val state = UltraBootAuthorizationRestore()
        assertEquals("OK", state.ensure("boot", "old") { "OK" })
        assertEquals("FAILED", state.ensure("boot", "new") { "FAILED" })
        var calls = 0
        assertEquals("OK", state.ensure("boot", "old") { calls++; "OK" })
        assertEquals(1, calls)
    }

    @Test fun unknownBootNewBootAndNewCredentialEachNeedRealRestoration() {
        val state = UltraBootAuthorizationRestore()
        var calls = 0
        for ((boot, key) in listOf(null to "key", null to "key", "boot-a" to "key",
            "boot-b" to "key", "boot-b" to "new-key")) {
            assertEquals("OK", state.ensure(boot, key) { calls++; "OK" })
        }
        assertEquals(5, calls)
    }

    @Test fun concurrentRecoveryRequestsSubmitOneSuccessfulSdkWrite() {
        val state = UltraBootAuthorizationRestore()
        val writes = AtomicInteger()
        val pool = Executors.newFixedThreadPool(6)
        try {
            val results = pool.invokeAll((1..24).map {
                Callable { state.ensure("boot", "key") { writes.incrementAndGet(); "OK" } }
            })
            results.forEach { assertEquals("OK", it.get(2, TimeUnit.SECONDS)) }
            assertEquals(1, writes.get())
        } finally { pool.shutdownNow() }
    }
}
