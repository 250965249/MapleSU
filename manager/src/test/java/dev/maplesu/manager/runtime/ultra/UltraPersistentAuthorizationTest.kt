package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import java.util.concurrent.Callable
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

/** Production PM/list reconciliation and broker lifetime run together; SDK writes are explicit fixtures. */
class UltraPersistentAuthorizationTest {
    private val name = "dev.maplesu.manager"
    private val trust = UltraReinstallTrust(name, 0, setOf("a".repeat(64)))
    private fun identity(uid: Int = 10999, signer: String = "a", installed: Long = 10) =
        ApplicationIdentity(uid, name, listOf(name), setOf(signer.repeat(64)), installed,
            installed + 1, "/data/app/$uid-$installed/base.apk")

    private inner class State {
        var now = 0L
        var current: ApplicationIdentity? = identity()
        var packages: List<String>? = listOf(name, "other.app")
        var reads = 0
        var grants = 0
        var revokes = 0
        var mappedUid: Int? = null
        var grantResult = "OK"
        var revokeResult = "OK"
        var listRead: (() -> List<String>?)? = null
        var identityRead: (() -> ApplicationIdentity?)? = null
        var grantHook: (() -> Unit)? = null
        val session = UltraManagerSignatureAuthorization.Session(trust) { now }
        fun tick() = session.refresh(
            identity = { val read = identityRead; if (read == null) current else read() },
            packages = { reads++; val read = listRead; if (read == null) packages else read() },
            grant = {
                grants++
                if (grantResult == "OK") {
                    packages = (packages.orEmpty() + name).distinct()
                    mappedUid = current?.uid
                }
                grantHook?.invoke()
                grantResult
            },
            revoke = {
                revokes++
                if (revokeResult == "OK") { packages = packages.orEmpty() - name; mappedUid = null }
                revokeResult
            })
    }

    @Test fun sameBootUidReplacementRebuildsTheMapping() {
        val state = State()
        assertEquals("OK", state.tick())
        state.current = identity(11001)
        assertEquals("OK", state.tick())
        assertEquals(2, state.grants)
        assertEquals(11001, state.mappedUid)
        assertTrue("other.app" in state.packages.orEmpty())
    }

    @Test fun sameUidNewInstallationIsNotAnEarlierSuccess() {
        val state = State()
        assertEquals("OK", state.tick())
        state.current = identity(installed = 20)
        assertEquals("OK", state.tick())
        assertEquals(2, state.grants)
    }

    @Test fun removedEntryIsReaddedAfterEarlierSuccess() {
        val state = State()
        assertEquals("OK", state.tick())
        state.packages = listOf("other.app")
        assertEquals("OK", state.tick())
        assertEquals(2, state.grants)
        assertEquals(setOf(name, "other.app"), state.packages?.toSet())
    }

    @Test fun unreadableListInvalidatesThePreviousSuccess() {
        val state = State()
        assertEquals("OK", state.tick())
        state.packages = null
        assertEquals("MANAGER_AUTH_LIST_UNREADABLE", state.tick())
        assertEquals(1, state.grants)
        state.packages = listOf(name)
        assertEquals("OK", state.tick())
        assertEquals(2, state.grants)
    }

    @Test fun transientGrantFailureRetriesTheChangedUid() {
        val state = State()
        assertEquals("OK", state.tick())
        state.current = identity(11001)
        state.grantResult = "MAPLESU_SDK_BUSY"
        assertEquals("MAPLESU_SDK_BUSY", state.tick())
        state.grantResult = "OK"
        assertEquals("OK", state.tick())
        assertEquals(3, state.grants)
        assertEquals(11001, state.mappedUid)
    }

    @Test fun failedReadbackDoesNotConfirmAGrant() {
        val state = State()
        var reads = 0
        state.listRead = { if (++reads % 2 == 0) emptyList() else listOf(name) }
        repeat(3) { assertEquals("MANAGER_AUTH_READBACK_FAILED", state.tick()) }
        assertEquals(3, state.grants)
        state.listRead = null
        assertEquals("OK", state.tick())
        assertEquals(4, state.grants)
    }

    @Test fun unknownIdentityForTwoThousandPassesRevokesOnlyOnce() {
        val state = State()
        assertEquals("OK", state.tick())
        state.current = null
        var passes = 0
        val results = mutableListOf<String>()
        val loop = UltraBootAuthorizationRestore { delay ->
            assertEquals(5_000L, delay)
            state.now += delay
            if (++passes == 2_000) state.current = identity(11001)
        }
        assertEquals("SUSPENDED", loop.maintain({ passes == 2_001 }, { state.tick() }, results::add))
        assertEquals(listOf("MANAGER_IDENTITY_PENDING", "OK"), results)
        assertEquals(1, state.revokes)
        assertEquals(2, state.grants)
    }

    @Test fun changedSignerRevokesOnceAndAValidSignerCanReturnLater() {
        val state = State()
        assertEquals("OK", state.tick())
        state.current = identity(signer = "b")
        repeat(2_000) { assertEquals("OK", state.tick()) }
        assertEquals(1, state.grants)
        assertEquals(1, state.revokes)
        assertEquals(listOf("other.app"), state.packages)
        state.current = identity(11001)
        assertEquals("OK", state.tick())
        assertEquals(2, state.grants)
    }

    @Test fun otherUserIdentityIsRevokedWithoutGranting() {
        val state = State()
        state.current = identity(110999)
        repeat(30) { assertEquals("OK", state.tick()) }
        assertEquals(0, state.grants)
        assertEquals(1, state.revokes)
    }

    @Test fun failedRevocationRemainsRetryable() {
        val state = State()
        state.current = identity(signer = "b")
        state.revokeResult = "MAPLESU_SDK_BUSY"
        assertEquals("MAPLESU_SDK_BUSY", state.tick())
        state.revokeResult = "OK"
        assertEquals("OK", state.tick())
        assertEquals(2, state.revokes)
        assertEquals(0, state.grants)
    }

    @Test fun identityChangingDuringGrantIsRevokedAndNotCached() {
        val state = State()
        state.grantHook = { state.current = identity(signer = "b") }
        assertEquals("MANAGER_IDENTITY_CHANGED", state.tick())
        assertEquals(1, state.revokes)
        state.grantHook = null
        state.current = identity()
        assertEquals("OK", state.tick())
        assertEquals(2, state.grants)
    }

    @Test fun identityChangingDuringAReadOnlyPassIsAlsoRevoked() {
        val state = State()
        assertEquals("OK", state.tick())
        var reads = 0
        state.identityRead = { if (++reads == 1) identity() else identity(signer = "b") }
        assertEquals("MANAGER_IDENTITY_CHANGED", state.tick())
        assertEquals(1, state.grants)
        assertEquals(1, state.revokes)
        state.identityRead = null
        assertEquals("OK", state.tick())
        assertEquals(2, state.grants)
    }

    @Test fun stablePassesOnlyReadUntilTheSixtySecondRenewal() {
        val state = State()
        assertEquals("OK", state.tick())
        for (time in 5_000L..55_000L step 5_000L) {
            state.now = time
            assertEquals("OK", state.tick())
        }
        assertEquals(1, state.grants)
        state.mappedUid = null // The package list cannot observe loss of the native UID map.
        state.now = 60_000L
        assertEquals("OK", state.tick())
        assertEquals(2, state.grants)
        assertEquals(10999, state.mappedUid)
    }

    @Test fun monotonicClockRegressionRenewsInsteadOfKeepingAnUnboundedLease() {
        val state = State()
        assertEquals("OK", state.tick())
        state.now = -1
        assertEquals("OK", state.tick())
        assertEquals(2, state.grants)
    }

    @Test fun concurrentReadinessRequestsPublishOneStableGrant() {
        val state = State()
        val pool = Executors.newFixedThreadPool(6)
        try {
            val results = pool.invokeAll((1..24).map { Callable { state.tick() } })
            results.forEach { assertEquals("OK", it.get(2, TimeUnit.SECONDS)) }
            assertEquals(1, state.grants)
        } finally { pool.shutdownNow() }
    }

    @Test fun brokerContinuesAfterSuccessAndConvergesOnChangesAndTransientFailures() {
        val state = State()
        var passes = 0
        val delays = mutableListOf<Long>()
        val results = mutableListOf<String>()
        val loop = UltraBootAuthorizationRestore { delay ->
            delays += delay
            state.now += delay
            when (++passes) {
                1 -> state.current = identity(11001)
                2 -> state.packages = listOf("other.app")
                3 -> state.packages = null
                4 -> state.packages = listOf(name, "other.app")
                5 -> state.current = identity(signer = "b")
                6 -> state.current = identity(11002)
            }
        }
        assertEquals("SUSPENDED", loop.maintain({ passes == 7 }, { state.tick() }, results::add))
        assertEquals(List(7) { 5_000L }, delays)
        assertEquals(5, state.grants)
        assertEquals(1, state.revokes)
        assertEquals(11002, state.mappedUid)
        assertEquals(listOf("OK", "MANAGER_AUTH_LIST_UNREADABLE", "OK"), results)
    }

    @Test fun brokerRetriesOrdinaryErrorsAndExceptionsWithoutUserAction() {
        val expected = listOf("MAPLESU_SDK_BUSY", "MANAGER_AUTH_LIST_UNREADABLE",
            "MANAGER_AUTH_RESTORE_EXCEPTION", "ERR_MODULE_PARAM", "OK")
        var passes = 0
        val observed = mutableListOf<String>()
        val loop = UltraBootAuthorizationRestore { passes++ }
        assertEquals("SUSPENDED", loop.maintain({ passes == expected.size }, {
            if (passes == 2) throw IllegalStateException("PM temporarily unavailable")
            expected[passes]
        }, observed::add))
        assertEquals(expected, observed)
    }

    @Test fun exceptionInvalidatesAnEarlierSessionGrantBeforeRetry() {
        val state = State()
        assertEquals("OK", state.tick())
        state.listRead = { throw IllegalStateException("unavailable") }
        assertThrows(IllegalStateException::class.java) { state.tick() }
        state.listRead = null
        assertEquals("OK", state.tick())
        assertEquals(2, state.grants)
    }

    @Test fun disabledLoopStopsBeforeReadingAndAfterItsPause() {
        var disabled = true
        var reads = 0
        val loop = UltraBootAuthorizationRestore { disabled = true }
        assertEquals("SUSPENDED", loop.maintain({ disabled }, { reads++; "OK" }))
        assertEquals(0, reads)
        disabled = false
        assertEquals("SUSPENDED", loop.maintain({ disabled }, { reads++; "OK" }))
        assertEquals(1, reads)
    }

    @Test fun disabledReceiptStopsWithoutAnotherPause() {
        val loop = UltraBootAuthorizationRestore { error("disabled loop must stop") }
        assertEquals("SUSPENDED", loop.maintain({ false }, { "SUSPENDED" }))
    }

    @Test fun interruptionBeforeWorkOrDuringPausePreservesCancellation() {
        try {
            Thread.currentThread().interrupt()
            assertEquals("MAPLESU_SDK_INTERRUPTED", UltraBootAuthorizationRestore().maintain(
                { error("interrupted scope") }, { error("interrupted write") }))
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        try {
            assertEquals("MAPLESU_SDK_INTERRUPTED", UltraBootAuthorizationRestore { throw InterruptedException() }
                .maintain({ false }, { "OK" }))
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    @Test fun interruptionFromSdkRestorationPreservesTheFlag() {
        try {
            assertEquals("MAPLESU_SDK_INTERRUPTED", UltraBootAuthorizationRestore { error("unexpected pause") }
                .maintain({ false }, { throw InterruptedException() }))
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    @Test fun actualSleepingWorkerStopsWhenInterrupted() {
        val started = CountDownLatch(1)
        val result = AtomicReference<String>()
        val interrupted = AtomicReference<Boolean>()
        val worker = Thread {
            result.set(UltraBootAuthorizationRestore().maintain({ false }, { "OK" }, { started.countDown() }))
            interrupted.set(Thread.currentThread().isInterrupted)
        }
        try {
            worker.start()
            assertTrue(started.await(2, TimeUnit.SECONDS))
            worker.interrupt()
            worker.join(2_000L)
            assertFalse(worker.isAlive)
            assertEquals("MAPLESU_SDK_INTERRUPTED", result.get())
            assertEquals(true, interrupted.get())
        } finally { worker.interrupt(); worker.join(2_000L) }
    }

    @Test fun cancellationAndErrorsAreNotConvertedIntoBackgroundRetries() {
        for (failure in listOf(CancellationException("cancelled"), AssertionError("failed"))) {
            val loop = UltraBootAuthorizationRestore { error("unexpected retry") }
            val caught = assertThrows(failure.javaClass) { loop.maintain({ false }, { throw failure }) }
            assertSame(failure, caught)
        }
    }
}
