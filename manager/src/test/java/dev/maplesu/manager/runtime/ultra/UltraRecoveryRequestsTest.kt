package dev.maplesu.manager.runtime.ultra

import kotlinx.coroutines.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

class UltraRecoveryRequestsTest {
    @Test fun eventsDuringRecoveryConflateIntoOneFreshPass() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        try {
            val release = CompletableDeferred<Unit>()
            val second = CompletableDeferred<Unit>()
            var calls = 0
            var active = 0
            var maximum = 0
            val requests = UltraRecoveryRequests(scope, recover = {
                calls++
                active++
                maximum = maxOf(maximum, active)
                if (calls == 1) release.await()
                active--
                if (calls == 2) second.complete(Unit)
            }, failed = { throw AssertionError(it) })
            requests.request()
            repeat(1_000) { requests.request() }
            assertEquals(1, calls)
            release.complete(Unit)
            withTimeout(2_000) { second.await() }
            assertEquals(2, calls)
            assertEquals(1, maximum)
            requests.request()
            assertEquals(3, calls)
        } finally { scope.cancel() }
    }

    @Test fun aFailedPassDoesNotDisableLaterForegroundRecovery() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        try {
            val failures = mutableListOf<Exception>()
            var calls = 0
            val requests = UltraRecoveryRequests(scope,
                recover = { if (++calls == 1) error("broker not ready") },
                failed = { failures += it })
            requests.request()
            requests.request()
            assertEquals(2, calls)
            assertEquals(1, failures.size)
        } finally { scope.cancel() }
    }

    @Test fun cancellationEndsThatPassAndAFreshEventCanStartAnother() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        try {
            var calls = 0
            val requests = UltraRecoveryRequests(scope, recover = {
                if (++calls == 1) throw CancellationException("interrupted recovery")
            }, failed = { throw AssertionError("cancellation was swallowed", it) })
            requests.request()
            requests.request()
            assertEquals(2, calls)
        } finally { scope.cancel() }
    }

    @Test fun anEventAlreadyQueuedWhenAPassCancelsRunsWithoutAnotherExternalEvent() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        try {
            val release = CompletableDeferred<Unit>()
            val second = CompletableDeferred<Unit>()
            var calls = 0
            val requests = UltraRecoveryRequests(scope, recover = {
                if (++calls == 1) {
                    release.await()
                    throw CancellationException("only this recovery pass ended")
                }
                second.complete(Unit)
            }, failed = { throw AssertionError(it) })
            requests.request()
            requests.request()
            release.complete(Unit)
            assertTrue("queued foreground event was left without a consumer",
                withTimeoutOrNull(300L) { second.await(); true } == true)
            assertEquals(2, calls)
        } finally { scope.cancel() }
    }

    @Test fun firstRequestIsRetainedBeforeTheIoConsumerBegins() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val completed = CompletableDeferred<Unit>()
            val requests = UltraRecoveryRequests(scope, recover = { completed.complete(Unit) },
                failed = { throw AssertionError(it) })
            requests.request()
            withTimeout(2_000L) { completed.await() }
        } finally { scope.cancel() }
    }

    @Test fun simultaneousProducersConflateBehindOneActualIoRecovery() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val release = CountDownLatch(1)
        try {
            val started = CountDownLatch(1)
            val second = CompletableDeferred<Unit>()
            val calls = AtomicInteger()
            val active = AtomicInteger()
            val maximum = AtomicInteger()
            val requests = UltraRecoveryRequests(scope, recover = {
                val running = active.incrementAndGet()
                maximum.accumulateAndGet(running, ::maxOf)
                try {
                    if (calls.incrementAndGet() == 1) {
                        started.countDown()
                        check(release.await(2, TimeUnit.SECONDS))
                    } else second.complete(Unit)
                } finally { active.decrementAndGet() }
            }, failed = { throw AssertionError(it) })
            requests.request()
            assertTrue(started.await(2, TimeUnit.SECONDS))
            coroutineScope {
                repeat(24) { launch(Dispatchers.Default) { repeat(100) { requests.request() } } }
            }
            assertEquals(1, calls.get())
            release.countDown()
            withTimeout(2_000L) { second.await() }
            assertEquals(2, calls.get())
            assertEquals(1, maximum.get())
        } finally { release.countDown(); scope.cancel() }
    }

    @Test fun parentScopeCancellationStopsTheConsumerAndAllQueuedEvents() = runBlocking {
        val owner = SupervisorJob()
        val scope = CoroutineScope(owner + Dispatchers.Unconfined)
        try {
            val started = CompletableDeferred<Unit>()
            var calls = 0
            val requests = UltraRecoveryRequests(scope, recover = {
                calls++
                started.complete(Unit)
                awaitCancellation()
            }, failed = { throw AssertionError(it) })
            requests.request()
            withTimeout(2_000L) { started.await() }
            requests.request()
            owner.cancelAndJoin()
            requests.request()
            assertEquals(1, calls)
            assertTrue(owner.isCompleted)
        } finally { owner.cancel() }
    }

    @Test fun lateBrokerReadinessRetriesTheWholeRecoverySetupPairChain() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        try {
            val absent = UltraStartupWarmup.Input(null, true, false, false, false, false, false, false)
            val calls = mutableListOf<String>()
            var brokerReady = false
            val results = mutableListOf<UltraStartupWarmup.Result>()
            val requests = UltraRecoveryRequests(scope, recover = {
                results += UltraStartupWarmup.run(absent,
                    setupEnvironment = { calls += "setup" },
                    pairEnvironment = { calls += "pair"; true },
                    retryDetection = { calls += "detect" },
                    recoverIdentity = { calls += "recover"; brokerReady })
            }, failed = { throw AssertionError(it) })
            requests.request()
            assertFalse(results.single().ran)
            brokerReady = true
            requests.request()
            assertTrue(results.last().paired)
            assertEquals(listOf("recover", "recover", "setup", "pair", "detect"), calls)
        } finally { scope.cancel() }
    }

    @Test fun cancelledApplicationScopeDoesNotRunNewWork() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        var calls = 0
        val requests = UltraRecoveryRequests(scope, recover = { calls++ }, failed = { throw AssertionError(it) })
        scope.cancel()
        requests.request()
        assertEquals(0, calls)
    }
}
