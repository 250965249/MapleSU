package dev.maplesu.manager.workmode.detect

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

class SuReadinessCacheTest {
    private val usable = SuProbeDecision.report(listOf(SuProbeAttempt("fixture", SuReadiness.USABLE, 0, 0)))

    @Test fun concurrentStartupCallersExecuteOnlyOneRealProbe() {
        val cache = SuReadinessCache()
        val pool = Executors.newFixedThreadPool(12)
        val entered = CountDownLatch(12)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        try {
            val results = List(12) { pool.submit<SuProbeReport> {
                entered.countDown()
                cache.read(1_500) { calls.incrementAndGet(); release.await(); usable }
            } }
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            Thread.sleep(60)
            release.countDown()
            results.forEach { assertSame(usable, it.get(2, TimeUnit.SECONDS)) }
            assertEquals(1, calls.get())
        } finally { release.countDown(); pool.shutdownNow() }
    }

    @Test fun joiningCallerKeepsItsOwnDeadlineWithoutStartingAnotherProbe() {
        val cache = SuReadinessCache()
        val pool = Executors.newSingleThreadExecutor()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        try {
            val first = pool.submit<SuProbeReport> { cache.read(1_500) { entered.countDown(); release.await(); usable } }
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            val started = System.nanoTime()
            val result = cache.read(30) { error("Duplicate executable probe") }
            assertEquals(SuReadiness.UNKNOWN, result.readiness)
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < 500)
            release.countDown()
            assertSame(usable, first.get(1, TimeUnit.SECONDS))
        } finally { release.countDown(); pool.shutdownNow() }
    }

    @Test fun invalidationDiscardsTheRunningObservationAndDoesNotCacheIt() {
        val cache = SuReadinessCache()
        assertEquals(SuReadiness.UNKNOWN, cache.read(1_500) { cache.invalidate(); usable }.readiness)
        var called = false
        assertSame(usable, cache.read(1_500) { called = true; usable })
        assertTrue(called)
    }

    @Test fun expiredOrInvalidatedObservationsAreReadAgain() {
        var now = 0L
        val cache = SuReadinessCache { now }
        var calls = 0
        fun read() = cache.read(1_500) { calls++; usable }
        read(); now = 1_999_000_000; read(); assertEquals(1, calls)
        now = 2_000_000_000; read(); assertEquals(2, calls)
        cache.invalidate(); read(); assertEquals(3, calls)
    }

    @Test fun aProbeExceptionAllowsTheNextCallerToRetry() {
        val cache = SuReadinessCache()
        try { cache.read(1_500) { error("probe failed") }; fail() } catch (_: IllegalStateException) { }
        assertSame(usable, cache.read(1_500) { usable })
    }
}
