package dev.maplesu.manager.workmode.detect

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Shares the short-lived executable SU observation across startup callers. */
internal class SuReadinessCache(private val now: () -> Long = System::nanoTime) {
    private var cached: Pair<Long, SuProbeReport>? = null
    private var revision = 0L
    private class Flight(val revision: Long, val result: CompletableFuture<SuProbeReport> = CompletableFuture())
    private var inFlight: Flight? = null

    @Synchronized fun invalidate() { revision++; cached = null }

    fun read(budgetMillis: Long, probe: () -> SuProbeReport): SuProbeReport {
        val deadline = System.nanoTime() + budgetMillis.coerceAtLeast(1) * 1_000_000L
        var owner = false
        val flight = synchronized(this) {
            cached?.let { if (now() - it.first in 0 until 2_000_000_000L) return it.second }
            inFlight ?: Flight(revision).also { inFlight = it; owner = true }
        }
        if (!owner) return try {
            flight.result.get((deadline - System.nanoTime()).coerceAtLeast(0), TimeUnit.NANOSECONDS)
        } catch (_: TimeoutException) {
            unknown()
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            unknown()
        } catch (error: ExecutionException) {
            throw error.cause ?: error
        }
        try {
            val observed = probe()
            val result = synchronized(this) {
                inFlight = null
                if (flight.revision == revision) observed.also { cached = now() to it } else unknown()
            }
            flight.result.complete(result)
            return result
        } catch (error: Throwable) {
            synchronized(this) { inFlight = null }
            flight.result.completeExceptionally(error)
            throw error
        }
    }

    private fun unknown() = SuProbeReport(SuReadiness.UNKNOWN)
}
