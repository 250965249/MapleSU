package dev.maplesu.manager.jailbreak

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * M1 (report `maplesu-ultra-attestation-stability-2026-10-31.md` §5): the accept with a
 * deadline.
 *
 * <p>`LocalServerSocket.accept()` has no timeout. The old listener checked its deadline
 * only *between* accepts, so a socket nobody connected to held its thread - and, through
 * the binder claim, the whole `am instrument` run - until the host's 600 s timeout
 * (regression-1). These tests pin the contract the listener relies on: with no client,
 * [boundedAccept] returns null *at* the deadline, not after the accept eventually
 * returns; and it never lets an exception out, because the caller's fallback is the
 * record on disk.
 */
class HookAttestBoundedAcceptTest {

    @Test
    fun `a listener nobody connects to returns at the deadline, not later`() {
        val timeout = 200L
        val timeouts = AtomicInteger()
        val started = System.nanoTime()
        val result = boundedAccept(
            acceptor = {
                // Stands in for accept() on a socket nobody connects to: it would block
                // here for a minute if the deadline were not enforced.
                Thread.sleep(60_000)
                "client"
            },
            timeoutMillis = timeout,
            onTimeout = { timeouts.incrementAndGet() },
        )
        val elapsedMillis = (System.nanoTime() - started) / 1_000_000
        assertNull(result)
        assertTrue("returned after " + elapsedMillis + "ms, budget was " + timeout + "ms",
            elapsedMillis <= timeout + 200)
        assertEquals("the timeout path must close the listener exactly once",
            1, timeouts.get())
    }

    @Test
    fun `an accept that answers immediately is returned`() {
        assertEquals("client",
            boundedAccept(acceptor = { "client" }, timeoutMillis = 1_000))
    }

    @Test
    fun `a failed accept is null, never an exception`() {
        assertNull(boundedAccept(
            acceptor = { throw java.io.IOException("EBADF") },
            timeoutMillis = 1_000))
    }

    @Test
    fun `a zero budget does not even start the accept`() {
        val called = AtomicBoolean(false)
        assertNull(boundedAccept(
            acceptor = { called.set(true); "client" },
            timeoutMillis = 0))
        assertTrue("a zero budget must not run the acceptor", !called.get())
    }

    @Test
    fun `the timeout callback runs after the wait, not before`() {
        val observed = AtomicInteger(-1)
        val elapsedAtClose = AtomicInteger(-1)
        val started = System.nanoTime()
        boundedAccept(
            acceptor = { Thread.sleep(60_000); "client" },
            timeoutMillis = 150,
            onTimeout = {
                observed.set(1)
                elapsedAtClose.set(((System.nanoTime() - started) / 1_000_000).toInt())
            },
        )
        assertEquals(1, observed.get())
        assertTrue("the listener must be closed at the deadline, was " +
            elapsedAtClose.get() + "ms", elapsedAtClose.get() >= 100)
    }
}
