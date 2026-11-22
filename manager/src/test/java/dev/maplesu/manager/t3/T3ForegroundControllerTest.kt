package dev.maplesu.manager.t3

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class T3ForegroundControllerTest {
    private fun cachedStore() = object : T3AccountStore {
        override fun read() = T3Session("account", "identity", "state")
        override fun write(session: T3Session) = Unit
    }

    @Test fun repeatedStartAndLifecycleResumeKeepOneHeartbeatLoop() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val ticks = Channel<Unit>(Channel.UNLIMITED)
        var heartbeats = 0
        val client = T3AccountClient(T3Transport { operation, _ ->
            if (operation == T3Operation.HEARTBEAT) heartbeats++
            T3Response(200)
        }, cachedStore(), { error("cache expected") }, { "kernel model" })
        val controller = T3ForegroundController(scope, client, Dispatchers.Unconfined) { ticks.receive() }
        try {
            controller.start()
            controller.start()
            assertEquals(1, heartbeats)
            ticks.trySend(Unit)
            assertEquals(2, heartbeats)
            controller.stop()
            controller.stop()
            assertEquals(2, heartbeats)
            controller.start()
            controller.start()
            assertEquals(3, heartbeats)
            ticks.trySend(Unit)
            assertEquals(4, heartbeats)
        } finally {
            controller.stop()
            scope.cancel()
        }
    }

    @Test fun heartbeatUsesFixedMinuteBoundariesWithoutAddingNetworkDuration() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val ticks = Channel<Unit>(Channel.UNLIMITED)
        var now = 0L
        var requestDuration = 10_000L
        val starts = mutableListOf<Long>()
        val waits = mutableListOf<Long>()
        val client = T3AccountClient(T3Transport { operation, _ ->
            if (operation == T3Operation.HEARTBEAT) {
                starts += now
                now += requestDuration
            }
            T3Response(200)
        }, cachedStore(), { "identity" }, { "kernel model" })
        val controller = T3ForegroundController(scope, client, Dispatchers.Unconfined, { now }) { duration ->
            waits += duration
            now += duration
            ticks.receive()
        }
        try {
            controller.start()
            ticks.trySend(Unit)
            requestDuration = 75_000L
            ticks.trySend(Unit)
            ticks.trySend(Unit)
            assertEquals(listOf(0L, 60_000L, 120_000L, 240_000L), starts)
            assertEquals(listOf(50_000L, 50_000L, 45_000L, 45_000L), waits)
        } finally {
            controller.stop()
            scope.cancel()
        }
    }

    @Test fun stopInterruptsBlockingRequestAndResumeWaitsForItsCleanup() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val firstStarted = CountDownLatch(1)
        val firstInterrupted = CountDownLatch(1)
        val allowCleanup = CountDownLatch(1)
        val secondStarted = CountDownLatch(1)
        val calls = AtomicInteger()
        val active = AtomicInteger()
        val maximumActive = AtomicInteger()
        val notices = AtomicInteger()
        val cancelledNotices = AtomicInteger()
        val client = T3AccountClient(T3Transport { operation, _ ->
            if (operation == T3Operation.HEARTBEAT) {
                val current = active.incrementAndGet()
                maximumActive.accumulateAndGet(current, ::maxOf)
                try {
                    if (calls.incrementAndGet() == 1) {
                        firstStarted.countDown()
                        try {
                            CountDownLatch(1).await()
                        } catch (interrupted: InterruptedException) {
                            firstInterrupted.countDown()
                            allowCleanup.await()
                            throw interrupted
                        }
                    } else {
                        secondStarted.countDown()
                    }
                } finally {
                    active.decrementAndGet()
                }
            }
            if (operation == T3Operation.NOTICE) {
                notices.incrementAndGet()
                if (calls.get() == 1) cancelledNotices.incrementAndGet()
            }
            T3Response(200)
        }, cachedStore(), { "identity" }, { "kernel model" })
        val controller = T3ForegroundController(scope, client)
        try {
            controller.start()
            assertTrue("first request started", firstStarted.await(3, TimeUnit.SECONDS))
            controller.stop()
            assertTrue("blocked transport interrupted", firstInterrupted.await(3, TimeUnit.SECONDS))
            controller.start()
            controller.start()
            assertFalse("resume waits for old request cleanup", secondStarted.await(100, TimeUnit.MILLISECONDS))
            allowCleanup.countDown()
            assertTrue("resumed request started", secondStarted.await(3, TimeUnit.SECONDS))
            assertEquals(1, maximumActive.get())
            assertEquals(2, calls.get())
            assertEquals(0, cancelledNotices.get())
            assertTrue("cancelled cycle did not fetch notice", notices.get() <= 1)
        } finally {
            allowCleanup.countDown()
            controller.stop()
            scope.cancel()
        }
    }
}
