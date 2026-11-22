package dev.maplesu.manager.workmode.service

import android.os.IBinder
import java.io.Closeable
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Proxy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class ModeSwitchRootBridgeOwnerTest {
    @Test fun independentIdleManagerProcessesCanBothUseTheRootBridge() = Fixture().use {
        it.claim(Manager())
        it.claim(Manager())
        assertFalse(it.lease.isHeld())
    }

    @Test fun theActiveLeaseStaysWithItsLiveManagerAcrossConnections() = Fixture().use {
        val manager = Manager()
        it.claim(manager)
        it.hold()
        it.claim(manager)
        val busy = assertThrows(IllegalStateException::class.java) { it.claim(Manager()) }
        assertEquals(ModeSwitchRootLease.BUSY, busy.message)
        assertTrue(it.lease.isHeld())
        assertEquals(0, it.releases)
    }

    @Test fun aStaleManagersDeathDoesNotCloseTheCurrentManagersLease() = Fixture().use {
        val old = Manager()
        it.claim(old)
        it.claim(Manager())
        it.hold()
        old.die()
        it.drain()
        assertTrue(it.lease.isHeld())
        assertEquals(0, it.releases)
    }

    @Test fun aDeadManagerReleasesItsLockAndTheNextProcessCanResume() = Fixture().use {
        val old = Manager()
        it.claim(old)
        it.hold()
        old.die()
        it.drain()
        assertFalse(it.lease.isHeld())
        assertEquals(1, it.releases)
        it.claim(Manager())
        assertEquals(1, it.releases)
    }

    @Test fun aManagerDeathWaitsForTheAcceptedOperationBeforeReleasingItsLock() = Fixture().use {
        val manager = Manager()
        it.claim(manager)
        it.hold()
        val started = CountDownLatch(1)
        val finish = CountDownLatch(1)
        val operation = it.worker.submit {
            started.countDown()
            check(finish.await(2, TimeUnit.SECONDS))
            assertTrue(it.lease.isHeld())
        }
        try {
            assertTrue(started.await(2, TimeUnit.SECONDS))
            manager.die()
            assertTrue(it.lease.isHeld())
            assertEquals(0, it.releases)
        } finally { finish.countDown() }
        operation.get(2, TimeUnit.SECONDS)
        it.drain()
        assertFalse(it.lease.isHeld())
        assertEquals(1, it.releases)
    }

    /** Test the actual private owner branch without invoking Android socket or file APIs. */
    private class Fixture : Closeable {
        private val bridge = ModeSwitchRootBridge(10411, "/unused")
        private val claim = bridge.javaClass.getDeclaredMethod("claimManager", IBinder::class.java)
            .apply { isAccessible = true }
        val lease = bridge.javaClass.getDeclaredField("lease").apply { isAccessible = true }.get(bridge)
            as ModeSwitchRootLease
        private val held = lease.javaClass.getDeclaredField("held").apply { isAccessible = true }
        val worker = bridge.javaClass.getDeclaredField("worker").apply { isAccessible = true }.get(bridge)
            as ExecutorService
        var releases = 0
            private set
        fun claim(manager: Manager) {
            try { claim.invoke(bridge, manager.binder) }
            catch (error: InvocationTargetException) { throw error.cause ?: error }
        }
        fun hold() = held.set(lease, Closeable { releases++ })
        fun drain() { worker.submit {}.get(2, TimeUnit.SECONDS) }
        override fun close() {
            bridge.close()
            assertTrue(worker.awaitTermination(2, TimeUnit.SECONDS))
        }
    }

    private class Manager {
        private var alive = true
        private val deaths = mutableListOf<IBinder.DeathRecipient>()
        val binder = Proxy.newProxyInstance(IBinder::class.java.classLoader,
            arrayOf(IBinder::class.java)) { instance, method, arguments ->
            when (method.name) {
                "isBinderAlive", "pingBinder" -> alive
                "equals" -> instance === arguments?.get(0)
                "hashCode" -> System.identityHashCode(instance)
                "linkToDeath" -> { deaths += arguments!![0] as IBinder.DeathRecipient; null }
                "unlinkToDeath" -> deaths.remove(arguments!![0])
                else -> null
            }
        } as IBinder
        fun die() {
            alive = false
            deaths.toList().forEach { it.binderDied() }
        }
    }
}
