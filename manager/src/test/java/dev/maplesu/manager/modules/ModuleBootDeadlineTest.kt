package dev.maplesu.manager.modules

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

class ModuleBootDeadlineTest {
    @Test fun aCancelledTimerAlreadyDispatchedForThePreviousStepCannotStopTheNextStep() {
        val callbacks = mutableListOf<Runnable>()
        val timer = object : ScheduledThreadPoolExecutor(1) {
            override fun schedule(command: Runnable, delay: Long, unit: TimeUnit): ScheduledFuture<*> {
                callbacks += command
                return super.schedule({}, 1, TimeUnit.DAYS)
            }
        }
        var ends = 0
        val deadline = ModuleBootDeadline({ ends++ }, timer)
        try {
            deadline.step("first", 1_000) { Unit }
            assertEquals("second", deadline.step("second", 1_000) {
                callbacks.first().run()
                "second"
            })
            assertEquals(0, ends)
        } finally { deadline.close() }
        assertEquals(1, ends)
    }

    @Test fun stuckRootPreparationEndsTheForegroundLifetimeWithoutWaitingForRoot() {
        val finished = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        var stage: String? = null
        val deadline = ModuleBootDeadline({ stage = it; calls.incrementAndGet(); finished.countDown() })
        val worker = Executors.newSingleThreadExecutor()
        try {
            val task = worker.submit { deadline.step("prepare", 100) { release.await(3, TimeUnit.SECONDS) } }
            assertTrue(finished.await(1, TimeUnit.SECONDS))
            assertEquals("prepare", stage)
            assertFalse(task.isDone)
            deadline.close()
            assertEquals(1, calls.get())
            release.countDown()
        } finally { release.countDown(); deadline.close(); worker.shutdownNow() }
    }

    @Test fun normalCompletionDisarmsTheTimerAndFinishesOnce() {
        val finished = CountDownLatch(1)
        val calls = AtomicInteger()
        var stage: String? = "unexpected"
        val deadline = ModuleBootDeadline({ stage = it; calls.incrementAndGet(); finished.countDown() })
        assertEquals(17, deadline.step("service", 200) { 17 })
        assertFalse(finished.await(300, TimeUnit.MILLISECONDS))
        deadline.close(); deadline.close()
        assertEquals(1, calls.get())
        assertNull(stage)
    }

    @Test fun failedStepsDisarmTheirDeadlineAndTheNextStageCanRun() {
        var ends = 0
        val deadline = ModuleBootDeadline({ ends++ })
        try {
            try { deadline.step("broken-module", 1_000) { error("module failed") }; fail() }
            catch (_: IllegalStateException) { }
            assertEquals("ok", deadline.step("next-module", 1_000) { "ok" })
            assertEquals(0, ends)
        } finally { deadline.close() }
        assertEquals(1, ends)
    }
}
