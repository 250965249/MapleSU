package dev.maplesu.manager.workmode.boot

import dev.maplesu.manager.workmode.ActivationSource
import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test

class ModeBootstrapDeadlineTest {
    private class Runtime : ModeRuntimePort {
        val calls = mutableListOf<String>()
        override fun recordDetection(result: DetectionResult) { calls += "record" }
        override fun completeBootstrap(result: DetectionResult) { calls += "complete" }
        override fun activate(mode: WorkMode, bootId: String, source: ActivationSource): Boolean {
            calls += "activate"; return true
        }
        override fun failBootstrap(code: String) { calls += code }
    }

    @Test fun timedOutDetectorNeverPublishesOrActivatesItsLateResult() = runBlocking {
        val release = CountDownLatch(1)
        val exited = CountDownLatch(1)
        val runtime = Runtime()
        val detector = object : ModeDetector {
            override suspend fun detect(request: DetectionRequest): DetectionResult {
                try { awaitIgnoringInterrupts(release) } finally { exited.countDown() }
                return TestFixtures.detection(ModeState.MODE_A_ACTIVE)
            }
        }
        val pipeline = ModeBootstrapPipeline(detector, runtime)
        try {
            val outcome = withTimeout(1_000) { pipeline.run(request()) }
            assertEquals("MODE_DETECT_TIMEOUT", (outcome as BootstrapOutcome.Failed).code)
            assertEquals("MODE_DETECT_BUSY", (pipeline.run(request()) as BootstrapOutcome.Failed).code)
            assertEquals(listOf("MODE_DETECT_TIMEOUT", "MODE_DETECT_BUSY"), runtime.calls)
        } finally { release.countDown() }
        assertTrue(exited.await(1, TimeUnit.SECONDS))
        assertFalse(runtime.calls.any { it == "activate" || it == "record" || it == "complete" })
    }

    @Test fun cancelledPipelineLeavesRuntimeUntouched() = runBlocking {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val runtime = Runtime()
        val pipeline = ModeBootstrapPipeline(object : ModeDetector {
            override suspend fun detect(request: DetectionRequest): DetectionResult {
                entered.countDown(); awaitIgnoringInterrupts(release)
                return TestFixtures.detection(ModeState.MODE_A_ACTIVE)
            }
        }, runtime)
        val job = async(Dispatchers.Default) { pipeline.run(request().copy(timeoutMillis = 10_000)) }
        try {
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            withTimeout(1_000) { job.cancelAndJoin() }
            assertTrue(job.isCancelled)
            assertTrue(runtime.calls.isEmpty())
        } finally { release.countDown() }
    }

    @Test fun missingPipelineProducesRetryableFailure() = runBlocking {
        val coordinator = ModeBootstrapCoordinator(pipelineProvider = { null })
        repeat(2) {
            assertEquals("MODE_PIPELINE_UNAVAILABLE", (coordinator.runPhaseTwo() as BootstrapOutcome.Failed).code)
        }
    }

    @Test fun coordinatorPropagatesCancellationAndReleasesPhaseTwoClaim() = runBlocking {
        var cancelled = true
        val coordinator = ModeBootstrapCoordinator(pipelineProvider = {
            if (cancelled) throw CancellationException("cancelled")
            null
        })
        try { coordinator.runPhaseTwo(); fail("Cancellation must propagate") }
        catch (_: CancellationException) { }
        cancelled = false
        assertTrue(coordinator.runPhaseTwo() is BootstrapOutcome.Failed)
    }

    @Test fun providerExceptionProducesFailureInsteadOfMissingOutcome() = runBlocking {
        val coordinator = ModeBootstrapCoordinator(pipelineProvider = { error("unavailable") })
        assertEquals("MODE_BOOTSTRAP_FAILED", (coordinator.runPhaseTwo() as BootstrapOutcome.Failed).code)
    }

    private fun request() = DetectionRequest(DetectionOrigin.STARTUP, false, false, timeoutMillis = 50)
    private fun awaitIgnoringInterrupts(latch: CountDownLatch) {
        while (true) {
            try { latch.await(); return } catch (_: InterruptedException) { }
        }
    }
}
