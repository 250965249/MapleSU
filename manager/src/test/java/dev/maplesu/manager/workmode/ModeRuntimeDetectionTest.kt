package dev.maplesu.manager.workmode

import dev.maplesu.manager.workmode.detect.ModeState
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Before
import org.junit.Assert.*
import org.junit.Test

class ModeRuntimeDetectionTest {
    @Before fun before() = ModeRuntime.resetForTest()
    @After fun after() = ModeRuntime.resetForTest()

    @Test fun unfinishedDetectionHasNoInventedMode() = runBlocking {
        assertFalse(ModeRuntime.awaitDetectionSettled(1))
        assertFalse(ModeRuntime.detectionComplete)
        assertNull(ModeRuntime.active)
    }

    @Test fun completedUnresolvedDetectionReleasesWaiters() = runBlocking {
        ModeRuntime.finishDetection()
        assertTrue(ModeRuntime.awaitDetectionSettled(1))
        assertNull(ModeRuntime.active)
        assertEquals(1L, ModeRuntime.detectionRevision.value)
    }

    @Test fun failedDetectionRetainsReasonWithoutActivating() = runBlocking {
        ModeRuntime.failBootstrap("MODE_DETECT_TIMEOUT")
        assertTrue(ModeRuntime.awaitDetectionSettled(1))
        assertEquals("MODE_DETECT_TIMEOUT", ModeRuntime.detectionFailure)
        assertNull(ModeRuntime.active)
        assertNull(ModeRuntime.latestDetection)
    }

    @Test fun retryStartsANewWaitAndSuccessfulResultClearsFailure() = runBlocking {
        ModeRuntime.failBootstrap("MODE_DETECT_TIMEOUT")
        ModeRuntime.beginDetection()
        assertFalse(ModeRuntime.detectionComplete)
        assertNull(ModeRuntime.detectionFailure)
        ModeRuntime.installBootIdProviderForTest { "boot-1" }
        ModeRuntime.recordDetection(TestFixtures.detection(ModeState.MODE_A_ACTIVE))
        assertTrue(ModeRuntime.activate(WorkMode.LITE, "boot-1", ActivationSource.BOOT_DETECTION))
        assertTrue(ModeRuntime.awaitDetectionSettled(1))
        assertEquals(WorkMode.LITE, ModeRuntime.active)
        assertEquals(2L, ModeRuntime.detectionRevision.value)
    }

    @Test fun resetRemovesCompletionAndFailure() {
        ModeRuntime.failBootstrap("MODE_DETECT_FAILED")
        ModeRuntime.resetForTest()
        assertFalse(ModeRuntime.detectionComplete)
        assertNull(ModeRuntime.detectionFailure)
        assertEquals(0L, ModeRuntime.detectionRevision.value)
    }
}
