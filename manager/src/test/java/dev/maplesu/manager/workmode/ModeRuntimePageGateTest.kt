package dev.maplesu.manager.workmode

import com.maplesu.core.ui.viewmodel.SuperuserStartupLoader
import dev.maplesu.manager.workmode.detect.ModeState
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class ModeRuntimePageGateTest {
    @Before fun before() {
        ModeRuntime.resetForTest()
        ModeRuntime.installBootIdProviderForTest { "boot-1" }
    }
    @After fun after() = ModeRuntime.resetForTest()

    @Test fun completedUnresolvedDetectionStopsSuperuserRefreshWithoutReadingABackend() = runBlocking {
        ModeRuntime.finishDetection()
        var reads = 0
        val loader = SuperuserStartupLoader({ ModeRuntime.active }, { ModeRuntime.awaitPageMode(15_000) })
        assertFalse(withTimeout(1_000) { loader.load({}) { reads++ } })
        assertEquals(0, reads)
        assertNull(ModeRuntime.active)
    }

    @Test fun finishingDetectionReleasesASuperuserPageAlreadyWaitingForMode() = runBlocking {
        var reads = 0
        val loader = SuperuserStartupLoader({ ModeRuntime.active }, { ModeRuntime.awaitPageMode(15_000) })
        val pending = async(start = CoroutineStart.UNDISPATCHED) { loader.load({}) { reads++ } }
        assertFalse(pending.isCompleted)
        ModeRuntime.failBootstrap("MODE_DETECT_FAILED")
        assertFalse(withTimeout(1_000) { pending.await() })
        assertEquals(0, reads)
    }

    @Test fun everyRealActivationReleasesTheSuperuserPageIntoTheCorrectBackend() = runBlocking {
        for (mode in WorkMode.entries) {
            ModeRuntime.resetForTest()
            ModeRuntime.installBootIdProviderForTest { "boot-1" }
            var selected: WorkMode? = null
            val loader = SuperuserStartupLoader({ ModeRuntime.active }, { ModeRuntime.awaitPageMode(15_000) })
            val pending = async(start = CoroutineStart.UNDISPATCHED) { loader.load({}) { selected = it } }
            ModeRuntime.recordDetection(TestFixtures.detection(
                if (mode == WorkMode.LITE) ModeState.MODE_A_ACTIVE else ModeState.MODE_B_ACTIVE))
            assertTrue(ModeRuntime.activate(mode, "boot-1", ActivationSource.BOOT_DETECTION))
            assertTrue(withTimeout(1_000) { pending.await() })
            assertEquals(mode, selected)
        }
    }

    @Test fun pageTimeoutDoesNotCompleteOrInventAnActivation() = runBlocking {
        assertNull(ModeRuntime.awaitPageMode(20))
        assertFalse(ModeRuntime.detectionComplete)
        assertNull(ModeRuntime.active)
    }

    @Test fun aPageOpenedBeforePhaseTwoStartsSeesTheNewDetectionComplete() = runBlocking {
        val pending = async(start = CoroutineStart.UNDISPATCHED) { ModeRuntime.awaitPageMode(15_000) }
        ModeRuntime.beginDetection()
        ModeRuntime.finishDetection()
        assertNull(withTimeout(1_000) { pending.await() })
    }

    @Test fun phaseTwoActivationReleasesAPageWaitingBeforeDetectionStarted() = runBlocking {
        val pending = async(start = CoroutineStart.UNDISPATCHED) { ModeRuntime.awaitPageMode(15_000) }
        ModeRuntime.beginDetection()
        ModeRuntime.recordDetection(TestFixtures.detection(ModeState.MODE_A_ACTIVE))
        assertTrue(ModeRuntime.activate(WorkMode.LITE, "boot-1", ActivationSource.BOOT_DETECTION))
        assertEquals(WorkMode.LITE, withTimeout(1_000) { pending.await() })
    }

    @Test fun pageCancellationPreservesTheSharedDetection() = runBlocking {
        val pending = async(start = CoroutineStart.UNDISPATCHED) { ModeRuntime.awaitPageMode(15_000) }
        pending.cancelAndJoin()
        assertTrue(pending.isCancelled)
        assertFalse(ModeRuntime.detectionComplete)
    }

    @Test fun completedPageDetectionDoesNotReleaseTheBootActivationGate() = runBlocking {
        val boot = async(start = CoroutineStart.UNDISPATCHED) { ModeRuntime.awaitActivated(15_000) }
        ModeRuntime.finishDetection()
        assertNull(ModeRuntime.awaitPageMode(15_000))
        assertFalse(boot.isCompleted)
        ModeRuntime.beginDetection()
        ModeRuntime.recordDetection(TestFixtures.detection(ModeState.MODE_A_ACTIVE))
        assertTrue(ModeRuntime.activate(WorkMode.LITE, "boot-1", ActivationSource.BOOT_DETECTION))
        assertEquals(WorkMode.LITE, withTimeout(1_000) { boot.await() })
    }
}
