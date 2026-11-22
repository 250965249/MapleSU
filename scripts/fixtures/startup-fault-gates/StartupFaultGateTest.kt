package dev.maplesu.manager.runtime.ultra

import android.content.Context
import com.maplesu.core.KernelSUApplication
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.boot.ModeBootstrapFixture
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class StartupFaultGateTest {
    private val context = Context()
    private val fault = UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Fault)
    private val running = UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running)
    @Before fun reset() = Fixture.reset()
    private fun startup() = runBlocking { KernelSUApplication().runRecovery() }

    @Test fun sameKeyAndBootFaultStopsBeforeAnyRestoreOrSdkCall() {
        Fixture.observe(fault)
        assertTrue(UltraIdentityRecovery.blocked(context))
        assertEquals("RECOVERY_SUSPENDED", UltraIdentityRecovery.recover(context))
        assertEquals(emptyList<String>(), Fixture.calls)
    }

    @Test fun faultAlsoStopsTheEarlyTemporarySessionBranch() {
        Fixture.session = "fixture-session-key"
        Fixture.observe(fault)
        assertEquals("RECOVERY_SUSPENDED", UltraIdentityRecovery.recover(context))
        assertEquals(emptyList<String>(), Fixture.calls)
    }

    @Test fun changedKeyDoesNotInheritAHistoricalFault() {
        Fixture.observe(fault)
        Fixture.key = "fixture-key-b"
        assertFalse(UltraIdentityRecovery.blocked(context))
        assertEquals("RECOVERY_ROOT_NOT_VERIFIED", UltraIdentityRecovery.recover(context))
        assertEquals(listOf("restore"), Fixture.calls)
    }

    @Test fun changedBootDoesNotInheritAHistoricalFault() {
        Fixture.observe(fault)
        Fixture.boot = "fixture-boot-b"
        assertFalse(UltraIdentityRecovery.blocked(context))
        assertEquals("RECOVERY_ROOT_NOT_VERIFIED", UltraIdentityRecovery.recover(context))
        assertEquals(listOf("restore"), Fixture.calls)
    }

    @Test fun absentKeyStillReachesIdentityRecovery() {
        Fixture.observe(fault)
        Fixture.key = null
        assertFalse(UltraIdentityRecovery.blocked(context))
        assertEquals("RECOVERY_ROOT_NOT_VERIFIED", UltraIdentityRecovery.recover(context))
        assertEquals(listOf("restore"), Fixture.calls)
    }

    @Test fun rootCandidateProofDoesNotWriteAPersistentLogPolicy() {
        for (uid in listOf(null, 1, 0)) {
            Fixture.calls.clear(); Fixture.uid = uid
            assertEquals(uid, UltraIdentityRecovery.candidateUid("fixture-candidate"))
            assertEquals(listOf("uid"), Fixture.calls)
        }
    }

    @Test fun historicalPairingDoesNotPermitLoggingWithUnknownOrFaultEvidence() {
        Fixture.pair = true
        for (observation in listOf(UltraEnvironmentProbe.Snapshot(), fault)) {
            Fixture.calls.clear(); Fixture.observe(observation)
            startup()
            assertFalse(Fixture.calls.toString(), "persistent-log" in Fixture.calls)
        }
    }

    @Test fun successfulPairingWritesOnlyAfterTheScopedRootObservation() {
        Fixture.pair = true; Fixture.pairedObservation = running
        startup()
        assertEquals(listOf("restore", "setup", "pair", "persistent-log"), Fixture.calls)
    }

    @Test fun verifiedKernelRootStillPermitsLoggingWhenTheHelperIsUnresolved() {
        for (state in listOf(UltraEnvironmentProbe.State.Unknown, UltraEnvironmentProbe.State.NotInstalled)) {
            Fixture.calls.clear(); Fixture.observe(UltraEnvironmentProbe.Snapshot())
            Fixture.pair = true
            Fixture.pairedObservation = UltraEnvironmentProbe.Snapshot(state, kernelRootVerified = true)
            startup()
            assertEquals(listOf("restore", "setup", "pair", "persistent-log"), Fixture.calls)
        }
    }

    @Test fun aTemporarySessionDoesNotWriteUsingTheHistoricalPermanentKey() {
        Fixture.session = "fixture-session-key"; Fixture.ready = true
        Fixture.observe(running)
        startup()
        assertEquals(listOf("setup", "boot-ready"), Fixture.calls)
    }

    @Test fun unsuccessfulWarmupDoesNotWriteEvenWithHistoricalRunningEvidence() {
        Fixture.observe(running)
        startup()
        assertEquals(listOf("restore", "setup", "pair"), Fixture.calls)
    }

    @Test fun ksuOwnershipDoesNotWriteUsingHistoricalUltraEvidence() {
        Fixture.observe(running); ModeRuntime.active = WorkMode.KSU
        startup()
        assertEquals(emptyList<String>(), Fixture.calls)
    }

    @Test fun unresolvedDetectionDoesNotWriteBeforeIdentityRecovery() {
        ModeRuntime.active = null; ModeRuntime.detectionComplete = false
        startup()
        assertEquals(listOf("await-detection", "restore"), Fixture.calls)
    }

    @Test fun acceptedIdentityReusesTheValidSameKeyAndBootObservation() {
        Fixture.observe(running.copy(observedAtElapsedMs = 0))
        repeat(3) { UltraIdentityRecovery.accept(context, Fixture.key!!) }
        assertEquals(listOf("maintenance", "maintenance", "maintenance"), Fixture.calls)
    }

    @Test fun acceptedIdentityWithAChangedKeyPerformsOneNewEnvironmentQuery() {
        Fixture.observe(running.copy(observedAtElapsedMs = 0))
        Fixture.key = "fixture-key-b"
        repeat(2) { UltraIdentityRecovery.accept(context, Fixture.key!!) }
        assertEquals(listOf("environment-jni", "maintenance", "maintenance"), Fixture.calls)
        assertEquals(Fixture.key, UltraEnvironmentProbe.snapshotKey)
    }

    @Test fun acceptedIdentityWithAChangedBootPerformsOneNewEnvironmentQuery() {
        Fixture.observe(running.copy(observedAtElapsedMs = 0))
        Fixture.boot = "fixture-boot-b"
        repeat(2) { UltraIdentityRecovery.accept(context, Fixture.key!!) }
        assertEquals(listOf("environment-jni", "maintenance", "maintenance"), Fixture.calls)
        assertEquals(Fixture.boot, UltraEnvironmentProbe.snapshotBootId)
    }

    @Test fun expiredEvidenceStillPerformsOneQueryBeforeItIsReused() {
        Fixture.observe(running.copy(observedAtElapsedMs = 0))
        android.os.SystemClock.now = 3_000
        repeat(2) { UltraIdentityRecovery.accept(context, Fixture.key!!) }
        assertEquals(listOf("environment-jni", "maintenance", "maintenance"), Fixture.calls)
    }

    @Test fun pairedFirstFrameReusesFreshEvidenceBeforeFullDetection() {
        ModeRuntime.active = null; Fixture.key = "A".repeat(48); Fixture.pair = true
        Fixture.observe(running.copy(observedAtElapsedMs = 0))
        ModeBootstrapFixture().onManagerFirstFrame(context)
        assertEquals(emptyList<String>(), Fixture.calls)
    }

    @Test fun pairedFirstFrameDoesNotInheritEvidenceFromAnotherKeyOrBoot() {
        ModeRuntime.active = null; Fixture.key = "A".repeat(48); Fixture.pair = true
        Fixture.observe(running.copy(observedAtElapsedMs = 0))
        Fixture.key = "B".repeat(48)
        ModeBootstrapFixture().onManagerFirstFrame(context)
        assertEquals(listOf("environment-jni"), Fixture.calls)
        Fixture.calls.clear(); Fixture.boot = "fixture-boot-b"
        ModeBootstrapFixture().onManagerFirstFrame(context)
        assertEquals(listOf("environment-jni"), Fixture.calls)
    }
}
