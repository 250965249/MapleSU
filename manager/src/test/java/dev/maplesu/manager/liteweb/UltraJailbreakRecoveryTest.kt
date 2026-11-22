package dev.maplesu.manager.liteweb

import dev.maplesu.manager.litehidden.ParasiteMarkers
import dev.maplesu.manager.litehidden.RecoveryIdentity
import dev.maplesu.manager.runtime.RootExecResult
import org.junit.Assert.assertFalse
import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.ModeState
import org.junit.Assert.assertEquals
import org.junit.Test

class UltraJailbreakRecoveryTest {
    @Test fun verifiedUltraHookUsesTheExistingRecoveryDaemon() {
        assertEquals(LiteWebStartStrategy.ULTRA_ENV_DAEMON,
            LiteWebBackendPolicy.strategy(WorkMode.LITE, RootBackend.HOOK))
    }

    @Test fun recoveredUltraHookCanPrepareBeforeModeActivation() {
        val evidence = LiteWebBackendPolicy.hasLiteEvidence(RootBackend.HOOK, ModeState.MODE_A_ACTIVE)
        assertEquals(LiteWebStartStrategy.ULTRA_ENV_DAEMON,
            LiteWebBackendPolicy.strategy(null, RootBackend.HOOK, evidence))
    }

    @Test fun normalModeNeverStartsTheUltraDaemon() {
        assertEquals(LiteWebStartStrategy.UNAVAILABLE,
            LiteWebBackendPolicy.strategy(WorkMode.KSU, RootBackend.HOOK, true))
    }

    @Test fun customPortUsesAuthenticatedDaemonReceiptRatherThanCandidateScan() {
        val result = daemon("LITEWEB_DAEMON_STARTED port=29483").startForApk("/data/app/base.apk", identity)
        assertEquals(true, result.started)
        assertEquals(29483, result.port)
    }

    @Test fun malformedOrAmbiguousPortReceiptNeverReportsReady() {
        for (receipt in listOf("LITEWEB_DAEMON_STARTED", "LITEWEB_DAEMON_STARTED port=0",
                "LITEWEB_DAEMON_STARTED port=65536", "LITEWEB_DAEMON_STARTED port=29483 garbage",
                "LITEWEB_DAEMON_STARTED port=29483\nLITEWEB_DAEMON_STARTED port=18427")) {
            assertFalse(receipt, daemon(receipt).startForApk("/data/app/base.apk", identity).started)
        }
    }

    @Test fun normalKernelNeverBecomesUltraEvidenceWhileModeIsUnresolved() {
        assertFalse(LiteWebBackendPolicy.hasLiteEvidence(RootBackend.KSU, null))
        assertFalse(LiteWebBackendPolicy.hasLiteEvidence(RootBackend.KSU, ModeState.MODE_A_ACTIVE))
    }

    private val identity = RecoveryIdentity("0123456789abcdef", "dev.maplesu.manager", 10123)
    private fun daemon(receipt: String) = RootCmdUltraEnvLiteWebDaemon(
        execute = { RootExecResult(RootBackend.HOOK, 0, "${ParasiteMarkers.IDENTITY_OK}\n$receipt\n") },

    )
}
