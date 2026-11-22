package dev.maplesu.manager.runtime

import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.*
import org.junit.Test

class HookSuLifetimePolicyTest {
    private val ready = JailbreakStatus("dirtyfrag", JailbreakStatus.STAGE_DAEMON_READY,
        "verified", 1L, 2L, "boot", "attempt", rootBackend = JailbreakRequest.BACKEND_HOOK)

    @Test fun onlyCurrentReadyHookCanRetainPublication() {
        assertTrue(hookPublicationMayStayAlive(ready, "boot", WorkMode.LITE))
        assertTrue(hookPublicationMayStayAlive(ready, "boot", null))
    }

    @Test fun normalAndOtherBackendsNeverRetainHookPublication() {
        assertFalse(hookPublicationMayStayAlive(ready, "boot", WorkMode.KSU))
        for (backend in listOf(null, JailbreakRequest.BACKEND_KSU, "ir")) {
            assertFalse(hookPublicationMayStayAlive(ready.copy(rootBackend = backend), "boot", WorkMode.LITE))
        }
    }

    @Test fun staleMissingAndFailedClaimsNeverRetainPublication() {
        assertFalse(hookPublicationMayStayAlive(null, "boot", WorkMode.LITE))
        assertFalse(hookPublicationMayStayAlive(ready, "new-boot", WorkMode.LITE))
        assertFalse(hookPublicationMayStayAlive(ready.copy(bootId = null), null, WorkMode.LITE))
        assertFalse(hookPublicationMayStayAlive(ready.copy(attemptId = null), "boot", WorkMode.LITE))
        assertFalse(hookPublicationMayStayAlive(ready.copy(failure = "failed"), "boot", WorkMode.LITE))
        assertFalse(hookPublicationMayStayAlive(ready.copy(stage = JailbreakStatus.STAGE_CANCELLED), "boot", WorkMode.LITE))
    }
}
