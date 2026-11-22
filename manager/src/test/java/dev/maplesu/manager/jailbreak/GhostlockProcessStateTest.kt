package dev.maplesu.manager.jailbreak

import org.junit.Assert.*
import org.junit.Test

class GhostlockProcessStateTest {
    @Test fun exitCodesDoNotProveDispatch() {
        val state = GhostlockProcessState()
        assertNull(state.failure(null))
        assertEquals("GHOSTLOCK_PROVIDER_EXIT_BEFORE_HANDOVER:64", state.failure(64))
        assertEquals("GHOSTLOCK_PROVIDER_EXIT_BEFORE_HANDOVER:0", state.failure(0))
    }

    @Test fun onlyTheStructuredDispatchTransitionKeepsTheWorkerWaitAlive() {
        val state = GhostlockProcessState()
        state.observe("maplesu downstream dispatched")
        state.observe("\u001eGLK_STATUS w3 completed")
        assertNotNull(state.failure(0))
        state.observe("\u001eGLK_STATUS maplesu_dispatch completed")
        assertNull(state.failure(0))
        assertNull(state.failure(1))
    }

    @Test fun disabledStatusDoesNotPrematurelyCloseARestoringWorker() {
        val state = GhostlockProcessState()
        state.observe("\u001eGLK_STATUS_DISABLED")
        assertNull(state.failure(0))
        assertNotNull(state.failure(1))
    }
}
