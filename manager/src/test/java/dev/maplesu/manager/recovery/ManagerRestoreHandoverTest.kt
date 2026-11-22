package dev.maplesu.manager.recovery

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class ManagerRestoreHandoverTest {
    @get:Rule val temp = TemporaryFolder()
    private fun ticket() = File(temp.root, "manager-restore.ticket")
    private fun nonce() = ticket().readText().trim().substringAfter(':')

    @Test fun processDeathRetainsTheSamePendingSession() {
        assertTrue(ManagerRestoreHandover(ticket()).prepare().ok)
        val previous = nonce()
        val restarted = ManagerRestoreHandover(ticket())
        assertTrue(restarted.pending())
        assertTrue(restarted.prepare().ok)
        assertEquals(previous, nonce())
    }

    @Test fun webTokenAloneAndStaleSessionsNeverConfirmTheManager() {
        val handover = ManagerRestoreHandover(ticket())
        handover.prepare()
        var finalizations = 0
        assertFalse(handover.confirm("wrong-session", { true }) {
            finalizations++; RecoveryCleanupResult(true)
        }.ok)
        assertEquals(0, finalizations)
        assertTrue(handover.pending())
    }

    @Test fun missingLiveManagerPreservesRecovery() {
        val handover = ManagerRestoreHandover(ticket())
        handover.prepare()
        assertFalse(handover.confirm(nonce(), { false }) { error("must retain recovery") }.ok)
        assertTrue(handover.pending())
    }

    @Test fun cleanupFailureAndLostReplyAreRetryable() {
        val handover = ManagerRestoreHandover(ticket())
        handover.prepare()
        val nonce = nonce()
        assertFalse(handover.confirm(nonce, { true }) { RecoveryCleanupResult(false, "REVOKE_FAILED") }.ok)
        assertTrue(handover.pending())
        var finalizations = 0
        assertTrue(handover.confirm(nonce, { true }) { finalizations++; RecoveryCleanupResult(true) }.ok)
        val restarted = ManagerRestoreHandover(ticket())
        assertFalse(restarted.pending())
        assertTrue(restarted.confirm(nonce, { true }) { finalizations++; error("duplicate cleanup") }.ok)
        assertEquals(1, finalizations)
    }

    @Test fun partialOrMissingTicketNeverClosesRecovery() {
        val handover = ManagerRestoreHandover(ticket())
        assertFalse(handover.confirm("nonce", { true }) { error("no ticket") }.ok)
        ticket().writeText("pending:half-written")
        assertFalse(handover.confirm("nonce", { true }) { error("corrupt ticket") }.ok)
        assertTrue(handover.prepare().ok)
        assertTrue(handover.pending())
    }
}
