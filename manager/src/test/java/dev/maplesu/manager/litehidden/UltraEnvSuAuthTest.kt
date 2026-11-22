package dev.maplesu.manager.litehidden

import org.junit.Assert.*
import org.junit.Test

class UltraEnvSuAuthTest {
    @Test fun existingFreshGrantIsNeverOwnedByRollback() {
        val events = mutableListOf<String>()
        val auth = UltraEnvSuAuth(read = { events += "read"; true },
            write = { _, _ -> events += "write"; true })
        assertEquals(SuAuthOutcome.AlreadyGranted, auth.grant("com.example.host"))
        assertEquals(listOf("read", "write", "read"), events)
    }

    @Test fun unreadablePreStateDoesNotWriteOrClaimANewGrant() {
        var writes = 0
        val auth = UltraEnvSuAuth(read = { null }, write = { _, _ -> writes++; true })
        val result = auth.grant("com.example.host") as SuAuthOutcome.Failed
        assertFalse(result.rollbackGrant)
        assertEquals(0, writes)
    }

    @Test fun lostReplyAfterNewGrantStillRegistersRollbackOwnership() {
        var granted = false
        val auth = UltraEnvSuAuth(read = { granted }, write = { _, allow -> granted = allow; false })
        val result = auth.grant("com.example.host") as SuAuthOutcome.Failed
        assertTrue(granted)
        assertTrue(result.rollbackGrant)
    }

    @Test fun lostReplyForExistingGrantNeverRegistersRollbackOwnership() {
        val auth = UltraEnvSuAuth(read = { true }, write = { _, _ -> false })
        val result = auth.grant("com.example.host") as SuAuthOutcome.Failed
        assertFalse(result.rollbackGrant)
    }

    @Test fun readbackLossDoesNotReturnAlreadyGrantedOrGranted() {
        var reads = 0
        val auth = UltraEnvSuAuth(read = { if (reads++ == 0) false else null }, write = { _, _ -> true })
        assertTrue((auth.grant("com.example.host") as SuAuthOutcome.Failed).rollbackGrant)
    }

    @Test fun rollbackCanRevokeANewGrantWhosePendingMirrorMakesThePreReadUnknown() {
        var written = false
        val auth = UltraEnvSuAuth(read = { if (written) false else null },
            write = { _, allow -> assertFalse(allow); written = true; true })
        assertEquals(SuAuthOutcome.Revoked, auth.revoke("com.example.host"))
        assertTrue(written)
    }

    @Test fun revocationStillRequiresAConfirmedFreshReadback() {
        val auth = UltraEnvSuAuth(read = { null }, write = { _, _ -> true })
        assertTrue(auth.revoke("com.example.host") is SuAuthOutcome.Failed)
    }

}
