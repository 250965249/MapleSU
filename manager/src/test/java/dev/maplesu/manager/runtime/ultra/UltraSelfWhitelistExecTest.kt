package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraSelfWhitelistExecTest {
    @Test fun workingOrdinaryUidNeedsNoSdkWrite() {
        assertTrue(UltraSelfWhitelist.verifyExec(current = { true }, probe = { true },
            rootVerified = { error("unexpected SDK Root probe") }, refresh = { error("unexpected refresh") }))
    }

    @Test fun staleUidRequiresLiveSdkRootAndOneRefreshBeforeReprobe() {
        val calls = mutableListOf<String>()
        var probes = 0
        assertTrue(UltraSelfWhitelist.verifyExec(current = { true },
            probe = { calls += "exec"; ++probes == 2 },
            rootVerified = { calls += "root"; true }, refresh = { calls += "refresh"; true }))
        assertEquals(listOf("exec", "root", "refresh", "exec"), calls)
    }

    @Test fun failedSdkRootNeverRefreshes() {
        assertFalse(UltraSelfWhitelist.verifyExec(current = { true }, probe = { false },
            rootVerified = { false }, refresh = { error("unexpected refresh") }))
    }

    @Test fun failedRefreshDoesNotRetryTheWriteOrTheExec() {
        var probes = 0
        var writes = 0
        assertFalse(UltraSelfWhitelist.verifyExec(current = { true }, probe = { probes++; false },
            rootVerified = { true }, refresh = { writes++; false }))
        assertEquals(1, probes)
        assertEquals(1, writes)
    }

    @Test fun successfulWriteStillNeedsAnActualSuccessfulExec() {
        var probes = 0
        var writes = 0
        assertFalse(UltraSelfWhitelist.verifyExec(current = { true }, probe = { probes++; false },
            rootVerified = { true }, refresh = { writes++; true }))
        assertEquals(2, probes)
        assertEquals(1, writes)
    }

    @Test fun changedScopeStopsAtTheNextBoundary() {
        for (changedAt in listOf("initial", "exec", "root", "refresh", "reprobe")) {
            var current = changedAt != "initial"
            var probes = 0
            var writes = 0
            assertFalse(changedAt, UltraSelfWhitelist.verifyExec(current = { current },
                probe = {
                    probes++
                    if (changedAt == "exec" || changedAt == "reprobe" && probes == 2) current = false
                    probes == 2
                },
                rootVerified = { if (changedAt == "root") current = false; true },
                refresh = { writes++; if (changedAt == "refresh") current = false; true }))
            assertEquals(changedAt, if (changedAt in listOf("refresh", "reprobe")) 1 else 0, writes)
        }
    }
}
