package dev.maplesu.manager.runtime

import org.junit.Assert.*
import org.junit.Test

class RootServiceBootstrapTest {
    private val ready = RootServiceBootstrap.Result(0, "MAPLESU_ROOT_SERVICE_READY\n")

    @Test fun failedStaleAndNonrootSourcesDoNotSuppressTheLaterWorkingSu() {
        val events = mutableListOf<String>()
        val candidates = listOf(
            RootServiceBootstrap.Candidate("stale-sdk") { events += "sdk"; throw IllegalStateException() },
            RootServiceBootstrap.Candidate("nonroot-su") { events += "nonroot"; RootServiceBootstrap.Result(13, "") },
            RootServiceBootstrap.Candidate("working-su") { command ->
                if (command.contains("MAPLESU_ROOT_SERVICE_READY")) {
                    events += "probe"; ready
                } else {
                    events += "launch"; RootServiceBootstrap.Result(0, "")
                }
            },
        )
        assertTrue(RootServiceBootstrap.launch("start-service", candidates).ok)
        assertEquals(listOf("sdk", "nonroot", "probe", "launch"), events)
    }

    @Test fun zeroExitWithoutAReadinessReceiptDoesNotDispatch() {
        var calls = 0
        val candidate = RootServiceBootstrap.Candidate("empty") {
            calls++; RootServiceBootstrap.Result(0, "")
        }
        assertFalse(RootServiceBootstrap.launch("start-service", listOf(candidate)).ok)
        assertEquals(1, calls)
    }

    @Test fun aSuBannerBeforeTheReceiptDoesNotDiscardWorkingRoot() {
        var calls = 0
        val candidate = RootServiceBootstrap.Candidate("su") {
            calls++
            if (calls == 1) ready.copy(output = "su banner\n${ready.output}") else RootServiceBootstrap.Result(0, "")
        }
        assertTrue(RootServiceBootstrap.launch("start-service", listOf(candidate)).ok)
        assertEquals(2, calls)
    }

    @Test fun aSubmittedLaunchIsNeverReplayedThroughAnotherSource() {
        var calls = 0
        val first = RootServiceBootstrap.Candidate("selected") {
            calls++
            if (calls == 1) ready else RootServiceBootstrap.Result(19, "", "lost reply")
        }
        val other = RootServiceBootstrap.Candidate("other") { error("must not replay a submitted launch") }
        assertEquals(19, RootServiceBootstrap.launch("start-service", listOf(first, other)).code)
        assertEquals(2, calls)
    }

    @Test fun allSourcesAreAttemptedBeforeReportingExhaustion() {
        val tried = mutableListOf<Int>()
        val sources = (1..12).map { index -> RootServiceBootstrap.Candidate("source-$index") {
            tried += index; RootServiceBootstrap.Result(-1, "")
        } }
        val result = RootServiceBootstrap.launch("start-service", sources)
        assertFalse(result.ok)
        assertEquals("INSTALLER_ROOT_SOURCES_EXHAUSTED", result.detail)
        assertEquals((1..12).toList(), tried)
    }

    @Test fun verifiedUidWithBlockedFrameworkIsDistinctFromMissingRoot() {
        val sources = listOf(
            RootServiceBootstrap.Candidate("root") { RootServiceBootstrap.Result(14, "") },
            RootServiceBootstrap.Candidate("missing") { RootServiceBootstrap.Result(13, "") },
        )
        assertEquals("INSTALLER_SERVICE_FRAMEWORK_UNAVAILABLE",
            RootServiceBootstrap.launch("start-service", sources).detail)
    }

    @Test fun cancellationStopsBeforeDispatchWithoutBecomingAnotherProbe() {
        try {
            val candidate = RootServiceBootstrap.Candidate("interrupted") {
                Thread.currentThread().interrupt(); ready
            }
            val other = RootServiceBootstrap.Candidate("other") { error("cancelled") }
            assertEquals("ROOT_EXECUTION_INTERRUPTED",
                RootServiceBootstrap.launch("start-service", listOf(candidate, other)).detail)
        } finally { Thread.interrupted() }
    }
}
