package dev.maplesu.manager.runtime.ultra

import java.io.EOFException
import java.util.concurrent.CancellationException
import org.junit.Assert.*
import org.junit.Test

class UltraIdentityBrokerDeploymentTest {
    private class Port(
        private val initial: UltraIdentityBrokerDeployment.Observation,
    ) : UltraIdentityBrokerDeployment.Port {
        val events = mutableListOf<String>()
        var preparationFailure: String? = null
        var allowed = true
        var stopped = true
        var started = true
        var replacementMatches = true
        var afterPreparation = initial
        var revokeOnRefresh = false
        var onObserve: (Int) -> Unit = {}
        var onPrepare: () -> Unit = {}
        var onComplete: () -> Unit = {}
        var onPause: () -> Unit = {}
        private var observations = 0
        override fun observe(): UltraIdentityBrokerDeployment.Observation {
            events += "observe"
            val index = observations++
            val result = when (index) {
                0 -> initial
                1 -> afterPreparation.also { if (revokeOnRefresh) allowed = false }
                else -> UltraIdentityBrokerDeployment.Observation(9000, replacementMatches)
            }
            onObserve(index)
            return result
        }
        override fun prepare(): String? { events += "prepare"; onPrepare(); return preparationFailure }
        override fun eligible() = allowed
        override fun stop(pid: Int): Boolean { events += "stop:$pid"; return stopped }
        override fun start(): Boolean { events += "start"; return started }
        override fun complete(): String { events += "complete"; onComplete(); return "IDENTITY_READY" }
        override fun pause(millis: Long) { assertEquals(200L, millis); events += "pause"; onPause() }
    }

    @Test fun eofAndLegacyRepliesRetainOnlyTheRootSocketOwner() {
        for (read in listOf<() -> String?>({ throw EOFException("legacy protocol") }, { null })) {
            val endpoint = UltraIdentityBrokerDeployment.readEndpoint(0, 4088, read)
            assertEquals(4088, endpoint.ownerPid)
            assertNull(endpoint.identity)
        }
    }

    @Test fun legacySocketIsReplacedBeforeTheNewDeploymentCanBecomeReady() {
        val endpoint = UltraIdentityBrokerDeployment.readEndpoint<String>(0, 4088) {
            throw EOFException("legacy broker does not support delegated v4")
        }
        val port = Port(UltraIdentityBrokerDeployment.Observation(endpoint.ownerPid, endpoint.identity != null))
        assertEquals("IDENTITY_READY", UltraIdentityBrokerDeployment.ensure(false, port))
        assertEquals(listOf("observe", "prepare", "observe", "stop:4088", "start", "observe", "complete"), port.events)
    }

    @Test fun nonRootAndInvalidPeersDoNotReadTheProtocolOrSupplyARestartTarget() {
        for ((uid, pid) in listOf(1000 to 4088, 0 to -1, 0 to 0, 0 to 1)) {
            val endpoint = UltraIdentityBrokerDeployment.readEndpoint(uid, pid) { error("untrusted protocol") }
            assertNull(endpoint.ownerPid)
            assertNull(endpoint.identity)
        }
    }

    @Test fun aMatchingLiveDeploymentUsesTheFastPath() {
        val port = Port(UltraIdentityBrokerDeployment.Observation(4088, true))
        assertEquals("IDENTITY_READY", UltraIdentityBrokerDeployment.ensure(false, port))
        assertEquals(listOf("observe", "complete"), port.events)
    }

    @Test fun forcedPreparationDoesNotStopAnAlreadyMatchingBroker() {
        val port = Port(UltraIdentityBrokerDeployment.Observation(4088, true))
        assertEquals("IDENTITY_READY", UltraIdentityBrokerDeployment.ensure(true, port))
        assertEquals(listOf("observe", "prepare", "observe", "complete"), port.events)
    }

    @Test fun aDeploymentThatBecomesCurrentDuringPreparationIsNotStopped() {
        val port = Port(UltraIdentityBrokerDeployment.Observation(4088, false)).apply {
            afterPreparation = UltraIdentityBrokerDeployment.Observation(9000, true)
        }
        assertEquals("IDENTITY_READY", UltraIdentityBrokerDeployment.ensure(false, port))
        assertEquals(listOf("observe", "prepare", "observe", "complete"), port.events)
    }

    @Test fun replacementUsesTheFreshSocketOwnerInsteadOfThePreDeploymentPid() {
        val port = Port(UltraIdentityBrokerDeployment.Observation(4088, false)).apply {
            afterPreparation = UltraIdentityBrokerDeployment.Observation(5000, false)
        }
        assertEquals("IDENTITY_READY", UltraIdentityBrokerDeployment.ensure(false, port))
        assertEquals(listOf("observe", "prepare", "observe", "stop:5000", "start", "observe", "complete"), port.events)
    }

    @Test fun invalidPostDeploymentOwnerIsNeverPassedToTheRestartCommand() {
        val port = Port(UltraIdentityBrokerDeployment.Observation(4088, false)).apply {
            afterPreparation = UltraIdentityBrokerDeployment.Observation(1, false)
        }
        assertEquals("IDENTITY_RESTART_UNVERIFIED", UltraIdentityBrokerDeployment.ensure(false, port))
        assertEquals(listOf("observe", "prepare", "observe"), port.events)
    }

    @Test fun failedKeyOrDeploymentPreparationNeverStopsOrStartsABroker() {
        for (failure in listOf("IDENTITY_ROOT_NOT_VERIFIED", "IDENTITY_PACKAGE_UNVERIFIED",
                "IDENTITY_BRIDGE_ASSET_ABSENT", "IDENTITY_DEPLOY_FAILED")) {
            val port = Port(UltraIdentityBrokerDeployment.Observation(4088, false)).apply {
                preparationFailure = failure
            }
            assertEquals(failure, UltraIdentityBrokerDeployment.ensure(false, port))
            assertEquals(listOf("observe", "prepare"), port.events)
        }
    }

    @Test fun scopeChangeAfterPreparationNeverStopsOrStartsABroker() {
        val port = Port(UltraIdentityBrokerDeployment.Observation(4088, false)).apply {
            onPrepare = { allowed = false }
        }
        assertEquals("IDENTITY_SUSPENDED", UltraIdentityBrokerDeployment.ensure(false, port))
        assertEquals(listOf("observe", "prepare"), port.events)
    }

    @Test fun scopeChangeWhileRefreshingTheSocketOwnerNeverStopsOrStartsABroker() {
        val port = Port(UltraIdentityBrokerDeployment.Observation(4088, false)).apply { revokeOnRefresh = true }
        assertEquals("IDENTITY_SUSPENDED", UltraIdentityBrokerDeployment.ensure(false, port))
        assertEquals(listOf("observe", "prepare", "observe"), port.events)
    }

    @Test fun aFailedControlledStopDoesNotStartOrConfirmAReplacement() {
        val port = Port(UltraIdentityBrokerDeployment.Observation(4088, false)).apply { stopped = false }
        assertEquals("IDENTITY_RESTART_UNVERIFIED", UltraIdentityBrokerDeployment.ensure(false, port))
        assertEquals(listOf("observe", "prepare", "observe", "stop:4088"), port.events)
    }

    @Test fun noSocketOwnerStartsWithoutStoppingAnArbitraryProcess() {
        val port = Port(UltraIdentityBrokerDeployment.Observation(null, false))
        assertEquals("IDENTITY_READY", UltraIdentityBrokerDeployment.ensure(false, port))
        assertEquals(listOf("observe", "prepare", "observe", "start", "observe", "complete"), port.events)
    }

    @Test fun failedStartDoesNotReadOrConfirmAReplacement() {
        val port = Port(UltraIdentityBrokerDeployment.Observation(4088, false)).apply { started = false }
        assertEquals("IDENTITY_START_FAILED", UltraIdentityBrokerDeployment.ensure(false, port))
        assertEquals(listOf("observe", "prepare", "observe", "stop:4088", "start"), port.events)
    }

    @Test fun rootOwnerWithoutMatchingBuildAndDeploymentNeverBecomesReady() {
        val port = Port(UltraIdentityBrokerDeployment.Observation(4088, false)).apply { replacementMatches = false }
        assertEquals("IDENTITY_HANDSHAKE_PENDING", UltraIdentityBrokerDeployment.ensure(false, port))
        assertFalse(port.events.contains("complete"))
        assertEquals(15, port.events.count { it == "pause" })
        assertEquals(17, port.events.count { it == "observe" })
    }

    @Test fun cancellationAndInterruptKeepTheirExistingSemantics() {
        assertThrows(CancellationException::class.java) {
            UltraIdentityBrokerDeployment.readEndpoint<Any>(0, 4088) { throw CancellationException() }
        }
        try {
            val endpoint = UltraIdentityBrokerDeployment.readEndpoint<Any>(0, 4088) { throw InterruptedException() }
            assertNull(endpoint.identity)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    @Test fun interruptOnReadCompletionPreservesTheOwnerWithoutAcceptingIdentity() {
        try {
            val endpoint = UltraIdentityBrokerDeployment.readEndpoint(0, 4088) {
                Thread.currentThread().interrupt()
                "identity"
            }
            assertEquals(4088, endpoint.ownerPid)
            assertNull(endpoint.identity)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    @Test fun anAlreadyInterruptedDeploymentDoesNotObserveOrPrepare() {
        val port = Port(UltraIdentityBrokerDeployment.Observation(4088, true))
        try {
            Thread.currentThread().interrupt()
            assertEquals("IDENTITY_SUSPENDED", UltraIdentityBrokerDeployment.ensure(false, port))
            assertTrue(port.events.isEmpty())
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    private fun matchingPort(stage: Int) = Port(UltraIdentityBrokerDeployment.Observation(4088, stage == 0)).apply {
        afterPreparation = UltraIdentityBrokerDeployment.Observation(4088, stage == 1)
    }

    @Test fun interruptWhileObservingEveryMatchingBranchPreventsCompletion() {
        for (stage in 0..2) {
            val port = matchingPort(stage).apply {
                onObserve = { if (it == stage) Thread.currentThread().interrupt() }
            }
            try {
                assertEquals("IDENTITY_SUSPENDED", UltraIdentityBrokerDeployment.ensure(false, port))
                assertEquals(stage + 1, port.events.count { it == "observe" })
                assertFalse(port.events.contains("complete"))
                assertTrue(Thread.currentThread().isInterrupted)
            } finally { Thread.interrupted() }
        }
    }

    @Test fun eligibilityRevokedWhileObservingEveryMatchingBranchPreventsCompletion() {
        for (stage in 0..2) {
            val port = matchingPort(stage).apply {
                onObserve = { if (it == stage) allowed = false }
            }
            assertEquals("IDENTITY_SUSPENDED", UltraIdentityBrokerDeployment.ensure(false, port))
            assertEquals(stage + 1, port.events.count { it == "observe" })
            assertFalse(port.events.contains("complete"))
        }
    }

    @Test fun cancellationWhileObservingEveryMatchingBranchIsPropagated() {
        for (stage in 0..2) {
            val port = matchingPort(stage).apply {
                onObserve = { if (it == stage) throw CancellationException() }
            }
            assertThrows(CancellationException::class.java) { UltraIdentityBrokerDeployment.ensure(false, port) }
            assertEquals(stage + 1, port.events.count { it == "observe" })
            assertFalse(port.events.contains("complete"))
        }
    }

    @Test fun completionResultsAreDiscardedAfterInterruptOrEligibilityRevocation() {
        for (interrupt in listOf(false, true)) {
            val port = matchingPort(0).apply {
                onComplete = { if (interrupt) Thread.currentThread().interrupt() else allowed = false }
            }
            try {
                assertEquals("IDENTITY_SUSPENDED", UltraIdentityBrokerDeployment.ensure(false, port))
                assertEquals(listOf("observe", "complete"), port.events)
                assertEquals(interrupt, Thread.currentThread().isInterrupted)
            } finally { Thread.interrupted() }
        }
    }

    @Test fun pauseInterruptionSuspendsAndRestoresTheInterruptFlag() {
        val port = matchingPort(2).apply {
            replacementMatches = false
            onPause = { throw InterruptedException() }
        }
        try {
            assertEquals("IDENTITY_SUSPENDED", UltraIdentityBrokerDeployment.ensure(false, port))
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(1, port.events.count { it == "pause" })
            assertFalse(port.events.contains("complete"))
        } finally { Thread.interrupted() }
    }

    @Test fun cancellationWhileWaitingIsPropagated() {
        val port = matchingPort(2).apply {
            replacementMatches = false
            onPause = { throw CancellationException() }
        }
        assertThrows(CancellationException::class.java) { UltraIdentityBrokerDeployment.ensure(false, port) }
        assertEquals(1, port.events.count { it == "pause" })
        assertFalse(port.events.contains("complete"))
    }
}
