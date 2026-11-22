package dev.maplesu.manager.ksu

import org.junit.Assert.*
import org.junit.Test

class KsuManagerFdTest {
    @Test fun anExistingDriverDoesNotLaunchAnotherRootCommand() {
        KsuManagerFd.awaitDriver({ true }, { fail("Unexpected driver transfer") }, { fail("Unexpected delay") })
    }
    @Test fun aManagerStartedBeforeLateLoadAcquiresTheDriver() {
        var ready = false
        var transfers = 0
        KsuManagerFd.awaitDriver({ ready }, { transfers++; ready = true }, { fail("Unexpected delay") })
        assertEquals(1, transfers)
    }
    @Test fun discoveryWaitsForTheRealJniScanThrottle() {
        var elapsed = 0L
        var transfers = 0
        KsuManagerFd.awaitDriver({ elapsed >= 2000 }, { transfers++ }, { elapsed += it })
        assertEquals(2000L, elapsed)
        assertEquals(1, transfers)
    }
    @Test fun aTransferredDescriptorDoesNotImplyAWorkingDriver() {
        var elapsed = 0L
        val error = runCatching {
            KsuManagerFd.awaitDriver({ false }, {}, { elapsed += it })
        }.exceptionOrNull()
        assertEquals("KSU_MANAGER_FD_NOT_OBSERVED", error?.message)
        assertEquals(2500L, elapsed)
    }
    @Test fun transferFailuresArePreserved() {
        val error = IllegalStateException("KSU_MANAGER_FD_PEER")
        assertSame(error, runCatching {
            KsuManagerFd.awaitDriver({ false }, { throw error }, { fail("Unexpected delay") })
        }.exceptionOrNull())
    }
    @Test fun canceledPreparationStopsTheDiscoveryLoop() {
        val error = InterruptedException("canceled")
        assertSame(error, runCatching {
            KsuManagerFd.awaitDriver({ false }, {}, { throw error })
        }.exceptionOrNull())
    }
}
