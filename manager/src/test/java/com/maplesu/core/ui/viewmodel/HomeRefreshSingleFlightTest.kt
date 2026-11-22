package com.maplesu.core.ui.viewmodel

import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test

class HomeRefreshSingleFlightTest {
    @Test fun repeatedRequestsDuringModeWaitAndProbeDoNotQueueAnotherRefresh() = runBlocking {
        val flight = HomeRefreshSingleFlight()
        val modeReady = CompletableDeferred<Unit>()
        val probeReady = CompletableDeferred<Unit>()
        val probing = CompletableDeferred<Unit>()
        var waits = 0
        var probes = 0
        var publications = 0
        val first = flight.launch(this) {
            waits++
            modeReady.await()
            probes++
            probing.complete(Unit)
            probeReady.await()
            publications++
        }
        repeat(8) { assertNull(flight.launch(this) { waits++; probes++; publications++ }) }
        yield()
        assertEquals(1, waits)
        modeReady.complete(Unit)
        probing.await()
        repeat(8) { assertNull(flight.launch(this) { waits++; probes++; publications++ }) }
        probeReady.complete(Unit)
        first!!.join()
        assertEquals(1, waits)
        assertEquals(1, probes)
        assertEquals(1, publications)
        flight.launch(this) { publications++ }!!.join()
        assertEquals(2, publications)
    }

    @Test fun cancellationDuringModeWaitReleasesTheClaim() = runBlocking {
        val flight = HomeRefreshSingleFlight()
        val entered = CompletableDeferred<Unit>()
        val first = flight.launch(this) { entered.complete(Unit); awaitCancellation() }
        entered.await()
        first!!.cancelAndJoin()
        assertNotNull(flight.launch(this) {})
    }

    @Test fun aScopeCancelledBeforeLaunchDoesNotKeepTheClaim() = runBlocking {
        val flight = HomeRefreshSingleFlight()
        val scope = CoroutineScope(Job().also { it.cancel() })
        flight.launch(scope) { fail("Cancelled scope must not run the refresh") }!!.join()
        flight.launch(this) {}!!.join()
    }

    @Test fun failedRefreshReleasesTheClaim() = runBlocking {
        val flight = HomeRefreshSingleFlight()
        val scope = CoroutineScope(coroutineContext + SupervisorJob() + CoroutineExceptionHandler { _, _ -> })
        try {
            flight.launch(scope) { error("probe failed") }!!.join()
            flight.launch(this) {}!!.join()
        } finally { scope.cancel() }
    }
}
