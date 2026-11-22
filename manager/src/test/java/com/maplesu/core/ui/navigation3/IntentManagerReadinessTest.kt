package com.maplesu.core.ui.navigation3

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class IntentManagerReadinessTest {
    @Test fun coldStartWaitsBeforeReadingTheManagerIdentity() = runBlocking {
        val ready = CompletableDeferred<Boolean>()
        var manager = false
        var identityReads = 0
        val pending = async(start = CoroutineStart.UNDISPATCHED) {
            awaitIntentManager({ ready.await() }, { identityReads++; manager })
        }
        assertFalse("validated shortcut must remain pending during detection", pending.isCompleted)
        assertEquals(0, identityReads)
        manager = true
        ready.complete(true)
        assertTrue(pending.await())
        assertEquals(1, identityReads)
    }

    @Test fun failedOrTimedOutReadinessDoesNotReadOrApproveIdentity() = runBlocking {
        var identityReads = 0
        assertFalse(awaitIntentManager({ false }, { identityReads++; true }))
        assertEquals(0, identityReads)
    }

    @Test fun eachNewRequestChecksTheCurrentIdentity() = runBlocking {
        var manager = false
        val current = { manager }
        assertFalse(awaitIntentManager({ true }, current))
        manager = true
        assertTrue(awaitIntentManager({ true }, current))
        manager = false
        assertFalse(awaitIntentManager({ true }, current))
    }
}
