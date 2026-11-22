package com.maplesu.core.ui.screen.module

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class ModuleOperationQueueTest {
    @Test fun unrelatedModuleWritesRunInTapOrderWithoutBlockingAdmission() = runBlocking {
        val queue = PendingModuleOperations()
        val release = CompletableDeferred<Unit>()
        val writes = mutableListOf<String>()
        val jobs = listOf("first", "second", "third").map { id ->
            assertTrue(queue.begin(id))
            launch(start = CoroutineStart.UNDISPATCHED) {
                try {
                    queue.execute {
                        writes += id
                        if (id == "first") release.await()
                    }
                } finally { queue.finish(id) }
            }
        }
        assertEquals(listOf("first"), writes)
        assertEquals(setOf("first", "second", "third"), queue.ids)
        release.complete(Unit)
        jobs.forEach { it.join() }
        assertEquals(listOf("first", "second", "third"), writes)
        assertTrue(queue.ids.isEmpty())
    }

    @Test fun failureAndCancellationDoNotSubmitCancelledWritesOrHoldLaterModules() = runBlocking {
        val queue = PendingModuleOperations()
        val release = CompletableDeferred<Unit>()
        val writes = mutableListOf<String>()
        val first = launch(start = CoroutineStart.UNDISPATCHED) {
            try { queue.execute { writes += "first"; release.await(); error("fixture") } }
            catch (_: IllegalStateException) { }
        }
        val cancelled = launch(start = CoroutineStart.UNDISPATCHED) { queue.execute { writes += "cancelled" } }
        val last = launch(start = CoroutineStart.UNDISPATCHED) { queue.execute { writes += "last" } }
        cancelled.cancelAndJoin()
        release.complete(Unit)
        first.join(); last.join()
        assertEquals(listOf("first", "last"), writes)
    }
}
