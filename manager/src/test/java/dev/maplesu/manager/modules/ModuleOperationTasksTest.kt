package dev.maplesu.manager.modules

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test

class ModuleOperationTasksTest {
    @Test fun registrationWaitsForTheServiceAndTheTokenIsClaimedOnce() = runBlocking {
        val tasks = ModuleOperationTasks()
        var calls = 0
        val task = tasks.register { calls++; "done" }
        assertEquals(0, calls)
        assertSame(task, tasks.take(task.token))
        assertNull(tasks.take(task.token))
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            task.start(scope)!!.join()
            assertEquals("done", task.result.await())
            assertEquals(1, calls)
            assertNull(task.start(scope))
            assertEquals(1, calls)
        } finally { scope.cancel() }
    }

    @Test fun theServiceScopeActuallyOwnsExecutionAndReceipts() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default + CoroutineName("module-service"))
        val output = mutableListOf<String>()
        val task = ModuleOperationTasks().register {
            output += "stdout"
            currentCoroutineContext()[CoroutineName]?.name
        }
        try {
            task.start(scope)
            assertEquals("module-service", task.result.await())
            assertEquals(listOf("stdout"), output)
        } finally { scope.cancel() }
    }

    @Test fun failureIsReturnedWithoutRetryingTheSubmittedOperation() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        var calls = 0
        val failure = IllegalStateException("fixture failure")
        val task = ModuleOperationTasks().register<String> { calls++; throw failure }
        try {
            task.start(scope)!!.join()
            val returned = runCatching { task.result.await() }.exceptionOrNull()
            assertEquals(failure.javaClass, returned?.javaClass)
            assertEquals(failure.message, returned?.message)
            assertEquals(1, calls)
            assertNull(task.start(scope))
            assertEquals(1, calls)
        } finally { scope.cancel() }
    }

    @Test fun cancellationBeforeServiceClaimRemovesTheTask() = runBlocking {
        val tasks = ModuleOperationTasks()
        var calls = 0
        val task = tasks.register { calls++ }
        tasks.discard(task.token)
        assertNull(tasks.take(task.token))
        assertTrue(task.result.isCancelled)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            task.start(scope)!!.join()
            assertEquals(0, calls)
        } finally { scope.cancel() }
    }

    @Test fun callerCancellationCancelsTheOwnedJobAndRunsItsCleanup() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val started = CompletableDeferred<Unit>()
        val cleaned = CompletableDeferred<Unit>()
        val task = ModuleOperationTasks().register {
            try { started.complete(Unit); awaitCancellation() }
            finally { cleaned.complete(Unit) }
        }
        try {
            val job = task.start(scope)!!
            withTimeout(2_000) { started.await() }
            task.result.cancel()
            withTimeout(2_000) { job.join(); cleaned.await() }
            assertTrue(job.isCancelled)
        } finally { scope.cancel() }
    }

    @Test fun destroyingTheServiceCancelsItsResultAndRecreationDoesNotReplay() = runBlocking {
        val tasks = ModuleOperationTasks()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val started = CompletableDeferred<Unit>()
        var calls = 0
        val task = tasks.register { calls++; started.complete(Unit); awaitCancellation() }
        val owned = tasks.take(task.token)!!
        val job = owned.start(scope)!!
        withTimeout(2_000) { started.await() }
        scope.cancel()
        withTimeout(2_000) { job.join() }
        assertTrue(task.result.isCancelled)
        assertNull(tasks.take(task.token))
        assertNull(ModuleOperationTasks().take(task.token))
        assertEquals(1, calls)
    }
}
