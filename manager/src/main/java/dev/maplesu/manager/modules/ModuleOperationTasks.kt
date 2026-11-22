package dev.maplesu.manager.modules

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Process-local handoff: a service can claim a user operation exactly once. */
internal class ModuleOperationTasks {
    private val pending = ConcurrentHashMap<String, Task<*>>()

    fun <T> register(operation: suspend () -> T): Task<T> =
        Task(UUID.randomUUID().toString(), operation).also { pending[it.token] = it }

    fun take(token: String): Task<*>? = pending.remove(token)

    fun discard(token: String) { pending.remove(token)?.result?.cancel() }

    class Task<T> internal constructor(val token: String, private val operation: suspend () -> T) {
        val result = CompletableDeferred<T>()
        private val started = AtomicBoolean(false)

        fun start(scope: CoroutineScope): Job? {
            if (!started.compareAndSet(false, true)) return null
            val job = scope.launch(start = CoroutineStart.LAZY) {
                try {
                    result.complete(operation())
                } catch (error: CancellationException) {
                    result.cancel(error)
                    throw error
                } catch (error: Throwable) {
                    result.completeExceptionally(error)
                }
            }
            result.invokeOnCompletion { if (result.isCancelled) job.cancel() }
            job.invokeOnCompletion { error -> if (error != null) result.completeExceptionally(error) }
            job.start()
            return job
        }
    }
}
