package dev.maplesu.manager.runtime.ultra

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch

/** Serial recovery; events during a pass retain one later pass with fresh observations. */
internal class UltraRecoveryRequests(
    scope: CoroutineScope,
    private val recover: suspend () -> Unit,
    private val failed: (Exception) -> Unit,
) {
    private val requests = Channel<Unit>(Channel.CONFLATED)
    init {
        scope.launch {
            for (request in requests) {
                try {
                    recover()
                } catch (cancelled: CancellationException) {
                    // A cancelled pass keeps later events; cancelling the owner ends the actor.
                    currentCoroutineContext().ensureActive()
                } catch (error: Exception) {
                    failed(error)
                }
            }
        }
    }

    fun request() {
        requests.trySend(Unit)
    }
}
