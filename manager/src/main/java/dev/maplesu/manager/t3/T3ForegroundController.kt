package dev.maplesu.manager.t3

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible

internal class T3ForegroundController(
    private val scope: CoroutineScope,
    private val client: T3AccountClient,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val monotonicMillis: () -> Long = { System.nanoTime() / 1_000_000L },
    private val awaitHeartbeat: suspend (Long) -> Unit = { delay(it) },
) {
    val disabledMessage = client.disabledMessage
    val notice = client.notice
    private var job: Job? = null

    @Synchronized
    fun start() {
        if (job?.isActive == true) return
        val previous = job
        job = scope.launch(dispatcher) {
            previous?.join()
            var nextHeartbeat = monotonicMillis()
            while (isActive) {
                runInterruptible(dispatcher) { client.synchronize() }
                nextHeartbeat += HEARTBEAT_INTERVAL_MS
                val now = monotonicMillis()
                if (nextHeartbeat <= now) {
                    nextHeartbeat += ((now - nextHeartbeat) / HEARTBEAT_INTERVAL_MS + 1) * HEARTBEAT_INTERVAL_MS
                }
                awaitHeartbeat(nextHeartbeat - now)
            }
        }
    }

    @Synchronized
    fun stop() {
        job?.cancel()
    }

    private companion object {
        const val HEARTBEAT_INTERVAL_MS = 60_000L
    }
}
