package dev.maplesu.manager.recovery

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/** A successful absence is conclusive; missing readiness and failed reads need another attempt. */
internal suspend fun <T> readRestoreOnceReady(
    attempts: Int = 8,
    load: () -> Result<T?>,
    pause: suspend (Long) -> Unit = { delay(it) },
): T? {
    repeat(attempts) { attempt ->
        val result = withContext(Dispatchers.IO) { load() }
        if (result.isSuccess) return result.getOrNull()
        result.exceptionOrNull()?.let { if (it is CancellationException) throw it }
        if (attempt < attempts - 1) pause(1_000)
    }
    return null
}
