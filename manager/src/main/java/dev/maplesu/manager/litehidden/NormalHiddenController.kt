package dev.maplesu.manager.litehidden

import dev.maplesu.manager.liteweb.LiteWebPortPolicy
import java.util.concurrent.atomic.AtomicBoolean

data class NormalHiddenResult(
    val ok: Boolean,
    val code: String = "",
    val recoveryUrl: String = "",
)

/** Preparation never hides or removes the manager; activation consumes one confirmed session. */
class NormalHiddenController(
    private val prepareSession: (Int) -> NormalHiddenResult,
    private val activateSession: (String) -> NormalHiddenResult,
) {
    private val busy = AtomicBoolean(false)
    private val lock = Any()
    private var generation = 0L
    private var preparedUrl: String? = null
    private var activating = false

    suspend fun prepare(port: Int = LiteWebPortPolicy.DEFAULT_PORT): NormalHiddenResult {
        if (!busy.compareAndSet(false, true)) return NormalHiddenResult(false, "NORMAL_HIDDEN_BUSY")
        val current = synchronized(lock) { preparedUrl = null; ++generation }
        return try {
            val result = if (LiteWebPortPolicy.validate(port) != null) {
                NormalHiddenResult(false, "LITEWEB_PORT_RANGE")
            } else runCatching { prepareSession(port) }.getOrElse { NormalHiddenResult(false, "NORMAL_PREPARE_FAILED") }
            synchronized(lock) {
                if (generation != current) NormalHiddenResult(false, "NORMAL_PREPARE_CANCELLED")
                else if (result.ok && result.recoveryUrl.isNotEmpty()) {
                    preparedUrl = result.recoveryUrl
                    result
                } else result.copy(ok = false)
            }
        } finally {
            busy.set(false)
        }
    }

    suspend fun activate(): NormalHiddenResult {
        if (!busy.compareAndSet(false, true)) return NormalHiddenResult(false, "NORMAL_HIDDEN_BUSY")
        return try {
            val url = synchronized(lock) {
                preparedUrl.also { preparedUrl = null; activating = it != null }
            } ?: return NormalHiddenResult(false, "NORMAL_RECOVERY_NOT_PREPARED")
            runCatching { activateSession(url) }.getOrElse { NormalHiddenResult(false, "NORMAL_ACTIVATE_FAILED") }
        } finally {
            synchronized(lock) { activating = false }
            busy.set(false)
        }
    }

    /** Cancellation invalidates preparation; an already confirmed removal finishes independently. */
    fun cancel() = synchronized(lock) {
        if (!activating) { generation++; preparedUrl = null }
    }
}
