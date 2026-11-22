package dev.maplesu.manager.workmode.boot

/** Keep a retry requested by startup warmup until the current attempt releases execution. */
internal class ModeBootstrapRetryState(
    private val maxAttempts: Int,
    private val retryDelayMillis: Long,
) {
    private var executing = false
    private var attempts = 0
    private var retryRequested = false

    @Synchronized
    fun tryStart(): Int? {
        if (executing) return null
        executing = true
        return ++attempts
    }

    /** True means the caller should schedule now; otherwise finish() consumes the merged request. */
    @Synchronized
    fun requestRetry(): Boolean {
        if (executing) {
            retryRequested = true
            return false
        }
        attempts = 0
        return true
    }

    /** Returns one next delay, or null when resolved / the automatic budget is exhausted. */
    @Synchronized
    fun finish(resolved: Boolean): Long? {
        executing = false
        if (resolved) {
            retryRequested = false
            return null
        }
        if (retryRequested) {
            retryRequested = false
            attempts = 0
            return 0L
        }
        return if (attempts < maxAttempts) retryDelayMillis * attempts else null
    }
}
