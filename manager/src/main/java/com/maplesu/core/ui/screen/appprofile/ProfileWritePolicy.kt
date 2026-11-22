package com.maplesu.core.ui.screen.appprofile

/** Results arrive in write order; only the newest request may replace the optimistic UI. */
internal class ProfileWritePolicy<T>(initial: T) {
    private var confirmed = initial
    private var latestRequest = 0L

    data class Completion<T>(val profile: T, val saved: Boolean)

    fun request(): Long = ++latestRequest

    fun isLatest(request: Long): Boolean = request == latestRequest

    fun complete(request: Long, submitted: T, saved: Boolean): Completion<T>? {
        if (saved) confirmed = submitted
        if (!isLatest(request)) return null
        return Completion(if (saved) submitted else confirmed, saved)
    }
}
