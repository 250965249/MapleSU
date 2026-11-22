package dev.maplesu.manager.t3

/** A confirmed disable owns one deadline, including across Activity recreation. */
internal class T3DisableCountdown(private val nowMillis: () -> Long) {
    private var deadline: Long? = null

    @Synchronized
    fun confirm() {
        if (deadline == null) deadline = nowMillis() + 3_000L
    }

    @Synchronized
    fun remainingSeconds(): Int? = deadline?.let {
        ((it - nowMillis()).coerceAtLeast(0L) + 999L).div(1_000L).toInt()
    }
}
