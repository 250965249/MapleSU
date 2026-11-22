package dev.maplesu.manager.jailbreak

/** Consume a verified carrier attempt before dispatch; recreated UI never replays it. */
internal class JailbreakAutomaticReboot(
    private val lastAttempt: () -> String?,
    private val recordAttempt: (String) -> Boolean,
) {
    fun onSuccess(
        requested: Boolean,
        backend: String,
        outcome: JailbreakController.Outcome,
        reboot: () -> Boolean,
    ): Boolean? = synchronized(lock) {
        val attempt = outcome.attemptId
        if (!requested || backend !in setOf(JailbreakRequest.BACKEND_HOOK, JailbreakRequest.BACKEND_KSU) ||
            outcome.failure != null ||
            outcome.stage != JailbreakStatus.STAGE_DAEMON_READY || attempt.isNullOrBlank() ||
            lastAttempt() == attempt
        ) return null
        if (!recordAttempt(attempt)) return false
        runCatching(reboot).getOrDefault(false)
    }

    private companion object {
        val lock = Any()
    }
}
