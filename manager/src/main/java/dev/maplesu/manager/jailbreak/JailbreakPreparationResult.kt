package dev.maplesu.manager.jailbreak

/** The preparation reply is authoritative, including failures not persisted by the provider. */
internal fun preparedJailbreakOutcome(request: JailbreakRequest, observed: JailbreakStatus?): JailbreakController.Outcome {
    if (observed == null || observed.attemptId != request.attemptId || observed.bootId != request.bootId ||
        observed.rootBackend != request.rootBackend
    ) return JailbreakController.Outcome(JailbreakStatus.STAGE_FAILED, "attempt produced no matching status record",
        "JAILBREAK_ATTEMPT_NOT_CONFIRMED")
    if (observed.failure != null || observed.stage != JailbreakStatus.STAGE_DAEMON_READY) {
        return JailbreakController.Outcome(
            if (observed.stage == JailbreakStatus.STAGE_CANCELLED) JailbreakStatus.STAGE_CANCELLED else JailbreakStatus.STAGE_FAILED,
            observed.message, observed.failure ?: "JAILBREAK_ATTEMPT_NOT_CONFIRMED:" + observed.stage,
        )
    }
    return JailbreakController.Outcome(observed.stage, observed.message, null, request.attemptId)
}

/** Reuse the bounded startup detector; a successful operation is not an implicit mode activation. */
internal fun refreshJailbreakEnvironment(
    outcome: JailbreakController.Outcome,
    invalidate: () -> Unit,
    detect: () -> Unit,
    prepare: () -> Unit = {},
) {
    if (outcome.stage != JailbreakStatus.STAGE_DAEMON_READY || outcome.failure != null || outcome.attemptId.isNullOrBlank()) return
    try {
        prepare()
    } finally {
        invalidate()
        detect()
    }
}
