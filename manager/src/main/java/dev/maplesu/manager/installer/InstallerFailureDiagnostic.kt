package dev.maplesu.manager.installer

/** Surface a stable diagnostic identifier, never arbitrary exception messages or paths. */
internal fun installerFailureDiagnostic(error: Throwable?, recorded: String = ""): String {
    val messages = generateSequence(error) { it.cause }.take(8).mapNotNull { it.message }.toList() + recorded
    return messages.asSequence().map { it.substringBefore(':') }
        .firstOrNull {
            it == "PRODUCE_KSud_FAILED" ||
                it.matches(Regex("(?:INSTALLER|VR_BOOTSTRAP|ULTRA_KERNEL|BASELINE|SWITCH|MODE_SWITCH|KSU|PRODUCE|ULTRA_ENV|HIDDEN|SUPERUSER|MOVE)_[A-Z0-9_]{1,100}"))
        }
        ?: "INSTALLER_OPERATION_FAILED"
}
