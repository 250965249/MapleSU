package dev.maplesu.client

/**
 * The single failure type of this library.
 *
 * [code] is a stable SCREAMING_SNAKE identifier so a caller can branch without
 * parsing prose. Codes that the Root side produced carry its own identifier
 * (`AUTH_NOT_GRANTED`, `SU_SESSION_LIMIT`, ...); codes produced here describe the
 * transport or the local contract (`SU_EXECUTOR_NOT_READY`, `SU_SIGNER_POLICY_EMPTY`,
 * ...). A [SecurityException] raised by the Root side is preserved as the cause and
 * its identifier is lifted into [code], because Binder may deliver it either as the
 * original type or as a transport failure depending on the platform version.
 */
class CooperativeSuException(
    val code: String,
    message: String? = null,
    cause: Throwable? = null,
) : Exception(if (message == null) code else "$code: $message", cause) {

    internal companion object {
        /**
         * Root-side identifiers that may arrive as free text after crossing Binder.
         * Recognizing them keeps [code] meaningful instead of collapsing every
         * rejection into one transport code.
         */
        private val KNOWN = listOf(
            "AUTH_DISABLED", "AUTH_NOT_GRANTED", "AUTH_IDENTITY_CHANGED",
            "AUTH_IDENTITY_UNAVAILABLE", "AUTH_REVOKED",
            "SU_SESSION_LIMIT", "SU_SESSION_CLOSED", "SU_TERMINAL_ALREADY_CLAIMED",
            "SU_WAIT_TIMEOUT_INVALID", "SU_SIGNAL_INVALID", "SU_WINDOW_INVALID",
            "SU_REQUEST_INVALID", "SU_REQUEST_TRAILING_DATA", "SU_PROTOCOL_INVALID",
            "SU_FRAME_TOO_LARGE", "SU_USER_LOCKED", "SU_OWNER_MISMATCH",
            "SU_EXIT_CODE_INVALID",
        )

        /**
         * Normalizes any throwable crossing the Binder boundary.
         *
         * A remote stub can only carry an exception whose class the platform knows
         * how to marshal; everything else reaches the caller as [android.os.RemoteException]
         * or as a transaction failure. Scanning the whole cause chain for a known
         * identifier keeps the Root side's decision visible either way.
         */
        fun normalize(failure: Throwable, fallback: String): CooperativeSuException {
            if (failure is CooperativeSuException) return failure
            val text = generateSequence(failure) { it.cause }
                .mapNotNull { it.message }
                .joinToString(" | ")
            val code = KNOWN.firstOrNull { text.contains(it) }
                ?: if (failure is android.os.DeadObjectException) "SU_EXECUTOR_DIED"
                else if (failure is SecurityException) "SU_REMOTE_REJECTED"
                else fallback
            return CooperativeSuException(code, text.ifEmpty { failure.javaClass.name }, failure)
        }
    }
}
