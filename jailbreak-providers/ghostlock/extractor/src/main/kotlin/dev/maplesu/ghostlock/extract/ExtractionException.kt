package dev.maplesu.ghostlock.extract

/** Failure classes mirroring `tools/extract_rs/src/error.rs` exit codes. */
enum class FailureKind {
    /** Generic parse failure (reference exit 2). */
    GENERIC,

    /** The image's layout makes the requested route impossible (exit 3). */
    INFEASIBLE,

    /** Required offsets/fields are missing from the image (exit 4). */
    UNSUPPORTED,

    /** Kallsyms recovery failed (exit 5). */
    KALLSYMS,

    /** `remove_waiter()` already fixed: the primitive is gone (exit 6). */
    ALREADY_FIXED,
}

/**
 * One extraction failure. [message] is diagnostics for the log, never user
 * copy: the UI maps [kind] to one human line.
 */
class ExtractionException(
    val kind: FailureKind,
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)
