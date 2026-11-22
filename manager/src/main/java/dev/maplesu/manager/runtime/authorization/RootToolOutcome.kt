package dev.maplesu.manager.runtime.authorization

import java.util.Base64

/**
 * The answer of one `SuperuserTool` / `AuthorizationTool` run, interpreted once.
 *
 * <p>Why this is a separate, pure type: the root tool can fail in two very different
 * ways, and the caller has to distinguish them without guessing.
 *
 *  - **A protocol answer.** The tool prints exactly one `OK <payload>` or `ERR <reason>`
 *    line and then halts. That line is the only thing the caller may act on; an `ERR`
 *    line is a refusal even when the process exit status is 0 (the tool always halts
 *    with 0 after printing).
 *  - **No protocol answer.** The process was killed before it could print. A death by
 *    `SIGSYS` means the kernel's seccomp filter stopped a syscall before `main()` could
 *    answer. The App forked that child, so it inherited the App's own filter; seccomp
 *    cannot be removed from the child. This case is the named
 *    [SuCodes.SU_PRIVILEGED_PATH_SECCOMP_BLOCKED], never a generic "transport
 *    unavailable" and never a retry that could turn a policy refusal into a success.
 *
 * <p>An `OK` line printed before a later `SIGSYS` is still a success: the tool prints
 * `OK` only after [SuperuserOps.run] has returned (the transaction, the audit line and
 * the output are already complete), and `Runtime.halt` does not allocate resources. A
 * `SIGSYS` before that point leaves no `OK` line. The parser therefore follows the
 * protocol line first and uses the exit status only to classify the *no-answer* case.
 *
 * <p>Pure so the host test can assert the whole fail-closed table:
 * `manager/src/test/.../SuperuserSeccompPathTest.kt`.
 */
internal sealed interface RootToolOutcome {
    /** The tool printed `OK <payload>`; the payload is exactly the bytes after `OK `. */
    data class Ok(val payload: String) : RootToolOutcome

    /** The run failed closed; [code] is a stable [SuCodes] token. */
    data class Failed @JvmOverloads constructor(
        val code: String,
        val detail: String = "",
        val rev: Long = 0,
        val pendingApply: Boolean = false,
        /** Default state fields carry no mark receipt; only the strict decoder sets this. */
        val receiptKnown: Boolean = false,
    ) : RootToolOutcome

    companion object {
        /** `SIGSYS` on every Linux ABI this App ships for. */
        const val SIGSYS = 31

        /**
         * `waitpid`'s shell/JNI spelling of a signal death: the native client returns
         * `128 + WTERMSIG(status)` (`manager/src/main/cpp/maplesu_su.c`), and a Posix
         * shell returns the same number for a killed child.
         */
        const val EXIT_SIGSYS = 128 + SIGSYS

        private const val MAX_DETAIL = 4096
        private const val MAX_RECEIPT = 16_640

        /** Private tool text only, not the CORE wire. Detail never supplies typed facts. */
        fun failureReceipt(outcome: SuperuserTransaction.Outcome): String {
            require(!outcome.ok && outcome.rev >= 0)
            val detail = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(outcome.detail.take(MAX_DETAIL).toByteArray(Charsets.UTF_8))
            return "${outcome.code ?: SuCodes.SU_STORE_WRITE_FAILED} receipt=su1 rev=${outcome.rev} " +
                "pending=${if (outcome.pendingApply) 1 else 0} detail=$detail"
        }

        private fun receipt(text: String): Failed? {
            if (text.length > MAX_RECEIPT) return null
            val fields = text.split(' ')
            if (fields.size != 5 || !fields[0].matches(Regex("(?:AUTH|SU)_[A-Z0-9_]{1,120}")) || fields[1] != "receipt=su1" ||
                !fields[2].startsWith("rev=") || !fields[4].startsWith("detail=")) return null
            val revision = fields[2].substring(4)
            val rev = revision.toLongOrNull()?.takeIf { it >= 0 && it.toString() == revision } ?: return null
            val pending = when (fields[3]) { "pending=0" -> false; "pending=1" -> true; else -> return null }
            val encoded = fields[4].substring(7)
            val bytes = try { Base64.getUrlDecoder().decode(encoded) }
                catch (_: IllegalArgumentException) { return null }
            if (Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) != encoded) return null
            val detail = bytes.toString(Charsets.UTF_8)
            if (detail.length > MAX_DETAIL || !detail.toByteArray(Charsets.UTF_8).contentEquals(bytes)) return null
            return Failed(fields[0], detail, rev, pending, receiptKnown = true)
        }

        /**
         * Interpret one child result.
         *
         * @param exitCode the process exit status (128 + signal when killed).
         * @param output the child's stdout, where the one protocol line is printed. Only
         *   stdout is trusted: a diagnostic line on stderr must never be able to spell a
         *   success the tool did not print.
         */
        fun parse(exitCode: Int, output: String): RootToolOutcome {
            val line = output.lineSequence()
                .lastOrNull { it.startsWith("OK ") || it.startsWith("ERR ") }
            if (line != null) {
                return if (line.startsWith("OK ")) {
                    Ok(line.substring(3).trim())
                } else {
                    val text = line.substring(4)
                    val detail = text.trim().take(MAX_DETAIL)
                    val known = setOf(
                        SuCodes.AUTH_DENIED, SuCodes.AUTH_NOT_GRANTED, SuCodes.AUTH_DISABLED,
                        SuCodes.AUTH_IDENTITY_CHANGED, SuCodes.AUTH_IDENTITY_UNAVAILABLE,
                        SuCodes.AUTH_REVOKED, SuCodes.SU_STORE_READ_FAILED,
                        SuCodes.SU_STORE_WRITE_FAILED, SuCodes.SU_JOURNAL_WRITE_FAILED,
                        SuCodes.SU_AUDIT_WRITE_FAILED, SuCodes.SU_AUTH_APPLY_PENDING,
                        SuCodes.SU_TRANSPORT_UNAVAILABLE,
                    )
                    val code = detail.split(':', ' ', '\t', '<', '>')
                        .firstOrNull { it in known } ?: SuCodes.SU_TRANSPORT_UNAVAILABLE
                    // Exact positional fields reject missing/extra/duplicate data. Legacy
                    // exception chains retain their diagnostic, with no inferred state.
                    receipt(text) ?: Failed(code, detail)
                }
            }
            return Failed(
                if (isSeccompDeath(exitCode)) {
                    SuCodes.SU_PRIVILEGED_PATH_SECCOMP_BLOCKED
                } else {
                    SuCodes.SU_TRANSPORT_UNAVAILABLE
                },
            )
        }

        /** True only for the kernel's seccomp termination, never for an ordinary exit. */
        fun isSeccompDeath(exitCode: Int): Boolean = exitCode == EXIT_SIGSYS
    }
}
