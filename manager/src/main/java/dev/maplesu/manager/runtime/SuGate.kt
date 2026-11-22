package dev.maplesu.manager.runtime

import android.content.Context
import android.util.Log
import dev.maplesu.manager.jailbreak.DirtyfragAttempt
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject

/**
 * The L3 su gate as the kernel-side helper recorded it (ABI v1, 2026-10-31).
 *
 * <p>**Where the authority comes from.** The token is not something the App
 * generates or the UI passes down. The UMH helper - a uid-0 worker the kernel
 * started - writes `maplesu-hook-daemon.json` after the L3 module armed, and this
 * object re-reads that file for *this attempt and this boot*. Two independent
 * facts are checked before anything is called armed:
 *
 *  - the file is owned by uid 0, which the App cannot produce for itself, so a
 *    token it invented cannot reach [armed];
 *  - `suGate` says `ARMED` and `suToken` is the ABI's 16 lowercase hex digits.
 *
 * <p>**What it does not prove.** It does not prove the kernel gate accepts the
 * token - only the native child in [NativeSu] can, via the ABI's magic `prctl`
 * option (whose numeric value exists in exactly one place, the native source), and
 * that is why the native path re-checks `getuid() == 0` before it execs anything. A
 * gate that is armed but whose module was unloaded (reboot) just returns EPERM there
 * and the child exits 126; it can never be mistaken for success.
 *
 * <p>Missing, malformed, stale or unowned records all produce [UNAVAILABLE], never
 * a default. There is no path in this file that arms a gate by accident.
 */
object SuGate {
    const val TAG = "MapleSUSuGate"

    /** The helper's own record, rewritten after the restore (0664, root-owned). */
    const val DAEMON_FILE = "maplesu-hook-daemon.json"

    /** `suGate` value that means the L3 module is loaded and acceptably armed. */
    const val ARMED = "ARMED"

    /** Everything else - absent, unreadable, stale, malformed - is this. */
    const val UNAVAILABLE = "UNAVAILABLE"

    /**
     * The named refusal the su path returns when the gate is not armed.
     *
     * <p>It travels as the `err` of a `{code,out,err}` bundle with [EXIT_GATE_DENIED],
     * never as a zero exit: "no su" must be distinguishable from "su ran and the
     * command failed".
     */
    const val ERROR_NOT_ARMED = "SU_GATE_NOT_ARMED"

    /** ABI v1: exactly 16 lowercase hex digits, `%016llx`. */
    private val TOKEN = Regex("^[0-9a-f]{16}$")

    private val json = Json { isLenient = false }

    /** One 64-bit token. [value] keeps the ABI's bit pattern, including bit 63. */
    data class Token(val hex: String) {
        /** Unsigned 64-bit value; a token with the high bit set is negative here. */
        val value: Long get() = java.lang.Long.parseUnsignedLong(hex, 16)
    }

    /**
     * What one record says, *plus* whether it is bound to the attempt that is asking.
     *
     * <p>[bound] is deliberately separate from [suGate]: a record can say `ARMED`
     * and still belong to another boot. Every accessor that could be used to run
     * something reads [armed], which requires both.
     */
    data class Gate(
        val suToken: Token?,
        val suGate: String?,
        val bound: Boolean,
        val attempt: String?,
        val bootId: String?,
        val reason: String? = null,
    ) {
        /**
         * The one predicate that may start a process.
         *
         * <p>A zero token is refused here as well as by the kernel: the module's ARM
         * branch rejects it (`token == 0`), so "ARMED + zeros" cannot be a usable
         * gate - it is a half-written record. Handing it to `prctl` would only earn a
         * guaranteed EPERM, and treating it as unarmed keeps the App's answer equal
         * to the kernel's.
         */
        val armed: Boolean
            get() = bound && suGate == ARMED && suToken != null && suToken.value != 0L

        /** The state to persist or report: exactly two values, never a third. */
        val state: String get() = if (armed) ARMED else UNAVAILABLE

        companion object {
            /** The only "nothing" value; used for every absent/unreadable record. */
            @JvmStatic
            val UNAVAILABLE_GATE = Gate(null, null, false, null, null)
        }
    }

    /**
     * Strict token parse. Uppercase, a missing digit, a `0x` prefix or any
     * non-hex character is a malformed record, not a token to be repaired.
     */
    @JvmStatic
    fun parseToken(raw: String?): Token? {
        if (raw == null) return null
        val match = TOKEN.matchEntire(raw) ?: return null
        return Token(match.value)
    }

    /**
     * Parse a decoded record. Pure, so the host tests drive every branch without an
     * Android `Context` and without org.json (the unit-test runtime has neither).
     *
     * <p>The token is only exposed when the record is bound to the asking attempt;
     * an unbound record reports its raw `suGate` for diagnostics but can never be
     * [Gate.armed].
     */
    @JvmStatic
    fun parse(document: JsonObject, attemptId: String?, bootId: String?): Gate {
        val attempt = text(document, "attempt")
        val boot = text(document, "bootId")
        val rawGate = text(document, "suGate")
        val bound = !attemptId.isNullOrBlank() && !bootId.isNullOrBlank() &&
            attempt == attemptId && boot == bootId
        return Gate(
            suToken = if (bound) parseToken(text(document, "suToken")) else null,
            suGate = rawGate,
            bound = bound,
            attempt = attempt,
            bootId = boot,
            reason = text(document, "suGateReason"),
        )
    }

    /** Parse the helper's record text; a malformed document is `UNAVAILABLE`. */
    @JvmStatic
    fun parse(text: String, attemptId: String?, bootId: String?): Gate = runCatching {
        parse(json.parseToJsonElement(text).jsonObject, attemptId, bootId)
    }.getOrDefault(Gate.UNAVAILABLE_GATE)

    /**
     * Read this attempt's gate from the helper's record.
     *
     * <p>Every refusal returns [Gate.UNAVAILABLE_GATE] and logs why; the caller has
     * one branch to handle, and it is the safe one.
     */
    @JvmStatic
    fun read(context: Context, attemptId: String?, bootId: String?): Gate {
        if (attemptId.isNullOrBlank() || bootId.isNullOrBlank()) {
            Log.w(TAG, "gate unavailable: no attempt/boot binding")
            return Gate.UNAVAILABLE_GATE
        }
        if (bootId != DirtyfragAttempt.readBootId()) {
            Log.w(TAG, "gate unavailable: record belongs to another kernel boot")
            return Gate.UNAVAILABLE_GATE
        }
        val file: File = File(DirtyfragAttempt.hookEvidence(context), DAEMON_FILE)
        if (!file.isFile) {
            Log.w(TAG, "gate unavailable: no " + file.path)
            return Gate.UNAVAILABLE_GATE
        }
        /*
         * The owner check is the reason a token read here is worth anything: uid 0
         * wrote it, the App cannot. A copy planted by the App has owner = the App uid
         * and is refused instead of trusted.
         */
        val owner = runCatching { android.system.Os.stat(file.path).st_uid }.getOrNull()
        if (owner != 0) {
            Log.w(TAG, "gate unavailable: record owner uid=" + owner)
            return Gate.UNAVAILABLE_GATE
        }
        val body = runCatching { file.readText() }.getOrNull()
        if (body == null) {
            Log.w(TAG, "gate unavailable: record unreadable")
            return Gate.UNAVAILABLE_GATE
        }
        val gate = parse(body, attemptId, bootId)
        // Diagnostics only: the token itself is never logged.
        Log.w(TAG, "gate state=" + gate.state + " bound=" + gate.bound +
            " suGate=" + gate.suGate)
        return gate
    }

    private fun text(document: JsonObject, name: String): String? =
        (document[name] as? JsonPrimitive)?.takeIf { it !is JsonNull }
            ?.contentOrNull?.takeIf { it.isNotEmpty() }
}
