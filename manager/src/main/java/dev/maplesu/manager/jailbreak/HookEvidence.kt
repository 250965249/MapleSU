package dev.maplesu.manager.jailbreak

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject

/**
 * The step-3 UMH handover evidence, and the merge rules that turn it into the
 * `JailbreakStatus` restore fields (design
 * `docs/patching/maplesu-step3-umh-mode-design-2026-10-29.md` §5.4/§5.5, Appendix A).
 *
 * Two files are written by the helper in the device-protected attempt directory:
 *
 *  - `maplesu-hook.json` - the parent process's own observations (window, stage-2 and
 *    daemon slots, the restore rung it performed, and the unload state it waited for);
 *  - `maplesu-hook-unload.json` - the forked unload child's record: the
 *    `delete_module` result, the readback after it, and the final readback.
 *
 * The child's record is later and more authoritative for the restore (it ran the
 * kernel's `cleanup_module` rung), so it wins wherever both speak. That ordering is
 * the whole reason the merge exists: reading only one file would either report a
 * restore the kernel performed as "unconfirmed", or trust a parent that cannot know
 * the child's errno.
 *
 * **Missing or malformed evidence is never success.** Rule 1 below is the same reading
 * the App already applies to `maplesu-teardown`: an absent file means "no evidence",
 * not "clean".
 *
 * The decision surface ([merge]) is pure Kotlin so it runs in host unit tests, and the
 * JSON parsing ([parseMain], [parseUnload], [read]) uses the same pinned
 * `kotlinx-serialization-json` reader the rest of the App uses, so it is exercised by
 * those host tests too: the schema typing the helper actually emits is covered before
 * the one device run (review M3).
 */
object HookEvidence {

    const val MAIN_FILE = "maplesu-hook.json"
    const val UNLOAD_FILE = "maplesu-hook-unload.json"
    const val SCHEMA = "maplesu.hook.v1"
    const val UNLOAD_SCHEMA = "maplesu.hook.unload.v1"

    /** Verdict / state words shared with the helper; never invented App-side. */
    const val VERDICT_OK = "OK"
    const val VERDICT_DEGRADED = "DEGRADED"
    const val VERDICT_FAILED = "FAILED"
    const val UNLOAD_DONE = "DONE"
    const val UNLOAD_FAILED = "FAILED"
    const val UNLOAD_PENDING = "PENDING"

    /**
     * The token `escalateHook()` publishes when the merged evidence does not admit a
     * handover and the records carry no more specific token. Kept here (not in the
     * executor) so the "good run must not publish it" path is a host-testable function
     * ([refusalToken]) instead of an Android-only branch (review M3).
     */
    const val TOKEN_RESTORE_UNVERIFIED = "MAPLESU_HOOK_RESTORE_UNVERIFIED"

    /**
     * Step-4 R5/R6 tokens: the evidence exists but does not answer for this attempt, or
     * cannot be read at all. Both are named refusals (C10: no token means no success).
     */
    const val TOKEN_FOREIGN_BOOT = "MAPLESU_HOOK_EVIDENCE_FOREIGN_BOOT"
    const val TOKEN_FOREIGN_ATTEMPT = "MAPLESU_HOOK_EVIDENCE_FOREIGN_ATTEMPT"
    const val TOKEN_EVIDENCE_UNREADABLE = "MAPLESU_HOOK_EVIDENCE_UNREADABLE"
    const val TOKEN_EVIDENCE_MISSING = "MAPLESU_HOOK_EVIDENCE_MISSING"

    data class Entry(val argv: String?, val origin: String?)

    data class Window(val enforceBefore: Int?, val open: Boolean)

    data class Stage2(val state: String?, val path: String?, val rc: Int?,
                      val errno: Int?, val name: String?)

    data class Daemon(val state: String?, val path: String?, val pid: Int?)

    data class Restore(val wantFinal: String?, val target: String?, val wrote: Boolean,
                       val readbackPreUnload: Int?, val origin: String?, val failures: Int?,
                       /**
                        * Step-4 (MF-10/G-10): the provenance label the helper decided
                        * with - `observed`/`baseline` when the target came from the App's
                        * env, `kernel` only when `enforce_before == 1` really was the
                        * kernel's own byte, `unknown` otherwise. Audit only: the verdict
                        * is still decided by origin + readback, never by this label.
                        */
                       val source: String? = null)

    data class Unload(val name: String?, val state: String?)

    data class Main(
        val schema: String?,
        val helper: String?,
        val helperPid: Int?,
        val bootId: String?,
        /**
         * Step-4 (R5/G-10): the attempt this evidence belongs to. The helper used to
         * write a hard-coded `"attempt":null`, which made "these bytes are from *this*
         * attempt" unprovable; the field existed, only its value was missing.
         */
        val attempt: String? = null,
        val entry: Entry?,
        val window: Window?,
        val stage2: Stage2?,
        val daemon: Daemon?,
        val restore: Restore?,
        val unload: Unload?,
        val verdict: String?,
        val token: String?,
    )

    data class UnloadRecord(
        val schema: String?,
        val rc: Int?,
        val errno: Int?,
        val attempts: Int?,
        val readbackPostUnload: Int?,
        val readbackFinal: Int?,
        val origin: String?,
        val failures: Int?,
        /**
         * Step-4 (D2): did the child actually write selinuxfs? 0 means the target was
         * already there (`restore preexisting=... by=external`) and the child recorded
         * the competition instead of writing twice. Absent in step-3 records.
         */
        val wrote: Int? = null,
    )

    /**
     * The status fields the merge is allowed to fill (design §5.5). `null` means "no
     * evidence for this field", which the status writer then leaves unset - it never
     * means zero.
     */
    data class Merged(
        val verdict: String,
        val restoreState: String,
        val origin: String?,
        val enforcing: Int?,
        val failures: Int?,
        val unloadState: String?,
        val unloadErrno: Int?,
        val token: String?,
        val stage2: String?,
        val daemon: String?,
        val daemonPid: Int?,
        val entryArgv: String?,
        val helper: String?,
        val bootId: String?,
        /** Step-4 (R5): the attempt the evidence names, for the binding check. */
        val attempt: String? = null,
    ) {
        val ok: Boolean get() = verdict == VERDICT_OK
    }

    /**
     * Merge the two records (design §5.4 rules 1-4, §5.5 mapping).
     *
     * Rule 1: no main record -> no evidence (`null`), never an empty success.
     * Rule 2: the child's record supplies origin/enforcing/failures.
     * Rule 3: child record missing while `unload.state == DONE` -> the child was
     *         probably killed before its write; only the log lines remain, so the
     *         restore is `RESTORED_UNCONFIRMED` and the verdict cannot be OK.
     * Rule 4: `unload.state == PENDING` -> the caller may re-read for up to 2 s; what
     *         this function reports meanwhile is DEGRADED (never success) - unless the
     *         child's own record already proves the unload (`rc=0`, `failures=0`),
     *         which is the R12 case where the child finishes after the parent's
     *         bounded wait.
     */
    fun merge(main: Main?, unload: UnloadRecord?): Merged? {
        if (main == null) return null
        val rawUnloadState = main.unload?.state
        val restore = main.restore
        val want = restore?.wantFinal
        val childFailures = unload?.failures
        val parentFailures = restore?.failures ?: 0
        val failures = childFailures ?: parentFailures
        val enforcing = unload?.readbackFinal ?: unload?.readbackPostUnload
            ?: restore?.readbackPreUnload
        val origin = unload?.origin ?: restore?.origin
        val stage2 = main.stage2?.state
        val daemon = main.daemon?.state
        /*
         * B1 (ABI v2): only INVALID is a staging defect this verdict must surface.
         * LOAD_FAILED means the kernel refused the *optional* L3 module, which the
         * helper's own hook_verdict() already stopped treating as a handover failure
         * (no token, no FAILED), and L3 is decided by `suGate` alone. Keeping it in
         * the verdict chain made a verified restore read as FAILED whenever the
         * module would not load. It stays informational: `Merged.stage2` still
         * carries LOAD_FAILED, and every restore/unload/daemon rule is unchanged.
         */
        val stage2Failed = stage2 == "INVALID"
        val daemonFailed = daemon == "INVALID" || daemon == "EXEC_FAILED"
        /*
         * R12: the parent's wait is bounded at 1500 ms and the child's retry window is
         * deliberately longer, so "the parent saw PENDING" plus "the child's record says
         * rc=0 and no failures" is a *verified* unload that simply finished after the
         * parent stopped watching. The child's record is the later, authoritative one
         * (rule 2), so it settles the state; no child record means PENDING stands.
         */
        val childSettled = unload != null && unload.failures == 0 &&
            (unload.rc == 0 || unload.rc == null)
        val unloadState = if (childSettled && rawUnloadState == UNLOAD_PENDING) {
            UNLOAD_DONE
        } else {
            rawUnloadState
        }
        val childMissing = unload == null && unloadState == UNLOAD_DONE

        val verdict = when {
            // Fail closed on every observation that is not a verified restore.
            unloadState == UNLOAD_FAILED -> VERDICT_FAILED
            // R7 (step-4 D4-12/MF-12): a failed daemon slot is DEGRADED, not FAILED.
            // The daemon slot carries the *second* proof (F2/F3); the restore evidence
            // (F1) is this record, and turning it FAILED would erase exactly what the
            // App has to report when attestation is what broke. DAEMON_READY is still
            // refused - by the attestation check in the provider, and by refusalToken()
            // which keeps returning the helper's MA_HOOK_DAEMON_* token.
            stage2Failed -> VERDICT_FAILED
            failures > 0 -> VERDICT_FAILED
            want != null && enforcing != null && want != enforcing.toString() ->
                VERDICT_FAILED
            want == null || enforcing == null -> VERDICT_FAILED
            childMissing -> VERDICT_DEGRADED
            main.verdict == VERDICT_FAILED -> VERDICT_FAILED
            daemonFailed -> VERDICT_DEGRADED
            unloadState != UNLOAD_DONE -> VERDICT_DEGRADED
            main.window != null && main.window.open.not() -> VERDICT_DEGRADED
            // The parent called it DEGRADED because it saw PENDING; a child record that
            // settled the unload is later evidence and outranks that verdict (R12).
            main.verdict == VERDICT_DEGRADED && !childSettled -> VERDICT_DEGRADED
            else -> VERDICT_OK
        }
        val restoreState = when {
            verdict == VERDICT_FAILED -> "FAILED"
            childMissing -> "RESTORED_UNCONFIRMED"
            origin == "BASELINE" -> "RESTORED_BASELINE"
            origin == "KERNEL_CLEANUP" -> "RESTORED_KERNEL_CLEANUP"
            origin == "KERNEL_SAVED" -> "RESTORED_KERNEL"
            else -> "RESTORED_UNCONFIRMED"
        }
        return Merged(
            verdict = verdict,
            restoreState = restoreState,
            origin = origin,
            enforcing = enforcing,
            failures = failures,
            unloadState = unloadState,
            // Design §6: a real errno exists only in the child record/log; the parent
            // can only state "gone" (0) or "not proven" (null).
            unloadErrno = if (unloadState == UNLOAD_DONE) 0 else null,
            token = main.token,
            stage2 = stage2,
            daemon = daemon,
            daemonPid = main.daemon?.pid,
            entryArgv = main.entry?.argv,
            helper = main.helper,
            bootId = main.bootId,
            attempt = main.attempt,
        )
    }

    /** Rule 2's cross-check: both records exist and disagree about the value. */
    fun contradiction(main: Main?, unload: UnloadRecord?): String? {
        if (main == null || unload == null) return null
        val pre = main.restore?.readbackPreUnload
        val post = unload.readbackPostUnload
        if (pre != null && post != null && pre != post) {
            return "readbackPreUnload=" + pre + " != readbackPostUnload=" + post
        }
        return null
    }

    /**
     * What `escalateHook()` must do with a merged record: `null` means the evidence
     * admits the handover (publish `STAGE_ROOT_WORKER_OBSERVED`); a token means publish
     * `FAILED` with that token. Extracted from the executor so the step-3 acceptance
     * path (a good run must **not** produce [TOKEN_RESTORE_UNVERIFIED]) is covered by a
     * host unit test.
     */
    fun refusalToken(merged: Merged): String? =
        if (merged.ok) null else merged.token ?: TOKEN_RESTORE_UNVERIFIED

    /**
     * Rule R5 (step-4): the evidence must belong to this attempt and this boot.
     *
     * <p>Without it, a readable record from an earlier boot or an earlier attempt would
     * be accepted as this attempt's handover - the failure mode is silent, because the
     * record looks perfect. Fail closed: when the caller knows the boot or attempt id and
     * the record disagrees (or says nothing), the record is refused.
     */
    fun bindingRefusal(merged: Merged, bootId: String?, attemptId: String?): String? {
        if (bootId != null && merged.bootId != bootId) return TOKEN_FOREIGN_BOOT
        if (attemptId != null && merged.attempt != attemptId) return TOKEN_FOREIGN_ATTEMPT
        return null
    }

    /**
     * One directory read, with the "present but unreadable" case kept separate from
     * "absent" (step-4 R6). The two must not collapse: an absent file means this attempt
     * produced no evidence, while a file that exists and cannot be read (DAC, a truncated
     * write, malformed JSON) means the evidence *is* there and the App is not allowed to
     * see it - a different defect with a different cause. R3 proved the difference
     * matters: the helper succeeded and the App reported `EACCES` as a path message.
     */
    data class Reading(val merged: Merged?, val unreadable: String?) {
        val present: Boolean get() = merged != null
    }

    // -- parsing ------------------------------------------------------------- //

    /**
     * Strict single-document reader. The helper writes one `write()` of one JSON line,
     * so anything that is not a complete document is a defect and must not parse as
     * "some evidence": the merge rules already treat a `null` half as no evidence.
     */
    private val json = Json { isLenient = false }

    private fun optionalInt(document: JsonObject, name: String): Int? =
        (document[name] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.intOrNull

    private fun optionalText(document: JsonObject, name: String): String? =
        (document[name] as? JsonPrimitive)?.takeIf { it !is JsonNull }
            ?.contentOrNull?.takeIf { it.isNotEmpty() }

    private fun optionalObject(document: JsonObject, name: String): JsonObject? =
        document[name] as? JsonObject

    /**
     * Read a boolean field that the helper may write as a JSON boolean *or* as a JSON
     * number.
     *
     * The evidence writer is C and emits `"open":%d` and `"wrote":%d` (design §5.4;
     * `bootstrap.c` `hook_write_main_json`), while `JSONObject.optBoolean` only accepts
     * a Boolean (or the strings "true"/"false") and returns the fallback for every
     * Number. Reading the number `1` as `false` made `window.open==false` on a fully
     * open window, so **every good handover merged as DEGRADED** and `escalateHook()`
     * published `MAPLESU_HOOK_RESTORE_UNVERIFIED` instead of the handover (independent
     * review M3). Accept both shapes; anything unrecognised keeps the caller's
     * fail-closed default.
     */
    private fun optionalBool(document: JsonObject, name: String, default: Boolean): Boolean {
        val primitive = document[name] as? JsonPrimitive ?: return default
        if (primitive is JsonNull) return default
        return coerceBoolean(
            primitive.booleanOrNull ?: primitive.intOrNull ?: primitive.contentOrNull,
            default,
        )
    }

    /**
     * The type coercion behind [optionalBool], pure Kotlin so the host tests can feed it
     * exactly the values a JSON reader produces for `1`, `0`, `true`, `false` and `null`.
     */
    internal fun coerceBoolean(value: Any?, default: Boolean): Boolean = when (value) {
        is Boolean -> value
        is Number -> value.toDouble() != 0.0
        is String -> when (value.trim().lowercase()) {
            "true", "1" -> true
            "false", "0" -> false
            else -> default
        }
        // Includes JSON null and any unexpected object: never guess "open".
        else -> default
    }

    fun parseMain(text: String): Main? = runCatching {
        val document = json.parseToJsonElement(text).jsonObject
        Main(
            schema = optionalText(document, "schema"),
            helper = optionalText(document, "helper"),
            helperPid = optionalInt(document, "helperPid"),
            bootId = optionalText(document, "bootId"),
            attempt = optionalText(document, "attempt"),
            entry = optionalObject(document, "entry")?.let {
                Entry(argv = optionalText(it, "argv"), origin = optionalText(it, "origin"))
            },
            window = optionalObject(document, "window")?.let {
                Window(enforceBefore = optionalInt(it, "enforceBefore"),
                    open = optionalBool(it, "open", false))
            },
            stage2 = optionalObject(document, "stage2")?.let {
                Stage2(state = optionalText(it, "state"), path = optionalText(it, "path"),
                    rc = optionalInt(it, "rc"), errno = optionalInt(it, "errno"),
                    name = optionalText(it, "name"))
            },
            daemon = optionalObject(document, "daemon")?.let {
                Daemon(state = optionalText(it, "state"), path = optionalText(it, "path"),
                    pid = optionalInt(it, "pid"))
            },
            restore = optionalObject(document, "restore")?.let {
                Restore(wantFinal = optionalText(it, "wantFinal"),
                    target = optionalText(it, "target"),
                    wrote = optionalBool(it, "wrote", false),
                    readbackPreUnload = optionalInt(it, "readbackPreUnload"),
                    origin = optionalText(it, "origin"),
                    failures = optionalInt(it, "failures"),
                    source = optionalText(it, "source"))
            },
            unload = optionalObject(document, "unload")?.let {
                Unload(name = optionalText(it, "name"), state = optionalText(it, "state"))
            },
            verdict = optionalText(document, "verdict"),
            token = optionalText(document, "token")?.let(::jailbreakErrorCode),
        )
    }.getOrNull()

    fun parseUnload(text: String): UnloadRecord? = runCatching {
        val document = json.parseToJsonElement(text).jsonObject
        UnloadRecord(
            schema = optionalText(document, "schema"),
            rc = optionalInt(document, "rc"),
            errno = optionalInt(document, "errno"),
            attempts = optionalInt(document, "attempts"),
            readbackPostUnload = optionalInt(document, "readbackPostUnload"),
            readbackFinal = optionalInt(document, "readbackFinal"),
            origin = optionalText(document, "origin"),
            failures = optionalInt(document, "failures"),
            wrote = optionalInt(document, "wrote"),
        )
    }.getOrNull()

    /**
     * Read both files from the device-protected attempt directory and merge them.
     * A file that is absent yields `null` for that half, which the merge rules above
     * already treat as "no evidence" / "unconfirmed".
     *
     * <p>Step-4 (R6): a file that **exists** but cannot be read (or does not parse) is
     * reported as unreadable instead of being folded into "absent". See [inspect].
     */
    fun read(directory: File): Merged? = inspect(directory).merged

    /**
     * Step-4 (R6) replacement for the old `read()` body. `readText()` used to throw
     * `FileNotFoundException` straight out of here, through `escalateHook()` and into
     * `escalate()`'s `catch (IOException)`, which turned a permissions problem into a
     * path-shaped failure message and lost the distinction between "no evidence" and
     * "evidence I am not allowed to read".
     */
    fun inspect(directory: File): Reading {
        val problems = mutableListOf<String>()
        val main = parseFile(File(directory, MAIN_FILE), MAIN_FILE, problems, ::parseMain)
        val unload = parseFile(File(directory, UNLOAD_FILE), UNLOAD_FILE, problems,
            ::parseUnload)
        return Reading(merge(main, unload), problems.firstOrNull())
    }

    private fun <T> parseFile(file: File, name: String, problems: MutableList<String>,
                              parse: (String) -> T?): T? {
        if (!file.isFile) {
            // Absent is not a problem. Present-but-not-a-regular-file is: a directory or a
            // socket at the evidence path is a defect the device run has to be able to see.
            if (file.exists()) problems += name + ":not-a-file"
            return null
        }
        val text = runCatching { file.readText() }.getOrElse {
            problems += name + ":" + it.javaClass.simpleName
            return null
        }
        val parsed = parse(text)
        if (parsed == null) problems += name + ":malformed"
        return parsed
    }
}
