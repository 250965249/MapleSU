package dev.maplesu.manager.jailbreak

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Locale

/**
 * Evidence for the **SELinux domain the `su` child actually ends up in**. **androidTest only.**
 *
 * <p>Why this exists: the 2026-10-31 Ultra run showed that a uid-0 `su` child can still be
 * useless. The kernel log has
 *
 * ```
 * avc: denied { search } for comm="su" name="8eORURvE0cAkp3ml" dev="dm-87"
 *   scontext=u:r:untrusted_app:s0:c225,c257,c512,c768
 *   tcontext=u:object_r:kernel:s0 tclass=dir permissive=0 app=dev.maplesu.manager
 * ```
 *
 * i.e. the child reached **uid 0 but stayed in the caller's `untrusted_app` domain**, so it
 * cannot search the daemon directory (labelled `kernel`) and the daemon's own children die
 * with `SIGABRT` (`Cmdline: <random> --suicide`, `uid: 0`). A uid alone cannot tell that
 * apart from a working root, so every probe here records **uid + domain** from the same
 * `su` invocation:
 *
 * ```
 * su -c 'id -u; cat /proc/self/attr/current'
 * ```
 *
 * (with `/system/bin/getcon` as the fallback when `/proc/self/attr/current` is not
 * readable). When the answer is an `untrusted_app` domain the record carries
 * `SU_DOMAIN_UNEXPECTED:<domain>`; when nothing could be read it carries
 * `SU_DOMAIN_UNAVAILABLE:<why>` instead of pretending the domain was fine.
 *
 * <p>This is evidence, never an assertion: it must not turn a real A/B/C su verdict red,
 * and it must not hide one either. The tokens are meant to be grepped out of the JSON (or
 * out of `logcat`) on the next round to answer "commit 未生效 or domain/seccomp problem".
 */
internal object SuDomainEvidence {
    /**
     * The command the task asks for, verbatim: uid and domain from one `su`.
     *
     * <p>Executed with `2>&1` appended so a `su` that aborts (SIGABRT is a real outcome
     * on this device) leaves its message in the record; [record] keeps both forms.
     */
    const val SHELL_COMMAND = "su -c 'id -u; cat /proc/self/attr/current'"

    /** Same facts for a session whose argv is already `/system/bin/sh -c <command>`. */
    const val SESSION_COMMAND =
        "/system/bin/id -u; cat /proc/self/attr/current 2>/dev/null || getcon 2>/dev/null"

    /** The KSU line: `/system/bin/su -c '<command>'` from the fixture's own UID. */
    const val FIXTURE_COMMAND = "/system/bin/id -u; cat /proc/self/attr/current"

    /** `u:r:untrusted_app:s0`, `u:r:untrusted_app_30:s0:c216,...` and friends. */
    private val UNTRUSTED = Regex("^u:r:untrusted_app(_[0-9]+)?(:.*)?$")

    /** `u:r:<domain>:s0[:categories]`, including MLS ranges such as `s0-s0:c0.c1023`. */
    private val DOMAIN = Regex("^u:r:[a-z0-9_]+:s[0-9].*$")

    private val NUMERIC = Regex("^[0-9]{1,10}$")

    const val UNEXPECTED_PREFIX = "SU_DOMAIN_UNEXPECTED:"
    const val UNAVAILABLE_PREFIX = "SU_DOMAIN_UNAVAILABLE:"

    private const val RAW_LIMIT = 4_000

    private const val EXPECTATION =
        "a su child that really became root must not stay in the calling app's domain: a " +
            "real su transitions to its own domain (u:r:su:s0 / u:r:magisk:s0 / the " +
            "provider's suser domain) and can then search the daemon directory. The " +
            "observed failure mode is uid 0 with scontext=u:r:untrusted_app:s0, which " +
            "produces `avc: denied { search } ... tcontext=u:object_r:kernel:s0` and " +
            "SIGABRTs inside the daemon."

    private const val EXPLANATION =
        "uid and domain are read from the SAME su invocation, so `uid=0, domain=" +
            "untrusted_app` means the uid transition worked and the SELinux domain " +
            "transition did not (commit did not take effect, a missing setcon/exec " +
            "transition, or the domain change was blocked). `uid=null, domain=null` with " +
            "rc=127 means /system/bin/su is not on this build at all (the hook/kernel " +
            "commit did not publish a su binary)."

    /**
     * Runs [SHELL_COMMAND] as the **shell UID** (uid 2000) through
     * [InstrumentationShell] and returns the record.
     *
     * <p>Shell is a different caller from both the Manager and the fixture, so this line
     * answers "does the published su work for anybody at all on this boot". A `su` that
     * waits for an approval dialog is bounded by [timeoutMillis] and recorded as
     * `SHELL_TIMEOUT`, never allowed to hang the test.
     */
    fun probeShell(
        label: String = "shell",
        timeoutMillis: Long = 20_000L,
    ): JSONObject {
        /*
         * No `2>&1`: the runner captures the command's stderr on its own, so `stdout`
         * stays the uid/domain stream and `stderr` carries `su`'s refusal text. The old
         * call merged them and then passed `stderr = null`, which is how a real failure
         * became `SHELL_ERROR:null`.
         */
        val record = InstrumentationShell.run(SHELL_COMMAND, timeoutMillis = timeoutMillis)
        val stderr = record.optString("stderr")
        return fromOutput(
            label = label,
            command = SHELL_COMMAND,
            executed = record.optString("shell") + " | mode=" + record.optString("mode"),
            stdout = record.optString("output"),
            rc = record.optInt("rc", -1),
            stderr = stderr.takeIf { it.isNotEmpty() },
            runner = "UiAutomation.executeShellCommandRw(/system/bin/sh) as the shell UID " +
                "(uid 2000); the script (with `su -c '...'`) is written on the shell's " +
                "stdin, so quoting and `rc` are real",
            callerUid = android.os.Process.myUid(),
            /* JSONObject.NULL's toString() is "null"; isNull is the only honest test. */
            shellError = if (record.isNull("error")) null else record.optString("error"),
        )
            .put("transport", record.optString("transport"))
            .put("shellMode", record.optString("mode"))
            .put("markerPresent", record.optBoolean("markerPresent", false))
            .put("shellElapsedMillis", record.optLong("elapsedMillis", 0L))
            .put("stderrSource", if (record.optBoolean("stderrMerged", false))
                "merged into stdout by the fallback script" else "separate capture by the script")
    }

    /**
     * Builds the record from output that some other su path already produced
     * (`deploySu`, an `INativeSuSession` session, `/system/bin/su -c`, ...).
     */
    fun fromOutput(
        label: String,
        command: String,
        executed: String? = null,
        stdout: String,
        rc: Int,
        stderr: String? = null,
        runner: String? = null,
        callerUid: Int? = null,
        shellError: String? = null,
        accepted: Boolean? = null,
    ): JSONObject {
        val lines = stdout.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        val uid = lines.firstOrNull { NUMERIC.matches(it) }?.toIntOrNull()
        val domain = lines.firstOrNull { DOMAIN.matches(it) }
        val unexpected = domain != null && UNTRUSTED.matches(domain)
        val reason = if (domain == null) unavailableReason(stdout, stderr, rc, shellError) else null
        val token = when {
            unexpected -> UNEXPECTED_PREFIX + domain
            domain == null -> UNAVAILABLE_PREFIX + reason
            else -> null
        }
        return JSONObject()
            .put("schemaVersion", 1)
            .put("label", label)
            .put("command", command)
            .put("executed", executed ?: JSONObject.NULL)
            .put("runner", runner ?: JSONObject.NULL)
            .put("callerUid", callerUid ?: JSONObject.NULL)
            /*
             * Whether the entry started the session at all. `null` = unknown (a post-hoc
             * probe of a uid-0 child, e.g. deploySu). Ultra sets it explicitly so "the
             * domain session was admitted without a grant" can be told apart from
             * "accepted but the child produced nothing".
             */
            .put("accepted", accepted ?: JSONObject.NULL)
            .put("rc", rc)
            .put("uid", uid ?: JSONObject.NULL)
            .put("domain", domain ?: JSONObject.NULL)
            .put("domainAvailable", domain != null)
            .put("unexpectedDomain", unexpected)
            .put("token", token ?: JSONObject.NULL)
            .put("reason", reason ?: JSONObject.NULL)
            .put("stderr", bounded(stderr ?: "", 800).takeIf { it.isNotEmpty() } ?: JSONObject.NULL)
            .put("shellError", shellError ?: JSONObject.NULL)
            .put("raw", bounded(stdout, RAW_LIMIT))
            .put("expectation", EXPECTATION)
            .put("explanation", EXPLANATION)
            .put("suBinary", suBinary())
    }

    /**
     * The su was **refused** (scenario A/C): an expected answer, so no unexpected-domain
     * token is produced - the refusal itself is the record.
     */
    fun refused(label: String, command: String, denial: String?, detail: String?): JSONObject =
        JSONObject()
            .put("schemaVersion", 1)
            .put("label", label)
            .put("command", command)
            .put("refused", true)
            .put("accepted", false)
            .put("denial", denial ?: JSONObject.NULL)
            .put("detail", detail ?: JSONObject.NULL)
            .put("uid", JSONObject.NULL)
            .put("domain", JSONObject.NULL)
            .put("domainAvailable", false)
            .put("unexpectedDomain", false)
            .put("token", JSONObject.NULL)
            .put("reason", "REFUSED:" + (denial ?: "unknown"))
            .put("expectation", EXPECTATION)

    /** The probe could not run at all (no published entry, harness error, timeout). */
    fun notAttempted(label: String, why: String): JSONObject = JSONObject()
        .put("schemaVersion", 1)
        .put("label", label)
        .put("domainAvailable", false)
        .put("unexpectedDomain", false)
        .put("uid", JSONObject.NULL)
        .put("domain", JSONObject.NULL)
        .put("token", UNAVAILABLE_PREFIX + why)
        .put("reason", why)
        .put("expectation", EXPECTATION)

    /**
     * Aggregates per-probe records into the document node the tests write:
     * `probes`, the unexpected domains, the tokens, and the single token to grep for.
     */
    fun summary(vararg probes: Pair<String, JSONObject?>): JSONObject {
        val observed = JSONObject()
        val unexpectedDomains = JSONArray()
        val unexpectedTokens = JSONArray()
        val unavailableTokens = JSONArray()
        var domainsObserved = 0
        for ((label, record) in probes) {
            if (record == null) continue
            observed.put(label, record)
            val domain = text(record, "domain")
            if (domain != null) {
                domainsObserved += 1
                if (record.optBoolean("unexpectedDomain", false)) {
                    unexpectedDomains.put(label + "=" + domain)
                }
            }
            val token = text(record, "token") ?: continue
            if (token.startsWith(UNEXPECTED_PREFIX)) unexpectedTokens.put(label + ":" + token)
            else unavailableTokens.put(label + ":" + token)
        }
        val firstUnexpected =
            if (unexpectedTokens.length() > 0) unexpectedTokens.getString(0) else null
        return JSONObject()
            .put("probes", observed)
            .put("unexpectedDomains", unexpectedDomains)
            .put("unexpectedTokens", unexpectedTokens)
            .put("unavailableTokens", unavailableTokens)
            .put("domainsObserved", domainsObserved)
            .put("unexpectedToken", firstUnexpected ?: JSONObject.NULL)
            .put("verdict", when {
                firstUnexpected != null -> "SU_DOMAIN_UNEXPECTED"
                domainsObserved == 0 -> "SU_DOMAIN_NOT_OBSERVED"
                else -> "DOMAIN_NOT_UNTRUSTED"
            })
            .put("expectation", EXPECTATION)
            .put("explanation", EXPLANATION)
            .put("remediation", remediation(firstUnexpected))
    }

    /**
     * `org.json` keeps an explicit JSON null as [JSONObject.NULL], whose `toString()` is
     * the four characters `null`; `optString` therefore answers `"null"` instead of `""`.
     * A reader that took that as a token would report every **refusal** (a valid answer)
     * as a missing domain, so every optional string goes through this.
     */
    private fun text(record: JSONObject, name: String): String? =
        if (record.isNull(name)) null else record.optString(name).takeIf { it.isNotEmpty() }

    /** What to look at next, phrased so the record itself says it. */
    fun remediation(unexpectedToken: String?): JSONArray = JSONArray().apply {
        if (unexpectedToken != null) {
            put("A su child reached a uid but its SELinux domain is the caller's " +
                ": " + unexpectedToken)
            put("Next round: check whether the domain transition itself is the defect " +
                "(setcon/exec-time transition in the provider) or whether the " +
                "commit/exec of the su binary is blocked (seccomp / noexec / mount). " +
                "`avc: denied { search } ... tcontext=u:object_r:kernel:s0` on " +
                "comm=\"su\" is the fingerprint of the domain problem, not of the uid.")
            put("The uid number alone is not evidence of working root: compare `uid` " +
                "and `domain` in the same probe record.")
        } else {
            put("No untrusted_app domain was observed; if the uid is still not 0 the " +
                "defect is earlier in the chain (su binary absent / exec refused / " +
                "authorization), not the SELinux domain.")
        }
    }

    private fun unavailableReason(
        stdout: String,
        stderr: String?,
        rc: Int,
        shellError: String?,
    ): String {
        val text = (stdout + "\n" + (stderr ?: "")).lowercase(Locale.US)
        return when {
            shellError != null && shellError.startsWith("SHELL_TIMEOUT") ->
                "SU_TIMEOUT:" + shellError
            shellError != null -> "SHELL_ERROR:" + shellError
            rc == 126 -> "SU_NOT_EXECUTABLE"
            rc == 127 || text.contains("not found") || text.contains("inaccessible") ->
                "SU_BINARY_ABSENT"
            text.contains("permission denied") || text.contains("operation not permitted") ->
                "SU_PERMISSION_DENIED"
            text.contains("sigabrt") || text.contains("fatal signal") ||
                text.contains("abort") || rc == 134 -> "SU_CHILD_ABORTED"
            text.contains("denied") || text.contains("avc") -> "SU_DENIED"
            rc == 0 -> "NO_DOMAIN_IN_OUTPUT"
            else -> "EXIT_" + rc
        }
    }

    /** Whether a `su` binary exists at the standard path (a stat, not an exec). */
    private fun suBinary(): JSONObject {
        val record = JSONObject().put("path", "/system/bin/su")
        val inspected = runCatching {
            val file = File("/system/bin/su")
            record.put("exists", file.exists()).put("executable", file.canExecute())
        }
        if (inspected.isFailure) {
            record.put("exists", JSONObject.NULL).put("executable", JSONObject.NULL)
            record.put("error", describe(inspected.exceptionOrNull() ?: RuntimeException("unknown")))
        }
        runCatching {
            record.put("getcon", File("/system/bin/getcon").exists())
        }.onFailure {
            record.put("getcon", JSONObject.NULL)
        }
        return record
    }
}
