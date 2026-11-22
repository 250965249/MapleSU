package dev.maplesu.manager.jailbreak

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/*
 * Process liveness and shell evidence for the long third-party-su device tests.
 *
 * **androidTest only.** Nothing here is reachable from `main`.
 *
 * ## 2026-10-31 (second pass): the foreground Activity is OFF by default
 *
 * The first keep-alive attempt launched the App's own `MainActivity` from inside the
 * instrumentation process (the same process) with `startActivitySync`. The device
 * answered with
 *
 * ```
 * I/wm_finish_activity: [0,14258338,4078,dev.maplesu.manager/com.maplesu.core.ui.MainActivity,
 *                        proc died without state saved]
 * ```
 *
 * and the instrumentation process was gone **before `prepareHook` was ever called**
 * (`.analysis/ultra3p6-124925/evidence.json`: `phase=pre`, `foreground.started=true`,
 * `foreground.ok=true`, `prepareHookCalls=0`). That is not a vendor reclaim: there is no
 * `am_kill` / `am_proc_died` line and the death is recorded by the window manager, so
 * the launch itself is the trigger. Starting the process's own UI from its own
 * instrumentation is therefore **not** a liveness primitive on this device family.
 *
 * So [ForegroundSession] is `DISABLED_BY_DEFAULT`: it starts no Activity and the
 * keep-alive is exactly the platform doze exemption ([DeviceIdlePolicy] -
 * `cmd deviceidle whitelist +<pkg>` and `am set-inactive <pkg> false`, both with a
 * read-back). The Activity path is kept, unchanged and reachable only through an
 * explicit opt-in (`-e maplesuForeground activity` or `-Dmaplesu.foreground=activity`),
 * so a future device that needs it does not have to resurrect the old code.
 *
 * ## 2026-10-31 (third pass): the shell is `sh` on stdin, not a quoted `sh -c` argument
 *
 * `UiAutomation.executeShellCommand` executes its argument **directly** on this
 * platform, not through a shell. The evidence proves it:
 * `cmd deviceidle whitelist` came back as `Unknown command: whitelist;` (the trailing
 * `;` is part of argv) and the whitelist add came back as
 * `Package must be prefixed with +, -, or =: echo` (the `echo` of the rc marker was an
 * argv entry). Wrapping the command in `sh -c '...'` then made it worse: the split put
 * `'<first word>` into `sh`'s own script argument, `sh` wrote the syntax error to stderr
 * (not captured by that path) and every command answered `rc=-1, output=""` - the whole
 * `logcat`/`deviceIdle`/`processKill` side-car and the su-domain probe went blind.
 * [InstrumentationShell] now starts one `/system/bin/sh` through
 * `executeShellCommandRw` and writes the script on its stdin, so shell syntax, real
 * `stderr` and the command's own `rc` all work.
 */

/**
 * One foreground activation of the target process - or, by default, the deliberate
 * decision not to do one.
 *
 * <p>`mode` is `DISABLED_BY_DEFAULT` (no Activity is started) or `ACTIVITY` (the
 * opt-in path). `started`/`ok` keep their old meaning for the opt-in path and are
 * `false`/`false` when the foreground is disabled, so an old reader cannot mistake a
 * disabled keep-alive for a successful one. [evidence] is safe to call from a watchdog
 * thread; [finish] is idempotent and never throws.
 */
internal class ForegroundSession internal constructor(
    private val instrumentation: Instrumentation?,
    private val activity: Activity?,
    val mode: String,
    val started: Boolean,
    val ok: Boolean,
    val error: String?,
    val launchedAtMillis: Long,
    private val decision: String,
) {
    @Volatile private var releasing = false
    @Volatile private var finished = false
    @Volatile private var finishedAtMillis: Long? = null
    @Volatile private var finishError: String? = null
    @Volatile private var finishNote: String? = null

    /** True only on the opt-in path, when an Activity handle was actually returned. */
    val activityLaunched: Boolean get() = activity != null

    /** The `foreground{mode, started, ok, error}` record, extended with the release result. */
    fun evidence(): JSONObject = JSONObject()
        .put("mode", mode)
        .put("disabledByDefault", mode == DISABLED_BY_DEFAULT)
        .put("started", started)
        .put("ok", ok)
        .put("error", error ?: JSONObject.NULL)
        .put("activityClass", if (mode == DISABLED_BY_DEFAULT) JSONObject.NULL else MAIN_ACTIVITY)
        .put("activityLaunched", activity != null)
        .put("launchedAtMillis", launchedAtMillis)
        .put("finished", finished)
        .put("finishedAtMillis", finishedAtMillis ?: JSONObject.NULL)
        .put("finishError", finishError ?: JSONObject.NULL)
        .put("finishNote", finishNote ?: JSONObject.NULL)
        .put("source", source())
        .put("interpretation", interpretation())
        .put("decision", decision)
        .put("keepAlive", if (mode == DISABLED_BY_DEFAULT) {
            "deviceIdle node only: `cmd deviceidle whitelist +<pkg>` + " +
                "`am set-inactive <pkg> false` (with read-back); no Activity is started"
        } else {
            "opted-in Activity " + MAIN_ACTIVITY + " (startActivitySync) + deviceIdle node"
        })
        .put("reuse", reuse())

    /**
     * `finishAndRemoveTask()` first so no task is left behind, then `finish()` when the
     * platform did not already mark it finishing. `waitForIdle` is bounded on purpose:
     * a stuck main thread must not hang the evidence write that follows.
     *
     * <p>When the foreground is disabled there is nothing to finish; the call records
     * that fact instead of an error.
     */
    fun finish() {
        if (releasing) return
        releasing = true
        val target = activity
        val host = instrumentation
        if (target == null || host == null) {
            finishedAtMillis = System.currentTimeMillis()
            finishError = null
            finishNote = if (mode == DISABLED_BY_DEFAULT) {
                "NO_ACTIVITY_LAUNCHED"
            } else {
                "NO_ACTIVITY_HANDLE"
            }
            finished = true
            return
        }
        val errors = mutableListOf<String>()
        try {
            target.finishAndRemoveTask()
        } catch (error: Throwable) {
            errors += "finishAndRemoveTask:" + describe(error)
        }
        if (!target.isFinishing) {
            try {
                target.finish()
            } catch (error: Throwable) {
                errors += "finish:" + describe(error)
            }
        }
        try {
            host.uiAutomation.waitForIdle(500L, 3_000L)
        } catch (error: Throwable) {
            errors += "waitForIdle:" + describe(error)
        }
        finishedAtMillis = System.currentTimeMillis()
        finishError = if (errors.isEmpty()) null else errors.joinToString("; ")
        finishNote = "ACTIVITY_FINISHED"
        finished = true
    }

    private fun source(): String = if (mode == DISABLED_BY_DEFAULT) {
        "none: ForegroundSession.activate() returns DISABLED_BY_DEFAULT and starts no " +
            "Activity; keep-alive = DeviceIdlePolicy (cmd deviceidle whitelist +<pkg>, " +
            "am set-inactive <pkg> false)"
    } else {
        SOURCE_ACTIVITY
    }

    private fun interpretation(): String = if (mode == DISABLED_BY_DEFAULT) {
        "started=false/ok=false because no Activity was launched: launching " +
            "MainActivity from this process is what killed it on 2026-10-31 " +
            "(wm_finish_activity ... proc died without state saved, before prepareHook). " +
            "The deviceIdle node is the keep-alive that is actually in force."
    } else {
        INTERPRETATION_ACTIVITY
    }

    private fun reuse(): JSONObject = JSONObject()
        .put("mainForegroundServices", JSONArray().apply {
            put("com.maplesu.core.ui.util.DownloadService " +
                "(foregroundServiceType=dataSync, exported=false): started only for a real " +
                "download request, not a residency primitive")
            put("dev.maplesu.manager.modules.LiteModuleBootService " +
                "(foregroundServiceType=specialUse, exported=false): runs user module scripts " +
                "on BOOT_COMPLETED, not a residency primitive")
        })
        .put("generalResidencyService", false)
        .put("startableFromAndroidTestWithoutMainChange", false)
        .put("decision", decision)
        .put("why", "this change is androidTest-only: no new main service was written, and " +
            "the two existing foreground services have their own work to do")

    companion object {
        /** The App's launcher activity, only used by the explicit opt-in path. */
        const val MAIN_ACTIVITY = "com.maplesu.core.ui.MainActivity"

        /** Default: no Activity is started at all. */
        const val DISABLED_BY_DEFAULT = "DISABLED_BY_DEFAULT"

        /** Opt-in: `startActivitySync(MainActivity)` (the pre-2026-10-31 behaviour). */
        const val ACTIVITY = "ACTIVITY"

        /** `am instrument ... -e maplesuForeground activity` enables the opt-in path. */
        const val ARG_FOREGROUND = "maplesuForeground"

        /** `-Dmaplesu.foreground=activity` / `System.setProperty` - same switch. */
        const val PROPERTY_FOREGROUND = "maplesu.foreground"

        private const val START_TIMEOUT_MILLIS = 30_000L

        private const val SOURCE_ACTIVITY =
            "Instrumentation.startActivitySync(Intent(ACTION_MAIN)" +
                ".setClassName(context, \"com.maplesu.core.ui.MainActivity\")" +
                ".addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))"

        private const val INTERPRETATION_ACTIVITY =
            "started = the launch intent was handed to ActivityManager; " +
                "ok = startActivitySync returned the resumed MainActivity of the target " +
                "process, i.e. the process under test is foreground"

        private const val DISABLED_DECISION =
            "no foreground Activity: the keep-alive is the platform doze exemption only"

        private const val ACTIVITY_DECISION =
            "opt-in foreground activity " + MAIN_ACTIVITY

        /**
         * Resolves the requested mode. Default (argument and property absent) is
         * [DISABLED_BY_DEFAULT]; only the literal `activity` opts in, so a typo can never
         * silently re-enable the path that killed the process.
         */
        fun requestedMode(): String {
            val argument = runCatching {
                InstrumentationRegistry.getArguments().getString(ARG_FOREGROUND)
            }.getOrNull()
            val property = runCatching { System.getProperty(PROPERTY_FOREGROUND) }.getOrNull()
            val value = (argument ?: property)?.trim()?.lowercase(Locale.US)
            return if (value == "activity") ACTIVITY else DISABLED_BY_DEFAULT
        }

        /**
         * The keep-alive decision for this run. Default: **no Activity**.
         *
         * <p>The opt-in path still exists (and is unchanged); it is only reachable by
         * asking for it, because on this device family the launch itself is the death.
         */
        fun activate(
            context: Context,
            timeoutMillis: Long = START_TIMEOUT_MILLIS,
        ): ForegroundSession {
            val requested = requestedMode()
            if (requested != ACTIVITY) {
                return ForegroundSession(
                    instrumentation = null,
                    activity = null,
                    mode = DISABLED_BY_DEFAULT,
                    started = false,
                    ok = false,
                    error = null,
                    launchedAtMillis = System.currentTimeMillis(),
                    decision = DISABLED_DECISION,
                )
            }
            val instrumentation = InstrumentationRegistry.getInstrumentation()
            val launchedAt = System.currentTimeMillis()
            val intent = Intent(Intent.ACTION_MAIN)
                .setClassName(context, MAIN_ACTIVITY)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            val future = CompletableFuture<Activity>()
            Thread({
                try {
                    future.complete(instrumentation.startActivitySync(intent))
                } catch (error: Throwable) {
                    future.completeExceptionally(error)
                }
            }, "maplesu-foreground-start").apply { isDaemon = true }.start()
            return try {
                val started = future.get(timeoutMillis, TimeUnit.MILLISECONDS)
                ForegroundSession(instrumentation, started, ACTIVITY, started = true,
                    ok = started != null, error = null, launchedAtMillis = launchedAt,
                    decision = ACTIVITY_DECISION)
            } catch (error: TimeoutException) {
                /* No handle: let a late launch clean up after itself. */
                future.thenAccept { late ->
                    runCatching { late.finishAndRemoveTask() }
                    runCatching { late.finish() }
                }
                ForegroundSession(instrumentation, null, ACTIVITY, started = true, ok = false,
                    error = "START_TIMEOUT:" + timeoutMillis + "ms",
                    launchedAtMillis = launchedAt, decision = ACTIVITY_DECISION)
            } catch (error: ExecutionException) {
                ForegroundSession(instrumentation, null, ACTIVITY, started = true, ok = false,
                    error = describe(error.cause ?: error), launchedAtMillis = launchedAt,
                    decision = ACTIVITY_DECISION)
            } catch (error: InterruptedException) {
                Thread.currentThread().interrupt()
                ForegroundSession(instrumentation, null, ACTIVITY, started = true, ok = false,
                    error = "INTERRUPTED", launchedAtMillis = launchedAt,
                    decision = ACTIVITY_DECISION)
            }
        }

        /**
         * The record for a path that collected no foreground facts at all (it must still
         * say which mode was in force, never imply a successful launch).
         */
        fun notCollected(): JSONObject = JSONObject()
            .put("mode", DISABLED_BY_DEFAULT)
            .put("disabledByDefault", true)
            .put("started", false)
            .put("ok", false)
            .put("error", "not-collected")
            .put("activityClass", JSONObject.NULL)
            .put("activityLaunched", false)
            .put("source", "none: no foreground record was collected")
            .put("interpretation", "started=false/ok=false: no Activity was launched and no " +
                "foreground record was collected")
    }
}

/**
 * Runs one shell command as the shell UID through `UiAutomation`, bounded by a timeout,
 * and reports the command's own **stdout, stderr and exit status**.
 *
 * <p>**Why this is not `executeShellCommand`** (2026-10-31, third pass). Two device
 * records pin the platform behaviour down:
 *
 *  - `.analysis/ultra3p6-124925/evidence.json`: `cmd deviceidle whitelist +pkg; echo
 *    maplesu_rc=$?` answered `Unknown package: dev.maplesu.manager;` and
 *    `Package must be prefixed with +, -, or =: echo`. The `;` stayed **inside an argv
 *    entry**, so that path splits the argument on whitespace and executes it directly -
 *    there is no shell in it;
 *  - `.analysis/ultra3p7-132937/evidence.json`: after the `sh -c '<script>'` wrapper was
 *    added, *every* command answered `ok=false, rc=-1, output=""`. With the argument
 *    split, `sh` received `-c` plus the literal token `'<first word>` as its script,
 *    wrote `sh: '...: not found` to **stderr** (which that path does not capture) and
 *    exited, so the `maplesu_rc=` marker never appeared and stdout stayed empty. That is
 *    why `deviceIdle`/`processKill`/`logcat` all looked "empty" and why the su-domain
 *    probe degenerated to `SHELL_ERROR:null`.
 *
 * <p>So no command text is handed to `executeShellCommand` when shell syntax matters.
 * One `sh` is started through `executeShellCommandRw("/system/bin/sh")` - a single argv
 * word, which is exactly what that path can do - and the **script is written to its
 * stdin**. The script captures stdout and stderr into two temp files under
 * `/data/local/tmp`, prints them back between markers and then prints the command's own
 * exit status. `rc` and `stderr` are therefore observed, not guessed; if the temp files
 * cannot be created the script is retried as one merged `2>&1` stream, and if
 * `executeShellCommandRw` itself is unavailable the platform's argv path is used as a
 * last resort (recorded as such, never presented as a shell run).
 */
internal object InstrumentationShell {
    private const val DEFAULT_TIMEOUT_MILLIS = 30_000L
    private const val OUTPUT_LIMIT = 16_000
    private const val SCRIPT_LIMIT = 4_000
    const val MARKER = "maplesu_rc="

    private const val OUT_BEGIN = "MAPLESU_STDOUT_BEGIN_3f19"
    private const val OUT_END = "MAPLESU_STDOUT_END_3f19"
    private const val ERR_BEGIN = "MAPLESU_STDERR_BEGIN_3f19"
    private const val ERR_END = "MAPLESU_STDERR_END_3f19"
    private const val TMP_UNWRITABLE = "MAPLESU_TMP_UNWRITABLE_3f19"

    private const val SHELL = "/system/bin/sh"

    const val TRANSPORT_INTERACTIVE =
        "UiAutomation.executeShellCommandRw(/system/bin/sh) with the script on stdin"
    const val TRANSPORT_LEGACY = "UiAutomation.executeShellCommand (argv, no shell)"

    fun run(
        command: String,
        timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
        outputLimit: Int = OUTPUT_LIMIT,
    ): JSONObject {
        val startedAtMillis = System.currentTimeMillis()
        val record = JSONObject().put("command", command)
        val script = splitScript(command)
        val split = runScript(script, timeoutMillis)
        val transcript = if (split.exception == null && split.text.contains(TMP_UNWRITABLE)) {
            runScript(mergedScript(command), timeoutMillis)
        } else {
            split
        }
        if (transcript.exception != null) {
            /* The rw transport itself is unavailable; keep a degraded, labelled read. */
            return legacy(command, record, timeoutMillis, outputLimit, transcript, startedAtMillis)
        }
        val parsed = parse(transcript.text)
        val error: String? = when {
            transcript.timedOut -> "SHELL_TIMEOUT:" + timeoutMillis + "ms"
            !parsed.marker -> "NO_EXIT_STATUS:no " + MARKER + " marker in " +
                transcript.text.length + " chars (the script did not finish)"
            else -> null
        }
        record.put("transport", TRANSPORT_INTERACTIVE)
            .put("mode", parsed.mode)
            .put("shell", SHELL + " (script on stdin; stdout+stderr separated by markers)")
            .put("script", bounded(script, SCRIPT_LIMIT))
            .put("ok", error == null)
            .put("rc", parsed.rc)
            .put("output", bounded(parsed.output, outputLimit))
            .put("stderr", bounded(parsed.stderr, outputLimit))
            .put("stderrMerged", parsed.mode != "stdout+stderr")
            .put("markerPresent", parsed.marker)
            .put("rawBytes", transcript.text.length)
            .put("elapsedMillis", System.currentTimeMillis() - startedAtMillis)
            .put("timeoutMillis", timeoutMillis)
            .put("error", error ?: JSONObject.NULL)
        if (error != null && parsed.output.isEmpty() && transcript.text.isNotEmpty()) {
            /* Keep what the shell did say when the markers are missing. */
            record.put("raw", bounded(transcript.text, outputLimit))
        }
        return record
    }

    private class Transcript(
        val text: String,
        val timedOut: Boolean,
        val exception: String?,
    )

    private class Parsed(
        val output: String,
        val stderr: String,
        val rc: Int,
        val marker: Boolean,
        val mode: String,
    )

    /**
     * Starts one `/system/bin/sh`, writes [script] on its stdin and reads its stdout
     * until EOF. The shell's own stderr is not captured here - the script redirects every
     * command's stderr into the record itself, which is the only way to keep it separate
     * from stdout without a second platform pipe.
     */
    private fun runScript(script: String, timeoutMillis: Long): Transcript {
        val descriptors = try {
            InstrumentationRegistry.getInstrumentation().uiAutomation
                .executeShellCommandRw(SHELL)
        } catch (error: Throwable) {
            return Transcript("", timedOut = false, exception = describe(error))
        }
        if (descriptors == null || descriptors.size < 2) {
            return Transcript("", timedOut = false, exception = "EXECUTE_SHELL_COMMAND_RW_EMPTY")
        }
        val bytes = ByteArrayOutputStream()
        val finished = CountDownLatch(1)
        val reader = Thread({
            try {
                ParcelFileDescriptor.AutoCloseInputStream(descriptors[1]).use { input ->
                    val buffer = ByteArray(8192)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        synchronized(bytes) { bytes.write(buffer, 0, count) }
                    }
                }
            } catch (ignored: Throwable) {
                /* A timed-out shell may be torn down mid-read; the bytes read so far stand. */
            } finally {
                finished.countDown()
            }
        }, "maplesu-shell-reader")
        reader.isDaemon = true
        reader.start()
        var writeError: String? = null
        try {
            ParcelFileDescriptor.AutoCloseOutputStream(descriptors[0]).use { input ->
                input.write(script.toByteArray(Charsets.UTF_8))
                input.flush()
            }
        } catch (error: Throwable) {
            writeError = describe(error)
        }
        val completed = try {
            finished.await(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        val text = synchronized(bytes) { bytes.toByteArray().toString(Charsets.UTF_8) }
        return Transcript(text, timedOut = !completed, exception = writeError)
    }

    /** Last resort: the platform's argv path, which cannot run shell syntax. */
    private fun legacy(
        command: String,
        record: JSONObject,
        timeoutMillis: Long,
        outputLimit: Int,
        transcript: Transcript,
        startedAtMillis: Long,
    ): JSONObject {
        val output = try {
            val descriptor = InstrumentationRegistry.getInstrumentation()
                .uiAutomation.executeShellCommand(command)
            ParcelFileDescriptor.AutoCloseInputStream(descriptor).use {
                it.readBytes().toString(Charsets.UTF_8)
            }
        } catch (error: Throwable) {
            ""
        }
        return record
            .put("transport", TRANSPORT_LEGACY)
            .put("mode", "legacy-argv")
            .put("shell", command)
            .put("script", JSONObject.NULL)
            .put("ok", false)
            .put("rc", -1)
            .put("output", bounded(output, outputLimit))
            .put("stderr", "")
            .put("stderrMerged", true)
            .put("markerPresent", false)
            .put("rawBytes", output.length)
            .put("elapsedMillis", System.currentTimeMillis() - startedAtMillis)
            .put("timeoutMillis", timeoutMillis)
            .put(
                "error",
                "NO_SHELL_TRANSPORT:" + (transcript.exception ?: "unknown") +
                    ":the argv path cannot run shell syntax, output may be incomplete",
            )
    }

    private fun parse(text: String): Parsed {
        val markerAt = text.lastIndexOf(MARKER)
        val marker = markerAt >= 0
        val rc = if (!marker) {
            -1
        } else {
            text.substring(markerAt + MARKER.length).lineSequence()
                .firstOrNull()?.trim()?.toIntOrNull() ?: -1
        }
        val body = if (!marker) text else text.substring(0, markerAt)
        val outBegin = body.indexOf(OUT_BEGIN)
        val outEnd = body.indexOf(OUT_END)
        val errBegin = body.indexOf(ERR_BEGIN)
        val errEnd = body.indexOf(ERR_END)
        if (outBegin >= 0 && outEnd > outBegin && errBegin > outEnd && errEnd > errBegin) {
            return Parsed(
                output = body.substring(outBegin + OUT_BEGIN.length, outEnd).trim('\n'),
                stderr = body.substring(errBegin + ERR_BEGIN.length, errEnd).trim('\n'),
                rc = rc,
                marker = marker,
                mode = "stdout+stderr",
            )
        }
        return Parsed(
            output = body.trim('\n'),
            stderr = "",
            rc = rc,
            marker = marker,
            mode = "merged",
        )
    }

    private fun nonce(): String =
        java.util.UUID.randomUUID().toString().replace("-", "").take(12)

    /**
     * The script that keeps stdout and stderr apart: the command's group is redirected
     * into two temp files, the files are printed back between markers, and the command's
     * own status is printed after them.
     */
    private fun splitScript(command: String): String {
        val id = nonce()
        return "set +e\n" +
            "__o=/data/local/tmp/maplesu-shell-" + id + ".out\n" +
            "__e=/data/local/tmp/maplesu-shell-" + id + ".err\n" +
            ": >\"\$__o\" 2>/dev/null || printf '%s\\n' '" + TMP_UNWRITABLE + "'\n" +
            "{\n" + command + "\n} >\"\$__o\" 2>\"\$__e\"\n" +
            "__rc=\$?\n" +
            "printf '\\n%s\\n' '" + OUT_BEGIN + "'\n" +
            "cat \"\$__o\" 2>/dev/null\n" +
            "printf '\\n%s\\n' '" + OUT_END + "'\n" +
            "printf '%s\\n' '" + ERR_BEGIN + "'\n" +
            "cat \"\$__e\" 2>/dev/null\n" +
            "printf '\\n%s\\n' '" + ERR_END + "'\n" +
            "printf '%s%s\\n' '" + MARKER + "' \"\$__rc\"\n" +
            "rm -f \"\$__o\" \"\$__e\"\n" +
            "exit 0\n"
    }

    /** Fallback when `/data/local/tmp` is not writable: one merged stream, real rc. */
    private fun mergedScript(command: String): String =
        "set +e\n" + command + " 2>&1\n" +
            "__rc=\$?\n" +
            "printf '%s%s\\n' '" + MARKER + "' \"\$__rc\"\n" +
            "exit 0\n"

    /** POSIX single-quote quoting: `it's` -> `'it'\''s'`. */
    fun quote(text: String): String = "'" + text.replace("'", "'\\''") + "'"
}

/**
 * The two platform requests that keep a background-ish UID out of the idle/cached set,
 * recorded but never fatal: a vendor build is free to ignore either of them.
 *
 * <p>With the foreground Activity disabled by default these two requests **are** the
 * keep-alive, so each one is re-read afterwards instead of being assumed.
 */
internal object DeviceIdlePolicy {
    private const val POLICY =
        "`cmd deviceidle whitelist +<pkg>` and `am set-inactive <pkg> false` are attempted " +
            "once, before the long attempt, through UiAutomation.executeShellCommand " +
            "(shell UID) wrapped in `sh -c`, and each one is read back " +
            "(`cmd deviceidle whitelist`, `am get-inactive <pkg>`). A non-zero rc or " +
            "missing output is recorded in this node; it never fails the test."

    fun apply(context: Context): JSONObject {
        val packageName = context.packageName
        return JSONObject()
            .put("appliedAtMillis", System.currentTimeMillis())
            .put("packageName", packageName)
            .put("policy", POLICY)
            .put("keepAliveRole", "primary: the foreground Activity is DISABLED_BY_DEFAULT")
            .put("fatalOnFailure", false)
            .put("whitelistBefore", whitelistState(packageName))
            .put("whitelistAdd", InstrumentationShell.run(
                "cmd deviceidle whitelist +" + packageName))
            .put("whitelistAfter", whitelistState(packageName))
            .put("setInactive", InstrumentationShell.run(
                "am set-inactive " + packageName + " false"))
            .put("inactiveAfter", InstrumentationShell.run(
                "am get-inactive " + packageName))
    }

    /**
     * The device's own answer to "is this package on the doze allowlist right now".
     *
     * <p>`cmd deviceidle whitelist` prints one `<type>,<package>,<uid>` line per entry,
     * so the match is on the comma-separated package field, not on a suffix. A build
     * that does not have the `cmd` sub-command falls back to
     * `dumpsys deviceidle whitelist` and records which source answered.
     */
    private fun whitelistState(packageName: String): JSONObject {
        val primary = InstrumentationShell.run("cmd deviceidle whitelist")
        val fallback = if (primary.optString("output").contains("Unknown command")) {
            InstrumentationShell.run("dumpsys deviceidle whitelist")
        } else {
            null
        }
        val record = fallback ?: primary
        val lines = record.optString("output").lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toList()
        val listed = lines.any { line ->
            val fields = line.split(',').map { it.trim() }
            fields.any { it == packageName } || line == packageName
        }
        return record
            .put("source", if (fallback == null) "cmd deviceidle whitelist"
                else "dumpsys deviceidle whitelist (cmd sub-command unavailable)")
            .put("matchRule", "a comma-separated field or a whole line equals the package name")
            .put("listed", listed)
            .put("whitelisted", if (record.optBoolean("ok")) listed else JSONObject.NULL)
            .put("lineCount", lines.size)
    }
}

/**
 * What the platform logged about this package's processes dying: `am_kill` /
 * `am_proc_died` lines from the events buffer, the crash buffers for contrast, and a
 * classification that separates a **system reclaim of a cached process**
 * (`Cached(nirvana)`, `empty`, `lmkd`, ...) from an App crash.
 *
 * <p>This is evidence, never a verdict on its own: [systemKillLine] only returns a line
 * that can be attributed to this run or to this attempt's pids, and the tests then
 * replace a vague failure token with `PROCESS_KILLED_BY_SYSTEM:<line>`.
 */
internal object ProcessKillEvidence {
    private const val TAIL_LINES = 120
    private const val LINE_LIMIT = 400

    /** `Cached(nirvana)` and friends: the process was reclaimed, not crashed. */
    private const val CACHED_RECLAIM = "CACHED_RECLAIM"
    private const val SYSTEM_RECLAIM = "SYSTEM_RECLAIM"

    /** The kill reason classes this device family produces for a *cached* process. */
    private val CACHED_REASON = Regex("(?i)cached|nirvana")
    private val RECLAIM_REASON = Regex("(?i)empty process|lmkd|low.?memory|reclaim|trim.?memory")

    fun collect(context: Context, tag: String, sinceMillis: Long? = null): JSONObject {
        val packageName = context.packageName
        val document = JSONObject()
            .put("tag", tag)
            .put("collectedAtMillis", System.currentTimeMillis())
            .put("sinceMillis", sinceMillis ?: JSONObject.NULL)
            .put("processPid", android.os.Process.myPid())
            .put("processName", processName())
            .put("packageName", packageName)

        val events = InstrumentationShell.run(
            "logcat -b events -d -v threadtime" +
                " | grep -E 'am_kill|am_proc_died|am_crash|am_anr'" +
                " | grep -F '" + packageName + "' | tail -n " + TAIL_LINES
        )
        document.put("events", events)
        val lines = events.optString("output").lineSequence()
            .filter { it.isNotBlank() }
            .map { bounded(it.trim(), LINE_LIMIT) }
            .toList()
        document.put("lines", JSONArray().apply { lines.forEach { put(it) } })

        val kills = JSONArray()
        val crashes = JSONArray()
        var lastSystemKill: String? = null
        var lastCachedKill: String? = null
        for (line in lines) {
            val record = parse(line, sinceMillis) ?: continue
            val kind = record.optString("kind")
            if (kind == "am_kill" || kind == "am_proc_died") {
                kills.put(record)
                if (record.optBoolean("systemReclaim", false)) {
                    lastSystemKill = line
                    if (record.optString("reclaimClass") == CACHED_RECLAIM) lastCachedKill = line
                }
            } else {
                crashes.put(record)
            }
        }
        document.put("killRecords", kills)
        document.put("crashSignals", crashes)
        document.put("systemKill", lastSystemKill != null)
        document.put("systemKillLine", lastSystemKill ?: JSONObject.NULL)
        document.put("cachedReclaim", lastCachedKill != null)
        document.put("cachedReclaimLine", lastCachedKill ?: JSONObject.NULL)

        /*
         * The window manager's own record of an Activity's owner process dying without
         * saving state - the shape this device produced when MainActivity was launched
         * from the instrumentation process.
         */
        document.put("windowManager", InstrumentationShell.run(
            "logcat -b system -d -v threadtime" +
                " | grep -E 'wm_finish_activity|wm_on_create_called|ActivityTaskManager'" +
                " | grep -F '" + packageName + "' | tail -n 60"
        ))

        /* The contrast: a crash has a FATAL/tombstone; a reclaim has none of that. */
        val crashBuffer = InstrumentationShell.run("logcat -b crash -d -t 80")
        document.put("crashBuffer", crashBuffer)
        /* `isNull(error)`, not a string test: JSONObject.NULL prints as "null". */
        document.put("crashBufferEmpty", crashBuffer.optString("output").isBlank() &&
            crashBuffer.optInt("rc", 0) == 0 && crashBuffer.isNull("error"))
        document.put("fatalLines", InstrumentationShell.run(
            "logcat -b main -d -t 600" +
                " | grep -E 'FATAL EXCEPTION|AndroidRuntime|Force finishing|ANR in'" +
                " | grep -F '" + packageName + "' | tail -n 40"
        ))
        document.put("exitInfo", InstrumentationShell.run(
            "dumpsys activity exit-info " + packageName + " 2>&1 | head -n 60"))
        document.put("interpretation",
            "am_kill with a cached/nirvana reason is a system reclaim of a cached " +
                "process, not an App crash: it has no tombstone and no FATAL EXCEPTION. " +
                "A `wm_finish_activity ... proc died without state saved` line without an " +
                "am_kill is the window manager reporting the owner process of an Activity " +
                "dying - which is what a launched MainActivity produced on 2026-10-31. " +
                "crashBufferEmpty is only claimed when the crash-buffer command itself " +
                "succeeded (rc==0).")
        return document
    }

    /**
     * The line that explains a death, or null when nothing can be attributed:
     *  - a `systemReclaim` kill whose pid is one of [pids] (this attempt's owner/worker),
     *    which is how a killed attempt is explained on the next run; otherwise
     *  - a `systemReclaim` kill seen **during this run** (`withinRun`).
     *
     * A kill of an unrelated process and an old kill from another boot are both ignored.
     */
    fun systemKillLine(
        evidence: JSONObject,
        pids: Set<Int> = emptySet(),
        sinceMillis: Long? = null,
    ): String? {
        val records = evidence.optJSONArray("killRecords") ?: return null
        var attributed: String? = null
        var inWindow: String? = null
        for (index in 0 until records.length()) {
            val record = records.optJSONObject(index) ?: continue
            if (!record.optBoolean("systemReclaim", false)) continue
            val line = record.optString("line")
            if (line.isEmpty()) continue
            val pid = record.optInt("pid", -1)
            if (pids.isNotEmpty() && pid > 0 && pids.contains(pid)) {
                attributed = line
                continue
            }
            if (sinceMillis != null && record.optBoolean("withinRun", false)) inWindow = line
        }
        return attributed ?: inWindow
    }

    /** The one token the tests are allowed to report for a reclaim. */
    fun token(line: String): String = "PROCESS_KILLED_BY_SYSTEM:" + line

    private fun parse(line: String, sinceMillis: Long?): JSONObject? {
        val kind = when {
            line.contains("am_kill") -> "am_kill"
            line.contains("am_proc_died") -> "am_proc_died"
            line.contains("am_crash") -> "am_crash"
            line.contains("am_anr") -> "am_anr"
            else -> return null
        }
        val body = bracketBody(line)
        val fields = body?.split(',')?.map { it.trim() } ?: emptyList()
        val pid = fields.getOrNull(1)?.toIntOrNull()
        val process = fields.getOrNull(2)?.takeIf { it.isNotEmpty() }
        val oomAdj = fields.getOrNull(3)
        val reason = if (fields.size > 4) fields.drop(4).joinToString(",") else null
        val reclaimClass = when {
            reason == null -> null
            CACHED_REASON.containsMatchIn(reason) -> CACHED_RECLAIM
            RECLAIM_REASON.containsMatchIn(reason) -> SYSTEM_RECLAIM
            else -> null
        }
        val timestampText = timestamp(line)
        val timestampMillis = timestampText?.let { parseThreadTime(it) }
        val withinRun = if (sinceMillis == null || timestampMillis == null) null
        else timestampMillis >= sinceMillis
        return JSONObject()
            .put("kind", kind)
            .put("pid", pid ?: JSONObject.NULL)
            .put("process", process ?: JSONObject.NULL)
            .put("oomAdj", oomAdj ?: JSONObject.NULL)
            .put("reason", reason ?: JSONObject.NULL)
            .put("reclaimClass", reclaimClass ?: JSONObject.NULL)
            .put("systemReclaim", reclaimClass != null)
            .put("timestampText", timestampText ?: JSONObject.NULL)
            .put("timestampMillis", timestampMillis ?: JSONObject.NULL)
            .put("withinRun", withinRun ?: JSONObject.NULL)
            .put("pidIsThisProcess", pid != null && pid == android.os.Process.myPid())
            .put("line", line)
    }

    /** `am_kill : [0,15024,dev.maplesu.manager,0,Cached(nirvana)[(instrumentation)]]`. */
    private fun bracketBody(line: String): String? {
        val open = line.indexOf('[')
        val close = line.lastIndexOf(']')
        if (open < 0 || close <= open) return null
        return line.substring(open + 1, close)
    }

    private val THREAD_TIME = Regex("^\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2}\\.\\d{3}")

    private fun timestamp(line: String): String? =
        THREAD_TIME.find(line)?.value

    /**
     * `MM-dd HH:mm:ss.SSS` carries no year and no zone; the year is filled in from now
     * and a value that would be in the future by more than a day is read as last year.
     * Unparseable text stays null (unknown), never "false".
     */
    private fun parseThreadTime(text: String): Long? = runCatching {
        val parsed = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US).parse(text)
            ?: return null
        val calendar = Calendar.getInstance()
        calendar.time = parsed
        calendar.set(Calendar.YEAR, Calendar.getInstance().get(Calendar.YEAR))
        var millis = calendar.timeInMillis
        if (millis - System.currentTimeMillis() > 24L * 3600L * 1000L) {
            calendar.add(Calendar.YEAR, -1)
            millis = calendar.timeInMillis
        }
        millis
    }.getOrNull()

    private fun processName(): String = runCatching {
        File("/proc/self/cmdline").readBytes().toString(Charsets.UTF_8).trim('\u0000')
    }.getOrDefault("unknown")
}

internal fun bounded(text: String, limit: Int): String =
    if (text.length <= limit) text else text.take(limit) + "...(truncated)"

internal fun describe(thrown: Throwable): String =
    thrown.javaClass.simpleName + ": " + (thrown.message ?: "")
