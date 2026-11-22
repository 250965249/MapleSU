package dev.maplesu.manager.jailbreak

import android.content.Context
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import org.json.JSONObject
import java.io.File

/**
 * Evidence side-cars for the third-party-su device tests. **androidTest only**.
 *
 * <p>Two facts the previous runs could not answer after the process died:
 *
 *  - **R4**: did the App / `:root_directory` process crash, when, and what did the
 *    kernel/`am` say about it? [LogcatEvidence] snapshots the `crash` buffer, the
 *    `am_proc_died`/`am_crash`/`am_anr` events and `dumpsys activity exit-info`, so
 *    the next run has the crash text *in the same JSON* as the su verdict. It is
 *    evidence only and never decides a test.
 *  - **orchestration**: was this boot's one kernel attempt already spent before the
 *    test called `prepareHook`? [AttemptGuard] reads the two product-side markers
 *    (`/dev/df` and the app-private `jailbreak-kernel-window` marker) without
 *    touching either, and never creates an attempt.
 *
 * <p>Every shell call is bounded (tail only) and every failure is recorded as data;
 * a device that cannot run `logcat` produces `{ok:false,error:...}`, never an
 * exception that would mask the test's own verdict.
 */
internal object LogcatEvidence {
    /** Keep the tail only: the newest lines are the ones that explain a death. */
    private const val TAIL_CHARS = 32_000

    fun collect(context: Context, tag: String): JSONObject {
        val document = JSONObject()
            .put("tag", tag)
            .put("collectedAtMillis", System.currentTimeMillis())
            .put("processPid", android.os.Process.myPid())
            .put("processUid", android.os.Process.myUid())
            .put("packageName", context.packageName)

        /* R4: the crash buffer itself (FATAL EXCEPTION / tombstones / lowmemorykiller). */
        document.put("crash", shell("logcat -b crash -d -t 200"))

        /* `am_proc_died` lives in the events buffer; keep the whole tail, then a filter. */
        document.put("events", shell("logcat -b events -d -t 400"))
        document.put("amProcDied", shell(
            "logcat -b events -d | grep -E 'am_proc_died|am_crash|am_anr|am_kill|am_low_memory' " +
                "| tail -n 200"
        ))
        document.put("managerEvents", shell(
            "logcat -b events -d | grep -i 'maplesu' | grep -E 'am_proc_died|am_crash|am_anr|am_kill' " +
                "| tail -n 120"
        ))

        /* The ART-side reason, when the crash buffer rotated or was never written. */
        document.put("androidRuntime", shell(
            "logcat -b main -d | grep -E 'FATAL EXCEPTION|AndroidRuntime|Process: dev\\.maplesu\\.manager" +
                "|Force finishing|ANR in' | tail -n 160"
        ))

        /* API 30+: the platform's own per-package exit record (reason + timestamp). */
        document.put("exitInfo", shell("dumpsys activity exit-info dev.maplesu.manager 2>&1"))
        return document
    }

    /**
     * One bounded shell read, through the same `sh -c`-wrapped [InstrumentationShell] the
     * liveness code uses. Without that wrapping every `... | grep ... | tail` here
     * returned nothing on this platform (`executeShellCommand` does not interpret its
     * argument as a script), which is why earlier records claimed an "empty crash buffer"
     * from a command that had not run at all.
     *
     * <p>`ok` means "the command ran and produced output"; `rc` is its own exit status,
     * so a `grep` with no match is `ok=true, rc=1` - a valid "nothing matched answer",
     * not a broken command.
     */
    private fun shell(command: String): JSONObject {
        val record = InstrumentationShell.run(command, outputLimit = TAIL_CHARS)
        val text = record.optString("output")
        record.remove("output")
        return record
            .put("lineCount", text.lineSequence().count())
            .put("bytes", text.toByteArray(Charsets.UTF_8).size)
            .put("text", tail(text))
            /*
             * `isNull`, not `optString(...).isEmpty()`: org.json stores a successful
             * command's `error` as JSONObject.NULL, whose toString() is the string "null",
             * so optString would report every success as a failure.
             */
            .put("ok", record.isNull("error"))
            .put("rcNote", "rc is the command's own exit status through sh -c; a non-zero " +
                "rc from a `... | grep ...` pipeline means 'no match', not 'did not run'")
    }

    private fun tail(text: String): String =
        if (text.length <= TAIL_CHARS) text
        else "...(" + (text.length - TAIL_CHARS) + " chars truncated)\n" + text.takeLast(TAIL_CHARS)
}

/**
 * Read-only view of the two per-boot attempt guards. Never creates, clears or ranks
 * an attempt; `rebootRequired` is an observation (either marker is set) that the
 * tests use to phrase their remediation, not a product decision.
 */
internal object AttemptGuard {
    fun read(context: Context, bootId: String?): JSONObject {
        val document = JSONObject()
        document.put("bootId", bootId ?: JSONObject.NULL)

        val devDf = JSONObject().put("path", "/dev/df")
        try {
            val stat = Os.stat("/dev/df")
            devDf.put("present", true)
                .put("uid", stat.st_uid)
                .put("mode", stat.st_mode)
        } catch (error: ErrnoException) {
            if (error.errno == OsConstants.ENOENT) {
                devDf.put("present", false)
            } else {
                // Not "absent": the stat itself was refused, which is a different fact.
                devDf.put("present", JSONObject.NULL)
                devDf.put("errno", error.errno)
            }
        } catch (error: Throwable) {
            devDf.put("present", JSONObject.NULL)
            devDf.put("error", error.javaClass.simpleName + ": " + (error.message ?: ""))
        }
        document.put("devDf", devDf)
        document.put("devDfPresent", devDf.optBoolean("present", false))

        val window = File(context.filesDir, "jailbreak-kernel-window")
        val spent = JSONObject()
            .put("path", window.absolutePath)
            .put("present", window.isFile)
        val text = runCatching { window.readText().trim() }.getOrNull()
        spent.put("bootId", text ?: JSONObject.NULL)
        spent.put("matchesThisBoot", bootId != null && text == bootId)
        document.put("kernelWindow", spent)
        document.put("kernelWindowSpentThisBoot", spent.optBoolean("matchesThisBoot", false))

        document.put(
            "rebootRequired",
            devDf.optBoolean("present", false) || spent.optBoolean("matchesThisBoot", false),
        )
        return document
    }
}
