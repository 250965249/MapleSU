package dev.maplesu.manager.jailbreak

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.Timer
import java.util.TimerTask
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Step-2 canary trigger: one attempt per boot, then stop.
 *
 * <p>The canary proves four things in a single boot: the module loads from memory and
 * stays resident, a kprobe resolves `kallsyms_lookup_name`, `call_usermodehelper`
 * really started the native helper, and SELinux is back to Enforcing with a readback.
 * Its verdict is **not** the App's `MAPLESU_IR_*` status: the packaged product slot
 * deliberately carries a non-ELF stub, so `install_ir()` always ends in
 * `MAPLESU_IR_MODULE_INVALID` after the canary slot has been probed. That is the
 * designed fail-closed ending, and reading it as a canary failure would be wrong.
 *
 * <p>What this test does is therefore only: remove stale probe candidates, run the one
 * attempt, and write every observation into `jailbreak-evidence/root-canary.json` so
 * the evidence survives even if `adb` is lost.
 *
 * <p>**Evidence capture v2 (DEV-165).** Attempt #1 proved the old shape wrong: the
 * record was built *after* `JailbreakExecutor.escalate()` returned, so when the
 * instrumentation process was frozen mid-`escalate()` (the thread dump shows it inside
 * `DirtyfragAttempt.awaitStageExit`) and then killed by ActivityManager, nothing was
 * written and no `root-canary.json` existed at all. The record is now written three
 * times, and the file is the deliverable rather than a side effect:
 *
 * <ol>
 *   <li>`phase=pre` - before `escalate()` is called at all. This record cannot be lost
 *       to a hang, a freeze or a kill, and it already carries the boot id, the
 *       `getenforce` read, `/proc/modules`, the staged-helper digest and the provider
 *       log line offset `N0`;</li>
 *   <li>`phase=watchdog` - a daemon timer fires after [WATCHDOG_MILLIS] if the attempt
 *       has not returned, so a blocked call still leaves a post-attempt-ish snapshot;</li>
 *   <li>`phase=final` - in a `finally`, before any assertion. A throwable from
 *       `escalate()` is recorded in `failure` and never re-thrown before the write.</li>
 * </ol>
 *
 * <p>The file goes to `getExternalFilesDir(null)/jailbreak-evidence/root-canary.json`
 * (the `adb pull`-able path), with a best-effort copy under the app's private dir if
 * external storage is unavailable; both the path and any write error are in the record.
 * Boot-id stability is still the one hard assertion, but it is checked *after* the
 * final write - a red test must not be able to erase its own evidence.
 *
 * <p>Run it with:
 * `am instrument -w -e class dev.maplesu.manager.jailbreak.RootCanaryAndroidTest#canaryLoadsAndRestoresEnforcing dev.maplesu.manager.test/androidx.test.runner.AndroidJUnitRunner`
 */
@RunWith(AndroidJUnit4::class)
class RootCanaryAndroidTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    /**
     * Everything one attempt observed. Fields are read again at each snapshot, so the
     * pre-record, the watchdog record and the final record all describe the same run.
     */
    private inner class Run(
        val attemptId: String,
        val startedAtMillis: Long,
        val bootBefore: String?,
        val enforcingBefore: Int,
        val moduleBefore: String,
        val helperBefore: JSONObject,
        val probes: JSONObject,
        val logLinesBefore: Int,
    ) {
        @Volatile var status: JailbreakStatus? = null
        @Volatile var failure: String? = null
        @Volatile var bootAfter: String? = null
        private val writeErrors = mutableListOf<String>()

        fun recordWriteError(detail: String) {
            if (detail.isEmpty()) return
            synchronized(writeErrors) { writeErrors.add(detail) }
        }

        private fun writeErrorText(): String =
            synchronized(writeErrors) { writeErrors.joinToString("; ") }

        fun snapshot(label: String): JSONObject {
            val enforcingAfter = DirtyfragAttempt.readEnforcing()
            return JSONObject()
                .put("schemaVersion", 2)
                .put("canary", "step-2/root-canary")
                .put("phase", label)
                .put("attemptId", attemptId)
                .put("startedAtMillis", startedAtMillis)
                .put("writtenAtMillis", System.currentTimeMillis())
                .put("bootIdBefore", bootBefore ?: JSONObject.NULL)
                .put("bootIdAfter", bootAfter ?: JSONObject.NULL)
                .put("bootUnchanged",
                    bootBefore != null && bootAfter != null && bootBefore == bootAfter)
                .put("enforcingBefore", enforcingBefore)
                .put("enforcingAfter", enforcingAfter)
                .put("getenforceBefore", enforcingText(enforcingBefore))
                .put("getenforceAfter", enforcingText(enforcingAfter))
                .put("moduleLinesBefore", moduleBefore)
                .put("moduleLinesAfter", moduleLines())
                .put("stagedHelperBefore", helperBefore)
                .put("stagedHelperAfter", stagedHelper())
                .put("stagedProbes", probes)
                .put("status", statusJson(status))
                .put("statusRecord", statusRecord())
                .put("providerLog", providerTail(logLinesBefore))
                .put("failure", failure ?: JSONObject.NULL)
                .put("writeErrors", writeErrorText())
                .put("sdk", android.os.Build.VERSION.SDK_INT)
        }

        /** Non-empty when the run cannot be called a clean canary. */
        fun problems(): List<String> {
            val list = mutableListOf<String>()
            if (bootBefore == null) list.add("boot id unreadable before the attempt")
            if (bootAfter == null) list.add("boot id unreadable after the attempt")
            if (bootBefore != null && bootAfter != null && bootBefore != bootAfter) {
                list.add("boot id changed during the canary attempt")
            }
            failure?.let { list.add("attempt threw: " + it) }
            if (status == null && failure == null) list.add("escalate() returned no status")
            writeErrorText().takeIf { it.isNotEmpty() }?.let {
                list.add("evidence write: " + it)
            }
            return list
        }
    }

    /** Where adb/run-as can collect it. */
    private fun evidenceFile(): File? =
        context.getExternalFilesDir(null)?.let { File(it, "jailbreak-evidence/root-canary.json") }

    /** Best-effort copy inside the app's private dir; not adb-pullable, still durable. */
    private fun evidenceFallbackFile(): File =
        File(context.filesDir, "jailbreak-evidence/root-canary.json")

    /**
     * Writes the record and returns the error text (empty on success). Both the
     * primary external file and the private fallback are attempted; a failure never
     * escapes - it becomes part of the next record and of the test's final assertion.
     */
    @Synchronized
    private fun writeEvidence(document: JSONObject): String {
        val primary = evidenceFile()
        if (primary != null) document.put("evidencePath", primary.path)
        var error = ""
        if (primary == null) {
            error = "external files dir unavailable"
        } else {
            try {
                primary.parentFile?.let { directory ->
                    if (!directory.isDirectory && !directory.mkdirs() && !directory.isDirectory) {
                        throw java.io.IOException("mkdirs failed: " + directory.path)
                    }
                }
                writeAtomically(primary, document)
            } catch (thrown: Throwable) {
                error = describe(thrown)
            }
        }
        if (error.isNotEmpty()) {
            try {
                val fallback = evidenceFallbackFile()
                fallback.parentFile?.mkdirs()
                document.put("evidenceFallbackPath", fallback.path)
                writeAtomically(fallback, document)
            } catch (thrown: Throwable) {
                document.put("evidenceFallbackError", describe(thrown))
            }
        }
        return error
    }

    private fun writeAtomically(target: File, document: JSONObject) {
        val staging = File(target.parentFile, target.name + ".new")
        staging.writeText(document.toString(2))
        if (!staging.renameTo(target)) {
            target.writeText(document.toString(2))
            if (staging.exists() && !staging.delete()) {
                // Best effort; the rename already succeeded or the copy is complete.
            }
        }
    }

    private fun describe(thrown: Throwable): String =
        thrown.javaClass.simpleName + ": " + (thrown.message ?: "")

    /** The device-protected directory the bootstrap and the module both use. */
    private fun attemptDirectory(): File =
        context.createDeviceProtectedStorageContext().getDataDir()

    private fun providerLog(): File = File(attemptDirectory(), "maplesu-ultravider.log")

    private fun enforcingText(value: Int): String = when (value) {
        1 -> "Enforcing"
        0 -> "Permissive"
        else -> "unreadable"
    }

    /**
     * The bring-up directory can hold hand-staged `.ko` files from earlier sessions;
     * `ir_probe_staged()` would load each of them before the canary slot's own work is
     * finished. Removing them is part of making this a *single* controlled attempt.
     */
    private fun clearStagedProbes(): JSONObject {
        val directory = File(attemptDirectory(), "probe")
        val removed = mutableListOf<String>()
        val failures = mutableListOf<String>()
        val entries = directory.listFiles()
        if (entries != null) {
            for (entry in entries) {
                if (!entry.name.endsWith(".ko")) continue
                if (entry.delete()) removed.add(entry.name) else failures.add(entry.name)
            }
        }
        return JSONObject()
            .put("directory", directory.path)
            .put("present", entries != null)
            .put("removed", removed.joinToString(","))
            .put("failed", failures.joinToString(","))
    }

    /** A digest of the helper the App just staged, so a stale binary is visible. */
    private fun stagedHelper(): JSONObject {
        val file = File(attemptDirectory(), IrImages.HELPER_FILE)
        if (!file.isFile) return JSONObject().put("present", false)
        val digest = runCatching {
            java.security.MessageDigest.getInstance("SHA-256")
                .digest(file.readBytes())
                .joinToString("") { "%02x".format(it) }
        }.getOrElse { "unreadable:" + it.javaClass.simpleName }
        return JSONObject()
            .put("present", true)
            .put("bytes", file.length())
            .put("sha256", digest)
            .put("executable", file.canExecute())
            .put("path", file.path)
    }

    private fun moduleLines(): String = runCatching {
        File("/proc/modules").readLines()
            .filter { it.startsWith("maplesu_root ") }
            .joinToString("\n")
    }.getOrElse { "unreadable:" + it.javaClass.simpleName }

    /** Current line count of the provider log; the attempt's lines are the ones after it. */
    private fun providerLineCount(): Int = runCatching {
        val log = providerLog()
        if (!log.isFile) 0 else log.readLines().size
    }.getOrDefault(0)

    /**
     * The provider log holds the module's printks (the bootstrap dump and, with helper
     * v2, the helper's own `kernel |` capture) and the helper's marker line. Only the
     * lines this attempt appended are kept, so the record stays small.
     */
    private fun providerTail(fromLine: Int, limit: Int = 120): JSONObject {
        val log = providerLog()
        if (!log.isFile) return JSONObject().put("present", false)
        val lines = runCatching { log.readLines() }.getOrElse {
            return JSONObject().put("present", true).put("readable", false)
                .put("error", it.javaClass.simpleName)
        }
        val fresh = lines.drop(fromLine.coerceAtLeast(0))
        val kept = fresh.takeLast(limit)
        return JSONObject()
            .put("present", true)
            .put("readable", true)
            .put("path", log.path)
            .put("linesBefore", fromLine)
            .put("linesAfter", lines.size)
            .put("freshLines", fresh.size)
            .put("truncated", fresh.size > kept.size)
            .put("tail", kept.joinToString("\n"))
    }

    /** The persisted attempt record the executor wrote; read-only, never required. */
    private fun statusRecord(): JSONObject = runCatching {
        val file = File(File(context.filesDir, "jailbreak"), "status.json")
        if (!file.isFile) return JSONObject().put("present", false)
        JSONObject(file.readText()).put("present", true)
    }.getOrElse { JSONObject().put("present", false).put("error", it.javaClass.simpleName) }

    private fun statusJson(status: JailbreakStatus?): JSONObject {
        if (status == null) return JSONObject().put("present", false)
        return JSONObject()
            .put("present", true)
            .put("method", status.method)
            .put("stage", status.stage)
            .put("message", status.message)
            .put("rootBackend", status.rootBackend ?: JSONObject.NULL)
            .put("target", status.target ?: JSONObject.NULL)
            .put("attemptId", status.attemptId ?: JSONObject.NULL)
            .put("ownerPid", status.ownerPid ?: JSONObject.NULL)
            .put("failure", status.failure ?: JSONObject.NULL)
    }

    @Test
    fun canaryLoadsAndRestoresEnforcing() {
        val run = Run(
            attemptId = UUID.randomUUID().toString(),
            startedAtMillis = System.currentTimeMillis(),
            bootBefore = DirtyfragAttempt.readBootId(),
            enforcingBefore = DirtyfragAttempt.readEnforcing(),
            moduleBefore = moduleLines(),
            helperBefore = stagedHelper(),
            probes = clearStagedProbes(),
            logLinesBefore = providerLineCount(),
        )

        // (1) Pre-attempt record: the one write that cannot be lost to a hang or a kill.
        run.recordWriteError(writeEvidence(run.snapshot("pre")))

        // (2) Watchdog: attempt #1 was killed with the record still unwritten because the
        // write sat after a call that never returned inside the test's budget.
        val finished = AtomicBoolean(false)
        val watchdog = Timer("root-canary-evidence", true)
        watchdog.schedule(object : TimerTask() {
            override fun run() {
                if (!finished.get()) writeEvidence(run.snapshot("watchdog"))
            }
        }, WATCHDOG_MILLIS)

        var problems: List<String> = emptyList()
        var finalWriteError = ""
        try {
            val request = JailbreakRequest(
                method = "dirtyfrag",
                attemptId = run.attemptId,
                bootId = run.bootBefore,
                // The canary must not soft-reboot: the single attempt happens in this boot.
                softReboot = false,
                rootBackend = "ir",
            )
            run.status = JailbreakExecutor.escalate(context, request)
        } catch (thrown: Throwable) {
            // Recorded, never re-thrown: the write below is the deliverable.
            run.failure = describe(thrown)
        } finally {
            finished.set(true)
            watchdog.cancel()
            run.bootAfter = runCatching { DirtyfragAttempt.readBootId() }.getOrNull()
            problems = run.problems()
            finalWriteError = writeEvidence(run.snapshot("final").put(
                "problems", if (problems.isEmpty()) "" else problems.joinToString("; ")))
            run.recordWriteError(finalWriteError)
        }

        // (3) Assertions last: a red test still leaves the complete record on disk.
        assertTrue("root-canary problems: " + problems.joinToString("; "), problems.isEmpty())
        assertEquals("evidence was not written", "", finalWriteError)

        // The attempt is invalid if the device rebooted under it: record, never retry.
        assertEquals("boot id changed during the canary attempt",
            run.bootBefore, run.bootAfter)
    }

    private companion object {
        /** The attempt has 60 s inside `escalate()` alone; 90 s means "stuck", not "slow". */
        const val WATCHDOG_MILLIS = 90_000L
    }
}
