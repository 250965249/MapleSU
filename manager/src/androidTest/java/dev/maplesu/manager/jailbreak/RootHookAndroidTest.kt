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
 * Step-3 trigger: one hook handover attempt per boot, then stop.
 *
 * <p>What this test proves is the step-3 acceptance, not the App's status: the module
 * loads from memory through the canary slot, the UMH helper runs as kernel-domain root,
 * SELinux is restored and read back, the module is *unloaded* through `delete_module`,
 * and the two evidence files carry the observations. The verdict is read from
 * `maplesu-hook.json` / `maplesu-hook-unload.json` (through [HookEvidence]); the App's
 * `MAPLESU_IR_MODULE_INVALID` is the designed ending of the R1 delivery and is **not** a
 * hook failure - the product IR slot deliberately carries a non-ELF stub.
 *
 * <p>The record is written three times, exactly like the step-2 canary
 * (`RootCanaryAndroidTest`, DEV-165), because attempt #1 of that series lost its whole
 * record to a freeze inside `escalate()`: `phase=pre` before the attempt,
 * `phase=watchdog` from a timer, and `phase=final` in `finally` before any assertion.
 * A throwable is recorded and never re-thrown before the write.
 *
 * <p>The one hard assertion is boot-id stability. Hook evidence presence is *recorded*
 * (and the files are copied into the record), not asserted: step-3 acceptance is judged
 * from the provider log and the two JSONs, so a red test must not be able to hide them.
 *
 * <p>Run it with:
 * `am instrument -w -e class dev.maplesu.manager.jailbreak.RootHookAndroidTest#hookHandsOverAndUnloads dev.maplesu.manager.test/androidx.test.runner.AndroidJUnitRunner`
 */
@RunWith(AndroidJUnit4::class)
class RootHookAndroidTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    /** Everything one attempt observed; re-read at each snapshot. */
    private inner class Run(
        val attemptId: String,
        val startedAtMillis: Long,
        val bootBefore: String?,
        val enforcingBefore: Int,
        val moduleBefore: String,
        val stagedBootstrapBefore: JSONObject,
        val packagedHookModule: JSONObject,
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
                .put("schemaVersion", 3)
                .put("hook", "step-3/root-hook")
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
                .put("stagedBootstrapBefore", stagedBootstrapBefore)
                .put("stagedBootstrapAfter", stagedBootstrap())
                .put("packagedHookModule", packagedHookModule)
                .put("stagedProbes", probes)
                .put("status", statusJson(status))
                .put("statusRecord", statusRecord())
                .put("hookEvidence", hookEvidence())
                .put("providerLog", providerTail(logLinesBefore))
                .put("providerHookLines", providerHookLines(logLinesBefore))
                .put("failure", failure ?: JSONObject.NULL)
                .put("writeErrors", writeErrorText())
                .put("sdk", android.os.Build.VERSION.SDK_INT)
        }

        /** Non-empty when the run cannot be read as a clean attempt at all. */
        fun problems(): List<String> {
            val list = mutableListOf<String>()
            if (bootBefore == null) list.add("boot id unreadable before the attempt")
            if (bootAfter == null) list.add("boot id unreadable after the attempt")
            if (bootBefore != null && bootAfter != null && bootBefore != bootAfter) {
                list.add("boot id changed during the hook attempt")
            }
            failure?.let { list.add("attempt threw: " + it) }
            writeErrorText().takeIf { it.isNotEmpty() }?.let {
                list.add("evidence write: " + it)
            }
            return list
        }
    }

    /** Where adb/run-as can collect it. */
    private fun evidenceFile(): File? =
        context.getExternalFilesDir(null)?.let { File(it, "jailbreak-evidence/root-hook.json") }

    private fun evidenceFallbackFile(): File =
        File(context.filesDir, "jailbreak-evidence/root-hook.json")

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
                // Best effort; the copy above is complete.
            }
        }
    }

    private fun describe(thrown: Throwable): String =
        thrown.javaClass.simpleName + ": " + (thrown.message ?: "")

    /** The device-protected directory the helper writes its evidence into. */
    private fun attemptDirectory(): File = DirtyfragAttempt.hookEvidence(context)

    private fun providerLog(): File = File(attemptDirectory(), "maplesu-ultravider.log")

    private fun enforcingText(value: Int): String = when (value) {
        1 -> "Enforcing"
        0 -> "Permissive"
        else -> "unreadable"
    }

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

    /**
     * The staged `bs`: the file the module actually execs (design §3). It is staged by
     * `DirtyfragAttempt.stageBootstrap()` in the CE data directory, not in the
     * device-protected one, so a digest here proves the handover target exists and is
     * the build under test.
     */
    private fun stagedBootstrap(): JSONObject {
        val home = context.filesDir.parentFile
            ?: return JSONObject().put("present", false).put("error", "no data directory")
        val file = File(home, "bs")
        if (!file.isFile) return JSONObject().put("present", false).put("path", file.path)
        val digest = runCatching {
            java.security.MessageDigest.getInstance("SHA-256")
                .digest(file.readBytes())
                .joinToString("") { "%02x".format(it) }
        }.getOrElse { "unreadable:" + it.javaClass.simpleName }
        return JSONObject()
            .put("present", true)
            .put("path", file.path)
            .put("expectedPath", IrImages.HELPER_PATH)
            .put("pathMatchesModule", file.path == IrImages.HELPER_PATH)
            .put("bytes", file.length())
            .put("sha256", digest)
            .put("executable", file.canExecute())
    }

    /** The module this build believes it delivers through the canary slot. */
    private fun packagedHookModule(): JSONObject {
        val inventory = IrImages.inventory(context)
        val canary = inventory.canary
        return JSONObject()
            .put("mode", inventory.mode ?: JSONObject.NULL)
            .put("isRootCanary", inventory.isRootCanary)
            .put("helperPath", IrImages.HELPER_PATH)
            .put("helperAssetPresent", inventory.canaryHelper != null)
            .put("canaryAsset", canary?.asset ?: JSONObject.NULL)
            .put("canarySha256", canary?.sha256 ?: JSONObject.NULL)
            .put("canaryBytes", canary?.bytes ?: JSONObject.NULL)
    }

    private fun moduleLines(): String = runCatching {
        File("/proc/modules").readLines()
            .filter { it.startsWith("maplesu_root ") }
            .joinToString("\n")
    }.getOrElse { "unreadable:" + it.javaClass.simpleName }

    private fun providerLineCount(): Int = runCatching {
        val log = providerLog()
        if (!log.isFile) 0 else log.readLines().size
    }.getOrDefault(0)

    /**
     * The two UMH evidence files, verbatim and bounded, plus the merged verdict the App
     * would derive. Reading them here is what makes the androidTest record a complete
     * artifact even if `adb pull` of the provider log is lost.
     */
    private fun hookEvidence(): JSONObject {
        val directory = attemptDirectory()
        val main = File(directory, HookEvidence.MAIN_FILE)
        val unload = File(directory, HookEvidence.UNLOAD_FILE)
        val merged = runCatching { HookEvidence.read(directory) }.getOrNull()
        return JSONObject()
            .put("directory", directory.path)
            .put("mainPresent", main.isFile)
            .put("mainBytes", if (main.isFile) main.length() else 0)
            .put("mainText", if (main.isFile) readBounded(main) else JSONObject.NULL)
            .put("unloadPresent", unload.isFile)
            .put("unloadBytes", if (unload.isFile) unload.length() else 0)
            .put("unloadText", if (unload.isFile) readBounded(unload) else JSONObject.NULL)
            .put("merged", mergedJson(merged))
    }

    private fun readBounded(file: File, limit: Int = 4096): String = runCatching {
        val text = file.readText()
        if (text.length <= limit) text else text.take(limit) + "...(truncated)"
    }.getOrElse { "unreadable:" + it.javaClass.simpleName }

    private fun mergedJson(merged: HookEvidence.Merged?): JSONObject {
        if (merged == null) return JSONObject().put("present", false)
        return JSONObject()
            .put("present", true)
            .put("verdict", merged.verdict)
            .put("ok", merged.ok)
            .put("restoreState", merged.restoreState)
            .put("origin", merged.origin ?: JSONObject.NULL)
            .put("enforcing", merged.enforcing ?: JSONObject.NULL)
            .put("failures", merged.failures ?: JSONObject.NULL)
            .put("unloadState", merged.unloadState ?: JSONObject.NULL)
            .put("unloadErrno", merged.unloadErrno ?: JSONObject.NULL)
            .put("token", merged.token ?: JSONObject.NULL)
            .put("stage2", merged.stage2 ?: JSONObject.NULL)
            .put("daemon", merged.daemon ?: JSONObject.NULL)
            .put("helper", merged.helper ?: JSONObject.NULL)
    }

    private fun providerTail(fromLine: Int, limit: Int = 160): JSONObject {
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

    /**
     * The lines the step-3 acceptance greps for, selected by prefix: the helper's own
     * `maplesu-hook:` records, the module's printks and the ring-buffer dumps. Design
     * §8.5 names this as the one filter change from the canary test.
     */
    private fun providerHookLines(fromLine: Int, limit: Int = 200): JSONObject {
        val log = providerLog()
        if (!log.isFile) return JSONObject().put("present", false)
        val lines = runCatching { log.readLines() }.getOrElse {
            return JSONObject().put("present", false).put("error", it.javaClass.simpleName)
        }
        val needles = listOf("maplesu-hook:", "maplesu_root:", "klog hook-")
        val selected = lines.drop(fromLine.coerceAtLeast(0))
            .filter { line -> needles.any { line.contains(it) } }
        val kept = selected.takeLast(limit)
        return JSONObject()
            .put("present", true)
            .put("selected", selected.size)
            .put("truncated", selected.size > kept.size)
            .put("needles", needles.joinToString(","))
            .put("lines", kept.joinToString("\n"))
    }

    /**
     * Step-4 (item 26): the pre-entry baseline the App wrote, verbatim. A9 reads the
     * attempt binding out of it, and a wrong `expected`/`source` pair is the cheapest
     * way to explain A3 failing later.
     */
    private fun hookEnv(): JSONObject = runCatching {
        val file = DirtyfragAttempt.hookEnvFile(context)
        JSONObject()
            .put("present", file.isFile)
            .put("path", file.path)
            .put("modeOk", if (file.isFile) HookEnv.permissionsOk(file) else false)
            .put("text", if (file.isFile) readBounded(file, 256) else JSONObject.NULL)
    }.getOrElse { JSONObject().put("present", false).put("error", it.javaClass.simpleName) }

    /** The attestation worker's own declaration, verbatim (F2/F3 cross-check). */
    private fun daemonDocument(): JSONObject = runCatching {
        val file = File(attemptDirectory(), "maplesu-hook-daemon.json")
        JSONObject()
            .put("present", file.isFile)
            .put("path", file.path)
            .put("text", if (file.isFile) readBounded(file) else JSONObject.NULL)
    }.getOrElse { JSONObject().put("present", false).put("error", it.javaClass.simpleName) }

    /**
     * Step-4 A10/A11: the kernel-credentialed attestation for this attempt. A12 compares
     * `statusRecord.workerPid` against `peerPid` here, so a self-declared pid cannot pass.
     */
    private fun attestation(request: JailbreakRequest): JSONObject = runCatching {
        val result = HookWorker.attest(context, request)
        if (result == null) {
            JSONObject().put("present", false)
                .put("reason", "worker_unreachable")
        } else {
            JSONObject()
                .put("present", true)
                .put("peerUid", result.peerUid)
                .put("peerPid", result.peerPid)
                .put("replyPid", result.replyPid)
                .put("nonce", result.nonce)
                .put("nonceEcho", result.replyNonce ?: JSONObject.NULL)
                .put("bootId", result.bootId ?: JSONObject.NULL)
                .put("attempt", result.attempt ?: JSONObject.NULL)
                .put("replyBootId", result.replyBootId ?: JSONObject.NULL)
                .put("replyAttempt", result.replyAttempt ?: JSONObject.NULL)
                .put("domain", result.domain ?: JSONObject.NULL)
                .put("enforcing", result.enforcing ?: JSONObject.NULL)
                .put("starttime", result.starttime ?: JSONObject.NULL)
                .put("refusal", HookWorker.refusal(result) ?: JSONObject.NULL)
        }
    }.getOrElse {
        JSONObject().put("present", false)
            .put("reason", "threw:" + it.javaClass.simpleName)
    }

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
            .put("restoreState", status.restoreState ?: JSONObject.NULL)
            .put("restoreOrigin", status.restoreOrigin ?: JSONObject.NULL)
            .put("restoreEnforcing", status.restoreEnforcing ?: JSONObject.NULL)
            .put("restoreUnloadErrno", status.restoreUnloadErrno ?: JSONObject.NULL)
            .put("restoreFailures", status.restoreFailures ?: JSONObject.NULL)
            .put("workerPid", status.workerPid ?: JSONObject.NULL)
            .put("failure", status.failure ?: JSONObject.NULL)
    }

    @Test
    fun hookHandsOverAndUnloads() {
        val run = Run(
            attemptId = UUID.randomUUID().toString(),
            startedAtMillis = System.currentTimeMillis(),
            bootBefore = DirtyfragAttempt.readBootId(),
            enforcingBefore = DirtyfragAttempt.readEnforcing(),
            moduleBefore = moduleLines(),
            stagedBootstrapBefore = stagedBootstrap(),
            packagedHookModule = packagedHookModule(),
            probes = clearStagedProbes(),
            logLinesBefore = providerLineCount(),
        )

        // (1) Pre-attempt record: cannot be lost to a hang, a freeze or a kill.
        run.recordWriteError(writeEvidence(run.snapshot("pre")))

        // (2) Watchdog: the step-2 series lost a record exactly this way.
        val finished = AtomicBoolean(false)
        val watchdog = Timer("root-hook-evidence", true)
        watchdog.schedule(object : TimerTask() {
            override fun run() {
                if (!finished.get()) writeEvidence(run.snapshot("watchdog"))
            }
        }, WATCHDOG_MILLIS)

        var problems: List<String> = emptyList()
        var finalWriteError = ""
        var request: JailbreakRequest? = null
        try {
            val attemptRequest = JailbreakRequest(
                method = "dirtyfrag",
                attemptId = run.attemptId,
                bootId = run.bootBefore,
                // One boot, one attempt: a soft reboot would spend the window and
                // invalidate the acceptance.
                softReboot = false,
                rootBackend = JailbreakRequest.BACKEND_HOOK,
            )
            request = attemptRequest
            /*
             * Step-4 (item 26 / MF-1): provider-first, and exactly **once**.
             *
             * `NativeSuDirectoryProvider.prepare` is what calls
             * `JailbreakExecutor.escalate`, so this single call *is* the product path and
             * the only place `DAEMON_READY` can be written. Doing
             * `escalate()` and then `prepareHook()` would start a second attempt in the
             * same boot, which `DirtyfragAttempt.admit` refuses with
             * `DIRTYFRAG_REBOOT_REQUIRED_AFTER_ATTEMPT` - the attempt would destroy
             * itself and the acceptance would read a self-inflicted failure (R-D13).
             */
            run.status = dev.maplesu.manager.runtime.NativeSuDaemon
                .prepareHook(context, attemptRequest)
        } catch (thrown: Throwable) {
            // Recorded, never re-thrown: the write below is the deliverable.
            run.failure = describe(thrown)
        } finally {
            finished.set(true)
            watchdog.cancel()
            run.bootAfter = runCatching { DirtyfragAttempt.readBootId() }.getOrNull()
            // Step-4: the status the provider left behind, the App's env, the worker's own
            // document and a fresh kernel-credentialed attestation. A2/A3/A8/A9/A10/A11
            // read these instead of hand-parsing the provider log.
            val evidence = run.snapshot("final")
            evidence.put("statusAfterPrepare", statusRecord())
            evidence.put("hookEnv", hookEnv())
            evidence.put("daemonDoc", daemonDocument())
            request?.let { evidence.put("attestation", attestation(it)) }
            problems = run.problems()
            finalWriteError = writeEvidence(evidence.put(
                "problems", if (problems.isEmpty()) "" else problems.joinToString("; ")))
            run.recordWriteError(finalWriteError)
        }

        // (3) Assertions last: a red test still leaves the complete record on disk.
        assertTrue("root-hook problems: " + problems.joinToString("; "), problems.isEmpty())
        assertEquals("evidence was not written", "", finalWriteError)
        assertEquals("boot id changed during the hook attempt",
            run.bootBefore, run.bootAfter)
    }

    private companion object {
        /** `escalate()` alone may spend ~60 s; the evidence re-read adds <= 2 s. */
        const val WATCHDOG_MILLIS = 120_000L
    }
}
