package dev.maplesu.manager.jailbreak

import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.NativeSuDaemon
import dev.maplesu.manager.runtime.StageMark
import dev.maplesu.manager.workmode.migration.MigrationPaths
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest
import java.util.Timer
import java.util.TimerTask
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * P1 device acceptance: does the **Normal (KernelSU) backend** actually run
 * `ksud late-load` on this kernel, and if it refuses, with which code?
 *
 * <p>Code under test: `JailbreakExecutor.escalateKsu`
 * (`manager/src/main/java/dev/maplesu/manager/jailbreak/JailbreakExecutor.kt`). The
 * executor itself only runs inside `:root_directory`; the product path reaches it
 * through `NativeSuDirectoryProvider.call("prepare")`, which is what
 * `NativeSuDaemon.management(context, request)` performs. That call is made
 * **exactly once**: `escalateKsu` spends this boot's kernel window
 * (`DirtyfragAttempt.markKernelWindow`), so a second attempt in the same boot
 * would refuse itself with `DIRTYFRAG_REBOOT_REQUIRED_AFTER_ATTEMPT`.
 *
 * <p>The route marker and the staged daemon are not written here on purpose:
 * `DirtyfragAttempt.startKernelSu` writes `<DE>/use-ksu` and stages
 * `libksud_ksu.so` as `<CE>/ksud` itself, and a marker written by the test would
 * be a route the product never chose. If the daemon is not packaged the route
 * fails closed with `MAPLESU_KSU_DAEMON_MISSING`, which is exactly the evidence
 * this test wants.
 *
 * <p>**Verdict vocabulary.** The provider's own channel is the only verdict
 * either side can honestly read, so the record classifies the run as:
 *
 *  - [VERDICT_OK] - the fresh provider log carries
 *    `maplesu-dirtyfrag: ksu: loaded` **and** the persisted status reached
 *    `ROOT_WORKER_OBSERVED` for this attempt;
 *  - [VERDICT_OK_STAGE_UNPUBLISHED] - the same loaded marker is there, but the
 *    status never reached `ROOT_WORKER_OBSERVED`. This is a *separate* label,
 *    never folded into OK: `ksud late-load` ends with
 *    `am force-stop dev.maplesu.manager`, so on the success path the manager (and
 *    with it the executor and this test process) is normally killed **before**
 *    `escalateKsu` can publish its stage. The load still happened; the stage is
 *    missing for a reason the record names;
 *  - [VERDICT_REFUSED] - a named failure code from the provider log
 *    (`MAPLESU_KSU_*`), or from the status record / the provider exception
 *    (`MAPLESU_KSU_DAEMON_MISSING`, `MAPLESU_KSU_NOT_READY`, `DIRTYFRAG_*`, ...);
 *  - [VERDICT_INCONCLUSIVE] - none of the above; the test fails and the record
 *    says what was observed instead. This is never reported as success.
 *
 * <p>Evidence is written three ways per run - `pre` before the attempt,
 * `watchdog` from a one-second timer while it runs, `final` once the call
 * returns - because the success path kills this process. The required copy is
 * `context.filesDir/jailbreak-evidence/normal-ksu.json` (`adb shell run-as
 * dev.maplesu.manager cat ...` can read it without pulling anything), an
 * external-files copy is written too, and every write also emits one logcat line
 * `MAPLESU_NORMAL_KSU_EVIDENCE {json}` under the `MapleSU` tag.
 *
 * <p>Run it with:
 * `am instrument -w -e class dev.maplesu.manager.jailbreak.NormalKsuAndroidTest#ksuLateLoadRunsOrRefusesWithCode dev.maplesu.manager.test/androidx.test.runner.AndroidJUnitRunner`
 */
@RunWith(AndroidJUnit4::class)
class NormalKsuAndroidTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()

    /** One shell invocation; [error] is non-null when the command could not be run. */
    private class Shell(val text: String, val error: String?)

    /** One append-only log file, split at the line count observed before the attempt. */
    private class LogFile(
        val name: String,
        val path: String,
        val present: Boolean,
        val readable: Boolean,
        val linesBefore: Int,
        val linesAfter: Int,
        val fresh: List<String>,
        val error: String?,
        val note: String?,
    ) {
        fun json(): JSONObject = JSONObject()
            .put("name", name)
            .put("path", path)
            .put("present", present)
            .put("readable", readable)
            .put("linesBefore", linesBefore)
            .put("linesAfter", linesAfter)
            .put("freshLines", fresh.size)
            .put("fresh", JSONArray(fresh.takeLast(TAIL_LINES)))
            .put("error", error ?: JSONObject.NULL)
            .put("note", note ?: JSONObject.NULL)

        private companion object {
            const val TAIL_LINES = 160
        }
    }

    /** Everything the two provider channels showed for this attempt. */
    private class LogScan(
        val provider: LogFile,
        val stage: LogFile,
        val ksuLines: List<String>,
        val loaderErrors: List<String>,
        val loadedLine: String?,
        val failureToken: String?,
        val failureLine: String?,
        val lateLoadRc: String?,
        val ksudAlreadyLoaded: Boolean,
        val errors: List<String>,
    )

    /** One classified outcome; [source] names the channel the code came from. */
    private class Verdict(val name: String, val token: String?, val source: String, val reason: String)

    /** Everything this attempt observed; re-read for each evidence phase. */
    private inner class Run(val attemptId: String, val startedAtMillis: Long) {
        @Volatile var bootBefore: String? = null
        @Volatile var enforcingBefore: Int = Int.MIN_VALUE
        @Volatile var baseline: JSONObject = JSONObject()
        @Volatile var request: JailbreakRequest? = null
        @Volatile var providerLinesBefore: Int = 0
        @Volatile var stageLinesBefore: Int = 0
        @Volatile var entryThrew: String? = null
        @Volatile var entryReturned: Boolean = false
        @Volatile var callMillis: Long = -1L
        @Volatile var environmentAfter: JSONObject = JSONObject()
        @Volatile var routeNotes: String = ""

        /** Raw `jailbreak/status.json` as this attempt left it (no expiry rewrite). */
        fun rawStatus(): JSONObject? = runCatching {
            val file = File(File(context.filesDir, JailbreakStatus.DIRECTION), "status.json")
            if (!file.isFile) null else JSONObject(file.readText())
        }.getOrNull()

        fun attributedStatus(): JSONObject? =
            rawStatus()?.takeIf { it.optString("attemptId") == attemptId }

        /** The one place a verdict is computed; every phase uses it. */
        fun verdict(stage: String?, failure: String?, scan: LogScan): Verdict {
            val tokenFromLog = scan.failureToken
            val tokenFromException = entryThrew?.let { message ->
                FAILURE_TOKEN.find(message)?.groupValues?.get(1)
            }
            return when {
                /*
                 * Fail closed on a contradictory log: both a loaded marker and a
                 * FAILED token cannot describe one attempt, so the refusal wins.
                 */
                tokenFromLog != null && scan.loadedLine != null -> Verdict(
                    VERDICT_REFUSED, tokenFromLog, "log",
                    "provider log carries both '" + scan.loadedLine + "' and a FAILED " +
                        "token; refusing rather than reporting success")
                tokenFromLog != null -> Verdict(
                    VERDICT_REFUSED, tokenFromLog, "log",
                    "provider log reported " + tokenFromLog + " (" +
                        (scan.failureLine ?: "no detail line") + ")")
                scan.loadedLine != null && stage == JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED ->
                    Verdict(
                        VERDICT_OK, null, "log+status",
                        "provider log carries 'maplesu-dirtyfrag: ksu: loaded' and the " +
                            "attempt reached ROOT_WORKER_OBSERVED")
                scan.loadedLine != null -> Verdict(
                    VERDICT_OK_STAGE_UNPUBLISHED, null, "log",
                    "provider log carries 'maplesu-dirtyfrag: ksu: loaded' but the status " +
                        "stopped at " + (stage ?: "no status for this attempt") +
                        "; ksud late-load force-stops the manager, so the executor may have " +
                        "been killed before it could publish ROOT_WORKER_OBSERVED")
                failure != null -> Verdict(
                    VERDICT_REFUSED, failure, "status",
                    "status record refused the attempt with " + failure +
                        " (" + rawStatus()?.optString("message").orEmpty() + ")")
                tokenFromException != null -> Verdict(
                    VERDICT_REFUSED, tokenFromException, "exception",
                    "the preparation call threw " + tokenFromException)
                else -> Verdict(
                    VERDICT_INCONCLUSIVE, null, "none",
                    "no loaded marker, no MAPLESU_KSU_* token and no status failure for this " +
                        "attempt; nothing observed may be reported as success")
            }
        }

        /**
         * The record. Every phase rebuilds it from what is on disk *now*, so the
         * watchdog copy is a newer observation, not a repeat of the pre one.
         */
        @Synchronized
        fun snapshot(phase: String): JSONObject {
            val raw = rawStatus()
            val attributed = attributedStatus()
            val stage = attributed?.optString("stage")?.takeIf { it.isNotEmpty() && it != "null" }
            val failure = attributed?.optString("failure")?.takeIf { it.isNotEmpty() && it != "null" }
            val scan = scanLogs(includeStage = attributed != null,
                linesBefore = providerLinesBefore, stageLinesBefore = stageLinesBefore)
            val outcome = verdict(stage, failure, scan)
            val requestJson = request?.let {
                JSONObject()
                    .put("method", it.method)
                    .put("attemptId", it.attemptId)
                    .put("bootId", it.bootId ?: JSONObject.NULL)
                    .put("softReboot", it.softReboot)
                    .put("rootBackend", it.rootBackend ?: JSONObject.NULL)
                    .put("origin", it.origin)
            } ?: JSONObject.NULL
            return JSONObject()
                .put("schemaVersion", 1)
                .put("flow", "p1/normal-ksu-late-load")
                .put("phase", phase)
                .put("attemptId", attemptId)
                .put("startedAtMillis", startedAtMillis)
                .put("writtenAtMillis", System.currentTimeMillis())
                .put("verdictName", outcome.name)
                .put("verdictToken", outcome.token ?: JSONObject.NULL)
                .put("verdictReason", outcome.reason)
                .put("verdictSource", outcome.source)
                .put(
                    "verdict",
                    JSONObject()
                        .put("name", outcome.name)
                        .put("token", outcome.token ?: JSONObject.NULL)
                        .put("source", outcome.source)
                        .put("reason", outcome.reason)
                        .put("stageAtVerdict", stage ?: JSONObject.NULL)
                        .put("stagePublished", stage == JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED)
                        .put("loadedMarkerSeen", scan.loadedLine != null)
                        .put("statusAttributedToAttempt", attributed != null),
                )
                .put("request", requestJson)
                .putText("bootBefore", bootBefore)
                .put("enforcingBefore", enforcingValue(enforcingBefore))
                .put("baseline", baseline)
                .put(
                    "entry",
                    JSONObject()
                        .put("invoked", "dev.maplesu.manager.runtime.NativeSuDaemon.management")
                        .put("route", "content://" + ROOT_DIRECTORY_AUTHORITY + " prepare -> JailbreakExecutor.escalate -> escalateKsu")
                        .put("returned", entryReturned)
                        .putText("threw", entryThrew)
                        .put("elapsedMillis", callMillis),
                )
                .put(
                    "status",
                    JSONObject()
                        .put("attributed", attributed != null)
                        .put("raw", raw ?: JSONObject.NULL)
                        .put("read", statusJson(runCatching { JailbreakStatus.read(context) }.getOrNull())),
                )
                .put(
                    "logs",
                    JSONObject()
                        .put("provider", scan.provider.json())
                        .put("stage", scan.stage.json())
                        .put("ksuLines", JSONArray(scan.ksuLines))
                        .put("loaderErrors", JSONArray(scan.loaderErrors))
                        .put("ksudAlreadyLoaded", scan.ksudAlreadyLoaded)
                        .put("ksudAlreadyLoadedSource",
                            "provider/stage lines only; ksud logs it to logcat (tag KernelSU) - " +
                                "see environmentAfter.shell.logcatKsu")
                        .put("lateLoadRc", scan.lateLoadRc ?: JSONObject.NULL)
                        .put("readErrors", JSONArray(scan.errors)),
                )
                .put("stageMarks", bound(StageMark.read(context), 4096))
                .put("environmentAfter", environmentAfter)
                .putText("routeNotes", routeNotes)
                .put("sdk", android.os.Build.VERSION.SDK_INT)
        }
    }

    @Test
    fun ksuLateLoadRunsOrRefusesWithCode() {
        val run = Run(UUID.randomUUID().toString(), System.currentTimeMillis())
        run.routeNotes = ROUTE_NOTES

        // (1) Baseline, before anything that can spend this boot's window.
        run.bootBefore = runCatching { DirtyfragAttempt.readBootId() }.getOrNull()
        run.enforcingBefore = readEnforcingRobust()
        run.baseline = baseline()
        run.providerLinesBefore = lineCount(providerLog())
        run.stageLinesBefore = lineCount(nativeStageLog())

        // (2) The pre-attempt record: cannot be lost to a kill inside the handover.
        var writeError = writeEvidence(safeSnapshot(run, "pre"))

        // (3) A one-second watchdog. The success path ends with
        // `am force-stop dev.maplesu.manager`, so this is the only way the record
        // can carry what the provider logged before this process died.
        val finished = AtomicBoolean(false)
        val lastSignature = java.util.concurrent.atomic.AtomicReference("")
        val watchdog = Timer("normal-ksu-evidence", true)
        watchdog.schedule(
            object : TimerTask() {
                override fun run() {
                    if (finished.get()) return
                    runCatching {
                        val document = run.snapshot("watchdog")
                        // Only on change: a 120 s run must not write 120 copies.
                        val signature = document.optString("verdictName") + "|" +
                            document.optString("verdictToken") + "|" +
                            (document.getJSONObject("status").optJSONObject("raw")?.toString() ?: "") + "|" +
                            document.getJSONObject("logs").getJSONObject("provider")
                                .optInt("linesAfter") + "|" +
                            document.getJSONObject("logs").getJSONObject("stage")
                                .optInt("linesAfter")
                        if (signature != lastSignature.getAndSet(signature)) {
                            writeEvidence(document)
                        }
                    }
                }
            },
            WATCHDOG_PERIOD_MILLIS,
            WATCHDOG_PERIOD_MILLIS,
        )

        var finalDocument: JSONObject? = null
        try {
            // (4) The product path, exactly once. `escalateKsu` needs nothing from
            // this process except the request: it stages `use-ksu` and the daemon
            // itself. On this backend the provider's lease-directory step is
            // expected to refuse after a successful escalation (there is no lease
            // on the KernelSU route); that refusal is recorded, never judged.
            val attemptRequest = JailbreakRequest(
                method = "dirtyfrag",
                attemptId = run.attemptId,
                bootId = run.bootBefore,
                // The KernelSU handoff issues its own `ksud soft-reboot`; this flag
                // only drives the lease route's reboot and stays as the product sets it.
                softReboot = true,
                rootBackend = JailbreakRequest.BACKEND_KSU,
            )
            run.request = attemptRequest
            val startedCall = System.currentTimeMillis()
            try {
                NativeSuDaemon.management(context, attemptRequest)
                run.entryReturned = true
            } catch (thrown: Throwable) {
                run.entryThrew = describeChain(thrown)
            } finally {
                run.callMillis = System.currentTimeMillis() - startedCall
            }

            // (5) Bounded observation of a provider that may still be waiting for
            // `ksud late-load` (the bootstrap waits up to 120 s). Stop as soon as a
            // verdict exists; never invent one at the deadline.
            val deadline = run.startedAtMillis + WAIT_MILLIS
            while (System.currentTimeMillis() < deadline && !finished.get()) {
                val scan = scanLogs(
                    includeStage = run.attributedStatus() != null,
                    linesBefore = run.providerLinesBefore,
                    stageLinesBefore = run.stageLinesBefore,
                )
                val status = run.attributedStatus()
                val outcome = run.verdict(
                    status?.optString("stage")?.takeIf { it.isNotEmpty() && it != "null" },
                    status?.optString("failure")?.takeIf { it.isNotEmpty() && it != "null" },
                    scan,
                )
                if (outcome.name != VERDICT_INCONCLUSIVE) break
                runCatching { Thread.sleep(POLL_MILLIS) }
            }
        } finally {
            finished.set(true)
            watchdog.cancel()
            run.environmentAfter = environmentAfter(run.startedAtMillis - 2_000L)
            val document = safeSnapshot(run, "final")
            finalDocument = document
            writeError = writeEvidence(document)
        }

        // (6) Assertions last: everything above has already left the record on disk.
        assertEquals("the evidence record was not written: " + writeError, "", writeError)

        val document = requireNotNull(finalDocument) { "no evidence document was produced" }
        val verdictName = document.optString("verdictName")
        val verdictToken = document.optString("verdictToken")
        val detail = document.optString("verdictReason") +
            " (status=" + run.attributedStatus() + " threw=" + run.entryThrew + ")"
        assertNotNull("boot id is unreadable before the attempt", run.bootBefore)
        assertTrue(
            "the attempt did not reach the KernelSU route at all: " + detail,
            document.getJSONObject("status").optBoolean("attributed") ||
                run.entryThrew != null,
        )
        /*
         * The one shape assertion this test makes: either the provider said the
         * module loaded, or it named a code. "Nothing observed" is a red test, not
         * a pass - a silent run must never read as a working Normal backend.
         */
        assertTrue(
            "no KernelSU verdict: " + detail,
            verdictName == VERDICT_OK ||
                verdictName == VERDICT_OK_STAGE_UNPUBLISHED ||
                verdictName == VERDICT_REFUSED,
        )
        if (verdictName == VERDICT_REFUSED) {
            assertTrue(
                "refused without a stable code: " + detail,
                verdictToken.isNotEmpty(),
            )
        }
        assertTrue(
            "the loaded marker was reported without being in the provider log: " + detail,
            document.getJSONObject("verdict").optBoolean("loadedMarkerSeen") ||
                verdictName != VERDICT_OK,
        )
    }

    /**
     * A snapshot that cannot itself fail the run. Collecting evidence is the
     * deliverable, so a defect in one collector must still leave a record behind
     * (with the defect named) instead of throwing before the write.
     */
    private fun safeSnapshot(run: Run, phase: String): JSONObject =
        runCatching { run.snapshot(phase) }.getOrElse { thrown ->
            JSONObject()
                .put("schemaVersion", 1)
                .put("flow", "p1/normal-ksu-late-load")
                .put("phase", phase)
                .put("attemptId", run.attemptId)
                .put("startedAtMillis", run.startedAtMillis)
                .put("writtenAtMillis", System.currentTimeMillis())
                .put("verdictName", VERDICT_INCONCLUSIVE)
                .put("verdictReason", "the evidence snapshot itself failed: " + describe(thrown))
                .putText("bootBefore", run.bootBefore)
                .putText("entryThrew", run.entryThrew)
        }

    // ---------------------------------------------------------------- baseline

    /** Device facts an ordinary app can observe, plus the packaged route inputs. */
    private fun baseline(): JSONObject {
        val bootId = runCatching { DirtyfragAttempt.readBootId() }.getOrNull()
        val windowFile = File(context.filesDir, "jailbreak-kernel-window")
        val window = runCatching { windowFile.takeIf { it.isFile }?.readText()?.trim() }.getOrNull()
        val nativeDir = context.applicationInfo.nativeLibraryDir
        val ksud = nativeDir?.let { File(it, DirtyfragAttempt.KSU_DAEMON_LIBRARY) }
        val attemptDirectory = DirtyfragAttempt.hookEvidence(context)
        val providerFile = providerLog()
        val stageFile = nativeStageLog()
        return JSONObject()
            .put("capturedAtMillis", System.currentTimeMillis())
            .putText("bootId", bootId)
            .put("enforcing", enforcingValue(runCatching { DirtyfragAttempt.readEnforcing() }.getOrDefault(-1)))
            .put("sdk", android.os.Build.VERSION.SDK_INT)
            .putText("androidRelease", android.os.Build.VERSION.RELEASE)
            .putText("fingerprint", android.os.Build.FINGERPRINT)
            .putText("model", android.os.Build.MODEL)
            .putText("soc", runCatching { android.os.Build.SOC_MODEL }.getOrNull())
            .putText("securityPatch", android.os.Build.VERSION.SECURITY_PATCH)
            .put("supportedAbis", JSONArray(android.os.Build.SUPPORTED_ABIS.toList()))
            .put(
                "kernelWindow",
                JSONObject()
                    .putText("path", windowFile.path)
                    .putText("recorded", window)
                    .put("spentInThisBoot", window != null && window == bootId),
            )
            .put(
                "packagedRouteInputs",
                JSONObject()
                    .putText("nativeLibraryDir", nativeDir)
                    .put(
                        "ksud",
                        JSONObject()
                            .putText("name", DirtyfragAttempt.KSU_DAEMON_LIBRARY)
                            .put("present", ksud?.isFile == true)
                            .put("executable", ksud?.canExecute() == true)
                            .put("bytes", ksud?.length() ?: 0L)
                            .putText("sha256", ksud?.let { digestOf(it) }),
                    )
                    .put(
                        "managerPackage",
                        JSONObject()
                            .putText("expected", DirtyfragAttempt.KSU_MANAGER_PACKAGE)
                            .put("isThisApp", DirtyfragAttempt.KSU_MANAGER_PACKAGE ==
                                context.packageName),
                    ),
            )
            .put(
                "stagedState",
                JSONObject()
                    .putText("attemptDirectory", attemptDirectory.path)
                    .put(
                        "useKsuMarker",
                        JSONObject()
                            .putText("name", DirtyfragAttempt.USE_KSU)
                            .put("present", File(attemptDirectory, DirtyfragAttempt.USE_KSU).isFile)
                            .put("clearedByThisTest", false),
                    )
                    .put(
                        "stagedKsud",
                        JSONObject()
                            .put("present", File(attemptDirectory.parentFile, "ksud").isFile)
                            .put("path", File(attemptDirectory.parentFile, "ksud").path),
                    )
                    .put("stagedBootstrap", File(attemptDirectory.parentFile, "bs").path)
                    .put("providerLogPresent", providerFile.isFile)
                    .put("providerLogLines", lineCount(providerFile))
                    .put("nativeStageLogPresent", stageFile.isFile)
                    .put("nativeStageLogLines", lineCount(stageFile)),
            )
            .put("ksuManagerPackages", installedPackages(MigrationPaths.KSU_MANAGER_PACKAGES))
            .put("previousStatus", runCatching { JSONObject(File(File(context.filesDir, "jailbreak"), "status.json").readText()) }.getOrNull() ?: JSONObject.NULL)
            .put(
                "shell",
                JSONObject()
                    .put("getenforce", shellJson(shell("getenforce")))
                    .put("uname", shellJson(shell("uname -a")))
                    .put("buildProps", shellJson(shell("getprop ro.build.version.release; getprop ro.build.fingerprint")))
                    .put("selinuxEnforce", shellJson(shell("cat /sys/fs/selinux/enforce")))
                    .put("mounts", shellJson(shell("cat /proc/mounts")))
                    .put("ps", shellJson(shell("ps -A -o USER,PID,PPID,NAME")))
                    .put("ksuProcesses", shellJson(shell("ps -A -o PID,NAME | grep -Ei 'ksud|kernelsu' || true")))
                    .put("procModules", shellJson(shell("cat /proc/modules 2>&1 | head -40")))
                    .put("dataAdbKsud", shellJson(shell("ls -l " + MigrationPaths.KSUD + " 2>&1")))
                    .put("devMarkers", shellJson(shell("ls -l /dev/df /dev/dfm* /dev/dfme* /dev/dfmw* 2>&1")))
                    .put("attemptDirectoryListing", shellJson(shell("ls -la /data/user_de/0/" + context.packageName + " 2>&1 | head -40")))
                    /*
                     * KernelSU activity that predates this attempt. A `ksud` already
                     * running (or an earlier `KernelSU` log line) means `has_kernelsu()`
                     * may short-circuit the load, which changes how a "loaded" verdict
                     * must be read - so it is recorded before anything runs.
                     */
                    .put("logcatTail", shellJson(shell("logcat -d -v brief -t 40 2>&1")))
                    .put("logcatKsuBaseline", shellJson(logcatKsu(System.currentTimeMillis() - 120_000L)))
                    .put("daemonCachedEndpointPresent",
                        runCatching { NativeSuDaemon.current() != null }.getOrDefault(false)),
            )
    }

    /** The same device facts after the attempt, for the before/after comparison. */
    private fun environmentAfter(sinceMillis: Long): JSONObject = JSONObject()
        .put("capturedAtMillis", System.currentTimeMillis())
        .putText("bootId", runCatching { DirtyfragAttempt.readBootId() }.getOrNull())
        .put("enforcing", enforcingValue(readEnforcingRobust()))
        .put("ksuManagerPackages", installedPackages(MigrationPaths.KSU_MANAGER_PACKAGES))
        .put(
            "stagedState",
            JSONObject()
                .put("useKsuMarker",
                    File(DirtyfragAttempt.hookEvidence(context), DirtyfragAttempt.USE_KSU).isFile)
                .put("stagedKsud",
                    File(DirtyfragAttempt.hookEvidence(context).parentFile, "ksud").isFile)
                .put("providerLogLines", lineCount(providerLog()))
                .put("nativeStageLogLines", lineCount(nativeStageLog())),
        )
        .put(
            "shell",
            JSONObject()
                .put("getenforce", shellJson(shell("getenforce")))
                .put("mounts", shellJson(shell("cat /proc/mounts")))
                .put("ps", shellJson(shell("ps -A -o USER,PID,PPID,NAME")))
                .put("ksuProcesses", shellJson(shell("ps -A -o PID,NAME | grep -Ei 'ksud|kernelsu' || true")))
                .put("procModules", shellJson(shell("cat /proc/modules 2>&1 | head -40")))
                .put("dataAdbKsud", shellJson(shell("ls -l " + MigrationPaths.KSUD + " 2>&1")))
                .put("devMarkers", shellJson(shell("ls -l /dev/df /dev/dfm* /dev/dfme* /dev/dfmw* 2>&1")))
                /*
                 * ksud logs through android_logger (tag "KernelSU"), so its module
                 * loader's own reason - "Cannot find symbol", "disagrees about version
                 * of symbol", the kernel's init_module dump - never reaches the pipe
                 * the bootstrap captured. `shell` holds READ_LOGS, this process does
                 * not, which is why the reason is collected here and only here.
                 */
                .put("logcatKsu", shellJson(logcatKsu(sinceMillis))),
        )

    /**
     * The filtered device log since before the attempt. This is where ksud's own
     * android_logger output (tag `KernelSU`) and the kernel's `init_module` error
     * text end up; the stable code always comes from the provider log instead.
     */
    private fun logcatKsu(sinceMillis: Long): Shell {
        val stamp = java.text.SimpleDateFormat("MM-dd HH:mm:ss.SSS", java.util.Locale.US)
            .format(java.util.Date(sinceMillis))
        return shell(
            "logcat -d -v threadtime -T \"" + stamp + "\" 2>/dev/null | grep -Ei " +
                "'ksud|kernelsu|late.load|${dev.maplesu.manager.compat.StoredInputs.ENVIRONMENT_NAME_PATTERN}|maplesu|init_module|vermagic|" +
                "version magic|unknown symbol|import_ns|modversions' | tail -200",
        )
    }

    // -------------------------------------------------------------------- logs

    /**
     * The provider's two channels, split at this attempt's starting line count so
     * an earlier attempt (or an earlier boot) can never be read as this one's
     * success.
     *
     * <p>`native-stage.log` is deleted by `DirtyfragAttempt.start` before the
     * attempt starts, which is why it is only trusted once a status record for
     * this attempt exists; until then its lines belong to somebody else.
     */
    private fun scanLogs(includeStage: Boolean, linesBefore: Int, stageLinesBefore: Int): LogScan {
        val provider = readLog(
            name = "maplesu-ultravider.log",
            file = providerLog(),
            linesBefore = linesBefore,
            forceFresh = false,
        )
        val stage = readLog(
            name = "native-stage.log",
            file = nativeStageLog(),
            linesBefore = stageLinesBefore,
            forceFresh = includeStage,
        )
        val evidence = provider.fresh + (if (includeStage) stage.fresh else emptyList())
        val ksuLines = evidence.filter { line -> KSU_NEEDLES.any { line.contains(it, ignoreCase = true) } }
        val loaderErrors = evidence.filter { line -> LOADER_ERROR_NEEDLES.any { line.contains(it, ignoreCase = true) } }
        val loadedLine = evidence.firstOrNull { it.contains(LOADED_MARKER) }
        val failureLine = evidence.firstOrNull { KSU_FAILURE.containsMatchIn(it) }
            ?: evidence.firstOrNull { it.contains("ksu: FAILED") }
        val token = failureLine?.let { KSU_FAILURE.find(it)?.groupValues?.get(1) }
            ?: ksuLines.firstNotNullOfOrNull { KSU_ANY_TOKEN.find(it)?.groupValues?.get(1) }
        val lateLoad = evidence.firstOrNull { it.contains("ksu late-load rc=") }
            ?.let { LATE_LOAD_RC.find(it)?.groupValues?.get(1) }
        val errors = listOfNotNull(provider.error, stage.error)
        return LogScan(
            provider = provider,
            stage = stage,
            ksuLines = ksuLines.takeLast(200),
            loaderErrors = loaderErrors.takeLast(40),
            loadedLine = loadedLine,
            failureToken = token,
            failureLine = failureLine,
            lateLoadRc = lateLoad,
            ksudAlreadyLoaded = evidence.any { it.contains("KernelSU already loaded", ignoreCase = true) },
            errors = errors,
        )
    }

    private fun readLog(name: String, file: File, linesBefore: Int, forceFresh: Boolean): LogFile {
        if (!file.isFile) {
            return LogFile(name, file.path, false, false, linesBefore, 0, emptyList(), null, null)
        }
        val lines = runCatching { file.readLines() }.getOrElse {
            return LogFile(name, file.path, true, false, linesBefore, 0, emptyList(),
                it.javaClass.simpleName + ": " + (it.message ?: ""), null)
        }
        val truncated = lines.size < linesBefore
        val fresh = when {
            forceFresh -> lines
            truncated -> lines
            else -> lines.drop(linesBefore.coerceAtLeast(0))
        }
        val note = when {
            forceFresh -> "recreated by this attempt (DirtyfragAttempt.start deletes it)"
            truncated -> "file shrank since the baseline; every line is treated as fresh"
            else -> null
        }
        return LogFile(name, file.path, true, true, linesBefore, lines.size, fresh, null, note)
    }

    private fun providerLog(): File =
        File(DirtyfragAttempt.hookEvidence(context), "maplesu-ultravider.log")

    private fun nativeStageLog(): File =
        File(DirtyfragAttempt.hookEvidence(context), "native-stage.log")

    private fun lineCount(file: File): Int = runCatching {
        if (file.isFile) file.readLines().size else 0
    }.getOrDefault(0)

    // ------------------------------------------------------------------ shell

    private fun shell(command: String): Shell = runCatching {
        val descriptor = instrumentation.uiAutomation.executeShellCommand(command)
        val text = ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { stream ->
            stream.readBytes().toString(Charsets.UTF_8)
        }
        Shell(text, null)
    }.getOrElse {
        Shell("", describe(it))
    }

    private fun shellJson(result: Shell): JSONObject = JSONObject()
        .put("ok", result.error == null)
        .putText("error", result.error)
        .put("lines", result.text.lineSequence().count { it.isNotBlank() })
        .put("text", bound(result.text, SHELL_LIMIT))

    /** SELinux state as the device has it; `-1` means no source could answer. */
    private fun readEnforcingRobust(): Int {
        repeat(3) {
            val value = runCatching { DirtyfragAttempt.readEnforcing() }.getOrDefault(-1)
            if (value == 0 || value == 1) return value
            runCatching { Thread.sleep(150) }
        }
        return when (shell("cat /sys/fs/selinux/enforce").text.trim()) {
            "0" -> 0
            "1" -> 1
            else -> -1
        }
    }

    private fun installedPackages(names: Set<String>): JSONArray {
        val array = JSONArray()
        for (name in names.sorted()) {
            val installed = runCatching {
                context.packageManager.getPackageInfo(name, 0)
                true
            }.getOrDefault(false)
            if (installed) array.put(name)
        }
        return array
    }

    // --------------------------------------------------------------- evidence

    /** The internal copy the task requires; `run-as` can read it without a pull. */
    private fun evidenceFile(): File = File(File(context.filesDir, "jailbreak-evidence"), FILE_NAME)

    private fun externalEvidenceFile(): File? =
        runCatching { context.getExternalFilesDir(null) }
            .getOrNull()
            ?.let { File(File(it, "jailbreak-evidence"), FILE_NAME) }

    /**
     * Writes the record atomically. The internal copy is the deliverable and its
     * failure is returned; the external copy is a convenience and is recorded in
     * the document instead of failing the run.
     */
    @Synchronized
    private fun writeEvidence(document: JSONObject): String {
        var error = ""
        val internal = evidenceFile()
        try {
            internal.parentFile?.let { directory ->
                if (!directory.isDirectory && !directory.mkdirs() && !directory.isDirectory) {
                    throw java.io.IOException("mkdirs failed: " + directory.path)
                }
            }
            document.put("evidencePath", internal.path)
            writeAtomically(internal, document)
        } catch (thrown: Throwable) {
            error = describe(thrown)
            document.put("evidenceError", error)
        }
        val external = externalEvidenceFile()
        if (external == null) {
            document.put("evidenceExternalError", "external files dir unavailable")
        } else {
            try {
                external.parentFile?.mkdirs()
                document.put("evidenceExternalPath", external.path)
                writeAtomically(external, document)
            } catch (thrown: Throwable) {
                document.put("evidenceExternalError", describe(thrown))
            }
        }
        /* One logcat line the operator can grep without any file access at all. */
        android.util.Log.i("MapleSU", LOG_PREFIX + document)
        return error
    }

    private fun writeAtomically(target: File, document: JSONObject) {
        val parent = target.parentFile
        val staging = if (parent == null) target else File(parent, target.name + ".new")
        staging.writeText(document.toString(2))
        if (!staging.renameTo(target)) {
            target.writeText(document.toString(2))
            if (staging.exists() && !staging.delete()) {
                // Best effort; the direct copy above is complete.
            }
        }
    }

    private fun statusJson(status: JailbreakStatus?): JSONObject {
        if (status == null) return JSONObject().put("present", false)
        return JSONObject()
            .put("present", true)
            .put("method", status.method)
            .put("stage", status.stage)
            .putText("failure", status.failure)
            .put("message", status.message)
            .putText("rootBackend", status.rootBackend)
            .putText("attemptId", status.attemptId)
            .putText("bootId", status.bootId)
            .putText("target", status.target)
            .put("ownerPid", status.ownerPid ?: JSONObject.NULL)
            .put("restoreEnforcing", status.restoreEnforcing ?: JSONObject.NULL)
    }

    // ---------------------------------------------------------------- helpers

    private fun digestOf(file: File): String? = runCatching {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { stream ->
            val chunk = ByteArray(65536)
            while (true) {
                val read = stream.read(chunk)
                if (read < 0) break
                digest.update(chunk, 0, read)
            }
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    }.getOrNull()

    private fun enforcingValue(value: Int): Any =
        if (value == Int.MIN_VALUE || value < 0) JSONObject.NULL else value.toLong()

    private fun bound(text: String, limit: Int): String =
        if (text.length <= limit) text else text.take(limit) + "...(truncated)"

    private fun describe(thrown: Throwable): String =
        thrown.javaClass.simpleName + ": " + (thrown.message ?: "")

    /** `describe`, plus the cause chain: the provider wraps its refusal. */
    private fun describeChain(thrown: Throwable): String {
        val parts = mutableListOf<String>()
        var current: Throwable? = thrown
        var depth = 0
        while (current != null && depth < 4) {
            parts.add(describe(current))
            current = current.cause
            depth++
        }
        return parts.joinToString(" <- ")
    }

    private companion object {
        const val FILE_NAME = "normal-ksu.json"
        const val LOG_PREFIX = "MAPLESU_NORMAL_KSU_EVIDENCE "
        const val ROOT_DIRECTORY_AUTHORITY = "dev.maplesu.manager.root_directory"

        /*
         * The verdict vocabulary. OK requires both halves (provider log + persisted
         * stage); OK_STAGE_UNPUBLISHED exists because ksud late-load force-stops the
         * manager before the executor can publish its stage, and the two must never
         * be merged into one label.
         */
        const val VERDICT_OK = "KSU_LATE_LOAD_OK"
        const val VERDICT_OK_STAGE_UNPUBLISHED = "KSU_LATE_LOAD_OK_STAGE_UNPUBLISHED"
        const val VERDICT_REFUSED = "KSU_REFUSED_WITH_CODE"
        const val VERDICT_INCONCLUSIVE = "KSU_INCONCLUSIVE"

        /** `escalateKsu` waits 60 s for the stage and the bootstrap 120 s for ksud. */
        const val WAIT_MILLIS = 120_000L
        const val POLL_MILLIS = 1_000L
        const val WATCHDOG_PERIOD_MILLIS = 1_000L
        const val SHELL_LIMIT = 6_000

        /** `JailbreakExecutor.KSU_LOADED`, verbatim. */
        const val LOADED_MARKER = "maplesu-dirtyfrag: ksu: loaded"

        /** `JailbreakExecutor.KSU_FAILURE`, verbatim. */
        val KSU_FAILURE = Regex("maplesu-dirtyfrag: ksu: FAILED (MAPLESU_KSU_[A-Z_]+)")

        /** Any stable failure code the record may carry (status, log or exception). */
        val FAILURE_TOKEN = Regex(
            "(MAPLESU_[A-Z][A-Z0-9_]*|DIRTYFRAG_[A-Z][A-Z0-9_]*|" +
                "SU_DIRECTORY_[A-Z][A-Z0-9_]*|JAILBREAK_[A-Z][A-Z0-9_]*)",
        )
        val KSU_ANY_TOKEN = Regex("(MAPLESU_KSU_[A-Z_]+)")
        val LATE_LOAD_RC = Regex("ksu late-load rc=(-?\\d+)")

        /**
         * The lines this run is about. Deliberately broad. Note where each channel
         * actually comes from: the bootstrap's own `ksu ...` records go to
         * `maplesu-ultravider.log` and to its stderr (captured as `native-stage.log`),
         * while ksud's module loader logs through `android_logger` (tag `KernelSU`)
         * to logcat only - `environmentAfter.shell.logcatKsu` is that channel, and
         * these needles also apply to the two file channels because an anyhow
         * failure is printed to stderr before ksud resets its stdio.
         */
        val KSU_NEEDLES = listOf(
            "ksu:", "MAPLESU_KSU", "late-load", "late_load", "ksu handoff",
            "ksu init domain", "ksu restore", "ksu soft-reboot", "kernelsu",
            "ksud", "KernelSU", "load_module", "insmod", "init_module",
        )

        /**
         * Reasons a module load can fail on a KernelSU-compatible kernel. The
         * authoritative copies of these live in `environmentAfter.shell.logcatKsu`
         * (ksuinit logs `Cannot find symbol` and the kernel's `init_module` dump at
         * error level); they are matched against the file channels as well because
         * a build may print them before stdio is reset.
         */
        val LOADER_ERROR_NEEDLES = listOf(
            "Unknown symbol", "vermagic", "version magic", "import_ns", "Exec format error",
            "invalid module format", "Failed to load", "could not insert", "no symbol version",
            "disagrees about version", "Operation not permitted", "Permission denied",
            "not found in", "undefined symbol", "kallsyms",
        )

        const val ROUTE_NOTES =
            "BACKEND_KSU facts this record assumes and does not change: (1) " +
                "DirtyfragAttempt.startKernelSu writes <DE>/use-ksu and stages " +
                "libksud_ksu.so as <CE>/ksud; the test writes neither. (2) The provider " +
                "runs escalateKsu and then the unconditional lease-directory step, which " +
                "has no lease on this backend and therefore throws " +
                "SU_DIRECTORY_JAILBREAK_LEASE_MISSING after a successful escalation - " +
                "that exception is recorded in entry.threw and is never read as the " +
                "KernelSU verdict. (3) DAEMON_READY is consequently unreachable for " +
                "BACKEND_KSU in this build; ROOT_WORKER_OBSERVED (plus the provider's " +
                "'ksu: loaded' line) is the strongest verdict the route can publish. " +
                "(4) ksud late-load ends with 'am force-stop dev.maplesu.manager', so on " +
                "the success path this process is killed before it can write a final " +
                "record; the pre/watchdog copies and " +
                "/data/user_de/0/dev.maplesu.manager/maplesu-ultravider.log carry the verdict."
    }
}

/**
 * Puts a string, or JSON null when the observation is absent. Used instead of
 * `put(key, null)` because `put(String, Any?)` removes the key entirely, and a
 * missing field cannot be told apart from "not observed".
 */
private fun JSONObject.putText(key: String, value: String?): JSONObject =
    put(key, if (value.isNullOrEmpty()) JSONObject.NULL else value)
