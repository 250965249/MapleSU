package dev.maplesu.manager.jailbreak

import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostlock.app.data.HoconSupport
import com.ghostlock.app.data.ValueMap
import com.ghostlock.app.data.asValueMap
import com.ghostlock.app.data.route.RouteKind
import dev.maplesu.manager.runtime.NativeSuDaemon
import dev.maplesu.manager.runtime.StageMark
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.Timer
import java.util.TimerTask
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * P2 device entry for the **Ghostlock** provider: does one attempt reach the
 * provider, and if it refuses, with which named code?
 *
 * <p>Code under test: `JailbreakExecutor.escalateGhostlock`
 * (`manager/src/main/java/dev/maplesu/manager/jailbreak/JailbreakExecutor.kt:307-420`).
 * The executor only runs inside `:root_directory`; the product reaches it through
 * `NativeSuDirectoryProvider.call("prepare")`, which is what
 * `NativeSuDaemon.management(context, request)` performs. The entry is selected by
 * **method**, not by backend: `JailbreakExecutor.escalate` routes
 * `JailbreakMethod.GHOSTLOCK.wireName` to `escalateGhostlock` (`:97-101`), and
 * `escalateGhostlock` never reads `request.rootBackend`. `prepareHook` is the
 * hook route only (`NativeSuDaemon.kt:114-119` requires `rootBackend == "hook"`,
 * which would route to `escalateHook`), so this test calls `management` with
 * `rootBackend = null` - exactly the product path the UI uses for a non-Ultra
 * mode.
 *
 * <p>**Reference gate (2026-10-31).** The user requirement for this round is to
 * follow the GhostLock-App reference implementation and not to run an attempt on
 * guessed offsets. The reference profile set
 * (`work/ghostlock-app/app/src/main/assets/kernel_profiles` + `index.conf`, and
 * `docs/kernel_profiles/SUPPORTED_DEVICES.md`) has **no exact `uname -r` profile**
 * for this device; the reference app requires an exact match
 * (`README.md:13`, `PROFILE_SCHEMA.md` §2) and refuses otherwise. The APK does
 * carry a MapleSU product profile for this exact release
 * (`jailbreak-providers/ghostlock/product-profiles/...`, `verified=false`,
 * converted from a public anchor). That is a candidate, not a reference-verified
 * profile, so by default this test records the gap and **does not start a provider
 * attempt** while the gate says `GHOSTLOCK_REFERENCE_PROFILE_MISSING`. The
 * attempt branch below is the real product path and is taken when the reference
 * snapshot has an exact profile for the running release.
 *
 * <p>**Explicit experimental override.** The safe default can be overridden for
 * one deliberate run with
 * `-e ghostlockExperimental true`. Only then is the packaged candidate profile
 * attempted while the reference profile is missing; the evidence then carries
 * `experimental=true`, `reference.status=GHOSTLOCK_REFERENCE_PROFILE_MISSING`,
 * `reference.profileSource` and `reference.offsetDiffs` (the six differences
 * against the nearest reference 6.6.89/OP13 profile), so the run can never be
 * mistaken for a reference-verified success. The flag is off unless the operator
 * passes it; nothing in the product reads it.
 *
 * <p>When the gate is open, the verdict vocabulary is the one the task defines:
 *
 *  - [VERDICT_REACHED] - the attempt reached at least
 *    `PROVIDER_RUNNING` (i.e. profile resolved, artifacts verified, provider
 *    process started). `HANDOFF_AUTHENTICATED`, `ROOT_WORKER_OBSERVED` and
 *    `DAEMON_READY` are the higher forms of the same pass;
 *  - [VERDICT_REFUSED] - no provider stage was reached, but the attempt produced
 *    a named `GHOSTLOCK_*` code (profile codec, artifact gate, provider start,
 *    restore verification);
 *  - [VERDICT_INCONCLUSIVE] - neither of the above. This is a red test and is
 *    never reported as success;
 *  - [VERDICT_REFERENCE_MISSING] - the reference gate above. Also red, but a
 *    precondition, not a Ghostlock verdict: the evidence names the reference
 *    snapshot, the nearest reference profile and the packaged candidate.
 *
 * <p>Evidence is written three ways per run - `pre` before the attempt,
 * `watchdog` from a two-second timer while it runs, `final` once the observation
 * window closes - to `context.filesDir/jailbreak-evidence/ghostlock.json` (the
 * required copy, readable with `adb shell run-as`), to an external-files copy,
 * and to logcat as one line `MAPLESU_GHOSTLOCK_EVIDENCE {json}` under the
 * `MapleSU` tag. The record is always written before the assertions, so a red run
 * still leaves the complete artifact on disk.
 *
 * <p>Run it with:
 * `am instrument -w -e class dev.maplesu.manager.jailbreak.GhostlockTakeoverAndroidTest#ghostlockReachesProviderOrRefusesWithCode dev.maplesu.manager.test/androidx.test.runner.AndroidJUnitRunner`
 */
@RunWith(AndroidJUnit4::class)
class GhostlockTakeoverAndroidTest {

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()

    private val context get() = instrumentation.targetContext

    private class Verdict(
        val name: String,
        val token: String?,
        val stage: String?,
        val reason: String,
    ) {
        val passed: Boolean
            get() = name == GhostlockTakeoverAndroidTest.VERDICT_REACHED ||
                name == GhostlockTakeoverAndroidTest.VERDICT_REFUSED
    }

    private class StageObservation(
        val stage: String,
        val failure: String?,
        val message: String,
        val atMillis: Long,
    )

    private class Mounts(val json: JSONObject, val keys: List<String>)

    /** Everything one observation window saw; re-read for each evidence phase. */
    private inner class Run(val attemptId: String, val startedAtMillis: Long) {
        @Volatile var deviceRelease: String? = null
        @Volatile var bootBefore: String? = null
        @Volatile var bootAfter: String? = null
        @Volatile var enforcingBefore: Int = Int.MIN_VALUE
        @Volatile var enforcingAfter: Int = Int.MIN_VALUE
        @Volatile var enforcingShellBefore: String? = null
        @Volatile var enforcingShellAfter: String? = null
        @Volatile var mountsBefore: JSONObject? = null
        @Volatile var mountsAfter: JSONObject? = null
        val mountKeysBefore = mutableListOf<String>()
        val mountAdded = mutableListOf<String>()
        val mountRemoved = mutableListOf<String>()
        @Volatile var reference: JSONObject = JSONObject().put("available", false)
        @Volatile var product: JSONObject = JSONObject().put("present", false)
        @Volatile var request: JailbreakRequest? = null
        @Volatile var previousStatus: JSONObject? = null
        @Volatile var entryInvoked = false
        @Volatile var entryReturned = false
        @Volatile var entryThrew: String? = null
        @Volatile var entryFinishedAt: Long = 0L
        @Volatile var callMillis: Long = -1L
        @Volatile var worker: Thread? = null
        @Volatile var statusRaw: JSONObject? = null
        @Volatile var statusAttributed = false
        @Volatile var maxStage: String? = null
        @Volatile var failure: String? = null
        @Volatile var experimental = false
        @Volatile var experimentalRequested = false
        @Volatile var referenceGate = "SAFE_DEFAULT_CLOSED"
        @Volatile var verdict: Verdict = Verdict(
            GhostlockTakeoverAndroidTest.VERDICT_INCONCLUSIVE, null, null, "not evaluated")
        val stages = mutableListOf<StageObservation>()
        private val problems = mutableListOf<String>()
        private val notes = mutableListOf<String>()

        fun recordProblem(detail: String) {
            if (detail.isEmpty()) return
            synchronized(problems) { problems.add(detail) }
        }

        fun recordNote(detail: String) {
            if (detail.isEmpty()) return
            synchronized(notes) { notes.add(detail) }
        }

        fun problemsText(): String = synchronized(problems) { problems.joinToString("; ") }

        fun notesText(): String = synchronized(notes) { notes.joinToString("; ") }

        /** Reads the raw status file (no expiry rewrite) and tracks this attempt's stages. */
        fun observeStatus() {
            val raw = rawStatus()
            statusRaw = raw
            val attributed = raw?.takeIf { it.optString("attemptId") == attemptId }
            statusAttributed = attributed != null
            if (attributed == null) return
            val stage = attributed.optString("stage")
            val stageFailure = attributed.optString("failure")
                .takeIf { it.isNotEmpty() && it != "null" }
            val message = attributed.optString("message")
            if (stageFailure != null) failure = stageFailure
            synchronized(stages) {
                if (stages.none { it.stage == stage && it.failure == stageFailure }) {
                    stages.add(StageObservation(stage, stageFailure, message,
                        System.currentTimeMillis()))
                }
            }
            if (stageIndex(stage) > stageIndex(maxStage)) maxStage = stage
        }

        fun reachedTerminal(): Boolean =
            failure != null || maxStage == JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED ||
                maxStage == JailbreakStatus.STAGE_DAEMON_READY

        fun rawStatus(): JSONObject? = runCatching {
            val file = File(File(context.filesDir, JailbreakStatus.DIRECTION), "status.json")
            if (!file.isFile) null else JSONObject(file.readText())
        }.getOrNull()

        fun stagesJson(): JSONArray = synchronized(stages) {
            val array = JSONArray()
            for (item in stages) {
                array.put(JSONObject()
                    .put("stage", item.stage)
                    .put("failure", item.failure ?: JSONObject.NULL)
                    .put("message", item.message)
                    .put("atMillis", item.atMillis)
                    .put("orderIndex", stageIndex(item.stage)))
            }
            array
        }

        @Synchronized
        fun snapshot(phase: String, full: Boolean): JSONObject {
            val readStatus = runCatching { JailbreakStatus.read(context) }.getOrNull()
            val document = JSONObject()
                .put("schemaVersion", 1)
                .put("flow", "p2/ghostlock-takeover")
                .put("phase", phase)
                .put("attemptId", attemptId)
                .put("startedAtMillis", startedAtMillis)
                .put("writtenAtMillis", System.currentTimeMillis())
                .put("device", deviceJson())
                .put("boot", JSONObject()
                    .put("before", bootBefore ?: JSONObject.NULL)
                    .put("after", bootAfter ?: JSONObject.NULL)
                    .put("unchanged", if (bootBefore != null && bootAfter != null) {
                        bootBefore == bootAfter
                    } else {
                        JSONObject.NULL
                    }))
                .put("enforcing", JSONObject()
                    .put("before", enforcingJson(enforcingBefore, enforcingShellBefore))
                    .put("after", enforcingJson(enforcingAfter, enforcingShellAfter)))
                .put("mounts", JSONObject()
                    .put("before", mountsBefore ?: JSONObject.NULL)
                    .put("after", mountsAfter ?: JSONObject.NULL)
                    .put("added", JSONArray(mountAdded))
                    .put("removed", JSONArray(mountRemoved)))
                .put("reference", reference)
                .put("productProfile", product)
                .put("experimental", experimental)
                .put("experimentalRequested", experimentalRequested)
                .put("referenceGate", referenceGate)
                .put("request", requestJson())
                .put("entry", entryJson())
                .put("status", JSONObject()
                    .put("attributed", statusAttributed)
                    .put("raw", statusRaw ?: JSONObject.NULL)
                    .put("read", statusJson(readStatus))
                    .put("observedStages", stagesJson())
                    .put("maxStage", maxStage ?: JSONObject.NULL)
                    .put("failure", failure ?: JSONObject.NULL))
                .put("failure", failure ?: verdict.token ?: JSONObject.NULL)
                .put("verdict", JSONObject()
                    .put("name", verdict.name)
                    .put("passed", verdict.passed)
                    .put("token", verdict.token ?: JSONObject.NULL)
                    .put("stage", verdict.stage ?: JSONObject.NULL)
                    .put("reason", verdict.reason)
                    .put("experimental", experimental)
                    .put("referenceMissing",
                        reference.optString("status") != REFERENCE_PRESENT)
                    .put("referenceGate", referenceGate))
                .put("problems", problemsText())
                .put("notes", notesText())
                .put("sdk", Build.VERSION.SDK_INT)
            if (full) document.put("logs", logsJson()) else document.put("logs", lightLogsJson())
            return document
        }

        private fun deviceJson(): JSONObject = JSONObject()
            .put("release", deviceRelease ?: JSONObject.NULL)
            .put("model", Build.MODEL ?: JSONObject.NULL)
            .put("fingerprint", Build.FINGERPRINT ?: JSONObject.NULL)
            .put("sdk", Build.VERSION.SDK_INT)

        private fun enforcingJson(value: Int, shellText: String?): JSONObject = JSONObject()
            .put("value", if (value == Int.MIN_VALUE) JSONObject.NULL else value)
            .put("text", enforcingText(value))
            .put("getenforce", shellText ?: JSONObject.NULL)

        fun requestJson(): Any {
            val current = request ?: return JSONObject.NULL
            return JSONObject()
                .put("method", current.method)
                .put("attemptId", current.attemptId)
                .put("bootId", current.bootId ?: JSONObject.NULL)
                .put("softReboot", current.softReboot)
                .put("rootBackend", current.rootBackend ?: JSONObject.NULL)
                .put("origin", current.origin)
        }

        private fun entryJson(): JSONObject = JSONObject()
            .put("invoked", entryInvoked)
            .put("invokedAs", "dev.maplesu.manager.runtime.NativeSuDaemon.management")
            .put("route",
                "content://dev.maplesu.manager.root_directory prepare -> " +
                    "JailbreakExecutor.escalate -> escalateGhostlock")
            .put("routing",
                "JailbreakExecutor.escalate routes by method (JailbreakExecutor.kt:97-101); " +
                    "escalateGhostlock (307-420) never reads request.rootBackend. " +
                    "prepareHook requires backEnd=hook and would route to escalateHook, so " +
                    "the ghostlock entry is management() with rootBackend=null.")
            .put("returned", entryReturned)
            .put("threw", entryThrew ?: JSONObject.NULL)
            .put("elapsedMillis", callMillis)
            .put("stillRunning", worker?.isAlive == true)
            .put("experimental", experimental)
            .put("referenceGate", referenceGate)
            .put("skippedBecause", if (!entryInvoked) {
                reference.optString("status", "not invoked")
            } else {
                JSONObject.NULL
            })

        private fun logsJson(): JSONObject {
            val marks = runCatching { StageMark.read(context) }.getOrDefault("")
            val logcat = logcatTail()
            return JSONObject()
                .put("stageMarks", bound(marks, 8192))
                .put("stageMarksBytes", marks.length)
                .put("logcat", bound(logcat, 8192))
                .put("logcatBytes", logcat.length)
                .put("evidenceDirectory", DirtyfragAttempt.hookEvidence(context).path)
                .put("evidenceListing",
                    JSONArray(listDirectory(DirtyfragAttempt.hookEvidence(context), 40)))
                .put("attemptHomes", attemptHomes())
                .put("tail", bound(marks + "\n--- logcat ---\n" + logcat, LOG_TAIL_LIMIT))
        }

        private fun lightLogsJson(): JSONObject = JSONObject()
            .put("stageMarksBytes", runCatching { StageMark.read(context).length }.getOrDefault(0))
            .put("note", "watchdog phase: heavy log collection runs at pre/final only")
    }

    @Test
    fun ghostlockReachesProviderOrRefusesWithCode() {
        val run = Run(UUID.randomUUID().toString(), System.currentTimeMillis())

        // (1) Baseline that can be captured without touching the kernel.
        run.deviceRelease = runCatching { android.system.Os.uname().release }.getOrNull()
        run.bootBefore = runCatching { DirtyfragAttempt.readBootId() }.getOrNull()
        run.enforcingBefore = runCatching { DirtyfragAttempt.readEnforcing() }.getOrDefault(Int.MIN_VALUE)
        run.enforcingShellBefore = shell("getenforce").trim().takeIf { it.isNotEmpty() }
        val mounts = readMounts()
        run.mountsBefore = mounts.json
        run.mountKeysBefore.addAll(mounts.keys)
        run.reference = referencePreflight(run.deviceRelease)
        run.product = productProfilePreflight(run.deviceRelease)
        run.experimentalRequested = instrumentationFlag("ghostlockExperimental")
        val referencePresent = run.reference.optString("status") == REFERENCE_PRESENT
        run.experimental = !referencePresent && run.experimentalRequested
        run.referenceGate = when {
            referencePresent -> "REFERENCE_PRESENT"
            run.experimental -> "EXPERIMENTAL_OVERRIDE"
            else -> "SAFE_DEFAULT_CLOSED"
        }
        run.reference.put("gate", run.referenceGate)
        run.reference.put("experimental", run.experimental)
        run.product.put("offsetDiffs",
            run.reference.optJSONArray("offsetDiffs") ?: JSONArray())
        run.product.put("experimental", run.experimental)
        run.request = JailbreakRequest(
            method = "ghostlock",
            attemptId = run.attemptId,
            bootId = run.bootBefore,
            // One boot, one attempt: a soft reboot would spend the window and
            // destroy the evidence. The product path honours this flag.
            softReboot = false,
            // escalateGhostlock ignores this field; null is the product's
            // "decide from what is packaged" value and keeps the route
            // method-driven. "hook" would mean the hook backend, not Ghostlock.
            rootBackend = null,
        )

        // (2) The pre-attempt record. Written before anything that can hang.
        var writeError = writeEvidence(safeSnapshot(run, "pre", true))

        // (3) Watchdog: a provider attempt can kill this process (the plan's
        // 1/3 reboot risk); the record must survive it.
        val finished = AtomicBoolean(false)
        val lastSignature = AtomicReference("")
        val watchdog = Timer("ghostlock-evidence", true)
        watchdog.schedule(object : TimerTask() {
            override fun run() {
                if (finished.get()) return
                runCatching {
                    val signature = run.attemptId + "|" + run.maxStage + "|" + run.failure +
                        "|" + run.entryFinishedAt + "|" + run.stages.size
                    if (signature != lastSignature.getAndSet(signature)) {
                        writeEvidence(safeSnapshot(run, "watchdog", false))
                    }
                }
            }
        }, WATCHDOG_PERIOD_MILLIS, WATCHDOG_PERIOD_MILLIS)

        var finalDocument: JSONObject? = null
        try {
            if (!referencePresent && !run.experimental) {
                /*
                 * Reference gate: no exact GhostLock-App profile for this
                 * release. Running escalateGhostlock here would spend this
                 * boot's kernel window on the packaged MapleSU candidate
                 * (verified=false), i.e. on offsets the reference does not
                 * confirm. Do not start a provider.
                 */
                run.recordNote("reference gate closed: " + run.reference.optString("status") +
                    "; no provider attempt was made " +
                    "(pass -e ghostlockExperimental true to override deliberately)")
            } else if (run.bootBefore == null) {
                run.recordProblem("boot id unreadable before the attempt")
            } else {
                if (run.experimental) {
                    run.recordNote("EXPERIMENTAL OVERRIDE: the reference has no exact " +
                        "profile for " + run.deviceRelease + "; the packaged candidate " +
                        "profile was used because -e ghostlockExperimental true was passed")
                }
                run.previousStatus = rawStatusFile()
                JailbreakStatus.clear(context)
                runAttempt(run)
            }
        } finally {
            finished.set(true)
            watchdog.cancel()
            run.bootAfter = runCatching { DirtyfragAttempt.readBootId() }.getOrNull()
            run.enforcingAfter = runCatching { DirtyfragAttempt.readEnforcing() }
                .getOrDefault(Int.MIN_VALUE)
            run.enforcingShellAfter = shell("getenforce").trim().takeIf { it.isNotEmpty() }
            val afterMounts = readMounts()
            run.mountsAfter = afterMounts.json
            val beforeSet = run.mountKeysBefore.toSet()
            val afterSet = afterMounts.keys.toSet()
            run.mountAdded.addAll(afterMounts.keys.filter { it !in beforeSet })
            run.mountRemoved.addAll(run.mountKeysBefore.filter { it !in afterSet })
            if (run.bootBefore != null && run.bootAfter != null &&
                run.bootBefore != run.bootAfter) {
                run.recordProblem("boot id changed during the ghostlock window")
            }
            run.verdict = evaluateVerdict(run)
            val document = safeSnapshot(run, "final", true)
            finalDocument = document
            writeError = writeEvidence(document)
        }

        // (4) Assertions last: every branch above has already left the record
        // on disk (and in logcat).
        assertEquals("the evidence record was not written: " + writeError, "", writeError)
        val document = requireNotNull(finalDocument) { "no evidence document was produced" }
        assertNotNull("boot id is unreadable before the attempt", run.bootBefore)
        assertNotNull("boot id is unreadable after the attempt", run.bootAfter)
        assertTrue("evidence integrity problems: " + run.problemsText(), run.problemsText().isEmpty())

        val verdict = run.verdict
        if (run.experimental) {
            assertTrue("experimental run is not marked in the evidence",
                document.optBoolean("experimental"))
            assertEquals("experimental run lost the reference-missing marker",
                REFERENCE_MISSING, run.reference.optString("status"))
        }
        when (verdict.name) {
            VERDICT_REFERENCE_MISSING -> fail(
                "GHOSTLOCK_REFERENCE_PROFILE_MISSING: " + verdict.reason +
                    "; reference=" + run.reference +
                    "; packagedCandidate=" + run.product.optString("file") +
                    " verified=" + run.product.optBoolean("verified") +
                    "; offsetDiffs=" + run.reference.optJSONArray("offsetDiffs") +
                    "; no provider attempt was made (entry.invoked=" + run.entryInvoked + "). " +
                    "A deliberate experimental run requires " +
                    "-e ghostlockExperimental true on the am instrument command line.")
            VERDICT_REACHED -> assertTrue(
                "REACHED stage is below PROVIDER_RUNNING: " + verdict.stage,
                stageIndex(verdict.stage) >= stageIndex(JailbreakStatus.STAGE_PROVIDER_RUNNING))
            VERDICT_REFUSED -> assertTrue(
                "refusal token is not a GHOSTLOCK_* code: " + verdict.token,
                verdict.token?.startsWith("GHOSTLOCK_") == true)
            else -> fail(
                "no Ghostlock verdict: " + verdict.reason +
                    "; maxStage=" + (run.maxStage ?: "none") +
                    "; entry.threw=" + (run.entryThrew ?: "no") +
                    "; status=" + (run.statusRaw?.toString() ?: "missing") +
                    "; evidence=" + document.optString("evidencePath"))
        }
    }

    /**
     * The one product entry, exactly once, on a background thread (management
     * refuses the main looper), with a bounded 180 s observation window.
     */
    private fun runAttempt(run: Run) {
        val request = run.request ?: return
        val startedCall = System.currentTimeMillis()
        run.entryInvoked = true
        val worker = Thread({
            try {
                NativeSuDaemon.management(context, request)
                run.entryReturned = true
            } catch (thrown: Throwable) {
                run.entryThrew = describeChain(thrown)
            } finally {
                run.entryFinishedAt = System.currentTimeMillis()
                run.callMillis = run.entryFinishedAt - startedCall
            }
        }, "maplesu-ghostlock-attempt")
        worker.isDaemon = true
        run.worker = worker
        worker.start()

        val deadline = run.startedAtMillis + WAIT_MILLIS
        while (System.currentTimeMillis() < deadline) {
            run.observeStatus()
            if (run.reachedTerminal()) break
            /*
             * The provider work happens inside the binder call, so once the
             * entry returned/failed no later stage will be published. A short
             * settle keeps a just-written final stage from being missed.
             */
            val finishedAt = run.entryFinishedAt
            if (finishedAt > 0 && System.currentTimeMillis() - finishedAt > SETTLE_MILLIS) break
            runCatching { Thread.sleep(POLL_MILLIS) }
        }
        run.observeStatus()
        if (run.entryFinishedAt == 0L) {
            run.recordNote("entry still running at the 180 s deadline; the provider may still " +
                "be alive (GhostlockAttempt.close does not kill the process)")
        }
    }

    /**
     * The one place the verdict is computed. A reached provider stage wins over a
     * missing GHOSTLOCK_* code because it already proves the profile/artifact
     * contract up to the process; a named GHOSTLOCK_* code is the other accepted
     * outcome. Everything else is inconclusive and red.
     */
    private fun evaluateVerdict(run: Run): Verdict {
        val referenceStatus = run.reference.optString("status")
        if (referenceStatus != REFERENCE_PRESENT && !run.experimental) {
            return Verdict(
                VERDICT_REFERENCE_MISSING,
                "GHOSTLOCK_REFERENCE_PROFILE_MISSING",
                run.maxStage,
                referenceStatus + " for " + (run.deviceRelease ?: "unknown release") +
                    "; reference snapshot=" + run.reference.optString("appPath") +
                    " checked=" + run.reference.optString("checkedRelease"),
            )
        }
        val max = run.maxStage
        if (max != null &&
            stageIndex(max) >= stageIndex(JailbreakStatus.STAGE_PROVIDER_RUNNING)) {
            return Verdict(
                VERDICT_REACHED, null, max,
                "the attempt reached " + max +
                    (run.failure?.let { " (final failure " + it + ")" } ?: "") +
                    "; the provider/adaptor contract held up to the process",
            )
        }
        val token = firstGhostlockToken(run.failure)
            ?: firstGhostlockToken(run.statusRaw?.optString("message"))
            ?: firstGhostlockToken(run.entryThrew)
            ?: firstGhostlockToken(run.product.optJSONObject("codec")?.optString("token"))
            ?: firstGhostlockToken(run.product.optString("token"))
        if (token != null) {
            return Verdict(
                VERDICT_REFUSED, token, max,
                "the attempt was refused with " + token + " at stage " +
                    (max ?: "none") + "; entry.threw=" + (run.entryThrew ?: "no"),
            )
        }
        return Verdict(
            VERDICT_INCONCLUSIVE, null, max,
            "no provider stage and no GHOSTLOCK_* code; entry.threw=" +
                (run.entryThrew ?: "no") + ", status=" + (run.statusRaw?.toString() ?: "missing") +
                (if (run.experimental) "; EXPERIMENTAL override with reference " +
                    run.reference.optString("status") else ""),
        )
    }

    /**
     * Reads one boolean instrumentation argument, default off. Only the explicit
     * `-e ghostlockExperimental true` form can open the experimental gate; a
     * missing or malformed value keeps the safe default.
     */
    private fun instrumentationFlag(name: String): Boolean {
        val value = runCatching {
            InstrumentationRegistry.getArguments().getString(name)
        }.getOrNull()?.trim()?.lowercase() ?: return false
        return value == "true" || value == "1" || value == "yes" || value == "on"
    }

    // ------------------------------------------------------------- reference

    /**
     * Host preflight of the GhostLock-App reference profile set, carried into the
     * APK as `androidTest/assets/ghostlock-reference.json` so this decision is
     * made from the same bytes on every run. The snapshot records the reference
     * commit, the index/supported-devices digests, all 75 device profiles and the
     * keys of the closest 6.6.89 family profiles. It does not invent a profile:
     * an absent release stays absent.
     */
    private fun referencePreflight(deviceRelease: String?): JSONObject {
        val snapshotBytes = runCatching {
            instrumentation.context.assets.open(REFERENCE_ASSET).use { it.readBytes() }
        }.getOrNull()
        if (snapshotBytes == null) {
            return JSONObject()
                .put("available", false)
                .put("appPath", REFERENCE_APP)
                .put("profilePath", JSONObject.NULL)
                .put("unameMatch", false)
                .put("profileKeys", JSONArray())
                .put("status", REFERENCE_SNAPSHOT_UNAVAILABLE)
                .put("checkedRelease", JSONObject.NULL)
        }
        val snapshot = JSONObject(String(snapshotBytes, Charsets.UTF_8))
        val profiles = snapshot.optJSONArray("deviceProfiles") ?: JSONArray()
        var exact: JSONObject? = null
        for (index in 0 until profiles.length()) {
            val entry = profiles.optJSONObject(index) ?: continue
            if (entry.optString("release") == deviceRelease) {
                exact = entry
                break
            }
        }
        return JSONObject()
            .put("available", true)
            .put("appPath", snapshot.optString("referenceApp"))
            .put("appCommit", snapshot.optString("referenceAppCommit"))
            .put("kernelProfilesDir", snapshot.optString("kernelProfilesDir"))
            .put("profilePath", exact?.let {
                snapshot.optString("kernelProfilesDir") + "/" + it.optString("file")
            } ?: JSONObject.NULL)
            .put("profileSha256", exact?.optString("sha256") ?: JSONObject.NULL)
            .put("profileKeys", exact?.optJSONArray("keys") ?: JSONArray())
            .put("unameMatch", exact != null)
            .put("status", if (exact != null) REFERENCE_PRESENT else REFERENCE_MISSING)
            .put("deviceRelease", deviceRelease ?: JSONObject.NULL)
            .put("checkedRelease", snapshot.optString("deviceReleaseChecked"))
            .put("index", snapshot.optJSONObject("index") ?: JSONObject.NULL)
            .put("supportedDevices", snapshot.optJSONObject("supportedDevices") ?: JSONObject.NULL)
            .put("profileSchema", snapshot.optJSONObject("profileSchema") ?: JSONObject.NULL)
            .put("nearestFamilyProfile",
                snapshot.optJSONObject("nearestFamilyProfile") ?: JSONObject.NULL)
            .put("offsetDiffs", snapshot.optJSONArray("offsetDiffs") ?: JSONArray())
            .put("profileSource",
                snapshot.optJSONObject("productProfile")?.optString("profileSource")
                    ?: JSONObject.NULL)
            .put("experimentalArgument", "-e ghostlockExperimental true")
            .put("schemaKeyGroups", snapshot.optJSONObject("schemaKeyGroups") ?: JSONObject.NULL)
            .put("deviceProfileCount", profiles.length())
            .put("sameSublevelCandidates", sameSublevelCandidates(profiles, deviceRelease))
            .put("readmeRule",
                "GhostLock-App README.md:13: support requires an exact uname -r match; " +
                    "PROFILE_SCHEMA.md: release must equal the device uname -r exactly")
            .put("snapshotSha256", sha256(snapshotBytes))
            .put("source", "androidTest asset " + REFERENCE_ASSET +
                " (host snapshot of work/ghostlock-app)")
    }

    private fun sameSublevelCandidates(profiles: JSONArray, deviceRelease: String?): JSONArray {
        val release = deviceRelease ?: return JSONArray()
        val sublevel = Regex("^(\\d+\\.\\d+\\.\\d+)").find(release)?.groupValues?.get(1)
            ?: return JSONArray()
        val array = JSONArray()
        for (index in 0 until profiles.length()) {
            val value = profiles.optJSONObject(index)?.optString("release") ?: continue
            if (value.startsWith(sublevel + "-")) array.put(value)
        }
        return array
    }

    /**
     * What the APK itself carries. Reading the packaged profile and encoding it is
     * a pure HOCON -> wire-v2 transformation (no process, no kernel action); the
     * result separates `GHOSTLOCK_PROFILE_*` from a later artifact/provider
     * refusal. The provenance is recorded because this is the candidate profile,
     * not a reference-verified one.
     */
    private fun productProfilePreflight(deviceRelease: String?): JSONObject {
        val out = JSONObject().put("present", false)
        if (deviceRelease == null) {
            return out.put("error", "device release unreadable")
        }
        return try {
            val profiles = GhostlockProfiles.from(context)
            val releases = profiles.releases()
            out.put("present", true)
                .put("releaseCount", releases.size)
                .put("packagedExact", releases.contains(deviceRelease))
                .put("manifestRelease", deviceRelease)
            if (!releases.contains(deviceRelease)) {
                return out.put("note", "the APK carries no exact profile for this release")
            }
            val profile = profiles.resolve(deviceRelease)
            val document = profile.document()
            out.put("file", profile.file())
                .put("assumed", profile.assumed())
                .put("assumedFrom", profile.assumedFrom() ?: JSONObject.NULL)
                .put("bytes", document.size)
                .put("sha256", sha256(document))
                .put("keys", keyPaths(String(document, Charsets.UTF_8)))
                .put("provenance", PRODUCT_PROVENANCE)
                .put("verified", false)
                .put("note", "candidate profile converted from a public anchor; not " +
                    "confirmed by the GhostLock-App reference")
            val tuning = runCatching { tuningExecution(profiles) }.getOrNull()
            val presets = runCatching { routePresets(profiles) }.getOrElse { emptyMap() }
            try {
                val wire = GhostlockProfileCodec.toWire(profile, deviceRelease, tuning, presets)
                out.put("codec", JSONObject()
                    .put("ok", true)
                    .put("bytes", wire.size)
                    .put("sha256", sha256(wire))
                    .put("release", deviceRelease)
                    .put("tuningPresent", tuning != null)
                    .put("routePresets", JSONArray(presets.keys.sorted()))
                    .put("note", "pure encoding preflight; no process was created"))
            } catch (thrown: Throwable) {
                out.put("codec", JSONObject()
                    .put("ok", false)
                    .put("token", firstGhostlockToken(thrown.message) ?: JSONObject.NULL)
                    .put("error", describeChain(thrown)))
            }
            out
        } catch (thrown: Throwable) {
            out.put("error", describeChain(thrown))
                .put("token", firstGhostlockToken(thrown.message) ?: JSONObject.NULL)
        }
    }

    /** The executor's own packaged-tuning reads (`JailbreakExecutor.kt:259-295`). */
    private fun tuningExecution(profiles: GhostlockProfiles): ValueMap? {
        val text = profiles.packagedDocument("execution-tuning.conf") ?: return null
        return runCatching {
            HoconSupport.parseValue(text).asValueMap()?.get("execution").asValueMap()
        }.getOrNull()
    }

    /** Per-route presets keyed by the route token, exactly as the executor does. */
    private fun routePresets(profiles: GhostlockProfiles): Map<String, ValueMap> {
        val out = LinkedHashMap<String, ValueMap>()
        for (kind in RouteKind.entries) {
            val token = kind.token
            val file = "execution-" + token.replace('_', '-') + ".conf"
            val text = profiles.packagedDocument(file) ?: continue
            val entry = runCatching {
                HoconSupport.parseValue(text).asValueMap()?.get("execution").asValueMap()
                    ?.get("routes").asValueMap()?.get(token).asValueMap()
            }.getOrNull() ?: continue
            out[token] = entry
        }
        return out
    }

    // ---------------------------------------------------------------- status

    private fun rawStatusFile(): JSONObject? = runCatching {
        val file = File(File(context.filesDir, JailbreakStatus.DIRECTION), "status.json")
        if (!file.isFile) null else JSONObject(file.readText())
    }.getOrNull()

    private fun statusJson(status: JailbreakStatus?): JSONObject {
        if (status == null) return JSONObject().put("present", false)
        return JSONObject()
            .put("present", true)
            .put("method", status.method)
            .put("stage", status.stage)
            .put("message", status.message)
            .put("failure", status.failure ?: JSONObject.NULL)
            .put("rootBackend", status.rootBackend ?: JSONObject.NULL)
            .put("attemptId", status.attemptId ?: JSONObject.NULL)
            .put("bootId", status.bootId ?: JSONObject.NULL)
            .put("target", status.target ?: JSONObject.NULL)
            .put("ownerPid", status.ownerPid ?: JSONObject.NULL)
            .put("workerPid", status.workerPid ?: JSONObject.NULL)
            .put("workerDomain", status.workerDomain ?: JSONObject.NULL)
            .put("restoreState", status.restoreState ?: JSONObject.NULL)
            .put("restoreOrigin", status.restoreOrigin ?: JSONObject.NULL)
            .put("restoreEnforcing", status.restoreEnforcing ?: JSONObject.NULL)
            .put("restorePolicy", status.restorePolicy ?: JSONObject.NULL)
            .put("restoreUnloadErrno", status.restoreUnloadErrno ?: JSONObject.NULL)
            .put("restoreFailures", status.restoreFailures ?: JSONObject.NULL)
    }

    // ------------------------------------------------------------------ logs

    /** One bounded shell invocation; the platform shell has READ_LOGS. */
    private fun shell(command: String): String = runCatching {
        val descriptor = instrumentation.uiAutomation.executeShellCommand(command)
        ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { input ->
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(64 * 1024)
            while (out.size() < 256 * 1024) {
                val read = input.read(buffer)
                if (read < 0) break
                out.write(buffer, 0, read)
            }
            String(out.toByteArray(), Charsets.UTF_8)
        }
    }.getOrElse { "" }

    /**
     * The provider's own stdout is deliberately drained and discarded by
     * `GhostlockAttempt.readProvider` (only `\x1E GLK_STATUS` lines are ACKed),
     * so there is no provider log file to read. This is the one channel that
     * still carries the adapter's stderr and the App's stage records.
     */
    private fun logcatTail(): String = shell(
        "logcat -d -v threadtime -t 400 2>/dev/null | grep -E " +
            "'MapleSU|StageMark|Ghostlock|root_directory|maplesu' | tail -120")

    private fun attemptHomes(): JSONArray {
        val dirs = runCatching {
            context.filesDir.listFiles()
                ?.filter { it.isDirectory && it.name.startsWith("maplesu-glk-") }
                ?.sortedBy { it.name }
                ?.takeLast(8)
                ?: emptyList()
        }.getOrElse { emptyList() }
        val array = JSONArray()
        for (directory in dirs) {
            val script = File(directory, ".ghostlock_root.sh")
            array.put(JSONObject()
                .put("name", directory.name)
                .put("path", directory.path)
                .put("rootScriptPresent", script.isFile)
                .put("rootScriptBytes", if (script.isFile) script.length() else 0L)
                .put("entries", JSONArray(directory.list()?.sorted()?.take(32)
                    ?: emptyList<String>())))
        }
        return array
    }

    private fun listDirectory(directory: File, limit: Int): List<String> = runCatching {
        directory.listFiles()?.sortedBy { it.name }?.take(limit)?.map {
            it.name + (if (it.isDirectory) "/" else ":" + it.length())
        } ?: emptyList()
    }.getOrDefault(emptyList())

    // ---------------------------------------------------------------- mounts

    private fun readMounts(): Mounts {
        val file = File("/proc/mounts")
        if (!file.isFile) {
            return Mounts(JSONObject().put("readable", false).put("path", file.path), emptyList())
        }
        val text = runCatching { file.readText() }.getOrElse {
            return Mounts(JSONObject().put("readable", false).put("path", file.path)
                .put("error", it.javaClass.simpleName), emptyList())
        }
        val keys = text.lineSequence()
            .filter { it.isNotBlank() }
            .map { line -> line.trim().split(Regex("\\s+")).take(3).joinToString(" ") }
            .toList()
        val json = JSONObject()
            .put("readable", true)
            .put("path", file.path)
            .put("count", keys.size)
            .put("sha256", sha256(keys.joinToString("\n").toByteArray(Charsets.UTF_8)))
            .put("first", JSONArray(keys.take(3)))
            .put("tail", JSONArray(keys.takeLast(3)))
        return Mounts(json, keys)
    }

    // -------------------------------------------------------------- evidence

    private fun evidenceFile(): File =
        File(File(context.filesDir, "jailbreak-evidence"), EVIDENCE_NAME)

    private fun externalEvidenceFile(): File? =
        runCatching { context.getExternalFilesDir(null) }
            .getOrNull()
            ?.let { File(File(it, "jailbreak-evidence"), EVIDENCE_NAME) }

    /**
     * Writes the record atomically, then emits the one logcat line. The internal
     * copy is the deliverable and its failure is returned; the external copy and
     * the log line are conveniences recorded in the document.
     */
    @Synchronized
    private fun writeEvidence(document: JSONObject): String {
        var error = ""
        val internal = evidenceFile()
        val external = externalEvidenceFile()
        document.put("evidencePath", internal.path)
        if (external == null) {
            document.put("evidenceExternalError", "external files dir unavailable")
        } else {
            document.put("evidenceExternalPath", external.path)
        }
        try {
            internal.parentFile?.let { directory ->
                if (!directory.isDirectory && !directory.mkdirs() && !directory.isDirectory) {
                    throw java.io.IOException("mkdirs failed: " + directory.path)
                }
            }
            writeAtomically(internal, document)
        } catch (thrown: Throwable) {
            error = describe(thrown)
            document.put("evidenceError", error)
        }
        if (external != null) {
            try {
                external.parentFile?.mkdirs()
                writeAtomically(external, document)
            } catch (thrown: Throwable) {
                document.put("evidenceExternalError", describe(thrown))
            }
        }
        /* One logcat line an operator can grep without file access at all. */
        val verdict = document.optJSONObject("verdict")
        val summary = JSONObject()
            .put("phase", document.optString("phase"))
            .put("attemptId", document.optString("attemptId"))
            .put("verdict", verdict?.optString("name") ?: JSONObject.NULL)
            .put("token", verdict?.optString("token") ?: JSONObject.NULL)
            .put("stage", document.optJSONObject("status")?.optString("maxStage")
                ?: JSONObject.NULL)
            .put("gate", document.optString("referenceGate"))
            .put("experimental", document.optBoolean("experimental"))
            .put("failure", document.optString("failure"))
            .put("evidencePath", document.optString("evidencePath"))
        /*
         * The full record can exceed logcat's per-line limit; the compact line
         * keeps the verdict greppable even when the JSON line is truncated.
         */
        android.util.Log.i("MapleSU", LOG_PREFIX + "SUMMARY " + summary)
        android.util.Log.i("MapleSU", LOG_PREFIX + document)
        return error
    }

    private fun writeAtomically(target: File, document: JSONObject) {
        val parent = target.parentFile
        val staging = if (parent == null) target else File(parent, target.name + ".new")
        val text = document.toString(2)
        staging.writeText(text)
        if (!staging.renameTo(target)) {
            target.writeText(text)
            if (staging.exists() && !staging.delete()) {
                // Best effort; the direct copy above is complete.
            }
        }
    }

    private fun safeSnapshot(run: Run, phase: String, full: Boolean): JSONObject =
        runCatching { run.snapshot(phase, full) }.getOrElse { thrown ->
            JSONObject()
                .put("schemaVersion", 1)
                .put("flow", "p2/ghostlock-takeover")
                .put("phase", phase)
                .put("attemptId", run.attemptId)
                .put("startedAtMillis", run.startedAtMillis)
                .put("writtenAtMillis", System.currentTimeMillis())
                .put("deviceRelease", run.deviceRelease ?: JSONObject.NULL)
                .put("reference", run.reference)
                .put("productProfile", run.product)
                .put("failure", run.failure ?: JSONObject.NULL)
                .put("problems", "the evidence snapshot itself failed: " + describe(thrown) +
                    "; " + run.problemsText())
        }

    // --------------------------------------------------------------- helpers

    private fun firstGhostlockToken(value: String?): String? {
        if (value.isNullOrEmpty()) return null
        val token = GHOSTLOCK_TOKEN.find(value)?.value ?: return null
        // The assumption marker is a provenance label, not a failure code.
        if (token.startsWith("GHOSTLOCK_PROFILE_ASSUMED")) return null
        return token
    }

    private fun keyPaths(text: String): JSONArray {
        val out = JSONArray()
        val stack = ArrayList<String>()
        for (rawLine in text.split("\n")) {
            var line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) continue
            while (line.startsWith("}")) {
                if (stack.isNotEmpty()) stack.removeAt(stack.size - 1)
                line = line.substring(1).trim()
            }
            if (line.isEmpty()) continue
            if (line.endsWith("{")) {
                stack.add(line.removeSuffix("{").trim())
                continue
            }
            val match = Regex("^([A-Za-z0-9_]+)\\s*=\\s*(.+?)\\s*,?$").find(line) ?: continue
            val path = if (stack.isEmpty()) {
                match.groupValues[1]
            } else {
                stack.joinToString(".") + "." + match.groupValues[1]
            }
            out.put(path)
        }
        return out
    }

    private fun stageIndex(stage: String?): Int =
        if (stage == null) -1 else JailbreakStatus.ORDER.indexOf(stage)

    private fun enforcingText(value: Int): String = when (value) {
        1 -> "Enforcing"
        0 -> "Permissive"
        else -> "unreadable"
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }

    private fun bound(text: String, limit: Int): String =
        if (text.length <= limit) text else text.take(limit) + "...(truncated)"

    private fun describe(thrown: Throwable): String =
        thrown.javaClass.simpleName + ": " + (thrown.message ?: "")

    /** `describe`, plus the cause chain: the provider wraps its refusal. */
    private fun describeChain(thrown: Throwable): String {
        val parts = mutableListOf<String>()
        var current: Throwable? = thrown
        var depth = 0
        while (current != null && depth < 5) {
            parts.add(describe(current))
            current = current.cause
            depth++
        }
        return parts.joinToString(" <- ")
    }

    private companion object {
        const val EVIDENCE_NAME = "ghostlock.json"
        const val LOG_PREFIX = "MAPLESU_GHOSTLOCK_EVIDENCE "
        const val REFERENCE_ASSET = "ghostlock-reference.json"
        const val REFERENCE_APP = "work/ghostlock-app"

        const val REFERENCE_PRESENT = "GHOSTLOCK_REFERENCE_PROFILE_PRESENT"
        const val REFERENCE_MISSING = "GHOSTLOCK_REFERENCE_PROFILE_MISSING"
        const val REFERENCE_SNAPSHOT_UNAVAILABLE = "GHOSTLOCK_REFERENCE_SNAPSHOT_UNAVAILABLE"

        const val VERDICT_REFERENCE_MISSING = "REFERENCE_PROFILE_MISSING"
        const val VERDICT_REACHED = "REACHED_PROVIDER_STAGE"
        const val VERDICT_REFUSED = "REFUSED_WITH_CODE"
        const val VERDICT_INCONCLUSIVE = "INCONCLUSIVE"

        /** `escalateGhostlock` waits 45 s for the lease; the directory step adds up to 120 s. */
        const val WAIT_MILLIS = 180_000L
        const val POLL_MILLIS = 500L
        const val SETTLE_MILLIS = 2_000L
        const val WATCHDOG_PERIOD_MILLIS = 2_000L
        const val LOG_TAIL_LIMIT = 12_000
        const val PRODUCT_PROVENANCE =
            "byemaxx/ghostlock-anchor ghostlock-oneplus/src/devices/op13/offsets.h " +
                "OFFSETS_ENTRY for this exact uname (hex converted to decimal); " +
                "candidate until re-derived on the device"

        /** Any stable Ghostlock refusal code, with its optional detail suffix. */
        val GHOSTLOCK_TOKEN = Regex("GHOSTLOCK_[A-Z][A-Z0-9_]*(?::[A-Za-z0-9_.:/+\\-]+)*")
    }
}
