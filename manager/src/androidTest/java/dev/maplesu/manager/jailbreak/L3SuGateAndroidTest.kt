package dev.maplesu.manager.jailbreak

import android.net.Uri
import android.os.Bundle
import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.NativeSu
import dev.maplesu.manager.runtime.NativeSuDaemon
import dev.maplesu.manager.runtime.SuGate
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.IOException
import java.util.Collections
import java.util.Timer
import java.util.TimerTask
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * L3 (ABI v2) device acceptance: one hook attempt arms the kernel su gate, the
 * published `deploySu` path runs commands as uid 0 three times, a forged token is
 * refused, and the attempt leaves the device exactly as it found it.
 *
 * <p>This is the same one-attempt-per-boot product path the app uses:
 * [NativeSuDaemon.prepareHook] is called exactly **once** and it is the provider
 * that escalates. Calling `escalate` first would spend this boot's kernel window
 * and make the attempt refuse itself (`DIRTYFRAG_REBOOT_REQUIRED_AFTER_ATTEMPT`).
 *
 * <p>Evidence is written before every assertion, and three times per run: `pre`
 * before the product path, `watchdog` from a timer, and `final` in `finally`. The
 * step-2/step-3 series lost whole records when the process died inside the
 * handover; a red result must still leave the JSON behind.
 *
 * <p>**Process liveness (2026-10-31, second pass).** Before the attempt the test records
 * `deviceIdle{whitelistBefore, whitelistAdd, whitelistAfter, setInactive, inactiveAfter}`
 * (`cmd deviceidle whitelist +<pkg>`, `am set-inactive <pkg> false`, each read back) and
 * `foreground{mode=DISABLED_BY_DEFAULT, started=false, ok=false}`: **no Activity is
 * started**. Launching `MainActivity` from the instrumentation process is what killed
 * that process before `prepareHook` on 2026-10-31 (`wm_finish_activity ... proc died
 * without state saved`, no `am_kill`), so the keep-alive is the doze exemption only; the
 * old foreground path is opt-in (`-e maplesuForeground activity`). After the attempt it
 * records `processKill{...}`, and a cached reclaim that can be attributed to this
 * attempt's pids (or to this run's window) is named as
 * `PROCESS_KILLED_BY_SYSTEM:<line>` in `failure`/`killLine` rather than left implicit.
 *
 * <p>**su domain (2026-10-31, second pass).** The three `deploySu` runs prove uid 0; they
 * do not prove the child's SELinux domain. So one more `deploySu` runs
 * `id -u; cat /proc/self/attr/current` and the shell-UID probe
 * `su -c 'id -u; cat /proc/self/attr/current'` is recorded too. `suDomain.unexpectedToken`
 * carries `SU_DOMAIN_UNEXPECTED:<domain>` when the uid-0 child is still in
 * `untrusted_app` - evidence only, it never changes the L3 verdict.
 *
 * <p>Recorded at
 * `getExternalFilesDir(null)/jailbreak-evidence/l3-su-gate.json` (the same file
 * `tools/device_l3_acceptance.sh` pulls), with a `filesDir` fallback if the
 * external volume is unavailable.
 *
 * <p>Run it with:
 * `am instrument -w -e class dev.maplesu.manager.jailbreak.L3SuGateAndroidTest#gateArmsAndSuRuns dev.maplesu.manager.test/androidx.test.runner.AndroidJUnitRunner`
 */
@RunWith(AndroidJUnit4::class)
class L3SuGateAndroidTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()

    /** ABI v2: exactly 16 lowercase hex digits, `%016llx`. */
    private val tokenPattern = Regex("^[0-9a-f]{16}$")

    /** One shell invocation; [error] is non-null when the command could not be run. */
    private class Shell(val text: String, val error: String?)

    /** One `deploySu` answer; [threw] is non-null when the provider call itself failed. */
    private class Deploy(
        val code: Int?,
        val out: String,
        val err: String,
        val threw: String?,
    )

    /** Everything this attempt observed; re-read for each evidence phase. */
    private inner class Run(val attemptId: String, val startedAtMillis: Long) {
        @Volatile var bootBefore: String? = null
        @Volatile var bootAfter: String? = null
        @Volatile var enforcingBefore: Int = Int.MIN_VALUE
        @Volatile var enforcingAfter: Int = Int.MIN_VALUE
        @Volatile var mountsBefore: Shell = Shell("", "not-collected")
        @Volatile var mountsAfter: Shell = Shell("", "not-collected")
        @Volatile var status: JailbreakStatus? = null
        @Volatile var gate: SuGate.Gate? = null
        @Volatile var negative: JSONObject? = null
        @Volatile var processUidBefore: Int = -1
        @Volatile var processUidAfter: Int = -1
        @Volatile var ps: Shell = Shell("", "not-collected")
        @Volatile var failure: String? = null
        /** Process liveness: the foreground decision, the doze requests and the kill record. */
        @Volatile var foreground: ForegroundSession? = null
        @Volatile var deviceIdle: JSONObject? = null
        @Volatile var processKill: JSONObject? = null
        @Volatile var killLine: String? = null

        /** The su domain: the extra `deploySu` child plus the shell-UID probe. */
        @Volatile var suDomainDeploy: Deploy? = null
        @Volatile var suDomain: JSONObject? = null

        val deploys = Collections.synchronizedList(mutableListOf<Deploy>())

        @Synchronized
        fun snapshot(phase: String): JSONObject {
            val observed = status
            val gateNow = gate
            val mountsError = mountsBefore.error ?: mountsAfter.error
            val mountsDiff =
                if (mountsBefore.error == null && mountsAfter.error == null) {
                    mountDiff(
                        projectedMounts(mountsBefore.text),
                        projectedMounts(mountsAfter.text),
                    )
                } else {
                    emptyList()
                }
            val su = JSONArray()
            synchronized(deploys) {
                for (deploy in deploys) {
                    su.put(
                        JSONObject()
                            .put("code", deploy.code?.toLong() ?: JSONObject.NULL)
                            .put("out", deploy.out)
                            .put("err", deploy.err)
                            .put("threw", deploy.threw ?: JSONObject.NULL),
                    )
                }
            }
            return JSONObject()
                .put("schemaVersion", 1)
                .put("hook", "l3/su-gate")
                .put("phase", phase)
                .put("attemptId", attemptId)
                .put("startedAtMillis", startedAtMillis)
                .put("writtenAtMillis", System.currentTimeMillis())
                .put("bootBefore", bootBefore ?: JSONObject.NULL)
                .put("bootAfter", bootAfter ?: JSONObject.NULL)
                .put(
                    "bootUnchanged",
                    bootBefore != null && bootAfter != null && bootBefore == bootAfter,
                )
                .put("enforcingBefore", enforcingValue(enforcingBefore))
                .put("enforcingAfter", enforcingValue(enforcingAfter))
                .put("status", statusJson(observed))
                .put("gate", gateJson(gateNow))
                .put("su", su)
                .put("negative", negative ?: JSONObject.NULL)
                .put("mountsBeforeError", mountsBefore.error ?: JSONObject.NULL)
                .put("mountsAfterError", mountsAfter.error ?: JSONObject.NULL)
                .put("mountsDiffLines", JSONArray(mountsDiff))
                .put("mountsConsistent", mountsError == null && mountsDiff.isEmpty() && bootAfter != null)
                .put("psUid0Manager", JSONArray(uidZeroManagerLines(ps.text)))
                .put("psError", ps.error ?: JSONObject.NULL)
                .put("ps", bound(ps.text, 4000))
                .put("processUidBefore", processUidBefore)
                .put("processUidAfter", processUidAfter)
                .put("foreground", foreground?.evidence() ?: ForegroundSession.notCollected())
                .put("deviceIdle", deviceIdle ?: JSONObject().put("applied", false))
                .put("processKill", processKill ?: JSONObject().put("collected", false))
                .put("killLine", killLine ?: JSONObject.NULL)
                .put("suDomain", suDomain ?: JSONObject().put("collected", false))
                .put("suDomainToken", suDomain?.let {
                    if (it.isNull("unexpectedToken")) JSONObject.NULL
                    else it.optString("unexpectedToken")
                } ?: JSONObject.NULL)
                .put("failure", failure ?: JSONObject.NULL)
        }
    }

    @Test
    fun gateArmsAndSuRuns() {
        val run = Run(UUID.randomUUID().toString(), System.currentTimeMillis())
        run.processUidBefore = android.os.Process.myUid()
        /*
         * Process liveness first: **no Activity is started** (`foreground.mode=
         * DISABLED_BY_DEFAULT`). On 2026-10-31 holding MainActivity in the foreground was
         * itself the death: `wm_finish_activity ... proc died without state saved` before
         * `prepareHook`, no `am_kill`. What is left is the doze exemption, which never
         * touches the target process. Both calls are recorded and neither is fatal.
         */
        run.foreground = ForegroundSession.activate(context)
        run.deviceIdle = DeviceIdlePolicy.apply(context)

        val finished = AtomicBoolean(false)
        val watchdog = Timer("l3-su-gate-evidence", true)
        watchdog.schedule(
            object : TimerTask() {
                override fun run() {
                    if (!finished.get()) {
                        writeEvidence(run.snapshot("watchdog"))
                    }
                }
            },
            WATCHDOG_MILLIS,
        )

        var writeError = ""
        try {
            // (1) Baseline: boot, SELinux and the mount table before anything runs.
            run.bootBefore = DirtyfragAttempt.readBootId()
            run.enforcingBefore = readEnforcingRobust()
            run.mountsBefore = shell("cat /proc/mounts")

            // (2) The pre-attempt record: cannot be lost to a hang or a kill.
            writeError = writeEvidence(run.snapshot("pre"))

            // (3) The product path, exactly once. It is the provider that
            // escalates; a prior `escalate()` would burn this boot's window.
            val attemptRequest = JailbreakRequest(
                method = "dirtyfrag",
                attemptId = run.attemptId,
                bootId = run.bootBefore,
                // One boot, one attempt: a soft reboot would invalidate the
                // acceptance and could not be observed from here.
                softReboot = false,
                rootBackend = JailbreakRequest.BACKEND_HOOK,
            )
            val status = NativeSuDaemon.prepareHook(context, attemptRequest)
            run.status = status

            // (4) Gate: always read it for the record. The helper's document is
            // root-owned and bound to this attempt and this boot.
            val gate = SuGate.read(context, run.attemptId, run.bootBefore)
            run.gate = gate

            if (status.stage == JailbreakStatus.STAGE_DAEMON_READY) {
                // (5) The published path, three times. Every call re-reads the
                // gate and forks its own child; none may be 126 or non-zero.
                repeat(DEPLOY_ATTEMPTS) {
                    run.deploys.add(deploySu("/system/bin/id -u"))
                }

                /*
                 * (5b) The domain half: one more `deploySu` whose child prints its uid
                 *      **and** its SELinux domain. The three runs above prove uid 0; this
                 *      is what tells a real root apart from a uid-0 child that stayed in
                 *      the caller's untrusted_app domain. Recorded, never asserted.
                 */
                run.suDomainDeploy = deploySu(SuDomainEvidence.SESSION_COMMAND)

                // (6) Negative: a gate copy with a forged non-zero token. The
                // client has no way to know it is forged, so this exercises the
                // kernel ARM check itself; it must refuse and the child must not
                // be able to exec.
                run.negative = runNegative(gate)
            } else {
                run.negative = JSONObject()
                    .put("skipped", "stage_not_daemon_ready")
                    .put("stage", status.stage)
                    .put("code", -1)
            }
        } catch (thrown: Throwable) {
            // Recorded, never re-thrown here: the final write is the deliverable.
            run.failure = describe(thrown)
        } finally {
            finished.set(true)
            watchdog.cancel()
            /* Close the keep-alive before the last record so the task is not left behind. */
            run.foreground?.finish()
            run.processUidAfter = android.os.Process.myUid()
            run.bootAfter = runCatching { DirtyfragAttempt.readBootId() }.getOrNull()
            run.enforcingAfter = readEnforcingRobust()
            run.mountsAfter = shell("cat /proc/mounts")
            run.ps = shell("ps -A -o UID,NAME")
            /*
             * The platform's own record of this package's processes dying. A cached-state
             * reclaim is named as such (`PROCESS_KILLED_BY_SYSTEM:<line>`) instead of being
             * left as a stage that merely "is not DAEMON_READY"; a spent-window stage is
             * not reclassified, because that is orchestration, not a death.
             */
            val processKill = ProcessKillEvidence.collect(
                context, "l3-su-gate", run.startedAtMillis)
            run.processKill = processKill
            val deathPids = setOfNotNull(run.status?.ownerPid, run.status?.workerPid)
            val killLine = ProcessKillEvidence.systemKillLine(
                processKill, deathPids, run.startedAtMillis)
            run.killLine = killLine
            if (run.failure == null && killLine != null &&
                run.status?.stage != JailbreakStatus.STAGE_DAEMON_READY
            ) {
                run.failure = ProcessKillEvidence.token(killLine)
            }
            /*
             * The su domain, collected last: the extra `deploySu` child (uid + SELinux
             * domain from one invocation) and the shell-UID probe. Evidence only - it
             * never decides this test.
             */
            run.suDomain = SuDomainEvidence.summary(
                "deploySu" to run.suDomainDeploy?.let { deploy ->
                    if (deploy.threw != null) {
                        SuDomainEvidence.notAttempted(
                            "l3/deploySu", "DEPLOY_THREW:" + deploy.threw)
                    } else {
                        SuDomainEvidence.fromOutput(
                            label = "l3/deploySu",
                            command = SuDomainEvidence.SESSION_COMMAND,
                            executed = "content://dev.maplesu.manager.root_directory " +
                                "deploySu(script=\"" + SuDomainEvidence.SESSION_COMMAND + "\")",
                            stdout = deploy.out,
                            rc = deploy.code ?: -1,
                            stderr = deploy.err,
                            runner = "the published deploySu provider method (uid-0 child " +
                                "of the Manager)",
                            callerUid = android.os.Process.myUid(),
                        )
                    }
                },
                "shell" to SuDomainEvidence.probeShell("l3/shell"),
            )
            writeError = writeEvidence(run.snapshot("final"))
        }

        // (7) Assertions last: every failure has already left the record on disk.
        assertEquals("evidence was not written to the external files dir: " + writeError, "", writeError)
        assertEquals(
            "prepareHook stage (failure=" + run.status?.failure + " message=" +
                run.status?.message + (run.killLine?.let { " processKill=" + it } ?: "") + ")",
            JailbreakStatus.STAGE_DAEMON_READY,
            run.status?.stage,
        )
        assertNull("L3 attempt threw before it could be judged: " + run.failure, run.failure)

        val gate = run.gate
        assertNotNull("SuGate.read returned no gate", gate)
        assertTrue(
            "gate not armed: suGate=" + gate?.suGate + " bound=" + gate?.bound +
                " attempt=" + gate?.attempt,
            gate?.armed == true,
        )
        val token = gate?.suToken
        assertNotNull("gate.suToken is missing", token)
        assertTrue(
            "suToken is not 16 lowercase hex digits (len=" + (token?.hex?.length ?: -1) + ")",
            token != null && tokenPattern.matches(token.hex),
        )

        assertEquals("deploySu must be called exactly three times", 3, run.deploys.size)
        run.deploys.forEachIndexed { index, deploy ->
            assertEquals(
                "deploySu[" + index + "] code (out=" + deploy.out + " err=" + deploy.err +
                    " threw=" + deploy.threw + ")",
                0,
                deploy.code,
            )
            assertEquals("deploySu[" + index + "] out", "0", deploy.out)
        }

        val negative = run.negative
        assertNotNull("negative token probe is missing", negative)
        assertTrue(
            "a forged token produced a successful su: " + negative,
            negative != null && negative.optInt("code", 0) != 0,
        )
        assertEquals("the instrumentation process changed uid", run.processUidBefore, run.processUidAfter)
        assertTrue("the instrumentation process is uid 0", run.processUidBefore != 0)

        assertEquals("boot id changed during the L3 attempt", run.bootBefore, run.bootAfter)
        assertEquals("SELinux was not restored to enforcing", 1, run.enforcingAfter)
        assertNull("mounts before unreadable: " + run.mountsBefore.error, run.mountsBefore.error)
        assertNull("mounts after unreadable: " + run.mountsAfter.error, run.mountsAfter.error)
        assertNull("ps -A -o UID,NAME failed: " + run.ps.error, run.ps.error)
        assertTrue("ps -A -o UID,NAME produced no output", run.ps.text.isNotBlank())
        val diff = mountDiff(
            projectedMounts(run.mountsBefore.text),
            projectedMounts(run.mountsAfter.text),
        )
        assertTrue(
            "mount table changed during the attempt: " + diff.joinToString(" | "),
            diff.isEmpty(),
        )
        val leaked = uidZeroManagerLines(run.ps.text)
        assertTrue(
            "a uid-0 dev.maplesu.manager process is still running: " +
                leaked.joinToString(" | ") + " (ps=" + bound(run.ps.text, 500) + ")",
            leaked.isEmpty(),
        )
    }

    /** One `deploySu` through the published provider method. */
    private fun deploySu(script: String): Deploy = runCatching {
        val result = context.contentResolver.call(
            Uri.parse("content://dev.maplesu.manager.root_directory"),
            "deploySu",
            null,
            Bundle().apply { putString("script", script) },
        )
        Deploy(
            code = result?.getInt("code", Int.MIN_VALUE),
            out = result?.getString("out").orEmpty().trim(),
            err = result?.getString("err").orEmpty(),
            threw = null,
        )
    }.getOrElse {
        Deploy(null, "", "", describe(it))
    }

    /**
     * A bound, `ARMED` gate whose token is replaced by a forged non-zero value.
     * [SuGate.Gate.armed] cannot tell it apart from the real one, so [NativeSu]
     * hands it to the kernel, which is exactly the check under test.
     */
    private fun runNegative(real: SuGate.Gate): JSONObject {
        val fake = SuGate.Gate(
            suToken = SuGate.Token(FORGED_TOKEN),
            suGate = real.suGate,
            bound = real.bound,
            attempt = real.attempt,
            bootId = real.bootId,
        )
        val record = JSONObject()
            .put("token", FORGED_TOKEN)
            .put("clientGateArmed", fake.armed)
            .put("processUidBefore", android.os.Process.myUid())
        if (!fake.armed) {
            // Only reachable when the real gate is not bound to this attempt;
            // nothing was sent to the kernel, so say that instead of implying a
            // refusal was observed.
            return record.put("skipped", "forged_gate_not_armed").put("code", -1)
        }
        val result = runCatching {
            NativeSu.executeScript(fake, "/system/bin/id -u", fallback = null, timeoutMillis = 15_000)
        }
        return if (result.isSuccess) {
            val value = result.getOrThrow()
            record
                .put("code", value.code)
                .put("out", value.out)
                .put("err", value.err)
                .put("processUidAfter", android.os.Process.myUid())
        } else {
            record
                .put("threw", describe(result.exceptionOrNull() ?: RuntimeException("unknown")))
                .put("code", -1)
                .put("processUidAfter", android.os.Process.myUid())
        }
    }

    private fun shell(command: String): Shell = runCatching {
        val descriptor = instrumentation.uiAutomation.executeShellCommand(command)
        val text = ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { stream ->
            stream.readBytes().toString(Charsets.UTF_8)
        }
        Shell(text, null)
    }.getOrElse {
        Shell("", describe(it))
    }

    /**
     * SELinux enforcement as the *device* has it, not as one failed `open()` says.
     *
     * <p>The first attempt at this measurement returned `-1` on a device whose
     * `/sys/fs/selinux/enforce` was `1` (a transient IOException inside the test
     * process after the attempt), which turned a real acceptance into a red test.
     * So: retry the direct read, then ask the shell - which is the same source the
     * operator's `adb shell getenforce` uses - and only then give up. `-1` now means
     * "no source could answer", never "one read failed".
     */
    private fun readEnforcingRobust(): Int {
        repeat(3) {
            val value = runCatching { DirtyfragAttempt.readEnforcing() }.getOrDefault(-1)
            if (value == 0 || value == 1) return value
            runCatching { Thread.sleep(150) }
        }
        val fromShell = shell("cat /sys/fs/selinux/enforce").text.trim()
        return when (fromShell) {
            "0" -> 0
            "1" -> 1
            else -> -1
        }
    }

    private fun statusJson(status: JailbreakStatus?): JSONObject {
        if (status == null) return JSONObject().put("present", false)
        return JSONObject()
            .put("present", true)
            .put("method", status.method)
            .put("stage", status.stage)
            .put("failure", status.failure ?: JSONObject.NULL)
            .put("message", status.message)
            .put("rootBackend", status.rootBackend ?: JSONObject.NULL)
            .put("attemptId", status.attemptId ?: JSONObject.NULL)
            .put("bootId", status.bootId ?: JSONObject.NULL)
            .put("restoreEnforcing", status.restoreEnforcing ?: JSONObject.NULL)
            .put("suGate", status.suGate ?: JSONObject.NULL)
            .put("suTokenRecorded", status.suToken != null)
    }

    private fun gateJson(gate: SuGate.Gate?): JSONObject {
        if (gate == null) return JSONObject().put("present", false)
        return JSONObject()
            .put("present", true)
            .put("suGate", gate.suGate ?: JSONObject.NULL)
            .put("armed", gate.armed)
            .put("bound", gate.bound)
            .put("attempt", gate.attempt ?: JSONObject.NULL)
            .put("bootId", gate.bootId ?: JSONObject.NULL)
            .put("suTokenPresent", gate.suToken != null)
            .put("suTokenHexLength", gate.suToken?.hex?.length ?: -1)
    }

    /**
     * Writes the record atomically. Returns a non-empty error only when the
     * required external location failed; the `filesDir` fallback is recorded in
     * the document itself.
     */
    @Synchronized
    private fun writeEvidence(document: JSONObject): String {
        val external = runCatching { context.getExternalFilesDir(null) }.getOrNull()
        val primary = external?.let {
            File(File(it, "jailbreak-evidence"), "l3-su-gate.json")
        }
        var error = ""
        if (primary == null) {
            error = "external files dir unavailable"
        } else {
            try {
                document.put("evidencePath", primary.path)
                primary.parentFile?.let { directory ->
                    if (!directory.isDirectory && !directory.mkdirs() && !directory.isDirectory) {
                        throw IOException("mkdirs failed: " + directory.path)
                    }
                }
                writeAtomically(primary, document)
            } catch (thrown: Throwable) {
                error = describe(thrown)
            }
        }
        if (error.isNotEmpty()) {
            try {
                val fallback = File(File(context.filesDir, "jailbreak-evidence"), "l3-su-gate.json")
                fallback.parentFile?.mkdirs()
                document.put("evidenceFallbackPath", fallback.path)
                writeAtomically(fallback, document)
            } catch (thrown: Throwable) {
                document.put("evidenceFallbackError", describe(thrown))
            }
        }
        /*
         * The internal copy is written unconditionally: `/sdcard/Android/data` is not
         * readable through `run-as` on this platform, and the operator has to be able
         * to `adb shell run-as dev.maplesu.manager cat` the record without pulling it.
         * It is also what the device-acceptance script reads. The external copy stays
         * as the human-openable one.
         */
        try {
            val internal = File(File(context.filesDir, "jailbreak-evidence"), "l3-su-gate.json")
            internal.parentFile?.mkdirs()
            document.put("evidenceInternalPath", internal.path)
            writeAtomically(internal, document)
        } catch (thrown: Throwable) {
            document.put("evidenceInternalError", describe(thrown))
            if (error.isEmpty()) error = describe(thrown)
        }
        /* One logcat line the operator can grep without any file access at all. */
        android.util.Log.i("MapleSU", "MAPLESU_L3_EVIDENCE " + document)
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

    /**
     * `$(1,$2,$3)` projection of `/proc/mounts`, sorted: the fields that must not
     * change within one boot. Mount options (field 4) legitimately change.
     */
    private fun projectedMounts(text: String): List<String> =
        text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .mapNotNull { line ->
                val fields = line.split(Regex("\\s+"))
                if (fields.size >= 3) fields.take(3).joinToString(" ") else null
            }
            .sorted()
            .toList()

    /** Multiset difference of the two projections; empty means "unchanged". */
    private fun mountDiff(before: List<String>, after: List<String>): List<String> {
        val beforeCounts = before.groupingBy { it }.eachCount()
        val afterCounts = after.groupingBy { it }.eachCount()
        val diff = mutableListOf<String>()
        for (key in (beforeCounts.keys + afterCounts.keys).sorted()) {
            val old = beforeCounts[key] ?: 0
            val new = afterCounts[key] ?: 0
            if (old != new) diff.add("-[" + old + "] +[" + new + "] " + key)
        }
        return diff
    }

    /** `ps -A -o UID,NAME` lines that are both uid 0 (or `root`) and this package. */
    private fun uidZeroManagerLines(ps: String): List<String> =
        ps.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .filter { line ->
                val fields = line.split(Regex("\\s+"))
                fields.size >= 2 &&
                    (fields[0] == "0" || fields[0] == "root") &&
                    fields[1].contains("dev.maplesu.manager")
            }
            .toList()

    private fun enforcingValue(value: Int): Any =
        if (value == Int.MIN_VALUE) JSONObject.NULL else value.toLong()

    private fun bound(text: String, limit: Int): String =
        if (text.length <= limit) text else text.take(limit) + "...(truncated)"

    private fun describe(thrown: Throwable): String =
        thrown.javaClass.simpleName + ": " + (thrown.message ?: "")

    private companion object {
        /** `deploySu` is run this many times: one success must not be a fluke. */
        const val DEPLOY_ATTEMPTS = 3

        /** Non-zero and not the real token: the kernel's ARM branch must refuse it. */
        const val FORGED_TOKEN = "0000000000000001"

        /** A frozen `prepareHook` still leaves a usable record. */
        const val WATCHDOG_MILLIS = 120_000L
    }
}
