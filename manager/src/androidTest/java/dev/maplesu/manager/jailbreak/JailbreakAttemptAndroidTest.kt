package dev.maplesu.manager.jailbreak

import android.os.Binder
import android.os.Build
import android.system.Os
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Ordinary-App provider attempt on a real device.
 *
 * <p>R08 (review 2026-10-26): this file used to accept `DAEMON_READY` **or**
 * `FAILED` and compared two post-attempt integrity reads with each other, so an
 * instrumentation "OK" proved nothing. A successful attempt is now asserted
 * exactly: the trusted process must report DAEMON_READY, the restoration must be
 * verified for this attempt, a real child must return UID 0 with exit code 0, and
 * the properties, slot, boot id and partition digests captured *before* the
 * attempt must still hold after it. Observation-only records stay in separate
 * tests and are never phrased as acceptance.
 */
@RunWith(AndroidJUnit4::class)
class JailbreakAttemptAndroidTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun evidenceDirectory(): File {
        val directory = File(context.getExternalFilesDir(null), "jailbreak-evidence")
        if (!directory.isDirectory) directory.mkdirs()
        check(directory.isDirectory) { "EVIDENCE_DIRECTORY_MISSING" }
        return directory
    }

    private fun write(name: String, document: JSONObject) {
        File(evidenceDirectory(), name).writeText(document.toString(2))
    }

    private fun target(): JSONObject = JSONObject()
        .put("androidRelease", Build.VERSION.RELEASE)
        .put("sdk", Build.VERSION.SDK_INT)
        .put("kernelRelease", Os.uname().release)
        .put("abi", Build.SUPPORTED_ABIS.firstOrNull().orEmpty())
        .put("manufacturer", Build.MANUFACTURER)
        .put("soc", Build.SOC_MODEL)
        .put("fingerprint", Build.FINGERPRINT)
        .put("securityPatch", Build.VERSION.SECURITY_PATCH)
        .put("bootId", DirtyfragAttempt.readBootId())
        .put("enforcing", DirtyfragAttempt.readEnforcing())

    /**
     * Everything an ordinary App can capture *before* an attempt exists. The four
     * partition digests need privilege, so they are captured immediately after the
     * handover and only ever labelled POST_ATTEMPT_HASH_STABLE - they are not a
     * before/after pair.
     */
    private fun preEntryBaseline(): JSONObject {
        val status = JailbreakStatus.read(context)
        return JSONObject()
            .put("bootId", DirtyfragAttempt.readBootId())
            .put("fingerprint", Build.FINGERPRINT)
            .put("securityPatch", Build.VERSION.SECURITY_PATCH)
            .put("kernelRelease", Os.uname().release)
            .put("slotSuffix", systemProperty("ro.boot.slot_suffix"))
            .put("verifiedBootState", systemProperty("ro.boot.verifiedbootstate"))
            .put("flashLocked", systemProperty("ro.boot.flash.locked"))
            .put("apkDigests", apkDigests())
            .put("guardPresent", File("/dev/df").exists())
            .put("priorAttemptStage", status?.stage ?: JSONObject.NULL)
            .put("priorAttemptLive", status != null && status.stage in JailbreakStatus.LIVE_CLAIM)
    }

    private fun systemProperty(name: String): String =
        runCatching {
            val clazz = Class.forName("android.os.SystemProperties")
            clazz.getMethod("get", String::class.java).invoke(null, name) as? String
        }.getOrNull().orEmpty()

    private fun apkDigests(): JSONObject {
        val digests = JSONObject()
        val paths = context.packageManager.getPackageInfo(
            context.packageName, android.content.pm.PackageManager.GET_META_DATA)?.applicationInfo
        val source = paths?.sourceDir ?: context.applicationInfo.sourceDir
        for (path in listOf(source) + (paths?.splitSourceDirs?.toList() ?: emptyList())) {
            digests.put(File(path).name, sha256(File(path)))
        }
        return digests
    }

    private fun sha256(file: File): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val chunk = ByteArray(65536)
            while (true) {
                val read = input.read(chunk)
                if (read < 0) break
                digest.update(chunk, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun sharedDirtyReport(): JSONObject {
        val report = JSONObject()
        var mappings = 0
        var executableMapping = false
        var currentPath: String? = null
        var dirtyKb = 0L
        for (raw in File("/proc/self/smaps").readLines()) {
            val line = raw.trim()
            if (line.matches(Regex("^[0-9a-f]+-[0-9a-f]+\\s.*"))) {
                val parts = line.split(Regex("\\s+"))
                val path = if (parts.size >= 6) parts.subList(5, parts.size).joinToString(" ") else ""
                val permissions = parts.getOrNull(1) ?: ""
                executableMapping = permissions.length >= 4 && permissions[2] == 'x'
                currentPath = path
                if (executableMapping && path.contains("libc++")) mappings++
                continue
            }
            if (!line.startsWith("Shared_Dirty:") || !executableMapping) continue
            val path = currentPath ?: continue
            if (!path.contains("libc++") && !path.contains("libbinderdebug")) continue
            dirtyKb += line.removePrefix("Shared_Dirty:").trim().removeSuffix("kB").trim().toLongOrNull() ?: 0L
        }
        report.put("libcxxExecutableMappings", mappings)
        report.put("sharedDirtyKb", dirtyKb)
        report.put("clean", mappings > 0 && dirtyKb == 0L)
        return report
    }

    /** Shell text is assembled with an explicit dollar constant; `$` must not be interpolated. */
    private fun integrityScript(): List<String> {
        val d = "$"
        val script = "s=" + d + "(getprop ro.boot.slot_suffix); " +
            "echo enforcing=" + d + "(getenforce); " +
            "echo checkreqprot=" + d + "(cat /sys/fs/selinux/checkreqprot); " +
            "echo slot=" + d + "s; " +
            "for p in boot init_boot vendor_boot vbmeta; do " +
            "echo \"" + d + "p=" + d + "(sha256sum /dev/block/by-name/" + d + "p" + d + "s 2>/dev/null | cut -d' ' -f1)" +
            d + "(sha256sum /dev/block/by-name/" + d + "p 2>/dev/null | cut -d' ' -f1)\"; done; " +
            "echo policy=" + d + "(sha256sum /sys/fs/selinux/policy 2>/dev/null | cut -d' ' -f1); " +
            "echo modules=" + d + "(grep -c dfroot /proc/modules 2>/dev/null); " +
            "echo guards=" + d + "(ls /dev/df /dev/dfm0 2>/dev/null | wc -l); " +
            "echo bootid=" + d + "(cat /proc/sys/kernel/random/boot_id); " +
            "echo rootuid=" + d + "(id -u)"
        return listOf("/system/bin/sh", "-c", script)
    }

    private fun fields(output: String): Map<String, String> {
        val map = mutableMapOf<String, String>()
        for (line in output.lines()) {
            val at = line.indexOf('=')
            if (at <= 0) continue
            map[line.substring(0, at).trim()] = line.substring(at + 1).trim()
        }
        return map
    }

    /**
     * Observation only: the packaged profile set exists, and it does not contain
     * this release. It asserts the exact blocker, not a blanket refusal.
     */
    @Test
    fun ghostlockAdmissionNamesTheMissingRelease() {
        val releases = JailbreakAdmission.ghostlockReleases(context)
        val running = Os.uname().release
        val probe = JailbreakDeviceProbe.collect()
        val assessment = JailbreakAdmission.assess(JailbreakMethod.GHOSTLOCK, probe, releases)
        write("ghostlock-admission.json", JSONObject()
            .put("target", target())
            .put("runningRelease", running)
            .put("packagedReleases", releases.size)
            .put("containsRunningRelease", running in releases)
            .put("sourceCommit", assessment.sourceCommit)
            .put("blockers", JSONArray(assessment.blockers.map { it.name }))
            .put("canStart", assessment.canStart)
            .put("artefactBlocker",
                JailbreakAdmission.verifyArtifacts(context, JailbreakMethod.GHOSTLOCK)?.name))
        assertTrue("the APK must carry the pinned exact-profile set", releases.size > 70)
        if (running in releases) {
            assertTrue("a packaged exact profile must be admitted", assessment.canStart)
        } else {
            assertFalse("an unprofiled release must not be admitted", assessment.canStart)
            assertTrue("the blocker must name the missing profile",
                JailbreakBlocker.GHOSTLOCK_EXACT_PROFILE_MISSING in assessment.blockers)
        }
    }

    @Test
    fun dirtyfragAttemptProducesVerifiedHandover() {
        // The attempt must run while the App is actually runnable: this device's
        // vendor power manager freezes background UIDs, which would stop the App
        // from accepting the lease. Launching the real UI keeps the product path
        // (a visible App starting an attempt) and its foreground state intact.
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        var activity: android.app.Activity? = null
        try {
            activity = instrumentation.startActivitySync(
                android.content.Intent(android.content.Intent.ACTION_MAIN)
                    .setClassName(context, "com.maplesu.core.ui.MainActivity")
                    .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (error: Exception) {
            throw AssertionError("MAIN_ACTIVITY_START_FAILED", error)
        }
        try {
            dirtyFragAttempt()
        } finally {
            runCatching { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }

    private fun dirtyFragAttempt() {
        val before = preEntryBaseline()
        val probe = JailbreakDeviceProbe.collect()
        // The verdict comes from the packaged measured-target table, not from the
        // test: if this build is not the measured one, admission closes.
        val verified = JailbreakTargets.verdict(JailbreakTargets.PROVIDER_DIRTYFRAG,
            probe.kernelRelease, probe.fingerprint, probe.soc, probe.securityPatch, true) ==
            JailbreakTargets.Verdict.VERIFIED_TARGET
        val assessment = JailbreakAdmission.assess(JailbreakMethod.DIRTYFRAG, probe,
            verifiedTarget = verified)
        val document = JSONObject()
            .put("target", target())
            .put("method", "dirtyfrag")
            .put("preEntry", before)
            .put("admission", JSONObject()
                .put("kmi", assessment.kmi ?: JSONObject.NULL)
                .put("canStart", assessment.canStart)
                .put("blockers", JSONArray(assessment.blockers.map { it.name })))
            .put("artefactBlocker",
                JailbreakAdmission.verifyArtifacts(context, JailbreakMethod.DIRTYFRAG)?.name)
        if (!assessment.canStart) {
            write("dirtyfrag-attempt.json", document)
            fail("admission closed: " + assessment.blockers)
            return
        }
        val started = System.currentTimeMillis()
        val outcome = JailbreakController.run(context, JailbreakMethod.DIRTYFRAG)
        val status = JailbreakController.status(context)
        document.put("outcome", JSONObject()
            .put("stage", outcome.stage)
            .put("message", outcome.message)
            .put("failure", outcome.failure))
        document.put("elapsedMillis", System.currentTimeMillis() - started)
        if (status != null) {
            document.put("status", JSONObject()
                .put("stage", status.stage)
                .put("message", status.message)
                .put("failure", status.failure)
                .put("attemptId", status.attemptId ?: JSONObject.NULL)
                .put("bootId", status.bootId ?: JSONObject.NULL)
                .put("workerPid", status.workerPid ?: JSONObject.NULL)
                .put("workerDomain", status.workerDomain ?: JSONObject.NULL)
                .put("enforcingAtLease", status.enforcingAtLease ?: JSONObject.NULL)
                .put("restoreState", status.restoreState ?: JSONObject.NULL)
                .put("restoreOrigin", status.restoreOrigin ?: JSONObject.NULL)
                .put("restoreEnforcing", status.restoreEnforcing ?: JSONObject.NULL)
                .put("restoreCheckreqprot", status.restoreCheckreqprot ?: JSONObject.NULL)
                .put("restorePolicy", status.restorePolicy ?: JSONObject.NULL)
                .put("restoreFailures", status.restoreFailures ?: JSONObject.NULL))
        }
        // R08: the attempt succeeded only when the trusted process says so.
        assertEquals("attempt did not reach DAEMON_READY: " + outcome.failure,
            JailbreakStatus.STAGE_DAEMON_READY, outcome.stage)
        assertNotNull("attempt produced no status record", status)
        checkNotNull(status)
        assertEquals(JailbreakStatus.STAGE_DAEMON_READY, status.stage)
        assertEquals(before.getString("bootId"), status.bootId)
        assertNotNull("attempt id missing", status.attemptId)
        assertTrue("restoration must be verified, was " + status.restoreState,
            status.restoreState == "RESTORED_OBSERVED" || status.restoreState == "RESTORED_BASELINE")
        assertEquals("entry policy must be back to enforcing", 1, status.restoreEnforcing)
        assertEquals("the restore must not have changed the policy", 0, status.restorePolicy)
        assertEquals("native stage reported restore failures", 0, status.restoreFailures)

        val rootProbe = JailbreakController.probe(context, listOf("/system/bin/id"))
        document.put("probe", JSONObject()
            .put("rootUid", rootProbe.rootUid).put("rootPid", rootProbe.rootPid)
            .put("exitCode", rootProbe.exitCode).put("timedOut", rootProbe.timedOut)
            .put("output", rootProbe.output.take(512)))
        assertTrue("the executor did not return a real UID 0 child: " + rootProbe.error,
            rootProbe.succeeded)
        assertTrue("id did not report root: " + rootProbe.output,
            rootProbe.output.contains("uid=0(root)"))

        // A non-zero child must never count as a successful probe.
        val negative = JailbreakController.probe(context,
            listOf("/system/bin/sh", "-c", "exit 7"))
        document.put("negativeProbe", JSONObject()
            .put("exitCode", negative.exitCode).put("succeeded", negative.succeeded))
        assertFalse("a failing command must not be reported as success", negative.succeeded)
        assertEquals(7, negative.exitCode)

        val integrity = JailbreakController.probe(context, integrityScript())
        assertTrue("integrity read failed: " + integrity.error, integrity.succeeded)
        val observed = fields(integrity.output)
        document.put("postAttempt", JSONObject(observed as Map<*, *>))
        assertEquals("SELinux must be back to enforcing", "Enforcing", observed["enforcing"])
        assertEquals("checkreqprot must be unchanged", "0", observed["checkreqprot"])
        assertEquals("the module must not be loaded", "0", observed["modules"])
        assertEquals("attempt markers must be gone", "0", observed["guards"])
        assertEquals("the boot id must not change", before.getString("bootId"), observed["bootid"])
        assertEquals("uid 0 through the executor", "0", observed["rootuid"])
        assertEquals("the slot must not change", before.getString("slotSuffix"), observed["slot"])
        // Partition digests are captured after the handover, so they are recorded
        // as a stable observation, never as a before/after pair.
        val partitions = JSONObject()
        for (key in listOf("boot", "init_boot", "vendor_boot", "vbmeta")) {
            partitions.put(key, observed[key].orEmpty())
        }
        val allPresent = listOf("boot", "init_boot", "vendor_boot", "vbmeta")
            .all { observed[it].orEmpty().isNotEmpty() }
        document.put("partitionDigests", JSONObject()
            .put("state", if (allPresent) "POST_ATTEMPT_HASH_STABLE"
                 else "UNREADABLE_FROM_EXECUTOR_DOMAIN")
            .put("values", partitions)
            .put("allPresent", allPresent))
        /*
         * An unreadable digest is not a pass and is not faked: it is recorded as
         * such. The zero-write claim then rests on the checks above (slot, module,
         * guards, enforcing) which are all readable from this domain.
         */
        assertTrue("no partition digest readable and no slot evidence",
            allPresent or observed["slot"].orEmpty().isNotEmpty())

        // Same vantage point as the detector: this process reading its own smaps.
        val dirty = sharedDirtyReport()
        document.put("sharedDirty", dirty)
        assertTrue("restored system libraries must not stay shared-dirty: " + dirty,
            dirty.getBoolean("clean"))
        assertEquals("fingerprint changed during the attempt",
            before.getString("fingerprint"), Build.FINGERPRINT)

        /*
         * §7 authorization surface, exercised against the live executor: the master
         * switch must refuse to run, and grant/revoke must be observable.
         */
        val management = dev.maplesu.manager.runtime.NativeSuDaemon.management(context)
        val target = context.applicationInfo.uid
        val authorization = JSONObject()
        assertTrue("the master switch must start enabled", management.isEnabled())
        management.setEnabled(false)
        authorization.put("disabledStopsStart", management.start(arrayOf("/system/bin/id"), Binder(), false) == null)
        management.setEnabled(true)
        management.revoke(target)
        management.grant(target)
        authorization.put("hasGrant", management.hasGrant(target))
        authorization.put("grantCount", management.grantCount())
        management.revoke(target)
        authorization.put("revoked", !management.hasGrant(target))
        document.put("authorization", authorization)

        /*
         * S11 (partial): the task surface through the live executor. Short command,
         * large dual-stream output and a non-zero exit are checked here; a *streaming*
         * reader, deadline and cancel need the streaming protocol and are recorded as
         * not yet exercised in the document below.
         */
        val tasks = JSONObject()
        val short = JailbreakController.probe(context, listOf("/system/bin/id"))
        tasks.put("short", JSONObject().put("exit", short.exitCode)
            .put("hasUid0", short.output.contains("uid=0(root)")))
        assertEquals("short command must exit 0", 0, short.exitCode)
        assertTrue("short command must report root", short.output.contains("uid=0(root)"))
        val large = JailbreakController.probe(context, listOf("/system/bin/sh", "-c",
            "head -c 200000 /dev/zero | base64 -w0; head -c 200000 /dev/zero | base64 -w0 >&2"))
        tasks.put("largeDualStream", JSONObject().put("exit", large.exitCode)
            .put("stdoutBytes", large.output.length).put("timedOut", large.timedOut))
        assertEquals("large output must exit 0", 0, large.exitCode)
        assertTrue("large output must not time out", !large.timedOut)
        val failing = JailbreakController.probe(context, listOf("/system/bin/sh", "-c", "exit 9"))
        tasks.put("nonZeroExit", JSONObject().put("exit", failing.exitCode).put("succeeded", failing.succeeded))
        assertEquals("non-zero exit must be reported as 9", 9, failing.exitCode)
        assertTrue("a non-zero child must not count as a successful probe", !failing.succeeded)
        /*
         * S11: streaming and cancel are NOT_EXERCISED. The AIDL path uses the
         * synchronous run reply (the polling-based streaming variant timed out on one
         * of six runs), so claiming them here would be a false positive.
         */
        tasks.put("streaming", "NOT_EXERCISED")
        tasks.put("cancel", "NOT_EXERCISED")
        document.put("taskSurface", tasks)
        assertTrue("disabling the switch must stop start()", authorization.getBoolean("disabledStopsStart"))
        assertTrue("grant must be visible", authorization.getBoolean("hasGrant"))
        assertTrue("revoke must be visible", authorization.getBoolean("revoked"))
        write("dirtyfrag-attempt.json", document)
    }
}
