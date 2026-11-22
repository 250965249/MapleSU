package dev.maplesu.manager.jailbreak

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import dev.maplesu.manager.ksu.KsuBackends
import dev.maplesu.manager.runtime.IdentityProbeService
import dev.maplesu.manager.runtime.JailbreakGrantStore
import dev.maplesu.manager.runtime.NativeSuDiscovery
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.boot.ModeBootstrap
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/**
 * P1.su: does the **KSU su** path serve an app that is not the Manager?
 *
 * <p>Question this test answers, on the Normal (KernelSU) line only: a third-party UID
 * executes `/system/bin/su`, the KSU kernel's sucompat hook decides by the kernel
 * allowlist, and the Manager's own superuser surface is the thing that writes that
 * allowlist. So the chain under test is
 *
 * ```
 * manager UI list  ->  Natives.getAppProfile/setAppProfile  ->  libmaplesu_ksu.so
 *                  ->  KSU supercall (app profile / allowlist) -> sucompat
 *                  ->  /system/bin/su exec by the fixture's UID  ->  uid 0 or a refusal
 * ```
 *
 * <p>It also records the other two stores, because they are **not** the same list:
 * [JailbreakGrantStore] is what the Ultra/hook endpoint authorizes
 * (`JailbreakSuEndpoint.kt:53`), while `AuthorizationPolicy`
 * (`/data/adb/maplesu/authorization/<uid>/authorizations.bin`) is what the Normal
 * cooperative endpoint authorizes (`NativeSuDaemonService.kt:23`). The test writes one
 * grant into each store and reads the other back, so `sameListAsUltra` is measured, not
 * assumed.
 *
 * <p>Evidence (`filesDir/jailbreak-evidence/ksu-thirdparty.json` + `Log.i`) is written
 * **before** every assertion, so a red run still leaves the reason on disk. A run that
 * is not a Normal (KSU) boot records the named token and is skipped rather than failed:
 * the token says why this item cannot be exercised here.
 *
 * <p>**Process liveness (2026-10-31, second pass).** Before the su probes this class
 * records `deviceIdle{whitelistBefore, whitelistAdd, whitelistAfter, setInactive,
 * inactiveAfter}` (`cmd deviceidle whitelist +<pkg>`, `am set-inactive <pkg> false`, each
 * read back - attempted, recorded, never fatal) and
 * `foreground{mode=DISABLED_BY_DEFAULT, started=false, ok=false}`: **no Activity is
 * started**. Launching `MainActivity` from the instrumentation process is what killed that
 * process before `prepareHook` on 2026-10-31 (`wm_finish_activity ... proc died without
 * state saved`, no `am_kill`), so the old path is opt-in only
 * (`-e maplesuForeground activity`). After the probes it records `processKill{...}` from
 * `logcat -b events`; a cached-state reclaim inside this run's window
 * (`Cached(nirvana)`-class) turns the failure into
 * `...:PROCESS_KILLED_BY_SYSTEM:<line>` instead of an undifferentiated
 * `KSU_THIRD_PARTY_SU_NOT_WIRED`.
 *
 * <p>**su domain (2026-10-31, second pass).** A uid of 0 is not proof of working root, so
 * this class also records the SELinux domain of the child: the fixture runs
 * `/system/bin/su -c '/system/bin/id -u; cat /proc/self/attr/current'` as its own UID
 * (fixture transaction +9) and the shell-UID probe
 * `su -c 'id -u; cat /proc/self/attr/current'` is recorded too. `suDomain` carries
 * `SU_DOMAIN_UNEXPECTED:<domain>` when the su child is still in `untrusted_app`.
 *
 * <p>Run explicitly on a Normal boot:
 * `adb shell am instrument -w -e class dev.maplesu.manager.jailbreak.KsuThirdPartySuAndroidTest \
 *   dev.maplesu.manager.test/androidx.test.runner.AndroidJUnitRunner`
 *
 * <p>The fixture is [IdentityProbeService] in the test APK: a different package, a
 * different Linux UID and a different process from the Manager, exactly as
 * `JailbreakTakeoverAndroidTest` uses it. The `su` exec happens **inside that process**
 * (`NativeSuProbe.suCompat`, transaction +8); the instrumentation only reads the result.
 */
@RunWith(AndroidJUnit4::class)
class KsuThirdPartySuAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context get() = instrumentation.targetContext
    private val fixturePackage: String get() = instrumentation.context.packageName
    private val evidenceName = "ksu-thirdparty.json"
    private val tag = "MAPLESU_KSU_THIRDPARTY"

    /** The one name that classifies every refusal branch this test can observe. */
    private val notWired = "KSU_THIRD_PARTY_SU_NOT_WIRED"

    private fun bootId(): String? = runCatching {
        File("/proc/sys/kernel/random/boot_id").readText().trim()
    }.getOrNull()

    /**
     * One bounded shell read for the preconditions block. Goes through
     * [InstrumentationShell] so it is wrapped in `sh -c` like every other read here:
     * `executeShellCommand` does not interpret its argument as a script on this platform,
     * so a `ls ... 2>&1; echo rc=$?` reached `ls` with `;`, `echo` and `rc=$?` as arguments.
     */
    private fun shell(command: String): String {
        val record = InstrumentationShell.run(command)
        /* `isNull`, not optString: a successful command stores error as JSONObject.NULL,
         * whose toString() is the string "null". */
        return if (record.isNull("error")) record.optString("output")
        else "SHELL_COMMAND_FAILED:" + record.optString("error")
    }

    private fun text(bytes: ByteArray?): String = String(bytes ?: ByteArray(0), Charsets.UTF_8)

    private fun fixtureUid(): Int =
        context.packageManager.getApplicationInfo(fixturePackage, 0).uid

    private fun write(document: JSONObject) {
        val directory = File(context.filesDir, "jailbreak-evidence")
        if (!directory.isDirectory) directory.mkdirs()
        File(directory, evidenceName).writeText(document.toString(2))
        Log.i("MapleSU", tag + " " + document)
        if (document.optString("failure").isNotEmpty() && !document.isNull("failure")) {
            Log.w("MapleSU", tag + "_FAILURE " + document.optString("failure"))
        }
    }

    private fun waitForMode(timeoutMillis: Long): WorkMode? {
        val deadline = android.os.SystemClock.elapsedRealtime() + timeoutMillis
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            ModeRuntime.active?.let { return it }
            android.os.SystemClock.sleep(100)
        }
        return ModeRuntime.active
    }

    /** The fixture's own UID executes the KSU su path; every byte of the verdict is its own. */
    private fun probeSuCompat(fixture: IBinder): Bundle {
        val request = Parcel.obtain()
        val response = Parcel.obtain()
        try {
            request.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
            assertTrue("the fixture did not answer the KSU su probe",
                fixture.transact(IBinder.FIRST_CALL_TRANSACTION + 8, request, response, 0))
            response.readException()
            return requireNotNull(response.readTypedObject(Bundle.CREATOR)) {
                "the fixture returned no su verdict"
            }
        } finally {
            request.recycle()
            response.recycle()
        }
    }

    /**
     * The domain half of the KSU su verdict: the fixture's own UID runs
     * `/system/bin/su -c '/system/bin/id -u; cat /proc/self/attr/current'` (fixture
     * transaction +9), so the uid **and** the SELinux domain come from the same child.
     * Never throws.
     */
    private fun probeSuDomain(fixture: IBinder): JSONObject {
        val request = Parcel.obtain()
        val response = Parcel.obtain()
        try {
            request.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
            if (!fixture.transact(IBinder.FIRST_CALL_TRANSACTION + 9, request, response, 0)) {
                return SuDomainEvidence.notAttempted("ksu/fixture-su", "FIXTURE_TRANSACTION_ABSENT")
            }
            response.readException()
            val result = response.readTypedObject(Bundle.CREATOR)
                ?: return SuDomainEvidence.notAttempted("ksu/fixture-su", "FIXTURE_RETURNED_NOTHING")
            if (!result.getBoolean("started")) {
                return SuDomainEvidence.refused(
                    "ksu/fixture-su",
                    FIXTURE_SU_DOMAIN_COMMAND,
                    result.getString("errnoName") ?: result.getString("exception"),
                    result.getString("message") ?: result.getString("causes"),
                )
            }
            return SuDomainEvidence.fromOutput(
                label = "ksu/fixture-su",
                command = FIXTURE_SU_DOMAIN_COMMAND,
                executed = "/system/bin/su -c \"" + FIXTURE_SU_DOMAIN_COMMAND + "\"",
                stdout = text(result.getByteArray("stdout")),
                rc = if (result.getBoolean("finished")) result.getInt("code", -1) else -1,
                stderr = text(result.getByteArray("stderr")),
                runner = "NativeSuProbe.suDomain (fixture transaction +9) from the test " +
                    "APK's own UID",
                callerUid = result.getInt("uid", -1),
            )
        } catch (error: Throwable) {
            return SuDomainEvidence.notAttempted("ksu/fixture-su", "HARNESS:" + error)
        } finally {
            request.recycle()
            response.recycle()
        }
    }

    /**
     * Writes the aggregated su-domain node plus the two flat fields a grep can find:
     * `suDomainToken` (`SU_DOMAIN_UNEXPECTED:<domain>`) and `suDomainUnexpected`.
     */
    private fun putSuDomain(document: JSONObject, vararg probes: Pair<String, JSONObject?>) {
        val summary = SuDomainEvidence.summary(*probes)
        val token = if (summary.isNull("unexpectedToken")) null
        else summary.optString("unexpectedToken").takeIf { it.isNotEmpty() }
        document.put("suDomain", summary)
        document.put("suDomainToken", token ?: JSONObject.NULL)
        document.put("suDomainUnexpected", token != null)
    }

    private fun describeSu(value: Bundle): JSONObject = JSONObject().apply {
        val out = text(value.getByteArray("stdout"))
        put("fixtureUid", value.getInt("uid", -1))
        put("path", value.getString("path") ?: JSONObject.NULL)
        put("started", value.getBoolean("started"))
        put("finished", value.getBoolean("finished"))
        put("code", value.getInt("code", -1))
        put("stdout", out)
        put("stderr", text(value.getByteArray("stderr")))
        put("exception", value.getString("exception") ?: JSONObject.NULL)
        put("message", value.getString("message") ?: JSONObject.NULL)
        if (value.containsKey("errno")) put("errno", value.getInt("errno")) else put("errno", JSONObject.NULL)
        put("errnoName", value.getString("errnoName") ?: JSONObject.NULL)
        put("causes", value.getString("causes") ?: JSONObject.NULL)
        put("uidZero", value.getBoolean("started") && value.getBoolean("finished") &&
            value.getInt("code", -1) == 0 && out.trim() == "0")
    }

    /**
     * The explicit denial code for a refused run. A refusal is either the exec itself
     * failing (`ENOENT` when no `/system/bin/su` exists and the kernel did not redirect)
     * or a started process that did not answer `0`.
     */
    private fun denialCode(value: Bundle, described: JSONObject): String {
        if (!value.getBoolean("started")) {
            val errno = value.getString("errnoName")
            val exception = value.getString("exception")
            return "EXEC_FAILED:" + (errno ?: exception ?: "unknown")
        }
        if (!value.getBoolean("finished")) return "TIMEOUT"
        if (described.optBoolean("uidZero")) return "NOT_DENIED"
        val stderr = text(value.getByteArray("stderr")).trim().lineSequence().firstOrNull().orEmpty()
        return "EXIT_" + value.getInt("code", -1) + (if (stderr.isEmpty()) "" else ":" + stderr.take(120))
    }

    private fun <T> withFixture(action: (IBinder) -> T): T {
        val ready = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                ready.complete(binder)
            }

            override fun onServiceDisconnected(name: ComponentName) = Unit
        }
        val intent = Intent()
            .setComponent(ComponentName(fixturePackage, IdentityProbeService::class.java.name))
            .addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
        assertTrue("could not bind the fixture",
            context.bindService(intent, Context.BIND_AUTO_CREATE, context.mainExecutor, connection))
        try {
            return action(ready.get(15, TimeUnit.SECONDS))
        } finally {
            runCatching { context.unbindService(connection) }
        }
    }

    /**
     * Writes one entry of the **Manager's KSU superuser list**: read the current profile
     * and change only `allowSu`, exactly as `KsuSuperuserAdapterImpl.setAllow` does, so a
     * per-app configuration is not overwritten by defaults.
     */
    private fun setKsuAllow(uid: Int, allow: Boolean): Boolean {
        val current = runCatching { Natives.getAppProfile(fixturePackage, uid) }.getOrNull()
        val profile = (current ?: Natives.Profile(fixturePackage, uid)).copy(
            name = fixturePackage,
            currentUid = uid,
            allowSu = allow,
        )
        return runCatching { Natives.setAppProfile(profile) }.getOrDefault(false)
    }

    private fun ksuAllow(uid: Int): Boolean? =
        runCatching { Natives.getAppProfile(fixturePackage, uid)?.allowSu }.getOrNull()

    @Test fun thirdPartyGetsUidZero() {
        /*
         * Process liveness first, and recorded: **no Activity is started**
         * (`foreground.mode=DISABLED_BY_DEFAULT`). On 2026-10-31 launching MainActivity
         * from this process was followed by `wm_finish_activity ... proc died without
         * state saved` before `prepareHook`; the only keep-alive left is the platform
         * doze exemption, which does not touch the target process. Both requests are best
         * effort: a non-zero rc is evidence, not a failure.
         */
        val runStartedAtMillis = System.currentTimeMillis()
        val foreground = ForegroundSession.activate(context)
        val deviceIdle = DeviceIdlePolicy.apply(context)
        val document = JSONObject()
        document.put("schema", 1)
        document.put("test", "thirdPartyGetsUidZero")
        document.put("recordedAtMillis", System.currentTimeMillis())
        document.put("foreground", foreground.evidence())
        document.put("deviceIdle", deviceIdle)
        /*
         * Orchestration facts, recorded before anything runs. This class is the
         * *consumer* of a KSU boot that a late-load + soft-reboot produced; it must not
         * initiate a late-load, a mode switch or a DirtyFrag attempt itself. The only
         * mode call it makes is ModeBootstrap.start(), which is the app's own
         * detection entry (phase one: no root, no switch, no late-load) and is
         * idempotent with Application.onCreate.
         */
        val bootBefore = bootId()
        val attemptBefore = runCatching { JailbreakStatus.read(context) }.getOrNull()
        document.put("bootId", bootBefore ?: JSONObject.NULL)
        document.put("orchestration", JSONObject()
            .put("policy", SAME_BOOT_POLICY)
            .put("lateLoadInitiatedByTest", false)
            .put("attemptInitiatedByTest", false)
            .put("modeBootstrap", "ModeBootstrap.start() = local mode detection only; " +
                "it never performs a late-load, soft-reboot or kernel attempt")
            .put("hookAttemptBefore", attemptSnapshot(attemptBefore)))

        val fixture = fixtureUid()
        val manager = context.applicationInfo.uid
        assertTrue("the fixture must not be the Manager", manager != fixture)
        document.put("fixturePackage", fixturePackage)
        document.put("fixtureUid", fixture)
        document.put("managerUid", manager)

        /* Everything an ordinary app can see about the KSU entry, recorded, never asserted. */
        val preconditions = JSONObject()
        preconditions.put("enforcing", shell("getenforce").trim())
        preconditions.put("kernelRelease", shell("uname -r").trim())
        preconditions.put("systemSu", JSONObject()
            .put("path", "/system/bin/su")
            .put("exists", File("/system/bin/su").exists())
            .put("executable", File("/system/bin/su").canExecute()))
        preconditions.put("ksud", JSONObject()
            .put("path", "/data/adb/ksud")
            .put("exists", File("/data/adb/ksud").exists())
            .put("shell", shell(
                "ls -ld /data/adb/ksud /data/adb/ksu /data/adb/ksu/.allowlist 2>&1; echo rc=$?").trim()))
        document.put("preconditions", preconditions)

        /*
         * The su **domain** question, asked from the shell UID before the allowlist is
         * touched: `su -c 'id -u; cat /proc/self/attr/current'`. Bounded (a su that waits
         * for an approval dialog is recorded as a timeout) and never fatal.
         */
        val shellDomain = SuDomainEvidence.probeShell("ksu/shell")
        document.put("suDomainShell", shellDomain)

        runCatching { ModeBootstrap.start(context) }
        val mode = waitForMode(25_000)
        document.put("modeRuntimeActive", mode?.name ?: JSONObject.NULL)
        /* The activation carries its bootId and source, i.e. "which boot decided KSU". */
        document.put("modeActivation", ModeRuntime.activation.toString())
        val ksu = KsuBackends.natives()
        document.put("ksuBackend", JSONObject()
            .put("available", ksu.available)
            .put("loadError", KsuBackends.nativeLoadError() ?: JSONObject.NULL)
            .put("version", ksu.version)
            .put("isManager", ksu.isManager)
            .put("kernelUAPIVersion", ksu.kernelUAPIVersion)
            .put("suEnabled", runCatching { ksu.isSuEnabled() }.getOrNull()))

        val reason = when {
            mode != WorkMode.KSU -> "MODE_NOT_KSU:" + (mode?.name ?: "UNRESOLVED")
            !ksu.available -> "KSU_NATIVE_UNAVAILABLE:" + (KsuBackends.nativeLoadError() ?: "unknown")
            !ksu.isManager -> "NOT_KSU_MANAGER"
            else -> null
        }
        if (reason != null) {
            val skipCode = "KSU_THIRD_PARTY_SU_SKIPPED:" + reason
            document.put("applicable", false)
            document.put("skipCode", reason)
            document.put("failure", skipCode)
            val bootAfter = bootId()
            val attemptAfter = runCatching { JailbreakStatus.read(context) }.getOrNull()
            document.put("orchestration", orchestrationJson(
                attemptBefore, attemptAfter, bootBefore, bootAfter))
            foreground.finish()
            document.put("foreground", foreground.evidence())
            document.put("processKill",
                ProcessKillEvidence.collect(context, "ksu-thirdparty", runStartedAtMillis))
            document.put("logcat", LogcatEvidence.collect(context, "ksu-thirdparty"))
            putSuDomain(document, "shell" to shellDomain)
            write(document)
            android.util.Log.w("MapleSU", tag + "_SKIPPED " + skipCode)
            assumeTrue("not a Normal (KSU) boot: " + reason, false)
            return
        }
        document.put("applicable", true)

        val originalProfile = runCatching { Natives.getAppProfile(fixturePackage, fixture) }.getOrNull()
        val originalKsuAllow = ksuAllow(fixture)
        val originalUltra = runCatching { JailbreakGrantStore.hasGrant(context, fixture) }.getOrDefault(false)
        val originalSuSwitch = runCatching { Natives.isSuEnabled() }.getOrDefault(false)
        document.put("original", JSONObject()
            .put("ksuAllow", originalKsuAllow ?: JSONObject.NULL)
            .put("ultraGrant", originalUltra)
            .put("suEnabled", originalSuSwitch)
            .put("profileName", originalProfile?.name ?: JSONObject.NULL))

        var grantedRun: JSONObject? = null
        var deniedRun: JSONObject? = null
        var denial: String? = null
        /** The fixture-UID su domain probe (uid + SELinux domain from one invocation). */
        var fixtureDomain: JSONObject? = null
        var ksuGrantReadback = false
        var ultraSeesKsuGrant = false
        var ksuSeesUltraGrant = false
        var cooperativeSeesKsuGrant: Boolean? = null
        var cooperativeGranted: Boolean? = null
        try {
            /* The feature switch is part of the KSU entry; record it and turn it on for the test. */
            if (!originalSuSwitch) {
                document.put("suSwitchWritten", Natives.setSuEnabled(true))
            }
            document.put("suEnabledForRun", runCatching { Natives.isSuEnabled() }.getOrNull())

            /* Baseline: neither list contains the fixture. */
            JailbreakGrantStore.revoke(context, fixture)
            val baselineKsuWritten = setKsuAllow(fixture, false)
            document.put("baseline", JSONObject()
                .put("ksuAllowWritten", baselineKsuWritten)
                .put("ksuAllow", ksuAllow(fixture) ?: JSONObject.NULL)
                .put("ultraGrant", JailbreakGrantStore.hasGrant(context, fixture)))

            /* 1) Granted in the KSU list: the third party must become UID 0. */
            val grantedWritten = setKsuAllow(fixture, true)
            ksuGrantReadback = ksuAllow(fixture) == true
            document.put("ksuGrant", JSONObject()
                .put("written", grantedWritten)
                .put("readback", ksuGrantReadback))
            ultraSeesKsuGrant = runCatching { JailbreakGrantStore.hasGrant(context, fixture) }
                .getOrDefault(false)
            cooperativeSeesKsuGrant = runCatching {
                ManagerAuthorizations.policy(context).hasCurrentGrant(fixture)
            }.getOrNull()
            grantedRun = withFixture { fixtureBinder -> describeSu(probeSuCompat(fixtureBinder)) }
            document.put("grantedRun", grantedRun)
            document.put("grantedUidZero", grantedRun?.optBoolean("uidZero") == true)

            /*
             * 1b) The domain half, while the kernel allowlist still contains the fixture:
             *     the same real `su` exec, with a command that prints uid AND SELinux
             *     domain (fixture transaction +9). "uid 0" without this is not working
             *     root: an untrusted_app-domain child cannot search the daemon directory.
             */
            fixtureDomain = withFixture { fixtureBinder -> probeSuDomain(fixtureBinder) }
            document.put("suDomainFixture", fixtureDomain)

            /* 2) Granted in the Ultra list but revoked in the KSU list: must be refused. */
            setKsuAllow(fixture, false)
            JailbreakGrantStore.grant(context, fixture)
            ksuSeesUltraGrant = ksuAllow(fixture) == true
            cooperativeGranted = runCatching {
                ManagerAuthorizations.policy(context).hasCurrentGrant(fixture)
            }.getOrNull()
            val revoked = withFixture { fixtureBinder -> probeSuCompat(fixtureBinder) }
            val denied = describeSu(revoked)
            deniedRun = denied
            denial = denialCode(revoked, denied)
            document.put("deniedRun", denied)
            document.put("deniedCode", denial)

            /*
             * 3) Record what the *other* two entries would say for the same app. This is
             *    diagnostic only: it must never be allowed to decide this test's verdict.
             */
            val endpointPublished = runCatching {
                NativeSuDiscovery.peek(context.applicationInfo.uid)?.isBinderAlive == true
            }.getOrDefault(false)
            document.put("cooperativeEntry", JSONObject()
                .put("publishedEndpoint", endpointPublished)
                .put("listSource", "RootAuthorizationStore /data/adb/maplesu/authorization/<uid>/authorizations.bin")
                .put("granted", cooperativeGranted ?: JSONObject.NULL))
        } finally {
            /* Restore both lists and the feature switch, whatever happened above. */
            runCatching { setKsuAllow(fixture, originalKsuAllow == true) }
            runCatching {
                if (originalUltra) JailbreakGrantStore.grant(context, fixture)
                else JailbreakGrantStore.revoke(context, fixture)
            }
            runCatching { Natives.setSuEnabled(originalSuSwitch) }
            document.put("restored", JSONObject()
                .put("ksuAllow", ksuAllow(fixture) ?: JSONObject.NULL)
                .put("ultraGrant", runCatching { JailbreakGrantStore.hasGrant(context, fixture) }.getOrDefault(false))
                .put("suEnabled", runCatching { Natives.isSuEnabled() }.getOrNull()))
        }

        /*
         * The verdict: both directions are measured, so "same list" is not a claim.
         * A KSU grant is invisible to the Ultra store, and an Ultra grant is invisible
         * to the KSU store - unless a future change really does unify them.
         */
        val sameListAsUltra = ultraSeesKsuGrant && ksuSeesUltraGrant
        val authorization = JSONObject()
            .put("listSource", "KSU_APP_PROFILE / kernel allowlist " +
                "(Natives.getAppProfile/setAppProfile -> libmaplesu_ksu.so -> supercall)")
            .put("ksuListWriter", "KsuSuperuserAdapter.setAllow / Natives.setAppProfile " +
                "(Normal superuser surface; KsuSuperuserBackend.kt:83-88, Natives.kt:149-155)")
            .put("ultraListSource", "JailbreakGrantStore " +
                "(filesDir/jailbreak-grants.json; read by JailbreakSuEndpoint.kt:53)")
            .put("ultraListWriter", "none in production: only the test and " +
                "JailbreakLeaseProxy.grant (IRootManagementService, no production caller) write it; " +
                "the LITE UI writes DirectPolicy instead")
            .put("cooperativeListSource", "RootAuthorizationStore " +
                "/data/adb/maplesu/authorization/<managerUid>/authorizations.bin " +
                "(NativeSuDaemonService.kt:23; written by ManagerAuthorizations.saveProfile)")
            .put("cooperativeListWriter", "ManagerAuthorizations.saveProfile / DirectPolicy " +
                "(LITE superuser surface; ManagerAuthorizations.kt:95-96)")
            .put("granted", ksuGrantReadback)
            .put("ultraSeesKsuGrant", ultraSeesKsuGrant)
            .put("ksuSeesUltraGrant", ksuSeesUltraGrant)
            .put("sameListAsUltra", sameListAsUltra)
            .put("cooperativeSeesKsuGrant", cooperativeSeesKsuGrant ?: JSONObject.NULL)
            .put("sameListAsCooperative", ksuGrantReadback && cooperativeSeesKsuGrant == true)
            .put("deniedCode", denial ?: JSONObject.NULL)
            .put("deniedCodeSemantics", "KSU sucompat has no refusal token: a uid outside the " +
                "kernel allowlist is not intercepted, so the exec fails with errno (ENOENT when " +
                "no /system/bin/su file exists). The product's own endpoints return " +
                "AUTH_DENIED/AUTH_DISABLED instead, on their own lists.")
            .put("cooperativeGranted", cooperativeGranted ?: JSONObject.NULL)
        document.put("authorization", authorization)

        /* Classify before asserting; the reason is written to disk first. */
        val grantedUidZero = grantedRun?.optBoolean("uidZero") == true
        val deniedUidZero = deniedRun?.optBoolean("uidZero") == true
        var failure = when {
            grantedUidZero && !deniedUidZero -> null
            !grantedUidZero -> notWired + ":SUCOMPAT_DID_NOT_GRANT:" + grantFailureReason(grantedRun)
            else -> notWired + ":REVOKED_GRANT_STILL_GRANTED:" + denial
        }
        /*
         * Orchestration assertions for this boot: the KSU verdict is only meaningful on
         * the boot the installer produced (late-load + soft-reboot), and this class must
         * not have created a DirtyFrag attempt. Both are facts read back after the
         * probes, so a crash-heavy run still shows which assumption broke.
         */
        val bootAfter = bootId()
        val attemptAfter = runCatching { JailbreakStatus.read(context) }.getOrNull()
        val attemptIdBefore = attemptBefore?.attemptId
        val attemptIdAfter = attemptAfter?.attemptId
        val secondAttempt = attemptIdBefore != attemptIdAfter
        val bootUnchanged = bootBefore == null || bootAfter == null || bootBefore == bootAfter
        if (failure == null && secondAttempt) {
            failure = notWired + ":ORCHESTRATION_SECOND_ATTEMPT:" +
                (attemptIdBefore ?: "none") + "->" + (attemptIdAfter ?: "none")
        }
        if (failure == null && !bootUnchanged) {
            failure = notWired + ":BOOT_CHANGED_DURING_RUN:" + bootBefore + "->" + bootAfter
        }
        document.put("orchestration",
            orchestrationJson(attemptBefore, attemptAfter, bootBefore, bootAfter))
        document.put("bootBefore", bootBefore ?: JSONObject.NULL)
        document.put("bootAfter", bootAfter ?: JSONObject.NULL)
        document.put("bootUnchanged", bootUnchanged)
        /*
         * Process liveness, closed on the way out: finish the foreground handle (with
         * mode=DISABLED_BY_DEFAULT there is nothing to finish), then read what the
         * platform logged about this package's processes dying. This class creates no
         * attempt, so there is no attempt pid to attribute against; only a reclaim
         * **inside this run's window** is allowed to explain a failure, and it is named as
         * a system kill instead of being reported as "not wired".
         */
        foreground.finish()
        val processKill = ProcessKillEvidence.collect(
            context, "ksu-thirdparty", runStartedAtMillis)
        val killLine = ProcessKillEvidence.systemKillLine(
            processKill, emptySet<Int>(), runStartedAtMillis)
        val failureBeforeKill = failure
        if (failure != null && killLine != null) {
            failure = notWired + ":" + ProcessKillEvidence.token(killLine)
        }
        document.put("foreground", foreground.evidence())
        document.put("processKill", processKill)
        document.put("processKillAttribution", JSONObject()
            .put("attributedLine", killLine ?: JSONObject.NULL)
            .put("failureBeforeKill", failureBeforeKill ?: JSONObject.NULL)
            .put("failureReplaced", failure != failureBeforeKill)
            .put("basis", "this class creates no attempt, so only an am_kill of this " +
                "package inside this run's window (timestamp >= sinceMillis) is attributed"))
        document.put("logcat", LogcatEvidence.collect(context, "ksu-thirdparty"))
        putSuDomain(document, "fixtureSu" to fixtureDomain, "shell" to shellDomain)
        document.put("failure", failure ?: JSONObject.NULL)
        write(document)

        if (failure != null) {
            fail(failure + " granted=" + grantedRun + " denied=" + deniedRun +
                " ksu=" + document.optJSONObject("ksuBackend"))
        }
        assertEquals("the fixture is not a third-party UID", fixture.toLong(),
            (grantedRun?.optInt("fixtureUid", -1) ?: -1).toLong())
        assertTrue("the KSU grant did not read back", authorization.optBoolean("granted"))
        assertTrue("the granted third-party run did not output uid 0: " + grantedRun,
            grantedUidZero)
        assertTrue("the revoked third-party run was not refused (deniedCode=" + denial + ")",
            !deniedUidZero)
    }

    private fun grantFailureReason(value: JSONObject?): String {
        if (value == null) return "NO_RESULT"
        if (!value.optBoolean("started")) {
            return "EXEC_FAILED:" + (value.optString("errnoName").ifEmpty { "unknown" })
        }
        return "EXIT_" + value.optInt("code", -1) +
            (value.optString("stderr").trim().take(80).let { if (it.isEmpty()) "" else ":" + it })
    }

    /** The attempt facts this test is allowed to *read*; it never creates one. */
    private fun attemptSnapshot(status: JailbreakStatus?): JSONObject {
        if (status == null) return JSONObject().put("present", false)
        return JSONObject()
            .put("present", true)
            .put("attemptId", status.attemptId ?: JSONObject.NULL)
            .put("bootId", status.bootId ?: JSONObject.NULL)
            .put("method", status.method)
            .put("stage", status.stage)
            .put("rootBackend", status.rootBackend ?: JSONObject.NULL)
            .put("failure", status.failure ?: JSONObject.NULL)
            .put("ownerPid", status.ownerPid ?: JSONObject.NULL)
    }

    /**
     * The same-boot / no-second-attempt record written in every path of this class.
     * `lateLoadInitiatedByTest` and `attemptInitiatedByTest` are `false` by
     * construction: there is no late-load/soft-reboot call and no
     * `NativeSuDaemon.prepareHook`/`management` call in this file.
     */
    private fun orchestrationJson(
        before: JailbreakStatus?,
        after: JailbreakStatus?,
        bootBefore: String?,
        bootAfter: String?,
    ): JSONObject {
        val idBefore = before?.attemptId
        val idAfter = after?.attemptId
        return JSONObject()
            .put("policy", SAME_BOOT_POLICY)
            .put("lateLoadInitiatedByTest", false)
            .put("attemptInitiatedByTest", false)
            .put("modeBootstrap", "ModeBootstrap.start() = local mode detection only; " +
                "it never performs a late-load, soft-reboot or kernel attempt")
            .put("hookAttemptBefore", attemptSnapshot(before))
            .put("hookAttemptAfter", attemptSnapshot(after))
            .put("attemptIdBefore", idBefore ?: JSONObject.NULL)
            .put("attemptIdAfter", idAfter ?: JSONObject.NULL)
            .put("attemptIdStable", idBefore == idAfter)
            .put("secondAttemptDetected", idBefore != idAfter)
            .put("bootBefore", bootBefore ?: JSONObject.NULL)
            .put("bootAfter", bootAfter ?: JSONObject.NULL)
            .put("bootUnchanged", bootBefore == null || bootAfter == null || bootBefore == bootAfter)
    }

    private companion object {
        /**
         * What this class may and may not do on the KSU line.
         */
        const val SAME_BOOT_POLICY =
            "run only in the same boot that the installer's KSU late-load + soft-reboot " +
                "produced (MODE==KSU). This test never initiates a late-load/soft-reboot, " +
                "never calls NativeSuDaemon.prepareHook or management(), and never writes " +
                "the hook attempt: it only reads MODE, drives the KSU allowlist through " +
                "Natives.setAppProfile, and has the fixture exec /system/bin/su through " +
                "the KSU sucompat hook. A non-KSU boot is skipped with an explicit code; " +
                "a changed attempt id during the run is a failure."

        /**
         * The command the fixture runs through the real su binary: uid and SELinux domain
         * of the same child, so "uid 0" can be told apart from working root.
         */
        const val FIXTURE_SU_DOMAIN_COMMAND = SuDomainEvidence.FIXTURE_COMMAND
    }
}
