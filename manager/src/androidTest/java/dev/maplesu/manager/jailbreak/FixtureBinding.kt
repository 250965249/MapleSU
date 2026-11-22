package dev.maplesu.manager.jailbreak

import android.app.Instrumentation
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The test APK's `IdentityProbeService`: a real Binder caller in **another process and
 * another Linux UID** than the Manager. Every third-party-su scenario needs exactly such
 * a caller, because `Binder.getCallingUid()` inside the published entry is the only
 * identity the authorization decision can see.
 *
 * <p>**androidTest only.** Nothing here is reachable from `main`.
 *
 * <p>## Why this class exists (2026-10-31, third pass)
 *
 * <p>The previous helper did (verbatim, before this file):
 *
 * ```kotlin
 * val boundOk = context.bindService(intent, connection, Context.BIND_AUTO_CREATE)
 * assertTrue("the identity fixture did not bind", boundOk)
 * return action(ready.get(10, TimeUnit.SECONDS))
 * ```
 *
 * <p>and the device answered `threw=AssertionError: the identity fixture did not bind`
 * three times (`.analysis/ultra3p7-132937/evidence.json`, `trials[A/B/C].threw`), which
 * then surfaced as
 * `suDomain.probes.*.token=SU_DOMAIN_UNAVAILABLE:HARNESS:AssertionError: the identity
 * fixture did not bind`. That assertion threw away every fact needed to explain the
 * refusal:
 *
 *  - the bind return value was not recorded (only the assertion message survived);
 *  - no `ServiceConnection` callback was ever recorded, so "bind returned false" was
 *    indistinguishable from "bound but never connected";
 *  - the component's `exported`/`enabled`/`process`, the package's UID, signatures,
 *    test-only/stopped flags and the Manager's package visibility were never inspected;
 *  - the AMS sentence that explains a refused bind (`Unable to start service ... not
 *    found`, `Permission Denial`, `not exported`, ...) was never read - and the `sh -c`
 *    shell path that could have read it was itself broken on this platform.
 *
 * <p>So this class: (a) inspects the package/service **before** binding, (b) tries the
 * bind shapes this codebase actually uses (the plain overload that failed, the
 * `Executor` overload the other fixture tests use, a bind after a shell `am startservice`
 * of the fixture process, and the test-APK op-package variant), (c) waits for
 * `onServiceConnected` with an explicit 12 s deadline while recording every callback,
 * (d) records the real exception (class + message, including a `SecurityException`
 * from a calling-package/UID mismatch), and (e) on failure collects the AMS/logcat/
 * `dumpsys package` facts through [InstrumentationShell]. It **never throws**: a failure
 * is a typed [error] plus [diagnostics] that the caller writes into the evidence
 * document instead of a bare `AssertionError`.
 */
internal class FixtureBinding private constructor(
    val servicePackage: String,
    val serviceUid: Int,
    val managerUid: Int,
    private val diagnostics: JSONObject,
) {
    /** True only after `onServiceConnected` delivered a live binder. */
    var bound: Boolean = false
        private set

    /** The fixture's binder, valid only while [bound]. */
    var binder: IBinder? = null
        private set

    /** End-to-end cost of the successful path (or of the whole failed attempt). */
    var elapsedMillis: Long = 0
        private set

    /** `FIXTURE_NOT_BOUND:<hint>` (or a bind-time exception); null when [bound]. */
    var error: String? = null
        private set

    private val unbinders = ArrayList<Pair<Context, ServiceConnection>>()

    /**
     * The evidence node the tests write as `fixture{...}`:
     * `bound / error / servicePackage / uid / elapsedMillis / diagnostics`.
     */
    fun evidence(): JSONObject = JSONObject()
        .put("bound", bound)
        .put("error", error ?: JSONObject.NULL)
        .put("servicePackage", servicePackage)
        .put("serviceClass", SERVICE_CLASS)
        .put("uid", serviceUid)
        .put("elapsedMillis", elapsedMillis)
        .put("binderAlive", binder?.isBinderAlive ?: false)
        .put("differentUid", serviceUid >= 0 && serviceUid != managerUid)
        .put("diagnostics", diagnostics)

    /** Releases every connection this object owns; safe to call more than once. */
    fun close() {
        for ((caller, connection) in unbinders) {
            runCatching { caller.unbindService(connection) }
        }
        unbinders.clear()
    }

    private fun register(caller: Context, connection: ServiceConnection) {
        unbinders += caller to connection
    }

    private class BindAttempt(val label: String) {
        @Volatile var startedAtMillis: Long = System.currentTimeMillis()
        @Volatile var bindResult = false
        @Volatile var binder: IBinder? = null
        @Volatile var serviceConnected = false
        @Volatile var nullBinding = false
        @Volatile var bindingDied = false
        @Volatile var serviceDisconnected = false
        @Volatile var exception: String? = null
        @Volatile var elapsedMillis = 0L
        @Volatile var connectedAfterMillis = -1L

        private val waitMillis: Long get() = FixtureBinding.WAIT_MILLIS

        val connected = CountDownLatch(1)

        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                binder = service
                serviceConnected = true
                connectedAfterMillis = System.currentTimeMillis() - startedAtMillis
                connected.countDown()
            }

            override fun onServiceDisconnected(name: ComponentName) {
                serviceDisconnected = true
            }

            override fun onNullBinding(name: ComponentName) {
                nullBinding = true
                connected.countDown()
            }

            override fun onBindingDied(name: ComponentName) {
                bindingDied = true
                connected.countDown()
            }
        }

        fun json(): JSONObject = JSONObject()
            .put("strategy", label)
            .put("bindResult", bindResult)
            .put("exception", exception ?: JSONObject.NULL)
            .put("onServiceConnected", serviceConnected)
            .put("onNullBinding", nullBinding)
            .put("onBindingDied", bindingDied)
            .put("onServiceDisconnected", serviceDisconnected)
            .put("binderAlive", binder?.isBinderAlive ?: false)
            .put("connectedAfterMillis", connectedAfterMillis)
            .put("elapsedMillis", elapsedMillis)

        /** Why this attempt produced no binder, in one token. */
        fun failure(): String? = when {
            exception != null -> exception
            !bindResult -> "BIND_RETURNED_FALSE"
            binder != null -> null
            nullBinding -> "ON_NULL_BINDING"
            bindingDied -> "ON_BINDING_DIED"
            else -> "NO_ON_SERVICE_CONNECTED_WITHIN_" + waitMillis + "ms"
        }
    }

    companion object {
        /** The class the test APK declares with `android:exported="true"`. */
        const val SERVICE_CLASS = "dev.maplesu.manager.runtime.IdentityProbeService"

        /** The `onServiceConnected` deadline: 10-15 s, per the harness contract. */
        const val WAIT_MILLIS = 12_000L

        /** The token prefix the tests' `failure` uses. */
        const val ERROR_PREFIX = "FIXTURE_NOT_BOUND:"

        private const val FLAG_DEBUGGABLE = 1 shl 1
        private const val FLAG_TEST_ONLY = 1 shl 8
        private const val FLAG_STOPPED = 1 shl 21

        /** The `fixture{}` node before any bind was attempted (pre-phase record). */
        fun notAttempted(servicePackage: String, serviceUid: Int, reason: String): JSONObject =
            JSONObject()
                .put("bound", false)
                .put("error", ERROR_PREFIX + reason)
                .put("servicePackage", servicePackage)
                .put("serviceClass", SERVICE_CLASS)
                .put("uid", serviceUid)
                .put("elapsedMillis", 0)
                .put("binderAlive", false)
                .put("diagnostics", JSONObject().put("state", reason))

        /**
         * Binds the fixture, or explains why it could not.
         *
         * @param manager the instrumentation's `targetContext` - the Manager process
         *     whose UID must *not* be the caller the fixture impersonates.
         * @param instrumentation the running instrumentation, for its own
         *     `androidTest` context (a different op package).
         */
        fun open(manager: Context, instrumentation: Instrumentation): FixtureBinding {
            val startedAtMillis = System.currentTimeMillis()
            val fixturePackage = instrumentation.context.packageName
            val managerUid = manager.applicationInfo.uid
            val component = ComponentName(fixturePackage, SERVICE_CLASS)
            val uid = runCatching {
                manager.packageManager.getApplicationInfo(fixturePackage, 0).uid
            }.getOrDefault(-1)

            val diagnostics = JSONObject()
                .put("state", "binding")
                .put("servicePackage", fixturePackage)
                .put("serviceClass", SERVICE_CLASS)
                .put("component", component.flattenToShortString())
                .put("managerPackage", manager.packageName)
                .put("managerUid", managerUid)
                .put("fixtureUid", uid)
                .put("differentUid", uid >= 0 && uid != managerUid)
                .put("waitMillis", WAIT_MILLIS)
                .put(
                    "why",
                    "a third-party su verdict needs a Binder caller whose Linux UID is " +
                        "not the Manager's; the test APK's IdentityProbeService is that " +
                        "caller, so a bind failure is a HARNESS result, not a product verdict",
                )

            val binding = FixtureBinding(fixturePackage, uid, managerUid, diagnostics)
            val inspected = inspect(manager, fixturePackage, component)
            diagnostics.put("package", inspected)

            val attempts = JSONArray()
            val strategies = listOf(
                "targetContext.bindService(intent, connection, BIND_AUTO_CREATE)",
                "targetContext.bindService(intent, BIND_AUTO_CREATE, mainExecutor, connection)",
            )
            for ((index, label) in strategies.withIndex()) {
                if (binding.binder != null) break
                binding.bind(manager, component, useExecutor = index == 1, label = label, attempts = attempts)
            }
            /*
             * If both direct binds were refused, ask the shell to start the fixture's
             * process (`:identity_probe`) by name and try again. A refusal is recorded
             * with its own message: it is the difference between "AMS cannot resolve the
             * component" (the bind is refused for everybody) and "the process could not
             * be created" (the bind is refused because starting it failed).
             */
            if (binding.binder == null) {
                val started = InstrumentationShell.run(
                    "am startservice -n " + component.flattenToShortString(),
                )
                diagnostics.put("shellStartService", started)
                binding.bind(
                    manager,
                    component,
                    useExecutor = false,
                    label = "targetContext.bindService(...) after `am startservice`",
                    attempts = attempts,
                )
            }
            /*
             * The test APK's own op package. This is known to be able to fail with a
             * calling-package/UID mismatch (the code runs in the *target* process, so the
             * real UID is the Manager's while `getOpPackageName()` is the test package);
             * the refusal itself is evidence and is kept.
             */
            if (binding.binder == null) {
                binding.bind(
                    instrumentation.context,
                    component,
                    useExecutor = false,
                    label = "instrumentation.context.bindService(...) (op package = test APK)",
                    attempts = attempts,
                )
            }
            diagnostics.put("attempts", attempts)

            if (binding.binder != null && binding.binder?.isBinderAlive == true) {
                binding.bound = true
                binding.elapsedMillis = System.currentTimeMillis() - startedAtMillis
                diagnostics.put("state", "bound")
                return binding
            }

            val shell = failureDiagnostics(fixturePackage)
            diagnostics.put("shell", shell)
            val hint = hintOf(inspected, shell)
            diagnostics.put("hint", hint)
            diagnostics.put("hypotheses", hypotheses(inspected, hint))
            diagnostics.put("state", "not_bound")
            val firstFailure = (0 until attempts.length())
                .mapNotNull { attempts.optJSONObject(it) }
                .firstOrNull { it.optString("exception").isNotEmpty() || !it.optBoolean("bindResult") }
                ?.let { it.optString("exception").takeIf { value -> value.isNotEmpty() }
                    ?: it.optString("strategy") + ":bind=false" }
            diagnostics.put("firstFailure", firstFailure ?: JSONObject.NULL)
            binding.error = ERROR_PREFIX + hint +
                (if (firstFailure == null) ":bind=false" else ":bind=false:" + firstFailure)
            binding.elapsedMillis = System.currentTimeMillis() - startedAtMillis
            return binding
        }

        /**
         * One bind + bounded wait. Registers the connection before waiting, so a bind
         * that returned true but never called back is still released by [close].
         */
        private fun FixtureBinding.bind(
            caller: Context,
            component: ComponentName,
            useExecutor: Boolean,
            label: String,
            attempts: JSONArray,
        ) {
            val attempt = BindAttempt(label)
            val intent = Intent()
                .setComponent(component)
                .addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
            attempt.startedAtMillis = System.currentTimeMillis()
            try {
                attempt.bindResult = if (useExecutor) {
                    caller.bindService(
                        intent, Context.BIND_AUTO_CREATE, caller.mainExecutor, attempt.connection,
                    )
                } else {
                    caller.bindService(intent, attempt.connection, Context.BIND_AUTO_CREATE)
                }
            } catch (error: Throwable) {
                attempt.exception = describe(error)
            }
            if (attempt.bindResult) {
                register(caller, attempt.connection)
                try {
                    attempt.connected.await(WAIT_MILLIS, TimeUnit.MILLISECONDS)
                } catch (interrupted: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
            attempt.elapsedMillis = System.currentTimeMillis() - attempt.startedAtMillis
            if (attempt.binder == null) {
                attempt.exception = attempt.exception ?: attempt.failure()
            }
            attempts.put(attempt.json())
            if (attempt.binder != null) {
                binder = attempt.binder
            }
        }

        /** Everything `PackageManager` can say about the component, before any bind. */
        @Suppress("DEPRECATION")
        private fun inspect(
            manager: Context,
            fixturePackage: String,
            component: ComponentName,
        ): JSONObject {
            val record = JSONObject()
            val packageManager = manager.packageManager
            runCatching { packageManager.getApplicationInfo(fixturePackage, 0) }
                .onSuccess { info ->
                    record.put("packageResolved", true)
                        .put("packageVisible", true)
                        .put("uid", info.uid)
                        .put("flags", "0x" + Integer.toHexString(info.flags))
                        .put("testOnly", (info.flags and FLAG_TEST_ONLY) != 0)
                        .put("stopped", (info.flags and FLAG_STOPPED) != 0)
                        .put("debuggable", (info.flags and FLAG_DEBUGGABLE) != 0)
                        .put("enabled", info.enabled)
                        .put("targetSdk", info.targetSdkVersion)
                        .put("sourceDir", info.sourceDir)
                }
                .onFailure {
                    record.put("packageResolved", false)
                        .put("packageVisible", false)
                        .put("packageError", describe(it))
                }
            runCatching { packageManager.getServiceInfo(component, 0) }
                .onSuccess { info ->
                    record.put("serviceResolved", true)
                        .put("exported", info.exported)
                        .put("serviceEnabled", info.enabled)
                        .put("processName", info.processName)
                        .put("permission", info.permission ?: JSONObject.NULL)
                }
                .onFailure {
                    record.put("serviceResolved", false)
                        .put("serviceError", describe(it))
                }
            record.put("signature", runCatching {
                when (packageManager.checkSignatures(manager.packageName, fixturePackage)) {
                    PackageManager.SIGNATURE_MATCH -> "SIGNATURE_MATCH"
                    PackageManager.SIGNATURE_NEITHER_SIGNED -> "SIGNATURE_NEITHER_SIGNED"
                    PackageManager.SIGNATURE_FIRST_NOT_SIGNED -> "SIGNATURE_FIRST_NOT_SIGNED"
                    PackageManager.SIGNATURE_SECOND_NOT_SIGNED -> "SIGNATURE_SECOND_NOT_SIGNED"
                    PackageManager.SIGNATURE_NO_MATCH -> "SIGNATURE_NO_MATCH"
                    PackageManager.SIGNATURE_UNKNOWN_PACKAGE -> "SIGNATURE_UNKNOWN_PACKAGE"
                    else -> "UNKNOWN"
                }
            }.getOrElse { describe(it) })
            record.put("managerQueriesAllPackages", runCatching {
                packageManager.checkPermission(
                    "android.permission.QUERY_ALL_PACKAGES", manager.packageName,
                ) == PackageManager.PERMISSION_GRANTED
            }.getOrDefault(false))
            return record
        }

        /**
         * The facts only the platform can produce: whether the fixture process exists,
         * how the package is installed, and what AMS wrote when it refused the bind.
         */
        private fun failureDiagnostics(fixturePackage: String): JSONObject {
            val process = fixturePackage + ":identity_probe"
            return JSONObject()
                .put("fixturePid", InstrumentationShell.run("pidof " + process))
                .put(
                    "processList",
                    InstrumentationShell.run(
                        "ps -A -o USER,PID,NAME | grep -E 'identity_probe|" +
                            "maplesu\\.manager\\.test' | grep -v grep",
                    ),
                )
                .put("packages", InstrumentationShell.run("pm list packages | grep -i maplesu"))
                .put(
                    "packageDump",
                    InstrumentationShell.run(
                        "dumpsys package " + fixturePackage +
                            " | grep -E 'userId=|flags=|enabled=|stopped=|installerPackageName='",
                    ),
                )
                .put(
                    "amsLog",
                    InstrumentationShell.run(
                        "logcat -d -b system -t 800 | grep -i -E " +
                            "'Unable to start service|Permission Denial|not found|not exported|" +
                            fixturePackage + "|IdentityProbeService' | tail -n 80",
                    ),
                )
                .put(
                    "mainLog",
                    InstrumentationShell.run(
                        "logcat -d -b main -t 800 | grep -i -E " +
                            "'bindService|" + fixturePackage +
                            "|IdentityProbeService' | tail -n 80",
                    ),
                )
        }

        /** The single most likely reason, phrased as a token the tests can grep. */
        private fun hintOf(inspected: JSONObject, shell: JSONObject): String {
            val log = listOf("amsLog", "mainLog").joinToString("\n") { name ->
                shell.optJSONObject(name)?.optString("output").orEmpty()
            }.lowercase(Locale.US)
            return when {
                log.contains("permission denial") -> "AMS_PERMISSION_DENIAL"
                log.contains("does not belong to") -> "CALLING_PACKAGE_UID_MISMATCH"
                log.contains("not exported") -> "SERVICE_NOT_EXPORTED"
                log.contains("test-only") || log.contains("testonly") -> "TEST_ONLY_PACKAGE"
                log.contains("background start not allowed") -> "BACKGROUND_START_REFUSED"
                log.contains("unable to start service") || log.contains("not found") ->
                    "AMS_SERVICE_NOT_FOUND"
                inspected.optBoolean("stopped") -> "STOPPED_PACKAGE"
                !inspected.optBoolean("packageVisible", true) -> "PACKAGE_NOT_VISIBLE"
                !inspected.optBoolean("serviceResolved", true) -> "SERVICE_NOT_DECLARED"
                inspected.optString("signature") != "SIGNATURE_MATCH" -> "SIGNATURE_MISMATCH"
                inspected.optBoolean("testOnly") -> "TEST_ONLY_PACKAGE"
                else -> "BIND_RETURNED_FALSE"
            }
        }

        /** What to do about [hintOf]'s answer, in the record itself. */
        private fun hypotheses(inspected: JSONObject, hint: String): JSONArray = JSONArray().apply {
            put("hint=" + hint)
            if (inspected.optBoolean("testOnly")) {
                put(
                    "the test APK is installed test-only (ApplicationInfo.FLAG_TEST_ONLY): " +
                        "AMS may refuse to spawn a component process for a caller that is " +
                        "not the instrumentation itself. Reinstall the test APK without " +
                        "`-t` (that is what marks it) or move the peer to a normal app",
                )
            }
            if (!inspected.optBoolean("packageVisible", true)) {
                put(
                    "the Manager's PackageManager cannot see the fixture package: " +
                        "QUERY_ALL_PACKAGES must be declared in the *main* manifest and " +
                        "granted at install (main is out of scope for this change)",
                )
            }
            if (inspected.optBoolean("stopped")) {
                put("the fixture package is in the stopped state; `am startservice`/`am instrument` clears it")
            }
            if (inspected.optString("signature") != "SIGNATURE_MATCH") {
                put("the Manager and the fixture are not signed by the same certificate")
            }
            put(
                "read diagnostics.shell.amsLog first: it carries the AMS sentence that " +
                    "explains the refusal ('not found', 'Permission Denial', 'not exported')",
            )
        }
    }
}
