package dev.maplesu.manager.jailbreak

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.JailbreakGrantStore
import dev.maplesu.manager.runtime.NativeSuDaemon
import dev.maplesu.manager.runtime.NativeSuDiscovery
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/**
 * E2/E3 on one provider activation.
 *
 * <p>The review's E2 pass condition is a single activation that then serves: (a) an
 * ordinary third party reaching the **published restricted su entry and executing**,
 * (b) the same third party being refused when it is denied or the master switch is
 * off, and (c) the Manager opening an interactive shell through the current executor,
 * writing into it, reading the result and closing it. E3 continues on the same
 * activation: three streams, a real exit code, cancel, and a global mount namespace.
 *
 * <p>The third party here is genuinely another UID: [IdentityProbeService] runs in the
 * test APK's own process and performs the Binder transactions itself, so nothing below
 * can be explained by the Manager's own identity.
 */
@RunWith(AndroidJUnit4::class)
class JailbreakTakeoverAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val fixture get() = instrumentation.context.packageName

    private fun evidence(): JSONObject = JSONObject()

    private fun write(name: String, document: JSONObject) {
        val directory = File(context.getExternalFilesDir(null), "jailbreak-evidence")
        if (!directory.isDirectory) directory.mkdirs()
        File(directory, name).writeText(document.toString(2))
        android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE " + name + "=" + document)
    }

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    private fun fixtureUid(): Int = context.packageManager.getApplicationInfo(fixture, 0).uid

    /** One provider activation on the real UI path, exactly as the acceptance test does. */
    private fun activate(): Pair<JailbreakStatus, JSONObject> {
        var activity: android.app.Activity? = null
        try {
            activity = instrumentation.startActivitySync(
                Intent(Intent.ACTION_MAIN)
                    .setClassName(context, "com.maplesu.core.ui.MainActivity")
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (error: Exception) {
            throw AssertionError("MAIN_ACTIVITY_START_FAILED", error)
        }
        val document = evidence()
        try {
            val outcome = JailbreakController.run(context, JailbreakMethod.DIRTYFRAG)
            document.put("stage", outcome.stage)
            document.put("failure", outcome.failure ?: JSONObject.NULL)
            assertEquals("E1: the attempt did not reach DAEMON_READY: " + outcome.failure,
                JailbreakStatus.STAGE_DAEMON_READY, outcome.stage)
            val status = JailbreakController.status(context)
            assertNotNull("E1: no status record for this attempt", status)
            checkNotNull(status)
            assertEquals(JailbreakStatus.STAGE_DAEMON_READY, status.stage)
            assertTrue("E1: restoration must be verified, was " + status.restoreState,
                status.restoreState == "RESTORED_OBSERVED" || status.restoreState == "RESTORED_BASELINE")
            assertEquals("E1: entry policy must be back to enforcing", 1, status.restoreEnforcing)
            assertEquals("E1: restore must not rewrite the policy", 0, status.restorePolicy)
            assertEquals("E1: native stage reported restore failures", 0, status.restoreFailures)
            document.put("restoreState", status.restoreState ?: JSONObject.NULL)
            document.put("workerPid", status.workerPid ?: JSONObject.NULL)
            return status to document
        } finally {
            runCatching { activity?.finish() }
            instrumentation.waitForIdleSync()
        }
    }

    /**
     * The published restricted entry, resolved through the same public discovery an
     * ordinary client uses. `peek` refusing means the entry was never published, which
     * is precisely the E2 gap this test exists to close.
     */
    private fun broker(): IBinder {
        try {
            return NativeSuDiscovery.peek(context.applicationInfo.uid)
        } catch (error: Throwable) {
            throw AssertionError("E2: the restricted su entry is not published: " + error.message, error)
        }
    }

    private fun withFixture(action: (IBinder) -> Bundle): Bundle {
        val ready = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                ready.complete(binder)
            }

            override fun onServiceDisconnected(name: ComponentName) = Unit
        }
        assertTrue(context.bindService(
            Intent().setComponent(ComponentName(fixture, "dev.maplesu.manager.runtime.IdentityProbeService"))
                .addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES),
            connection, Context.BIND_AUTO_CREATE))
        try {
            return action(ready.get(10, TimeUnit.SECONDS))
        } finally {
            runCatching { context.unbindService(connection) }
        }
    }

    private fun session(target: IBinder, command: String, input: String, globalMnt: Boolean,
                        cancel: Boolean, cancelAfterMillis: Int): Bundle {
        val request = Parcel.obtain()
        val response = Parcel.obtain()
        try {
            request.writeInterfaceToken("dev.maplesu.manager.identityProbe")
            request.writeInt(6)
            request.writeStrongBinder(target)
            request.writeString(command)
            request.writeString("/")
            request.writeByteArray(input.toByteArray())
            request.writeStringArray(arrayOf("PATH=/system/bin:/system/xbin"))
            request.writeInt((if (globalMnt) 1 else 0) or (if (cancel) 2 else 0))
            request.writeInt(cancelAfterMillis)
            assertTrue("the fixture did not answer", fixtureTransact(request, response))
            response.readException()
            return requireNotNull(response.readTypedObject(Bundle.CREATOR)) { "fixture returned nothing" }
        } finally {
            request.recycle()
            response.recycle()
        }
    }

    private var fixtureBinder: IBinder? = null

    private fun fixtureTransact(request: Parcel, response: Parcel): Boolean {
        val binder = fixtureBinder ?: error("fixture binder absent")
        return binder.transact(IBinder.FIRST_CALL_TRANSACTION + 4, request, response, 0)
    }

    private fun describe(value: Bundle): JSONObject = JSONObject().apply {
        put("uid", value.getInt("uid", -1))
        put("accepted", value.getBoolean("accepted"))
        put("finished", value.getBoolean("finished"))
        put("exitCode", value.getInt("exitCode", -1))
        put("awaitMillis", value.getLong("awaitMillis", -1))
        put("stdout", String(value.getByteArray("stdout") ?: ByteArray(0)))
        put("stderr", String(value.getByteArray("stderr") ?: ByteArray(0)))
    }

    @Test fun takeoverServesThirdPartySuAndManagementShell() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val document = evidence()
        val original = JSONObject().apply {
            put("enabled", JailbreakGrantStore.isEnabled(context))
            put("grant", JailbreakGrantStore.hasGrant(context, fixtureUid()))
        }
        val (status, activation) = activate()
        document.put("activation", activation)
        assertNotNull(status.attemptId)

        val peer = fixtureUid()
        assertTrue("the fixture must be a different UID", peer != context.applicationInfo.uid)
        try {
            JailbreakGrantStore.setEnabled(context, true)
            JailbreakGrantStore.grant(context, peer)
            val target = broker()
            document.put("brokerAlive", target.isBinderAlive)

            /* E2: the third party really executes through the published entry. */
            val granted = withFixture { fixture ->
                fixtureBinder = fixture
                session(target, "/system/bin/id -u; /system/bin/cat; printf err >&2; exit 37",
                    "from-third-party\n", globalMnt = false, cancel = false, cancelAfterMillis = -1)
            }
            document.put("granted", describe(granted))
            assertTrue("E2: the authorised third party was refused", granted.getBoolean("accepted"))
            assertEquals("E2: the session ran for another uid than the fixture",
                peer, granted.getInt("uid"))
            assertTrue("E2: the child did not exit", granted.getBoolean("finished"))
            assertEquals("E2: exit status was not carried", 37, granted.getInt("exitCode"))
            val stdout = String(granted.getByteArray("stdout") ?: ByteArray(0))
            val stderr = String(granted.getByteArray("stderr") ?: ByteArray(0))
            assertTrue("E2: the child was not root: $stdout", stdout.lineSequence().firstOrNull()?.trim() == "0")
            assertTrue("E2: stdin did not reach the child: $stdout", stdout.contains("from-third-party"))
            assertTrue("E2: stderr was lost: $stderr", stderr.contains("err"))

            /* E2: a cancel stops a running child and still reports a real exit. */
            val cancelled = withFixture {
                session(target, "/system/bin/sleep 30", "", globalMnt = false, cancel = true,
                    cancelAfterMillis = 1500)
            }
            document.put("cancelled", describe(cancelled))
            assertTrue("E3: a cancelled session must still finish", cancelled.getBoolean("finished"))
            assertTrue("E3: cancel did not shorten the wait (${cancelled.getLong("awaitMillis")} ms)",
                cancelled.getLong("awaitMillis", Long.MAX_VALUE) < 10_000)

            /* E3: the global mount namespace is the init one, verified by the child. */
            val mounted = withFixture {
                session(target, "echo \$(readlink /proc/self/ns/mnt):\$(readlink /proc/1/ns/mnt)",
                    "", globalMnt = true, cancel = false, cancelAfterMillis = -1)
            }
            document.put("globalMnt", describe(mounted))
            val namespaces = String(mounted.getByteArray("stdout") ?: ByteArray(0)).trim()
            val parts = namespaces.split(':')
            assertEquals("E3: the child did not report two namespaces: $namespaces", 2, parts.size)
            assertEquals("E3: globalMnt did not join init's mount namespace: $namespaces",
                parts[1], parts[0])

            /* E2: revoking the grant refuses the next session. */
            JailbreakGrantStore.revoke(context, peer)
            val revoked = withFixture {
                session(target, "/system/bin/id -u", "", globalMnt = false, cancel = false,
                    cancelAfterMillis = -1)
            }
            document.put("revoked", describe(revoked))
            assertFalse("E2: a revoked caller was still admitted", revoked.getBoolean("accepted"))

            /* E2: the master switch refuses even a granted caller. */
            JailbreakGrantStore.grant(context, peer)
            JailbreakGrantStore.setEnabled(context, false)
            val disabled = withFixture {
                session(target, "/system/bin/id -u", "", globalMnt = false, cancel = false,
                    cancelAfterMillis = -1)
            }
            document.put("disabled", describe(disabled))
            assertFalse("E2: the master switch did not refuse the session", disabled.getBoolean("accepted"))
        } finally {
            JailbreakGrantStore.setEnabled(context, original.getBoolean("enabled"))
            if (original.getBoolean("grant")) JailbreakGrantStore.grant(context, peer)
            else JailbreakGrantStore.revoke(context, peer)
        }

        /*
         * The management plane applies the same master switch, so the trusted call
         * below needs it on. The original state is restored at the end of the test.
         */
        JailbreakGrantStore.setEnabled(context, true)

        /* E2: the Manager's own interactive shell through the current executor. */
        val management = NativeSuDaemon.management(context)
        val state = management.status()
        document.put("managementRootPid", state.getInt("rootPid", -1))
        assertEquals("E2: the management endpoint is not the root executor", 0, state.getInt("rootUid", -1))
        val task = management.start(arrayOf("/system/bin/sh", "-c",
            "read line; echo GOT:\$line; echo BAD:stream >&2; exit 5"), Binder(), false)
        assertNotNull("E2: the management shell was not started", task)
        val output = StringBuilder()
        try {
            val stdout = task!!.openStdout()
            val stderr = task.openStderr()
            val reader = Thread {
                ParcelFileDescriptor.AutoCloseInputStream(stdout).use { stream ->
                    val buffer = ByteArray(4096)
                    while (true) {
                        val count = stream.read(buffer)
                        if (count <= 0) break
                        synchronized(output) { output.append(String(buffer, 0, count)) }
                    }
                }
            }.apply { isDaemon = true; start() }
            val errors = StringBuilder()
            val errorReader = Thread {
                ParcelFileDescriptor.AutoCloseInputStream(stderr).use { stream ->
                    val buffer = ByteArray(4096)
                    while (true) {
                        val count = stream.read(buffer)
                        if (count <= 0) break
                        synchronized(errors) { errors.append(String(buffer, 0, count)) }
                    }
                }
            }.apply { isDaemon = true; start() }
            ParcelFileDescriptor.AutoCloseOutputStream(task.openStdin()).use { input ->
                input.write("interactive-ok\n".toByteArray())
                input.flush()
            }
            val exit = task.awaitExit(15_000)
            reader.join(3_000)
            errorReader.join(3_000)
            document.put("managementShell", JSONObject()
                .put("exitCode", exit.getInt("exitCode", -1))
                .put("stdout", output.toString())
                .put("stderr", errors.toString()))
            assertTrue("E2: the interactive shell did not receive the command: $output",
                output.contains("GOT:interactive-ok"))
            assertEquals("E2: the shell's exit status was not carried", 5, exit.getInt("exitCode", -1))
            assertTrue("E3: the second stream was not readable: $errors", errors.contains("BAD:stream"))
        } finally {
            runCatching { task?.close() }
        }

        /*
         * E3: deployment runs through the current executor. `deploySu` publishes the
         * client with a shell script, and in jailbreak mode that script has to travel
         * over the lease - there is no credential to reach for.
         */
        val deployed = context.contentResolver.call(
            android.net.Uri.parse("content://dev.maplesu.manager.root_directory"),
            "deploySu", null,
            Bundle().apply { putString("script", "/system/bin/id -u; echo DEPLOY_OK") })
        document.put("deploy", JSONObject()
            .put("code", deployed?.getInt("code", -1) ?: -1)
            .put("out", deployed?.getString("out") ?: "")
            .put("err", deployed?.getString("err") ?: ""))
        assertNotNull("E3: deployment returned nothing", deployed)
        assertEquals("E3: deployment did not run through the executor: " +
            deployed!!.getString("err"), 0, deployed.getInt("code", -1))
        assertTrue("E3: deployment output: " + deployed.getString("out"),
            deployed.getString("out").orEmpty().contains("DEPLOY_OK"))

        /* E2: close must actually end the child, not only forget it. */
        val pidFile = "/data/local/tmp/maplesu-e2e-child.pid"
        shell("rm -f $pidFile")
        val longLived = management.start(arrayOf("/system/bin/sh", "-c",
            "echo \$\$ > $pidFile; exec /system/bin/sleep 30"), Binder(), false)
        assertNotNull("E2: the long-running shell was not started", longLived)
        runCatching { longLived!!.openStdout().close() }
        runCatching { longLived!!.openStderr().close() }
        runCatching { longLived!!.openStdin().close() }
        var childPid = ""
        val deadline = android.os.SystemClock.elapsedRealtime() + 8_000
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            childPid = shell("cat $pidFile 2>/dev/null").trim()
            if (childPid.isNotEmpty()) break
            Thread.sleep(200)
        }
        assertTrue("E2: the child never reported its pid", childPid.toIntOrNull() != null)
        val aliveBefore = shell("ps -A -o PID | grep -cw $childPid").trim()
        longLived.close()
        Thread.sleep(1_500)
        val aliveAfter = shell("ps -A -o PID | grep -cw $childPid").trim()
        document.put("closeTerminates", JSONObject()
            .put("childPid", childPid).put("aliveBefore", aliveBefore).put("aliveAfter", aliveAfter))
        assertTrue("E2: the long-lived child was not running before close",
            (aliveBefore.toIntOrNull() ?: 0) > 0)
        assertEquals("E2: close only removed the task; the child is still running",
            0, aliveAfter.toIntOrNull() ?: 0)
        JailbreakGrantStore.setEnabled(context, original.getBoolean("enabled"))
        write("takeover-e2e3.json", document)
    }
}
