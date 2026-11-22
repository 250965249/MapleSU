package dev.maplesu.manager.runtime

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.Process
import androidx.test.platform.app.InstrumentationRegistry
import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.ipc.RootService
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.json.JSONObject
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/** Opt-in transport admission only. A green test does not certify cold discovery or su sessions. */
class BinderAdmissionAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test(timeout = 60_000) fun nonDaemonBinderTransportAdmission() = probe(false)
    @Test(timeout = 60_000) fun daemonBinderTransportAdmission() = probe(true)

    private fun probe(daemon: Boolean) {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyBinderAdmission") == "true")
        val fixture = runCatching { Class.forName("dev.maplesu.manager.runtime.BinderAdmissionRootService") }.getOrNull()
        assumeTrue("Debug transport fixture is not packaged in this variant", fixture != null)
        val descriptor = requireNotNull(fixture).getField("DESCRIPTOR").get(null) as String
        val report = Bundle().apply {
            putString("mode", if (daemon) "libsu-daemon" else "libsu-non-daemon")
            putString("coldDiscovery", "NOT_PROVED: Manager forwards the initial Root handle")
            putString("lifecycle", "NOT_TESTED: use peer Activity cached-handle check after stopping Manager")
            putString("sessions", "NOT_TESTED: fixed FD echo only; no su, PTY, signal or resize")
            putString("policyBaseline", "NOT_VERIFIED_BY_THIS_TEST: run the separate baseline check")
        }
        val connected = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) { connected.complete(service) }
            override fun onServiceDisconnected(name: ComponentName) = Unit
        }
        val handler = Handler(Looper.getMainLooper())
        var stage = "open_internal_key_shell"
        try {
            MapleSuRuntime.openShell(context).use { shell ->
                assertTrue("Internal Key shell is not Root", shell.isRoot && shell.isAlive)
                report.putBoolean("internalKeyRoot", true)
                stage = "bind_libsu_root_service"
                val intent = Intent().setClassName(context, fixture.name)
                if (daemon) intent.addCategory(RootService.CATEGORY_DAEMON_MODE)
                val pending = CompletableFuture<Shell.Task?>()
                handler.post {
                    try { pending.complete(RootService.bindOrTask(intent, context.mainExecutor, connection)) }
                    catch (error: Exception) { pending.completeExceptionally(error) }
                }
                pending.get(5, TimeUnit.SECONDS)?.let { task ->
                    val submitted = CompletableFuture<Unit>()
                    shell.submitTask(object : Shell.Task {
                        override fun run(stdin: java.io.OutputStream, stdout: java.io.InputStream, stderr: java.io.InputStream) {
                            try { task.run(stdin, stdout, stderr); submitted.complete(Unit) }
                            catch (error: Exception) { submitted.completeExceptionally(error) }
                        }
                        override fun shellDied() {
                            submitted.completeExceptionally(IllegalStateException("BINDER_ADMISSION_LAUNCH_SHELL_DIED"))
                        }
                    })
                    submitted.get(10, TimeUnit.SECONDS)
                }
                // libsu's launch task only writes a background command. Retain the shell until bind completes.
                val root = connected.get(15, TimeUnit.SECONDS)
                stage = "manager_direct_root_identity"
                val identity = rootIdentity(root, descriptor)
                report.putBundle("managerToRoot", identity)
                assertEquals(identity.toString(), 0, identity.getInt("rootUid", -1))
                assertTrue(identity.toString(), identity.getInt("rootPid") > 1)
                assertEquals(identity.toString(), Process.myUid(), identity.getInt("callingUid", -1))
                report.putString("managerToRootObserved", identityJson(identity).toString())
                stage = "independent_peer_direct_root_and_fds"
                foregroundPeer()
                val peer = peerProbe(root)
                report.putBundle("peerToRoot", peer)
                val peerUid = context.packageManager.getApplicationInfo(instrumentation.context.packageName, 0).uid
                assertNotEquals(Process.myUid(), peerUid)
                assertEquals(peer.toString(), peerUid, peer.getInt("peerUid", -1))
                assertEquals(peer.toString(), "complete", peer.getString("stage"))
                for (name in listOf("identity", "stdio")) {
                    val observed = requireNotNull(peer.getBundle(name)) { "$name reply missing: $peer" }
                    assertEquals(observed.toString(), 0, observed.getInt("rootUid", -1))
                    assertEquals(observed.toString(), identity.getInt("rootPid"), observed.getInt("rootPid", -1))
                    assertEquals("Manager forwarding must not substitute caller identity: $observed", peerUid,
                        observed.getInt("callingUid", -1))
                }
                val io = requireNotNull(peer.getBundle("stdio"))
                assertTrue(io.toString(), io.getBoolean("stdio"))
                assertEquals(io.toString(), 37, io.getInt("exitCode", -1))
                assertArrayEquals((fixture.getField("INPUT").get(null) as String).toByteArray(), peer.getByteArray("stdout"))
                assertArrayEquals((fixture.getField("ERROR").get(null) as String).toByteArray(), peer.getByteArray("stderr"))
                report.putString("peerToRootObserved", JSONObject()
                    .put("peerUid", peer.getInt("peerUid"))
                    .put("peerPid", peer.getInt("peerPid"))
                    .put("identity", identityJson(requireNotNull(peer.getBundle("identity"))))
                    .put("stdio", identityJson(io).put("stdio", io.getBoolean("stdio"))
                        .put("exitCode", io.getInt("exitCode")))
                    .put("stdout", requireNotNull(peer.getByteArray("stdout")).toString(Charsets.UTF_8))
                    .put("stderr", requireNotNull(peer.getByteArray("stderr")).toString(Charsets.UTF_8)).toString())
                stage = "transport_passed_cold_discovery_not_proved"
            }
        } catch (error: Throwable) {
            report.putString("failure", error.toString())
            throw error
        } finally {
            report.putString("stage", stage)
            instrumentation.sendStatus(2, report)
            // The daemon-mode peer keeps its restricted Binder for manual Manager lifecycle checks.
            // Non-daemon libsu may exit after Manager unbinds; record that separately, not as a daemon failure.
            handler.post { RootService.unbind(connection) }
        }
    }

    private fun identityJson(identity: Bundle) = JSONObject()
        .put("rootUid", identity.getInt("rootUid", -1))
        .put("rootPid", identity.getInt("rootPid", -1))
        .put("callingUid", identity.getInt("callingUid", -1))
        .put("registryPresent", identity.getBoolean("registryPresent"))
        .put("registryLocal", identity.getBoolean("registryLocal"))
        .put("rootContext", identity.getString("rootContext"))

    private fun rootIdentity(root: IBinder, descriptor: String): Bundle {
        val request = Parcel.obtain(); val reply = Parcel.obtain()
        try {
            request.writeInterfaceToken(descriptor)
            assertTrue(root.transact(IBinder.FIRST_CALL_TRANSACTION, request, reply, 0))
            reply.readException()
            return requireNotNull(reply.readTypedObject(Bundle.CREATOR))
        } finally { request.recycle(); reply.recycle() }
    }

    private fun foregroundPeer() {
        val name = "${instrumentation.context.packageName}/${BinderAdmissionPeerActivity::class.java.name}"
        instrumentation.uiAutomation.executeShellCommand("am start -W -n $name").use { descriptor ->
            val output = ParcelFileDescriptor.AutoCloseInputStream(descriptor).bufferedReader().use { it.readText() }
            assertTrue(output, output.contains("Status: ok"))
        }
    }

    private fun peerProbe(root: IBinder): Bundle {
        val ready = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) { ready.complete(binder) }
            override fun onServiceDisconnected(name: ComponentName) = Unit
        }
        val intent = Intent().setComponent(ComponentName(instrumentation.context.packageName, BinderAdmissionPeerService::class.java.name))
        assertTrue(context.bindService(intent, Context.BIND_AUTO_CREATE, context.mainExecutor, connection))
        try {
            val request = Parcel.obtain(); val reply = Parcel.obtain()
            try {
                request.writeInterfaceToken(BinderAdmissionPeerService.DESCRIPTOR)
                request.writeStrongBinder(root)
                assertTrue(ready.get(7, TimeUnit.SECONDS).transact(IBinder.FIRST_CALL_TRANSACTION, request, reply, 0))
                reply.readException()
                return requireNotNull(reply.readTypedObject(Bundle.CREATOR))
            } finally { request.recycle(); reply.recycle() }
        } finally { context.unbindService(connection) }
    }
}
