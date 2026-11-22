package dev.maplesu.manager.runtime

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Production-owner checks are opt-in because they briefly change the real global switch and test grant. */
class ProductionRootOwnerAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val peerUid get() = context.packageManager.getApplicationInfo(instrumentation.context.packageName, 0).uid

    private fun requireOptIn() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("verifyMapleSuBoot") == "true")
        assumeTrue(args.getString("verifySuPolicyMutations") == "true")
        assumeTrue(args.getString("verifyProductionRootOwner") == "true")
    }

    @Test(timeout = 180_000) fun productionOwnerEnforcesGrantRevokeSwitchAndRealSessions() {
        requireOptIn()
        foregroundPeer()
        NativeSuDaemon.ensure(context)
        val management = NativeSuDaemon.management(context)
        val baseline = management.status()
        assertEquals(0, baseline.getInt("rootUid", -1))
        assertEquals(context.applicationInfo.uid, baseline.getInt("managerUid", -1))
        assertNotEquals(context.applicationInfo.uid, peerUid)
        val oldEnabled = management.isEnabled
        val oldGrant = management.hasGrant(peerUid)
        emit("baseline", baseline.toString())
        try {
            management.setEnabled(true)
            management.revoke(peerUid)
            withPeer { peer ->
                assertFalse(management.hasGrant(peerUid))
                assertEquals("denied", probe(peer, "denied").getString("authorization"))
                val count = management.grantCount()
                val deniedManagement = request(peer, 1) { it.writeStrongBinder(management.asBinder()) }
                emit("nonManagerControl", deniedManagement.toString())
                assertEquals(peerUid, deniedManagement.getInt("fixtureUid", -1))
                assertTrue(deniedManagement.toString(), deniedManagement.getBoolean("rejected"))
                assertEquals(count, management.grantCount())
                assertFalse(management.hasGrant(peerUid))
                management.grant(peerUid)
                assertTrue(management.hasGrant(peerUid))
                for (case in listOf("stdio", "pty", "signal", "cancel")) {
                    val result = probe(peer, case)
                    assertEquals(if (case == "signal") 130 else if (case == "cancel") 137 else 37,
                        result.optInt("actualExitCode", -1))
                }
                management.revoke(peerUid)
                assertFalse(management.hasGrant(peerUid))
                assertEquals("denied", probe(peer, "denied").getString("authorization"))
                management.grant(peerUid)
                management.setEnabled(false)
                assertFalse(management.isEnabled)
                assertEquals("denied", probe(peer, "denied").getString("authorization"))
                management.setEnabled(true)
                assertEquals(37, probe(peer, "stdio").optInt("actualExitCode", -1))
            }
            val after = management.status()
            assertEquals(baseline.getInt("rootPid"), after.getInt("rootPid"))
            assertEquals(0, after.getInt("activeSessions", -1))
            emit("after", after.toString())
        } finally {
            if (oldGrant) management.grant(peerUid) else management.revoke(peerUid)
            management.setEnabled(oldEnabled)
            emit("restored", "enabled=${management.isEnabled},testGrant=${management.hasGrant(peerUid)}")
        }
    }

    @Test(timeout = 60_000) fun productionManagementProcessPreservesThreeStreamsAndRealExit() {
        requireOptIn()
        val management = NativeSuDaemon.management(context)
        val readers = Executors.newFixedThreadPool(2)
        try {
            RootManagementProcess.start(management, listOf("/system/bin/sh", "-c",
                "test \"\$(id -u)\" = 0 || exit 91; read -r line; printf '%s' \"\$line\"; printf err >&2; exit 37")).use { process ->
                val stdout = readers.submit<String> { process.inputStream.bufferedReader().readText() }
                val stderr = readers.submit<String> { process.errorStream.bufferedReader().readText() }
                process.outputStream.use { it.write("management-process-marker\n".toByteArray()) }
                assertTrue(process.waitFor(10, TimeUnit.SECONDS))
                assertEquals(37, process.exitValue())
                assertEquals("management-process-marker", stdout.get(3, TimeUnit.SECONDS))
                assertEquals("err", stderr.get(3, TimeUnit.SECONDS))
                emit("managementProcess", "actualExitCode=37; independent stdin/stdout/stderr; uid0 checked by command")
            }
        } finally { readers.shutdownNow() }
    }

    @Test(timeout = 90_000) fun productionManagementNaturalExitReleasesSlotsWithoutDestroy() {
        requireOptIn()
        val management = NativeSuDaemon.management(context)
        val finished = ArrayList<RootManagementProcess>()
        try {
            repeat(6) { index ->
                val process = RootManagementProcess.start(management, listOf("/system/bin/sh", "-c",
                    "printf 'delayed-output-$index'; printf 'delayed-error-$index' >&2; exit 37"))
                finished.add(process)
                // Keep stdin open and do not drain output until after natural
                // exit. This detects both blocked-input and premature-output cleanup.
                assertTrue(process.waitFor(10, TimeUnit.SECONDS))
                assertEquals(37, process.exitValue())
                process.outputStream.close()
                assertEquals("delayed-output-$index", process.inputStream.bufferedReader().use { it.readText() })
                assertEquals("delayed-error-$index", process.errorStream.bufferedReader().use { it.readText() })
                // No destroy()/task.close() until all six have demonstrated that
                // the four-running-task quota was released by natural completion.
            }
            emit("managementNaturalExit", "six natural exits; stdin held; output read after wait; no destroy between tasks")
        } finally { finished.forEach { runCatching { it.close() } } }
    }

    private fun probe(peer: IBinder, case: String): JSONObject {
        val observed = request(peer, 0) { it.writeString(case) }
        assertEquals(peerUid, observed.getInt("fixtureUid", -1))
        val output = observed.getString("stdout") ?: error("Production client output missing")
        val reports = output.lineSequence().filter { it.startsWith("{") && it.endsWith("}") }.toList()
        assertEquals(observed.toString(), 1, reports.size)
        val result = JSONObject(reports.single())
        emit(case, result.toString())
        assertEquals(observed.toString(), 0, observed.getInt("exitCode", -1))
        assertEquals(result.toString(), "pass", result.getString("status"))
        assertEquals(peerUid, result.getInt("clientUid"))
        assertTrue(result.toString(), result.getString("clientContext").startsWith("u:r:untrusted_app:"))
        assertEquals("production_ams_peek", result.getString("discovery"))
        return result
    }

    private fun request(peer: IBinder, operation: Int, write: (Parcel) -> Unit): Bundle {
        val data = Parcel.obtain(); val reply = Parcel.obtain()
        try {
            data.writeInterfaceToken(ProductionRootPeerService.DESCRIPTOR); write(data)
            assertTrue(peer.transact(IBinder.FIRST_CALL_TRANSACTION + operation, data, reply, 0))
            reply.readException()
            return requireNotNull(reply.readTypedObject(Bundle.CREATOR))
        } finally { data.recycle(); reply.recycle() }
    }

    private fun <T> withPeer(action: (IBinder) -> T): T {
        val ready = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) { ready.complete(service) }
            override fun onServiceDisconnected(name: ComponentName) = Unit
        }
        val intent = Intent().setComponent(ComponentName(instrumentation.context.packageName, ProductionRootPeerService::class.java.name))
        assertTrue(context.bindService(intent, Context.BIND_AUTO_CREATE, context.mainExecutor, connection))
        try { return action(ready.get(10, TimeUnit.SECONDS)) } finally { context.unbindService(connection) }
    }

    private fun foregroundPeer() {
        val name = "${instrumentation.context.packageName}/androidx.test.core.app.InstrumentationActivityInvoker\$EmptyActivity"
        instrumentation.uiAutomation.executeShellCommand("am start -W -n $name").use { descriptor ->
            val output = ParcelFileDescriptor.AutoCloseInputStream(descriptor).bufferedReader().use { it.readText() }
            assertTrue(output, output.contains("Status: ok"))
        }
    }

    private fun emit(case: String, report: String) {
        instrumentation.sendStatus(2, Bundle().apply { putString("productionRoot_$case", report) })
    }
}
