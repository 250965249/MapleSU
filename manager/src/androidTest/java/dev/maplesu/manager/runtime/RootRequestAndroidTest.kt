package dev.maplesu.manager.runtime

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.UUID

class RootRequestAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test fun actualOtherUidWithoutGrantIsRejected() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        // Reuse the existing different-UID fixture; its original three transaction codes stay intact.
        openPackage(instrumentation.context.packageName,
            "androidx.test.core.app.InstrumentationActivityInvoker\$EmptyActivity")
        openPackage(context.packageName, "com.maplesu.core.ui.MainActivity")
        val peerUid = context.packageManager.getApplicationInfo(instrumentation.context.packageName, 0).uid
        assertNotEquals(Process.myUid(), peerUid)
        val policy = ManagerAuthorizations.policy(context)
        val enabled = policy.isEnabled
        val granted = policy.hasCurrentGrant(peerUid)
        try {
            policy.revoke(peerUid)
            policy.setEnabled(true)
            withService(ComponentName(context, RootRequestService::class.java)) { rootService ->
                withService(ComponentName(instrumentation.context.packageName,
                    IdentityProbeService::class.java.name)) { peerService ->
                    repeat(5) {
                        val request = Parcel.obtain()
                        val response = Parcel.obtain()
                        try {
                            request.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
                            request.writeStrongBinder(rootService)
                            assertTrue(peerService.transact(IBinder.FIRST_CALL_TRANSACTION + 3,
                                request, response, 0))
                            response.readException()
                            assertEquals(peerUid, response.readInt())
                            assertEquals("Unapproved peer obtained a root task", 0, response.readInt())
                        } finally {
                            request.recycle()
                            response.recycle()
                        }
                    }
                }
            }
        } finally {
            if (granted) policy.grant(peerUid) else policy.revoke(peerUid)
            policy.setEnabled(enabled)
        }
    }

    @Test fun authorizedBootRuntimePreservesStdioExitAndCancellation() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        assertTrue("This test requires the installed MapleSU kernel and paired credential",
            MapleSuRuntime.refresh(context))
        val uid = Process.myUid()
        val policy = ManagerAuthorizations.policy(context)
        val enabled = policy.isEnabled
        val granted = policy.hasCurrentGrant(uid)
        try {
            policy.grant(uid)
            policy.setEnabled(true)
            val marker = "literal \$(id) * 枫栖"
            val command = "printf '%s' \"\$1\"; printf err >&2; exit 37"
            RootRequestClient.connect(context).use { client ->
                client.start(listOf("/system/bin/sh", "-c", command, "fixture", marker)).use { task ->
                    ParcelFileDescriptor.AutoCloseOutputStream(task.stdin).close()
                    val out = readAsync(task.stdout)
                    val err = readAsync(task.stderr)
                    val result = task.awaitExit(10_000)
                    assertTrue(result.getBoolean("finished"))
                    assertEquals(37, result.getInt("exitCode"))
                    assertEquals(marker, out.get(5, TimeUnit.SECONDS).decodeToString())
                    assertEquals("err", err.get(5, TimeUnit.SECONDS).decodeToString())
                }
                val bytes = ByteArray(128 * 1024) { it.toByte() }
                client.start(listOf("/system/bin/cat")).use { task ->
                    val out = readAsync(task.stdout)
                    val err = readAsync(task.stderr)
                    ParcelFileDescriptor.AutoCloseOutputStream(task.stdin).use { it.write(bytes) }
                    val result = task.awaitExit(10_000)
                    assertTrue(result.getBoolean("finished"))
                    assertEquals(0, result.getInt("exitCode"))
                    assertArrayEquals(bytes, out.get(5, TimeUnit.SECONDS))
                    assertEquals(0, err.get(5, TimeUnit.SECONDS).size)
                }
                client.start(listOf("/system/bin/sleep", "30")).use { task ->
                    assertFalse(task.awaitExit(50).getBoolean("finished"))
                    task.cancel()
                    val result = task.awaitExit(10_000)
                    assertTrue(result.getBoolean("finished"))
                    assertTrue(result.getBoolean("cancelRequested"))
                    assertEquals(137, result.getInt("exitCode"))
                }
            }

            // Keep the client stdio ends open: service close must wake blocked stdin and stdout pumps.
            withService(ComponentName(context, RootRequestService::class.java)) { binder ->
                val service = IRootRequestService.Stub.asInterface(binder)
                val threadsBefore = workerCount()
                repeat(6) {
                    val task = service.start(arrayOf("/system/bin/sh", "-c",
                        "while :; do printf '%4096s' x; done"), Binder())
                    val stdin = task.openStdin()
                    val stdout = task.openStdout()
                    val stderr = task.openStderr()
                    try {
                        SystemClock.sleep(100)
                        val closing = CompletableFuture.runAsync { task.close() }
                        closing.get(10, TimeUnit.SECONDS)
                    } finally {
                        listOf(stdin, stdout, stderr).forEach { runCatching { it.close() } }
                        runCatching { task.close() }
                    }
                }
                // Cached workers remain idle briefly, but no completed session may retain a blocked pump.
                val deadline = SystemClock.elapsedRealtime() + 5_000
                while (blockedWorkerCount() > 0 && SystemClock.elapsedRealtime() < deadline) {
                    SystemClock.sleep(50)
                }
                assertEquals("Closed root sessions retained blocked stdio pumps", 0, blockedWorkerCount())
                assertTrue("Workers grew for each closed session", workerCount() <= threadsBefore + 8)
            }
        } finally {
            if (granted) policy.grant(uid) else policy.revoke(uid)
            policy.setEnabled(enabled)
        }
    }

    @Test fun actualOtherUidGrantExecutesAsRootThenRevocationAndGlobalDisableReject() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        openPackage(instrumentation.context.packageName,
            "androidx.test.core.app.InstrumentationActivityInvoker\$EmptyActivity")
        openPackage(context.packageName, "com.maplesu.core.ui.MainActivity")
        assertTrue("This test requires the installed MapleSU kernel and paired credential",
            MapleSuRuntime.refresh(context))
        val peerUid = context.packageManager.getApplicationInfo(instrumentation.context.packageName, 0).uid
        assertNotEquals(Process.myUid(), peerUid)
        val policy = ManagerAuthorizations.policy(context)
        val enabled = policy.isEnabled
        val granted = policy.hasCurrentGrant(peerUid)
        val marker = "literal \$(id) * 枫栖 ${UUID.randomUUID()}"
        try {
            policy.revoke(peerUid)
            policy.setEnabled(true)
            withService(ComponentName(context, RootRequestService::class.java)) { rootService ->
                withService(ComponentName(instrumentation.context.packageName,
                    IdentityProbeService::class.java.name)) { peerService ->
                    fun denied() {
                        val result = peerRootRoundTrip(peerService, rootService, marker)
                        assertEquals(peerUid, result.getInt("uid"))
                        assertFalse("Unapproved peer obtained a root task", result.getBoolean("accepted"))
                    }
                    denied()
                    policy.grant(peerUid)
                    val result = peerRootRoundTrip(peerService, rootService, marker)
                    assertEquals(peerUid, result.getInt("uid"))
                    assertTrue("Granted peer was rejected", result.getBoolean("accepted"))
                    assertTrue("Peer root task did not finish", result.getBoolean("finished"))
                    assertEquals(37, result.getInt("exitCode"))
                    assertEquals("0\n$marker", result.getByteArray("stdout")!!.decodeToString())
                    assertEquals("err", result.getByteArray("stderr")!!.decodeToString())
                    policy.revoke(peerUid)
                    denied()
                    policy.grant(peerUid)
                    policy.setEnabled(false)
                    denied()
                }
            }
        } finally {
            if (granted) policy.grant(peerUid) else policy.revoke(peerUid)
            policy.setEnabled(enabled)
        }
    }

    private fun peerRootRoundTrip(peer: IBinder, service: IBinder, marker: String): Bundle {
        val request = Parcel.obtain()
        val response = Parcel.obtain()
        try {
            request.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
            request.writeStrongBinder(service)
            request.writeString(marker)
            assertTrue(peer.transact(IBinder.FIRST_CALL_TRANSACTION + 5, request, response, 0))
            response.readException()
            return requireNotNull(response.readTypedObject(Bundle.CREATOR))
        } finally {
            request.recycle()
            response.recycle()
        }
    }

    private fun readAsync(descriptor: ParcelFileDescriptor): CompletableFuture<ByteArray> =
        CompletableFuture.supplyAsync {
            ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { it.readBytes() }
        }

    private fun workerCount(): Int = Thread.getAllStackTraces().keys.count {
        it.isAlive && it.name == "maplesu-root-request"
    }

    private fun blockedWorkerCount(): Int = Thread.getAllStackTraces().count { (thread, stack) ->
        thread.isAlive && thread.name == "maplesu-root-request" && stack.any {
            it.className.contains("RootRequestService") && it.methodName.contains("pump")
        }
    }

    private fun openPackage(packageName: String, activity: String) {
        instrumentation.uiAutomation.executeShellCommand("am start -W -n $packageName/$activity")
            .use { descriptor ->
                val output = ParcelFileDescriptor.AutoCloseInputStream(descriptor).bufferedReader()
                    .use { it.readText() }
                assertTrue(output, output.contains("Status: ok"))
            }
    }

    private fun <T> withService(component: ComponentName, action: (IBinder) -> T): T {
        val connected = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) { connected.complete(binder) }
            override fun onServiceDisconnected(name: ComponentName) {}
        }
        val intent = Intent().setComponent(component).addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
        assertTrue(context.bindService(intent, Context.BIND_AUTO_CREATE, context.mainExecutor, connection))
        try { return action(connected.get(10, TimeUnit.SECONDS)) }
        finally { context.unbindService(connection) }
    }
}
