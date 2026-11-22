package dev.maplesu.manager.runtime

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.io.FileInputStream

@RunWith(AndroidJUnit4::class)
class ManagerCallerAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test fun resolvesAndAcceptsTheInstalledManager() {
        ManagerCallerVerifier(context).enforce(Process.myUid())
    }

    @Test fun rejectsRootShellAndAnotherAndroidUser() {
        val verifier = ManagerCallerVerifier(context)
        for (uid in listOf(0, 2000, Process.myUid() + 100_000)) {
            assertThrows(SecurityException::class.java) { verifier.enforce(uid) }
        }
    }

    @Test fun rejectsATestPackageContextAsTheServiceAnchor() {
        assertThrows(IllegalArgumentException::class.java) {
            ManagerCallerVerifier(instrumentation.context)
        }
    }

    @Test fun rejectsAnActualBinderCallerFromAnotherUid() {
        // A freshly installed test APK has not yet been opened on this ROM.
        val component = instrumentation.context.packageName +
            "/androidx.test.core.app.InstrumentationActivityInvoker\$EmptyActivity"
        val launch = instrumentation.uiAutomation.executeShellCommand("am start -W -n $component")
        val output = launch.use { descriptor ->
            FileInputStream(descriptor.fileDescriptor).bufferedReader().use { it.readText() }
        }
        assertTrue(output, output.contains("Status: ok"))
        // Keep the instrumented package in the foreground after opening the other UID.
        instrumentation.uiAutomation.executeShellCommand(
            "am start -W -n ${context.packageName}/com.maplesu.core.ui.MainActivity"
        ).use { descriptor ->
            val restored = FileInputStream(descriptor.fileDescriptor).bufferedReader().use { it.readText() }
            assertTrue(restored, restored.contains("Status: ok"))
        }
        verifyPeerCaller()
    }

    private fun verifyPeerCaller() {
        val verifier = ManagerCallerVerifier(context)
        val observedUid = AtomicInteger(-1)
        fun target(guarded: Boolean) = object : Binder() {
            override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
                if (code != FIRST_CALL_TRANSACTION) return super.onTransact(code, data, reply, flags)
                data.enforceInterface(IdentityProbeService.DESCRIPTOR)
                val callerUid = getCallingUid()
                observedUid.set(callerUid)
                if (guarded) {
                    verifier.withCallingManager { requireNotNull(reply).writeNoException() }
                } else {
                    requireNotNull(reply).writeNoException()
                }
                return true
            }
        }
        val connected = CountDownLatch(1)
        var peer: IBinder? = null
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                peer = service
                connected.countDown()
            }
            override fun onServiceDisconnected(name: ComponentName) {}
        }
        val intent = Intent().setComponent(ComponentName(instrumentation.context.packageName,
            IdentityProbeService::class.java.name)).addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
        assertTrue("Test service visibility: ${context.packageManager.resolveService(intent, 0)}",
            context.bindService(intent, connection, Context.BIND_AUTO_CREATE))
        try {
            assertTrue("Test UID service did not bind", connected.await(10, TimeUnit.SECONDS))
            for (guarded in listOf(false, true)) {
                val request = Parcel.obtain()
                val response = Parcel.obtain()
                try {
                    request.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
                    request.writeStrongBinder(target(guarded))
                    assertTrue(requireNotNull(peer).transact(IBinder.FIRST_CALL_TRANSACTION, request, response, 0))
                    response.readException()
                    val peerUid = response.readInt()
                    assertNotEquals(Process.myUid(), peerUid)
                    assertEquals(peerUid, observedUid.get())
                    assertEquals(if (guarded) "Peer UID must be rejected" else "Unguarded control must accept peer",
                        if (guarded) 0 else 1, response.readInt())
                } finally {
                    request.recycle()
                    response.recycle()
                }
            }
        } finally {
            context.unbindService(connection)
        }
    }
}
