package dev.maplesu.manager.runtime

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.system.StructTimeval
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.FileDescriptor
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Opt-in, fixed-message transport diagnostic; never sends a command or changes Root grants. */
class RootSocketAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test(timeout = 30_000) fun rootContextListenerAcceptsOrdinaryUid() = probe("A")
    @Test(timeout = 30_000) fun managerCanListenAndAcceptTransferredRootBoundFd() = probe("B")
    @Test(timeout = 30_000) fun rootAcceptedSocketReportsManagerOperations() = probe("C")

    @Test(timeout = 30_000) fun actualAppProcessDiscoversManagerBinder() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyBinderBootstrap") == "true")
        foreground()
        val dexJar = ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(
            "cat /data/local/tmp/maplesu-binder-probe.jar")).use { it.readBytes() }
        val result = peerProbe(null, dexJar)
        instrumentation.sendStatus(2, result)
        assertNotEquals(Process.myUid(), result.getInt("fixtureUid"))
        assertEquals(result.getString("stderr"), 0, result.getInt("exitCode"))
        assertTrue(result.getString("stdout"), result.getString("stdout").orEmpty().contains("callbackUid=${Process.myUid()}"))
    }

    private fun probe(mode: String) {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySocketContext") == "true")
        foreground()
        assertTrue(MapleSuRuntime.refresh(context))
        val peerUid = context.packageManager.getApplicationInfo(instrumentation.context.packageName, 0).uid
        val suffix = UUID.randomUUID().toString()
        val controlName = "maplesu.socketprobe.control.$suffix"
        val listenerName = "maplesu.socketprobe.${mode.lowercase()}.$suffix"
        val results = Bundle().apply { putString("mode", mode) }
        val workers = Executors.newFixedThreadPool(4) { job ->
            Thread(job, "maplesu-socket-probe").apply { isDaemon = true }
        }
        val controlListener = LocalServerSocket(controlName)
        var task: MapleSuSupervisedProcess? = null
        var control: LocalSocket? = null
        var delegated: FileDescriptor? = null
        var server: LocalServerSocket? = null
        var pendingClient: java.util.concurrent.Future<Bundle>? = null
        var stage = "helper_start"
        try {
            val connection = workers.submit<LocalSocket> { controlListener.accept() }
            val rootTask = MapleSuSupervisedProcess.start(context, listOf(
                "/data/local/tmp/maplesu-socket-probe", mode,
                controlName, listenerName, Process.myUid().toString(), peerUid.toString()))
            task = rootTask
            val stdout = workers.submit<String> { rootTask.process.inputStream.bufferedReader().use { it.readText() } }
            val stderr = workers.submit<String> { rootTask.process.errorStream.bufferedReader().use { it.readText() } }
            rootTask.process.outputStream.close()
            try {
                stage = "control_accept"
                val channel = connection.get(7, TimeUnit.SECONDS)
                control = channel
                channel.soTimeout = 7_000
                assertEquals("Helper control peer", 0, channel.peerCredentials.uid)
                channel.outputStream.write('A'.code)
                channel.outputStream.flush()
                if (mode == "C") {
                    stage = "root_listener_ready"
                    assertEquals('R'.code, channel.inputStream.read())
                    val client = workers.submit<Bundle> { peerProbe(listenerName) }
                    pendingClient = client
                    stage = "receive_accepted_fd"
                    assertEquals('F'.code, channel.inputStream.read())
                    val descriptors = channel.ancillaryFileDescriptors.orEmpty()
                    if (descriptors.size != 1) {
                        descriptors.forEach { runCatching { Os.close(it) } }
                        fail("Expected one accepted FD, got ${descriptors.size}")
                    }
                    val descriptor = descriptors.single()
                    delegated = descriptor
                    Os.fcntlInt(descriptor, OsConstants.F_SETFD, OsConstants.FD_CLOEXEC)
                    val acceptedUid = java.io.DataInputStream(channel.inputStream).readInt()
                    results.putInt("helperAcceptedPeerUid", acceptedUid)
                    assertEquals(peerUid, acceptedUid)
                    stage = "manager_fd_operations"
                    fun operation(name: String, action: () -> Any?) {
                        results.putString(name, runCatching { "ok:${action()}" }.getOrElse { failure ->
                            "failed:" + generateSequence(failure) { it.cause }.take(4).joinToString(" <- ")
                        })
                    }
                    operation("managerGetopt") {
                        Os.getsockoptTimeval(descriptor, OsConstants.SOL_SOCKET, OsConstants.SO_RCVTIMEO)
                    }
                    operation("managerSetoptReceive") {
                        Os.setsockoptTimeval(descriptor, OsConstants.SOL_SOCKET, OsConstants.SO_RCVTIMEO, StructTimeval.fromMillis(5_000))
                    }
                    operation("managerSetoptSend") {
                        Os.setsockoptTimeval(descriptor, OsConstants.SOL_SOCKET, OsConstants.SO_SNDTIMEO, StructTimeval.fromMillis(5_000))
                    }
                    // Public SDK has no LocalSocket(FileDescriptor) constructor. Probe the platform view
                    // independently; failure here is not evidence that raw FD read/write was denied.
                    val view = runCatching {
                        try {
                            LocalSocket::class.java.getDeclaredMethod("createConnectedLocalSocket", FileDescriptor::class.java)
                                .invoke(null, descriptor) as LocalSocket
                        } catch (_: NoSuchMethodException) {
                            LocalSocket::class.java.getDeclaredConstructor(FileDescriptor::class.java)
                                .newInstance(descriptor)
                        }
                    }
                    results.putString("managerLocalSocketView", view.exceptionOrNull()?.let { failure ->
                        generateSequence(failure) { it.cause }.take(4).joinToString(" <- ")
                    } ?: "available")
                    if (view.isFailure) results.putString("managerPeerCredentials", "not_tested:view_unavailable")
                    view.getOrNull()?.let { socket ->
                        operation("managerPeerCredentials") {
                            socket.peerCredentials.uid.also { results.putInt("managerAcceptedPeerUid", it) }
                        }
                        operation("managerLocalSocketTimeout") { socket.soTimeout = 5_000 }
                    }
                    stage = "manager_read"
                    val ping = ByteArray(4)
                    var received = 0
                    while (received < ping.size) {
                        val pending = StructPollfd().apply { fd = descriptor; events = OsConstants.POLLIN.toShort() }
                        assertEquals("Manager accepted FD poll", 1, Os.poll(arrayOf(pending), 5_000))
                        val count = Os.read(descriptor, ping, received, ping.size - received)
                        assertTrue("Client EOF before PING", count > 0)
                        received += count
                    }
                    assertArrayEquals("PING".toByteArray(), ping)
                    results.putBoolean("managerReadPassed", true)
                    stage = "manager_write"
                    assertEquals(4, Os.write(descriptor, "PONG".toByteArray(), 0, 4))
                    results.putBoolean("managerWritePassed", true)
                    val peer = client.get(7, TimeUnit.SECONDS)
                    results.putBundle("client", peer)
                    results.putInt("serverPeerUid", peer.getInt("serverPeerUid", -1))
                    results.putInt("clientUid", peer.getInt("uid", -1))
                    results.putString("clientStage", peer.getString("stage"))
                    results.putString("clientFailure", peer.getString("failure"))
                    results.putInt("clientErrno", peer.getInt("errno", 0))
                    assertTrue(peer.toString(), peer.getBoolean("echo"))
                    assertEquals(peerUid, peer.getInt("uid"))
                    assertEquals(0, peer.getInt("serverPeerUid"))
                    if (results.containsKey("managerAcceptedPeerUid"))
                        assertEquals(peerUid, results.getInt("managerAcceptedPeerUid"))
                    channel.outputStream.write('D'.code)
                    channel.outputStream.flush()
                } else if (mode == "B") {
                    stage = "receive_bound_fd"
                    assertEquals('F'.code, channel.inputStream.read())
                    val descriptors = channel.ancillaryFileDescriptors.orEmpty()
                    if (descriptors.size != 1) {
                        descriptors.forEach { runCatching { Os.close(it) } }
                        fail("Expected one bound listener FD, got ${descriptors.size}")
                    }
                    val descriptor = descriptors.single()
                    delegated = descriptor
                    Os.fcntlInt(descriptor, OsConstants.F_SETFD, OsConstants.FD_CLOEXEC)
                    stage = "manager_listen"
                    val managerServer = LocalServerSocket(descriptor)
                    server = managerServer
                    channel.outputStream.write('L'.code)
                    channel.outputStream.flush()
                    assertEquals('R'.code, channel.inputStream.read())
                    val accepted = workers.submit<Bundle> {
                        val pending = StructPollfd().apply { fd = descriptor; events = OsConstants.POLLIN.toShort() }
                        assertEquals("Manager listener poll", 1, Os.poll(arrayOf(pending), 5_000))
                        managerServer.accept().use { socket ->
                            socket.soTimeout = 5_000
                            val actualUid = socket.peerCredentials.uid
                            assertEquals(peerUid, actualUid)
                            val ping = ByteArray(4)
                            java.io.DataInputStream(socket.inputStream).readFully(ping)
                            assertArrayEquals("PING".toByteArray(), ping)
                            socket.outputStream.write("PONG".toByteArray())
                            socket.outputStream.flush()
                            Bundle().apply { putInt("acceptedPeerUid", actualUid) }
                        }
                    }
                    stage = "peer_roundtrip"
                    val peer = peerProbe(listenerName)
                    results.putBundle("client", peer)
                    results.putInt("serverPeerUid", peer.getInt("serverPeerUid", -1))
                    results.putInt("clientUid", peer.getInt("uid", -1))
                    results.putString("clientStage", peer.getString("stage"))
                    results.putString("clientFailure", peer.getString("failure"))
                    results.putInt("clientErrno", peer.getInt("errno", 0))
                    assertTrue(peer.toString(), peer.getBoolean("connected"))
                    assertTrue(peer.toString(), peer.getBoolean("echo"))
                    assertEquals(peerUid, peer.getInt("uid"))
                    results.putBundle("accept", accepted.get(7, TimeUnit.SECONDS))
                    assertEquals("The production client expects Manager-owned SO_PEERCRED", Process.myUid(), peer.getInt("serverPeerUid"))
                    channel.outputStream.write('D'.code)
                    channel.outputStream.flush()
                } else {
                    stage = "root_listener_ready"
                    assertEquals('R'.code, channel.inputStream.read())
                    stage = "peer_roundtrip"
                    val peer = peerProbe(listenerName)
                    results.putBundle("client", peer)
                    results.putInt("serverPeerUid", peer.getInt("serverPeerUid", -1))
                    results.putInt("clientUid", peer.getInt("uid", -1))
                    results.putString("clientStage", peer.getString("stage"))
                    results.putString("clientFailure", peer.getString("failure"))
                    results.putInt("clientErrno", peer.getInt("errno", 0))
                    assertTrue(peer.toString(), peer.getBoolean("connected"))
                    assertTrue(peer.toString(), peer.getBoolean("echo"))
                    assertEquals(peerUid, peer.getInt("uid"))
                    assertEquals(0, peer.getInt("serverPeerUid"))
                }
                stage = "helper_exit"
                assertTrue(rootTask.process.waitFor(7, TimeUnit.SECONDS))
                results.putInt("helperExit", rootTask.process.exitValue())
                assertEquals(0, rootTask.process.exitValue())
                stage = "complete"
            } finally {
                runCatching { control?.close() }
                rootTask.cancel()
                rootTask.process.waitFor(2, TimeUnit.SECONDS)
                results.putString("helperStdout", runCatching { stdout.get(2, TimeUnit.SECONDS) }.getOrDefault(""))
                results.putString("helperStderr", runCatching { stderr.get(2, TimeUnit.SECONDS) }.getOrDefault(""))
            }
        } catch (error: Throwable) {
            results.putString("failure", error.toString())
            throw error
        } finally {
            if (!results.containsKey("client")) {
                runCatching { pendingClient?.get(100, TimeUnit.MILLISECONDS) }.getOrNull()?.let { peer ->
                    results.putBundle("client", peer)
                    results.putInt("serverPeerUid", peer.getInt("serverPeerUid", -1))
                    results.putInt("clientUid", peer.getInt("uid", -1))
                    results.putString("clientStage", peer.getString("stage"))
                    results.putString("clientFailure", peer.getString("failure"))
                    results.putInt("clientErrno", peer.getInt("errno", 0))
                }
            }
            results.putString("stage", stage)
            instrumentation.sendStatus(2, results)
            runCatching { server?.close() }
            delegated?.let { runCatching { Os.close(it) } }
            runCatching { control?.close() }
            runCatching { controlListener.close() }
            task?.let { it.cancel(); it.closeControl() }
            workers.shutdownNow()
        }
    }

    private fun foreground() {
        listOf(instrumentation.context.packageName to "androidx.test.core.app.InstrumentationActivityInvoker\$EmptyActivity",
            context.packageName to "com.maplesu.core.ui.MainActivity").forEach { (name, activity) ->
            instrumentation.uiAutomation.executeShellCommand("am start -W -n $name/$activity").use {
                val text = ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().use { reader -> reader.readText() }
                assertTrue(text, text.contains("Status: ok"))
            }
        }
    }

    private fun peerProbe(socketName: String?, dexJar: ByteArray? = null): Bundle {
        val ready = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) { ready.complete(binder) }
            override fun onServiceDisconnected(name: ComponentName) {}
        }
        val intent = Intent().setComponent(ComponentName(instrumentation.context.packageName, IdentityProbeService::class.java.name))
            .addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
        assertTrue(context.bindService(intent, Context.BIND_AUTO_CREATE, context.mainExecutor, connection))
        try {
            val request = Parcel.obtain(); val response = Parcel.obtain()
            try {
                request.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
                if (dexJar == null) request.writeString(socketName) else request.writeByteArray(dexJar)
                assertTrue(ready.get(7, TimeUnit.SECONDS).transact(IBinder.FIRST_CALL_TRANSACTION + if (dexJar == null) 6 else 7, request, response, 0))
                response.readException()
                return requireNotNull(response.readTypedObject(Bundle.CREATOR))
            } finally { request.recycle(); response.recycle() }
        } finally { context.unbindService(connection) }
    }
}
