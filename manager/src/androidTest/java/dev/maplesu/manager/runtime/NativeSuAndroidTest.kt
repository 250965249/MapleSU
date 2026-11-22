package dev.maplesu.manager.runtime

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import com.maplesu.core.data.repository.SettingsRepositoryImpl
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/**
 * Retired: this suite exercises the cooperative Binder path - a published global client,
 * a directory owner, a lease and a broker endpoint.
 *
 * <p>Under the non-resident contract the global publication is gone (see
 * `ROOT-NONRESIDENT-N1-DECISION-2026-10-27.md` §6.8) and an authorised application runs
 * the image delivered into its own library directory, so none of these steps exist to be
 * tested. The file is kept as the protocol's written record, not as a runnable gate: a
 * gate that can never become true only teaches people to ignore test results.
 *
 * <p>Coverage that must be re-established on the delivered path before release:
 * three streams, PTY, window resize, cancellation and file-descriptor reclamation. The
 * delivered-path suites (`DeliveredClientAndroidTest`, `PathWiringAndroidTest`) currently
 * prove admission and a single command only.
 */
@org.junit.Ignore("retired with the global publication; session coverage must move to the delivered path")
class NativeSuAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test fun helpAdvertisesCommandOptionToTerminalClients() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        // Help is public and must work without changing any production grants or switches.
        foreground()
        withFixture { fixture ->
            for (option in arrayOf("-h", "--help")) {
                val result = probeArguments(fixture, arrayOf(option), byteArrayOf())
                assertEquals(0, result.getInt("code"))
                assertEquals("", result.getByteArray("stderr")!!.decodeToString())
                val help = result.getByteArray("stdout")!!.decodeToString()
                assertTrue("MT would select legacy USER+EXECUTABLE syntax: $help", help.contains("--command"))
                assertTrue(help, help.contains("-c, --command COMMAND"))
                for (supported in arrayOf("--login", "--shell", "--preserve-environment", "--mount-master")) {
                    assertTrue(help, help.contains(supported))
                }
            }
        }
    }

    @Test fun nativeBrokerRejectsAnUnapprovedActualPeerUid() {
        prepareRuntime()
        val uid = peerUid()
        val policy = ManagerAuthorizations.policy(context)
        val enabled = policy.isEnabled
        val granted = policy.hasCurrentGrant(uid)
        NativeSuDaemon.ensure(context)
        try {
            waitForBroker()
            policy.revoke(uid); policy.setEnabled(true)
            withFixture { fixture ->
                val result = probeTerminal(fixture)
                assertNotEquals(Process.myUid(), result.getInt("uid"))
                assertEquals(uid, result.getInt("uid"))
                assertEquals(77, result.getInt("code"))
            }
        } finally {
            if (granted) policy.grant(uid) else policy.revoke(uid)
            policy.setEnabled(enabled)
        }
    }

    @Test fun serviceDiscoveryDoesNotAuthorizeAnUnapprovedUid() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        foreground()
        val uid = peerUid()
        assumeTrue(!ManagerAuthorizations.policy(context).hasCurrentGrant(uid))
        // Preparation is a trusted internal step and is no longer reachable from an
        // external bind. Bring the executor up through that trusted path first, so
        // this test judges exactly one thing: finding the endpoint grants nothing.
        assertTrue(MapleSuRuntime.refresh(context))
        NativeSuDaemon.ensure(context)
        waitForBroker()
        withFixture { fixture ->
            val result = probe(fixture, 0, "/system/bin/id -u")
            assertEquals(uid, result.getInt("uid"))
            assertNotEquals(Process.myUid(), uid)
            assertEquals(result.getByteArray("stderr")!!.decodeToString(), 77, result.getInt("code"))
            assertEquals("", result.getByteArray("stdout")!!.decodeToString())
        }
    }

    @Test fun grantedLegacySuPreservesStdioExitPtyResizeAndDisconnectCancellation() {
        prepareRuntime()
        val uid = peerUid()
        val policy = ManagerAuthorizations.policy(context)
        val enabled = policy.isEnabled
        val granted = policy.hasCurrentGrant(uid)
        try {
            policy.revoke(uid); policy.setEnabled(true)
            withFixture { fixture ->
                assertEquals(77, probe(fixture, 0, "/system/bin/id -u").getInt("code"))
                val profile = requireNotNull(Natives.getAppProfile(instrumentation.context.packageName, uid))
                assertTrue("Superuser profile did not persist the grant", Natives.setAppProfile(profile.copy(allowSu = true)))
                assertTrue(requireNotNull(Natives.getAppProfile(instrumentation.context.packageName, uid)).allowSu)
                for (arguments in listOf(
                    arrayOf("0", "-c", "/system/bin/id -u"),
                    arrayOf("root", "-c", "/system/bin/id -u"),
                    arrayOf("0", "-mm", "-c", "/system/bin/id -u"),
                    arrayOf("-mm", "0", "-c", "/system/bin/id -u"),
                    arrayOf("0", "/system/bin/sh", "-c", "/system/bin/id -u"),
                    arrayOf("--", "0", "/system/bin/id", "-u"),
                    arrayOf("0"),
                )) {
                    val conventional = probeArguments(fixture, arguments, "id -u\nexit\n".toByteArray())
                    assertEquals(arguments.joinToString(" ") + ": " +
                        conventional.getByteArray("stderr")!!.decodeToString(), 0, conventional.getInt("code"))
                    assertEquals("0", conventional.getByteArray("stdout")!!.decodeToString().trim())
                }
                val terminalEnvironment = probe(fixture, 4, "printf '%s|%s' \"\$LD_LIBRARY_PATH\" \"\$ENV\"")
                assertEquals(terminalEnvironment.getByteArray("stderr")!!.decodeToString(), 0, terminalEnvironment.getInt("code"))
                assertEquals("/maplesu-fixture/lib|/maplesu-fixture/missing-rc",
                    terminalEnvironment.getByteArray("stdout")!!.decodeToString())
                val marker = "literal \$(id) * 枫栖"
                val command = "test \"\$(id -u)\" = 0 || exit 91; read -r line; printf '%s' \"\$line\"; printf err >&2; exit 37"
                val result = probe(fixture, 0, command, (marker + "\n").toByteArray())
                assertEquals(uid, result.getInt("uid"))
                assertEquals(37, result.getInt("code"))
                assertEquals(marker, result.getByteArray("stdout")!!.decodeToString())
                assertEquals("err", result.getByteArray("stderr")!!.decodeToString())
                val bytes = ByteArray(128 * 1024) { it.toByte() }
                val cat = probe(fixture, 0, "/system/bin/cat", bytes)
                assertEquals(0, cat.getInt("code")); assertArrayEquals(bytes, cat.getByteArray("stdout"))
                assertTrue("Superuser profile did not revoke the grant", Natives.setAppProfile(profile.copy(allowSu = false)))
                assertEquals(77, probe(fixture, 0, "/system/bin/id -u").getInt("code"))
                policy.grant(uid)
                val settings = SettingsRepositoryImpl()
                assertEquals("supported", runBlocking { settings.getSuCompatStatus() })
                assertTrue(Natives.setSuEnabled(false))
                assertEquals(0L, runBlocking { settings.getSuCompatPersistValue() })
                assertFalse(settings.isSuEnabled())
                assertEquals(77, probe(fixture, 0, "/system/bin/id -u").getInt("code"))
                assertTrue(Natives.setSuEnabled(true))
                assertEquals(1L, runBlocking { settings.getSuCompatPersistValue() })
                assertTrue(settings.isSuEnabled())
                // Standard-path publication is gone with the zero-mount change: no
                // system directory is overlaid any more, and the state is explicit
                // rather than silently absent. A bare `su` lookup therefore fails by
                // design; the published absolute path is the supported entry.
                assertNull(RuntimeDeployment.status().toString(), RuntimeDeployment.status().standardPath)
                assertEquals("SU_STANDARD_PATH_NOT_PUBLISHED", RuntimeDeployment.status().error)
                val terminal = probeTerminal(fixture)
                assertEquals(37, terminal.getInt("code"))
                val transcript = terminal.getByteArray("stdout")!!.decodeToString()
                assertTrue(transcript, transcript.contains("25 80"))
                assertTrue(transcript, transcript.contains("35 110"))
                val cancelled = probe(fixture, 2)
                assertEquals(137, cancelled.getInt("code"))
                assertTrue("A disconnected native client retained the root stdio writer", cancelled.getBoolean("eof"))
                val pid = cancelled.getInt("pid")
                assertTrue(pid > 1)
                MapleSuRuntime.openShell(context).use { shell ->
                    assertFalse("Disconnected root child is still alive", shell.newJob().add("kill -0 $pid 2>/dev/null").exec().isSuccess)
                }
            }
        } finally {
            if (granted) policy.grant(uid) else policy.revoke(uid)
            policy.setEnabled(enabled)
        }
    }

    /**
     * The admission property that matters: a request the product rejects must not have
     * executed its command.
     *
     * <p>No injection or sleep hook is used. Phase 1 toggles the global switch from
     * another thread while requests are issued, so requests race a decision change; every
     * rejected request must show no command output. Phase 2 stops toggling and requires
     * the same harness to be admitted and show its output, so a phase-1 result cannot be
     * explained by a broken fixture. A gate that executed before deciding would make a
     * rejected request produce output, which is what phase 1 catches.
     */
    @Test fun admissionNeverRunsTheCommandWhenItRejects() {
        prepareRuntime()
        val uid = peerUid()
        val policy = ManagerAuthorizations.policy(context)
        val enabled = policy.isEnabled
        val granted = policy.hasCurrentGrant(uid)
        val stop = java.util.concurrent.atomic.AtomicBoolean(false)
        val toggleFailures = java.util.concurrent.atomic.AtomicInteger()
        var toggler: Thread? = null
        try {
            policy.grant(uid); policy.setEnabled(true)
            toggler = Thread({
                while (!stop.get()) {
                    runCatching { policy.setEnabled(false) }.onFailure { toggleFailures.incrementAndGet() }
                    runCatching { Thread.sleep(25) }
                    runCatching { policy.setEnabled(true) }.onFailure { toggleFailures.incrementAndGet() }
                    runCatching { Thread.sleep(25) }
                }
            }, "maplesu-admission-toggle").apply { isDaemon = true; start() }
            var admitted = 0
            var rejected = 0
            withFixture { fixture ->
                repeat(14) { index ->
                    val token = "RACE-$index-${System.nanoTime()}"
                    val result = probe(fixture, 0, "/system/bin/printf $token")
                    val code = result.getInt("code")
                    val out = result.getByteArray("stdout")?.decodeToString().orEmpty().trim()
                    if (code == 0) {
                        admitted++
                        assertEquals("an admitted request must have run its command", token, out)
                    } else {
                        rejected++
                        assertTrue("rejected request produced command output: code=$code out=$out",
                            out.isEmpty())
                    }
                }
                stop.set(true)
                toggler?.join(2_000)
                toggler = null
                // Phase 2: the same path must admit once nothing races it.
                policy.setEnabled(true)
                assertTrue("the switch did not stay enabled", policy.isEnabled)
                repeat(2) { index ->
                    val token = "ADMIT-$index-${System.nanoTime()}"
                    val result = probe(fixture, 0, "/system/bin/printf $token")
                    assertEquals("the fixture could not obtain Root at all",
                        token, result.getByteArray("stdout")?.decodeToString().orEmpty().trim())
                    assertEquals(0, result.getInt("code"))
                }
            }
            assertTrue("no request raced the switch, phase 1 proved nothing", rejected > 0)
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE admission_race admitted=$admitted " +
                "rejected=$rejected toggleFailures=${toggleFailures.get()}")
        } finally {
            stop.set(true)
            toggler?.join(2_000)
            if (granted) policy.grant(uid) else policy.revoke(uid)
            policy.setEnabled(enabled)
        }
    }

    private fun prepareRuntime() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        // These regressions briefly toggle the production authorization store. Never
        // run them as part of read-only checks while the device owner is using root.
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        // Legacy cooperative path: it needs the Binder endpoint, which the non-resident
        // migration no longer prepares. Gated behind its own flag so a retired path cannot
        // masquerade as a passing capability.
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyLegacyBroker") == "true")
        foreground()
        assertTrue(MapleSuRuntime.refresh(context))
        RuntimeDeployment.start(context)
        val deadline = SystemClock.elapsedRealtime() + 20_000
        while ((!RuntimeDeployment.status().brokerReady || RuntimeDeployment.status().clientPath == null) &&
            SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(50)
        assertEquals(RuntimeDeployment.status().toString(), RuntimeDeployment.clientPath(context),
            RuntimeDeployment.status().clientPath)
        assertTrue(RuntimeDeployment.status().brokerReady)
    }

    private fun probe(fixture: IBinder, mode: Int, command: String = "", input: ByteArray = byteArrayOf(),
        path: String = RuntimeDeployment.clientPath(context)): Bundle {
        val request = Parcel.obtain(); val response = Parcel.obtain()
        try {
            request.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
            request.writeInt(mode)
            if (mode == 0 || mode == 2 || mode == 4) {
                request.writeString(path)
                if (mode != 2) { request.writeString(command); request.writeByteArray(input) }
            }
            assertTrue(fixture.transact(IBinder.FIRST_CALL_TRANSACTION + 4, request, response, 0))
            response.readException()
            return requireNotNull(response.readTypedObject(Bundle.CREATOR))
        } finally { request.recycle(); response.recycle() }
    }
    private fun peerUid(): Int = context.packageManager.getApplicationInfo(instrumentation.context.packageName, 0).uid

    /**
     * PTY/resize/cancel probe through the published restricted binder.
     *
     * <p>The fixture process has a different UID from the Manager, so handing it the
     * published binder makes it the caller the Root endpoint judges. The zero-mount
     * build has no `su` on PATH and no `NATIVE_SU_BIND` discovery action any more, so
     * the fixture cannot find the entry by itself.
     */
    private fun probeTerminal(fixture: IBinder): Bundle {
        val broker = NativeSuDiscovery.peek(context.applicationInfo.uid)
        val request = Parcel.obtain(); val response = Parcel.obtain()
        try {
            request.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
            request.writeInt(5)
            request.writeStrongBinder(broker)
            assertTrue(fixture.transact(IBinder.FIRST_CALL_TRANSACTION + 4, request, response, 0))
            response.readException()
            return requireNotNull(response.readTypedObject(Bundle.CREATOR))
        } finally { request.recycle(); response.recycle() }
    }
    private fun probeArguments(fixture: IBinder, arguments: Array<String>, input: ByteArray): Bundle {
        val request = Parcel.obtain(); val response = Parcel.obtain()
        try {
            request.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
            request.writeInt(3)
            request.writeString(RuntimeDeployment.clientPath(context))
            request.writeStringArray(arguments); request.writeByteArray(input)
            assertTrue(fixture.transact(IBinder.FIRST_CALL_TRANSACTION + 4, request, response, 0))
            response.readException()
            return requireNotNull(response.readTypedObject(Bundle.CREATOR))
        } finally { request.recycle(); response.recycle() }
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
    private fun waitForBroker() {
        val deadline = SystemClock.elapsedRealtime() + 5_000
        while (SystemClock.elapsedRealtime() < deadline) {
            val state = NativeSuDaemon.management(context).status()
            val ready = state.getInt("rootUid", -1) == 0 && state.getInt("rootPid", -1) > 1 &&
                NativeSuDiscovery.peek(context.applicationInfo.uid).isBinderAlive
            if (ready) return
            SystemClock.sleep(50)
        }
        fail("Native broker was not available")
    }
    private fun <T> withFixture(action: (IBinder) -> T): T {
        val ready = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) { ready.complete(binder) }
            override fun onServiceDisconnected(name: ComponentName) {}
        }
        val intent = Intent().setComponent(ComponentName(instrumentation.context.packageName, IdentityProbeService::class.java.name))
            .addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
        assertTrue(context.bindService(intent, Context.BIND_AUTO_CREATE, context.mainExecutor, connection))
        try { return action(ready.get(10, TimeUnit.SECONDS)) } finally { context.unbindService(connection) }
    }
}
