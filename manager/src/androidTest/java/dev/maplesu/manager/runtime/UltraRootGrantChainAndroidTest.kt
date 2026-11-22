package dev.maplesu.manager.runtime

import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.jailbreak.FixtureBinding
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import dev.maplesu.manager.runtime.authorization.SuperuserControl
import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Opt-in current-Hook test: no preparation/exploit/reboot; temporary grants are restored. */
@RunWith(AndroidJUnit4::class)
class UltraRootGrantChainAndroidTest {
    @Test fun managerAndARealThirdPartyUseTheCurrentUltraRoot() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyUltraRootGrantChain") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assertTrue("This test only reuses a current Ultra gate", HookRootExecutor.production(context).available())
        val snapshot = requireNotNull(SuperuserControl.snapshot(context))
        val mode = SuEntryMode.read(context)
        val fixture = FixtureBinding.open(context, instrumentation)
        val evidence = JSONObject().put("passed", false).put("fixture", fixture.evidence())
        val report = File(context.cacheDir, "ultra-root-grant-chain.json")
        val marker = File(context.filesDir, "ultra-root-grant-chain-marker")
        var original: com.maplesu.core.Natives.Profile? = null
        var failure: Throwable? = null
        try {
            assertTrue(fixture.error, fixture.bound)
            val binder = requireNotNull(fixture.binder)
            val uid = fixture.serviceUid
            assertNotEquals(context.applicationInfo.uid, uid)
            original = requireNotNull(ManagerAuthorizations.profile(context, fixture.servicePackage, uid))
            assertTrue(SuperuserControl.setEnabled(context, true).ok)
            SuEntryMode.write(context, SuEntryMode.Mode.TRADITIONAL_COMPAT)
            marker.writeText("private-root-access")
            RootManagement.openShell(context).use { shell ->
                val result = shell.newJob().add("/system/bin/id -u", "/system/bin/service check activity")
                    .to(ArrayList<String>(), ArrayList<String>()).exec()
                evidence.put("manager", JSONObject().put("code", result.code).put("stdout", result.out.joinToString("\n")))
                assertTrue(result.err.toString(), result.isSuccess)
                assertEquals("0", result.out.firstOrNull())
                assertTrue(result.out.any { it.contains(": found") })
            }
            assertTrue(ManagerAuthorizations.saveProfile(context, original.copy(allowSu = false)))
            val entryDeadline = SystemClock.elapsedRealtime() + 45_000
            while (!HookSuCompatibility.traditionalReady(context) && SystemClock.elapsedRealtime() < entryDeadline) {
                SystemClock.sleep(500)
            }
            assertTrue(RuntimeDeployment.status().toString(), HookSuCompatibility.traditionalReady(context))
            val broker = bindDiscovery(context)
            try {
                val beforeDiscovery = discoveryProbe(binder, broker.endpoint)
                evidence.put("discoveryBeforeGrant", beforeDiscovery.toString())
                assertFalse(beforeDiscovery.toString(), beforeDiscovery.getBoolean("endpoint"))
            } finally { context.unbindService(broker.connection) }
            assertHidden(binder, evidence, "beforeGrant")
            assertTrue(ManagerAuthorizations.saveProfile(context, original.copy(allowSu = true)))
            val deadline = SystemClock.elapsedRealtime() + 45_000
            var allowed: Bundle
            do {
                allowed = try {
                    probe(binder, "/system/bin/id -u")
                } catch (error: Exception) {
                    // Publication is asynchronous; an entry missing on the first probe is expected.
                    Bundle().apply {
                        putInt("code", -1)
                        putByteArray("stderr", error.toString().toByteArray())
                    }
                }
                if (allowed.getInt("code", -1) == 0 && output(allowed).trim() == "0") break
                SystemClock.sleep(500)
            } while (SystemClock.elapsedRealtime() < deadline)
            val grantedBroker = bindDiscovery(context)
            try {
                val discovery = discoveryProbe(binder, grantedBroker.endpoint)
                evidence.put("discoveryGranted", discovery.toString())
                assertTrue(discovery.toString(), discovery.getBoolean("endpoint"))
                assertEquals("dev.maplesu.manager.runtime.INativeSuService", discovery.getString("endpointDescriptor"))
            } finally { context.unbindService(grantedBroker.connection) }
            evidence.put("grant", describe(allowed))
            assertEquals(describe(allowed).toString(), 0, allowed.getInt("code", -1))
            assertEquals("0", output(allowed).trim())
            val command = "IFS= read -r line; printf 'stdin=%s\\n' \"\$line\"; " +
                "/system/bin/cat '" + marker.path.replace("'", "'\\''") + "' || exit 41; " +
                "/system/bin/service check activity || exit 42; " +
                "printf 'stderr-marker\\n' >&2; exit 23"
            val streamed = probe(binder, command, "stream-input\n".toByteArray())
            evidence.put("streams", describe(streamed))
            assertEquals(describe(streamed).toString(), 23, streamed.getInt("code", -1))
            assertTrue(output(streamed).contains("stdin=stream-input"))
            assertTrue(output(streamed).contains("private-root-access"))
            assertTrue(output(streamed).contains(": found"))
            assertEquals("stderr-marker", streamed.getByteArray("stderr")!!.decodeToString().trim())
            assertTrue(ManagerAuthorizations.saveProfile(context, original.copy(allowSu = false)))
            assertHidden(binder, evidence, "afterRevoke")
            val revokedBroker = bindDiscovery(context)
            try {
                val discovery = discoveryProbe(binder, revokedBroker.endpoint)
                evidence.put("discoveryAfterRevoke", discovery.toString())
                assertFalse(discovery.toString(), discovery.getBoolean("endpoint"))
            } finally { context.unbindService(revokedBroker.connection) }
            val request = Parcel.obtain(); val response = Parcel.obtain()
            val denied = try {
                request.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
                assertTrue(binder.transact(IBinder.FIRST_CALL_TRANSACTION + 8, request, response, 0))
                response.readException()
                requireNotNull(response.readTypedObject(Bundle.CREATOR))
            } finally { request.recycle(); response.recycle() }
            evidence.put("revoke", describe(denied).put("started", denied.getBoolean("started"))
                .put("exception", denied.getString("exception")))
            assertFalse(describe(denied).toString(), denied.getBoolean("started"))
            assertTrue(output(denied).isBlank())
            evidence.put("passed", true)
        } catch (error: Throwable) {
            failure = error
            evidence.put("error", error.toString())
            throw error
        } finally {
            val cleanup = listOf(
                runCatching { original?.let { assertTrue("restore fixture grant", ManagerAuthorizations.saveProfile(context, it)) } },
                runCatching { assertTrue("restore superuser switch", SuperuserControl.setEnabled(context, snapshot.enabled).ok) },
                runCatching { SuEntryMode.write(context, mode) },
                runCatching { assertTrue("delete private marker", !marker.exists() || marker.delete()) },
                runCatching { fixture.close() },
            ).mapNotNull { it.exceptionOrNull() }
            if (cleanup.isNotEmpty()) evidence.put("passed", false)
            evidence.put("cleanupErrors", cleanup.joinToString("\n"))
            val reportFailure = runCatching { report.writeText(evidence.toString(2)) }.exceptionOrNull()
            val errors = cleanup + listOfNotNull(reportFailure)
            val primary = failure ?: errors.firstOrNull()
            if (primary != null) {
                errors.filter { it !== primary }.forEach(primary::addSuppressed)
                if (failure == null) throw primary
            }
        }
    }

    private data class DiscoveryBinding(val endpoint: IBinder, val connection: android.content.ServiceConnection)

    private fun bindDiscovery(context: android.content.Context): DiscoveryBinding {
        val future = java.util.concurrent.CompletableFuture<IBinder>()
        val connection = object : android.content.ServiceConnection {
            override fun onServiceConnected(name: android.content.ComponentName, binder: IBinder) { future.complete(binder) }
            override fun onServiceDisconnected(name: android.content.ComponentName) { }
            override fun onNullBinding(name: android.content.ComponentName) { future.completeExceptionally(AssertionError("null discovery")) }
        }
        assertTrue(context.bindService(android.content.Intent(NativeSuBrokerService.PEEK_ACTION)
            .setClass(context, NativeSuBrokerService::class.java), connection, android.content.Context.BIND_AUTO_CREATE))
        return try {
            DiscoveryBinding(future.get(8, java.util.concurrent.TimeUnit.SECONDS), connection)
        } catch (error: Throwable) { context.unbindService(connection); throw error }
    }

    private fun discoveryProbe(fixture: IBinder, broker: IBinder): Bundle {
        val query = Parcel.obtain(); val answer = Parcel.obtain()
        return try {
            query.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
            query.writeInt(7); query.writeStrongBinder(broker)
            assertTrue(fixture.transact(IBinder.FIRST_CALL_TRANSACTION + 4, query, answer, 0))
            answer.readException()
            requireNotNull(answer.readTypedObject(Bundle.CREATOR))
        } finally { query.recycle(); answer.recycle() }
    }

    private fun assertHidden(fixture: IBinder, evidence: JSONObject, label: String) {
        val request = Parcel.obtain(); val response = Parcel.obtain()
        val result = try {
            request.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
            assertTrue(fixture.transact(IBinder.FIRST_CALL_TRANSACTION + 10, request, response, 0))
            response.readException()
            requireNotNull(response.readTypedObject(Bundle.CREATOR))
        } finally { request.recycle(); response.recycle() }
        val observation = JSONObject().put("uid", result.getInt("uid", -1))
            .put("exists", result.getBoolean("exists")).put("executable", result.getBoolean("executable"))
            .put("statErrno", result.getInt("statErrno", -1)).put("lstatErrno", result.getInt("lstatErrno", -1))
            .put("readlinkErrno", result.getInt("readlinkErrno", -1))
            .put("legacyMount", result.getBoolean("legacyMount")).put("failure", result.getString("failure"))
        evidence.put(label, observation)
        assertFalse(observation.toString(), result.containsKey("failure"))
        assertFalse(observation.toString(), result.getBoolean("exists"))
        assertFalse(observation.toString(), result.getBoolean("executable"))
        assertEquals(observation.toString(), android.system.OsConstants.ENOENT, result.getInt("statErrno", -1))
        assertEquals(observation.toString(), android.system.OsConstants.ENOENT, result.getInt("lstatErrno", -1))
        assertEquals(observation.toString(), android.system.OsConstants.ENOENT, result.getInt("readlinkErrno", -1))
        assertFalse(observation.toString(), result.getBoolean("legacyMount"))
    }

    private fun probe(fixture: IBinder, command: String, input: ByteArray = byteArrayOf()): Bundle {
        val request = Parcel.obtain(); val response = Parcel.obtain()
        return try {
            request.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
            request.writeInt(0)
            request.writeString(HookSuCompatibility.STANDARD_PATH)
            request.writeString(command)
            request.writeByteArray(input)
            assertTrue(fixture.transact(IBinder.FIRST_CALL_TRANSACTION + 4, request, response, 0))
            response.readException()
            requireNotNull(response.readTypedObject(Bundle.CREATOR))
        } finally { request.recycle(); response.recycle() }
    }

    private fun output(result: Bundle) = result.getByteArray("stdout")?.decodeToString().orEmpty()

    private fun describe(result: Bundle) = JSONObject().put("callerUid", result.getInt("uid", -1))
        .put("code", result.getInt("code", -1)).put("stdout", output(result))
        .put("stderr", result.getByteArray("stderr")?.decodeToString().orEmpty())
}
