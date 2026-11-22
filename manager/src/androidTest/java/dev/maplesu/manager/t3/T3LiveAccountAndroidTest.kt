package dev.maplesu.manager.t3

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import android.os.Build
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import t3sdk.T3Verify

/** Opt-in live API evidence, confined to one persisted synthetic account in the isolated APK. */
class T3LiveAccountAndroidTest {
    @Test(timeout = 300_000L)
    fun isolatedAccountRoundTripCacheAndRealForegroundCadence() = runBlocking {
        assumeTrue("Pass -e t3Live true to run live API checks",
            InstrumentationRegistry.getArguments().getString("t3Live") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("Live API checks require the isolated APK", "dev.maplesu.manager.themetest", context.packageName)
        val deviceIdentity = T3DeviceIdentity.resolve(context)
        assertTrue("Production device identity resolved to a stable 32-digit digest",
            deviceIdentity?.matches(Regex("[0-9a-f]{32}")) == true)
        assertTrue("Repeated production identity reads are stable", deviceIdentity == T3DeviceIdentity.resolve(context))
        val fixturePreferences = context.getSharedPreferences("t3_live_fixture", Context.MODE_PRIVATE)
        val suppliedAccount = InstrumentationRegistry.getArguments().getString("t3FixtureAccount")
        if (suppliedAccount != null) {
            require(suppliedAccount.matches(Regex("[A-Za-z0-9]{1,20}"))) { "Invalid dedicated fixture account" }
        }
        val account = suppliedAccount ?: fixturePreferences.getString("account", null) ?: ("t3test" +
            UUID.randomUUID().toString().replace("-", "").take(14)).also {
            assertTrue("Fixture account persisted", fixturePreferences.edit().putString("account", it).commit())
        }
        assertTrue("Fixture account uses its reserved prefix or explicit dedicated account",
            suppliedAccount == account || (account.startsWith("t3test") && account.length == 20))
        val sdk = T3Verify()
        val transport = RecordingTransport(T3SdkTransport(sdk))
        val credentials = mapOf("user" to account, "pass" to T3AccountClient.PASSWORD)
        val loginParameters = credentials + ("imei" to account)
        var login = transport.call(T3Operation.LOGIN, loginParameters)
        if (suppliedAccount == null && login.code != 200 && T3AccountClient.isAccountMissing(login.message)) {
            val registration = transport.call(T3Operation.REGISTER,
                credentials + ("email" to "$account@maplesu.app"))
            assertTrue("Dedicated fixture registration succeeded or already exists",
                registration.code == 200 || T3AccountClient.isAlreadyRegistered(registration.message))
            login = transport.call(T3Operation.LOGIN, loginParameters)
        }
        assertEquals("Dedicated fixture login succeeded", 200, login.code)
        val statecode = login.statecode
        assertTrue("Login returned a statecode", !statecode.isNullOrBlank())
        val fixtureContext = SessionPreferencesContext(context)
        T3AndroidAccountStore(fixtureContext).write(T3Session(account, account, statecode!!))
        val restoredStore = T3AndroidAccountStore(SessionPreferencesContext(context))
        val restored = restoredStore.read()
        assertNotNull("A new Android store restored the session", restored)
        assertTrue("Cached account and identity restored", restored!!.account == account && restored.identity == account)
        assertTrue("Cached statecode restored", restored.statecode == statecode)

        val identityReads = AtomicInteger()
        val core = "T3 live fixture | ${Build.MODEL} | ${UUID.randomUUID().toString().take(8)}"
        val client = T3AccountClient(transport, restoredStore, {
            identityReads.incrementAndGet()
            null
        }, { core })
        val callsBeforeRestore = transport.calls.size
        client.synchronize()
        val restoredCalls = transport.calls.drop(callsBeforeRestore)
        assertEquals("Cache restoration begins with a heartbeat", T3Operation.HEARTBEAT, restoredCalls.first().operation)
        assertEquals("Cached heartbeat succeeded", 200, restoredCalls.first().code)
        assertTrue("Cache restoration avoids login and registration", restoredCalls.none {
            it.operation == T3Operation.LOGIN || it.operation == T3Operation.REGISTER
        })
        assertEquals("Cache restoration never reads a device identity", 0, identityReads.get())
        assertTrue("Only the fixture user's core was updated", restoredCalls.any {
            it.operation == T3Operation.UPDATE_CORE && it.code == 200
        })
        sdk.setGetUserCoreCode("16A3FD35D8F4AF25")
        val coreResult = sdk.getCoreByUser(account, T3AccountClient.PASSWORD)
        assertTrue("Fixture core read succeeded", coreResult.success)
        // The official get-user-core API returns the stored UTF-8 bytes as hexadecimal.
        val returnedCore = coreResult.core.orEmpty()
        val decodedCore = if (returnedCore.matches(Regex("(?:[0-9a-fA-F]{2})*"))) {
            returnedCore.chunked(2).map { it.toInt(16).toByte() }.toByteArray().toString(Charsets.UTF_8)
        } else returnedCore
        assertTrue("Fixture core round trip preserved the exact value", returnedCore == core || decodedCore == core)
        assertTrue("Live announcement request succeeded", restoredCalls.any {
            it.operation == T3Operation.NOTICE && it.code == 200
        })
        assertNull("Live service did not report program disablement", client.disabledMessage.value)

        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val controller = T3ForegroundController(scope, client)
        val originalRegistrations = transport.calls.count { it.operation == T3Operation.REGISTER }
        val heartbeatBaseline = transport.heartbeats().size
        try {
            controller.start()
            controller.start()
            awaitCondition(100_000L) { transport.heartbeats().size >= heartbeatBaseline + 2 }
            val foregroundHeartbeats = transport.heartbeats().drop(heartbeatBaseline)
            assertEquals("Repeated start preserves a single real heartbeat loop", 2, foregroundHeartbeats.size)
            assertTrue("Both foreground heartbeats succeeded", foregroundHeartbeats.all { it.code == 200 })
            val interval = foregroundHeartbeats[1].startedAt - foregroundHeartbeats[0].startedAt
            assertTrue("Real foreground heartbeat interval was ${interval}ms", interval in 58_000L..85_000L)

            controller.stop()
            awaitCondition(20_000L) { transport.inFlight.get() == 0 }
            val stoppedCallCount = transport.calls.size
            // Wait past a whole production interval so a leaked delayed loop would make a request.
            delay(65_000L)
            assertEquals("Stopped controller makes no further API requests", stoppedCallCount, transport.calls.size)

            controller.start()
            controller.start()
            awaitCondition(25_000L) { transport.heartbeats().size >= heartbeatBaseline + 3 }
            delay(2_000L)
            assertEquals("Restart creates exactly one immediate heartbeat", heartbeatBaseline + 3, transport.heartbeats().size)
            assertEquals("Restarted heartbeat succeeded", 200, transport.heartbeats().last().code)
            assertEquals("Foreground restart never repeats registration", originalRegistrations,
                transport.calls.count { it.operation == T3Operation.REGISTER })
            assertEquals("Foreground restart keeps the cached identity", 0, identityReads.get())
        } finally {
            controller.stop()
            withTimeout(20_000L) { scope.coroutineContext[Job]!!.cancelAndJoin() }
        }
    }

    private suspend fun awaitCondition(timeout: Long, condition: () -> Boolean) {
        withTimeout(timeout) {
            while (!condition()) delay(50L)
        }
    }

    /** Exercise the production store with a dedicated preferences file, keeping other fixture data intact. */
    private class SessionPreferencesContext(base: Context) : ContextWrapper(base) {
        override fun getApplicationContext(): Context = this
        override fun getSharedPreferences(name: String, mode: Int): SharedPreferences =
            super.getSharedPreferences("t3_live_fixture_session", mode)
    }

    private data class Call(val operation: T3Operation, val startedAt: Long, val code: Int)

    /** Record timing and status only: credentials, identity and statecode never enter test output. */
    private class RecordingTransport(private val delegate: T3Transport) : T3Transport {
        val calls = CopyOnWriteArrayList<Call>()
        val inFlight = AtomicInteger()

        override fun call(operation: T3Operation, parameters: Map<String, String>): T3Response {
            inFlight.incrementAndGet()
            val startedAt = SystemClock.elapsedRealtime()
            try {
                val response = delegate.call(operation, parameters) ?: error("T3 returned no response for $operation")
                calls += Call(operation, startedAt, response.code)
                return response
            } finally {
                inFlight.decrementAndGet()
            }
        }

        fun heartbeats(): List<Call> = calls.filter { it.operation == T3Operation.HEARTBEAT }
    }
}
