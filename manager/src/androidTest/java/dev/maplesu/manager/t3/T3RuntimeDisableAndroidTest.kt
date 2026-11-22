package dev.maplesu.manager.t3

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test

/** Production runtime/controller/countdown on Android's real clock; no Activity or root startup. */
class T3RuntimeDisableAndroidTest {
    @Test(timeout = 30_000L)
    fun disableStopsRequestsKeepsDeadlineAcrossOwnersAndAllowsFreshEnabledRuntime() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val target = instrumentation.targetContext
        assertEquals("Only the isolated APK may run this fixture", "dev.maplesu.manager.themetest", target.packageName)
        assertEquals("Root bootstrap must be skipped", "com.maplesu.core.ui.PresentationTestRunner",
            instrumentation.javaClass.name)
        val preferencesName = "t3_runtime_disable_fixture_${UUID.randomUUID()}"
        val fixtureContext = FixtureContext(target, preferencesName)
        val transport = FixtureTransport()
        val observed = CopyOnWriteArrayList<Pair<Int, Long>>()
        val observationScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        val runtimes = mutableListOf<T3Runtime>()
        lateinit var runtime: T3Runtime
        val initialOwner = Any()
        val recreatedOwner = Any()
        val enabledOwner = Any()

        try {
            instrumentation.runOnMainSync {
                assertNull("The isolated fixture must own a fresh singleton", instanceField().get(null))
                T3AndroidAccountStore(fixtureContext).write(T3Session("fixture", "fixture", "fixture-state"))
                runtime = T3Runtime.get(fixtureContext).also { runtimes += it }
                injectTransport(runtime, transport)
                observationScope.launch {
                    runtime.secondsRemaining.filterNotNull().collect { seconds ->
                        observed += seconds to SystemClock.elapsedRealtime()
                    }
                }
                runtime.attach(initialOwner)
                runtime.foreground(initialOwner)
            }

            awaitCondition { runtime.secondsRemaining.value == 2 }
            assertEquals("Only the disabling heartbeat ran", listOf(T3Operation.HEARTBEAT), transport.calls.toList())
            instrumentation.runOnMainSync {
                val controller = field(runtime, "controller") as T3ForegroundController
                val controllerJob = controller.javaClass.getDeclaredField("job").apply { isAccessible = true }
                    .get(controller) as? Job
                assertFalse("The runtime cancelled its production foreground loop", controllerJob?.isActive == true)
                runtime.destroy(initialOwner, finishing = false)
                assertSame("Configuration changes retain the disabled runtime", runtime, T3Runtime.get(fixtureContext))
                runtime.attach(recreatedOwner)
                runtime.foreground(recreatedOwner)
                assertEquals("Recreated foreground keeps the current deadline", 2, runtime.secondsRemaining.value)
            }

            awaitCondition { observed.any { it.first == 0 } }
            assertEquals("The production countdown emits every second", listOf(3, 2, 1, 0), observed.map { it.first })
            val elapsed = observed.first { it.first == 0 }.second - transport.disabledAt.get()
            assertTrue("Three-second deadline completed after ${elapsed}ms", elapsed in 2_800L..5_000L)
            instrumentation.runOnMainSync {
                runtime.foreground(recreatedOwner)
                runtime.background(recreatedOwner)
                runtime.foreground(recreatedOwner)
            }
            delay(300L)
            assertEquals("Disabled foreground and recreation never send another request", 1, transport.calls.size)
            instrumentation.runOnMainSync {
                runtime.destroy(recreatedOwner, finishing = true)
                assertNull("The last finishing owner clears the expired runtime", instanceField().get(null))
            }

            transport.disabled.set(false)
            lateinit var enabledRuntime: T3Runtime
            instrumentation.runOnMainSync {
                enabledRuntime = T3Runtime.get(fixtureContext).also { runtimes += it }
                assertNotSame("A fresh launch can check a re-enabled service", runtime, enabledRuntime)
                injectTransport(enabledRuntime, transport)
                assertNull("The fresh runtime has no stale disable deadline", enabledRuntime.secondsRemaining.value)
                enabledRuntime.attach(enabledOwner)
                enabledRuntime.foreground(enabledOwner)
            }
            awaitCondition { transport.calls.size >= 3 }
            assertEquals("Re-enabled launch resumes heartbeat and notice", listOf(
                T3Operation.HEARTBEAT, T3Operation.HEARTBEAT, T3Operation.NOTICE,
            ), transport.calls.toList())
            assertNull("Successful revalidation leaves the fresh runtime enabled", enabledRuntime.secondsRemaining.value)
            instrumentation.runOnMainSync {
                enabledRuntime.background(enabledOwner)
                enabledRuntime.destroy(enabledOwner, finishing = true)
            }
        } finally {
            instrumentation.runOnMainSync {
                observationScope.cancel()
                runtimes.forEach { current ->
                    val controller = field(current, "controller") as T3ForegroundController
                    controller.stop()
                    (field(current, "scope") as CoroutineScope).cancel()
                    val singleton = instanceField()
                    if (singleton.get(null) === current) singleton.set(null, null)
                }
                target.deleteSharedPreferences(preferencesName)
            }
        }
    }

    private suspend fun awaitCondition(condition: () -> Boolean) {
        withTimeout(10_000L) {
            while (!condition()) delay(20L)
        }
    }

    private fun injectTransport(runtime: T3Runtime, transport: T3Transport) {
        val client = field(runtime, "client") as T3AccountClient
        val transportField = T3AccountClient::class.java.getDeclaredField("transport").apply { isAccessible = true }
        transportField.set(client, transport)
        assertSame("The production client uses the fixture transport", transport, transportField.get(client))
    }

    private fun field(owner: Any, name: String): Any = owner.javaClass.getDeclaredField(name)
        .apply { isAccessible = true }.get(owner)!!

    private fun instanceField() = T3Runtime::class.java.getDeclaredField("instance").apply { isAccessible = true }

    private class FixtureContext(base: Context, private val name: String) : ContextWrapper(base) {
        override fun getApplicationContext(): Context = this
        override fun getSharedPreferences(name: String, mode: Int): SharedPreferences =
            super.getSharedPreferences(this.name, mode)
    }

    private class FixtureTransport : T3Transport {
        val calls = CopyOnWriteArrayList<T3Operation>()
        val disabled = AtomicBoolean(true)
        val disabledAt = AtomicLong()

        override fun call(operation: T3Operation, parameters: Map<String, String>): T3Response {
            calls += operation
            return when (operation) {
                T3Operation.HEARTBEAT -> if (disabled.get()) {
                    disabledAt.compareAndSet(0L, SystemClock.elapsedRealtime())
                    T3Response(201, "程序已禁用")
                } else T3Response(200)
                T3Operation.NOTICE -> T3Response(200, "fixture notice")
                else -> error("Unexpected fixture operation: $operation")
            }
        }
    }
}
