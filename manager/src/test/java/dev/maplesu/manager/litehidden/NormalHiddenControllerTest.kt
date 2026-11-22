package dev.maplesu.manager.litehidden

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import dev.maplesu.manager.recovery.RecoveryCommandResult

class NormalHiddenControllerTest {
    private val url = "http://127.0.0.1:18427/x7k9f/${"a".repeat(32)}/"

    @Test fun preparationDoesNotActivateAndActivationNeedsAnExplicitSession() = runBlocking {
        var prepared = 0
        var activated = 0
        val controller = NormalHiddenController({ prepared++; NormalHiddenResult(true, recoveryUrl = url) }, {
            assertEquals(url, it); activated++; NormalHiddenResult(true, recoveryUrl = it)
        })
        assertFalse(controller.activate().ok)
        assertTrue(controller.prepare().ok)
        assertEquals(1, prepared)
        assertEquals(0, activated)
        assertTrue(controller.activate().ok)
        assertEquals(1, activated)
        assertFalse(controller.activate().ok)
    }

    @Test fun cancellationInvalidatesThePreparedLinkWithoutActivation() = runBlocking {
        var activated = 0
        val controller = NormalHiddenController({ NormalHiddenResult(true, recoveryUrl = url) }, {
            activated++; NormalHiddenResult(true)
        })
        assertTrue(controller.prepare().ok)
        controller.cancel()
        assertFalse(controller.activate().ok)
        assertEquals(0, activated)
    }

    @Test fun latePreparationAfterCancelIsDiscardedAndConcurrentCallsAreRejected() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val result = AtomicReference<NormalHiddenResult>()
        val controller = NormalHiddenController({
            entered.countDown(); assertTrue(release.await(5, TimeUnit.SECONDS)); NormalHiddenResult(true, recoveryUrl = url)
        }, { NormalHiddenResult(true) })
        val thread = Thread { result.set(runBlocking { controller.prepare() }) }
        thread.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        assertEquals("NORMAL_HIDDEN_BUSY", runBlocking { controller.prepare() }.code)
        controller.cancel()
        release.countDown()
        thread.join(5_000)
        assertFalse(thread.isAlive)
        assertEquals("NORMAL_PREPARE_CANCELLED", result.get().code)
        assertFalse(runBlocking { controller.activate() }.ok)
    }

    @Test fun invalidPortAndFailedPreparationNeverProduceAnActivationSession() = runBlocking {
        var prepared = 0
        val controller = NormalHiddenController({ prepared++; NormalHiddenResult(false, "fixture") }, { error("activation") })
        assertFalse(controller.prepare(0).ok)
        assertEquals(0, prepared)
        assertFalse(controller.prepare().ok)
        assertFalse(controller.activate().ok)
    }

    @Test fun failedBundleReplacementKeepsTheSameTokenEvenAfterControllerRecreation() {
        var stored: String? = null
        var generated = 0
        val root = HiddenRootRunner { script ->
            if (script.startsWith("if [ -e")) RecoveryCommandResult(0, stored ?: "MAPLESU_TOKEN_ABSENT")
            else {
                assertTrue(script.contains("/data/adb/maplesu/normal-webui-token"))
                assertFalse(script.contains("/recovery/normal-webui-token"))
                stored = script.substringAfter("printf '%s' '").substringBefore('\'')
                RecoveryCommandResult(0, "NORMAL_SESSION_RETAINED")
            }
        }
        val factory = { generated++; "a".repeat(32) }
        val first = NormalHiddenSessionToken(root, factory).resolve(null)
        assertEquals("a".repeat(32), first)
        // RecoveryBundle.prepare may clear recovery/webui.conf before its copy fails.
        assertEquals(first, NormalHiddenSessionToken(root) { error("must reuse persisted token") }.resolve(null))
        assertEquals(1, generated)
    }

    @Test fun unreadableOrCorruptTokenStoreStopsBeforeReplacingRecoveryBundle() {
        assertNull(NormalHiddenSessionToken({ RecoveryCommandResult(1, "") }).resolve(null))
        assertNull(NormalHiddenSessionToken({ RecoveryCommandResult(0, "corrupt") }).resolve(null))
    }
}
