package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.switch.HookResult
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/** P0/W19：真实写者静默（门控位/组件停用/组合失败 fail-closed）+ 静默期拒绝新植入。 */
class LiteWriterQuiescenceTest {
    @After
    fun tearDown() {
        LiteImplantQuiesceGate.resetForTest()
        LiteImplantRecorderProvider.resetForTest()
    }

    private class FakeStopper(
        var stopResult: HookResult = HookResult.OK,
        var restoreResult: HookResult = HookResult.OK,
    ) : LiteWriterStopper {
        var stops = 0
        var restores = 0
        override fun stop(): HookResult {
            stops++
            return stopResult
        }

        override fun restore(): HookResult {
            restores++
            return restoreResult
        }
    }

    private class CountingRecorder : LiteImplantRecorder {
        var beforeDelivery = 0
        override fun beforeDelivery(
            packageName: String, uid: Int, deliverPath: String,
            deliverSha256: String, createdDirs: List<String>, now: Long,
        ): ImplantPreparation {
            beforeDelivery++
            return ImplantPreparation(ok = true)
        }

        override fun afterDelivery(preparation: ImplantPreparation) = Unit
        override fun beforeWiring(
            packageName: String, uid: Int, targetLibraryPath: String, deliverPath: String,
            deliverSha256: String, createdDirs: List<String>, now: Long,
        ) = ImplantPreparation(ok = true)

        override fun afterWiring(preparation: ImplantPreparation) = Unit
        override fun recordPathInjection(
            packageName: String, uid: Int, deliverPath: String, deliverSha256: String, now: Long,
        ) = ImplantPreparation(ok = true)
    }

    @Test
    fun gateEnterLeaveIsIdempotent() {
        assertFalse(LiteImplantQuiesceGate.isBlocked())
        assertTrue(LiteImplantQuiesceGate.tryEnter("switch"))
        assertFalse(LiteImplantQuiesceGate.tryEnter("again"))
        assertTrue(LiteImplantQuiesceGate.isBlocked())
        assertEquals(LiteImplantCodes.QUIESCING, LiteImplantQuiesceGate.blockedCode())
        LiteImplantQuiesceGate.leave()
        LiteImplantQuiesceGate.leave()
        assertFalse(LiteImplantQuiesceGate.isBlocked())
    }

    @Test
    fun gateGuardedRecorderRejectsNewImplantsWhileQuiescing() {
        val delegate = CountingRecorder()
        val recorder = GateGuardedLiteImplantRecorder(delegate)
        assertTrue(recorder.beforeDelivery("com.example.app", 1, "/x/su", "", emptyList(), 1L).ok)
        assertEquals(1, delegate.beforeDelivery)

        LiteImplantQuiesceGate.tryEnter()
        val rejected = recorder.beforeDelivery("com.example.app", 1, "/x/su", "", emptyList(), 1L)
        assertFalse(rejected.ok)
        assertEquals(LiteImplantCodes.QUIESCING, rejected.code)
        assertEquals(1, delegate.beforeDelivery)

        LiteImplantQuiesceGate.leave()
        assertTrue(recorder.beforeDelivery("com.example.app", 1, "/x/su", "", emptyList(), 1L).ok)
        assertEquals(2, delegate.beforeDelivery)
    }

    @Test
    fun registryRecorderAlsoRejectsWhileGateEntered() {
        val root = Files.createTempDirectory("maplesu-quiesce-recorder-").toFile()
        try {
            val runner = RootScriptRunner { RootScriptResult(0, "ORIGINAL:ABSENT\n") }
            val (recorder, registry) = createLiteImplantRecorder(root, runner)
            LiteImplantQuiesceGate.tryEnter()
            val rejected = recorder.beforeDelivery("com.example.app", 1, "/x/su", "a".repeat(64), emptyList(), 1L)
            assertFalse(rejected.ok)
            assertEquals(LiteImplantCodes.QUIESCING, rejected.code)
            assertTrue(registry.pending().isEmpty())
            LiteImplantQuiesceGate.leave()
            assertTrue(
                recorder.beforeDelivery("com.example.app", 1, "/x/su", "a".repeat(64), emptyList(), 1L).ok,
            )
            assertEquals(1, registry.pending().size)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun compositeStopFailureRollsBackStoppedWriters() {
        val first = FakeStopper()
        val second = FakeStopper(stopResult = HookResult.failed(LiteImplantCodes.QUIESCE_FAILED, "boom"))
        val composite = CompositeLiteWriterStopper(listOf(first, second))
        val result = composite.stop()
        assertFalse(result.ok)
        assertEquals(LiteImplantCodes.QUIESCE_FAILED, result.code)
        assertEquals(1, first.stops)
        assertEquals("already-stopped writers must be restored", 1, first.restores)
    }

    @Test
    fun compositeRestoreIsReverseOrderAndReportsFailure() {
        val order = mutableListOf<String>()
        val first = object : LiteWriterStopper {
            override fun stop() = HookResult.OK
            override fun restore(): HookResult {
                order += "first"
                return HookResult.OK
            }
        }
        val second = object : LiteWriterStopper {
            override fun stop() = HookResult.OK
            override fun restore(): HookResult {
                order += "second"
                return HookResult.failed(LiteImplantQuiesceHooks.RESTORE_WRITERS_FAILED, "restore boom")
            }
        }
        val result = CompositeLiteWriterStopper(listOf(first, second)).restore()
        assertFalse(result.ok)
        assertEquals(LiteImplantQuiesceHooks.RESTORE_WRITERS_FAILED, result.code)
        assertEquals(listOf("second", "first"), order)
    }

    @Test
    fun hooksStopFailurePropagatesQuiesceFailedAndStaysQuiescing() {
        val registry = EmptyLiteImplantRegistry
        val hooks = LiteImplantQuiesceHooks(
            registry,
            stopSourceWriters = { HookResult.failed(LiteImplantCodes.QUIESCE_FAILED, "stop failed") },
        )
        val result = hooks.quiesce(WorkMode.LITE)
        assertFalse(result.ok)
        assertEquals(LiteImplantCodes.QUIESCE_FAILED, result.code)
        assertTrue("failed quiesce must stay quiesced", hooks.isQuiescing())
    }

    @Test
    fun hooksRestoreFailurePropagatesRestoreWritersFailedButClearsQuiescing() {
        val hooks = LiteImplantQuiesceHooks(
            EmptyLiteImplantRegistry,
            restoreSourceWriters = { HookResult.failed(LiteImplantQuiesceHooks.RESTORE_WRITERS_FAILED, "restore") },
        )
        hooks.quiesce(WorkMode.LITE)
        val result = hooks.restoreAfterFailure(WorkMode.LITE)
        assertFalse(result.ok)
        assertEquals(LiteImplantQuiesceHooks.RESTORE_WRITERS_FAILED, result.code)
        assertFalse(hooks.isQuiescing())
    }

    @Test
    fun gateStopperIsIdempotentAndLeavesGateOnRestore() {
        assertTrue(GateLiteWriterStopper.stop().ok)
        assertTrue(GateLiteWriterStopper.stop().ok)
        assertTrue(LiteImplantQuiesceGate.isBlocked())
        assertTrue(GateLiteWriterStopper.restore().ok)
        assertFalse(LiteImplantQuiesceGate.isBlocked())
    }
}
