package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.switch.HookResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/** W19 钩子：S0-15 证据、静默期拒绝新植入、撤回可重试/幂等、结构化错误码。 */
class LiteImplantQuiesceHooksTest {

    private class FakeOriginals(var present: Boolean = true) : OriginalBackupStore {
        override fun hasOriginal(intent: ImplantIntent): Boolean = present
    }

    private class FakeReverter(var succeed: Boolean = true) : ImplantReverter {
        val calls = mutableListOf<String>()
        override fun revert(intent: ImplantIntent): Boolean {
            calls += intent.packageName
            return succeed
        }
    }

    private class FakeRecorder : LiteImplantRecorder {
        var beforeDeliveryCalls = 0
        var pathInjectionCalls = 0
        override fun beforeDelivery(
            packageName: String,
            uid: Int,
            deliverPath: String,
            deliverSha256: String,
            createdDirs: List<String>,
            now: Long,
        ): ImplantPreparation {
            beforeDeliveryCalls++
            return ImplantPreparation(ok = true)
        }

        override fun afterDelivery(preparation: ImplantPreparation) = Unit
        override fun beforeWiring(
            packageName: String,
            uid: Int,
            targetLibraryPath: String,
            deliverPath: String,
            deliverSha256: String,
            createdDirs: List<String>,
            now: Long,
        ): ImplantPreparation = ImplantPreparation(ok = true)

        override fun afterWiring(preparation: ImplantPreparation) = Unit
        override fun recordPathInjection(
            packageName: String,
            uid: Int,
            deliverPath: String,
            deliverSha256: String,
            now: Long,
        ): ImplantPreparation {
            pathInjectionCalls++
            return ImplantPreparation(ok = true)
        }
    }

    private fun intent(packageName: String = "com.example.app") = ImplantIntent(
        packageName = packageName,
        uid = 10_200,
        deliverPath = "/data/app/$packageName/lib/arm64/su",
        deliverSha256 = "d".repeat(64),
        wiringTargetLib = "/data/app/$packageName/lib/arm64/libfoo.so",
        wiringOriginalSha256 = "e".repeat(64),
        createdDirs = listOf("/data/app/$packageName/lib/arm64"),
        recordedAt = 1_000L,
        kind = ImplantKinds.WIRING,
    )

    private fun fixture(
        originals: FakeOriginals = FakeOriginals(),
        reverter: FakeReverter = FakeReverter(),
    ): Triple<File, FileLiteImplantRegistry, FakeReverter> {
        val root = Files.createTempDirectory("maplesu-implant-hooks-").toFile()
        return Triple(root, FileLiteImplantRegistry(root, originals, reverter), reverter)
    }

    @Test
    fun implantRestoreReadyFalseWhenOriginalMissing() {
        val (root, registry, _) = fixture(FakeOriginals(present = false))
        try {
            registry.record(intent())
            assertFalse(LiteImplantQuiesceHooks(registry).implantRestoreReady())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun implantRestoreReadyTrueWhenEmptyOrEvidencePresent() {
        val (root, registry, _) = fixture()
        try {
            assertTrue(LiteImplantQuiesceHooks(registry).implantRestoreReady())
            registry.record(intent())
            assertTrue(LiteImplantQuiesceHooks(registry).implantRestoreReady())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun quiesceBlocksNewImplantsUntilRestored() {
        val (root, registry, _) = fixture()
        try {
            val hooks = LiteImplantQuiesceHooks(registry)
            val delegate = FakeRecorder()
            val recorder = hooks.guardedRecorder(delegate)
            assertTrue(hooks.withdrawLiteImplants().ok)
            assertEquals(HookResult.OK, hooks.quiesce(WorkMode.LITE))
            assertTrue(hooks.isQuiescing())
            val rejected = recorder.beforeDelivery("com.example.app", 1, "/x/su", "", emptyList(), 1L)
            assertFalse(rejected.ok)
            assertEquals(LiteImplantCodes.QUIESCING, rejected.code)
            assertEquals(0, delegate.beforeDeliveryCalls)
            assertTrue(hooks.restoreAfterFailure(WorkMode.LITE).ok)
            assertFalse(hooks.isQuiescing())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun guardedRecorderDelegatesWhenNotQuiescing() {
        val (root, registry, _) = fixture()
        try {
            val delegate = FakeRecorder()
            val hooks = LiteImplantQuiesceHooks(registry)
            val recorder = hooks.guardedRecorder(delegate)
            assertTrue(recorder.beforeDelivery("com.example.app", 1, "/x/su", "", emptyList(), 1L).ok)
            assertEquals(1, delegate.beforeDeliveryCalls)
            assertTrue(recorder.recordPathInjection("com.example.app", 1, "/x/su", "", 1L).ok)
            assertEquals(1, delegate.pathInjectionCalls)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun withdrawReportsMissingOriginalAsImplantRestoreMissing() {
        val (root, registry, _) = fixture(FakeOriginals(present = false))
        try {
            registry.record(intent())
            val result = LiteImplantQuiesceHooks(registry).withdrawLiteImplants()
            assertFalse(result.ok)
            assertEquals(LiteImplantCodes.IMPLANT_RESTORE_MISSING, result.code)
            assertEquals(1, registry.pending().size)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun withdrawIsRetryableAfterFailureThenSucceeds() {
        val (root, registry, reverter) = fixture()
        try {
            registry.record(intent())
            val hooks = LiteImplantQuiesceHooks(registry)
            reverter.succeed = false
            val failed = hooks.withdrawLiteImplants()
            assertFalse(failed.ok)
            assertEquals(LiteImplantCodes.REVERT_FAILED, failed.code)
            assertEquals(1, registry.pending().size)

            reverter.succeed = true
            val retried = hooks.withdrawLiteImplants()
            assertTrue(retried.ok)
            assertTrue(registry.pending().isEmpty())
            // 幂等：再撤一次仍成功且无副作用。
            assertTrue(hooks.withdrawLiteImplants().ok)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun withdrawEmptyRegistryIsOkIdempotent() {
        val (root, registry, _) = fixture()
        try {
            val hooks = LiteImplantQuiesceHooks(registry)
            assertTrue(hooks.withdrawLiteImplants().ok)
            assertTrue(hooks.withdrawLiteImplants().ok)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun quiesceFailurePropagatesStructuredCode() {
        val (root, registry, _) = fixture()
        try {
            val hooks = LiteImplantQuiesceHooks(
                registry,
                stopSourceWriters = { HookResult.failed("LITE_WRITER_STOP_FAILED", "demo") },
            )
            val result = hooks.quiesce(WorkMode.LITE)
            assertFalse(result.ok)
            assertEquals("LITE_WRITER_STOP_FAILED", result.code)
            // 失败也要保持静默（撤回/回滚期间不得出现新植入）。
            assertTrue(hooks.isQuiescing())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun producerSideEffectsDelegateAndPropagateFailure() {
        val (root, registry, _) = fixture()
        try {
            val ok = LiteImplantQuiesceHooks(registry, producerSideEffectsCleanup = { HookResult.OK })
            assertTrue(ok.restoreProducerSideEffects().ok)
            val failed = LiteImplantQuiesceHooks(
                registry,
                producerSideEffectsCleanup = { HookResult.failed(LiteImplantQuiesceHooks.PRODUCER_CLEANUP_FAILED, "x") },
            )
            assertEquals(
                LiteImplantQuiesceHooks.PRODUCER_CLEANUP_FAILED,
                failed.restoreProducerSideEffects().code,
            )
        } finally {
            root.deleteRecursively()
        }
    }
}
