package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.schema.GrantIntent
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SuperuserSyncTest {
    private val identity = Fixtures.identity()

    private fun sync(
        control: TestControl,
        backends: List<SuperuserBackend>,
        clock: TestClock,
    ) = DefaultSuperuserSync(control.plane, backends, clock)

    private fun allowEntry() = Fixtures.shared(
        revision = 1, entries = listOf(Fixtures.intentFrom(identity)),
    )

    private fun denyEntry() = Fixtures.shared(
        revision = 1, entries = listOf(Fixtures.intentFrom(identity, GrantIntent.DENY)),
    )

    private fun backendWithIdentity(allow: Boolean = false): FakeBackend =
        FakeBackend(BackendId.A_DIRECT).apply { seed(identity, allow = allow) }

    @Test
    fun exportBackendUnavailableBlocksSwitch() = runBlocking {
        TestControl.create().use { control ->
            val backend = backendWithIdentity().apply { available = false }
            val result = sync(control, listOf(backend), control.clock).exportBeforeSwitch(WorkMode.LITE, 0)
            assertTrue(result is ExportResult.Blocked)
            assertEquals("SUPERUSER_BACKEND_UNAVAILABLE", (result as ExportResult.Blocked).code)
        }
    }

    @Test
    fun exportEnumerateFailureBlocksSwitch() = runBlocking {
        TestControl.create().use { control ->
            val backend = backendWithIdentity().apply { enumerateFailure = true }
            val sync = sync(control, listOf(backend), control.clock)
            val result = sync.exportBeforeSwitch(WorkMode.LITE, 0)
            assertEquals("SUPERUSER_ENUMERATE_FAILED", (result as ExportResult.Blocked).code)
            assertEquals(SyncState.BLOCKED, sync.status().state)
        }
    }

    @Test
    fun exportWritesRevisionAndPrevGeneration() = runBlocking {
        TestControl.create().use { control ->
            val backend = backendWithIdentity(allow = true)
            val sync = sync(control, listOf(backend), control.clock)
            val first = sync.exportBeforeSwitch(WorkMode.LITE, 0)
            assertTrue(first is ExportResult.Ok)
            assertEquals(1, (first as ExportResult.Ok).revision)
            assertEquals(1, first.allowed)
            assertEquals(1, control.read().revision)

            control.clock.now = 2_000L
            val second = sync.exportBeforeSwitch(WorkMode.LITE, 0)
            assertEquals(2, (second as ExportResult.Ok).revision)
            assertEquals(2, control.read().revision)
            assertTrue(java.io.File(control.root, "shared/superuser.json.prev").isFile)
        }
    }

    @Test
    fun exportMergesObservedGrantsWithOrigin() = runBlocking {
        TestControl.create(now = 7_000L).use { control ->
            val backend = backendWithIdentity(allow = true)
            sync(control, listOf(backend), control.clock).exportBeforeSwitch(WorkMode.LITE, 0)
            val entry = control.read().entries.single()
            assertEquals(GrantIntent.ALLOW, entry.decision)
            assertEquals("A", entry.origin)
            assertEquals(7_000L, entry.decidedAt)
        }
    }

    @Test
    fun applySuccessWritesAppliedMark() = runBlocking {
        TestControl.create().use { control ->
            control.write(allowEntry())
            val backend = backendWithIdentity(allow = false)
            val sync = sync(control, listOf(backend), control.clock)
            val result = sync.reconcileAfterBoot(WorkMode.LITE)
            assertEquals(1, result.applied)
            assertEquals(0, result.failed)
            assertEquals(SyncState.VERIFIED, result.state)
            val entry = control.read().entries.single()
            val mark = entry.applied.single { it.backend == "A_DIRECT" }
            assertTrue(mark.ok)
            assertEquals(1, mark.rev)
            assertEquals(1, backend.mutations)
        }
    }

    @Test
    fun applyFailureGoesPartialPendingWithoutOkMark() = runBlocking {
        TestControl.create().use { control ->
            control.write(allowEntry())
            val backend = backendWithIdentity(allow = false).apply { applyFailure = true }
            val sync = sync(control, listOf(backend), control.clock)
            val result = sync.reconcileAfterBoot(WorkMode.LITE)
            assertEquals(1, result.failed)
            assertEquals(SyncState.PARTIAL_PENDING, result.state)
            val entry = control.read().entries.single()
            assertTrue(entry.applied.none { it.backend == "A_DIRECT" && it.ok })
            assertEquals(1, entry.pending?.attempts)
            assertEquals("TEST_GRANT_FAILED", entry.pending?.lastError)
            assertEquals(SyncState.PARTIAL_PENDING, sync.status().state)
        }
    }

    @Test
    fun verifyMismatchIsNotOk() = runBlocking {
        TestControl.create().use { control ->
            control.write(allowEntry())
            // apply 声称成功，但 verify 看不到 → 发布红线 8：不得写 ok=true。
            val backend = backendWithIdentity(allow = false).apply { verifyOverride = emptyList() }
            val sync = sync(control, listOf(backend), control.clock)
            val result = sync.reconcileAfterBoot(WorkMode.LITE)
            assertEquals(0, result.applied)
            assertEquals(1, result.failed)
            val entry = control.read().entries.single()
            assertTrue(entry.applied.none { it.backend == "A_DIRECT" })
            assertEquals("VERIFY_MISMATCH", entry.pending?.lastError)
        }
    }

    @Test
    fun dangerousRevokeFailureIsReported() = runBlocking {
        TestControl.create().use { control ->
            control.write(denyEntry())
            val backend = backendWithIdentity(allow = true).apply { failRevokes = true }
            val result = sync(control, listOf(backend), control.clock).reconcileAfterBoot(WorkMode.LITE)
            assertEquals(1, result.failed)
            assertEquals(1, result.dangerousRevokeFailures.size)
            assertEquals(ApplyReport.OP_REVOKE, result.dangerousRevokeFailures.single().op)
            assertEquals(SyncState.PARTIAL_PENDING, result.state)
            assertEquals(true, backend.allowState(Fixtures.APP))
        }
    }

    @Test
    fun revokeSucceedsAndClearsExistingGrant() = runBlocking {
        TestControl.create().use { control ->
            control.write(denyEntry())
            val backend = backendWithIdentity(allow = true)
            val result = sync(control, listOf(backend), control.clock).reconcileAfterBoot(WorkMode.LITE)
            assertEquals(1, result.applied)
            assertEquals(0, result.failed)
            assertEquals(false, backend.allowState(Fixtures.APP))
        }
    }

    @Test
    fun pendingAttemptsIncrementAndBackoffAtThree() = runBlocking {
        TestControl.create().use { control ->
            control.write(allowEntry())
            val backend = backendWithIdentity(allow = false).apply { applyFailure = true }
            val sync = sync(control, listOf(backend), control.clock)
            repeat(3) {
                control.clock.now += 1_000L
                sync.reconcileAfterBoot(WorkMode.LITE)
            }
            val entry = control.read().entries.single()
            assertEquals(3, entry.pending?.attempts)
            assertEquals(SyncState.BACKOFF, sync.status().state)
        }
    }

    @Test
    fun bootReconcileIsIdempotent() = runBlocking {
        TestControl.create().use { control ->
            control.write(allowEntry())
            val backend = backendWithIdentity(allow = false)
            val sync = sync(control, listOf(backend), control.clock)
            sync.reconcileAfterBoot(WorkMode.LITE)
            val mutationsAfterFirst = backend.mutations
            val entriesAfterFirst = control.read().entries
            val second = sync.reconcileAfterBoot(WorkMode.LITE)
            assertEquals(mutationsAfterFirst, backend.mutations)
            assertEquals(entriesAfterFirst.size, control.read().entries.size)
            assertEquals(SyncState.VERIFIED, second.state)
        }
    }

    @Test
    fun tombstoneReplaysRevokeOnBoot() = runBlocking {
        TestControl.create().use { control ->
            val older = Fixtures.intentFrom(identity).copy(decidedAt = 1_000L)
            control.write(Fixtures.shared(
                revision = 1,
                entries = listOf(older),
                tombs = listOf(Fixtures.tomb(revokedAt = 2_000L)),
            ))
            val backend = backendWithIdentity(allow = true)
            val result = sync(control, listOf(backend), control.clock).reconcileAfterBoot(WorkMode.LITE)
            assertEquals(false, backend.allowState(Fixtures.APP))
            assertTrue(result.applied >= 1)
        }
    }

    @Test
    fun missingSharedIsNothingToDo() = runBlocking {
        TestControl.create().use { control ->
            val backend = FakeBackend(BackendId.A_DIRECT)
            val result = sync(control, listOf(backend), control.clock).reconcileAfterBoot(WorkMode.LITE)
            assertEquals(SyncState.IDLE, result.state)
            assertEquals(0, result.applied)
        }
    }

    @Test
    fun corruptSharedBlocksReconcileAndExport() = runBlocking {
        TestControl.create().use { control ->
            control.writeRaw("{not-json")
            val backend = backendWithIdentity(allow = true)
            val sync = sync(control, listOf(backend), control.clock)
            val reconcile = sync.reconcileAfterBoot(WorkMode.LITE)
            assertEquals(SyncState.BLOCKED, reconcile.state)
            assertEquals(SyncState.BLOCKED, sync.status().state)
            val export = sync.exportBeforeSwitch(WorkMode.LITE, 0)
            assertEquals("SHARED_CORRUPT", (export as ExportResult.Blocked).code)
        }
    }

    @Test
    fun ksuModeUsesKsuBackendAndAppliesPackageDecision() = runBlocking {
        TestControl.create().use { control ->
            control.write(allowEntry())
            val backend = FakeBackend(BackendId.B_KSU)
            val result = sync(control, listOf(backend), control.clock).reconcileAfterBoot(WorkMode.KSU)
            assertEquals(1, result.applied)
            assertEquals(true, backend.allowState(Fixtures.APP))
            val mark = control.read().entries.single().applied.single()
            assertEquals("B_KSU", mark.backend)
        }
    }
}
