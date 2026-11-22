package dev.maplesu.manager.workmode.switch

import dev.maplesu.installer.SwitchPlan
import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.ModeState
import dev.maplesu.manager.workmode.storage.MoveEntry
import dev.maplesu.manager.workmode.storage.MoveKind
import dev.maplesu.manager.workmode.storage.MoveMount
import dev.maplesu.manager.workmode.storage.MovePathRoots
import dev.maplesu.manager.workmode.storage.MoveSet
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.UUID

/**
 * S4「交换配置」真实实现测试：`MoveSet` → `FileMoveExecutor` 的出仓/入仓/物化/逆序回滚，
 * 以及 `ModeSwitchController.commitPhase` 的 4b→4c/4d→4e→4f 顺序、失败回滚、
 * 备份证据 manifest、幂等重放。
 */
private fun bytesOf(char: Char): ByteArray = ByteArray(4096) { char.code.toByte() }

class ModeSwitchMoveStageTest {

    private class StageHarness {
        val temp: File = TestFixtures.tempDir("movestage").toFile()
        val liveRoot = File(temp, "live").apply { mkdirs() }
        val storeRoot = File(temp, "store").apply { mkdirs() }
        val roots = MovePathRoots(liveRoot, storeRoot)
        val stage = FileSwitchMoveStage(roots)
        val journal = RecordingSwitchJournal()
        val switchId = UUID.randomUUID().toString()

        fun plan(from: WorkMode = WorkMode.LITE, to: WorkMode = WorkMode.KSU): MoveStagePlan =
            stage.plan(switchId, from, to)

        fun live(path: String): File = roots.live(path)

        fun store(owner: WorkMode, path: String): File = roots.store(MoveSet.storePathFor(owner, path))

        fun seedModules(live: Boolean = true) {
            val target = if (live) this.live("/data/adb/maplesu-su-policy") else store(WorkMode.KSU, "/metadata/ksu")
            target.mkdirs()
            File(target, "demo").apply { mkdirs() }
            File(target, "demo/module.prop").writeText("id=demo")
        }

        fun seedMetamoduleSymlink(): Boolean = runCatching {
            val modules = live("/data/adb/maplesu-su-policy")
            if (!modules.exists()) modules.mkdirs()
            Files.createSymbolicLink(live("/data/adb/metamodule").toPath(), modules.toPath())
            true
        }.getOrDefault(false)
    }

    // ------------------------------------------------------------------ plan / 校验

    @Test
    fun planBuildsOutboundAndInboundInContractOrder() {
        val h = StageHarness()
        val liteToKsu = h.plan(WorkMode.LITE, WorkMode.KSU)
        assertTrue(liteToKsu.validationErrors.joinToString(), liteToKsu.ok)
        assertEquals(MoveSet.outboundOrder(MoveSet.LITE_MOVE_SET).map { it.livePath },
            liteToKsu.plan.outbound.map { it.livePath })
        assertEquals(MoveSet.inboundOrder(MoveSet.KSU_MOVE_SET).map { it.livePath },
            liteToKsu.plan.inbound.map { it.livePath })
        assertTrue(MoveSet.NEVER_MOVE.isNotEmpty())
    }

    @Test
    fun planRejectsNeverMoveAndControlRoot() {
        val h = StageHarness()
        val bad = FileSwitchMoveStage(
            h.roots,
            dynamicFrom = listOf(
                MoveEntry("/data/adb", MoveKind.TREE, MoveMount.SAME_AS_STORE, WorkMode.LITE, MoveEntry.REAL_DIR),
            ),
        ).plan(h.switchId, WorkMode.LITE, WorkMode.KSU)
        assertFalse(bad.ok)
        assertTrue(bad.validationErrors.any { it.startsWith(MoveSet.Errors.FORBIDDEN_PATH) })
        assertEquals("MOVE_PLAN_INVALID", h.stage.moveOut(bad, h.journal).code)
    }

    @Test
    fun planRejectsMetadataEntryNotMarkedCrossMount() {
        val h = StageHarness()
        val bad = FileSwitchMoveStage(
            h.roots,
            dynamicFrom = listOf(
                MoveEntry("/metadata/x", MoveKind.TREE, MoveMount.SAME_AS_STORE, WorkMode.LITE, MoveEntry.REAL_DIR),
            ),
        ).plan(h.switchId, WorkMode.LITE, WorkMode.KSU)
        assertFalse(bad.ok)
        assertTrue(bad.validationErrors.any { it.startsWith(MoveSet.Errors.EXDEV_UNSUPPORTED) })
    }

    // ------------------------------------------------------------------ 出仓 / 入仓 / 回滚

    @Test
    fun moveOutMovesLiveToStoreAndJournals() {
        val h = StageHarness()
        h.seedModules()
        val result = h.stage.moveOut(h.plan(), h.journal)
        assertTrue("${result.code}/${result.detail}", result.ok)
        assertTrue(h.store(WorkMode.LITE, "/data/adb/maplesu-su-policy").isDirectory)
        assertFalse(h.live("/data/adb/maplesu-su-policy").exists())
        assertEquals("id=demo",
            File(h.store(WorkMode.LITE, "/data/adb/maplesu-su-policy"), "demo/module.prop").readText())
        assertTrue(h.journal.lines.any { it.op == SwitchOp.MOVE_INTENT.wire })
        assertTrue(h.journal.lines.any { it.op == SwitchOp.MOVE_DONE.wire })
        assertTrue(result.report!!.movedOut.contains("/data/adb/maplesu-su-policy"))
    }

    @Test
    fun moveInMovesTargetStoreToLive() {
        val h = StageHarness()
        h.seedModules(live = false) // KSU 离线仓里已有目标模式配置
        val plan = h.plan()
        val result = h.stage.moveIn(plan, h.journal)
        assertTrue("${result.code}/${result.detail}", result.ok)
        assertTrue(h.live("/metadata/ksu").isDirectory)
        assertFalse(h.store(WorkMode.KSU, "/metadata/ksu").exists())
        assertEquals("id=demo", File(h.live("/metadata/ksu"), "demo/module.prop").readText())
    }

    @Test
    fun moveOutSkipsAbsentEntriesWithoutFailing() {
        val h = StageHarness()
        val result = h.stage.moveOut(h.plan(), h.journal)
        assertTrue(result.ok)
        assertTrue(result.report!!.skipped.isNotEmpty())
        assertTrue(result.report!!.movedOut.isEmpty())
    }

    @Test
    fun manifestIsWrittenAsBackupEvidence() {
        val h = StageHarness()
        h.seedModules()
        val plan = h.plan()
        assertTrue(h.stage.moveOut(plan, h.journal).ok)
        val manifest = File(plan.manifest.path)
        assertTrue(manifest.isFile)
        val text = manifest.readText()
        assertTrue(text.contains("\"phase\":\"OUT\""))
        assertTrue(text.contains("/data/adb/maplesu-su-policy"))
        assertTrue(text.contains("storeExists=true"))
    }

    @Test
    fun rollbackRestoresLiveTreeAfterMoveOut() {
        val h = StageHarness()
        h.seedModules()
        val plan = h.plan()
        assertTrue(h.stage.moveOut(plan, h.journal).ok)
        val rollback = h.stage.rollback(plan, h.journal)
        assertTrue("${rollback.code}/${rollback.detail}", rollback.ok)
        assertTrue(h.live("/data/adb/maplesu-su-policy").isDirectory)
        assertFalse(h.store(WorkMode.LITE, "/data/adb/maplesu-su-policy").exists())
        assertEquals("id=demo", File(h.live("/data/adb/maplesu-su-policy"), "demo/module.prop").readText())
    }

    @Test
    fun moveOutFailsWhenStoreDestinationAlreadyExists() {
        val h = StageHarness()
        h.seedModules()
        h.store(WorkMode.LITE, "/data/adb/maplesu-su-policy").mkdirs()
        val result = h.stage.moveOut(h.plan(), h.journal)
        assertFalse(result.ok)
        assertEquals("MOVE_OUT_FAILED", result.code)
    }

    @Test
    fun verifyKeepsBackupAfterMoveOutAndClearsStoreAfterMoveIn() {
        val h = StageHarness()
        h.seedModules()
        val plan = h.plan()
        assertTrue(h.stage.moveOut(plan, h.journal).ok)
        assertTrue("outbound backup must be verifiable", h.stage.verify(plan).ok)
        assertTrue(h.stage.moveIn(plan, h.journal).ok)
        assertTrue(h.stage.verify(plan).ok)
    }

    @Test
    fun materializeWritesManifestAndPassesInvariants() {
        val h = StageHarness()
        h.seedModules()
        val plan = h.plan()
        assertTrue(h.stage.moveOut(plan, h.journal).ok)
        assertTrue(h.stage.moveIn(plan, h.journal).ok)
        val materialized = h.stage.materialize(plan, h.journal)
        assertTrue("${materialized.code}/${materialized.detail}", materialized.ok)
        assertTrue(File(plan.manifest.path).readText().contains("\"phase\":\"MATERIALIZE\""))
    }

    @Test
    fun repeatedMoveOutIsIdempotent() {
        val h = StageHarness()
        h.seedModules()
        val plan = h.plan()
        assertTrue(h.stage.moveOut(plan, h.journal).ok)
        val second = h.stage.moveOut(plan, h.journal)
        assertTrue(second.ok)
        assertTrue(second.report!!.skipped.isNotEmpty())
    }

    @Test
    fun crossMountEntryUsesCopyPathAndKeepsBytes() {
        val h = StageHarness()
        val metadata = h.live("/metadata/ksu").apply { mkdirs() }
        File(metadata, "blob").writeText("x".repeat(4096))
        val plan = FileSwitchMoveStage(
            h.roots,
            dynamicFrom = listOf(
                MoveEntry("/metadata/ksu", MoveKind.TREE, MoveMount.CROSS_MOUNT_COPY, WorkMode.LITE, MoveEntry.REAL_DIR),
            ),
        ).plan(h.switchId, WorkMode.LITE, WorkMode.KSU)
        assertTrue(plan.ok)
        assertTrue(h.stage.moveOut(plan, h.journal).ok)
        val stored = h.store(WorkMode.LITE, "/metadata/ksu")
        assertTrue(stored.isDirectory)
        assertEquals("x".repeat(4096), File(stored, "blob").readText())
    }

    @Test
    fun symlinkTargetIsRestoredByRollback() {
        val h = StageHarness()
        assumeTrue("symlink unsupported", h.seedMetamoduleSymlink())
        val plan = h.plan()
        assertTrue(h.stage.moveOut(plan, h.journal).ok)
        assertTrue(h.stage.rollback(plan, h.journal).ok)
        val link = h.live("/data/adb/metamodule")
        assertTrue(Files.isSymbolicLink(link.toPath()))
        assertEquals(h.live("/data/adb/maplesu-su-policy").toPath(), Files.readSymbolicLink(link.toPath()))
    }

    // ------------------------------------------------------------------ controller S4 编排

    /** 轻量网关：记录调用顺序 + 可注入 commit 结果；内容与摘要保持一致（供 plan 校验）。 */
    private class StubGateway : InstallerGateway {
        val calls = mutableListOf<String>()
        var onCommit: (() -> Unit)? = null
        var commitOutcome = GatewayOutcome(true, GatewayState.WRITTEN)
        var rollbackOutcome = GatewayOutcome(true, GatewayState.ROLLED_BACK)
        var lastPlan: SwitchPlan? = null

        private val pre = mapOf(
            "boot" to ByteArray(4096) { 'P'.code.toByte() },
            "init_boot" to ByteArray(4096) { 'S'.code.toByte() },
        )
        private val base = mapOf(
            "boot" to ByteArray(4096) { 'B'.code.toByte() },
            "init_boot" to ByteArray(4096) { 'I'.code.toByte() },
        )
        val partitions = listOf(
            SwitchPartitionStatus("boot", "RESTORE_BASELINE", 4096,
                Hashes.sha256(pre.getValue("boot")), Hashes.sha256(base.getValue("boot")), "r".repeat(64), "", "PENDING"),
            SwitchPartitionStatus("init_boot", "WRITE_CANDIDATE", 4096,
                Hashes.sha256(pre.getValue("init_boot")), Hashes.sha256(base.getValue("init_boot")), "s".repeat(64), "", "PENDING"),
        )

        override fun preflight(request: ModeSwitchRequest) = GatewayPreflight(true)

        override fun begin(request: ModeSwitchRequest, inputs: BeginInputs) = GatewayOutcome(true, GatewayState.WRITTEN)

        override fun snapshot(request: ModeSwitchRequest) = GatewayOutcome(
            true, GatewayState.WRITTEN,
            status = GatewayStatus(request.switchId, "SNAPSHOT", "S2", "snapshot", partitions = partitions),
        )

        override fun exportImage(request: ModeSwitchRequest, kind: String, partition: String,
                                 destination: File): ExportedImage {
            val bytes = if (kind == "PRE") pre.getValue(partition) else base.getValue(partition)
            destination.parentFile?.mkdirs()
            destination.writeBytes(bytes)
            return ExportedImage(destination, destination.length(), Hashes.sha256(bytes))
        }

        override fun submitCandidate(request: ModeSwitchRequest, partition: String,
                                     image: ExportedImage) = GatewayOutcome(true, GatewayState.WRITTEN)

        override fun preparePlan(request: ModeSwitchRequest, planFlatFields: Map<String, String>): GatewayOutcome =
            try {
                lastPlan = SwitchPlan.parse(planFlatFields)
                GatewayOutcome(true, GatewayState.WRITTEN)
            } catch (failure: dev.maplesu.installer.SwitchFailure) {
                GatewayOutcome(false, "", failure.code, failure.detail)
            }

        override fun commit(request: ModeSwitchRequest): GatewayOutcome {
            calls += "commit"
            onCommit?.invoke()
            val status = GatewayStatus(
                request.switchId, "REBOOT_REQUIRED", "S4", "4g",
                planSha256 = lastPlan?.planSha256.orEmpty(),
                partitions = partitions.map { it.copy(state = "DONE") },
            )
            return if (commitOutcome.ok) commitOutcome.copy(status = status) else commitOutcome
        }

        override fun rollback(request: ModeSwitchRequest): GatewayOutcome {
            calls += "rollback"
            return rollbackOutcome
        }

        override fun abort(request: ModeSwitchRequest) = GatewayOutcome(true, GatewayState.CANCELLED)

        override fun observePartitions(request: ModeSwitchRequest, names: List<String>) =
            emptyList<PartitionObservation>()

        override fun verify(request: ModeSwitchRequest) = GatewayOutcome(true, GatewayState.VERIFIED)

        override fun reboot(request: ModeSwitchRequest): Boolean = true

        override fun status(switchId: String): GatewayStatus? = null

        override fun exportDiagnostics(request: ModeSwitchRequest, destination: File): File {
            destination.writeText("diag")
            return destination
        }
    }

    private class ControllerHarness {
        val temp: File = TestFixtures.tempDir("moves4").toFile()
        val liveRoot = File(temp, "live").apply { mkdirs() }
        val storeRoot = File(temp, "store").apply { mkdirs() }
        val workRoot = File(temp, "work").apply { mkdirs() }
        val roots = MovePathRoots(liveRoot, storeRoot)
        val gateway = StubGateway()
        val journal = RecordingSwitchJournal()
        val authority = InMemorySwitchAuthority()
        var bootId = "boot-1"
        val bootIds = BootIdSource { bootId }
        val clock = Clock { 1_000L }
        val request = ModeSwitchRequest(UUID.randomUUID().toString(), WorkMode.LITE, WorkMode.KSU, "bl-1")
        val environment = object : SwitchEnvironment {
            override fun modeState() = ModeState.MODE_A_ACTIVE
            override fun currentMode() = WorkMode.LITE
            override fun deviceFacts() = SwitchDeviceFacts("_a", "fw", "5.10.198-android13-8-g", "Enforcing")
            override fun battery() = BatteryFacts(80, false)
            override fun pending() = PendingFacts()
            override fun rootRefusal(): String? = null
            override fun controlWritable() = true
            override fun implantRestoreReady() = true
            override fun exportReceipt() = mapOf(
                "boot" to Hashes.sha256(bytesOf('B')),
                "init_boot" to Hashes.sha256(bytesOf('I')),
            )
            override fun partitionInventory() = PartitionInventory(
                present = setOf("boot", "init_boot"),
                sizes = mapOf("boot" to 4096L, "init_boot" to 4096L),
            )
            override fun avb() = SwitchAvbFacts()
            override fun freeBytes() = 1L shl 40
            override fun beginInputs(): BeginInputs {
                val su = File(temp, "su.json").apply { writeText("{}") }
                val settings = File(temp, "settings.json").apply { writeText("{}") }
                return BeginInputs(su, settings)
            }
            override fun targetRootAvailable(to: WorkMode) = true
        }
        val producer = SwitchCandidateProducer { input ->
            val image = File(input.workDir, "candidate.bin")
            image.writeBytes(ByteArray(4096) { 'C'.code.toByte() })
            CandidateResult(image, Hashes.sha256(image.readBytes()), image.length())
        }
        val snapshots = object : ModeSwitchSnapshots {
            override suspend fun preSwitchSnapshot(request: ModeSwitchRequest) = GatewayOutcome(true, "")
            override suspend fun restoreAfterRollback(request: ModeSwitchRequest) = GatewayOutcome(true, "")
        }
        val hooks = object : SwitchQuiesceHooks {
            override fun quiesce(fromMode: WorkMode) = HookResult.OK
            override fun restoreAfterFailure(fromMode: WorkMode) = HookResult.OK
            override fun withdrawLiteImplants() = HookResult.OK
            override fun implantRestoreReady() = true
            override fun restoreProducerSideEffects() = HookResult.OK
        }
        val baseline = FakeBaselineStore(
            BaselineVerification(
                BaselineState.PRESENT_OK, "bl-1",
                BaselineCheck("bl-1", BaselineProvenance.OEM_PACKAGE,
                    Hashes.sha256(bytesOf('B')), Hashes.sha256(bytesOf('I')), true),
                emptyList(), null,
            ),
        )

        fun seedModules() {
            val modules = File(liveRoot, "data/adb/maplesu-su-policy").apply { mkdirs() }
            File(modules, "demo").apply { mkdirs() }
            File(modules, "demo/module.prop").writeText("id=demo")
        }

        fun controller(stage: SwitchMoveStage?): ModeSwitchController = ModeSwitchController(
            gateway = gateway,
            journalFactory = SwitchJournalFactory { journal },
            authority = authority,
            baselines = baseline,
            snapshots = snapshots,
            producer = producer,
            hooks = hooks,
            moveStage = stage,
            environment = environment,
            clock = clock,
            bootIds = bootIds,
            workRoot = workRoot,
        )
    }

    @Test
    fun controllerS4RunsMoveOutBeforeCommitAndKeepsOfflineBackup() = runBlocking {
        val h = ControllerHarness()
        h.seedModules()
        var storeExistsAtCommit = false
        var liveExistsAtCommit = true
        h.gateway.onCommit = {
            storeExistsAtCommit = h.roots.store(MoveSet.storePathFor(WorkMode.LITE, "/data/adb/maplesu-su-policy")).isDirectory
            liveExistsAtCommit = h.roots.live("/data/adb/maplesu-su-policy").exists()
        }
        val run = h.controller(FileSwitchMoveStage(h.roots)).begin(h.request)
        assertTrue("unexpected: $run", run is ModeSwitchRun.AwaitingReboot)
        assertTrue("store must contain backup before partition write", storeExistsAtCommit)
        assertFalse("live moved out before partition write", liveExistsAtCommit)
        // A→B：A 的配置留在 modes/A 离线仓（可切回还原），B 的 live 为空（B 尚无配置）。
        assertTrue(h.roots.store(MoveSet.storePathFor(WorkMode.LITE, "/data/adb/maplesu-su-policy")).isDirectory)
        assertFalse(h.roots.live("/data/adb/maplesu-su-policy").exists())
        val record = h.authority.read(h.request.switchId)!!
        assertEquals("DONE", record.stepState(SwitchSteps.MOVE_OUT))
        assertEquals("DONE", record.stepState(SwitchSteps.MOVE_IN))
        assertEquals("DONE", record.stepState(SwitchSteps.MATERIALIZE))
        assertTrue(record.moves.isNotEmpty())
        assertTrue(h.journal.lines.any { it.op == SwitchOp.MOVE_INTENT.wire && it.step == "4b" })
        assertTrue(h.journal.lines.any { it.op == SwitchOp.MOVE_INTENT.wire && it.step == "4e" })
        assertTrue(h.journal.lines.any { it.op == SwitchOp.MATERIALIZE_INTENT.wire && it.step == "4f" })
    }

    @Test
    fun controllerCommitFailureRollsBackMoveAndRestoresLiveConfig() = runBlocking {
        val h = ControllerHarness()
        h.seedModules()
        h.gateway.commitOutcome = GatewayOutcome(false, GatewayState.ROLLED_BACK, "WRITE_FAILED", "io")
        val run = h.controller(FileSwitchMoveStage(h.roots)).begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(SwitchStateNames.ROLLED_BACK, (run as ModeSwitchRun.Failed).state)
        assertTrue(h.roots.live("/data/adb/maplesu-su-policy").isDirectory)
        assertFalse(h.roots.store(MoveSet.storePathFor(WorkMode.LITE, "/data/adb/maplesu-su-policy")).exists())
        assertEquals("id=demo", File(h.roots.live("/data/adb/maplesu-su-policy"), "demo/module.prop").readText())
    }

    @Test
    fun controllerMoveInFailureRollsBackPartitionsAndConfig() = runBlocking {
        val h = ControllerHarness()
        h.seedModules()
        val failing = object : SwitchMoveStage by FileSwitchMoveStage(h.roots) {
            override fun moveIn(plan: MoveStagePlan, journal: SwitchJournal) =
                MoveStageResult(false, "MOVE_IN_FAILED", "injected")
        }
        val run = h.controller(failing).begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(SwitchStateNames.ROLLED_BACK, (run as ModeSwitchRun.Failed).state)
        assertTrue("partitions must be rolled back", h.gateway.calls.contains("rollback"))
        assertTrue(h.roots.live("/data/adb/maplesu-su-policy").isDirectory)
        assertFalse(h.roots.store(MoveSet.storePathFor(WorkMode.LITE, "/data/adb/maplesu-su-policy")).exists())
    }

    @Test
    fun controllerMaterializeFailureRollsBackAndNeverReportsReboot() = runBlocking {
        val h = ControllerHarness()
        h.seedModules()
        val failing = object : SwitchMoveStage by FileSwitchMoveStage(h.roots) {
            override fun materialize(plan: MoveStagePlan, journal: SwitchJournal) =
                MoveStageResult(false, "MOVE_VERIFY_FAILED", "injected")
        }
        val run = h.controller(failing).begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        assertFalse(run is ModeSwitchRun.AwaitingReboot)
        assertEquals(SwitchStateNames.ROLLED_BACK, (run as ModeSwitchRun.Failed).state)
    }

    @Test
    fun controllerMoveRollbackFailureBecomesRecoveryRequired() = runBlocking {
        val h = ControllerHarness()
        h.seedModules()
        val failing = object : SwitchMoveStage by FileSwitchMoveStage(h.roots) {
            override fun rollback(plan: MoveStagePlan, journal: SwitchJournal) =
                MoveStageResult(false, "MOVE_ROLLBACK_FAILED", "injected")
        }
        h.gateway.commitOutcome = GatewayOutcome(false, GatewayState.ROLLED_BACK, "WRITE_FAILED", "io")
        val run = h.controller(failing).begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(SwitchStateNames.RECOVERY_REQUIRED, (run as ModeSwitchRun.Failed).state)
        assertEquals("MOVE_ROLLBACK_FAILED", run.code)
    }

    @Test
    fun controllerWithoutMoveStageMarksMoveStepsSkipped() = runBlocking {
        val h = ControllerHarness()
        h.seedModules()
        val run = h.controller(null).begin(h.request)
        assertTrue(run is ModeSwitchRun.AwaitingReboot)
        val record = h.authority.read(h.request.switchId)!!
        assertEquals("SKIPPED", record.stepState(SwitchSteps.MOVE_OUT))
        assertEquals("SKIPPED", record.stepState(SwitchSteps.MOVE_IN))
        assertEquals("SKIPPED", record.materialize.state)
        assertNotNull(record.planSha256)
    }
}
