package dev.maplesu.manager.workmode.migration

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.ui.MigrationUiState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** W20–W22 生产 facade（HostMigrationFacade）主机测试：fake 探针/备份/写入 + 临时目录。 */
class HostMigrationFacadeTest {
    @get:Rule val tmp = TemporaryFolder()

    private val switchId = "ignored"

    // ------------------------------------------------------------------ fakes

    private class FakeProbe(var result: MigrationProbeResult) : MigrationProbePort {
        override suspend fun read(): MigrationProbeResult = result
    }

    private class FakeBackup(
        var outcome: MigrationBackupOutcome = verifiedBackup(),
        val gate: CompletableDeferred<Unit>? = null,
    ) : MigrationBackupPort {
        var calls = 0
        override suspend fun capture(migrationId: String, info: ExternalRootInfo): MigrationBackupOutcome {
            calls++
            gate?.await()
            return outcome
        }

        companion object {
            fun verifiedBackup(): MigrationBackupOutcome = MigrationBackupOutcome.Verified(
                summary = MigrationBackupSummary(objectCount = 3, totalBytes = 1024, verified = true),
                manifestPath = "backup/manifest.json",
                manifestSha256 = "f".repeat(64),
            )
        }
    }

    private class FakeWriter(
        var available: Boolean = true,
        var writeOutcome: MigrationWriteOutcome = MigrationWriteOutcome.Written(),
        var deployOutcome: MigrationWriteOutcome = MigrationWriteOutcome.Written(),
        val writeGate: CompletableDeferred<Unit>? = null,
    ) : MigrationWritePort {
        var writeCalls = 0
        var deployCalls = 0
        var lastPlan: MigrationPlan? = null

        override fun available(): Boolean = available

        override suspend fun write(migrationId: String, target: WorkMode, plan: MigrationPlan): MigrationWriteOutcome {
            writeCalls++
            lastPlan = plan
            writeGate?.await()
            return writeOutcome
        }

        override suspend fun deploy(migrationId: String, target: WorkMode): MigrationWriteOutcome {
            deployCalls++
            return deployOutcome
        }
    }

    // ------------------------------------------------------------------ helpers

    private fun probeResult(
        family: Family = Family.KSU_UPSTREAM,
        suUid: Int = 0,
        externalRootAvailable: Boolean = true,
        pendingTransaction: Boolean = false,
        marker: ImageMarker? = ImageMarker.KSU_KO,
        validSha: Boolean = true,
        withStockBackup: Boolean = true,
        managerPackage: String? = "me.weishu.kernelsu",
    ): MigrationProbeResult {
        val initBoot = if (validSha) {
            Fixtures.partition("init_boot", marker?.let { setOf(it) } ?: emptySet())
        } else {
            PartitionFacts("init_boot", present = true, size = 100, sha256 = "", markers = marker?.let { setOf(it) } ?: emptySet())
        }
        val files = buildMap {
            when (family) {
                Family.KSU_7K -> put(MigrationPaths.SEVENK_DIR, Fixtures.dir(MigrationPaths.SEVENK_DIR))
                Family.KSU_UPSTREAM -> put(MigrationPaths.KSU_DIR, Fixtures.dir(MigrationPaths.KSU_DIR))
                Family.MAGISK -> put(MigrationPaths.MAGISK_DIR, Fixtures.dir(MigrationPaths.MAGISK_DIR))
                else -> Unit
            }
        }
        val backups = if (withStockBackup) {
            mapOf("init_boot" to Fixtures.backup("init_boot"))
        } else {
            emptyMap()
        }
        val inventory = managerPackage?.let {
            PackageInventory(listOf(Fixtures.packageFacts(10123, it)))
        } ?: PackageInventory()
        return MigrationProbeResult.Ready(
            probe = ExternalRootProbe(
                suUid = suUid,
                suVersion = when (family) {
                    Family.KSU_UPSTREAM, Family.KSU_7K -> "KernelSU 0.9.5 (uapi: 6)"
                    Family.MAGISK -> "MAGISK:D"
                    else -> "unknown-su"
                },
                files = files,
                tools = when (family) {
                    Family.KSU_UPSTREAM, Family.KSU_7K ->
                        mapOf("ksud" to Fixtures.tool("/data/adb/ksud", true, "KernelSU 0.9.5 (uapi: 6)"))
                    Family.MAGISK -> mapOf(
                        "magisk" to Fixtures.tool("${MigrationPaths.MAGISK_DIR}/magisk", true, "MAGISK:D"),
                        "magiskboot" to Fixtures.tool("${MigrationPaths.MAGISK_DIR}/magiskboot", true),
                    )
                    else -> emptyMap()
                },
                partitions = mapOf(
                    "boot" to Fixtures.partition("boot"),
                    "init_boot" to initBoot,
                ),
                stockBackups = backups,
                device = Fixtures.device(
                    externalRootAvailable = externalRootAvailable,
                    pendingTransaction = pendingTransaction,
                ),
            ),
            inventory = inventory,
        )
    }

    private fun facade(
        root: File,
        probe: MigrationProbeResult,
        backup: FakeBackup = FakeBackup(),
        writer: FakeWriter = FakeWriter(),
    ): HostMigrationFacade = HostMigrationFacade(
        root = root,
        probes = FakeProbe(probe),
        backup = backup,
        writer = writer,
        clock = { 1_793_260_800_000L },
        bootIdSource = { "boot-1" },
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined),
    )

    private suspend fun HostMigrationFacade.awaitTerminal(migrationId: String): MigrationObservation =
        withTimeout(5_000) {
            observe(migrationId).first { it is MigrationObservation.Completed || it is MigrationObservation.Failed }
        }

    private fun workRoot(): File = File(tmp.root, "workmode")

    private suspend fun detected(facade: HostMigrationFacade): Pair<MigrationDetectionResult.Ready, String> {
        val detection = facade.detect()
        assertTrue("expected Ready but was $detection", detection is MigrationDetectionResult.Ready)
        val ready = detection as MigrationDetectionResult.Ready
        assertTrue(ready.migrationId.isNotBlank())
        return ready to ready.migrationId
    }

    // ------------------------------------------------------------------ 检测

    @Test
    fun detectCreatesMigrationIdJournalAndDetectSummary() = runBlocking {
        val facade = facade(workRoot(), probeResult(family = Family.KSU_UPSTREAM))
        val (ready, migrationId) = detected(facade)
        assertEquals(Family.KSU_UPSTREAM, ready.info.family)
        assertTrue(ready.eligibility.enabled)
        assertTrue(File(MigrationPaths.migrationDir(workRoot(), migrationId), "journal.json").isFile)
        val detect = File(MigrationPaths.migrationDir(workRoot(), migrationId), "detect.json").readText()
        assertTrue(detect.contains("KSU_UPSTREAM"))
        assertEquals(migrationId, facade.currentMigrationId())
    }

    @Test
    fun detectMagiskFamilyAndVersion() = runBlocking {
        val root = workRoot()
        val detection = facade(
            root,
            probeResult(family = Family.MAGISK, marker = null, managerPackage = "com.topjohnwu.magisk"),
        ).detect()
        val ready = detection as MigrationDetectionResult.Ready
        assertEquals(Family.MAGISK, ready.info.family)
        assertEquals("MAGISK:D", ready.info.version)
    }

    @Test
    fun detectUnknownFamilyKeepsBestEffort() = runBlocking {
        val detection = facade(
            workRoot(),
            probeResult(family = Family.UNKNOWN, marker = ImageMarker.OTHER_PATCHER, managerPackage = null),
        ).detect()
        val ready = detection as MigrationDetectionResult.Ready
        assertEquals(Family.UNKNOWN, ready.info.family)
        assertTrue(ready.info.bestEffort)
        assertTrue(ready.eligibility.enabled)
    }

    @Test
    fun detectWithoutRootIsUnavailable() = runBlocking {
        val detection = facade(
            workRoot(),
            probeResult(suUid = 2000, externalRootAvailable = false),
        ).detect()
        assertTrue(detection is MigrationDetectionResult.Unavailable)
        assertEquals(MigrationCodes.NO_ROOT, (detection as MigrationDetectionResult.Unavailable).code)
    }

    @Test
    fun unavailableProbeIsStructuredNotGuessed() = runBlocking {
        val detection = facade(
            workRoot(),
            MigrationProbeResult.Unavailable(AndroidMigrationProbePort.PROBE_UNAVAILABLE),
        ).detect()
        assertEquals(
            AndroidMigrationProbePort.PROBE_UNAVAILABLE,
            (detection as MigrationDetectionResult.Unavailable).code,
        )
    }

    // ------------------------------------------------------------------ start 拒绝

    @Test
    fun startRefusedWhenPendingTransactionBlocks() = runBlocking {
        val root = workRoot()
        val facade = facade(root, probeResult(pendingTransaction = true))
        detected(facade)
        val result = facade.start(WorkMode.LITE)
        assertTrue(result is MigrationStartResult.Refused)
        assertEquals(MigrationCodes.PENDING_TRANSACTION, (result as MigrationStartResult.Refused).code)
        assertTrue(result.reasons.contains(MigrationCodes.PENDING_TRANSACTION))
    }

    @Test
    fun startWithoutDetectIsRefused() = runBlocking {
        val result = facade(workRoot(), probeResult()).start(WorkMode.LITE)
        assertEquals(HostMigrationFacade.NOT_DETECTED, (result as MigrationStartResult.Refused).code)
    }

    @Test
    fun startWithMissingCleanImageFailsAtPlanNotAtStart() = runBlocking {
        val root = workRoot()
        // P2 策略宣称可离线重建（cleanImagePartitions=patched），但 facade 未接线外部还原端口；
        // 计划阶段拿不到已验证干净镜像 → M2 结构化失败，且绝不写分区。
        val writer = FakeWriter()
        val noBackup = facade(root, probeResult(family = Family.KSU_UPSTREAM, withStockBackup = false), FakeBackup(), writer)
        detected(noBackup)
        val started = noBackup.start(WorkMode.KSU)
        assertTrue(started is MigrationStartResult.Accepted)
        val terminal = noBackup.awaitTerminal((started as MigrationStartResult.Accepted).migrationId)
        assertEquals(MigrationCodes.CLEAN_IMAGE_UNAVAILABLE, (terminal as MigrationObservation.Failed).failure.code)
        assertEquals(0, writer.writeCalls)
    }

    // ------------------------------------------------------------------ 生命周期

    @Test
    fun happyPathRunsBackupPlanWriteDeployAndCompletes() = runBlocking {
        val root = workRoot()
        val backup = FakeBackup()
        val writer = FakeWriter()
        val facade = facade(root, probeResult(), backup, writer)
        val (_, migrationId) = detected(facade)
        val started = facade.start(WorkMode.LITE)
        assertTrue(started is MigrationStartResult.Accepted)
        val terminal = facade.awaitTerminal((started as MigrationStartResult.Accepted).migrationId) as MigrationObservation.Completed
        assertEquals(MigrationResultKind.VERIFIED, terminal.result.kind)
        assertTrue(terminal.result.rebootRequired)
        assertEquals(1, backup.calls)
        assertEquals(1, writer.writeCalls)
        assertEquals(1, writer.deployCalls)
        assertNotNull(writer.lastPlan)
        assertEquals(migrationId, started.migrationId)
    }

    @Test
    fun backupFailureBlocksBeforeAnyWrite() = runBlocking {
        val root = workRoot()
        val backup = FakeBackup(MigrationBackupOutcome.Failed(MigrationCodes.BACKUP_VERIFY_FAILED, "verify"))
        val writer = FakeWriter()
        val facade = facade(root, probeResult(), backup, writer)
        val (_, _) = detected(facade)
        val started = facade.start(WorkMode.LITE) as MigrationStartResult.Accepted
        val terminal = facade.awaitTerminal(started.migrationId)
        assertTrue(terminal is MigrationObservation.Failed)
        assertEquals(MigrationCodes.BACKUP_VERIFY_FAILED, (terminal as MigrationObservation.Failed).failure.code)
        assertEquals(0, writer.writeCalls)
        assertEquals(
            MigrationState.M1_FAILED,
            FileMigrationJournal(root).read(started.migrationId)!!.stateValue(),
        )
    }

    @Test
    fun incompleteBackupSummaryBlocksStart() = runBlocking {
        val root = workRoot()
        val backup = FakeBackup(
            MigrationBackupOutcome.Verified(
                MigrationBackupSummary(objectCount = 1, verified = false, missing = 1),
            ),
        )
        val writer = FakeWriter()
        val facade = facade(root, probeResult(), backup, writer)
        detected(facade)
        val started = facade.start(WorkMode.LITE) as MigrationStartResult.Accepted
        val terminal = facade.awaitTerminal(started.migrationId)
        assertEquals(MigrationCodes.BACKUP_VERIFY_FAILED, (terminal as MigrationObservation.Failed).failure.code)
        assertEquals(0, writer.writeCalls)
    }

    @Test
    fun planFailureStopsAtM2WithoutWrite() = runBlocking {
        val root = workRoot()
        val writer = FakeWriter()
        // 分区 sha 非法 → pre 镜像缺失；计划阶段抛 PRE_IMAGE_MISSING（备份/资格已通过）。
        val facade = facade(root, probeResult(validSha = false), FakeBackup(), writer)
        val detection = facade.detect() as MigrationDetectionResult.Ready
        val started = facade.start(WorkMode.LITE)
        assertTrue(started is MigrationStartResult.Accepted)
        val terminal = facade.awaitTerminal((started as MigrationStartResult.Accepted).migrationId)
        assertEquals(MigrationCodes.PRE_IMAGE_MISSING, (terminal as MigrationObservation.Failed).failure.code)
        assertEquals(0, writer.writeCalls)
        assertEquals(
            MigrationState.M2_FAILED,
            FileMigrationJournal(root).read(detection.migrationId)!!.stateValue(),
        )
    }

    @Test
    fun unavailableWriterFailsStructuredAfterBackup() = runBlocking {
        val root = workRoot()
        val backup = FakeBackup()
        val writer = FakeWriter(available = false)
        val facade = facade(root, probeResult(), backup, writer)
        detected(facade)
        val started = facade.start(WorkMode.LITE) as MigrationStartResult.Accepted
        val terminal = facade.awaitTerminal(started.migrationId)
        assertEquals(UnavailableMigrationWritePort.CODE, (terminal as MigrationObservation.Failed).failure.code)
        assertEquals(1, backup.calls)
        assertEquals(0, writer.writeCalls)
    }

    @Test
    fun writerRolledBackReportsRolledBack() = runBlocking {
        val root = workRoot()
        val writer = FakeWriter(writeOutcome = MigrationWriteOutcome.RolledBack("WRITE_FAILED"))
        val facade = facade(root, probeResult(), FakeBackup(), writer)
        detected(facade)
        val started = facade.start(WorkMode.LITE) as MigrationStartResult.Accepted
        val terminal = facade.awaitTerminal(started.migrationId) as MigrationObservation.Completed
        assertEquals(MigrationResultKind.ROLLED_BACK, terminal.result.kind)
        assertEquals(
            MigrationState.ROLLED_BACK,
            FileMigrationJournal(root).read(started.migrationId)!!.stateValue(),
        )
    }

    @Test
    fun writerRecoveryRequiredReportsRecovery() = runBlocking {
        val root = workRoot()
        val writer = FakeWriter(writeOutcome = MigrationWriteOutcome.RecoveryRequired("WRITE_ROLLBACK_FAILED"))
        val facade = facade(root, probeResult(), FakeBackup(), writer)
        detected(facade)
        val started = facade.start(WorkMode.LITE) as MigrationStartResult.Accepted
        val terminal = facade.awaitTerminal(started.migrationId) as MigrationObservation.Completed
        assertEquals(MigrationResultKind.RECOVERY_REQUIRED, terminal.result.kind)
    }

    @Test
    fun deployFailureRollsBack() = runBlocking {
        val root = workRoot()
        val writer = FakeWriter(deployOutcome = MigrationWriteOutcome.RolledBack("DEPLOY_FAILED"))
        val facade = facade(root, probeResult(), FakeBackup(), writer)
        detected(facade)
        val started = facade.start(WorkMode.LITE) as MigrationStartResult.Accepted
        val terminal = facade.awaitTerminal(started.migrationId) as MigrationObservation.Completed
        assertEquals(MigrationResultKind.ROLLED_BACK, terminal.result.kind)
        assertEquals(1, writer.deployCalls)
    }

    @Test
    fun residualPlanIsReportedInResult() = runBlocking {
        val root = workRoot()
        // UNKNOWN 家族 + 无干净镜像：restore-only 分区 LEAVE_UNCHANGED + residual=true，但不阻断。
        val facade = facade(
            root,
            probeResult(
                family = Family.UNKNOWN,
                marker = ImageMarker.OTHER_PATCHER,
                withStockBackup = false,
                managerPackage = null,
            ),
        )
        val detection = facade.detect() as MigrationDetectionResult.Ready
        assertTrue(detection.info.bestEffort)
        val started = facade.start(WorkMode.LITE) as MigrationStartResult.Accepted
        val terminal = facade.awaitTerminal(started.migrationId) as MigrationObservation.Completed
        assertTrue(terminal.result.residual)
        assertTrue(terminal.result.residues.isNotEmpty())
    }

    // ------------------------------------------------------------------ abort / observe

    @Test
    fun abortBeforeWriteRollsBackAndKeepsJournal() = runBlocking {
        val root = workRoot()
        val gate = CompletableDeferred<Unit>()
        val backup = FakeBackup(gate = gate)
        val writer = FakeWriter()
        val facade = facade(root, probeResult(), backup, writer)
        detected(facade)
        val started = facade.start(WorkMode.LITE) as MigrationStartResult.Accepted
        // 备份阶段已开始（gate 未释放）
        val progress = withTimeout(5_000) {
            facade.observe(started.migrationId).first { it is MigrationObservation.Progress }
        }
        assertEquals(MigrationStage.BACKING_UP, (progress as MigrationObservation.Progress).stage)
        assertTrue(facade.abort(started.migrationId))
        val terminal = facade.awaitTerminal(started.migrationId) as MigrationObservation.Completed
        assertEquals(MigrationResultKind.ROLLED_BACK, terminal.result.kind)
        assertEquals(
            MigrationState.ROLLED_BACK,
            FileMigrationJournal(root).read(started.migrationId)!!.stateValue(),
        )
        assertEquals(0, writer.writeCalls)
    }

    @Test
    fun abortAfterWriteIntentIsRefused() = runBlocking {
        val root = workRoot()
        val writeGate = CompletableDeferred<Unit>()
        val writer = FakeWriter(writeGate = writeGate)
        val facade = facade(root, probeResult(), FakeBackup(), writer)
        detected(facade)
        val started = facade.start(WorkMode.LITE) as MigrationStartResult.Accepted
        withTimeout(5_000) {
            facade.observe(started.migrationId).first { it is MigrationObservation.Progress }
        }
        assertFalse(facade.abort(started.migrationId))
        writeGate.complete(Unit)
        val terminal = facade.awaitTerminal(started.migrationId) as MigrationObservation.Completed
        assertEquals(MigrationResultKind.VERIFIED, terminal.result.kind)
    }

    @Test
    fun observeReconstructsStateFromJournalAfterReopen() = runBlocking {
        val root = workRoot()
        val facade = facade(root, probeResult())
        detected(facade)
        val started = facade.start(WorkMode.LITE) as MigrationStartResult.Accepted
        facade.awaitTerminal(started.migrationId)

        // 进程重启/页面重进：新 facade（无内存状态）只能靠 journal 重建；
        // 主机侧写完即停在 M7_FINALIZED（真实设备需重启后 M9 才能 VERIFIED）。
        val reopened = facade(root, probeResult())
        val first = withTimeout(5_000) { reopened.observe(started.migrationId).first() }
        assertTrue(first is MigrationObservation.Progress)
        assertEquals(MigrationStage.PENDING_REBOOT, (first as MigrationObservation.Progress).stage)
    }

    // ------------------------------------------------------------------ runtime / UI 降级

    @Test
    fun runtimeProviderReturnsInjectedFacadeAndResets() {
        val fake = UnavailableMigrationFacade
        MigrationRuntime.initialize(fake)
        assertEquals(fake, MigrationRuntime.current())
        MigrationRuntime.reset()
        assertEquals(null, MigrationRuntime.current())
    }

    @Test
    fun unavailableBackendKeepsStartButtonHidden() {
        val snapshot = MigrationUiReducer.reduce(
            MigrationUiSnapshot(),
            MigrationUiEvent.DetectionUnavailable(UnavailableMigrationFacade.CODE),
        )
        val state = MigrationUiState(snapshot)
        assertFalse(state.canStart)
        assertTrue(state.unavailable)
    }

    @Test
    fun defaultViewModelFacadeFallsBackWhenRuntimeMissing() {
        MigrationRuntime.reset()
        assertEquals(UnavailableMigrationFacade, dev.maplesu.manager.workmode.ui.MigrationViewModel.defaultFacade())
    }

    @Test
    fun detectIsIdempotentForRepeatedCalls() = runBlocking {
        val facade = facade(workRoot(), probeResult())
        val first = facade.detect() as MigrationDetectionResult.Ready
        val second = facade.detect() as MigrationDetectionResult.Ready
        assertNotEquals(first.migrationId, second.migrationId)
        assertTrue(File(MigrationPaths.migrationDir(workRoot(), first.migrationId), "journal.json").isFile)
        assertTrue(File(MigrationPaths.migrationDir(workRoot(), second.migrationId), "journal.json").isFile)
    }
}
