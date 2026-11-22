package dev.maplesu.manager.workmode.switch

import dev.maplesu.installer.BlockDeviceTransaction
import dev.maplesu.installer.SwitchFailure
import dev.maplesu.installer.SwitchJournalSink
import dev.maplesu.installer.SwitchPlan
import dev.maplesu.installer.SwitchStep
import dev.maplesu.installer.InstallerMultiPartitionTransaction
import dev.maplesu.installer.SwitchFacts
import dev.maplesu.installer.SwitchPartitionProvider
import dev.maplesu.installer.SwitchEvent
import dev.maplesu.installer.WritablePartition
import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.ModeState
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.util.UUID

/** W08 主机测试 Fake 集合：全部端口都有可控实现（无 Android 依赖）。 */
internal object ModeSwitchFixtures {
    const val PARTITION_SIZE = 4096L

    fun bootId(value: String = "boot-1") = BootIdSource { value }

    fun mutableBootId(initial: String = "boot-1"): Pair<BootIdSource, () -> Unit> {
        var current = initial
        val source = BootIdSource { current }
        return source to { current = "boot-2" }
    }

    fun clock(): Clock = Clock { 1_000L }
}

/** 记录型 WAL；可注入"追加即失败"。 */
internal class RecordingSwitchJournal : SwitchJournal {
    val lines = mutableListOf<JournalLine>()
    var failAppend = false

    override fun append(
        switchId: String,
        planSha256: String,
        stage: String,
        step: String,
        op: SwitchOp,
        partition: String,
        expectedSha256: String,
        observedSha256: String,
        code: String,
    ): JournalLine {
        if (failAppend) throw IllegalStateException("JOURNAL_WRITE_FAILED")
        val line = JournalLine(
            seq = (lines.lastOrNull()?.seq ?: 0L) + 1,
            switchId = switchId,
            planSha256 = planSha256,
            atUptimeMs = 1_000L,
            bootId = "boot-1",
            stage = stage,
            step = step,
            partition = partition,
            op = op.wire,
            expectedSha256 = expectedSha256,
            observedSha256 = observedSha256,
            code = code,
            prev = JournalLine.ZERO_PREV,
        )
        lines += line
        return line
    }

    override fun appendRaw(line: String): Long {
        lines += JournalLine(seq = lines.size + 1L, switchId = "", planSha256 = "", atUptimeMs = 0,
            bootId = "", stage = "", step = "", op = SwitchOp.PREPARED.wire, prev = JournalLine.ZERO_PREV)
        return lines.size.toLong()
    }

    override fun read(): JournalRead = JournalRead.Ok(lines.toList(), false)

    override fun last(): JournalLine? = lines.lastOrNull()

    override fun replay(switchId: String?): JournalReplay = JournalReplayRules.derive(lines)
}

internal class FakeBaselineStore(var verification: BaselineVerification) : BaselineStore {
    override fun state(): BaselineState = verification.state
    override fun verify(id: String?): BaselineVerification = verification
    override fun capture(request: BaselineCaptureRequest): BaselineResult =
        BaselineResult.Failed("UNUSED", "")
    override fun import(request: BaselineImportRequest): BaselineResult =
        BaselineResult.Failed("UNUSED", "")
    override fun open(id: String, partition: String): java.io.FileDescriptor? = null
    override fun captureTakeover(request: TakeoverRequest): BaselineResult =
        BaselineResult.Failed("UNUSED", "")
    override fun markStale(reason: String) {}
    override fun history(): List<BaselineManifest> = emptyList()
    override fun check(id: String?): BaselineCheck =
        verification.check ?: BaselineCheck("", "", "", "", false)
}

internal class FakeSwitchEnvironment(
    private val workDir: File,
) : SwitchEnvironment {
    var modeState: ModeState? = ModeState.MODE_A_ACTIVE
    var currentMode: WorkMode? = WorkMode.LITE
    var device = SwitchDeviceFacts("_a", "fw-1", "5.10.198-android13-8-g1234")
    var battery = BatteryFacts(80, false)
    var pending = PendingFacts()
    var rootRefusal: String? = null
    var controlWritable = true
    var implantRestoreReady = true
    var exportReceipt: Map<String, String> = emptyMap()
    var inventory = PartitionInventory()
    var avb = SwitchAvbFacts()
    var freeBytes = 1L shl 40
    var beginInputsError = ""
    var targetRoot = true

    private val superuserFile = File(workDir, "superuser-export.json").apply { writeText("{}") }
    private val settingsFile = File(workDir, "settings-mirror.json").apply { writeText("{}") }

    override fun modeState() = modeState
    override fun currentMode() = currentMode
    override fun deviceFacts() = device
    override fun battery() = battery
    override fun pending() = pending
    override fun rootRefusal() = rootRefusal
    override fun controlWritable() = controlWritable
    override fun implantRestoreReady() = implantRestoreReady
    override fun exportReceipt() = exportReceipt
    override fun partitionInventory() = inventory
    override fun avb() = avb
    override fun freeBytes() = freeBytes
    override fun targetRootAvailable(to: WorkMode) = targetRoot

    override fun beginInputs(): BeginInputs = if (beginInputsError.isBlank()) {
        BeginInputs(superuserFile, settingsFile)
    } else {
        BeginInputs(null, null, beginInputsError)
    }
}

internal class FakeModeSwitchSnapshots : ModeSwitchSnapshots {
    var failPre = false
    var failRestore = false
    var restoreCalls = 0

    override suspend fun preSwitchSnapshot(request: ModeSwitchRequest): GatewayOutcome =
        if (failPre) GatewayOutcome(false, "", ModeSwitchCodes.SNAPSHOT_FAILED, "snapshot failed")
        else GatewayOutcome(true, "")

    override suspend fun restoreAfterRollback(request: ModeSwitchRequest): GatewayOutcome {
        restoreCalls++
        return if (failRestore) GatewayOutcome(false, "", ModeSwitchCodes.SNAPSHOT_FAILED, "restore failed")
        else GatewayOutcome(true, "")
    }
}

/** producer 用 baseline 内容派生候选（末字节翻转），也可注入失败/长度/摘要异常。 */
internal class RecordingSwitchProducer(
    private val workDir: File,
) : SwitchCandidateProducer {
    var failCode = ""
    var truncateBytes = 0L
    var reportWrongSha = false
    var onProduce: (() -> Unit)? = null

    override fun produce(input: CandidateInput): CandidateResult {
        onProduce?.invoke()
        if (failCode.isNotEmpty()) return CandidateResult(null, "", 0, failCode, "injected")
        val baseline = input.baselineImage.readBytes()
        val candidate = baseline.copyOf()
        candidate[candidate.size - 1] = (candidate[candidate.size - 1].toInt() xor 0x5a).toByte()
        val file = File(workDir, "candidate-${input.partition}.img")
        file.writeBytes(candidate)
        val actual = Hashes.sha256(candidate)
        if (truncateBytes > 0) {
            RandomAccessFile(file, "rw").use { it.setLength(file.length() - truncateBytes) }
        }
        val reported = if (reportWrongSha) "b".repeat(64) else actual
        return CandidateResult(file, reported, file.length(), structureEvidence = "fixture")
    }
}

internal class RecordingQuiesceHooks : SwitchQuiesceHooks {
    var failQuiesce = false
    var failWithdraw = false
    var failRestore = false
    var failProducerCleanup = false
    var implantReady = true
    var withdrawCalls = 0
    var producerCleanupCalls = 0
    var restoreCalls = 0

    override fun quiesce(fromMode: WorkMode): HookResult =
        if (failQuiesce) HookResult.failed(ModeSwitchCodes.QUIESCE_TIMEOUT, "injected") else HookResult.OK

    override fun restoreAfterFailure(fromMode: WorkMode): HookResult {
        restoreCalls++
        return if (failRestore) HookResult.failed(ModeSwitchCodes.MOVE_ROLLBACK_FAILED, "injected") else HookResult.OK
    }

    override fun withdrawLiteImplants(): HookResult {
        withdrawCalls++
        return if (failWithdraw) HookResult.failed(ModeSwitchCodes.IMPLANT_RESTORE_MISSING, "injected") else HookResult.OK
    }

    override fun implantRestoreReady(): Boolean = implantReady

    override fun restoreProducerSideEffects(): HookResult {
        producerCleanupCalls++
        return if (failProducerCleanup) HookResult.failed("PRODUCE_SIDE_EFFECT_UNRECOVERED", "injected")
        else HookResult.OK
    }
}

internal class RecordingConsumer : ModeConsumerVerifier {
    var failures = 0
    override fun verify(mode: WorkMode, bootId: String): HookResult =
        if (failures > 0) {
            failures--
            HookResult.failed(ModeSwitchCodes.VERIFY_CONSUMER_FAILED, "injected")
        } else {
            HookResult.OK
        }
}

internal class RecordingSuperuser : SuperuserReconciler {
    var fail = false
    override suspend fun reconcileAfterBoot(mode: WorkMode): HookResult =
        if (fail) HookResult.failed(ModeSwitchCodes.VERIFY_SUPERUSER_FAILED, "injected") else HookResult.OK
}

internal class RecordingModeCommit : ModeCommitSink {
    var calls = 0
    var fail = false
    override fun commit(mode: WorkMode, bootId: String, bootSha256: String, initBootSha256: String) {
        calls++
        if (fail) throw IOException("CONTROL_WRITE_FAILED")
    }
}

/** 内存分区：支持一次性/永久写失败注入，以及"写后内容损坏"。 */
internal class FakePartition(
    val name: String,
    var bytes: ByteArray,
) {
    var failOnceAfter: Int = -1
    var failAlwaysAfter: Int = -1
    private var writes = 0
    private var failedOnce = false
    val writeLog = mutableListOf<String>()

    fun onWrite() {
        if (failAlwaysAfter in 0..writes) {
            writeLog += "always-fail@$writes"
            throw IOException("INSTALLER_DEVICE_WRITE_FAILED")
        }
        if (failOnceAfter in 0..writes && !failedOnce) {
            writeLog += "once-fail@$writes"
            failedOnce = true
            throw IOException("INSTALLER_DEVICE_WRITE_FAILED")
        }
        writeLog += "ok@$writes"
        writes++
    }
}

internal class FakeDevice(private val partition: FakePartition) : BlockDeviceTransaction.Device {
    override fun size(): Long = partition.bytes.size.toLong()
    override fun revalidate() {}
    override fun read(offset: Long, buffer: ByteArray, length: Int): Int {
        val count = minOf(length.toLong(), partition.bytes.size - offset).toInt()
        if (count <= 0) return 0
        System.arraycopy(partition.bytes, offset.toInt(), buffer, 0, count)
        return count
    }

    override fun write(offset: Long, buffer: ByteArray, start: Int, length: Int): Int {
        partition.onWrite()
        System.arraycopy(buffer, start, partition.bytes, offset.toInt(), length)
        return length
    }

    override fun sync() {}
    override fun close() {}
}

internal class FakeWritablePartition(private val partition: FakePartition) : WritablePartition {
    override fun name(): String = partition.name
    override fun size(): Long = partition.bytes.size.toLong()
    override fun sha256(): String = Hashes.sha256(partition.bytes)
    override fun tailSha256(): String {
        val count = minOf(partition.bytes.size, WritableTailProbe.BYTES)
        return Hashes.sha256(partition.bytes.copyOfRange(partition.bytes.size - count, partition.bytes.size))
    }

    override fun open(): BlockDeviceTransaction.Device = FakeDevice(partition)
    override fun readOnly(): Boolean = false
}

internal class FakePartitionProvider(
    private val partitions: Map<String, FakePartition>,
) : SwitchPartitionProvider {
    override fun get(name: String): WritablePartition {
        val partition = partitions[name] ?: throw IOException("SWITCH_PARTITION_LAYOUT_UNSUPPORTED")
        return FakeWritablePartition(partition)
    }

    override fun available(): MutableSet<String> = partitions.keys.toMutableSet()
}

/** 测试用 journal 屏障：只记录，不依赖 manager WAL。 */
internal class RecordingSink : SwitchJournalSink {
    val events = mutableListOf<SwitchEvent>()
    var fail = false
    override fun append(event: SwitchEvent) {
        if (fail) throw IOException("JOURNAL_WRITE_FAILED")
        events += event
    }
}

/**
 * 主机版安装网关：内部**真实调用** `InstallerMultiPartitionTransaction`（prepare/commit/
 * rollback/verify），因此失败回滚语义由 installer-core 的真实实现给出，而不是重写一遍。
 */
internal class FakeInstallerGateway(
    val partitions: LinkedHashMap<String, FakePartition>,
    private val facts: FakeSwitchFacts,
    var baselineBytes: Map<String, ByteArray> = emptyMap(),
) : InstallerGateway {
    private val provider = FakePartitionProvider(partitions)
    private val sink = RecordingSink()
    private var plan: SwitchPlan? = null
    private var preBytes: Map<String, ByteArray> = emptyMap()
    private var state = ""
    private var planSha = ""
    var failBegin: String? = null
    var failSnapshot: String? = null
    var failSubmit: String? = null
    var failPrepare: String? = null
    var failCommit: String? = null
    var failVerify: String? = null
    var verifyCodeOverride: String? = null
    var failObserve = false
    var failRollback: String? = null
    var rebootAccepted = true
    var rebootChangesBootId = true
    var rebootHook: (() -> Unit)? = null
    var tamperPreExport = false
    var preparedPlans = 0
    var commits = 0
    var rollbacks = 0
    var lastCommitState = ""
    var lastCommitCode = ""
    var lastCommitWritten: List<String> = emptyList()
    var lastCommitRestored: List<String> = emptyList()

    fun planOk(): SwitchPlan? = plan

    override fun preflight(request: ModeSwitchRequest): GatewayPreflight = GatewayPreflight(true)

    override fun begin(request: ModeSwitchRequest, inputs: BeginInputs): GatewayOutcome {
        failBegin?.let { return GatewayOutcome(false, "", it, "injected") }
        state = SwitchStateNames.BEGIN
        return GatewayOutcome(true, GatewayState.WRITTEN)
    }

    override fun snapshot(request: ModeSwitchRequest): GatewayOutcome {
        failSnapshot?.let { return GatewayOutcome(false, "", it, "injected") }
        preBytes = partitions.mapValues { it.value.bytes.copyOf() }
        state = SwitchStateNames.SNAPSHOT
        return GatewayOutcome(true, GatewayState.WRITTEN, status = status())
    }

    override fun exportImage(
        request: ModeSwitchRequest,
        kind: String,
        partition: String,
        destination: File,
    ): ExportedImage {
        destination.parentFile?.mkdirs()
        val bytes = when (kind) {
            "PRE" -> preBytes[partition]
            "BASE", "BASELINE" -> baselineBytes[partition]
            else -> throw IOException("SWITCH_PRE_IMAGE_INVALID: kind $kind")
        } ?: throw IOException("SWITCH_PRE_IMAGE_INVALID: $kind/$partition")
        val written = if (tamperPreExport && kind == "PRE") {
            bytes.copyOf().also { it[0] = (it[0].toInt() xor 0x7f).toByte() }
        } else {
            bytes
        }
        destination.writeBytes(written)
        return ExportedImage(destination, destination.length(), Hashes.sha256(written))
    }

    override fun submitCandidate(
        request: ModeSwitchRequest,
        partition: String,
        image: ExportedImage,
    ): GatewayOutcome {
        failSubmit?.let { return GatewayOutcome(false, "", it, "injected") }
        return GatewayOutcome(true, GatewayState.WRITTEN)
    }

    override fun preparePlan(request: ModeSwitchRequest, planFlatFields: Map<String, String>): GatewayOutcome {
        failPrepare?.let { return GatewayOutcome(false, "", it, "injected") }
        return try {
            val parsed = SwitchPlan.parse(planFlatFields)
            val planRequest = SwitchPlan.Request(
                parsed.schema, parsed.switchId, parsed.fromMode, parsed.toMode, parsed.baselineId,
                parsed.startBootId, parsed.device, parsed.steps,
            )
            plan = InstallerMultiPartitionTransaction.prepare(planRequest, provider, sink)
            planSha = plan!!.planSha256
            preparedPlans++
            state = SwitchStateNames.COMMIT
            GatewayOutcome(true, GatewayState.WRITTEN)
        } catch (failure: SwitchFailure) {
            GatewayOutcome(false, "", failure.code, failure.detail)
        }
    }

    override fun commit(request: ModeSwitchRequest): GatewayOutcome {
        failCommit?.let { return GatewayOutcome(false, "", it, "injected") }
        commits++
        val activePlan = plan ?: return GatewayOutcome(false, "", ModeSwitchCodes.PLAN_INVALID, "no plan")
        val result = runCatching {
            InstallerMultiPartitionTransaction.commit(activePlan, provider, sink)
        }.getOrElse { error ->
            if (error is SwitchFailure) return GatewayOutcome(false, "", error.code, error.detail)
            return GatewayOutcome(false, "", ModeSwitchCodes.WRITE_FAILED, error.message.orEmpty())
        }
        state = result.state.name
        lastCommitState = result.state.name
        lastCommitCode = result.code
        lastCommitWritten = result.written
        lastCommitRestored = result.restored
        // 02 §5.5：若某个分区的单分区事务返回 RECOVERY_REQUIRED（写失败且还原失败），
        // 多分区层不得因为"字节恰好仍等于 pre"就降级成 ROLLED_BACK。installer-core 当前的
        // allPre 提前返回尚未计入 UNRESTORABLE（W07 待修），服务端合同实现必须在这里升级。
        val unrecoverable = activePlan.steps.any { step ->
            (partitions[step.partition]?.failAlwaysAfter ?: -1) >= 0
        }
        return when (result.state) {
            InstallerMultiPartitionTransaction.State.WRITTEN ->
                GatewayOutcome(true, GatewayState.WRITTEN, status = status())
            InstallerMultiPartitionTransaction.State.ROLLED_BACK ->
                if (unrecoverable) {
                    GatewayOutcome(false, GatewayState.RECOVERY_REQUIRED,
                        "WRITE_ROLLBACK_FAILED", result.detail, status())
                } else {
                    GatewayOutcome(false, GatewayState.ROLLED_BACK, result.code, result.detail, status())
                }
            else ->
                GatewayOutcome(false, GatewayState.RECOVERY_REQUIRED, result.code, result.detail, status())
        }
    }

    override fun rollback(request: ModeSwitchRequest): GatewayOutcome {
        failRollback?.let { return GatewayOutcome(false, GatewayState.RECOVERY_REQUIRED, it, "injected") }
        rollbacks++
        val activePlan = plan
        if (activePlan == null) {
            // 尚未 prepare：按 pre 内容恢复（等价"没有分区被写"）。
            preBytes.forEach { (name, bytes) -> partitions[name]?.bytes = bytes.copyOf() }
            state = SwitchStateNames.ROLLED_BACK
            return GatewayOutcome(true, GatewayState.ROLLED_BACK)
        }
        val result = InstallerMultiPartitionTransaction.rollback(activePlan, provider, sink)
        state = result.state.name
        return if (result.state == InstallerMultiPartitionTransaction.State.ROLLED_BACK) {
            GatewayOutcome(true, GatewayState.ROLLED_BACK, status = status())
        } else {
            GatewayOutcome(false, GatewayState.RECOVERY_REQUIRED, result.code, result.detail, status())
        }
    }

    override fun abort(request: ModeSwitchRequest): GatewayOutcome {
        state = SwitchStateNames.CANCELLED
        return GatewayOutcome(true, GatewayState.CANCELLED)
    }

    override fun observePartitions(
        request: ModeSwitchRequest,
        names: List<String>,
    ): List<PartitionObservation> {
        if (failObserve) return emptyList()
        return names.mapNotNull { name ->
            partitions[name]?.let { PartitionObservation(name, it.bytes.size.toLong(), Hashes.sha256(it.bytes)) }
        }
    }

    override fun verify(request: ModeSwitchRequest): GatewayOutcome {
        failVerify?.let { return GatewayOutcome(false, "", it, "injected") }
        verifyCodeOverride?.let { return GatewayOutcome(false, GatewayState.RECOVERY_REQUIRED, it, "injected") }
        val activePlan = plan ?: return GatewayOutcome(false, "", ModeSwitchCodes.PLAN_INVALID, "no plan")
        val result = InstallerMultiPartitionTransaction.verify(activePlan, provider, facts, sink)
        state = result.state.name
        return if (result.state == InstallerMultiPartitionTransaction.State.VERIFIED) {
            GatewayOutcome(true, GatewayState.VERIFIED)
        } else {
            GatewayOutcome(false, GatewayState.RECOVERY_REQUIRED, result.code, result.detail)
        }
    }

    override fun reboot(request: ModeSwitchRequest): Boolean {
        if (!rebootAccepted) return false
        rebootHook?.invoke()
        return true
    }

    override fun status(switchId: String): GatewayStatus? =
        if (state.isEmpty()) null else status()

    override fun exportDiagnostics(request: ModeSwitchRequest, destination: File): File {
        destination.writeText("switchId=${request.switchId}")
        return destination
    }

    private fun status(): GatewayStatus {
        val activePlan = plan
        val rows = partitions.map { (name, partition) ->
            val step = activePlan?.steps?.firstOrNull { it.partition == name }
            SwitchPartitionStatus(
                name = name,
                role = step?.role?.name.orEmpty(),
                size = partition.bytes.size.toLong(),
                preSha256 = preBytes[name]?.let { Hashes.sha256(it) }.orEmpty(),
                targetSha256 = step?.imageSha256.orEmpty(),
                tailSha256 = step?.tailSha256.orEmpty(),
                observedSha256 = Hashes.sha256(partition.bytes),
                state = if (state == SwitchStateNames.REBOOT_REQUIRED || state == "WRITTEN") "DONE" else "PENDING",
            )
        }
        return GatewayStatus(
            switchId = activePlan?.switchId.orEmpty(),
            state = state,
            stage = "S4",
            step = SwitchSteps.COMMIT_PENDING,
            planSha256 = planSha,
            partitions = rows,
        )
    }
}

internal class FakeSwitchFacts(
    private val bootIds: BootIdSource,
    private val device: () -> SwitchDeviceFacts,
) : SwitchFacts {
    override fun bootId(): String = bootIds.read()
    override fun slotSuffix(): String = device().slot
    override fun firmware(): String = device().firmware
    override fun kernelRelease(): String = device().kernelRelease
    override fun selinux(): String = device().selinux
}

/** 控制器 + 全部 Fake 的测试装置。 */
internal class ModeSwitchHarness(
    fromMode: WorkMode = WorkMode.LITE,
    toMode: WorkMode = WorkMode.KSU,
) {
    val temp = TestFixtures.tempDir("modeswitch").toFile()
    val work = File(temp, "work").apply { mkdirs() }
    val control = File(temp, "control").apply { mkdirs() }
    val clock = ModeSwitchFixtures.clock()
    var bootId = "boot-1"
    val bootIds = BootIdSource { bootId }
    val device = SwitchDeviceFacts("_a", "fw-1", "5.10.198-android13-8-g1234")
    val env = FakeSwitchEnvironment(temp)
    val authority = InMemorySwitchAuthority()
    val journal = RecordingSwitchJournal()
    val snapshots = FakeModeSwitchSnapshots()
    val hooks = RecordingQuiesceHooks()
    val consumer = RecordingConsumer()
    val superuser = RecordingSuperuser()
    val modeCommit = RecordingModeCommit()
    val producer = RecordingSwitchProducer(work)
    val partitions = linkedMapOf(
        "boot" to FakePartition("boot", "P".repeat(ModeSwitchFixtures.PARTITION_SIZE.toInt()).toByteArray()),
        "init_boot" to FakePartition("init_boot", "S".repeat(ModeSwitchFixtures.PARTITION_SIZE.toInt()).toByteArray()),
    )
    val bootBaseline = "B".repeat(ModeSwitchFixtures.PARTITION_SIZE.toInt()).toByteArray()
    val initBootBaseline = "I".repeat(ModeSwitchFixtures.PARTITION_SIZE.toInt()).toByteArray()
    val gateway = FakeInstallerGateway(partitions, FakeSwitchFacts(bootIds) { device })
        .apply { baselineBytes = mapOf("boot" to bootBaseline, "init_boot" to initBootBaseline) }
    val baselineStore = FakeBaselineStore(presentBaseline())
    val request = ModeSwitchRequest(
        switchId = UUID.randomUUID().toString(),
        fromMode = fromMode,
        toMode = toMode,
        baselineId = "bl-1",
    )
    val controller = ModeSwitchController(
        gateway = gateway,
        journalFactory = SwitchJournalFactory { journal },
        authority = authority,
        baselines = baselineStore,
        snapshots = snapshots,
        producer = producer,
        hooks = hooks,
        environment = env,
        consumer = consumer,
        superuser = superuser,
        modeCommit = modeCommit,
        clock = clock,
        bootIds = bootIds,
        workRoot = work,
    )

    init {
        env.inventory = PartitionInventory(
            present = setOf("boot", "init_boot"),
            sizes = mapOf(
                "boot" to ModeSwitchFixtures.PARTITION_SIZE,
                "init_boot" to ModeSwitchFixtures.PARTITION_SIZE,
            ),
            readOnly = mapOf("boot" to false, "init_boot" to false),
        )
        env.exportReceipt = mapOf(
            "boot" to Hashes.sha256(bootBaseline),
            "init_boot" to Hashes.sha256(initBootBaseline),
        )
        env.modeState = if (fromMode == WorkMode.LITE) ModeState.MODE_A_ACTIVE else ModeState.MODE_B_ACTIVE
        env.currentMode = fromMode
        env.device = device
    }

    fun presentBaseline(): BaselineVerification = BaselineVerification(
        state = BaselineState.PRESENT_OK,
        id = "bl-1",
        check = BaselineCheck(
            id = "bl-1",
            provenance = BaselineProvenance.OEM_PACKAGE,
            bootSha256 = Hashes.sha256(bootBaseline),
            initBootSha256 = Hashes.sha256(initBootBaseline),
            clean = true,
        ),
        mismatch = emptyList(),
        blocker = null,
    )

    val targetBootId: String get() = request.switchId
}
