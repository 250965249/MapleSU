package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.installer.BaselineCaptureCodes
import dev.maplesu.manager.installer.BaselineProvisionOutcome
import dev.maplesu.manager.installer.BaselineProvisioner
import dev.maplesu.manager.installer.InstallCommitCodes
import dev.maplesu.manager.installer.InstallConfigMover
import dev.maplesu.manager.installer.InstallMoveOutcome
import dev.maplesu.manager.installer.InstallMovePhase
import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.switch.BaselineErrors
import dev.maplesu.manager.workmode.switch.BeginInputs
import dev.maplesu.manager.workmode.switch.BatteryFacts
import dev.maplesu.manager.workmode.switch.CandidateInput
import dev.maplesu.manager.workmode.switch.CandidateResult
import dev.maplesu.manager.workmode.switch.HiddenRecoveryFacts
import dev.maplesu.manager.workmode.switch.HiddenRecoveryFactsProvider
import dev.maplesu.manager.workmode.switch.HiddenState
import dev.maplesu.manager.workmode.switch.HiddenStateController
import dev.maplesu.manager.workmode.switch.HiddenStateStore
import dev.maplesu.manager.workmode.switch.HiddenSwitchCodes
import dev.maplesu.manager.workmode.switch.HiddenSwitchCoordinator
import dev.maplesu.manager.workmode.switch.HookResult
import dev.maplesu.manager.workmode.switch.ModeCommitSink
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.ModeSwitchHashes
import dev.maplesu.manager.workmode.switch.ModeSwitchRequest
import dev.maplesu.manager.workmode.switch.ModeSwitchSnapshots
import dev.maplesu.manager.workmode.switch.NoOpSwitchQuiesceHooks
import dev.maplesu.manager.workmode.switch.SwitchCandidateProducer
import dev.maplesu.manager.workmode.switch.SwitchDeviceFacts
import dev.maplesu.manager.workmode.switch.SwitchQuiesceHooks
import dev.maplesu.manager.workmode.switch.GatewayOutcome
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.UUID

/**
 * App 侧生产装配 + UI 后端（W08b）：零服务页面入口、startSwitch 执行调用序列、
 * fail-closed、重启后 verify 轮询收敛。全部依赖为 host fake（无 Android / 无 root）。
 */
class ModeSwitchFacadeTest {

    private val size = 4096L

    private fun status(
        state: String,
        switchId: String = "sw-1",
        pending: Boolean = state in setOf("BEGIN", "SNAPSHOT", "PRODUCE", "COMMIT", "REBOOT_REQUIRED", "VERIFYING"),
        error: String = "",
    ) = ClientStatus(
        switchId = switchId,
        state = state,
        stage = if (state == "REBOOT_REQUIRED") "S4" else "S2",
        step = if (state == "REBOOT_REQUIRED") "4g" else "snapshot",
        fromMode = "LITE",
        toMode = "KSU",
        error = error,
        errorDetail = "",
        planSha256 = "a".repeat(64),
        rebootRequired = state == "REBOOT_REQUIRED",
        bootObserved = false,
        canRollback = state in setOf("COMMIT", "REBOOT_REQUIRED", "VERIFYING", "RECOVERY_REQUIRED"),
        canResumeReboot = state == "REBOOT_REQUIRED",
        verifyFailures = 0,
        partitions = listOf(
            ClientPartition("boot", "RESTORE_BASELINE", size,
                "p".repeat(64), "t".repeat(64), "", "PENDING"),
            ClientPartition("init_boot", "WRITE_CANDIDATE", size,
                "q".repeat(64), "u".repeat(64), "", "PENDING"),
        ),
    )

    private class FakeClient : ModeSwitchClient {
        val calls = mutableListOf<String>()
        var preflightResult = ClientResult(true)
        var beginResult = ClientResult(true)
        var snapshotResult = ClientResult(true)
        var submitResult = ClientResult(true)
        var beginPlanFields: Map<String, String> = emptyMap()
        var commitResult = ClientResult(true, status = ClientStatus(
            "sw-1", "REBOOT_REQUIRED", "S4", "4g", "LITE", "KSU", "", "", "a".repeat(64),
            true, false, true, false, 0, listOf(
                ClientPartition("boot", "RESTORE_BASELINE", 4096, "p".repeat(64), "t".repeat(64), "", "DONE"),
                ClientPartition("init_boot", "WRITE_CANDIDATE", 4096, "q".repeat(64), "u".repeat(64), "", "DONE"),
            ),
        ))
        var rollbackResult = ClientResult(true)
        var verifyQueue = ArrayDeque<ClientResult>()
        var verifyDefault = ClientResult(true)
        var currentStatus: ClientStatus? = null
        var exportedKind: String? = null
        var markRebootCalls = 0
        var rollbackCalls = 0
        var abortCalls = 0
        var abortClosesTask = false
        var abortResult = ClientResult(true)
        var exportLogCalls = 0
        var statusCalls = 0
        var candidateSha: String? = null

        override suspend fun preflight(switchId: String, planFields: Map<String, String>): ClientResult {
            calls += "preflight"
            return preflightResult
        }

        override suspend fun begin(switchId: String, planFields: Map<String, String>,
                                   superuserJson: File, settingsMirrorJson: File): ClientResult {
            calls += "begin"
            beginPlanFields = planFields
            if (beginResult.ok) currentStatus = ClientStatus(
                switchId, "BEGIN", "S1", "begin", "LITE", "KSU", "", "", "", false, false,
                false, false, 0, listOf(
                    ClientPartition("boot", "RESTORE_BASELINE", 4096, "p".repeat(64), "", "", "PENDING"),
                    ClientPartition("init_boot", "WRITE_CANDIDATE", 4096, "q".repeat(64), "", "", "PENDING"),
                ),
            )
            return beginResult
        }

        override suspend fun snapshot(switchId: String): ClientResult {
            calls += "snapshot"
            if (snapshotResult.ok) currentStatus = ClientStatus(
                switchId, "SNAPSHOT", "S2", "snapshot", "LITE", "KSU", "", "", "", false, false,
                false, false, 0, listOf(
                    ClientPartition("boot", "RESTORE_BASELINE", 4096, "p".repeat(64), "", "", "PENDING"),
                    ClientPartition("init_boot", "WRITE_CANDIDATE", 4096, "q".repeat(64), "", "", "PENDING"),
                ),
            )
            return snapshotResult
        }

        override suspend fun exportImage(switchId: String, kind: String, partition: String,
                                         destination: File): Boolean {
            calls += "exportImage:$kind:$partition"
            exportedKind = kind
            destination.parentFile?.mkdirs()
            destination.writeBytes(ByteArray(4096) { 'I'.code.toByte() })
            return true
        }

        override suspend fun submitCandidate(switchId: String, partition: String,
                                             candidate: File, candidateSha256: String): ClientResult {
            calls += "submitCandidate:$partition"
            candidateSha = candidateSha256
            return submitResult
        }

        override suspend fun commit(switchId: String): ClientResult {
            calls += "commit"
            commitResult.status?.let { currentStatus = it }
            return commitResult
        }

        override suspend fun rollback(switchId: String): ClientResult {
            calls += "rollback"
            rollbackCalls++
            return rollbackResult
        }

        override suspend fun abort(switchId: String): ClientResult {
            calls += "abort"
            abortCalls++
            if (abortClosesTask && abortResult.ok) {
                val cancelled = currentStatus?.copy(state = "CANCELLED")
                // UltraRoot removes its journal; the successful abort reply carries the final status.
                currentStatus = null
                return abortResult.copy(status = cancelled)
            }
            return abortResult
        }

        override fun status(switchId: String): ClientStatus? {
            statusCalls++
            return currentStatus?.takeIf { switchId.isEmpty() || it.switchId == switchId }
        }

        override suspend fun verify(switchId: String): ClientResult {
            calls += "verify"
            return if (verifyQueue.isNotEmpty()) verifyQueue.removeFirst() else verifyDefault
        }

        override suspend fun markRebootRequested(switchId: String): Boolean {
            calls += "markReboot"
            markRebootCalls++
            return true
        }

        override suspend fun exportLog(switchId: String, destination: File): File? {
            exportLogCalls++
            destination.writeText("log")
            return destination
        }
    }

    private class FakeEnvironment(
        var active: WorkMode? = WorkMode.LITE,
        var facts: SwitchDeviceFacts? = SwitchDeviceFacts("_a", "fw", "5.10.198-android13-8-g", "Enforcing"),
        var battery: BatteryFacts = BatteryFacts(80, false),
        var freeBytes: Long = 1L shl 40,
        var bootId: String = "boot-1",
        val temp: File,
    ) : ModeSwitchAppEnvironment {
        var beginError = ""
        /** P0-1 第 3 项：null = 未接线（与生产默认一致，旧测试零改动）。 */
        var provisionerPort: BaselineProvisioner? = null
        var selectedPort: BaselineProvisioner? = null
        var selectedInput: ModeSwitchImages? = null
        var initBootPresent = true
        val diagnosticReads = mutableListOf<String>()
        override fun hasInitBoot(): Boolean { diagnosticReads += "hasInitBoot"; return initBootPresent }
        override fun selectedImages(target: WorkMode, images: ModeSwitchImages): BaselineProvisioner? {
            selectedInput = images
            return selectedPort
        }
        private val superuser = File(temp, "su.json").apply { writeText("{}") }
        private val settings = File(temp, "settings.json").apply { writeText("{}") }

        override fun activeMode(): WorkMode? = active
        override fun modeStateName(): String? { diagnosticReads += "modeState"; return if (active == null) null else "MODE_A_ACTIVE" }
        override fun bootId(): String { diagnosticReads += "bootId"; return bootId }
        override fun deviceFacts(): SwitchDeviceFacts? { diagnosticReads += "deviceFacts"; return facts }
        override fun battery(): BatteryFacts { diagnosticReads += "battery"; return battery }
        override fun freeBytes(): Long { diagnosticReads += "freeBytes"; return freeBytes }
        override fun provisioner(): BaselineProvisioner? { diagnosticReads += "provisioner"; return provisionerPort }
        override fun beginInputs(): BeginInputs =
            if (beginError.isEmpty()) BeginInputs(superuser, settings)
            else BeginInputs(null, null, beginError)
    }

    private class FakeHooks : SwitchQuiesceHooks {
        var ready = true
        var restoreChecks = 0
        override fun quiesce(fromMode: WorkMode) = HookResult.OK
        override fun restoreAfterFailure(fromMode: WorkMode) = HookResult.OK
        override fun withdrawLiteImplants() = HookResult.OK
        override fun implantRestoreReady(): Boolean { restoreChecks++; return ready }
        override fun restoreProducerSideEffects() = HookResult.OK
    }

    private class FakeProducer : SwitchCandidateProducer {
        var result: CandidateResult? = null
        var calls = 0
        var lastInput: CandidateInput? = null
        override fun produce(input: CandidateInput): CandidateResult {
            calls++
            lastInput = input
            result?.let { return it }
            val image = File(input.workDir, "candidate.bin")
            val bytes = ByteArray(input.baselineImage.length().toInt() * 0 + 4096) { 'C'.code.toByte() }
            image.writeBytes(bytes)
            return CandidateResult(image, Hashes.sha256(bytes), bytes.size.toLong())
        }
    }

    private class FakeSnapshots : ModeSwitchSnapshots {
        var fail = false
        var calls = 0
        var lastRequest: dev.maplesu.manager.workmode.switch.ModeSwitchRequest? = null
        override suspend fun preSwitchSnapshot(request: dev.maplesu.manager.workmode.switch.ModeSwitchRequest): GatewayOutcome {
            calls++
            lastRequest = request
            return if (fail) GatewayOutcome(false, "", ModeSwitchCodes.SNAPSHOT_FAILED, "injected")
            else GatewayOutcome(true, "")
        }

        override suspend fun restoreAfterRollback(
            request: dev.maplesu.manager.workmode.switch.ModeSwitchRequest,
        ): GatewayOutcome = GatewayOutcome(true, "")
    }

    private class FakeCommit : ModeCommitSink {
        var calls = 0
        var lastMode: WorkMode? = null
        override fun commit(mode: WorkMode, bootId: String, bootSha256: String, initBootSha256: String) {
            calls++
            lastMode = mode
        }
    }

    private class Harness(val snapshotsOk: Boolean = true) {
        val temp: File = TestFixtures.tempDir("facade").toFile()
        val client = FakeClient()
        val environment = FakeEnvironment(temp = temp)
        val hooks = FakeHooks()
        val producer = FakeProducer()
        val snapshots = FakeSnapshots().apply { fail = !snapshotsOk }
        val commit = FakeCommit()
        var delays = 0
        val receipts = mutableListOf<Triple<String, String, String?>>()
        var receiptFailure = false
        val facade: ModeSwitchFacade by lazy {
            facadeWith(hooks)
        }

        fun facadeWith(quiesceHooks: SwitchQuiesceHooks,
                       fingerprint: ((String) -> String?)? = null,
                       lifecycle: ModeSwitchEnvironmentLifecycle? = null,
                       normalBootUserland: () -> InstallMoveOutcome = { InstallMoveOutcome.OK }): ModeSwitchFacade =
            ModeSwitchFacade(
                client = client,
                environment = environment,
                producers = mapOf(WorkMode.LITE to producer, WorkMode.KSU to producer),
                workRoot = File(temp, "work"),
                snapshots = snapshots,
                hooks = quiesceHooks,
                modeCommit = commit,
                pollDelay = { delays++ },
                maxVerifyPolls = 3,
                ultraCredentialFingerprint = fingerprint,
                lifecycle = lifecycle,
                normalBootUserland = normalBootUserland,
                onInstallReceipt = { id, state, sha ->
                    if (state == "REBOOT_REQUIRED" && receiptFailure) error("ULTRA_PAIRING_STORE_FAILED")
                    receipts += Triple(id, state, sha)
                },
            )
    }

    @Test
    fun selectedNormalBootBypassesAutomaticBackupAndIsPatchedOnBoot() = runBlocking {
        val h = Harness()
        h.environment.provisionerPort = BaselineProvisioner { error("automatic backup must not run again") }
        h.environment.selectedPort = BaselineProvisioner { BaselineProvisionOutcome.Ready("selected-boot", false, "OEM_PACKAGE") }
        val selected = ModeSwitchImages(boot = File(h.temp, "chosen-boot.img"))
        val outcome = h.facade.startSwitch(WorkMode.KSU, images = selected)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertEquals(selected, h.environment.selectedInput)
        assertEquals("boot", h.client.beginPlanFields["targetPartition"])
        assertEquals("selected-boot", h.client.beginPlanFields["baselineId"])
        assertTrue(h.client.calls.contains("exportImage:BASE:boot"))
        assertTrue(h.client.calls.contains("submitCandidate:boot"))
        assertEquals("boot", h.snapshots.lastRequest?.targetPartition)
        assertEquals("boot", h.producer.lastInput?.partition)
        assertEquals("boot", ModeSwitchProgress(File(h.temp,
            "work/${(outcome as SwitchOutcome.AwaitingReboot).switchId}/switch-progress.properties"))
            .read()?.request?.targetPartition)
    }

    @Test fun normalSwitchVerifiesDaemonBeforeRebootWithoutAppStartup() = runBlocking {
        val h = Harness()
        val facade = h.facadeWith(h.hooks, normalBootUserland = {
            h.client.calls += "normal-userland"
            InstallMoveOutcome.OK
        })
        assertTrue(facade.startSwitch(WorkMode.KSU) is SwitchOutcome.AwaitingReboot)
        assertTrue(h.client.calls.indexOf("commit") < h.client.calls.indexOf("normal-userland"))
        assertTrue(h.client.calls.indexOf("normal-userland") < h.client.calls.indexOf("markReboot"))
    }

    @Test fun failedNormalUserlandRollsBackTheWrittenSwitch() = runBlocking {
        val h = Harness()
        val facade = h.facadeWith(h.hooks, normalBootUserland = {
            InstallMoveOutcome.failed("KSUD_BUSYBOX_UNUSABLE")
        })
        val result = facade.startSwitch(WorkMode.KSU) as SwitchOutcome.Failed
        assertEquals(InstallCommitCodes.MATERIALIZE_FAILED, result.code)
        assertTrue(result.detail.contains("KSUD_BUSYBOX_UNUSABLE"))
        assertEquals(1, h.client.rollbackCalls)
        assertEquals(0, h.client.markRebootCalls)
        assertTrue(h.receipts.none { it.second == "REBOOT_REQUIRED" })
    }

    @Test fun ultraSwitchDoesNotDeployNormalUserland() = runBlocking {
        val h = Harness()
        h.environment.active = WorkMode.KSU
        val facade = h.facadeWith(h.hooks, normalBootUserland = { error("Normal deployment in Ultra") })
        assertTrue(facade.startSwitch(WorkMode.LITE) is SwitchOutcome.AwaitingReboot)
    }

    @Test
    fun automaticNormalTargetOnBootOnlyDeviceStaysBootThroughoutSwitch() = runBlocking {
        val h = Harness()
        h.environment.initBootPresent = false
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertFalse(h.client.calls.contains("preflight"))
        assertEquals("boot", h.client.beginPlanFields["targetPartition"])
        assertTrue(h.client.calls.contains("exportImage:BASE:boot"))
        assertTrue(h.client.calls.contains("submitCandidate:boot"))
        assertEquals("boot", h.snapshots.lastRequest?.targetPartition)
        assertEquals("boot", h.producer.lastInput?.partition)
        assertEquals("boot", ModeSwitchProgress(File(h.temp,
            "work/${(outcome as SwitchOutcome.AwaitingReboot).switchId}/switch-progress.properties"))
            .read()?.request?.targetPartition)
    }

    @Test
    fun selectedUltraRestoreWithEmptyBootContinuesTheCompleteSwitch() = runBlocking {
        val h = Harness()
        h.environment.active = WorkMode.KSU
        h.environment.provisionerPort = BaselineProvisioner { error("automatic backup must not run again") }
        h.environment.selectedPort = BaselineProvisioner { BaselineProvisionOutcome.Ready("selected-input", false, "USER_SELECTED") }
        val selected = ModeSwitchImages(initBoot = File(h.temp, "restore-init_boot.img"))
        val outcome = h.facade.startSwitch(WorkMode.LITE, images = selected)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertNull(h.environment.selectedInput!!.boot)
        assertEquals(selected, h.environment.selectedInput)
        assertEquals("selected-input", h.client.beginPlanFields["baselineId"])
        assertEquals("boot", h.client.beginPlanFields["targetPartition"])
        assertTrue(h.client.calls.contains("submitCandidate:boot"))
        assertTrue(h.client.calls.contains("commit"))
    }

    @Test
    fun missingCompleteBackupDoesNotBlockSourceCarrierRecovery() = runBlocking {
        val h = Harness()
        h.environment.active = WorkMode.KSU
        h.environment.provisionerPort = BaselineProvisioner {
            BaselineProvisionOutcome.Failed(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, "unknown original")
        }
        val outcome = h.facade.startSwitch(WorkMode.LITE)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertEquals("", h.client.beginPlanFields["baselineId"])
        assertTrue(h.client.calls.contains("commit"))
        assertEquals(1, h.snapshots.calls)
    }

    @Test
    fun spaceFailureStillReportsItsCauseWithoutAskingForImages() = runBlocking {
        val h = Harness()
        h.client.snapshotResult = ClientResult(false, ModeSwitchCodes.SPACE_INSUFFICIENT, "no space")
        val outcome = h.facade.startSwitch(WorkMode.KSU) as SwitchOutcome.Failed
        assertEquals(ModeSwitchCodes.SPACE_INSUFFICIENT, outcome.code)
        assertFalse(h.client.calls.contains("commit"))
        assertEquals(1, h.client.abortCalls)
    }

    @Test
    fun unavailableSourceRequestsImagesOnlyAfterConfirmedAbort() = runBlocking {
        val h = Harness()
        h.client.snapshotResult = ClientResult(false, "SOURCE_RECOVERY_UNAVAILABLE", "ultra:boot")
        h.client.abortClosesTask = true
        assertEquals(SwitchOutcome.ImagesRequired(WorkMode.KSU, false), h.facade.startSwitch(WorkMode.KSU))
        assertEquals(listOf("begin", "snapshot", "abort"), h.client.calls)
        assertNull(h.client.currentStatus)
    }

    @Test
    fun failedOrUncertainAbortDoesNotReplaceSourceFailureWithAnImagePrompt() = runBlocking {
        for (abort in listOf(ClientResult(false, "ABORT_FAILED"),
            ClientResult(false, ModeSwitchRootProtocol.UNCERTAIN), ClientResult(true))) {
            val h = Harness()
            h.client.snapshotResult = ClientResult(false, "SOURCE_RECOVERY_UNAVAILABLE", "ultra:boot")
            h.client.abortResult = abort
            val outcome = h.facade.startSwitch(WorkMode.KSU)
            assertTrue("unexpected: $outcome", outcome is SwitchOutcome.Failed)
            assertFalse(h.client.calls.contains("commit"))
        }
    }

    @Test
    fun failedExplicitImageRecoveryRetainsItsActualFailure() = runBlocking {
        val h = Harness()
        h.environment.selectedPort = BaselineProvisioner { BaselineProvisionOutcome.Ready("selected", false, "USER_SELECTED") }
        h.client.snapshotResult = ClientResult(false, "SOURCE_RECOVERY_UNAVAILABLE", "ultra:boot")
        h.client.abortClosesTask = true
        val outcome = h.facade.startSwitch(WorkMode.KSU,
            images = ModeSwitchImages(boot = File(h.temp, "selected.img")))
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.Failed)
        assertEquals("SOURCE_RECOVERY_UNAVAILABLE", (outcome as SwitchOutcome.Failed).code)
        assertFalse(h.client.calls.contains("commit"))
    }

    // ------------------------------------------------------------------ canSwitch

    @Test
    fun canSwitchDoesNotConnectToTheInstallerOrReadDiagnostics() = runBlocking {
        val h = Harness()
        val eligibility = h.facade.canSwitch(WorkMode.KSU)
        assertTrue(eligibility is SwitchEligibility.Allowed)
        assertNotNull((eligibility as SwitchEligibility.Allowed).probeSwitchId)
        assertTrue(h.client.calls.isEmpty())
        assertEquals(0, h.client.statusCalls)
        assertTrue(h.environment.diagnosticReads.isEmpty())
        assertEquals(0, h.hooks.restoreChecks)
        assertEquals(0, h.snapshots.calls)
        assertEquals(0, h.producer.calls)
    }

    @Test
    fun lowAndUnknownBatteryNeverDisableEitherSwitchDirection() = runBlocking {
        for (active in listOf(WorkMode.LITE, WorkMode.KSU)) {
            val target = if (active == WorkMode.LITE) WorkMode.KSU else WorkMode.LITE
            for (level in listOf(-1, 0, 19, 20)) {
                val h = Harness()
                h.environment.active = active
                h.environment.battery = BatteryFacts(level, false)
                val eligibility = h.facade.canSwitch(target)
                assertTrue("$active level=$level: $eligibility", eligibility is SwitchEligibility.Allowed)
                assertTrue(h.client.calls.isEmpty())
            }
        }
    }

    @Test
    fun lowBatteryStillCompletesTheSimulatedSwitchCommit() = runBlocking {
        val h = Harness()
        h.environment.battery = BatteryFacts(0, false)
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertTrue(h.client.calls.contains("commit"))
    }

    @Test
    fun canSwitchAllowsUnknownModeToReachTheExecutionPage() = runBlocking {
        val h = Harness()
        h.environment.active = null
        val eligibility = h.facade.canSwitch(WorkMode.KSU)
        assertTrue(eligibility is SwitchEligibility.Allowed)
        assertTrue(h.facade.uiSwitchSupported(WorkMode.KSU))
        val support = h.facade.uiSupport(WorkMode.KSU)
        assertTrue(support.supported)
        assertNull(support.currentMode)
        assertTrue(support.blockers.isEmpty())
        assertTrue(h.client.calls.isEmpty())
        assertTrue(h.environment.diagnosticReads.isEmpty())
    }

    @Test
    fun canSwitchRejectsSameMode() = runBlocking {
        val eligibility = Harness().facade.canSwitch(WorkMode.LITE)
        assertTrue(eligibility is SwitchEligibility.Blocked)
        assertEquals(ModeSwitchCodes.SAME_MODE, (eligibility as SwitchEligibility.Blocked).code)
    }

    @Test
    fun canSwitchDoesNotUseHistoricalStatusAsAWriterLock() = runBlocking {
        val h = Harness()
        h.client.currentStatus = status("COMMIT")
        val eligibility = h.facade.canSwitch(WorkMode.KSU)
        assertTrue(eligibility is SwitchEligibility.Allowed)
        assertTrue(h.client.calls.isEmpty())
    }

    @Test
    fun incompleteDiagnosticsDoNotDisableTheSwitchEntry() = runBlocking {
        val h = Harness()
        h.environment.facts = null
        h.environment.battery = BatteryFacts(3, false)
        h.environment.bootId = ""
        h.environment.freeBytes = 0
        h.hooks.ready = false
        h.environment.provisionerPort = BaselineProvisioner { error("stock backup must not be requested") }
        h.client.preflightResult = ClientResult(false, BaselineErrors.BASELINE_MISSING, "no manifest")
        assertTrue(h.facade.canSwitch(WorkMode.KSU) is SwitchEligibility.Allowed)
        assertTrue(h.facade.uiSupport(WorkMode.KSU).supported)
        assertTrue(h.client.calls.isEmpty())
        assertEquals(0, h.client.statusCalls)
        assertTrue(h.environment.diagnosticReads.isEmpty())
        assertEquals(0, h.hooks.restoreChecks)
    }

    @Test
    fun startSwitchPreservesTheActualBeginErrorAndNeverCommits() = runBlocking {
        val h = Harness()
        h.client.beginResult = ClientResult(false, ModeSwitchCodes.ROOT_UNAVAILABLE, "root execution failed")
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.Failed)
        assertEquals(ModeSwitchCodes.ROOT_UNAVAILABLE, (outcome as SwitchOutcome.Failed).code)
        assertEquals("root execution failed", outcome.detail)
        assertEquals(listOf("begin"), h.client.calls)
        assertEquals(0, h.producer.calls)
    }

    // ------------------------------------------------------------------ 显式选择镜像与当前载体

    /** 记录"被调用"的 provisioner（顺序断言与零写盘断言共用一条 log ⇒ client.calls）。 */
    private fun recordingProvisioner(
        h: Harness,
        outcome: BaselineProvisionOutcome,
    ): BaselineProvisioner = BaselineProvisioner {
        h.client.calls += "provision"
        outcome
    }

    @Test
    fun startSwitchImportsExplicitImagesAndThreadsTheirId() = runBlocking {
        // 显式选择的输入先导入，真实 id 随 begin 传入；不要求独立预检。
        val h = Harness()
        h.environment.selectedPort =
            recordingProvisioner(h, BaselineProvisionOutcome.Ready("bl-a-1", false, "OEM_PACKAGE"))
        val outcome = h.facade.startSwitch(WorkMode.KSU,
            images = ModeSwitchImages(initBoot = File(h.temp, "selected.img")))
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        val provisionIndex = h.client.calls.indexOf("provision")
        val beginIndex = h.client.calls.indexOf("begin")
        assertTrue("provisioner 必须被调用: ${h.client.calls}", provisionIndex >= 0)
        assertFalse(h.client.calls.contains("preflight"))
        assertTrue("provision 必须早于 begin: ${h.client.calls}", provisionIndex < beginIndex)
        // begin 使用真实显式输入 id。
        assertEquals("bl-a-1", h.client.beginPlanFields["baselineId"])
    }

    @Test
    fun missingCompleteBackupDoesNotInterruptCarrierRecovery() = runBlocking {
        val h = Harness()
        h.environment.provisionerPort = recordingProvisioner(
            h,
            BaselineProvisionOutcome.Failed(BaselineCaptureCodes.CAPTURE_WRITE_FAILED, "asset missing"),
        )
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertFalse(h.client.calls.contains("provision"))
        assertTrue(h.client.calls.contains("snapshot"))
        assertEquals(1, h.producer.calls)
    }

    @Test
    fun explicitImageImportThrowBecomesAnExecutionFailure() = runBlocking {
        val h = Harness()
        h.environment.selectedPort = BaselineProvisioner {
            h.client.calls += "provision"
            throw IllegalStateException("boom")
        }
        val outcome = h.facade.startSwitch(WorkMode.KSU,
            images = ModeSwitchImages(initBoot = File(h.temp, "selected.img")))
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.Failed)
        assertEquals(BaselineCaptureCodes.CAPTURE_WRITE_FAILED, (outcome as SwitchOutcome.Failed).code)
        assertFalse(h.client.calls.contains("begin"))
        assertEquals(0, h.snapshots.calls)
    }

    @Test
    fun startSwitchWithoutProvisionerBeginsDirectlyWithCurrentCarrier() = runBlocking {
        val h = Harness()
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertEquals("begin", h.client.calls.first())
        assertFalse(h.client.calls.contains("provision"))
        assertEquals("", h.client.beginPlanFields["baselineId"])
    }

    @Test
    fun canSwitchNoLongerBlocksOnPermissiveSelinux() = runBlocking {
        // P0-1 第 1 项：SELinux 从"硬 blocker"改成"可修复/不阻断"。
        // 恢复动作只在 startSwitch 执行（canSwitch 被页面 init 与每次刷新走到，绝不能有副作用，
        // 见 ModeSwitchFacadeSelinuxTest.ensureIsNotCalledByCanSwitch）。
        val h = Harness()
        h.environment.facts = SwitchDeviceFacts("_a", "fw", "5.10.198-android13-8-g", "Permissive")
        val eligibility = h.facade.canSwitch(WorkMode.KSU)
        assertTrue("unexpected: $eligibility", eligibility is SwitchEligibility.Allowed)
        assertFalse(h.client.calls.contains("preflight"))
    }

    @Test
    fun startSwitchDoesNotRequireBootIdFactsOrReservedSpaceBeforeBegin() = runBlocking {
        val h = Harness()
        h.environment.bootId = ""
        h.environment.facts = null
        h.environment.freeBytes = 0
        h.hooks.ready = false
        h.environment.provisionerPort = BaselineProvisioner { error("complete backup must not be requested") }
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertEquals("begin", h.client.calls.first())
        assertFalse(h.client.calls.contains("preflight"))
        assertTrue(h.client.calls.contains("commit"))
        assertEquals(0, h.hooks.restoreChecks)
        assertFalse(h.environment.diagnosticReads.contains("freeBytes"))
        assertFalse(h.environment.diagnosticReads.contains("provisioner"))
    }

    @Test
    fun uiSupportAllowsANewAttemptWhenOnlyAHistoricalCommitRemains() = runBlocking {
        val h = Harness()
        h.client.currentStatus = status("COMMIT")
        val support = h.facade.uiSupport(WorkMode.KSU)
        assertTrue(support.supported)
        assertTrue(support.blockers.isEmpty())
        assertEquals(WorkMode.LITE, support.currentMode)
        val allowed = Harness().facade.uiSupport(WorkMode.KSU)
        assertTrue(allowed.supported)
        assertTrue(allowed.blockers.isEmpty())
    }

    // ------------------------------------------------------------------ startSwitch

    @Test
    fun startSwitchDrivesExecutionSequenceWithoutPreflightThroughRebootMarker() = runBlocking {
        val h = Harness()
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertEquals(
            listOf(
                "begin", "snapshot", "exportImage:BASE:init_boot",
                "submitCandidate:init_boot", "commit", "markReboot",
            ),
            h.client.calls.filterNot { it == "verify" },
        )
        assertEquals(1, h.producer.calls)
        assertEquals("BASE", h.client.exportedKind)
        assertNotNull(h.client.candidateSha)
        val sha = ModeSwitchHashes.sha256(File(File(h.temp, "work"), (outcome as SwitchOutcome.AwaitingReboot).switchId + "/candidate.bin"))
        assertEquals(sha, h.client.candidateSha)
        assertEquals(listOf(Triple(outcome.switchId, "REBOOT_REQUIRED", sha)), h.receipts)
    }

    @Test
    fun startSwitchReturnsUnresolvedModeAfterExecutionPreparation() = runBlocking {
        val h = Harness()
        h.environment.active = null
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue(outcome is SwitchOutcome.Blocked)
        assertTrue(h.client.calls.none { it == "begin" })
    }

    @Test
    fun executionPreparationCanResolveTheModeAfterNavigation() = runBlocking {
        val h = Harness()
        h.environment.active = null
        var prepares = 0
        val facade = ModeSwitchFacade(
            client = h.client, environment = h.environment,
            producers = mapOf(WorkMode.KSU to h.producer), workRoot = File(h.temp, "prepared-work"),
            snapshots = h.snapshots, hooks = h.hooks,
            lifecycle = object : ModeSwitchEnvironmentLifecycle {
                override fun prepare(): HookResult {
                    prepares++
                    h.environment.active = WorkMode.LITE
                    return HookResult.OK
                }
                override fun withdraw(request: ModeSwitchRequest) = HookResult.OK
                override fun restoreAfterFailure(request: ModeSwitchRequest) = HookResult.OK
            },
        )
        assertTrue(facade.uiSupport(WorkMode.KSU).supported)
        assertEquals(0, prepares)
        assertTrue(h.client.calls.isEmpty())
        val outcome = facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertEquals(1, prepares)
        assertEquals("LITE", h.client.beginPlanFields["fromMode"])
        assertEquals("begin", h.client.calls.first())
    }

    @Test
    fun firstBeginSelectsUltraRootBeforeCallerConfigMovesAreResolved() = runBlocking {
        val h = Harness()
        val unusedService = FakeClient()
        val selecting = SelectingModeSwitchClient(unusedService, { h.client }, { true })
        val facade = ModeSwitchFacade(
            client = selecting, environment = h.environment,
            producers = mapOf(WorkMode.KSU to h.producer), workRoot = File(h.temp, "selected-work"),
            snapshots = h.snapshots, hooks = h.hooks,
            moverFactory = { _, _, _ ->
                assertEquals(ModeSwitchClientKind.ULTRA_ROOT, selecting.selectedKind())
                assertEquals("begin", h.client.calls.first())
                h.client.calls += "mover-created"
                object : InstallConfigMover {
                    override fun moveOut(switchId: String, from: WorkMode, to: WorkMode): InstallMoveOutcome {
                        h.client.calls += "move-out"; return InstallMoveOutcome.OK
                    }
                    override fun moveIn(switchId: String, from: WorkMode, to: WorkMode): InstallMoveOutcome {
                        h.client.calls += "move-in"; return InstallMoveOutcome.OK
                    }
                    override fun materialize(switchId: String, from: WorkMode, to: WorkMode): InstallMoveOutcome {
                        h.client.calls += "materialize"; return InstallMoveOutcome.OK
                    }
                    override fun rollback(switchId: String, from: WorkMode, to: WorkMode,
                                          completed: Set<InstallMovePhase>) = InstallMoveOutcome.OK
                }
            },
        )
        assertEquals(ModeSwitchClientKind.SERVICE, selecting.selectedKind())
        assertTrue(facade.canSwitch(WorkMode.KSU) is SwitchEligibility.Allowed)
        assertEquals(ModeSwitchClientKind.SERVICE, selecting.selectedKind())
        val outcome = facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertTrue(unusedService.calls.isEmpty())
        assertEquals(
            listOf("begin", "mover-created", "snapshot", "exportImage:BASE:init_boot",
                "submitCandidate:init_boot", "move-out", "commit", "move-in", "materialize", "markReboot"),
            h.client.calls,
        )
    }

    @Test
    fun missingCallerMoverAbortsTheTaskCreatedByFirstBegin() = runBlocking {
        val h = Harness()
        h.client.abortClosesTask = true
        val selecting = SelectingModeSwitchClient(FakeClient(), { h.client }, { true })
        val facade = ModeSwitchFacade(
            client = selecting, environment = h.environment,
            producers = mapOf(WorkMode.KSU to h.producer), workRoot = File(h.temp, "missing-mover-work"),
            snapshots = h.snapshots, hooks = h.hooks,
            moverFactory = { _, _, _ -> error("mover unavailable") },
        )
        val outcome = facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.Failed)
        assertEquals(InstallCommitCodes.MOVE_STAGE_UNWIRED, (outcome as SwitchOutcome.Failed).code)
        assertEquals(listOf("begin", "abort"), h.client.calls)
        assertNull(h.client.currentStatus)
        assertEquals(0, h.producer.calls)
    }

    @Test
    fun startSwitchFailsWhenSnapshotServiceFailsAndNeverBegins() = runBlocking {
        val h = Harness(snapshotsOk = false)
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue(outcome is SwitchOutcome.Failed)
        assertEquals(ModeSwitchCodes.SNAPSHOT_FAILED, (outcome as SwitchOutcome.Failed).code)
        assertFalse(h.client.calls.contains("begin"))
    }

    @Test
    fun startSwitchIsBlockedWhenMirrorsUnavailableAndLeavesNoPendingTransaction() = runBlocking {
        val h = Harness()
        h.environment.beginError = ModeSwitchCodes.PREPARE_EXPORT_FAILED
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue(outcome is SwitchOutcome.Blocked)
        assertEquals(ModeSwitchCodes.PREPARE_EXPORT_FAILED, (outcome as SwitchOutcome.Blocked).code)
        assertEquals(ModeSwitchCodes.PREPARE_EXPORT_FAILED, outcome.detail)
        assertFalse(h.client.calls.contains("begin"))
        assertNull(h.client.currentStatus)
        assertFalse(h.facade.operationActive)
        assertFalse(File(h.temp, "work").walkTopDown().any { it.name == "switch-progress.properties" })
    }

    @Test
    fun startSwitchAbortsWhenProducerRejects() = runBlocking {
        val h = Harness()
        h.producer.result = CandidateResult(null, "", 0, ModeSwitchCodes.PRODUCE_FAILED, "injected")
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue(outcome is SwitchOutcome.Failed)
        assertEquals(ModeSwitchCodes.PRODUCE_FAILED, (outcome as SwitchOutcome.Failed).code)
        assertTrue(h.client.abortCalls >= 1)
        assertFalse(h.client.calls.contains("submitCandidate:init_boot"))
    }

    @Test
    fun startSwitchAbortsWhenSubmitRejected() = runBlocking {
        val h = Harness()
        h.client.submitResult = ClientResult(false, ModeSwitchCodes.PRODUCE_CANDIDATE_CHANGED, "sha")
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertEquals(ModeSwitchCodes.PRODUCE_CANDIDATE_CHANGED, (outcome as SwitchOutcome.Failed).code)
        assertTrue(h.client.abortCalls >= 1)
        assertFalse(h.client.calls.contains("commit"))
    }

    @Test
    fun startSwitchCommitRecoveryRequiredDoesNotAttemptRollback() = runBlocking {
        val h = Harness()
        h.client.commitResult = ClientResult(
            false, ModeSwitchCodes.VERIFY_PARTITION_MISMATCH, "",
            status("RECOVERY_REQUIRED", error = ModeSwitchCodes.VERIFY_PARTITION_MISMATCH),
        )
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        // RECOVERY_REQUIRED has no confirmed PRE images; retain the recovery failure code.
        assertEquals(InstallCommitCodes.PARTITION_ROLLBACK_FAILED, (outcome as SwitchOutcome.Failed).code)
        assertEquals(0, h.client.rollbackCalls)
    }

    @Test
    fun startSwitchCommitFailureRolledBackAttemptsRollback() = runBlocking {
        val h = Harness()
        h.client.commitResult = ClientResult(false, "WRITE_FAILED", "io", status("COMMIT"))
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue(outcome is SwitchOutcome.Failed)
        assertEquals("WRITE_FAILED", (outcome as SwitchOutcome.Failed).code)
        assertEquals(1, h.client.rollbackCalls)
    }

    @Test
    fun startSwitchRequiresProducerForTarget() = runBlocking {
        val h = Harness()
        val facade = ModeSwitchFacade(
            client = h.client, environment = h.environment,
            producers = mapOf(WorkMode.LITE to h.producer),
            workRoot = File(h.temp, "work2"), snapshots = h.snapshots, hooks = h.hooks,
        )
        assertTrue(facade.uiSwitchSupported(WorkMode.KSU))
        assertTrue(facade.uiSupport(WorkMode.KSU).supported)
        assertTrue(h.client.calls.isEmpty())
        // 真正执行到产出候选时返回错误并清退已建立任务。
        val outcome = facade.startSwitch(WorkMode.KSU)
        assertTrue(outcome is SwitchOutcome.Failed)
        assertEquals(ModeSwitchCodes.PRODUCE_FAILED, (outcome as SwitchOutcome.Failed).code)
    }

    // ------------------------------------------------------------------ 重启后收敛

    @Test
    fun reopenAfterRebootVerifiesAndCommitsMode() = runBlocking {
        val h = Harness()
        h.client.currentStatus = status("REBOOT_REQUIRED")
        val outcome = h.facade.reopenAfterReboot()
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.Verified)
        assertTrue(h.client.calls.contains("verify"))
        assertEquals(1, h.commit.calls)
        assertEquals(WorkMode.KSU, h.commit.lastMode)
    }

    @Test
    fun reopenPollsUntilVerificationConverges() = runBlocking {
        val h = Harness()
        h.client.currentStatus = status("VERIFYING")
        h.client.verifyQueue.addLast(ClientResult(false, ModeSwitchCodes.VERIFY_BOOT_NOT_OBSERVED, "boot"))
        h.client.verifyDefault = ClientResult(true)
        val outcome = h.facade.reopenAfterReboot()
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.Verified)
        assertTrue(h.delays >= 1)
    }

    @Test
    fun reopenReportsRecoveryRequired() = runBlocking {
        val h = Harness()
        h.client.currentStatus = status("RECOVERY_REQUIRED", error = "WRITE_ROLLBACK_FAILED")
        h.client.verifyQueue.addLast(ClientResult(false, "WRITE_ROLLBACK_FAILED", "rollback"))
        val outcome = h.facade.reopenAfterReboot()
        assertTrue(outcome is SwitchOutcome.Failed)
        assertEquals("WRITE_ROLLBACK_FAILED", (outcome as SwitchOutcome.Failed).code)
    }

    @Test
    fun reopenWithoutPendingRecordIsFailedNotThrowing() = runBlocking {
        val h = Harness()
        h.client.currentStatus = null
        val outcome = h.facade.reopenAfterReboot()
        assertTrue(outcome is SwitchOutcome.Failed)
        assertEquals(ModeSwitchCodes.PLAN_INVALID, (outcome as SwitchOutcome.Failed).code)
    }

    // ------------------------------------------------------------------ 其它动作

    @Test
    fun abortOnlyDelegatesForPendingSwitch() = runBlocking {
        val h = Harness()
        assertNull(h.facade.abort())
        h.client.currentStatus = status("PRODUCE")
        assertNotNull(h.facade.abort())
        assertEquals(1, h.client.abortCalls)
        // A committed partition must retain its journal and use rollback, never abort.
        h.client.currentStatus = status("COMMIT")
        assertEquals(ModeSwitchCodes.PENDING, h.facade.abort()?.code)
        assertEquals(1, h.client.abortCalls)
    }

    @Test
    fun rollbackAndExportLogDelegateToClient() = runBlocking {
        val h = Harness()
        h.client.currentStatus = status("COMMIT")
        assertNotNull(h.facade.rollback())
        assertEquals(1, h.client.rollbackCalls)
        val log = h.facade.exportLog(File(h.temp, "diag.txt"))
        assertNotNull(log)
        assertEquals(1, h.client.exportLogCalls)
    }

    @Test
    fun supportedFlagReflectsModeActivation() {
        val h = Harness()
        assertTrue(h.facade.supported)
        assertEquals(WorkMode.LITE, h.facade.currentMode())
        h.environment.active = null
        assertFalse(h.facade.supported)
        assertTrue(h.facade.uiSwitchSupported(WorkMode.KSU))
    }

    // ------------------------------------------------------------------ 植入诊断与执行动作

    @Test
    fun defaultNoOpHooksDoNotRequireAnImplantReadinessTicketForNavigation() = runBlocking {
        val h = Harness()
        val eligibility = h.facadeWith(NoOpSwitchQuiesceHooks).canSwitch(WorkMode.KSU)
        assertTrue(eligibility is SwitchEligibility.Allowed)
        assertTrue(h.client.calls.isEmpty())
    }

    @Test
    fun actualQuiesceHooksRemainInTheExecutionPath() = runBlocking {
        val h = Harness()
        val facade = h.facadeWith(FakeHooks().apply { ready = true })
        val eligibility = facade.canSwitch(WorkMode.KSU)
        assertTrue("unexpected: $eligibility", eligibility is SwitchEligibility.Allowed)
        val outcome = facade.startSwitch(WorkMode.KSU)
        assertTrue("startSwitch failed: $outcome", outcome is SwitchOutcome.AwaitingReboot)
    }

    @Test
    fun implantReadinessDiagnosticsDoNotBlockEitherNavigationDirection() = runBlocking {
        for (active in listOf(WorkMode.LITE, WorkMode.KSU)) {
            val h = Harness()
            h.environment.active = active
            h.hooks.ready = false
            val target = if (active == WorkMode.LITE) WorkMode.KSU else WorkMode.LITE
            assertTrue(h.facade.canSwitch(target) is SwitchEligibility.Allowed)
            assertEquals(0, h.hooks.restoreChecks)
            assertTrue(h.client.calls.isEmpty())
        }
    }

    // ------------------------------------------------------------------ 安装提交（P0-1 第 4 项）

    private fun installCandidate(h: Harness): dev.maplesu.manager.installer.InstallCandidateImage {
        val image = File(h.temp, "install-candidate.img").apply { writeBytes(ByteArray(size.toInt()) { 9 }) }
        return dev.maplesu.manager.installer.InstallCandidateImage(
            image = image,
            sha256 = ModeSwitchHashes.sha256(image),
            size = image.length(),
            partition = "init_boot",
        )
    }

    @Test
    fun installCommitRejectsWrongSourceModeWithoutTouchingTheService() = runBlocking {
        val h = Harness()
        // 已是 Normal（KSU）：Normal 安装必须显式失败，且一个客户端调用都不发。
        h.environment.active = WorkMode.KSU
        val outcome = h.facade.installCommit(installCandidate(h))
        assertTrue("expected Rejected, got $outcome",
            outcome is dev.maplesu.manager.installer.InstallCommitOutcome.Rejected)
        assertEquals(
            dev.maplesu.manager.installer.InstallCommitCodes.SOURCE_MODE_INVALID,
            (outcome as dev.maplesu.manager.installer.InstallCommitOutcome.Rejected).code,
        )
        assertTrue(h.client.calls.isEmpty())
    }

    @Test
    fun switchDoesNotRequestACompleteStockBaseline() = runBlocking {
        val h = Harness()
        var requested = false
        h.environment.provisionerPort = BaselineProvisioner {
            requested = true
            BaselineProvisionOutcome.Failed(BaselineErrors.BASELINE_MISSING, "no full stock backup")
        }
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertFalse("switch must use the captured carrier, not request a stock baseline", requested)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
    }

    @Test
    fun installCommitDoesNotRequestACompleteStockBaseline() = runBlocking {
        val h = Harness()
        var requested = false
        h.environment.provisionerPort = BaselineProvisioner {
            requested = true
            BaselineProvisionOutcome.Failed(BaselineErrors.BASELINE_MISSING, "no stock asset")
        }
        val outcome = h.facade.installCommit(installCandidate(h))
        assertFalse(requested)
        assertTrue("unexpected: $outcome",
            outcome is dev.maplesu.manager.installer.InstallCommitOutcome.AwaitingReboot)
    }

    @Test
    fun installPreparationResolvesAnInitiallyUnknownSourceMode() = runBlocking {
        val h = Harness()
        h.environment.active = null
        var prepares = 0
        val facade = h.facadeWith(h.hooks, lifecycle = object : ModeSwitchEnvironmentLifecycle {
            override fun prepare(): HookResult {
                prepares++
                h.environment.active = WorkMode.LITE
                return HookResult.OK
            }
            override fun withdraw(request: dev.maplesu.manager.workmode.switch.ModeSwitchRequest) = HookResult.OK
            override fun restoreAfterFailure(request: dev.maplesu.manager.workmode.switch.ModeSwitchRequest) = HookResult.OK
        })
        assertTrue(facade.uiSupport(WorkMode.KSU).supported)
        assertTrue(h.client.calls.isEmpty())
        val outcome = facade.installCommit(installCandidate(h))
        assertTrue("unexpected: $outcome", outcome is dev.maplesu.manager.installer.InstallCommitOutcome.AwaitingReboot)
        assertEquals(1, prepares)
        assertEquals("begin", h.client.calls.first())
        assertEquals("LITE", h.client.beginPlanFields["fromMode"])
    }

    @Test
    fun installPreparationFailureAndStillUnknownModeKeepTheirActualErrors() = runBlocking {
        for (channelFailure in listOf(false, true)) {
            val h = Harness()
            h.environment.active = null
            var prepares = 0
            val facade = h.facadeWith(h.hooks, lifecycle = object : ModeSwitchEnvironmentLifecycle {
                override fun prepare(): HookResult {
                    prepares++
                    return if (channelFailure) HookResult.failed("TEST_CHANNEL_ERROR", "prepare failed") else HookResult.OK
                }
                override fun withdraw(request: dev.maplesu.manager.workmode.switch.ModeSwitchRequest) = HookResult.OK
                override fun restoreAfterFailure(request: dev.maplesu.manager.workmode.switch.ModeSwitchRequest) = HookResult.OK
            })
            val outcome = facade.installCommit(installCandidate(h))
            assertTrue("unexpected: $outcome", outcome is dev.maplesu.manager.installer.InstallCommitOutcome.Rejected)
            outcome as dev.maplesu.manager.installer.InstallCommitOutcome.Rejected
            assertEquals(if (channelFailure) "TEST_CHANNEL_ERROR" else ModeSwitchCodes.STATE_UNDETERMINED, outcome.code)
            if (channelFailure) assertEquals("prepare failed", outcome.detail)
            assertEquals(1, prepares)
            assertTrue(h.client.calls.isEmpty())
        }
    }

    @Test
    fun installCommitSubmitsTheSelectedCandidateAndReturnsAwaitingReboot() = runBlocking {
        val h = Harness()
        h.environment.provisionerPort = BaselineProvisioner {
            BaselineProvisionOutcome.Ready("bl-a-deadbeef-001122334455", true, "OEM_PACKAGE")
        }
        val candidate = installCandidate(h)
        val outcome = h.facade.installCommit(candidate)
        assertTrue("expected AwaitingReboot, got $outcome",
            outcome is dev.maplesu.manager.installer.InstallCommitOutcome.AwaitingReboot)
        assertEquals(
            listOf("begin", "snapshot", "submitCandidate:init_boot", "commit", "markReboot"),
            h.client.calls,
        )
        // 「用户选的那个镜像」必须被提交（摘要一致），不是别的文件。
        assertEquals(candidate.sha256, h.client.candidateSha)
        assertFalse(h.client.calls.contains("preflight"))
        assertEquals("", h.client.beginPlanFields["baselineId"])
        assertEquals(listOf(Triple((outcome as dev.maplesu.manager.installer.InstallCommitOutcome.AwaitingReboot)
            .switchId, "REBOOT_REQUIRED", candidate.sha256)), h.receipts)
    }

    @Test
    fun installCommitNeverReportsSuccessBeforeCommitConfirmation() = runBlocking {
        val h = Harness()
        h.environment.provisionerPort = BaselineProvisioner {
            BaselineProvisionOutcome.Ready("bl-a-deadbeef-001122334455", true, "OEM_PACKAGE")
        }
        // 后端说 commit 成功，但状态还停在 SNAPSHOT：不得当成功，且不许发重启标记。
        h.client.commitResult = ClientResult(true, status = status("SNAPSHOT"))
        val outcome = h.facade.installCommit(installCandidate(h))
        assertEquals(
            dev.maplesu.manager.installer.InstallCommitCodes.COMMIT_NOT_CONFIRMED,
            (outcome as dev.maplesu.manager.installer.InstallCommitOutcome.Rejected).code,
        )
        assertTrue(h.client.calls.contains("rollback"))
        assertFalse(h.client.calls.contains("markReboot"))
        assertTrue(h.receipts.none { it.second == "REBOOT_REQUIRED" })
    }

    @Test
    fun installCommitUsesCarrierSnapshotsWithoutABaselineProvisioner() = runBlocking {
        val h = Harness()
        // provisionerPort 默认 null = 生产装配里 provisioner() 构造失败/未接线。
        val outcome = h.facade.installCommit(installCandidate(h))
        assertTrue("unexpected: $outcome",
            outcome is dev.maplesu.manager.installer.InstallCommitOutcome.AwaitingReboot)
        assertEquals("", h.client.beginPlanFields["baselineId"])
        assertTrue(h.client.calls.contains("snapshot"))
    }

    @Test
    fun invalidInstallPartitionKeepsTheTypedResultAndDoesNotCreateProgress() = runBlocking {
        val h = Harness()
        val id = UUID.randomUUID().toString()
        val outcome = h.facade.installCommit(installCandidate(h).copy(partition = "vendor_boot"),
            requestedSwitchId = id)
        assertTrue("unexpected: $outcome",
            outcome is dev.maplesu.manager.installer.InstallCommitOutcome.Rejected)
        assertEquals(InstallCommitCodes.PARTITION_INVALID,
            (outcome as dev.maplesu.manager.installer.InstallCommitOutcome.Rejected).code)
        assertEquals(id, outcome.switchId)
        assertTrue(h.client.calls.isEmpty())
        assertFalse(File(h.temp, "work/$id/switch-progress.properties").exists())
    }

    @Test
    fun selectedNormalBootInstallPersistsItsActualTarget() = runBlocking {
        val h = Harness()
        val candidate = installCandidate(h).copy(partition = "boot")
        h.client.commitResult = ClientResult(true, status = status("REBOOT_REQUIRED").copy(
            partitions = listOf(ClientPartition("boot", "WRITE_CANDIDATE", candidate.size,
                "a".repeat(64), candidate.sha256, candidate.sha256, "DONE"))))
        val outcome = h.facade.installCommit(candidate)
        assertTrue("unexpected: $outcome",
            outcome is dev.maplesu.manager.installer.InstallCommitOutcome.AwaitingReboot)
        assertFalse(h.client.calls.contains("preflight"))
        assertEquals("boot", h.client.beginPlanFields["targetPartition"])
        assertTrue(h.client.calls.contains("submitCandidate:boot"))
        val id = (outcome as dev.maplesu.manager.installer.InstallCommitOutcome.AwaitingReboot).switchId
        val progress = ModeSwitchProgress(File(h.temp, "work/$id/switch-progress.properties")).read()!!
        assertEquals("boot", progress.request.targetPartition)
        assertTrue(progress.waiting)
    }

    @Test
    fun selectedUltraInstallConfirmsItsExactCandidateAndPersistsTheCandidateFingerprint() = runBlocking {
        val h = Harness()
        h.environment.active = WorkMode.KSU
        h.environment.provisionerPort = BaselineProvisioner {
            BaselineProvisionOutcome.Ready("ultra-base", true, "OEM_PACKAGE")
        }
        val id = UUID.randomUUID().toString()
        val candidate = installCandidate(h).copy(partition = "boot")
        h.client.commitResult = ClientResult(true, status = status("REBOOT_REQUIRED", id).copy(
            fromMode = "KSU", toMode = "LITE", partitions = listOf(
                ClientPartition("boot", "WRITE_CANDIDATE", candidate.size, "a".repeat(64),
                    candidate.sha256, candidate.sha256, "DONE"))))
        val facade = h.facadeWith(h.hooks, fingerprint = { task ->
            assertEquals(id, task)
            "b".repeat(64)
        })
        val outcome = facade.installCommit(candidate, requestedSwitchId = id, target = WorkMode.LITE)
        assertTrue("unexpected: $outcome", outcome is dev.maplesu.manager.installer.InstallCommitOutcome.AwaitingReboot)
        assertEquals(listOf(Triple(id, "REBOOT_REQUIRED", candidate.sha256)), h.receipts)
        val progress = ModeSwitchProgress(File(h.temp, "work/$id/switch-progress.properties")).read()
        assertEquals("b".repeat(64), progress?.ultraBoot?.keyFingerprint)
    }

    @Test
    fun receiptPersistenceFailureDuringMigrationRollsBackBeforeReportingSuccess() = runBlocking {
        val h = Harness()
        h.environment.active = WorkMode.KSU
        h.receiptFailure = true
        val failure = runCatching { h.facade.startSwitch(WorkMode.LITE) }.exceptionOrNull()
        assertEquals("ULTRA_PAIRING_STORE_FAILED", failure?.message)
        assertTrue(h.client.calls.contains("rollback"))
        assertFalse(h.client.calls.contains("markReboot"))
        assertTrue(h.receipts.none { it.second == "REBOOT_REQUIRED" })
        assertTrue(h.receipts.any { it.second == "RESTORING" })
    }

    // ------------------------------------------------------------------ M4：安装链的 H5 前置

    private class InstallHiddenController : HiddenStateController {
        val states = mutableMapOf(WorkMode.LITE to HiddenState.OFF, WorkMode.KSU to HiddenState.OFF)
        val calls = mutableListOf<String>()
        override fun state(mode: WorkMode): HiddenState = states.getValue(mode)
        override fun setOff(mode: WorkMode): HookResult {
            calls += "off:${mode.suffix}"
            states[mode] = HiddenState.OFF
            return HookResult.OK
        }
        override fun setOn(mode: WorkMode): HookResult {
            calls += "on:${mode.suffix}"
            states[mode] = HiddenState.ON
            return HookResult.OK
        }
    }

    private class InstallHiddenStore : HiddenStateStore {
        val saved = mutableMapOf<WorkMode, HiddenState>()
        override fun saved(mode: WorkMode): HiddenState = saved[mode] ?: HiddenState.OFF
        override fun save(mode: WorkMode, state: HiddenState) {
            saved[mode] = state
        }
    }

    private fun facadeWithHidden(
        h: Harness,
        controller: InstallHiddenController,
        store: InstallHiddenStore,
        recovery: HiddenRecoveryFacts,
    ): ModeSwitchFacade = ModeSwitchFacade(
        client = h.client,
        environment = h.environment,
        producers = mapOf(WorkMode.LITE to h.producer, WorkMode.KSU to h.producer),
        workRoot = File(h.temp, "work"),
        snapshots = h.snapshots,
        hooks = h.hooks,
        modeCommit = h.commit,
        hidden = HiddenSwitchCoordinator(controller, store, HiddenRecoveryFactsProvider { recovery }),
        pollDelay = { h.delays++ },
        maxVerifyPolls = 3,
    )

    @Test
    fun installCommitPersistsAndUnhidesSourceBeforeAnyServiceCall() = runBlocking {
        val h = Harness()
        val controller = InstallHiddenController().apply { states[WorkMode.LITE] = HiddenState.ON }
        val store = InstallHiddenStore()
        val facade = facadeWithHidden(
            h, controller, store,
            HiddenRecoveryFacts(secretCodeConfigured = true, secretCodeVerified = true),
        )
        h.environment.provisionerPort = BaselineProvisioner {
            BaselineProvisionOutcome.Ready("bl-a-deadbeef-001122334455", true, "OEM_PACKAGE")
        }
        val outcome = facade.installCommit(installCandidate(h))
        assertTrue("unexpected: $outcome", outcome is dev.maplesu.manager.installer.InstallCommitOutcome.AwaitingReboot)
        // M4：源模式隐藏被**持久化**（切回可恢复）并真的关掉了。
        assertEquals(HiddenState.ON, store.saved[WorkMode.LITE])
        assertEquals(HiddenState.OFF, controller.state(WorkMode.LITE))
        assertEquals(listOf("off:A"), controller.calls)
    }

    @Test
    fun installCommitFailsBeforeAnyServiceCallWhenHiddenCannotBeReset() = runBlocking {
        val h = Harness()
        val controller = InstallHiddenController().apply { states[WorkMode.LITE] = HiddenState.ON }
        val store = InstallHiddenStore()
        // 恢复通道缺失 ⇒ H5 必须 fail-closed，且仍在写盘之前。
        val facade = facadeWithHidden(h, controller, store, HiddenRecoveryFacts())
        h.environment.provisionerPort = BaselineProvisioner {
            BaselineProvisionOutcome.Ready("bl-a-deadbeef-001122334455", true, "OEM_PACKAGE")
        }
        val outcome = facade.installCommit(installCandidate(h))
        assertEquals(
            HiddenSwitchCodes.HIDDEN_RECOVERY_NOT_CONFIGURED,
            (outcome as dev.maplesu.manager.installer.InstallCommitOutcome.Rejected).code,
        )
        assertTrue(h.client.calls.isEmpty())
        assertEquals(HiddenState.ON, controller.state(WorkMode.LITE))
    }
}
