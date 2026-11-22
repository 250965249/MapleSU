package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.switch.BatteryFacts
import dev.maplesu.manager.workmode.switch.BeginInputs
import dev.maplesu.manager.workmode.switch.CandidateInput
import dev.maplesu.manager.workmode.switch.CandidateResult
import dev.maplesu.manager.workmode.switch.GatewayOutcome
import dev.maplesu.manager.workmode.switch.HookResult
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.ModeSwitchRequest
import dev.maplesu.manager.workmode.switch.ModeSwitchSnapshots
import dev.maplesu.manager.workmode.switch.SuperuserReconciler
import dev.maplesu.manager.workmode.switch.SwitchCandidateProducer
import dev.maplesu.manager.workmode.switch.SwitchDeviceFacts
import dev.maplesu.manager.workmode.switch.SwitchQuiesceHooks
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.UUID

/**
 * SELinux 执行时恢复接线（host，全 fake）。
 * 页面不读取预检/恢复状态；真正执行时先恢复，再 begin。
 * 恢复失败、活性丢失和实际 begin 失败保持真实结果，写入前停止。
 * UNWIRED 仍按已有执行契约区分已 Enforcing 与实际需要恢复。
 */
class ModeSwitchFacadeSelinuxTest {

    private class FakeRestorer(
        var result: SelinuxRestoreResult,
        private val log: MutableList<String>? = null,
    ) : SelinuxRestorer {
        var calls = 0
        override fun ensureEnforcing(): SelinuxRestoreResult {
            calls++
            log?.add("selinux-ensure")
            return result
        }
    }

    private class Env(private val temp: File) : ModeSwitchAppEnvironment {
        private val dir = File(temp, "mirror").apply { mkdirs() }
        var restorer: SelinuxRestorer? = null
        var active: WorkMode = WorkMode.LITE
        /** 本机 SELinux 读数；默认 Permissive（自动恢复的目标场景）。 */
        var selinux: String = "Permissive"
        var battery: BatteryFacts = BatteryFacts(80, false)
        var free: Long = 1L shl 40
        override fun activeMode(): WorkMode? = active
        override fun modeStateName(): String? = "MODE_A_ACTIVE"
        override fun bootId(): String = "boot-1"
        // 注意：deviceFacts 默认是 Permissive —— canSwitch 不得因此阻断（P0-1 第 1 项）。
        override fun deviceFacts(): SwitchDeviceFacts =
            SwitchDeviceFacts("_a", "fw", "5.10.198-android13-8-g", selinux)
        override fun battery(): BatteryFacts = battery
        override fun freeBytes(): Long = free
        override fun beginInputs(): BeginInputs {
            val su = File(dir, "su.json").apply { writeText("{}") }
            val settings = File(dir, "settings.json").apply { writeText("{}") }
            return BeginInputs(su, settings)
        }
        override fun selinuxRestorer(): SelinuxRestorer? = restorer
    }

    private class Producer : SwitchCandidateProducer {
        var calls = 0
        override fun produce(input: CandidateInput): CandidateResult {
            calls++
            val image = File(input.workDir, "candidate.bin")
            image.writeBytes(ByteArray(4096) { 'C'.code.toByte() })
            return CandidateResult(image, Hashes.sha256(image.readBytes()), image.length())
        }
    }

    private class Snapshots : ModeSwitchSnapshots {
        override suspend fun preSwitchSnapshot(request: ModeSwitchRequest) = GatewayOutcome(true, "")
        override suspend fun restoreAfterRollback(request: ModeSwitchRequest) = GatewayOutcome(true, "")
    }

    private object ReadyHooks : SwitchQuiesceHooks {
        override fun quiesce(fromMode: WorkMode) = HookResult.OK
        override fun restoreAfterFailure(fromMode: WorkMode) = HookResult.OK
        override fun withdrawLiteImplants() = HookResult.OK
        override fun implantRestoreReady() = true
        override fun restoreProducerSideEffects() = HookResult.OK
    }

    private class Harness {
        val temp: File = TestFixtures.tempDir("selinux-facade").toFile()

        /** restorer 与 client 共用一条调用序记录（L-5：只记 client.calls 无法证明恢复在前）。 */
        val log = mutableListOf<String>()
        val client = FakeClient(log)
        val producer = Producer()
        val environment = Env(temp)
        val restorer = FakeRestorer(SelinuxRestoreResult(SelinuxRestoreResult.ENFORCING), log)
        val facade: ModeSwitchFacade by lazy {
            ModeSwitchFacade(
                client = client,
                environment = environment,
                producers = mapOf(WorkMode.LITE to producer, WorkMode.KSU to producer),
                workRoot = File(temp, "work"),
                snapshots = Snapshots(),
                hooks = ReadyHooks,
                superuser = SuperuserReconciler { HookResult.OK },
            )
        }
    }

    // ------------------------------------------------------------------ 页面零副作用

    @Test
    fun ensureIsNotCalledByCanSwitchOrUiSupport() = runBlocking {
        // 页面 init/每次刷新都会走到这两个方法：绝不能在这里 setenforce。
        val h = Harness()
        h.environment.restorer = h.restorer
        val eligibility = h.facade.canSwitch(WorkMode.KSU)
        assertTrue("unexpected: $eligibility", eligibility is SwitchEligibility.Allowed)
        h.facade.uiSupport(WorkMode.KSU)
        assertEquals(
            "canSwitch/uiSupport 触发了 SELinux 恢复（= 打开设置页就 setenforce）",
            0, h.restorer.calls,
        )
        assertTrue(h.client.calls.isEmpty())
        assertTrue(h.log.isEmpty())
    }

    // ------------------------------------------------------------------ 执行恢复次序与真实结果

    @Test
    fun startSwitchRepairsSelinuxBeforeAnyServiceCall() = runBlocking {
        val h = Harness()
        h.environment.restorer = h.restorer
        h.restorer.result = SelinuxRestoreResult(
            status = SelinuxRestoreResult.ENFORCING,
            attempted = true,
            rootAlive = true,
        )
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertEquals("恢复必须只做一次", 1, h.restorer.calls)
        // restorer 与 client 共用记录，恢复发生在真正 begin 之前。
        assertEquals(
            "恢复必须在实际 begin 之前: ${h.log}",
            listOf("selinux-ensure", "begin"),
            h.log.take(2),
        )
        assertEquals(0, h.log.count { it == "preflight" })
        assertTrue(h.client.calls.contains("commit"))
        assertTrue(h.client.calls.contains("markReboot"))
    }

    @Test
    fun startSwitchRestoresAndBeginsWithoutConsumingADiagnosticPreflight() = runBlocking {
        val h = Harness()
        h.environment.restorer = h.restorer
        h.client.defaultPreflight = ClientResult(false, ModeSwitchCodes.SELINUX_NOT_ENFORCING, "Permissive")
        assertTrue(h.facade.canSwitch(WorkMode.KSU) is SwitchEligibility.Allowed)
        assertTrue(h.log.isEmpty())
        h.restorer.result = SelinuxRestoreResult(
            status = SelinuxRestoreResult.ENFORCING, attempted = true, rootAlive = true,
        )
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertEquals(listOf("selinux-ensure", "begin"), h.log)
        assertEquals(1, h.restorer.calls)
        assertFalse(h.client.calls.contains("preflight"))
    }

    @Test
    fun startSwitchPreservesActualBeginFailureAfterSelinuxRepair() = runBlocking {
        val h = Harness()
        h.environment.restorer = h.restorer
        h.restorer.result = SelinuxRestoreResult(
            status = SelinuxRestoreResult.ENFORCING, attempted = true, rootAlive = true,
        )
        h.client.beginResult = ClientResult(false, ModeSwitchCodes.ROOT_UNAVAILABLE, "actual root failure")
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.Failed)
        assertEquals(ModeSwitchCodes.ROOT_UNAVAILABLE, (outcome as SwitchOutcome.Failed).code)
        assertEquals("actual root failure", outcome.detail)
        assertEquals(listOf("selinux-ensure", "begin"), h.log)
        assertEquals(listOf("begin"), h.client.calls)
        assertEquals(0, h.producer.calls)
    }

    @Test
    fun startSwitchFailsWithSelinuxCodeBeforeAnyServiceMutation() = runBlocking {
        val h = Harness()
        h.environment.restorer = h.restorer
        h.restorer.result = SelinuxRestoreResult(
            status = SelinuxRestoreResult.PERMISSIVE,
            attempted = true,
            detail = "setenforce not confirmed",
        )
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.Failed)
        val failed = outcome as SwitchOutcome.Failed
        assertEquals(ModeSwitchCodes.SELINUX_NOT_ENFORCING, failed.code)
        assertTrue(failed.detail.contains("Permissive"))
        assertTrue("SELinux 失败后不得发出任何写调用: ${h.client.calls}", h.client.calls.isEmpty())
        // Local eligibility does not query old transaction status to exclude new work.
        assertEquals(0, h.client.statusCalls)
        assertEquals(0, h.producer.calls)
    }

    @Test
    fun startSwitchFailsWithRootUnavailableWhenLivenessIsLost() = runBlocking {
        // setenforce 成功但根通道被打断（Pro 内核靠 permissive 维持通道的情形）：
        // 必须在写任何字节之前失败，而不是进 begin/commit。
        val h = Harness()
        h.environment.restorer = h.restorer
        h.restorer.result = SelinuxRestoreResult(
            status = SelinuxRestoreResult.ENFORCING,
            attempted = true,
            rootAlive = false,
            detail = "id -u != 0 after setenforce",
        )
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.Failed)
        val failed = outcome as SwitchOutcome.Failed
        assertEquals(ModeSwitchCodes.ROOT_UNAVAILABLE, failed.code)
        assertTrue("一个字节都还没写: ${h.client.calls}", h.client.calls.isEmpty())
        assertEquals(0, h.producer.calls)
    }

    // ------------------------------------------------------------------ 同模式与诊断事实

    @Test
    fun sameModeSkipsRepairWhileLowSpaceDoesNotBlockExecution() = runBlocking {
        val sameMode = Harness()
        sameMode.environment.restorer = sameMode.restorer
        val sameOutcome = sameMode.facade.startSwitch(WorkMode.LITE)
        assertTrue("unexpected: $sameOutcome", sameOutcome is SwitchOutcome.Blocked)
        assertEquals(ModeSwitchCodes.SAME_MODE, (sameOutcome as SwitchOutcome.Blocked).code)
        assertEquals(0, sameMode.restorer.calls)
        assertTrue(sameMode.client.calls.isEmpty())

        val lowSpace = Harness()
        lowSpace.environment.restorer = lowSpace.restorer
        lowSpace.environment.free = 0
        val spaceOutcome = lowSpace.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $spaceOutcome", spaceOutcome is SwitchOutcome.AwaitingReboot)
        assertEquals(1, lowSpace.restorer.calls)
        assertEquals(listOf("selinux-ensure", "begin"), lowSpace.log)
        assertTrue(lowSpace.client.calls.contains("commit"))
    }

    @Test
    fun lowBatteryStillRepairsSelinuxAndCommitsTheRequestedSwitch() = runBlocking {
        val h = Harness()
        h.environment.restorer = h.restorer
        h.environment.battery = BatteryFacts(5, false)
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertEquals(1, h.restorer.calls)
        assertTrue(h.client.calls.contains("commit"))
        assertEquals(listOf("selinux-ensure", "begin"), h.log)
    }

    // ------------------------------------------------------------------ M-2：UNWIRED 契约

    @Test
    fun unwiredRestorerFailsExplicitlyWhenSelinuxIsNotEnforcing() = runBlocking {
        // 非 Enforcing + UNWIRED ⇒ 显式失败（不静默继续，也不"接上线就每次硬失败"）。
        val h = Harness()
        h.environment.restorer = SelinuxRestorer.UNWIRED
        h.environment.selinux = "Permissive"
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.Failed)
        val failed = outcome as SwitchOutcome.Failed
        assertEquals(ModeSwitchCodes.SELINUX_NOT_ENFORCING, failed.code)
        assertTrue("detail 必须说明未接线: ${failed.detail}", failed.detail.contains("unwired"))
        assertTrue("零写调用: ${h.client.calls}", h.client.calls.isEmpty())
        assertEquals(0, h.producer.calls)
    }

    @Test
    fun unwiredRestorerContinuesWhenSelinuxIsAlreadyEnforcing() = runBlocking {
        // 已 Enforcing + UNWIRED ⇒ 未接线等价于"不需要修"，必须继续（不得每次切换都失败）。
        val h = Harness()
        h.environment.restorer = SelinuxRestorer.UNWIRED
        h.environment.selinux = "Enforcing"
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertTrue(h.client.calls.contains("commit"))
    }

    @Test
    fun startSwitchWithoutRestorerKeepsOldBehavior() = runBlocking {
        // 未接线（selinuxRestorer() == null）→ 不做恢复、也不新增阻断。
        val h = Harness()
        h.environment.restorer = null
        h.environment.selinux = "Permissive"
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertEquals(0, h.restorer.calls)
    }

    @Test
    fun startSwitchSkipsRootWorkWhenAlreadyEnforcing() = runBlocking {
        // 入口已 Enforcing：restorer 报告 attempted=false → 不做 liveness 判定，直接继续。
        val h = Harness()
        h.environment.restorer = h.restorer
        h.restorer.result = SelinuxRestoreResult(
            status = SelinuxRestoreResult.ENFORCING,
            attempted = false,
            rootAlive = false,
        )
        val outcome = h.facade.startSwitch(WorkMode.KSU)
        assertTrue("unexpected: $outcome", outcome is SwitchOutcome.AwaitingReboot)
        assertFalse(h.client.calls.isEmpty())
    }

    // ------------------------------------------------------------------ fake client

    private class FakeClient(private val log: MutableList<String>) : ModeSwitchClient {
        val calls = mutableListOf<String>()

        /** `status` 是只读调用（M-1 的本地判定会用到），单独计数，不混进写调用序列。 */
        var statusCalls = 0
        var currentStatus: ClientStatus? = null

        var defaultPreflight: ClientResult = ClientResult(true)
        var beginResult: ClientResult = ClientResult(true)

        override suspend fun preflight(switchId: String, planFields: Map<String, String>): ClientResult {
            calls += "preflight"
            log += "preflight"
            return defaultPreflight
        }

        override suspend fun begin(
            switchId: String,
            planFields: Map<String, String>,
            superuserJson: File,
            settingsMirrorJson: File,
        ): ClientResult {
            calls += "begin"
            log += "begin"
            if (!beginResult.ok) return beginResult
            currentStatus = snapshot(switchId, planFields["toMode"] ?: "KSU")
            return ClientResult(true, status = currentStatus)
        }

        override suspend fun snapshot(switchId: String): ClientResult {
            calls += "snapshot"; return ClientResult(true, status = currentStatus)
        }

        override suspend fun exportImage(
            switchId: String,
            kind: String,
            partition: String,
            destination: File,
        ): Boolean {
            calls += "exportImage:$kind:$partition"
            destination.parentFile?.mkdirs()
            destination.writeBytes(ByteArray(4096) { 'I'.code.toByte() })
            return true
        }

        override suspend fun submitCandidate(
            switchId: String,
            partition: String,
            candidate: File,
            candidateSha256: String,
        ): ClientResult {
            calls += "submitCandidate:$partition"; return ClientResult(true)
        }

        override suspend fun commit(switchId: String): ClientResult {
            calls += "commit"
            currentStatus = rebootRequired()
            return ClientResult(true, status = currentStatus)
        }

        override suspend fun rollback(switchId: String) = ClientResult(true)
        override suspend fun abort(switchId: String) = ClientResult(true)

        override fun status(switchId: String): ClientStatus? {
            statusCalls++
            return currentStatus
        }

        override suspend fun verify(switchId: String) = ClientResult(true, status = currentStatus)

        override suspend fun markRebootRequested(switchId: String): Boolean {
            calls += "markReboot"; return true
        }

        override suspend fun exportLog(switchId: String, destination: File): File? = destination

        companion object {
            fun snapshot(switchId: String, toMode: String) = ClientStatus(
                switchId, "SNAPSHOT", "S2", "snapshot", "LITE", toMode, "", "", "", false, false,
                false, false, 0, partitions(),
            )

            fun rebootRequired(toMode: String = "KSU", fromMode: String = "LITE") = ClientStatus(
                UUID.randomUUID().toString(), "REBOOT_REQUIRED", "S4", "4g", fromMode, toMode,
                "", "", "a".repeat(64), true, false, true, false, 0, partitions(),
            )

            private fun partitions() = listOf(
                ClientPartition("boot", "RESTORE_BASELINE", 4096,
                    "p".repeat(64), "t".repeat(64), "", "PENDING"),
                ClientPartition("init_boot", "WRITE_CANDIDATE", 4096,
                    "q".repeat(64), "u".repeat(64), "", "PENDING"),
            )
        }
    }
}
