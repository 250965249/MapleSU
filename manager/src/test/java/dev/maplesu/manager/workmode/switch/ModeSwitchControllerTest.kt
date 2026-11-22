package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * W08 编排主用例（02 §5/§6）：每阶段失败 → 逆序回滚 → ROLLED_BACK / RECOVERY_REQUIRED。
 *
 * Fake 网关内部真实调用 `InstallerMultiPartitionTransaction`，因此回滚顺序、读回校验与
 * 终态分类走的是 installer-core 的真实实现（不是测试里另写一套）。
 */
class ModeSwitchControllerTest {

    private fun begin(h: ModeSwitchHarness) = runBlocking { h.controller.begin(h.request) }

    private fun bytes(h: ModeSwitchHarness, name: String) = String(h.partitions.getValue(name).bytes)

    private fun record(h: ModeSwitchHarness) = h.authority.read(h.request.switchId)!!

    @Test
    fun normalAutomaticallyUsesBootWhenTheDeviceHasNoInitBoot() = runBlocking {
        val h = ModeSwitchHarness()
        h.partitions.remove("init_boot")
        h.env.inventory = PartitionInventory(setOf("boot"), mapOf("boot" to 4096L))
        h.env.device = h.env.device.copy(kernelRelease = "5.10.198-android12-8-g1234")
        val result = h.controller.begin(h.request)
        assertTrue("unexpected: $result", result is ModeSwitchRun.AwaitingReboot)
        assertEquals(listOf("boot"), h.gateway.lastCommitWritten)
    }

    @Test
    fun explicitNormalBootUsesOnlyBootEvenWhenInitBootExists() = runBlocking {
        val h = ModeSwitchHarness()
        val request = h.request.copy(targetPartition = "boot", sourcePartition = "boot")
        val result = h.controller.begin(request)
        assertTrue("unexpected: $result", result is ModeSwitchRun.AwaitingReboot)
        assertEquals(listOf("boot"), h.gateway.lastCommitWritten)
        assertTrue(h.partitions.getValue("init_boot").writeLog.isEmpty())
        assertEquals("boot", record(h).targetPartition)
        assertEquals("boot", record(h).sourcePartition)
    }

    @Test
    fun normalBootToUltraDoesNotRestoreInitBoot() = runBlocking {
        val h = ModeSwitchHarness(WorkMode.KSU, WorkMode.LITE)
        val request = h.request.copy(targetPartition = "boot", sourcePartition = "boot")
        val result = h.controller.begin(request)
        assertTrue("unexpected: $result", result is ModeSwitchRun.AwaitingReboot)
        assertEquals(listOf("boot"), h.gateway.lastCommitWritten)
        assertTrue(h.partitions.getValue("init_boot").writeLog.isEmpty())
    }

    @Test
    fun unknownNormalSourceReadsAvailableCarriersAndSkipsUnchangedInitBoot() = runBlocking {
        val h = ModeSwitchHarness(WorkMode.KSU, WorkMode.LITE)
        h.partitions.getValue("init_boot").bytes = h.initBootBaseline.copyOf()
        val result = h.controller.begin(h.request)
        assertTrue("unexpected: $result", result is ModeSwitchRun.AwaitingReboot)
        assertEquals("", record(h).sourcePartition)
        assertEquals(listOf("boot"), h.gateway.lastCommitWritten)
        assertTrue(h.partitions.getValue("init_boot").writeLog.isEmpty())
    }

    @Test
    fun normalInitBootToUltraRestoresInitBootBeforeBoot() = runBlocking {
        val h = ModeSwitchHarness(WorkMode.KSU, WorkMode.LITE)
        val result = h.controller.begin(h.request.copy(targetPartition = "boot", sourcePartition = "init_boot"))
        assertTrue("unexpected: $result", result is ModeSwitchRun.AwaitingReboot)
        assertEquals(listOf("init_boot", "boot"), h.gateway.lastCommitWritten)
        assertEquals(h.initBootBaseline.toList(), h.partitions.getValue("init_boot").bytes.toList())
    }

    @Test
    fun unchangedCandidateStillRestoresTheSourceAndSkipsTheTargetWrite() = runBlocking {
        val h = ModeSwitchHarness()
        val candidate = h.initBootBaseline.copyOf()
        candidate[candidate.size - 1] = (candidate.last().toInt() xor 0x5a).toByte()
        h.partitions.getValue("init_boot").bytes = candidate
        val result = h.controller.begin(h.request)
        assertTrue("unexpected: $result", result is ModeSwitchRun.AwaitingReboot)
        assertEquals(listOf("boot"), h.gateway.lastCommitWritten)
        assertEquals(h.bootBaseline.toList(), h.partitions.getValue("boot").bytes.toList())
        assertTrue(h.partitions.getValue("init_boot").writeLog.isEmpty())
        h.bootId = "boot-2"
        assertTrue(h.controller.verifyAfterBoot(h.request.switchId) is ModeSwitchRun.Verified)
    }

    @Test
    fun noEffectivePartitionWriteStillStopsBeforeCommit() = runBlocking {
        val h = ModeSwitchHarness()
        h.partitions.getValue("boot").bytes = h.bootBaseline.copyOf()
        val candidate = h.initBootBaseline.copyOf()
        candidate[candidate.size - 1] = (candidate.last().toInt() xor 0x5a).toByte()
        h.partitions.getValue("init_boot").bytes = candidate
        val result = h.controller.begin(h.request)
        assertTrue("unexpected: $result", result is ModeSwitchRun.Failed)
        assertEquals("SWITCH_STEP_NO_OP", (result as ModeSwitchRun.Failed).code)
        assertEquals(0, h.gateway.preparedPlans)
        assertEquals(0, h.gateway.commits)
        assertTrue(h.partitions.values.all { it.writeLog.isEmpty() })
    }

    @Test
    fun happyPathRestoresSourceThenWritesTargetAndAwaitsReboot() = runBlocking {
        val h = ModeSwitchHarness()
        val run = h.controller.begin(h.request)
        assertTrue("unexpected: $run", run is ModeSwitchRun.AwaitingReboot)
        // A→B(LKM)：boot 还原 baseline，init_boot 写候选。
        assertEquals("B".repeat(4096), bytes(h, "boot"))
        assertNotEquals("S".repeat(4096), bytes(h, "init_boot"))
        assertNotEquals("I".repeat(4096), bytes(h, "init_boot"))
        val persisted = record(h)
        assertEquals(SwitchStateNames.REBOOT_REQUIRED, persisted.state)
        assertTrue(persisted.pending)
        assertTrue(persisted.planSha256.matches(Regex("[0-9a-f]{64}")))
        assertTrue(h.journal.lines.any { it.op == SwitchOp.PREPARED.wire })
        assertTrue(h.journal.lines.any { it.op == SwitchOp.REBOOT_PENDING.wire })
        assertEquals(1, h.hooks.withdrawCalls)
        assertEquals(1, h.gateway.preparedPlans)
        assertEquals(1, h.gateway.commits)
    }

    @Test
    fun rebootThenVerifyConvergesToVerifiedAndCommitsMode() = runBlocking {
        val h = ModeSwitchHarness()
        assertTrue(h.controller.begin(h.request) is ModeSwitchRun.AwaitingReboot)
        h.bootId = "boot-2"
        val reboot = h.controller.requestReboot(h.request.switchId)
        assertTrue("unexpected: $reboot", reboot is ModeSwitchRun.AwaitingReboot)
        val verify = h.controller.verifyAfterBoot(h.request.switchId)
        assertTrue("unexpected: $verify", verify is ModeSwitchRun.Verified)
        assertEquals(SwitchStateNames.VERIFIED, record(h).state)
        assertFalse(record(h).pending)
        assertEquals(1, h.modeCommit.calls)
        assertTrue(h.journal.lines.any { it.op == SwitchOp.VERIFIED.wire })
        val status = h.controller.status(h.request.switchId)!!
        assertFalse(status.pending)
        assertFalse(status.requiresExternalRecovery)
        assertNull(status.externalRecovery)
    }

    @Test
    fun s0FailureWritesNoSwitchRecord() = runBlocking {
        val h = ModeSwitchHarness()
        h.env.freeBytes = 0
        val run = h.controller.begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        val failed = run as ModeSwitchRun.Failed
        assertEquals(SwitchStateNames.FAILED_PRE_WRITE, failed.state)
        assertEquals(ModeSwitchCodes.SPACE_INSUFFICIENT, failed.code)
        assertTrue(h.authority.read() is AuthorityRead.Missing)
    }

    @Test
    fun lowBatteryDoesNotBlockTheRequestedPartitionTransaction() = runBlocking {
        val h = ModeSwitchHarness()
        h.env.battery = BatteryFacts(1, false)
        val run = h.controller.begin(h.request)
        assertTrue("unexpected: $run", run is ModeSwitchRun.AwaitingReboot)
        assertEquals(1, h.gateway.commits)
        assertEquals(SwitchStateNames.REBOOT_REQUIRED, record(h).state)
    }

    @Test
    fun s1SnapshotFailureIsFailedPreWriteAndKeepsEvidence() = runBlocking {
        val h = ModeSwitchHarness()
        h.snapshots.failPre = true
        val run = h.controller.begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(ModeSwitchCodes.SNAPSHOT_FAILED, (run as ModeSwitchRun.Failed).code)
        val persisted = record(h)
        assertEquals(SwitchStateNames.FAILED_PRE_WRITE, persisted.state)
        assertEquals(ModeSwitchCodes.SNAPSHOT_FAILED, persisted.error.code)
    }

    @Test
    fun s1ServiceBeginFailureDoesNotTouchPartitions() = runBlocking {
        val h = ModeSwitchHarness()
        h.gateway.failBegin = "INSTALLER_OPERATION_BUSY"
        val run = h.controller.begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals("INSTALLER_OPERATION_BUSY", (run as ModeSwitchRun.Failed).code)
        assertEquals("P".repeat(4096), bytes(h, "boot"))
        assertEquals("S".repeat(4096), bytes(h, "init_boot"))
    }

    @Test
    fun s2PreImageMismatchIsRejectedBeforeAnyWrite() = runBlocking {
        val h = ModeSwitchHarness()
        h.gateway.tamperPreExport = true
        val run = h.controller.begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(ModeSwitchCodes.PRE_IMAGE_CHANGED, (run as ModeSwitchRun.Failed).code)
        assertEquals("P".repeat(4096), bytes(h, "boot"))
    }

    @Test
    fun s2MissingBaselineImageIsDetected() = runBlocking {
        val h = ModeSwitchHarness()
        h.gateway.baselineBytes = mapOf("boot" to h.bootBaseline)
        val run = h.controller.begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(BaselineErrors.BASELINE_CORRUPT, (run as ModeSwitchRun.Failed).code)
    }

    @Test
    fun s3ProducerFailureCleansSideEffectsAndKeepsPartitions() = runBlocking {
        val h = ModeSwitchHarness()
        h.producer.failCode = ModeSwitchCodes.PRODUCE_FAILED
        val run = h.controller.begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(ModeSwitchCodes.PRODUCE_FAILED, (run as ModeSwitchRun.Failed).code)
        assertTrue(h.hooks.producerCleanupCalls >= 1)
        assertEquals("P".repeat(4096), bytes(h, "boot"))
        assertEquals(SwitchStateNames.FAILED_PRE_WRITE, record(h).state)
    }

    @Test
    fun s3ShortCandidateIsRejectedByFullLengthRule() = runBlocking {
        val h = ModeSwitchHarness()
        h.producer.truncateBytes = 1
        val run = h.controller.begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(ModeSwitchCodes.PRODUCE_OUTPUT_SIZE_INVALID, (run as ModeSwitchRun.Failed).code)
    }

    @Test
    fun s3DigestMismatchIsRejected() = runBlocking {
        val h = ModeSwitchHarness()
        h.producer.reportWrongSha = true
        val run = h.controller.begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(ModeSwitchCodes.PRODUCE_CANDIDATE_CHANGED, (run as ModeSwitchRun.Failed).code)
    }

    @Test
    fun s3SubmitRefusalKeepsPartitions() = runBlocking {
        val h = ModeSwitchHarness()
        h.gateway.failSubmit = ModeSwitchCodes.SPACE_INSUFFICIENT
        val run = h.controller.begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(ModeSwitchCodes.SPACE_INSUFFICIENT, (run as ModeSwitchRun.Failed).code)
        assertEquals("P".repeat(4096), bytes(h, "boot"))
    }

    @Test
    fun s4QuiesceFailureRollsBackAndKeepsPreContent() = runBlocking {
        val h = ModeSwitchHarness()
        h.hooks.failQuiesce = true
        val run = h.controller.begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        val failed = run as ModeSwitchRun.Failed
        assertEquals(SwitchStateNames.ROLLED_BACK, failed.state)
        assertEquals(ModeSwitchCodes.QUIESCE_TIMEOUT, failed.code)
        assertEquals("P".repeat(4096), bytes(h, "boot"))
        assertEquals("S".repeat(4096), bytes(h, "init_boot"))
        assertEquals(SwitchStateNames.ROLLED_BACK, record(h).state)
    }

    @Test
    fun s4WithdrawImplantsFailureRollsBackBeforeWriteWindow() = runBlocking {
        val h = ModeSwitchHarness()
        h.hooks.failWithdraw = true
        val run = h.controller.begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(SwitchStateNames.ROLLED_BACK, (run as ModeSwitchRun.Failed).state)
        assertEquals("P".repeat(4096), bytes(h, "boot"))
    }

    @Test
    fun s4SecondPartitionFailureRollsBackInReverseOrder() = runBlocking {
        val h = ModeSwitchHarness()
        // 第二个写入的分区（init_boot candidate）第一次写失败，BDT 自身可还原 → 多分区逆序回滚。
        h.partitions.getValue("init_boot").failOnceAfter = 0
        val run = h.controller.begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        val failed = run as ModeSwitchRun.Failed
        assertEquals(SwitchStateNames.ROLLED_BACK, failed.state)
        assertEquals("P".repeat(4096), bytes(h, "boot"))
        assertEquals("S".repeat(4096), bytes(h, "init_boot"))
    }

    @Test
    fun s4RollbackFailureYieldsRecoveryRequired() = runBlocking {
        val h = ModeSwitchHarness()
        // 写失败且还原也失败（同一设备句柄）→ 只能外部恢复。
        h.partitions.getValue("init_boot").failAlwaysAfter = 0
        val run = h.controller.begin(h.request)
        assertTrue(run is ModeSwitchRun.Failed)
        val failed = run as ModeSwitchRun.Failed
        assertEquals(SwitchStateNames.RECOVERY_REQUIRED, failed.state)
        assertEquals(ModeSwitchCodes.ROLLBACK_FAILED, failed.code)
        assertEquals(SwitchStateNames.RECOVERY_REQUIRED, record(h).state)
        val status = h.controller.status(h.request.switchId)!!
        assertTrue(status.requiresExternalRecovery)
        assertTrue(status.externalRecovery!!.instructions.contains("不自动重启"))
    }

    @Test
    fun s5RejectedRebootKeepsAwaitingStateAndCountsAttempt() = runBlocking {
        val h = ModeSwitchHarness()
        assertTrue(h.controller.begin(h.request) is ModeSwitchRun.AwaitingReboot)
        h.bootId = "boot-2"
        h.gateway.rebootAccepted = false
        val run = h.controller.requestReboot(h.request.switchId)
        assertTrue(run is ModeSwitchRun.Incomplete)
        val incomplete = run as ModeSwitchRun.Incomplete
        assertEquals(SwitchStateNames.REBOOT_REQUIRED, incomplete.state)
        assertEquals(ModeSwitchCodes.REBOOT_NOT_OBSERVED, incomplete.code)
        assertEquals(1, record(h).attempts.rebootRequests)
    }

    @Test
    fun s5BootIdUnchangedIsReportedAsNotObserved() = runBlocking {
        val h = ModeSwitchHarness()
        assertTrue(h.controller.begin(h.request) is ModeSwitchRun.AwaitingReboot)
        val run = h.controller.requestReboot(h.request.switchId)
        assertTrue(run is ModeSwitchRun.Incomplete)
        assertEquals(ModeSwitchCodes.REBOOT_NOT_OBSERVED, (run as ModeSwitchRun.Incomplete).code)
    }

    @Test
    fun s6VerifyMismatchRollsBackWhenTargetRootAvailable() = runBlocking {
        val h = ModeSwitchHarness()
        assertTrue(h.controller.begin(h.request) is ModeSwitchRun.AwaitingReboot)
        h.bootId = "boot-2"
        h.env.targetRoot = true
        h.gateway.verifyCodeOverride = ModeSwitchCodes.VERIFY_PARTITION_MISMATCH
        val run = h.controller.verifyAfterBoot(h.request.switchId)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(SwitchStateNames.ROLLED_BACK, (run as ModeSwitchRun.Failed).state)
        assertEquals("P".repeat(4096), bytes(h, "boot"))
    }

    @Test
    fun s6VerifyMismatchWithoutTargetRootIsRecoveryRequired() = runBlocking {
        val h = ModeSwitchHarness()
        assertTrue(h.controller.begin(h.request) is ModeSwitchRun.AwaitingReboot)
        h.bootId = "boot-2"
        h.env.targetRoot = false
        h.gateway.verifyCodeOverride = ModeSwitchCodes.VERIFY_PARTITION_MISMATCH
        val run = h.controller.verifyAfterBoot(h.request.switchId)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(SwitchStateNames.RECOVERY_REQUIRED, (run as ModeSwitchRun.Failed).state)
    }

    @Test
    fun s6ConsumerFailureIsRetryableOnceThenForcedRecovery() = runBlocking {
        val h = ModeSwitchHarness()
        assertTrue(h.controller.begin(h.request) is ModeSwitchRun.AwaitingReboot)
        h.bootId = "boot-2"
        h.consumer.failures = 2
        val first = h.controller.verifyAfterBoot(h.request.switchId)
        assertTrue(first is ModeSwitchRun.Incomplete)
        assertEquals(SwitchStateNames.VERIFYING, (first as ModeSwitchRun.Incomplete).state)
        assertEquals(ModeSwitchCodes.VERIFY_CONSUMER_FAILED, first.code)
        val second = h.controller.verifyAfterBoot(h.request.switchId)
        assertTrue(second is ModeSwitchRun.Failed)
        assertEquals(SwitchStateNames.RECOVERY_REQUIRED, (second as ModeSwitchRun.Failed).state)
        assertEquals(ModeSwitchCodes.VERIFY_CONSUMER_FAILED, second.code)
    }

    @Test
    fun s6SuperuserFailureDoesNotBlockVerifiedButIsRecorded() = runBlocking {
        val h = ModeSwitchHarness()
        assertTrue(h.controller.begin(h.request) is ModeSwitchRun.AwaitingReboot)
        h.bootId = "boot-2"
        h.superuser.fail = true
        val run = h.controller.verifyAfterBoot(h.request.switchId)
        assertTrue(run is ModeSwitchRun.Verified)
        val persisted = record(h)
        assertEquals(SwitchStateNames.VERIFIED, persisted.state)
        assertEquals(ModeSwitchCodes.VERIFY_SUPERUSER_FAILED, persisted.error.code)
        assertEquals(1, h.modeCommit.calls)
    }

    @Test
    fun abortIsAllowedInPreWriteStatesAndForbiddenLater() = runBlocking {
        val h = ModeSwitchHarness()
        h.authority.write(
            SwitchRecord(
                switchId = h.request.switchId,
                state = SwitchStateNames.PRODUCE,
                stage = "S3",
                step = SwitchSteps.PRODUCE,
                fromMode = "LITE",
                toMode = "KSU",
                baselineId = "bl-1",
                startBootId = "boot-1",
            ),
        )
        val run = h.controller.abort(h.request.switchId)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(SwitchStateNames.CANCELLED, (run as ModeSwitchRun.Failed).state)
        assertEquals(SwitchStateNames.CANCELLED, record(h).state)
    }

    @Test
    fun recoverResumesPreWritePhaseFromPersistedRecord() = runBlocking {
        val h = ModeSwitchHarness()
        h.authority.write(
            SwitchRecord(
                switchId = h.request.switchId,
                state = SwitchStateNames.PRODUCE,
                stage = "S3",
                step = SwitchSteps.PRODUCE,
                fromMode = "LITE",
                toMode = "KSU",
                baselineId = "bl-1",
                startBootId = "boot-1",
                partitions = listOf(
                    SwitchRecordPartition(
                        "boot", "RESTORE_BASELINE", 4096,
                        Hashes.sha256(h.partitions.getValue("boot").bytes), "", "", "PENDING",
                    ),
                    SwitchRecordPartition(
                        "init_boot", "WRITE_CANDIDATE", 4096,
                        Hashes.sha256(h.partitions.getValue("init_boot").bytes), "", "", "PENDING",
                    ),
                ),
            ),
        )
        val outcome = h.controller.recover(h.request.switchId)
        assertTrue("unexpected: $outcome", outcome is RecoveryRun.Resumed)
        val resumed = (outcome as RecoveryRun.Resumed).run
        assertTrue("unexpected: $resumed", resumed is ModeSwitchRun.AwaitingReboot)
        assertEquals("B".repeat(4096), bytes(h, "boot"))
    }

    @Test
    fun recoverRollsBackRecordedFailure() = runBlocking {
        val h = ModeSwitchHarness()
        h.authority.write(
            SwitchRecord(
                switchId = h.request.switchId,
                state = SwitchStateNames.COMMIT,
                stage = "S4",
                step = SwitchSteps.WRITE_CANDIDATE,
                fromMode = "LITE",
                toMode = "KSU",
                baselineId = "bl-1",
                startBootId = "boot-1",
                error = SwitchRecordError(ModeSwitchCodes.WRITE_FAILED, "S4", "4d", "injected", 1),
                partitions = listOf(
                    SwitchRecordPartition(
                        "boot", "RESTORE_BASELINE", 4096,
                        Hashes.sha256(h.partitions.getValue("boot").bytes),
                        Hashes.sha256(h.bootBaseline), "", "FAILED",
                    ),
                ),
            ),
        )
        val outcome = h.controller.recover(h.request.switchId)
        assertTrue("unexpected: $outcome", outcome is RecoveryRun.RolledBack)
        assertEquals(SwitchStateNames.ROLLED_BACK, record(h).state)
    }

    @Test
    fun recoverRequiresExternalRecoveryForUnattributedContent() = runBlocking {
        val h = ModeSwitchHarness()
        h.partitions.getValue("boot").bytes = "X".repeat(4096).toByteArray()
        h.authority.write(
            SwitchRecord(
                switchId = h.request.switchId,
                state = SwitchStateNames.COMMIT,
                stage = "S4",
                step = SwitchSteps.RESTORE_BASELINE,
                fromMode = "LITE",
                toMode = "KSU",
                baselineId = "bl-1",
                startBootId = "boot-1",
                partitions = listOf(
                    SwitchRecordPartition(
                        "boot", "RESTORE_BASELINE", 4096,
                        Hashes.sha256(h.bootBaseline), "b".repeat(64), "", "INTENT",
                    ),
                ),
            ),
        )
        val outcome = h.controller.recover(h.request.switchId)
        assertTrue("unexpected: $outcome", outcome is RecoveryRun.RequiresRecovery)
        assertEquals(SwitchStateNames.RECOVERY_REQUIRED, record(h).state)
    }

    @Test
    fun recoverTerminalRecordIsNothingToDo() = runBlocking {
        val h = ModeSwitchHarness()
        h.authority.write(
            SwitchRecord(
                switchId = h.request.switchId,
                state = SwitchStateNames.VERIFIED,
                fromMode = "LITE",
                toMode = "KSU",
                baselineId = "bl-1",
            ),
        )
        assertEquals(RecoveryRun.NothingToDo, h.controller.recover())
    }

    @Test
    fun beginMoreThanOnceForSameSwitchResumesInsteadOfDuplicating() = runBlocking {
        val h = ModeSwitchHarness()
        assertTrue(h.controller.begin(h.request) is ModeSwitchRun.AwaitingReboot)
        val second = h.controller.begin(h.request)
        // 已过 S3：不再重头开始；返回真实持久状态。
        assertTrue("unexpected: $second", second is ModeSwitchRun.Incomplete)
        assertEquals(SwitchStateNames.REBOOT_REQUIRED, (second as ModeSwitchRun.Incomplete).state)
    }

    @Test
    fun differentSwitchWhilePendingIsRefused() = runBlocking {
        val h = ModeSwitchHarness()
        assertTrue(h.controller.begin(h.request) is ModeSwitchRun.AwaitingReboot)
        val other = h.request.copy(switchId = java.util.UUID.randomUUID().toString())
        val run = h.controller.begin(other)
        assertTrue(run is ModeSwitchRun.Failed)
        assertEquals(ModeSwitchCodes.PENDING, (run as ModeSwitchRun.Failed).code)
    }

    @Test
    fun exportDiagnosticsUsesGatewayAndRequiresRecord() = runBlocking {
        val h = ModeSwitchHarness()
        assertNull(h.controller.exportDiagnostics(h.request.switchId, java.io.File(h.temp, "diag.txt")))
        assertTrue(h.controller.begin(h.request) is ModeSwitchRun.AwaitingReboot)
        val file = h.controller.exportDiagnostics(h.request.switchId, java.io.File(h.temp, "diag.txt"))
        assertTrue(file != null && file.isFile)
    }
}
