package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.installer.BaselineProvisioning
import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.switch.BaselineCheck
import dev.maplesu.manager.workmode.switch.BaselineErrors
import dev.maplesu.manager.workmode.switch.BaselineProvenance
import dev.maplesu.manager.workmode.switch.BaselineState
import dev.maplesu.manager.workmode.switch.BaselineVerification
import dev.maplesu.manager.workmode.switch.CandidateResult
import dev.maplesu.manager.workmode.switch.FakeBaselineStore
import dev.maplesu.manager.workmode.switch.FakeInstallerGateway
import dev.maplesu.manager.workmode.switch.FakePartition
import dev.maplesu.manager.workmode.switch.FakeSwitchFacts
import dev.maplesu.manager.workmode.switch.FileSwitchAuthority
import dev.maplesu.manager.workmode.switch.FileSwitchMoveStage
import dev.maplesu.manager.workmode.switch.MoveStagePlan
import dev.maplesu.manager.workmode.switch.MoveStageResult
import dev.maplesu.manager.workmode.switch.SwitchJournal
import dev.maplesu.manager.workmode.switch.SwitchMoveStage
import dev.maplesu.manager.workmode.storage.MovePathRoots
import dev.maplesu.manager.workmode.storage.MoveSet
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.ModeSwitchHashes
import dev.maplesu.manager.workmode.switch.RecordingSwitchJournal
import dev.maplesu.manager.workmode.switch.SwitchDeviceFacts
import dev.maplesu.manager.workmode.switch.SwitchJournalFactory
import dev.maplesu.manager.workmode.switch.SwitchRecord
import dev.maplesu.manager.workmode.switch.SwitchStateNames
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.IOException
import java.util.UUID

/**
 * W08 服务端增量状态机（AIDL 12 方法的委托目标）主机测试。
 *
 * 覆盖：未预检/未就绪 fail-closed；S1→S2→S3→S4→S5→S6 全链路委托；pending/损坏/越权参数拒绝；
 * 回滚与重启标记语义（服务不自行 reboot）。
 */
class ModeSwitchDeviceDelegateTest {

    private class Harness(
        private val stage: SwitchMoveStage? = null,
        /** P0-1 第 3 项：默认 = 生产不变量（App 侧已接线基线自动获取）⇒ CTA 不灰。 */
        provisionable: Boolean = BaselineProvisioning.APP_WIRED,
        private val withRecovery: Boolean = false,
    ) {
        val baselineProvisionable: Boolean = provisionable
        val size = 4096
        val temp: File = TestFixtures.tempDir("device-delegate").toFile()
        val controlRoot = File(temp, "control-root").apply { mkdirs() }
        val workRoot = File(temp, "work-root").apply { mkdirs() }
        val liveRoot = File(temp, "live").apply { mkdirs() }
        val storeRoot = File(temp, "store").apply { mkdirs() }
        val roots = MovePathRoots(liveRoot, storeRoot)
        var bootId = "boot-1"
        val bootIds = BootIdSource { bootId }
        val clock = Clock { 1_000L }
        var device = SwitchDeviceFacts("_a", "fw-1", "5.10.198-android13-8-g1234", "Enforcing")
        val partitions = linkedMapOf(
            "boot" to FakePartition("boot", "P".repeat(size).toByteArray()),
            "init_boot" to FakePartition("init_boot", "S".repeat(size).toByteArray()),
        )
        val bootBaseline = "B".repeat(size).toByteArray()
        val initBootBaseline = "I".repeat(size).toByteArray()
        val gateway = FakeInstallerGateway(partitions, FakeSwitchFacts(bootIds) { device }).apply {
            baselineBytes = mapOf("boot" to bootBaseline, "init_boot" to initBootBaseline)
        }
        val authority = FileSwitchAuthority(File(controlRoot, "control"), clock)
        val baselines = FakeBaselineStore(
            BaselineVerification(
                BaselineState.PRESENT_OK, "bl-1",
                BaselineCheck("bl-1", BaselineProvenance.OEM_PACKAGE,
                    Hashes.sha256(bootBaseline), Hashes.sha256(initBootBaseline), true),
                emptyList(), null,
            ),
        )
        var installPending = false
        var modeCurrent: WorkMode? = WorkMode.LITE
        var modeState: String? = "MODE_A_ACTIVE"
        val recoveryCalls = mutableListOf<Pair<String, Boolean>>()
        val recoveredBytes = "R".repeat(size).toByteArray()
        var recover: (String, File, File) -> CandidateResult = { _, _, output ->
            output.mkdirs()
            val image = File(output, "recovered.img").apply { writeBytes(recoveredBytes) }
            CandidateResult(image, Hashes.sha256(image), image.length(), structureEvidence = "fixture:owned-writes-removed")
        }

        fun newDelegate() = ModeSwitchDeviceDelegate(
            controlRoot = controlRoot,
            workRoot = workRoot,
            authority = authority,
            journalFactory = SwitchJournalFactory { RecordingSwitchJournal() },
            baselines = baselines,
            gateway = gateway,
            modeFacts = DeviceModeFactsPort { DeviceModeFacts(modeCurrent, modeState) },
            pendingGuard = DevicePendingGuard { if (installPending) throw IOException("INSTALLER_TRANSACTION_BUSY") },
            lock = object : DeviceLockPort {
                override fun <T> withLock(action: () -> T): T = action()
            },
            deviceFacts = { device },
            moveStage = stage,
            bootIds = bootIds,
            clock = clock,
            baselineProvisionable = baselineProvisionable,
            sourceRecovery = if (withRecovery) { _, partition, input, output, known ->
                recoveryCalls += partition to known
                recover(partition, input, output)
            } else null,
        )
        val delegate = newDelegate()

        val switchId: String = UUID.randomUUID().toString()
        val planFields = mapOf("fromMode" to "LITE", "toMode" to "KSU", "baselineId" to "bl-1")
        /** CTA 语义：页面还不知道 id（`BASELINE_LATEST = ""`）。 */
        val planFieldsWithoutBaseline = mapOf("fromMode" to "LITE", "toMode" to "KSU", "baselineId" to "")

        fun writeBaselineImages() {
            File(controlRoot, "boot/baseline/bl-1").mkdirs()
            File(controlRoot, "boot/baseline/bl-1/boot.img").writeBytes(bootBaseline)
            File(controlRoot, "boot/baseline/bl-1/init_boot.img").writeBytes(initBootBaseline)
        }

        fun mirrorFiles(): Pair<File, File> {
            val dir = File(temp, "mirrors").apply { mkdirs() }
            return File(dir, "superuser.json").apply { writeText("{}") } to
                File(dir, "settings.json").apply { writeText("{}") }
        }

        fun preflightOk() {
            writeBaselineImages()
            val result = delegate.preflight(switchId, planFields)
            assertTrue("preflight failed: ${result.code}/${result.detail}", result.ok)
        }

        fun beginAndSnapshot(): File {
            preflightOk()
            val (superuser, settings) = mirrorFiles()
            val begin = delegate.begin(switchId, planFields, superuser, settings)
            assertTrue("begin failed: ${begin.code}/${begin.detail}", begin.ok)
            val snapshot = delegate.snapshot(switchId)
            assertTrue("snapshot failed: ${snapshot.code}/${snapshot.detail}", snapshot.ok)
            return File(workRoot, switchId)
        }

        fun submitCandidate(partition: String = "init_boot", client: ModeSwitchDeviceDelegate = delegate): String {
            val directory = File(workRoot, switchId)
            val baseline = (if (partition == "boot") bootBaseline else initBootBaseline).copyOf()
            baseline[baseline.size - 1] = (baseline[baseline.size - 1].toInt() xor 0x5a).toByte()
            val candidate = File(directory, "upload-$partition.img")
            candidate.writeBytes(baseline)
            val sha = Hashes.sha256(baseline)
            val result = client.submitCandidate(switchId, partition, candidate, sha)
            assertTrue("submit failed: ${result.code}/${result.detail}", result.ok)
            return sha
        }

        fun withoutBaseline() {
            baselines.verification = BaselineVerification(
                BaselineState.MISSING_NEVER_CAPTURED, null, null, emptyList(), BaselineErrors.BASELINE_MISSING,
            )
            gateway.baselineBytes = emptyMap()
        }

        fun beginWithoutBaseline(fields: Map<String, String> = planFieldsWithoutBaseline) {
            assertTrue(delegate.preflight(switchId, fields).ok)
            val (superuser, settings) = mirrorFiles()
            val begun = delegate.begin(switchId, fields, superuser, settings)
            assertTrue("begin failed: ${begun.code}/${begun.detail}", begun.ok)
        }
    }

    // ------------------------------------------------------------------ 全链路委托

    @Test
    fun candidateCopyDigestFailurePreservesTheOldFileAndSnapshotAuthority() {
        val h = Harness()
        val directory = h.beginAndSnapshot()
        val stored = File(directory, "candidate-init_boot.img").apply { writeText("O".repeat(h.size)) }
        val original = stored.readBytes()
        val snapshot = h.authority.read(h.switchId)!!
        val source = File(directory, "changing-upload.img").apply { writeText("C".repeat(h.size)) }
        val expected = Hashes.sha256(source)
        // Change bytes after the first digest, at the existing copy/alias decision.
        val changing = object : File(source.path) {
            override fun getCanonicalFile(): File {
                source.writeText("X".repeat(h.size))
                return super.getCanonicalFile()
            }
        }
        val result = h.delegate.submitCandidate(h.switchId, "init_boot", changing, expected)
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.PRODUCE_FAILED, result.code)
        assertTrue(original.contentEquals(stored.readBytes()))
        assertEquals(snapshot, h.authority.read(h.switchId))
        assertEquals(0, h.gateway.preparedPlans)
        assertEquals(0, h.gateway.commits)
        assertTrue(directory.listFiles().orEmpty().none { it.name.startsWith(".candidate-init_boot.img.tmp-") })
    }

    @Test
    fun candidateCopiesPublishExactBytesAndKeepTheSameFilePathValid() {
        for (sameFile in listOf(false, true)) {
            val h = Harness()
            val directory = h.beginAndSnapshot()
            val stored = File(directory, "candidate-init_boot.img").apply { writeText("O".repeat(h.size)) }
            val source = if (sameFile) stored else File(directory, "new-upload.img")
            source.writeText("C".repeat(h.size))
            val bytes = source.readBytes()
            val result = h.delegate.submitCandidate(h.switchId, "init_boot", source, Hashes.sha256(source))
            assertTrue("sameFile=$sameFile ${result.code}/${result.detail}", result.ok)
            assertTrue(bytes.contentEquals(stored.readBytes()))
            assertTrue(bytes.contentEquals(source.readBytes()))
            val record = h.authority.read(h.switchId)!!
            assertEquals(SwitchStateNames.COMMIT, record.state)
            assertEquals(stored.absolutePath, record.artifacts["candidate-init_boot"])
            assertEquals(Hashes.sha256(bytes), record.partitions.single { it.name == "init_boot" }.targetSha256)
        }
    }

    @Test
    fun successfulPreparePublishesTheExactPlanWithCommitAuthority() {
        val h = Harness()
        h.beginAndSnapshot()
        val snapshot = h.authority.read(h.switchId)!!
        h.authority.write(snapshot.copy(artifacts = snapshot.artifacts +
            (SwitchRecord.PREPARED_PLAN_PREFIX + "stale-key" to "old-plan")))
        h.submitCandidate()
        val record = FileSwitchAuthority(File(h.controlRoot, "control"), h.clock).read(h.switchId)!!
        val persisted = record.artifacts.filterKeys { it.startsWith(SwitchRecord.PREPARED_PLAN_PREFIX) }
            .mapKeys { (key, _) -> key.removePrefix(SwitchRecord.PREPARED_PLAN_PREFIX) }
        assertEquals(SwitchStateNames.COMMIT, record.state)
        assertEquals(h.gateway.planOk()!!.flatFields(), persisted)
        assertEquals(h.gateway.planOk()!!.planSha256, record.planSha256)
        assertFalse(persisted.containsKey("stale-key"))
        assertEquals(1, h.gateway.preparedPlans)
        assertEquals(0, h.gateway.commits)
    }

    @Test
    fun failedPrepareDoesNotPublishCommitOrACompletedPlan() {
        val h = Harness()
        val directory = h.beginAndSnapshot()
        h.gateway.failPrepare = "FIXTURE_PREPARE_FAILED"
        val candidate = File(directory, "failed-prepare.img").apply { writeText("C".repeat(h.size)) }
        val result = h.delegate.submitCandidate(h.switchId, "init_boot", candidate, Hashes.sha256(candidate))
        assertFalse(result.ok)
        assertEquals("FIXTURE_PREPARE_FAILED", result.code)
        val record = h.authority.read(h.switchId)!!
        assertEquals(SwitchStateNames.PRODUCE, record.state)
        assertEquals("", record.planSha256)
        assertTrue(record.artifacts.keys.none { it.startsWith(SwitchRecord.PREPARED_PLAN_PREFIX) })
        assertEquals(0, h.gateway.preparedPlans)
        assertEquals(0, h.gateway.commits)
    }

    @Test
    fun sharedRecoveryBuildsSourceAndRollsBackWithoutAStockBaseline() {
        val h = Harness(withRecovery = true)
        h.withoutBaseline()
        h.beginWithoutBaseline()
        val snapshot = h.delegate.snapshot(h.switchId)
        assertTrue("snapshot failed: ${snapshot.code}/${snapshot.detail}", snapshot.ok)
        assertEquals(listOf("boot" to true), h.recoveryCalls)
        assertEquals(h.recoveredBytes.toList(), h.delegate.imageFile(h.switchId, "BASE", "boot").readBytes().toList())
        assertEquals("S".repeat(h.size), h.delegate.imageFile(h.switchId, "BASE", "init_boot").readText())
        val record = h.authority.read(h.switchId)!!
        assertEquals("", record.baselineId)
        assertEquals("SOURCE_RECOVERY", record.artifacts["baseMode"])
        assertEquals(Hashes.sha256(h.recoveredBytes), record.artifacts["baseSha256-boot"])
        assertEquals("fixture:owned-writes-removed", record.artifacts["baseSource-boot"])
        assertEquals("PRE", record.artifacts["baseSource-init_boot"])
        assertEquals(BaselineState.MISSING_NEVER_CAPTURED, h.baselines.verification.state)
        h.submitCandidate()
        assertTrue(h.delegate.commit(h.switchId).ok)
        assertEquals(h.recoveredBytes.toList(), h.partitions.getValue("boot").bytes.toList())
        assertTrue(h.delegate.rollback(h.switchId).ok)
        assertEquals("P".repeat(h.size), String(h.partitions.getValue("boot").bytes))
        assertEquals("S".repeat(h.size), String(h.partitions.getValue("init_boot").bytes))
    }

    @Test
    fun unchangedTargetStillCommitsRecoveredSourceWithoutAnExternalBaseline() {
        val h = Harness(withRecovery = true)
        h.withoutBaseline()
        h.beginWithoutBaseline()
        assertTrue(h.delegate.snapshot(h.switchId).ok)
        val candidate = File(h.workRoot, "${h.switchId}/unchanged-target.img").apply {
            writeBytes(h.partitions.getValue("init_boot").bytes)
        }
        val submitted = h.delegate.submitCandidate(h.switchId, "init_boot", candidate, Hashes.sha256(candidate))
        assertTrue("submit failed: ${submitted.code}/${submitted.detail}", submitted.ok)
        assertTrue(h.delegate.commit(h.switchId).ok)
        assertEquals(listOf("boot"), h.gateway.lastCommitWritten)
        assertEquals(h.recoveredBytes.toList(), h.partitions.getValue("boot").bytes.toList())
        assertTrue(h.partitions.getValue("init_boot").writeLog.isEmpty())
        assertTrue(h.delegate.rollback(h.switchId).ok)
        assertEquals("P".repeat(h.size), String(h.partitions.getValue("boot").bytes))
        assertTrue(h.partitions.getValue("init_boot").writeLog.isEmpty())
    }

    @Test
    fun sharedRecoveryPersistsAcrossDelegateRecreationAndUsesOnlyExplicitBoot() {
        val h = Harness(withRecovery = true)
        h.withoutBaseline()
        h.beginWithoutBaseline(h.planFieldsWithoutBaseline + mapOf("targetPartition" to "boot", "sourcePartition" to "boot"))
        assertTrue(h.delegate.snapshot(h.switchId).ok)
        val recreated = h.newDelegate()
        h.submitCandidate("boot", recreated)
        assertTrue(recreated.commit(h.switchId).ok)
        assertEquals(listOf("boot"), h.gateway.lastCommitWritten)
        assertTrue(h.partitions.getValue("init_boot").writeLog.isEmpty())
        assertEquals(listOf("boot" to true), h.recoveryCalls)
    }

    @Test
    fun normalInitBootRecoveryKeepsUltraTargetBaseEqualToPre() {
        val h = Harness(withRecovery = true)
        h.modeCurrent = WorkMode.KSU
        h.withoutBaseline()
        h.beginWithoutBaseline(mapOf("fromMode" to "KSU", "toMode" to "LITE", "baselineId" to "",
            "targetPartition" to "boot", "sourcePartition" to "init_boot"))
        assertTrue(h.delegate.snapshot(h.switchId).ok)
        assertEquals(listOf("init_boot" to true), h.recoveryCalls)
        assertEquals("P".repeat(h.size), h.delegate.imageFile(h.switchId, "BASE", "boot").readText())
        h.submitCandidate("boot")
        assertTrue(h.delegate.commit(h.switchId).ok)
        assertEquals(listOf("init_boot", "boot"), h.gateway.lastCommitWritten)
        assertEquals(h.recoveredBytes.toList(), h.partitions.getValue("init_boot").bytes.toList())
    }

    @Test
    fun sourceRecoveryFailureBadDigestMutationAndShortOutputNeverPrepareAWrite() {
        for (failure in 0..3) {
            val h = Harness(withRecovery = true)
            h.withoutBaseline()
            h.recover = { _, input, output ->
                if (failure == 0) CandidateResult(null, "", 0, "SOURCE_RECOVERY_UNAVAILABLE", "fixture")
                else {
                    output.mkdirs()
                    val image = File(output, "recovered.img").apply {
                        writeBytes(if (failure == 3) byteArrayOf(1) else h.recoveredBytes)
                    }
                    if (failure == 2) input.writeBytes("X".repeat(h.size).toByteArray())
                    CandidateResult(image, if (failure == 1) "0".repeat(64) else Hashes.sha256(image), image.length(),
                        structureEvidence = "fixture:owned-writes-removed")
                }
            }
            h.beginWithoutBaseline()
            val result = h.delegate.snapshot(h.switchId)
            assertFalse("failure=$failure", result.ok)
            assertEquals(listOf("SOURCE_RECOVERY_UNAVAILABLE", "SOURCE_RECOVERY_OUTPUT_CHANGED",
                ModeSwitchCodes.PRE_IMAGE_CHANGED, ModeSwitchCodes.PRODUCE_OUTPUT_SIZE_INVALID)[failure], result.code)
            assertEquals(SwitchStateNames.BEGIN, h.authority.read(h.switchId)!!.state)
            assertEquals(0, h.gateway.preparedPlans)
            assertEquals(0, h.gateway.commits)
            assertEquals("P".repeat(h.size), String(h.partitions.getValue("boot").bytes))
            assertEquals("S".repeat(h.size), String(h.partitions.getValue("init_boot").bytes))
        }
    }

    @Test
    fun persistedRecoveryDigestProtectsBaseExportAndSourceRestorePlan() {
        val h = Harness(withRecovery = true)
        h.withoutBaseline()
        h.beginWithoutBaseline()
        assertTrue(h.delegate.snapshot(h.switchId).ok)
        File(h.workRoot, "${h.switchId}/base-boot.img").writeBytes("X".repeat(h.size).toByteArray())
        try {
            h.delegate.imageFile(h.switchId, "BASE", "boot")
            fail("Changed BASE must not be exported")
        } catch (error: DeviceSwitchError) {
            assertEquals("SOURCE_RECOVERY_OUTPUT_CHANGED", error.code)
        }
        val candidate = File(h.workRoot, "${h.switchId}/upload-init_boot.img").apply {
            writeBytes("C".repeat(h.size).toByteArray())
        }
        val submitted = h.delegate.submitCandidate(h.switchId, "init_boot", candidate, Hashes.sha256(candidate))
        assertFalse(submitted.ok)
        assertEquals(BaselineErrors.BASELINE_CORRUPT, submitted.code)
        assertEquals(0, h.gateway.preparedPlans)
        assertEquals(0, h.gateway.commits)
    }

    @Test
    fun missingPersistedRecoveryDigestDoesNotBecomeAnArbitraryFreshHash() {
        val h = Harness(withRecovery = true)
        h.withoutBaseline()
        h.beginWithoutBaseline()
        assertTrue(h.delegate.snapshot(h.switchId).ok)
        val record = h.authority.read(h.switchId)!!
        h.authority.write(record.copy(artifacts = record.artifacts - "baseSha256-boot"))
        val candidate = File(h.workRoot, "${h.switchId}/upload-init_boot.img").apply {
            writeBytes("C".repeat(h.size).toByteArray())
        }
        val submitted = h.delegate.submitCandidate(h.switchId, "init_boot", candidate, Hashes.sha256(candidate))
        assertFalse(submitted.ok)
        assertEquals(BaselineErrors.BASELINE_CORRUPT, submitted.code)
        assertEquals(0, h.gateway.preparedPlans)
    }

    @Test
    fun explicitBaselineKeepsItsOriginalContractWithSharedRecoveryInstalled() {
        val missing = Harness(withRecovery = true)
        missing.withoutBaseline()
        val rejected = missing.delegate.preflight(missing.switchId, missing.planFields)
        assertFalse(rejected.ok)
        assertEquals(BaselineErrors.BASELINE_MISSING, rejected.code)
        assertTrue(missing.recoveryCalls.isEmpty())

        val existing = Harness(withRecovery = true)
        existing.beginAndSnapshot()
        assertTrue(existing.recoveryCalls.isEmpty())
        assertEquals("B".repeat(existing.size), existing.delegate.imageFile(existing.switchId, "BASE", "boot").readText())
        existing.submitCandidate()
        assertTrue(existing.delegate.commit(existing.switchId).ok)
    }

    @Test
    fun snapshotRecaptureDropsRemovedPartitionArtifactsAndPreservesOtherStages() {
        val h = Harness(withRecovery = true)
        h.modeCurrent = WorkMode.KSU
        h.withoutBaseline()
        h.beginWithoutBaseline(mapOf("fromMode" to "KSU", "toMode" to "LITE", "baselineId" to "",
            "targetPartition" to "boot", "sourcePartition" to ""))
        assertTrue(h.delegate.snapshot(h.switchId).ok)
        val before = h.authority.read(h.switchId)!!
        val removedImage = File(before.artifacts.getValue("pre-init_boot"))
        val retained = mapOf("candidate-init_boot" to removedImage.absolutePath,
            "diagnostic" to "kept", "base-stock" to "kept", "baseSource-module" to "kept")
        h.authority.write(before.copy(artifacts = before.artifacts + retained))
        h.partitions.remove("init_boot")
        h.partitions.getValue("boot").bytes = "Q".repeat(h.size).toByteArray()

        val result = h.delegate.snapshot(h.switchId)
        assertTrue("${result.code}/${result.detail}", result.ok)
        val current = h.authority.read(h.switchId)!!
        assertEquals(listOf("boot"), current.partitions.map { it.name })
        for (prefix in listOf("pre-", "base-", "baseSha256-", "baseSource-")) {
            assertFalse(prefix, current.artifacts.containsKey(prefix + "init_boot"))
        }
        for ((key, value) in retained) assertEquals(key, value, current.artifacts[key])
        for (key in listOf("superuserMirror", "settingsMirror", "journal")) {
            assertEquals(key, before.artifacts[key], current.artifacts[key])
        }
        assertEquals("SOURCE_RECOVERY", current.artifacts["baseMode"])
        assertEquals(Hashes.sha256("Q".repeat(h.size).toByteArray()), current.partitions.single().preSha256)
        assertEquals("Q".repeat(h.size), h.delegate.imageFile(h.switchId, "PRE", "boot").readText())
        assertEquals(h.recoveredBytes.toList(), h.delegate.imageFile(h.switchId, "BASE", "boot").readBytes().toList())
        assertTrue(removedImage.isFile)
        for (kind in listOf("PRE", "BASE", "CANDIDATE")) {
            try {
                h.delegate.imageFile(h.switchId, kind, "init_boot")
                fail("Removed partition must not export $kind")
            } catch (error: DeviceSwitchError) {
                assertEquals(ModeSwitchCodes.PRE_IMAGE_INVALID, error.code)
            }
        }
        assertEquals(0, h.gateway.preparedPlans)
        assertEquals(0, h.gateway.commits)
    }

    @Test
    fun imageExportsIgnoreArtifactPathsOutsideCurrentPartitionRows() {
        val h = Harness()
        h.writeBaselineImages()
        val fields = h.planFields + mapOf("targetPartition" to "boot", "sourcePartition" to "boot")
        assertTrue(h.delegate.preflight(h.switchId, fields).ok)
        val (superuser, settings) = h.mirrorFiles()
        assertTrue(h.delegate.begin(h.switchId, fields, superuser, settings).ok)
        assertTrue(h.delegate.snapshot(h.switchId).ok)
        val image = File(h.workRoot, "${h.switchId}/unlisted-init_boot.img").apply {
            writeBytes(h.initBootBaseline)
        }
        val record = h.authority.read(h.switchId)!!
        h.authority.write(record.copy(artifacts = record.artifacts + mapOf(
            "pre-init_boot" to image.absolutePath, "base-init_boot" to image.absolutePath,
            "candidate-init_boot" to image.absolutePath)))
        for (kind in listOf("PRE", "BASE", "CANDIDATE")) {
            try {
                h.delegate.imageFile(h.switchId, kind, "init_boot")
                fail("Unlisted partition must not export $kind")
            } catch (error: DeviceSwitchError) {
                assertEquals(ModeSwitchCodes.PRE_IMAGE_INVALID, error.code)
            }
        }
        assertEquals("P".repeat(h.size), h.delegate.imageFile(h.switchId, "PRE", "boot").readText())
        assertEquals(h.bootBaseline.toList(), h.delegate.imageFile(h.switchId, "BASE", "boot").readBytes().toList())
        assertTrue(image.isFile)
        assertEquals(0, h.gateway.preparedPlans)
    }

    @Test
    fun explicitBaselineRecaptureReplacesOnlySnapshotRecoveryMetadata() {
        val h = Harness()
        h.beginAndSnapshot()
        val before = h.authority.read(h.switchId)!!
        val stale = mapOf("baseMode" to "SOURCE_RECOVERY", "baseSha256-boot" to "0".repeat(64),
            "baseSha256-init_boot" to "0".repeat(64), "baseSource-boot" to "old",
            "baseSource-init_boot" to "old")
        h.authority.write(before.copy(artifacts = before.artifacts + stale + ("diagnostic" to "kept")))
        assertTrue(h.delegate.snapshot(h.switchId).ok)
        val current = h.authority.read(h.switchId)!!
        for (key in stale.keys) assertFalse(key, key in current.artifacts)
        assertEquals("kept", current.artifacts["diagnostic"])
        for (key in listOf("superuserMirror", "settingsMirror", "journal")) {
            assertEquals(key, before.artifacts[key], current.artifacts[key])
        }
        assertEquals(h.bootBaseline.toList(), h.delegate.imageFile(h.switchId, "BASE", "boot").readBytes().toList())
        h.submitCandidate()
        assertEquals(1, h.gateway.preparedPlans)
        assertEquals(0, h.gateway.commits)
    }

    @Test
    fun explicitNormalBootRemainsTheCandidateCarrierAfterSnapshot() {
        val h = Harness()
        val fields = h.planFields + mapOf("targetPartition" to "boot", "sourcePartition" to "boot")
        h.writeBaselineImages()
        assertTrue(h.delegate.preflight(h.switchId, fields).ok)
        val (superuser, settings) = h.mirrorFiles()
        assertTrue(h.delegate.begin(h.switchId, fields, superuser, settings).ok)
        assertTrue(h.delegate.snapshot(h.switchId).ok)
        val candidate = File(h.workRoot, "${h.switchId}/upload-boot.img").apply {
            writeBytes(h.bootBaseline.copyOf().also { it[it.lastIndex] = 1 })
        }
        val submitted = h.delegate.submitCandidate(h.switchId, "boot", candidate, Hashes.sha256(candidate))
        assertTrue("${submitted.code}/${submitted.detail}", submitted.ok)
        assertTrue(h.delegate.commit(h.switchId).ok)
        assertEquals(listOf("boot"), h.gateway.lastCommitWritten)
        assertTrue(h.partitions.getValue("init_boot").writeLog.isEmpty())
    }

    @Test
    fun android12NormalBootDoesNotRequireAnInitBootCarrier() {
        val h = Harness()
        h.device = h.device.copy(kernelRelease = "5.10.198-android12-8-g1234")
        h.partitions.remove("init_boot")
        h.writeBaselineImages()
        val result = h.delegate.preflight(h.switchId,
            h.planFields + mapOf("targetPartition" to "boot", "sourcePartition" to "boot"))
        assertTrue("${result.code}/${result.detail}", result.ok)
    }

    @Test
    fun bootCarrierSurvivesServiceRecreationAndRejectsAnotherCandidate() {
        val h = Harness()
        val fields = h.planFields + mapOf("targetPartition" to "boot", "sourcePartition" to "boot")
        h.writeBaselineImages()
        assertTrue(h.delegate.preflight(h.switchId, fields).ok)
        val (superuser, settings) = h.mirrorFiles()
        assertTrue(h.delegate.begin(h.switchId, fields, superuser, settings).ok)
        val recreated = h.newDelegate()
        assertTrue(recreated.snapshot(h.switchId).ok)
        assertEquals("boot", h.authority.read(h.switchId)!!.targetPartition)
        assertEquals("boot", h.authority.read(h.switchId)!!.sourcePartition)
        assertEquals(listOf("boot"), recreated.status(h.switchId)!!.partitions.map { it.name })
        val candidate = File(h.workRoot, "${h.switchId}/upload.img").apply {
            writeBytes(h.bootBaseline.copyOf().also { it[it.lastIndex] = 1 })
        }
        assertEquals(ModeSwitchCodes.PLAN_INVALID,
            recreated.submitCandidate(h.switchId, "init_boot", candidate, Hashes.sha256(candidate)).code)
        assertTrue(recreated.submitCandidate(h.switchId, "boot", candidate, Hashes.sha256(candidate)).ok)
        assertTrue(recreated.commit(h.switchId).ok)
        assertEquals(listOf("boot"), h.gateway.lastCommitWritten)
    }

    @Test
    fun beginUsesTheCurrentExplicitTargetInsteadOfAnEarlierPreflight() {
        val h = Harness()
        h.writeBaselineImages()
        assertTrue(h.delegate.preflight(h.switchId, h.planFields).ok)
        val (superuser, settings) = h.mirrorFiles()
        val result = h.delegate.begin(h.switchId, h.planFields + ("targetPartition" to "boot"), superuser, settings)
        assertTrue("${result.code}/${result.detail}", result.ok)
        assertEquals("boot", h.authority.read(h.switchId)!!.targetPartition)
    }

    @Test
    fun invalidPartitionsReturnAResultBeforeCreatingTheRecord() {
        val h = Harness()
        for (field in listOf("targetPartition", "sourcePartition")) {
            val fields = h.planFields + (field to "vbmeta")
            assertEquals(ModeSwitchCodes.PLAN_INVALID, h.delegate.preflight(h.switchId, fields).code)
            val (superuser, settings) = h.mirrorFiles()
            assertEquals(ModeSwitchCodes.PLAN_INVALID,
                h.delegate.begin(h.switchId, fields, superuser, settings).code)
        }
        assertNull(h.authority.read(h.switchId))
    }

    @Test
    fun unknownNormalSourcePersistsAndRestoresOnlyChangedInitBoot() {
        val h = Harness()
        h.modeCurrent = WorkMode.KSU
        val fields = mapOf("fromMode" to "KSU", "toMode" to "LITE", "baselineId" to "bl-1",
            "targetPartition" to "boot")
        h.writeBaselineImages()
        assertTrue(h.delegate.preflight(h.switchId, fields).ok)
        val (superuser, settings) = h.mirrorFiles()
        assertTrue(h.delegate.begin(h.switchId, fields, superuser, settings).ok)
        assertEquals("", h.authority.read(h.switchId)!!.sourcePartition)
        val recreated = h.newDelegate()
        assertTrue(recreated.snapshot(h.switchId).ok)
        val candidate = File(h.workRoot, "${h.switchId}/upload.img").apply {
            writeBytes(h.bootBaseline.copyOf().also { it[it.lastIndex] = 1 })
        }
        assertTrue(recreated.submitCandidate(h.switchId, "boot", candidate, Hashes.sha256(candidate)).ok)
        assertTrue(recreated.commit(h.switchId).ok)
        assertEquals(listOf("init_boot", "boot"), h.gateway.lastCommitWritten)
    }

    @Test
    fun fullSequenceS1ToS6DelegatesAndPersists() {
        val h = Harness()
        h.preflightOk()
        val (superuser, settings) = h.mirrorFiles()
        val begin = h.delegate.begin(h.switchId, h.planFields, superuser, settings)
        assertTrue(begin.ok)
        assertEquals(SwitchStateNames.BEGIN, begin.status!!.state)
        assertEquals("S1", begin.status!!.stage)

        val snapshot = h.delegate.snapshot(h.switchId)
        assertTrue(snapshot.ok)
        assertEquals(SwitchStateNames.SNAPSHOT, snapshot.status!!.state)
        assertEquals(2, snapshot.status!!.partitions.size)
        assertTrue(File(h.workRoot, "${h.switchId}/pre-boot.img").isFile)
        assertTrue(File(h.workRoot, "${h.switchId}/base-init_boot.img").isFile)

        val pre = h.delegate.imageFile(h.switchId, "PRE", "init_boot")
        assertEquals("S".repeat(h.size), String(pre.readBytes()))

        val sha = h.submitCandidate()
        val submitted = h.delegate.status(h.switchId)!!
        assertEquals(SwitchStateNames.COMMIT, submitted.state)
        assertTrue(submitted.planSha256.matches(Regex("[0-9a-f]{64}")))
        assertEquals(sha, submitted.partitions.first { it.name == "init_boot" }.targetSha256)

        val commit = h.delegate.commit(h.switchId)
        assertTrue("commit failed: ${commit.code}/${commit.detail}", commit.ok)
        assertEquals(SwitchStateNames.REBOOT_REQUIRED, h.delegate.status(h.switchId)!!.state)
        assertTrue(h.delegate.status(h.switchId)!!.rebootRequired)
        assertEquals("B".repeat(h.size), String(h.partitions.getValue("boot").bytes))

        assertTrue(h.delegate.markRebootRequested(h.switchId))
        h.bootId = "boot-2"
        val verified = h.delegate.verify(h.switchId)
        assertTrue("verify failed: ${verified.code}/${verified.detail}", verified.ok)
        assertEquals(SwitchStateNames.VERIFIED, h.delegate.status(h.switchId)!!.state)
        assertFalse(h.delegate.status(h.switchId)!!.rebootRequired)
    }

    @Test
    fun rollbackRestoresPreImagesThroughGateway() {
        val h = Harness()
        h.beginAndSnapshot()
        h.submitCandidate()
        assertTrue(h.delegate.commit(h.switchId).ok)
        val rollback = h.delegate.rollback(h.switchId)
        assertTrue("rollback failed: ${rollback.code}/${rollback.detail}", rollback.ok)
        assertEquals(SwitchStateNames.ROLLED_BACK, h.delegate.status(h.switchId)!!.state)
        assertEquals("P".repeat(h.size), String(h.partitions.getValue("boot").bytes))
        assertEquals("S".repeat(h.size), String(h.partitions.getValue("init_boot").bytes))
    }

    @Test
    fun commitFailureIsDelegatedAsRecoveryRequiredAndNeverThrows() {
        val h = Harness()
        h.beginAndSnapshot()
        h.submitCandidate()
        h.partitions.getValue("init_boot").failAlwaysAfter = 0
        val result = h.delegate.commit(h.switchId)
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.ROLLBACK_FAILED, result.code)
        assertEquals(SwitchStateNames.RECOVERY_REQUIRED, h.delegate.status(h.switchId)!!.state)
    }

    @Test
    fun abortOnlyAllowedBeforeWriteWindow() {
        val h = Harness()
        h.preflightOk()
        val (superuser, settings) = h.mirrorFiles()
        assertTrue(h.delegate.begin(h.switchId, h.planFields, superuser, settings).ok)
        val abort = h.delegate.abort(h.switchId)
        assertTrue(abort.ok)
        assertEquals(SwitchStateNames.CANCELLED, h.delegate.status(h.switchId)!!.state)
        // 写窗口之后禁止 abort。
        val h2 = Harness()
        h2.beginAndSnapshot()
        h2.submitCandidate()
        val lateAbort = h2.delegate.abort(h2.switchId)
        assertFalse(lateAbort.ok)
        assertEquals(ModeSwitchCodes.PLAN_INVALID, lateAbort.code)
    }

    // ------------------------------------------------------------------ fail-closed

    @Test
    fun newServiceBeginsWithoutPreflightOrDiagnosticModeState() {
        val h = Harness()
        h.modeState = null
        val (superuser, settings) = h.mirrorFiles()
        val result = h.newDelegate().begin(h.switchId, h.planFields, superuser, settings)
        assertTrue("${result.code}/${result.detail}", result.ok)
        assertEquals("init_boot", h.authority.read(h.switchId)!!.targetPartition)
        assertEquals(SwitchStateNames.BEGIN, result.status!!.state)
        assertTrue(h.partitions.values.all { it.writeLog.isEmpty() })
    }

    @Test
    fun directBeginResolvesBootOnlyAndExplicitTargetsFromCurrentInventory() {
        for (explicit in listOf(false, true)) {
            val h = Harness()
            h.modeState = null
            if (!explicit) {
                h.device = h.device.copy(kernelRelease = "5.10.198-android12-8-g1234")
                h.partitions.remove("init_boot")
            }
            val fields = if (explicit) h.planFields + ("targetPartition" to "boot") else h.planFields
            val (superuser, settings) = h.mirrorFiles()
            val result = h.newDelegate().begin(h.switchId, fields, superuser, settings)
            assertTrue("explicit=$explicit ${result.code}/${result.detail}", result.ok)
            assertEquals("boot", h.authority.read(h.switchId)!!.targetPartition)
            assertEquals("boot", h.authority.read(h.switchId)!!.sourcePartition)
            assertTrue(h.partitions.values.all { it.writeLog.isEmpty() })
        }
    }

    @Test
    fun directBeginRejectsRealSourceLayoutSlotAndWriterErrorsWithoutPublishing() {
        for (failure in 0..5) {
            val h = Harness()
            when (failure) {
                0 -> h.modeCurrent = null
                1 -> h.modeCurrent = WorkMode.KSU
                2 -> h.device = h.device.copy(slot = "_z")
                3 -> h.partitions.remove("init_boot")
                4 -> h.gateway.failObserve = true
                5 -> h.installPending = true
            }
            val (superuser, settings) = h.mirrorFiles()
            val result = h.newDelegate().begin(h.switchId,
                h.planFields + ("targetPartition" to "init_boot"), superuser, settings)
            assertFalse("failure=$failure", result.ok)
            assertEquals(listOf(ModeSwitchCodes.STATE_UNDETERMINED, ModeSwitchCodes.SAME_MODE,
                ModeSwitchCodes.SLOT_INVALID, ModeSwitchCodes.LAYOUT_UNSUPPORTED,
                ModeSwitchCodes.LAYOUT_UNSUPPORTED, "INSTALLER_TRANSACTION_BUSY")[failure], result.code)
            assertNull(h.authority.read(h.switchId))
            assertFalse(File(h.workRoot, h.switchId).exists())
            assertTrue(h.partitions.values.all { it.writeLog.isEmpty() })
        }
    }

    @Test
    fun directBeginKeepsAKnownNormalSourceAndDoesNotInventAMissingCarrier() {
        for (sourcePresent in listOf(false, true)) {
            val h = Harness(withRecovery = true)
            h.modeCurrent = WorkMode.KSU
            h.modeState = null
            h.withoutBaseline()
            if (!sourcePresent) h.partitions.remove("init_boot")
            val fields = mapOf("fromMode" to "KSU", "toMode" to "LITE", "baselineId" to "",
                "targetPartition" to "boot", "sourcePartition" to "init_boot")
            val (superuser, settings) = h.mirrorFiles()
            val result = h.newDelegate().begin(h.switchId, fields, superuser, settings)
            assertEquals(sourcePresent, result.ok)
            if (sourcePresent) {
                val record = h.authority.read(h.switchId)!!
                assertEquals("boot", record.targetPartition)
                assertEquals("init_boot", record.sourcePartition)
                assertEquals("", record.baselineId)
            } else {
                assertEquals(ModeSwitchCodes.LAYOUT_UNSUPPORTED, result.code)
                assertNull(h.authority.read(h.switchId))
                assertFalse(File(h.workRoot, h.switchId).exists())
            }
            assertTrue(h.partitions.values.all { it.writeLog.isEmpty() })
        }
    }

    @Test
    fun missingMirrorsAreAnExecutionInputErrorWithoutPreflight() {
        val h = Harness()
        val result = h.newDelegate().begin(h.switchId, h.planFields,
            File(h.temp, "missing-superuser"), File(h.temp, "missing-settings"))
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.PREPARE_EXPORT_FAILED, result.code)
        assertNull(h.authority.read(h.switchId))
        assertFalse(File(h.workRoot, h.switchId).exists())
    }

    @Test
    fun preflightRejectsSameModeAndALiveWriterButAcceptsHistoricalTransactions() {
        val same = Harness().apply { modeCurrent = WorkMode.KSU }
        val sameResult = same.delegate.preflight(same.switchId, same.planFields)
        assertFalse(sameResult.ok)
        assertEquals(ModeSwitchCodes.SAME_MODE, sameResult.code)

        val pending = Harness()
        pending.authority.write(
            SwitchRecord(
                switchId = UUID.randomUUID().toString(),
                state = SwitchStateNames.COMMIT,
                fromMode = "LITE",
                toMode = "KSU",
                baselineId = "bl-1",
                startBootId = "boot-1",
            ),
        )
        assertTrue(pending.delegate.preflight(pending.switchId, pending.planFields).ok)

        val installPending = Harness()
        installPending.installPending = true
        assertEquals(
            "INSTALLER_TRANSACTION_BUSY",
            installPending.delegate.preflight(installPending.switchId, installPending.planFields).code,
        )
    }

    @Test
    fun preflightRejectsUnknownPlanFieldsAndMissingBaseline() {
        val h = Harness()
        val badFields = mapOf("fromMode" to "LITE", "toMode" to "KSU")
        assertEquals(ModeSwitchCodes.PLAN_INVALID, h.delegate.preflight(h.switchId, badFields).code)
        // 旧语义（`baselineProvisionable = false` = 未接线）必须逐字保留：缺基线仍在 preflight 阻断。
        val legacy = Harness(provisionable = false)
        legacy.writeBaselineImages()
        legacy.baselines.verification = BaselineVerification(
            BaselineState.MISSING_NEVER_CAPTURED, null, null, emptyList(), BaselineErrors.BASELINE_MISSING,
        )
        assertEquals(
            BaselineErrors.BASELINE_MISSING,
            legacy.delegate.preflight(legacy.switchId, legacy.planFields).code,
        )
    }

    // ------------------------------------------------------------------ P0-1 第 3 项：CTA 放宽

    @Test
    fun missingBaselineIsWarningNotBlockerWhenProvisionable() {
        // ① CTA 陷阱：KSU→LITE 走 SERVICE，缺基线时若在 preflight 阻断 ⇒ 按钮灰 ⇒
        // startSwitch 里的自动获取永远跑不到。可修复降级只把码放进 warning，不是放行写入。
        // CTA 语义 = 页面还不知道 id（baselineId = ""）。
        val h = Harness()
        h.baselines.verification = BaselineVerification(
            BaselineState.MISSING_NEVER_CAPTURED, null, null, emptyList(), BaselineErrors.BASELINE_MISSING,
        )
        val preflight = h.delegate.preflight(h.switchId, h.planFieldsWithoutBaseline)
        assertTrue("缺基线时 CTA 必须仍可点: ${preflight.code}", preflight.ok)
        assertEquals(BaselineErrors.BASELINE_MISSING, preflight.warning)
        assertEquals("", preflight.code)
    }

    @Test
    fun strictPreflightWithRealBaselineIdIsNeverRelaxed() {
        // 严格模式：`startSwitch` 自动获取基线后会带**真实 id** 重新 preflight；
        // 那一次 id 非空就说明"基线应该存在"——不存在必须显式阻断（不得降级掩盖）。
        val h = Harness()
        h.baselines.verification = BaselineVerification(
            BaselineState.MISSING_NEVER_CAPTURED, null, null, emptyList(), BaselineErrors.BASELINE_MISSING,
        )
        val strict = h.delegate.preflight(h.switchId, h.planFields)
        assertFalse(strict.ok)
        assertEquals(BaselineErrors.BASELINE_MISSING, strict.code)
        // 同一次调用若把 id 换成空（CTA 语义）才会降级。
        assertTrue(h.delegate.preflight(h.switchId, h.planFieldsWithoutBaseline).ok)
    }

    @Test
    fun missingExplicitBaselineFailsWhenSnapshotActuallyNeedsItsImages() {
        val h = Harness()
        h.baselines.verification = BaselineVerification(
            BaselineState.MISSING_NEVER_CAPTURED, null, null, emptyList(), BaselineErrors.BASELINE_MISSING,
        )
        val (superuser, settings) = h.mirrorFiles()
        val begin = h.newDelegate().begin(h.switchId, h.planFields, superuser, settings)
        assertTrue("${begin.code}/${begin.detail}", begin.ok)
        val snapshot = h.newDelegate().snapshot(h.switchId)
        assertFalse(snapshot.ok)
        assertEquals(BaselineErrors.BASELINE_MISSING, snapshot.code)
        assertEquals(SwitchStateNames.BEGIN, h.authority.read(h.switchId)!!.state)
        assertTrue(h.partitions.values.all { it.writeLog.isEmpty() })
        assertEquals(0, h.gateway.preparedPlans)
    }

    @Test
    fun permissiveSelinuxIsRecordedAndNeverBlocksPreflightOrBegin() {
        // 2026-11-01 用户指令：只有「越狱模式」可拒绝刷写 ⇒ SELinux 只记录事实。
        // 断言具体返回值：ok=true、code=""、warning=""（不冒充基线降级）、advisory 带真实读数。
        val h = Harness()
        h.device = h.device.copy(selinux = "Permissive")
        h.writeBaselineImages()
        val result = h.delegate.preflight(h.switchId, h.planFields)
        assertTrue(
            "SELinux 非 Enforcing 不得阻断 preflight: ${result.code}/${result.detail}",
            result.ok,
        )
        assertEquals("", result.code)
        assertEquals("", result.detail)
        assertEquals("不得冒充基线 warning", "", result.warning)
        assertEquals("${ModeSwitchCodes.SELINUX_NOT_ENFORCING}:selinux=Permissive", result.advisory)

        // 任何后续写入门槛都不因它出现：begin 照常成功，并把真实 SELinux 值写进记录（证据）。
        val (superuser, settings) = h.mirrorFiles()
        val begin = h.delegate.begin(h.switchId, h.planFields, superuser, settings)
        assertTrue("begin 不得因 SELinux 被拒: ${begin.code}/${begin.detail}", begin.ok)
        assertEquals("Permissive", begin.status!!.device["selinux"])

        // Enforcing 时 advisory 为空（同一路径不报噪音）。
        val enforcing = Harness()
        enforcing.writeBaselineImages()
        val clean = enforcing.delegate.preflight(enforcing.switchId, enforcing.planFields)
        assertTrue(clean.ok)
        assertEquals("", clean.advisory)
    }

    @Test
    fun provisionableDoesNotRelaxNonBaselinePreflightCodes() {
        // Invalid device facts remain errors; historical switch records do not exclude a new writer.
        val slot = Harness()
        slot.device = slot.device.copy(slot = "_z")
        val slotResult = slot.delegate.preflight(slot.switchId, slot.planFields)
        assertFalse(slotResult.ok)
        assertEquals(ModeSwitchCodes.SLOT_INVALID, slotResult.code)

        val pending = Harness()
        pending.authority.write(
            SwitchRecord(
                switchId = UUID.randomUUID().toString(),
                state = SwitchStateNames.COMMIT,
                fromMode = "LITE",
                toMode = "KSU",
                baselineId = "bl-1",
                startBootId = "boot-1",
            ),
        )
        assertTrue(pending.delegate.preflight(pending.switchId, pending.planFields).ok)
    }

    @Test
    fun baselineRepairWhitelistIsBaselineOnly() {
        for (code in listOf(
            BaselineErrors.BASELINE_MISSING,
            BaselineErrors.BASELINE_STALE,
            BaselineErrors.BASELINE_CORRUPT,
            BaselineErrors.BASELINE_UNCLEAN,
            BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
            BaselineErrors.BASELINE_PROMOTION_FORBIDDEN,
            BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED,
        )) {
            assertTrue("$code 应可降级", BaselinePreflightRepair.isRepairable(code))
        }
        for (code in listOf(
            "", ModeSwitchCodes.ROOT_UNAVAILABLE, ModeSwitchCodes.SELINUX_NOT_ENFORCING,
            ModeSwitchCodes.PRE_IMAGE_INVALID, ModeSwitchCodes.PENDING, ModeSwitchCodes.SPACE_INSUFFICIENT,
            ModeSwitchCodes.SLOT_INVALID, ModeSwitchCodes.KMI_UNSUPPORTED, ModeSwitchCodes.LAYOUT_UNSUPPORTED,
            ModeSwitchCodes.DEVICE_CHANGED, "SWITCH_BASELINE_REQUIRED", "WRITE_FAILED",
        )) {
            assertFalse("$code 不得降级", BaselinePreflightRepair.isRepairable(code))
        }
    }

    @Test
    fun stageOrderingIsEnforced() {
        val h = Harness()
        h.preflightOk()
        val (superuser, settings) = h.mirrorFiles()
        // 未 begin 就 snapshot/submit/commit 全部 fail-closed。
        assertEquals(ModeSwitchCodes.PLAN_INVALID, h.delegate.snapshot(h.switchId).code)
        assertEquals(ModeSwitchCodes.PLAN_INVALID,
            h.delegate.submitCandidate(h.switchId, "init_boot", File(h.temp, "x"), "a".repeat(64)).code)
        assertEquals(ModeSwitchCodes.PLAN_INVALID, h.delegate.commit(h.switchId).code)
        assertEquals(ModeSwitchCodes.PLAN_INVALID, h.delegate.verify(h.switchId).code)
        assertTrue(h.delegate.begin(h.switchId, h.planFields, superuser, settings).ok)
        // BEGIN 阶段不能直接 submit/commit。
        assertEquals(ModeSwitchCodes.PLAN_INVALID, h.delegate.commit(h.switchId).code)
    }

    @Test
    fun candidateLengthShaAndNoOpAreRejected() {
        val h = Harness()
        h.partitions.getValue("boot").bytes = h.bootBaseline.copyOf()
        h.beginAndSnapshot()
        val directory = File(h.workRoot, h.switchId)
        val shortFile = File(directory, "short.img").apply { writeBytes(ByteArray(10)) }
        assertEquals(
            ModeSwitchCodes.PRODUCE_OUTPUT_SIZE_INVALID,
            h.delegate.submitCandidate(h.switchId, "init_boot", shortFile, "a".repeat(64)).code,
        )
        val candidate = File(directory, "candidate.img").apply { writeBytes("C".repeat(h.size).toByteArray()) }
        assertEquals(
            ModeSwitchCodes.PRODUCE_CANDIDATE_CHANGED,
            h.delegate.submitCandidate(h.switchId, "init_boot", candidate, "b".repeat(64)).code,
        )
        // Neither the source nor the target requires a partition write.
        val preSha = Hashes.sha256("S".repeat(h.size).toByteArray())
        assertEquals(
            "SWITCH_STEP_NO_OP",
            h.delegate.submitCandidate(h.switchId, "init_boot",
                File(directory, "candidate.img").apply { writeBytes("S".repeat(h.size).toByteArray()) }, preSha).code,
        )
        assertEquals(SwitchStateNames.SNAPSHOT, h.authority.read(h.switchId)!!.state)
        assertEquals(0, h.gateway.preparedPlans)
        assertEquals(0, h.gateway.commits)
        assertTrue(h.partitions.values.all { it.writeLog.isEmpty() })
    }

    @Test
    fun imageFileRejectsForbiddenPartitionAndMissingArtifacts() {
        val h = Harness()
        h.beginAndSnapshot()
        try {
            h.delegate.imageFile(h.switchId, "PRE", "vbmeta")
            fail("expected forbidden")
        } catch (error: DeviceSwitchError) {
            assertEquals("SWITCH_PARTITION_FORBIDDEN", error.code)
        }
        try {
            h.delegate.imageFile(h.switchId, "CANDIDATE", "init_boot")
            fail("expected missing candidate")
        } catch (error: DeviceSwitchError) {
            assertEquals(ModeSwitchCodes.PRE_IMAGE_INVALID, error.code)
        }
    }

    @Test
    fun corruptSwitchJsonFailsClosedWithRecoveryCode() {
        val h = Harness()
        File(h.controlRoot, "control").mkdirs()
        File(h.controlRoot, "control/switch.json").writeText("{not-json")
        File(h.controlRoot, "control/switch.json.sha256").writeText("f".repeat(64))
        val statusResult = runCatching { h.delegate.status(h.switchId) }
        assertTrue(statusResult.isFailure)
        assertEquals(
            ModeSwitchCodes.RECOVERY_JOURNAL_CORRUPT,
            (statusResult.exceptionOrNull() as DeviceSwitchError).code,
        )
        assertEquals(ModeSwitchCodes.RECOVERY_JOURNAL_CORRUPT, h.delegate.commit(h.switchId).code)
    }

    @Test
    fun verifyBeforeRebootIsRejected() {
        val h = Harness()
        h.beginAndSnapshot()
        h.submitCandidate()
        assertTrue(h.delegate.commit(h.switchId).ok)
        // bootId 未变：不得把"没重启"报告成 VERIFIED。
        assertEquals(ModeSwitchCodes.VERIFY_BOOT_NOT_OBSERVED, h.delegate.verify(h.switchId).code)
        assertEquals(SwitchStateNames.REBOOT_REQUIRED, h.delegate.status(h.switchId)!!.state)
    }

    @Test
    fun rebootMarkerDoesNotRebootAndRequiresRebootState() {
        val h = Harness()
        assertFalse(h.delegate.markRebootRequested(h.switchId))
        h.beginAndSnapshot()
        h.submitCandidate()
        assertTrue(h.delegate.commit(h.switchId).ok)
        assertTrue(h.delegate.markRebootRequested(h.switchId))
        val status = h.delegate.status(h.switchId)!!
        assertEquals(SwitchStateNames.REBOOT_REQUIRED, status.state)
        assertTrue(status.rebootRequired)
    }

    @Test
    fun recoveryLogContainsPlanImagesAndNoAutoRetryStatement() {
        val h = Harness()
        h.beginAndSnapshot()
        val destination = File(h.temp, "recovery.txt")
        val log = h.delegate.recoveryLog(h.switchId, destination)
        assertTrue(log.isFile)
        val text = log.readText()
        assertTrue(text.contains("switchId=${h.switchId}"))
        assertTrue(text.contains("image pre-boot="))
        assertTrue(text.contains("不自动重启"))
    }

    @Test
    fun unknownSwitchIdStatusIsNullAndDoesNotLeakOtherRecord() {
        val h = Harness()
        h.beginAndSnapshot()
        assertNull(h.delegate.status(UUID.randomUUID().toString()))
        assertNotNull(h.delegate.status(h.switchId))
        assertEquals(ModeSwitchCodes.PLAN_CONFLICT, h.delegate.commit(UUID.randomUUID().toString()).code)
    }

    /** 02 §3.3：switch.json 丢失时 getModeSwitch 必须能从 journal head 重建只读状态。 */
    @Test
    fun statusFallsBackToJournalHeadWhenSwitchJsonMissing() {
        val h = Harness()
        val directory = File(h.workRoot, h.switchId).apply { mkdirs() }
        dev.maplesu.manager.workmode.switch.FileSwitchJournal(
            File(directory, "journal.jsonl"), h.clock, h.bootIds,
        ).append(
            h.switchId, "a".repeat(64), "S4", "4d",
            dev.maplesu.manager.workmode.switch.SwitchOp.COMMIT_INTENT,
        )
        val status = h.delegate.status(h.switchId)
        assertNotNull(status)
        assertEquals(SwitchStateNames.COMMIT, status!!.state)
        assertEquals("S4", status.stage)
    }

    // ------------------------------------------------------------------ W08b 服务端配置交换

    private fun FileSwitchMoveStage.seed(liveRoot: File): Unit {
        val modules = File(liveRoot, "data/adb/sevenk").apply { mkdirs() }
        File(modules, "demo").apply { mkdirs() }
        File(modules, "demo/module.prop").writeText("id=demo")
    }

    private fun storePrivateConfig(roots: MovePathRoots, owner: WorkMode = WorkMode.LITE): File =
        roots.store(MoveSet.storePathFor(owner, "/data/adb/sevenk"))

    @Test
    fun commitRunsServiceSideMoveOutAndInAndWritesManifest() {
        val h = Harness()
        val stage = FileSwitchMoveStage(h.roots)
        val delegate = h.delegateWith(stage)
        h.writeBaselineImages()
        assertTrue(delegate.preflight(h.switchId, h.planFields).ok)
        val (su, settings) = h.mirrorFiles()
        assertTrue(delegate.begin(h.switchId, h.planFields, su, settings).ok)
        assertTrue(delegate.snapshot(h.switchId).ok)
        val baseline = h.initBootBaseline.copyOf()
        baseline[baseline.size - 1] = (baseline[baseline.size - 1].toInt() xor 0x5a).toByte()
        val candidate = File(h.workRoot, "${h.switchId}/upload.img").apply { writeBytes(baseline) }
        assertTrue(delegate.submitCandidate(h.switchId, "init_boot", candidate, Hashes.sha256(baseline)).ok)
        File(h.liveRoot, "data/adb/sevenk").apply { mkdirs() }
        File(h.liveRoot, "data/adb/sevenk/demo").apply { mkdirs() }
        File(h.liveRoot, "data/adb/sevenk/demo/module.prop").writeText("id=demo")
        val shared = File(h.liveRoot, "data/adb/modules/shared/module.prop")
        shared.parentFile!!.mkdirs()
        shared.writeText("id=shared")
        val commit = delegate.commit(h.switchId)
        assertTrue("commit failed: ${commit.code}/${commit.detail}", commit.ok)
        assertEquals("id=shared", shared.readText())
        assertEquals(SwitchStateNames.REBOOT_REQUIRED, delegate.status(h.switchId)!!.state)
        // 服务端（root）已完成出仓：A 配置留在 modes/A 离线仓；B live 为空（B 无配置）。
        assertTrue(storePrivateConfig(h.roots).isDirectory)
        assertFalse(File(h.liveRoot, "data/adb/sevenk").exists())
        val record = h.authority.read(h.switchId)!!
        assertEquals("DONE", record.materialize.state)
        assertTrue(record.moves.isNotEmpty())
        val manifest = File(h.storeRoot, "boot/work/${h.switchId}/move-manifest.json")
        assertTrue("manifest evidence missing", manifest.isFile)
    }

    @Test
    fun commitFailsClosedWhenMoveOutFailsAndDoesNotWritePartitions() {
        val h = Harness()
        val stage = FileSwitchMoveStage(h.roots)
        val delegate = h.delegateWith(stage)
        h.writeBaselineImages()
        assertTrue(delegate.preflight(h.switchId, h.planFields).ok)
        val (su, settings) = h.mirrorFiles()
        assertTrue(delegate.begin(h.switchId, h.planFields, su, settings).ok)
        assertTrue(delegate.snapshot(h.switchId).ok)
        val baseline = h.initBootBaseline.copyOf()
        baseline[baseline.size - 1] = (baseline[baseline.size - 1].toInt() xor 0x5a).toByte()
        val candidate = File(h.workRoot, "${h.switchId}/upload.img").apply { writeBytes(baseline) }
        assertTrue(delegate.submitCandidate(h.switchId, "init_boot", candidate, Hashes.sha256(baseline)).ok)
        // 目标 store 冲突 → moveOut fail-fast；分区必须未动。
        File(h.liveRoot, "data/adb/sevenk").mkdirs()
        storePrivateConfig(h.roots).mkdirs()
        val commit = delegate.commit(h.switchId)
        assertFalse(commit.ok)
        assertEquals("MOVE_OUT_FAILED", commit.code)
        assertEquals(0, h.gateway.commits)
        assertEquals("P".repeat(h.size), String(h.gateway.partitions.getValue("boot").bytes))
    }

    @Test
    fun moveInFailureRollsBackPartitionsAndConfig() {
        val h = Harness()
        val failing = object : SwitchMoveStage by FileSwitchMoveStage(h.roots) {
            override fun moveIn(plan: MoveStagePlan, journal: SwitchJournal) =
                MoveStageResult(false, "MOVE_IN_FAILED", "injected")
        }
        val delegate = h.delegateWith(failing)
        h.writeBaselineImages()
        assertTrue(delegate.preflight(h.switchId, h.planFields).ok)
        val (su, settings) = h.mirrorFiles()
        assertTrue(delegate.begin(h.switchId, h.planFields, su, settings).ok)
        assertTrue(delegate.snapshot(h.switchId).ok)
        val baseline = h.initBootBaseline.copyOf()
        baseline[baseline.size - 1] = (baseline[baseline.size - 1].toInt() xor 0x5a).toByte()
        val candidate = File(h.workRoot, "${h.switchId}/upload.img").apply { writeBytes(baseline) }
        assertTrue(delegate.submitCandidate(h.switchId, "init_boot", candidate, Hashes.sha256(baseline)).ok)
        File(h.liveRoot, "data/adb/sevenk/demo").mkdirs()
        File(h.liveRoot, "data/adb/sevenk/demo/module.prop").writeText("id=demo")
        val commit = delegate.commit(h.switchId)
        assertFalse("unexpected success: $commit", commit.ok)
        assertEquals(SwitchStateNames.ROLLED_BACK, commit.status!!.state)
        assertTrue("partitions rolled back", h.gateway.rollbacks >= 1)
        // 配置也逆序回滚：A live 恢复。
        assertTrue(File(h.liveRoot, "data/adb/sevenk/demo/module.prop").isFile)
    }

    @Test
    fun moveRollbackFailureUpgradesToRecoveryRequired() {
        val h = Harness()
        val failing = object : SwitchMoveStage by FileSwitchMoveStage(h.roots) {
            override fun rollback(plan: MoveStagePlan, journal: SwitchJournal) =
                MoveStageResult(false, "MOVE_ROLLBACK_FAILED", "injected")
        }
        val delegate = h.delegateWith(failing)
        h.writeBaselineImages()
        assertTrue(delegate.preflight(h.switchId, h.planFields).ok)
        val (su, settings) = h.mirrorFiles()
        assertTrue(delegate.begin(h.switchId, h.planFields, su, settings).ok)
        assertTrue(delegate.snapshot(h.switchId).ok)
        val baseline = h.initBootBaseline.copyOf()
        baseline[baseline.size - 1] = (baseline[baseline.size - 1].toInt() xor 0x5a).toByte()
        val candidate = File(h.workRoot, "${h.switchId}/upload.img").apply { writeBytes(baseline) }
        assertTrue(delegate.submitCandidate(h.switchId, "init_boot", candidate, Hashes.sha256(baseline)).ok)
        File(h.liveRoot, "data/adb/sevenk/demo").mkdirs()
        File(h.liveRoot, "data/adb/sevenk/demo/module.prop").writeText("id=demo")
        h.partitions.getValue("init_boot").failAlwaysAfter = 0
        val commit = delegate.commit(h.switchId)
        assertFalse(commit.ok)
        assertEquals(SwitchStateNames.RECOVERY_REQUIRED, commit.status!!.state)
        assertEquals("MOVE_ROLLBACK_FAILED", commit.code)
    }

    @Test
    fun rollbackRestoresServiceSideMovedConfig() {
        val h = Harness()
        val stage = FileSwitchMoveStage(h.roots)
        val delegate = h.delegateWith(stage)
        h.writeBaselineImages()
        assertTrue(delegate.preflight(h.switchId, h.planFields).ok)
        val (su, settings) = h.mirrorFiles()
        assertTrue(delegate.begin(h.switchId, h.planFields, su, settings).ok)
        assertTrue(delegate.snapshot(h.switchId).ok)
        val baseline = h.initBootBaseline.copyOf()
        baseline[baseline.size - 1] = (baseline[baseline.size - 1].toInt() xor 0x5a).toByte()
        val candidate = File(h.workRoot, "${h.switchId}/upload.img").apply { writeBytes(baseline) }
        assertTrue(delegate.submitCandidate(h.switchId, "init_boot", candidate, Hashes.sha256(baseline)).ok)
        File(h.liveRoot, "data/adb/sevenk/demo").mkdirs()
        File(h.liveRoot, "data/adb/sevenk/demo/module.prop").writeText("id=demo")
        assertTrue(delegate.commit(h.switchId).ok)
        val rollback = delegate.rollback(h.switchId)
        assertTrue("rollback failed: ${rollback.code}/${rollback.detail}", rollback.ok)
        assertEquals(SwitchStateNames.ROLLED_BACK, delegate.status(h.switchId)!!.state)
        assertEquals("P".repeat(h.size), String(h.gateway.partitions.getValue("boot").bytes))
        assertTrue(File(h.liveRoot, "data/adb/sevenk/demo/module.prop").isFile)
        assertFalse(storePrivateConfig(h.roots).exists())
    }

    private fun Harness.delegateWith(stage: SwitchMoveStage): ModeSwitchDeviceDelegate =
        ModeSwitchDeviceDelegate(
            controlRoot = controlRoot,
            workRoot = workRoot,
            authority = authority,
            journalFactory = SwitchJournalFactory { RecordingSwitchJournal() },
            baselines = baselines,
            gateway = gateway,
            modeFacts = DeviceModeFactsPort { DeviceModeFacts(modeCurrent, "MODE_A_ACTIVE") },
            pendingGuard = DevicePendingGuard {
                if (installPending) throw IOException("INSTALLER_TRANSACTION_BUSY")
            },
            lock = object : DeviceLockPort {
                override fun <T> withLock(action: () -> T): T = action()
            },
            deviceFacts = { device },
            moveStage = stage,
            bootIds = bootIds,
            clock = clock,
            baselineProvisionable = baselineProvisionable,
        )
}
