package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.installer.InstallMovePhase
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.switch.ModeSwitchRequest
import java.io.File
import java.io.RandomAccessFile
import java.util.Properties
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ModeSwitchProgressTest {
    @get:Rule val tmp = TemporaryFolder()
    private val request = ModeSwitchRequest("0f8fad5b-d9cb-469f-a165-70867728950f", WorkMode.LITE, WorkMode.KSU, "baseline-fixture")
    private val file get() = File(tmp.root, "${request.switchId}/progress.properties")

    @Test
    fun aMissingRecordHasNoSavedTransaction() {
        assertNull(ModeSwitchProgress(file).read())
    }

    @Test
    fun durableRecordRoundTripsRequestCompletedPhasesAndWaitingState() {
        val progress = ModeSwitchProgress(file)
        progress.write(request, setOf(InstallMovePhase.OUT, InstallMovePhase.IN), withdrawn = true, waiting = true)
        val restored = ModeSwitchProgress(file).read()!!
        assertEquals(request, restored.request)
        assertEquals(setOf(InstallMovePhase.OUT, InstallMovePhase.IN), restored.phases)
        assertTrue(restored.withdrawn)
        assertTrue(restored.waiting)
        assertTrue(restored.quiesced)
        assertFalse(File(file.parentFile, file.name + ".new").exists())
    }

    @Test
    fun partitionFieldsRoundTripWithoutCollapsingUnknownAndLegacySources() {
        val progress = ModeSwitchProgress(file)
        val requests = listOf(
            request.copy(targetPartition = "boot", sourcePartition = "boot"),
            request.copy(targetPartition = "init_boot", sourcePartition = ""),
            ModeSwitchRequest(request.switchId, WorkMode.KSU, WorkMode.LITE, "baseline",
                targetPartition = "boot", sourcePartition = "init_boot"),
            ModeSwitchRequest(request.switchId, WorkMode.KSU, WorkMode.LITE, "baseline",
                targetPartition = "boot", sourcePartition = "boot"),
            ModeSwitchRequest(request.switchId, WorkMode.KSU, WorkMode.LITE, "baseline",
                targetPartition = "boot", sourcePartition = null),
        )
        for (original in requests) {
            progress.write(original, emptySet(), withdrawn = false, waiting = false)
            assertEquals(original, ModeSwitchProgress(file).read()!!.request)
        }
    }

    @Test
    fun oldRecordsWithoutPartitionFieldsKeepLegacyNullValues() {
        val progress = ModeSwitchProgress(file)
        progress.write(request.copy(targetPartition = "boot", sourcePartition = ""),
            emptySet(), withdrawn = false, waiting = false)
        val properties = Properties().apply { file.inputStream().use(::load) }
        properties.remove("targetPartition")
        properties.remove("sourcePartition")
        file.outputStream().use { properties.store(it, null) }
        assertEquals(request, ModeSwitchProgress(file).read()!!.request)
        assertNull(ModeSwitchProgress(file).read()!!.request.targetPartition)
        assertNull(ModeSwitchProgress(file).read()!!.request.sourcePartition)
    }

    @Test
    fun successiveWritesPublishOnlyTheNewestCompleteState() {
        val progress = ModeSwitchProgress(file)
        progress.write(request, emptySet(), withdrawn = false, waiting = false)
        progress.write(request, setOf(InstallMovePhase.OUT), withdrawn = true, waiting = false)
        progress.write(request, setOf(InstallMovePhase.OUT, InstallMovePhase.IN), withdrawn = true, waiting = true)
        val restored = progress.read()!!
        assertEquals(setOf(InstallMovePhase.OUT, InstallMovePhase.IN), restored.phases)
        assertTrue(restored.withdrawn)
        assertTrue(restored.waiting)
    }

    @Test
    fun finishClearsTheRecordAndIsIdempotent() {
        val progress = ModeSwitchProgress(file)
        progress.write(request, emptySet(), withdrawn = false, waiting = false)
        progress.finish()
        progress.finish()
        assertNull(progress.read())
    }

    @Test
    fun readRejectsARecordCopiedFromAnotherTransactionDirectory() {
        ModeSwitchProgress(file).write(request, emptySet(), withdrawn = false, waiting = false)
        val copied = File(tmp.root, "other-fixture/progress.properties")
        copied.parentFile!!.mkdirs()
        file.copyTo(copied)
        assertTrue(runCatching { ModeSwitchProgress(copied).read() }.isFailure)
    }

    @Test
    fun malformedPhasesModesAndBooleansAreRejectedInsteadOfInventingState() {
        ModeSwitchProgress(file).write(request, emptySet(), withdrawn = false, waiting = false)
        val original = file.readBytes()
        for ((key, value) in listOf("phases" to "UNKNOWN", "from" to "UNKNOWN", "withdrawn" to "yes", "waiting" to "1", "quiesced" to "yes",
            "targetPartition" to "vendor_boot", "sourcePartition" to "vendor_boot")) {
            file.writeBytes(original)
            val properties = Properties().apply { file.inputStream().use(::load) }
            properties.setProperty(key, value)
            file.outputStream().use { properties.store(it, null) }
            assertTrue("$key=$value", runCatching { ModeSwitchProgress(file).read() }.isFailure)
        }
    }

    @Test
    fun rollbackBootReceiptSurvivesDataJournalCompletion() {
        val progress = ModeSwitchProgress(file)
        progress.write(request, emptySet(), withdrawn = false, waiting = false)
        progress.recordRollbackBoot("target-boot", "_a")
        assertEquals(ModeSwitchProgress.RollbackBoot("target-boot", "_a", false), progress.rollbackBoot())
        progress.completeRollback()
        progress.finish()
        assertNull(progress.read())
        assertEquals(ModeSwitchProgress.RollbackBoot("target-boot", "_a", true),
            ModeSwitchProgress(file).rollbackBoot())
    }

    @Test
    fun incompleteRollbackCanBeRetriedAfterAnotherBoot() {
        val progress = ModeSwitchProgress(file)
        progress.recordRollbackBoot("first-boot", "_a")
        progress.recordRollbackBoot("second-boot", "_b")
        assertEquals(ModeSwitchProgress.RollbackBoot("second-boot", "_b", false), progress.rollbackBoot())
    }

    @Test
    fun rollbackReceiptRejectsAnotherTaskAndMalformedValues() {
        val progress = ModeSwitchProgress(file)
        progress.recordRollbackBoot("target-boot", "_a")
        val receipt = File(file.parentFile, "rollback-boot.properties")
        val original = receipt.readBytes()
        for ((key, value) in listOf("switchId" to "other", "bootId" to "", "slot" to "_c", "ready" to "yes")) {
            receipt.writeBytes(original)
            val properties = Properties().apply { receipt.inputStream().use(::load) }
            properties.setProperty(key, value)
            receipt.outputStream().use { properties.store(it, null) }
            assertTrue("$key=$value", runCatching { progress.rollbackBoot() }.isFailure)
        }
        assertTrue(runCatching { progress.recordRollbackBoot("bad boot", "_a") }.isFailure)
        assertTrue(runCatching { progress.recordRollbackBoot("target-boot", "_c") }.isFailure)
    }
    private fun ultraReceipt(id: String = request.switchId, waiting: Boolean = true): ModeSwitchProgress {
        val receipt = File(tmp.root, "$id/switch-progress.properties")
        receipt.parentFile!!.mkdirs()
        val candidate = File(receipt.parentFile, "ultra-candidate.img").apply { writeBytes(ByteArray(4096) { 17 }) }
        return ModeSwitchProgress(receipt).also {
            it.write(ModeSwitchRequest(id, WorkMode.KSU, WorkMode.LITE, "baseline"), emptySet(),
                withdrawn = true, waiting = waiting, ultraBoot = ModeSwitchProgress.UltraBoot("source-boot",
                    "b".repeat(64), Hashes.sha256(candidate), candidate.name))
        }
    }

    @Test fun ultraRecoveryRequiresCompleteCommitNewBootSameKeyAndUntamperedCandidate() {
        ultraReceipt(waiting = false)
        assertNull(ModeSwitchProgress.postBootUltraRecovery(tmp.root, "new-boot", "b".repeat(64)))
        ultraReceipt()
        assertEquals(request.switchId, ModeSwitchProgress.postBootUltraRecovery(tmp.root, "new-boot", "b".repeat(64)))
        assertNull(ModeSwitchProgress.postBootUltraRecovery(tmp.root, "source-boot", "b".repeat(64)))
        assertNull(ModeSwitchProgress.postBootUltraRecovery(tmp.root, "new-boot", "c".repeat(64)))
        assertNull(ModeSwitchProgress.postBootUltraRecovery(tmp.root, "", "b".repeat(64)))
        File(tmp.root, "${request.switchId}/ultra-candidate.img").appendText("changed")
        assertNull(ModeSwitchProgress.postBootUltraRecovery(tmp.root, "new-boot", "b".repeat(64)))
    }

    @Test fun rollbackIntentAndInvalidationBothRevokeUltraSetupReceipt() {
        val progress = ultraReceipt()
        progress.recordRollbackBoot("new-boot", "_a")
        assertNull(ModeSwitchProgress.postBootUltraRecovery(tmp.root, "new-boot", "b".repeat(64)))
        File(tmp.root, "${request.switchId}/rollback-boot.properties").delete()
        assertEquals(request.switchId, ModeSwitchProgress.postBootUltraRecovery(tmp.root, "new-boot", "b".repeat(64)))
        progress.invalidateUltraBoot()
        assertNull(ModeSwitchProgress.postBootUltraRecovery(tmp.root, "new-boot", "b".repeat(64)))
        assertTrue(progress.read()!!.waiting)
    }

    @Test fun ambiguousMissingAndTraversingCandidatesDoNotAuthorizeSetup() {
        ultraReceipt()
        val secondId = "0f8fad5b-d9cb-469f-a165-708677289510"
        ultraReceipt(secondId)
        assertNull(ModeSwitchProgress.postBootUltraRecovery(tmp.root, "new-boot", "b".repeat(64)))
        File(tmp.root, "$secondId/switch-progress.properties").delete()
        val receipt = File(tmp.root, "${request.switchId}/switch-progress.properties")
        val properties = Properties().apply { receipt.inputStream().use(::load) }
        properties.setProperty("ultra.candidate", "../ultra-candidate.img")
        receipt.outputStream().use { properties.store(it, null) }
        assertNull(ModeSwitchProgress.postBootUltraRecovery(tmp.root, "new-boot", "b".repeat(64)))
        ultraReceipt()
        File(tmp.root, "${request.switchId}/ultra-candidate.img").delete()
        assertNull(ModeSwitchProgress.postBootUltraRecovery(tmp.root, "new-boot", "b".repeat(64)))
    }

    @Test fun oversizedReceiptDoesNotAuthorizeSetup() {
        ultraReceipt()
        val receipt = File(tmp.root, "${request.switchId}/switch-progress.properties")
        receipt.appendText("#" + " ".repeat(64 * 1024))
        assertTrue(receipt.length() > 64L * 1024)
        assertNull(ModeSwitchProgress.postBootUltraRecovery(tmp.root, "new-boot", "b".repeat(64)))
    }

    @Test fun oversizedCandidateDoesNotAuthorizeSetup() {
        ultraReceipt()
        val candidate = File(tmp.root, "${request.switchId}/ultra-candidate.img")
        RandomAccessFile(candidate, "rw").use { it.setLength(512L * 1024 * 1024 + 1) }
        assertNull(ModeSwitchProgress.postBootUltraRecovery(tmp.root, "new-boot", "b".repeat(64)))
    }

}
