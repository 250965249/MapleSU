package dev.maplesu.manager.installer

import dev.maplesu.installer.BlockDeviceTransaction
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.IOException

class NativeInstallSequenceTest {
    @get:Rule val temporary = TemporaryFolder()
    private val events = mutableListOf<String>()
    private val attempted = mutableListOf<List<String>>()
    private val states = mutableListOf<String>()
    private val boot = MemoryDevice("boot", 1)
    private val init = MemoryDevice("init_boot", 2)
    private val devices = linkedMapOf("boot" to boot, "init_boot" to init)
    private val journal = NativeInstallSequence.Journal { state, _, names ->
        states += state
        attempted += names.toList()
    }

    private inner class MemoryDevice(private val name: String, value: Int) : BlockDeviceTransaction.Device {
        val original = ByteArray(4096) { value.toByte() }
        val bytes = original.clone()
        var writes = 0
        var failWrites: Set<Int> = emptySet()
        var partialBeforeFailure = false
        var afterSync: (() -> Unit)? = null
        var revalidateFails = false
        override fun size() = bytes.size.toLong()
        override fun revalidate() { if (revalidateFails) throw IOException("INSTALLER_PARTITION_CHANGED") }
        override fun read(offset: Long, buffer: ByteArray, length: Int): Int {
            bytes.copyInto(buffer, 0, offset.toInt(), offset.toInt() + length)
            return length
        }
        override fun write(offset: Long, buffer: ByteArray, start: Int, length: Int): Int {
            writes++
            events += "$name:${buffer[start]}"
            if (writes in failWrites) {
                if (partialBeforeFailure && writes == failWrites.min()) bytes[offset.toInt()] = buffer[start]
                throw IOException("INSTALLER_DEVICE_WRITE_FAILED")
            }
            buffer.copyInto(bytes, offset.toInt(), start, start + length)
            return length
        }
        override fun sync() { afterSync?.invoke() }
        override fun close() = Unit
    }

    private fun image(name: String, value: Int, size: Int = 4096): NativeInstallSequence.Image {
        val file = temporary.newFile("$name-${System.nanoTime()}.img")
        file.writeBytes(ByteArray(size) { value.toByte() })
        return NativeInstallSequence.Image(name, file, BlockDeviceTransaction.paddedDigest(file.toPath(), file.length()))
    }

    private fun pre() = mapOf("boot" to image("boot", 1), "init_boot" to image("init_boot", 2))

    @Test fun vivoBatchCommitsAllImagesAndEveryPartialFailureRestoresFullPre() {
        val order = listOf("vendor_boot", "init_boot", "boot")
        for (failAt in -1..2) {
            events.clear()
            val all = order.mapIndexed { index, name -> name to MemoryDevice(name, index + 1) }.toMap()
            val before = order.mapIndexed { index, name -> name to image(name, index + 1) }.toMap()
            if (failAt >= 0) all.getValue(order[failAt]).apply { failWrites = setOf(1); partialBeforeFailure = true }
            val result = NativeInstallSequence.commit(all, before,
                order.mapIndexed { index, name -> image(name, index + 11) }, journal)
            assertEquals(if (failAt < 0) "REBOOT_REQUIRED" else "RESTORED", result.state)
            all.values.forEachIndexed { index, device ->
                assertArrayEquals(if (failAt < 0) ByteArray(4096) { (index + 11).toByte() } else device.original, device.bytes)
            }
            if (failAt < 0) assertEquals(order, events.map { it.substringBefore(':') })
            else assertTrue(order.drop(failAt + 1).all { all.getValue(it).writes == 0 })
        }
    }

    @Test fun signedBatchWritesMainVbmetaLastAndReadsBackEveryPartition() {
        val order = listOf("init_boot", "boot", "recovery", "vbmeta_system", "vbmeta")
        val all = order.mapIndexed { index, name -> name to MemoryDevice(name, index + 1) }.toMap()
        val before = order.mapIndexed { index, name -> name to image(name, index + 1) }.toMap()
        val writes = order.mapIndexed { index, name -> image(name, index + 11) }
        val outcome = NativeInstallSequence.commit(all, before, writes, journal)
        assertEquals("REBOOT_REQUIRED", outcome.state)
        assertEquals(order, events.map { it.substringBefore(':') })
        all.values.forEachIndexed { index, device -> assertArrayEquals(ByteArray(4096) { (index + 11).toByte() }, device.bytes) }
    }

    @Test fun failureAtEachSignedPartitionRestoresTheWholeAttemptedPrefixInReverse() {
        val order = listOf("init_boot", "boot", "recovery", "vbmeta_system", "vbmeta")
        order.forEachIndexed { failedAt, failedName ->
            events.clear()
            val all = order.mapIndexed { index, name -> name to MemoryDevice(name, index + 1) }.toMap()
            val before = order.mapIndexed { index, name -> name to image(name, index + 1) }.toMap()
            all.getValue(failedName).failWrites = setOf(1)
            val outcome = NativeInstallSequence.commit(all, before, order.mapIndexed { index, name -> image(name, index + 11) }, journal)
            assertEquals("RESTORED", outcome.state)
            all.values.forEach { assertArrayEquals(it.original, it.bytes) }
            val previous = order.take(failedAt).asReversed()
            assertEquals(previous, events.takeLast(previous.size).map { it.substringBefore(':') })
            assertTrue(order.drop(failedAt + 1).all { all.getValue(it).writes == 0 })
        }
    }

    @Test fun restoresNonTargetFirstAndWritesTargetLast() {
        val originals = pre()
        val outcome = NativeInstallSequence.commit(devices, originals,
            listOf(image("init_boot", 4), image("boot", 3)), journal)
        assertEquals("REBOOT_REQUIRED", outcome.state)
        assertEquals(listOf("init_boot:4", "boot:3"), events)
        assertEquals(listOf("init_boot", "boot"), attempted.last())
        assertArrayEquals(ByteArray(4096) { 3 }, boot.bytes)
        assertArrayEquals(ByteArray(4096) { 4 }, init.bytes)
    }

    @Test fun stockRestoreWritesBothOriginalsWithoutAProducedCandidate() {
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("boot", 5), image("init_boot", 6)), journal)
        assertEquals("REBOOT_REQUIRED", outcome.state)
        assertEquals(listOf("boot:5", "init_boot:6"), events)
        assertArrayEquals(ByteArray(4096) { 5 }, boot.bytes)
        assertArrayEquals(ByteArray(4096) { 6 }, init.bytes)
    }

    @Test fun stockRestoreSecondPartitionFailureCompensatesToPre() {
        init.failWrites = setOf(1)
        init.partialBeforeFailure = true
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("boot", 5), image("init_boot", 6)), journal)
        assertEquals("RESTORED", outcome.state)
        assertArrayEquals(boot.original, boot.bytes)
        assertArrayEquals(init.original, init.bytes)
        assertEquals(listOf("init_boot:2", "boot:1"), events.takeLast(2))
    }

    @Test fun shortCandidatePadsTheWholeTargetAndLeavesOtherPartitionUntouched() {
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("boot", 3, 128)), journal)
        assertEquals("REBOOT_REQUIRED", outcome.state)
        assertArrayEquals(ByteArray(4096) { if (it < 128) 3 else 0 }, boot.bytes)
        assertEquals(0, init.writes)
        assertArrayEquals(init.original, init.bytes)
    }

    @Test fun initBootOnlyStockRestoreLeavesBootUntouched() {
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("init_boot", 6)), journal)
        assertEquals("REBOOT_REQUIRED", outcome.state)
        assertArrayEquals(ByteArray(4096) { 6 }, init.bytes)
        assertEquals(0, boot.writes)
        assertArrayEquals(boot.original, boot.bytes)
    }

    @Test fun subsetWriteAndReadbackFailuresRestoreOnlyTheAttemptedCarrier() {
        for (readback in listOf(false, true)) {
            val target = MemoryDevice("init_boot", 2)
            val all = mapOf("boot" to boot, "init_boot" to target)
            if (readback) target.afterSync = { if (target.writes == 1) target.bytes[0] = 9 }
            else target.apply { failWrites = setOf(1); partialBeforeFailure = true }
            val outcome = NativeInstallSequence.commit(all, pre(), listOf(image("init_boot", 6)), journal)
            assertEquals("RESTORED", outcome.state)
            assertArrayEquals(target.original, target.bytes)
            assertEquals(0, boot.writes)
            assertArrayEquals(boot.original, boot.bytes)
        }
    }

    @Test fun anUntargetedReadbackChangeNeverReportsSuccessfulStockRestoration() {
        init.afterSync = { if (init.writes == 1) boot.bytes[0] = 9 }
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("init_boot", 6)), journal)
        assertEquals("RECOVERY_REQUIRED", outcome.state)
        assertEquals(0, boot.writes)
        assertArrayEquals(init.original, init.bytes)
    }

    @Test fun anEmptyRestoreSetFailsBeforeAnyDeviceWrite() {
        assertThrows(IllegalArgumentException::class.java) {
            NativeInstallSequence.commit(devices, pre(), emptyList(), journal)
        }
        assertTrue(events.isEmpty())
    }

    @Test fun failedSecondWriteRestoresEveryAttemptedPartitionInReverseOrder() {
        boot.failWrites = setOf(1)
        boot.partialBeforeFailure = true
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("init_boot", 4), image("boot", 3)), journal)
        assertEquals("RESTORED", outcome.state)
        assertArrayEquals(boot.original, boot.bytes)
        assertArrayEquals(init.original, init.bytes)
        // The per-device primitive first restores boot; the multi-device rollback repeats boot then init_boot.
        assertEquals(listOf("boot:1", "init_boot:2"), events.takeLast(2))
        assertFalse(states.contains("REBOOT_REQUIRED"))
    }

    @Test fun rollbackFailureRetainsRecoveryAndStillRestoresTheOtherPartition() {
        boot.failWrites = setOf(1, 2, 3)
        boot.partialBeforeFailure = true
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("init_boot", 4), image("boot", 3)), journal)
        assertEquals("RECOVERY_REQUIRED", outcome.state)
        assertArrayEquals(init.original, init.bytes)
        assertEquals("RECOVERY_REQUIRED", states.last())
    }

    @Test fun deniedFirstWriteWithUnchangedPartitionsDoesNotReportRescue() {
        boot.failWrites = setOf(1, 2, 3)
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("boot", 3)), journal)
        assertEquals("RESTORED", outcome.state)
        assertEquals("INSTALLER_DEVICE_WRITE_FAILED", outcome.error)
        assertEquals(1, boot.writes)
        assertEquals(0, init.writes)
        assertArrayEquals(boot.original, boot.bytes)
        assertArrayEquals(init.original, init.bytes)
    }

    @Test fun unchangedCompanionIsVerifiedWithoutAWrite() {
        val outcome = NativeInstallSequence.commit(devices, pre(),
            listOf(image("init_boot", 2), image("boot", 3)), journal)
        assertEquals("REBOOT_REQUIRED", outcome.state)
        assertEquals(listOf("boot:3"), events)
        assertEquals(listOf("boot"), attempted.last())
        assertEquals(0, init.writes)
        assertArrayEquals(init.original, init.bytes)
    }

    @Test fun identicalReinstallKeepsTheExistingCompletionContractWithoutWriting() {
        val originals = pre()
        val outcome = NativeInstallSequence.commit(devices, originals, originals.values.toList(), journal)
        assertEquals("REBOOT_REQUIRED", outcome.state)
        assertTrue(events.isEmpty())
        assertEquals(emptyList<String>(), attempted.last())
        assertFalse(states.contains("WRITING"))
    }

    @Test fun zeroPaddedCandidateIsComparedAtTheFullPartitionSize() {
        val device = MemoryDevice("boot", 0)
        val before = mapOf("boot" to image("boot", 0))
        val outcome = NativeInstallSequence.commit(mapOf("boot" to device), before,
            listOf(image("boot", 0, 128)), journal)
        assertEquals("REBOOT_REQUIRED", outcome.state)
        assertEquals(0, device.writes)
        assertArrayEquals(device.original, device.bytes)
    }

    @Test fun skippedCompanionIsExcludedFromRecoveryWrites() {
        boot.failWrites = setOf(1)
        boot.partialBeforeFailure = true
        val outcome = NativeInstallSequence.commit(devices, pre(),
            listOf(image("init_boot", 2), image("boot", 3)), journal)
        assertEquals("RESTORED", outcome.state)
        assertEquals(0, init.writes)
        assertEquals(listOf("boot"), attempted.last())
        assertArrayEquals(boot.original, boot.bytes)
        assertArrayEquals(init.original, init.bytes)
    }

    @Test fun skippedCompanionStillParticipatesInTheFinalReadback() {
        boot.afterSync = {
            boot.afterSync = null
            init.bytes[0] = 9
        }
        val outcome = NativeInstallSequence.commit(devices, pre(),
            listOf(image("init_boot", 2), image("boot", 3)), journal)
        assertEquals("RECOVERY_REQUIRED", outcome.state)
        assertEquals(0, init.writes)
        assertArrayEquals(boot.original, boot.bytes)
        assertFalse(states.contains("REBOOT_REQUIRED"))
    }

    @Test fun unchangedCandidateStillRequiresItsDeclaredDigest() {
        val originals = pre()
        val invalid = originals.getValue("init_boot").copy(sha256 = "0".repeat(64))
        val outcome = NativeInstallSequence.commit(devices, originals,
            listOf(invalid, image("boot", 3)), journal)
        assertEquals("FAILED_BEFORE_WRITE", outcome.state)
        assertTrue(events.isEmpty())
    }

    @Test fun alteredPreStopsBeforeAnyWrite() {
        val originals = pre()
        originals.getValue("boot").file.writeBytes(ByteArray(4096) { 9 })
        val outcome = NativeInstallSequence.commit(devices, originals, listOf(image("boot", 3)), journal)
        assertEquals("FAILED_BEFORE_WRITE", outcome.state)
        assertTrue(events.isEmpty())
    }

    @Test fun alteredCandidateStopsBeforeAnyWrite() {
        val candidate = image("boot", 3)
        candidate.file.appendText("changed")
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(candidate), journal)
        assertEquals("FAILED_BEFORE_WRITE", outcome.state)
        assertTrue(events.isEmpty())
    }

    @Test fun livePartitionChangedBeforeCommitStopsBeforeAnyWrite() {
        boot.bytes[0] = 9
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("boot", 3)), journal)
        assertEquals("FAILED_BEFORE_WRITE", outcome.state)
        assertTrue(events.isEmpty())
    }

    @Test fun finalCrossPartitionReadbackDetectsChangesAndRestoresBoth() {
        boot.afterSync = {
            boot.afterSync = null
            init.bytes[0] = 9
        }
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("init_boot", 4), image("boot", 3)), journal)
        assertEquals("RESTORED", outcome.state)
        assertArrayEquals(boot.original, boot.bytes)
        assertArrayEquals(init.original, init.bytes)
    }

    @Test fun readbackFailureOnTargetNeverReportsSuccess() {
        boot.afterSync = {
            boot.afterSync = null
            boot.bytes[0] = 9
        }
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("boot", 3)), journal)
        assertEquals("RESTORED", outcome.state)
        assertArrayEquals(boot.original, boot.bytes)
        assertFalse(states.contains("REBOOT_REQUIRED"))
    }

    @Test fun interruptedRecoveryStillRestoresThenPreservesInterruptFlag() {
        val originals = pre()
        boot.bytes.fill(3)
        init.bytes.fill(4)
        Thread.currentThread().interrupt()
        try {
            val outcome = NativeInstallSequence.restore(devices, originals, listOf("init_boot", "boot"), journal)
            assertEquals("RESTORED", outcome.state)
            assertTrue(Thread.currentThread().isInterrupted)
            assertArrayEquals(boot.original, boot.bytes)
            assertArrayEquals(init.original, init.bytes)
        } finally { Thread.interrupted() }
    }

    @Test fun manualRecoveryUsesFullPreForAnInterruptedApp() {
        val originals = pre()
        boot.bytes.fill(3)
        init.bytes.fill(4)
        val outcome = NativeInstallSequence.restore(devices, originals, listOf("init_boot", "boot"), journal)
        assertEquals("RESTORED", outcome.state)
        assertEquals(listOf("boot:1", "init_boot:2"), events)
        assertArrayEquals(boot.original, boot.bytes)
        assertArrayEquals(init.original, init.bytes)
    }

    @Test fun missingRecoveryFileCausesZeroRecoveryWrites() {
        val originals = pre()
        originals.getValue("boot").file.delete()
        val outcome = NativeInstallSequence.restore(devices, originals, devices.keys.toList(), journal)
        assertEquals("RECOVERY_REQUIRED", outcome.state)
        assertTrue(events.isEmpty())
    }

    @Test fun missingPreEntryCausesZeroRecoveryWrites() {
        val outcome = NativeInstallSequence.restore(devices, pre().filterKeys { it == "boot" }, devices.keys.toList(), journal)
        assertEquals("RECOVERY_REQUIRED", outcome.state)
        assertTrue(events.isEmpty())
    }

    @Test fun writeAheadJournalFailureStopsBeforeAnyWrite() {
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("boot", 3)),
            NativeInstallSequence.Journal { _, _, _ -> throw IOException("disk full") })
        assertEquals("FAILED_BEFORE_WRITE", outcome.state)
        assertTrue(events.isEmpty())
    }

    @Test fun brokenRecoveryJournalStillRestoresBytesAndKeepsRecoveryRequired() {
        boot.failWrites = setOf(1)
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("init_boot", 4), image("boot", 3)),
            NativeInstallSequence.Journal { state, _, _ -> if (state == "RESTORING") throw IOException("disk full") })
        assertEquals("RECOVERY_REQUIRED", outcome.state)
        assertArrayEquals(boot.original, boot.bytes)
        assertArrayEquals(init.original, init.bytes)
    }

    @Test fun failedFinalSuccessJournalRollsBackBothPartitions() {
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("init_boot", 4), image("boot", 3)),
            NativeInstallSequence.Journal { state, _, _ -> if (state == "REBOOT_REQUIRED") throw IOException("disk full") })
        assertEquals("RESTORED", outcome.state)
        assertArrayEquals(boot.original, boot.bytes)
        assertArrayEquals(init.original, init.bytes)
    }

    @Test fun userlandIsPreparedAfterReadbackAndBeforeRebootIsPublished() {
        var prepared = false
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("boot", 3)),
            NativeInstallSequence.Journal { state, _, _ ->
                if (state == "REBOOT_REQUIRED") assertTrue(prepared)
            }, beforeReboot = {
                assertArrayEquals(ByteArray(4096) { 3 }, boot.bytes)
                assertArrayEquals(init.original, init.bytes)
                prepared = true
            })
        assertEquals("REBOOT_REQUIRED", outcome.state)
        assertTrue(prepared)
    }

    @Test fun failedUserlandPreparationRestoresWrittenPartitions() {
        val outcome = NativeInstallSequence.commit(devices, pre(),
            listOf(image("init_boot", 4), image("boot", 3)), journal,
            beforeReboot = { throw IOException("INSTALLER_NORMAL_USERLAND_FAILED") })
        assertEquals("RESTORED", outcome.state)
        assertEquals("INSTALLER_NORMAL_USERLAND_FAILED", outcome.error)
        assertFalse(states.contains("REBOOT_REQUIRED"))
        assertArrayEquals(boot.original, boot.bytes)
        assertArrayEquals(init.original, init.bytes)
    }

    @Test fun unchangedImageStillRequiresVerifiedUserland() {
        var attempts = 0
        val outcome = NativeInstallSequence.commit(devices, pre(), listOf(image("boot", 1)), journal,
            beforeReboot = { attempts++; throw IOException("INSTALLER_NORMAL_USERLAND_FAILED") })
        assertEquals(1, attempts)
        assertEquals("FAILED_BEFORE_WRITE", outcome.state)
        assertEquals("INSTALLER_NORMAL_USERLAND_FAILED", outcome.error)
        assertTrue(events.isEmpty())
        assertFalse(states.contains("REBOOT_REQUIRED"))
    }

    @Test fun failedFinalRecoveryJournalNeverReportsRestored() {
        val outcome = NativeInstallSequence.restore(devices, pre(), devices.keys.toList(),
            NativeInstallSequence.Journal { state, _, _ -> if (state == "RESTORED") throw IOException("disk full") })
        assertEquals("RECOVERY_REQUIRED", outcome.state)
        assertArrayEquals(boot.original, boot.bytes)
        assertArrayEquals(init.original, init.bytes)
    }
}
