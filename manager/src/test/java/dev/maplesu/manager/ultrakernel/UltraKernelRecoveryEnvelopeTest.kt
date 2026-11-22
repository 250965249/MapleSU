package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.BootImageRebuilder
import dev.maplesu.image.BootImageRecovery
import dev.maplesu.image.KernelCompression
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Ordinary synthetic bytes only; no SDK, generated executable payload or partition. */
class UltraKernelRecoveryEnvelopeTest {
    @get:Rule val temporary = TemporaryFolder()

    private data class Fixture(val original: File, val snapshot: File, val inverse: ByteArray,
                               val raw: ByteArray, val patched: ByteArray, val component: ByteArray)

    private fun fixture(format: String, random: Boolean = false): Fixture {
        val raw = ByteArray(if (random) 1_100_003 else 65537)
        if (random) java.util.Random(712).nextBytes(raw)
        raw.fill(0, 1024, 1027)
        "ARMd".toByteArray().copyInto(raw, 56)
        "Linux version 6.6.89-envelope-fixture (opaque)".toByteArray().copyInto(raw, 128)
        val component = KernelCompression.encode(raw, format)
        val ramdiskOffset = ((4096L + component.size + 4095) / 4096 * 4096).toInt()
        val image = ByteArray(ramdiskOffset + 32768)
        ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("ANDROID!".toByteArray()); putInt(8, component.size); putInt(12, 37)
            putInt(20, 1584); putInt(40, 4)
        }
        component.copyInto(image, 4096)
        image.fill(41, 4096 + component.size, ramdiskOffset)
        image.fill(19, ramdiskOffset, ramdiskOffset + 37)
        image.fill(29, ramdiskOffset + 37, ramdiskOffset + 4096)
        val original = temporary.newFile().apply { writeBytes(image) }
        val snapshot = File(temporary.newFolder(), "snapshot.bin")
        BootImageRecovery.capture(original, BootImageRecovery.Component.KERNEL, snapshot,
            BootImageRebuilder.OutputPolicy.STRICT)
        val plan = UltraKernelPlan.fromSpec(UltraKernelSpec.parse("#kernel=6.6.89-envelope-fixture\n1024|000000|070809"))
        val inverse = UltraKernelRecoveryRecord.fromPlan(plan, raw.size, 0, 0).encode()
        val patched = raw.clone().apply { byteArrayOf(7, 8, 9).copyInto(this, 1024) }
        return Fixture(original, snapshot, inverse, raw, patched, component)
    }

    @Test fun allEncodedFormatsRecoverTheExactFirstContainerWithoutReceipts() {
        for (format in listOf("RAW_ARM64", "GZIP", "LZ4_LEGACY", "LZ4_FRAME", "XZ", "ZSTD")) {
            val f = fixture(format)
            val workspace = temporary.newFolder()
            val envelope = UltraKernelRecoveryEnvelope.write(f.inverse, f.snapshot,
                f.component.takeUnless { format == "RAW_ARM64" }, workspace)
            val kernel = File(workspace, "replacement").apply { writeBytes(KernelCompression.encode(f.patched, format)) }
            val candidate = File(workspace, "candidate.img")
            BootImageRebuilder.rebuildWithRecoveryFile(f.original, kernel, candidate, envelope,
                BootImageRebuilder.OutputPolicy.STRICT)
            val originalBytes = f.original.readBytes()
            val before = candidate.readBytes()
            val result = UltraKernelOriginalRecovery(UltraKernelMemoryAssets(emptyMap())).recover(candidate,
                File(workspace, "absent-receipts"), emptyList(), File(workspace, "recover"), generatedOnly = true)
            assertNotNull(format, result)
            assertEquals(UltraKernelOriginalRecovery.Source.IMAGE_BOUND_EXACT_INPUT, result!!.source)
            assertArrayEquals(format, originalBytes, result.image.readBytes())
            assertArrayEquals(format, before, candidate.readBytes())
            assertArrayEquals(format, originalBytes, f.original.readBytes())
            assertNull(BootImageRebuilder.readRecoveryRecord(result.image))
            assertEquals(f.original.length(), result.image.length())
        }
    }

    @Test fun largeOriginalEncodedStreamUsesFilesAndLegacyReaderRetainsItsLimit() {
        val f = fixture("GZIP", random = true)
        val workspace = temporary.newFolder()
        val record = UltraKernelRecoveryEnvelope.write(f.inverse, f.snapshot, f.component, workspace)
        assertTrue(record.length() > UltraKernelRecoveryRecord.MAX_BYTES)
        UltraKernelRecoveryEnvelope.read(record, workspace).use { decoded ->
            assertArrayEquals(f.inverse, decoded.inverse)
            assertArrayEquals(f.component, decoded.originalComponent!!.readBytes())
            assertEquals(UltraKernelSpec.sha256(f.original), BootImageRecovery.read(decoded.snapshot!!).originalImageSha256)
        }
        val kernel = File(workspace, "large-replacement").apply { writeBytes(KernelCompression.encode(f.patched, "GZIP")) }
        val candidate = File(workspace, "large-candidate.img")
        BootImageRebuilder.rebuildWithRecoveryFile(f.original, kernel, candidate, record,
            BootImageRebuilder.OutputPolicy.STRICT)
        val error = assertThrows(IOException::class.java) { BootImageRebuilder.readRecoveryRecord(candidate) }
        assertEquals("RECOVERY_RECORD_SIZE_LIMIT", error.message)
    }

    @Test fun legacyInverseRemainsUnwrappedAndStrictlyDecoded() {
        val f = fixture("RAW_ARM64")
        val record = temporary.newFile().apply { writeBytes(f.inverse) }
        UltraKernelRecoveryEnvelope.read(record, temporary.root).use { decoded ->
            assertArrayEquals(f.inverse, decoded.inverse)
            assertNull(decoded.snapshot)
            assertNull(decoded.originalComponent)
        }
        assertArrayEquals(f.inverse, record.readBytes())
    }

    @Test fun sectionAndLengthCorruptionNeverYieldAValidatedPayload() {
        val f = fixture("GZIP")
        val record = UltraKernelRecoveryEnvelope.write(f.inverse, f.snapshot, f.component, temporary.root)
        val valid = record.readBytes()
        for (at in listOf(8, 16, 40, 136, valid.size - 33, valid.size - 1)) {
            record.writeBytes(valid.clone().apply { this[at] = (this[at].toInt() xor 1).toByte() })
            assertThrows(Exception::class.java) { UltraKernelRecoveryEnvelope.read(record, temporary.root).close() }
            assertFalse(temporary.root.listFiles().orEmpty().any { it.name.startsWith("container-read-") })
        }
        record.writeBytes(valid + byteArrayOf(1))
        assertThrows(Exception::class.java) { UltraKernelRecoveryEnvelope.read(record, temporary.root).close() }
        record.writeBytes(valid.copyOf(valid.size - 1))
        assertThrows(Exception::class.java) { UltraKernelRecoveryEnvelope.read(record, temporary.root).close() }
    }

    @Test fun repeatedPackingKeepsOneFirstInputSnapshotAndNoNestedEnvelope() {
        val f = fixture("LZ4_FRAME")
        val one = UltraKernelRecoveryEnvelope.write(f.inverse, f.snapshot, f.component, temporary.root)
        UltraKernelRecoveryEnvelope.read(one, temporary.root).use { decoded ->
            val two = UltraKernelRecoveryEnvelope.write(decoded.inverse, decoded.snapshot!!,
                decoded.originalComponent!!.readBytes(), temporary.root)
            assertArrayEquals(one.readBytes(), two.readBytes())
        }
    }

    @Test fun validSnapshotDoesNotAcceptAnUnrelatedEncodedComponent() {
        val f = fixture("GZIP")
        assertThrows(IllegalStateException::class.java) {
            UltraKernelRecoveryEnvelope.write(f.inverse, f.snapshot, f.component.clone().apply { this[lastIndex]++ }, temporary.root)
        }
    }

    @Test fun compressedSnapshotRequiresItsOriginalEncodedComponent() {
        val f = fixture("GZIP")
        assertThrows(IllegalStateException::class.java) {
            UltraKernelRecoveryEnvelope.write(f.inverse, f.snapshot, null, temporary.root)
        }
    }

    @Test fun returnedPayloadOwnsOnlyItsTemporarySections() {
        val f = fixture("GZIP")
        val workspace = temporary.newFolder()
        val unrelated = File(workspace, "unrelated.bin").apply { writeBytes(byteArrayOf(3, 7, 9)) }
        val record = UltraKernelRecoveryEnvelope.write(f.inverse, f.snapshot, f.component, workspace)
        val decoded = UltraKernelRecoveryEnvelope.read(record, workspace)
        val snapshot = decoded.snapshot!!
        val component = decoded.originalComponent!!
        val directory = snapshot.parentFile
        assertTrue(snapshot.isFile && component.isFile)
        decoded.close()
        decoded.close()
        assertFalse(snapshot.exists())
        assertFalse(component.exists())
        assertFalse(directory.exists())
        assertTrue(record.isFile && workspace.isDirectory)
        assertArrayEquals(byteArrayOf(3, 7, 9), unrelated.readBytes())
        assertTrue(f.snapshot.isFile)
    }

    @Test fun cleanupRetainsPrimaryAndAttemptsEveryOwnedFile() {
        val directory = temporary.newFolder()
        val blocked = File(directory, "blocked").apply { mkdir() }
        val unrelated = File(blocked, "keep").apply { writeText("keep") }
        val owned = File(directory, "owned").apply { writeText("owned") }
        val primary = IOException("PRIMARY")
        UltraKernelRecoveryEnvelope.cleanup(directory, blocked, owned, primary = primary)
        assertFalse(owned.exists())
        assertEquals("keep", unrelated.readText())
        assertTrue(primary.suppressed.single() is java.nio.file.DirectoryNotEmptyException)
        assertTrue(primary.suppressed.single().suppressed.single() is java.nio.file.DirectoryNotEmptyException)
    }

    @Test fun cleanupFailureAfterSuccessfulWorkIsReportedAndAllActionsAreAttempted() {
        val directory = temporary.newFolder()
        val blocked = File(directory, "blocked").apply { mkdir() }
        File(blocked, "keep").writeText("keep")
        val owned = File(directory, "owned").apply { writeText("owned") }
        val failure = assertThrows(java.nio.file.DirectoryNotEmptyException::class.java) {
            UltraKernelRecoveryEnvelope.cleanup(directory, blocked, owned)
        }
        assertFalse(owned.exists())
        assertTrue(failure.suppressed.single() is java.nio.file.DirectoryNotEmptyException)
    }

}
