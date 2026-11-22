package dev.maplesu.manager.installer

import com.maplesu.core.ui.util.FlashOutcome
import dev.maplesu.image.BootImageRebuilder
import dev.maplesu.installer.BlockDeviceTransaction
import dev.maplesu.manager.ultrakernel.*
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class OwnedEnvironmentRemovalTest {
    @get:Rule val temporary = TemporaryFolder()
    private val assets = UltraKernelMemoryAssets(emptyMap())

    @Test fun imageRecordRemovesOnlyOwnedWritesWithoutReceiptsOrOriginals() {
        val f = fixture()
        val before = f.boot.readBytes()
        val result = resolver().resolveForRestore(f.snapshot, f.live, temporary.newFolder(), setOf("boot"))
        assertEquals("maplesu-owned", result.family)
        assertEquals(ImageRestorationKind.OWNED_WRITES_REMOVED, result.kind)
        assertEquals("IMAGE_BOUND_KERNEL_REVERSE", result.ownershipSource)
        assertEquals(setOf("boot"), result.originals.keys)
        assertArrayEquals(f.original.readBytes(), result.originals.getValue("boot").readBytes())
        assertArrayEquals(before, f.boot.readBytes())
        assertArrayEquals(f.companionBytes, f.live.getValue("init_boot").readBytes())
    }

    @Test fun archivedInverseRemovesOwnedWritesAndReplaysWithoutLocalInstallRecords() {
        val (f, archive) = archivedFixture()
        val before = f.boot.readBytes()
        val result = StockOriginalResolver(archive, null).resolveForRestore(
            f.snapshot, f.live, temporary.newFolder(), null)
        assertEquals("maplesu-owned", result.family)
        assertEquals(ImageRestorationKind.OWNED_WRITES_REMOVED, result.kind)
        assertEquals("ARCHIVED_KERNEL_REVERSE", result.ownershipSource)
        assertEquals(setOf("boot"), result.originals.keys)
        assertArrayEquals(f.original.readBytes(), result.originals.getValue("boot").readBytes())
        assertArrayEquals(before, f.boot.readBytes())
        assertArrayEquals(f.companionBytes, f.live.getValue("init_boot").readBytes())
        val record = removalRecord(f).put("ownedRemovalSource", result.ownershipSource)
        assertEquals(setOf("boot"), StockRestoreTargets.saved(record, f.snapshot, emptyList()))
        assertEquals(ImageRestorationKind.OWNED_WRITES_REMOVED, StockRestoreTargets.restorationKind(record))
        assertEquals(FlashOutcome.WRITTEN, installerTaskResult(result.kind.completedState, false).outcome)
    }

    @Test fun damagedArchivedInverseKeepsItsActualErrorAndProducesNoCandidate() {
        val (f, archive) = archivedFixture(corruptInverse = true)
        val before = f.boot.readBytes()
        val output = temporary.newFolder()
        val error = assertThrows(IllegalStateException::class.java) {
            StockOriginalResolver(archive, null).resolveForRestore(f.snapshot, f.live, output, null)
        }
        assertEquals("ULTRA_KERNEL_ARCHIVED_RECORD_MISMATCH", error.message)
        assertFalse(File(output, "boot.img").exists())
        assertArrayEquals(before, f.boot.readBytes())
        assertArrayEquals(f.companionBytes, f.live.getValue("init_boot").readBytes())
    }

    @Test fun thirdPartyBytesOutsideOwnedRangesSurviveRemovalAndTheSingleWriter() {
        val f = fixture()
        val liveBytes = f.boot.readBytes().apply { this[4096 + 3072] = 0x5a; this[44] = 0x31 }
        f.boot.writeBytes(liveBytes)
        val result = resolver().resolveForRestore(f.snapshot(), f.live, temporary.newFolder(), setOf("boot"))
        val expected = f.original.readBytes().apply { this[4096 + 3072] = 0x5a; this[44] = 0x31 }
        assertArrayEquals(expected, result.originals.getValue("boot").readBytes())
        val devices = f.live.mapValues { MemoryDevice(it.value.readBytes()) }
        val pre = f.live.mapValues { (name, file) -> NativeInstallSequence.Image(name, file, hash(file)) }
        val image = result.originals.getValue("boot")
        val written = NativeInstallSequence.commit(devices, pre,
            listOf(NativeInstallSequence.Image("boot", image, hash(image))), NativeInstallSequence.Journal { _, _, _ -> })
        assertEquals("REBOOT_REQUIRED", written.state)
        assertArrayEquals(expected, devices.getValue("boot").bytes)
        assertArrayEquals(f.companionBytes, devices.getValue("init_boot").bytes)
        assertEquals(0, devices.getValue("init_boot").writes)
    }

    @Test fun ownedWriteFailureRestoresPreAndLeavesEveryCompanionUntouched() {
        val f = fixture()
        val result = resolver().resolveForRestore(f.snapshot, f.live, temporary.newFolder(), setOf("boot"))
        val devices = f.live.mapValues { MemoryDevice(it.value.readBytes()) }
        devices.getValue("boot").failFirstWrite = true
        val before = f.boot.readBytes()
        val image = result.originals.getValue("boot")
        val written = NativeInstallSequence.commit(devices,
            f.live.mapValues { (name, file) -> NativeInstallSequence.Image(name, file, hash(file)) },
            listOf(NativeInstallSequence.Image("boot", image, hash(image))), NativeInstallSequence.Journal { _, _, _ -> })
        assertEquals("RESTORED", written.state)
        assertArrayEquals(before, devices.getValue("boot").bytes)
        assertArrayEquals(f.companionBytes, devices.getValue("init_boot").bytes)
        assertEquals(0, devices.getValue("init_boot").writes)
    }

    @Test fun ownedRangeDamageRemainsTheActualFailureAndProducesNoCandidate() {
        val f = fixture()
        f.boot.writeBytes(f.boot.readBytes().apply { this[4096 + 1024] = 0x6b })
        val output = temporary.newFolder()
        val error = assertThrows(RuntimeException::class.java) {
            resolver().resolveForRestore(f.snapshot(), f.live, output, setOf("boot"))
        }
        assertTrue(error.message.orEmpty(), error.message.orEmpty().contains("ULTRA_KERNEL_RECOVERY_CURRENT_MISMATCH"))
        assertFalse(File(output, "boot.img").exists())
    }

    @Test fun damagedEmbeddedRecordIsNotTreatedAsAnAbsentBackup() {
        val f = fixture()
        val record = requireNotNull(BootImageRebuilder.readRecoveryRecord(f.boot)).apply {
            this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte()
        }
        val kernel = temporary.newFile().apply { writeBytes(UltraKernelPlan.readKernel(f.boot)) }
        val malformed = File(temporary.newFolder(), "boot.img")
        BootImageRebuilder.rebuild(f.boot, kernel, malformed, record)
        val live = f.live + ("boot" to malformed)
        val error = assertThrows(RuntimeException::class.java) {
            resolver().resolveForRestore(f.snapshot(live), live, temporary.newFolder(), setOf("boot"))
        }
        assertTrue(error.message.orEmpty(), error.message.orEmpty().contains("ULTRA_KERNEL_RECOVERY_CHECKSUM"))
    }

    @Test fun rawRecoveryIsNotOfferedByNormalStockInspection() {
        val f = fixture()
        val error = assertThrows(IllegalStateException::class.java) {
            resolver().resolve(f.snapshot, f.live, temporary.newFolder())
        }
        assertEquals("INSTALLER_STOCK_BACKUP_UNAVAILABLE", error.message)
    }

    @Test fun rootOwnedRemovalRecordSelectsItsProvenCarrierWithoutOldInstallRecords() {
        val f = fixture()
        val record = removalRecord(f)
        assertEquals(setOf("boot"), StockRestoreTargets.saved(record, f.snapshot, emptyList()))
        record.put("state", "BOOT_IMAGE_VERIFIED")
        assertEquals(setOf("boot"), StockRestoreTargets.saved(record, f.snapshot, emptyList()))
    }

    @Test fun ownedTargetProofRejectsMissingChangedOrUnprovenCarriers() {
        val f = fixture()
        for (mutate in listOf<(JSONObject) -> Unit>(
            { it.remove("ownedRemovalProof") },
            { it.getJSONObject("ownedRemovalProof").put("boot", "b".repeat(64)) },
            { it.put("ownedRemovalSource", "UNKNOWN") },
            { it.put("stockRestoreTargets", JSONArray(listOf("boot", "init_boot"))) },
            { it.put("stockRestoreTargets", JSONArray(emptyList<String>())) },
        )) {
            val record = removalRecord(f).also(mutate)
            assertThrows(RuntimeException::class.java) { StockRestoreTargets.saved(record, f.snapshot, emptyList()) }
        }
    }

    @Test fun bootOnlyRawReceiptMayNotLoseItsKindAndBecomeAnExactStockClaim() {
        val f = fixture()
        val bootOnly = f.snapshot(mapOf("boot" to f.boot))
        for (kind in listOf(null, "", "EXACT_STOCK")) {
            val record = removalRecord(f)
            if (kind == null) record.remove("restorationKind") else record.put("restorationKind", kind)
            assertThrows(RuntimeException::class.java) { StockRestoreTargets.saved(record, bootOnly, emptyList()) }
        }
    }

    @Test fun completedOwnedRemovalIsASuccessWithoutClaimingStockWasRestored() {
        val result = installerTaskResult("OWNED_WRITES_REMOVED", false)
        assertEquals(0, result.code)
        assertEquals(FlashOutcome.WRITTEN, result.outcome)
        assertFalse(result.showReboot)
    }

    @Test fun noInstallRecordUsesTheImageRecordAndLeavesNonTargetsAsPre() {
        val f = fixture()
        val result = resolver().resolveForRestore(f.snapshot, f.live, temporary.newFolder(), null)
        assertEquals(setOf("boot"), result.originals.keys)
        assertEquals(ImageRestorationKind.OWNED_WRITES_REMOVED, result.kind)
        assertArrayEquals(f.companionBytes, f.live.getValue("init_boot").readBytes())
    }

    @Test fun exactReceiptAndOriginalRemainPreferredOverTheEmbeddedInverse() {
        val f = fixture(keepReceipts = true)
        val result = StockOriginalResolver(assets, f.receipts, listOf(f.original)).resolveForRestore(
            f.snapshot, f.live, temporary.newFolder(), setOf("boot"))
        assertEquals(ImageRestorationKind.EXACT_STOCK, result.kind)
        assertEquals("maplesu-receipt", result.family)
        assertArrayEquals(f.original.readBytes(), result.originals.getValue("boot").readBytes())
    }

    @Test fun aMismatchingAlternateSlotIsNotDowngradedToAnAbsentBackup() {
        val f = fixture()
        val error = assertThrows(IllegalStateException::class.java) {
            StockOriginalResolver(assets, null, alternate = { AlternateSlotImages("_a", f.live) })
                .resolveForRestore(f.snapshot, f.live, temporary.newFolder(), null)
        }
        assertEquals("INSTALLER_STOCK_SLOT_MISMATCH", error.message)
    }

    @Test fun durableKindRoundTripsToTheCorrectPostbootStateAndRejectsUnknownKinds() {
        for ((kind, expected) in listOf(ImageRestorationKind.EXACT_STOCK to "STOCK_RESTORED",
            ImageRestorationKind.OWNED_WRITES_REMOVED to "OWNED_WRITES_REMOVED")) {
            val persisted = JSONObject(JSONObject().put("restorationKind", kind.name).toString())
            assertEquals(expected, imageRestorationAfterBoot("a".repeat(36), "b".repeat(36),
                persisted.getString("restorationKind"))?.completedState)
        }
        assertEquals("STOCK_RESTORED", ImageRestorationKind.fromWire(null).completedState)
        assertThrows(IllegalStateException::class.java) { ImageRestorationKind.fromWire("UNKNOWN") }
    }

    @Test fun sameBootOrMissingBootObservationNeverCompletesRemoval() {
        for (kind in ImageRestorationKind.entries) {
            assertNull(imageRestorationAfterBoot("a".repeat(36), "a".repeat(36), kind.name))
            assertNull(imageRestorationAfterBoot("", "b".repeat(36), kind.name))
            assertNull(imageRestorationAfterBoot("a".repeat(36), "", kind.name))
        }
    }

    private fun resolver() = StockOriginalResolver(assets, File(temporary.root, "absent-receipts"))
    private fun hash(file: File) = UltraKernelSpec.sha256(file)
    private fun archivedFixture(corruptInverse: Boolean = false): Pair<Fixture, UltraKernelAssetSource> {
        val f = fixture()
        val inverse = requireNotNull(BootImageRebuilder.readRecoveryRecord(f.boot))
        val patched = UltraKernelPlan.readKernel(f.boot)
        f.boot.writeBytes(f.original.readBytes().apply { patched.copyInto(this, 4096) })
        val digest = UltraKernelSpec.sha256(patched)
        val metadata = buildJsonObject {
            put("schemaVersion", 1); put("kernelBytes", patched.size)
            put("kernelRelease", f.snapshot.kernelRelease); put("patchedKernelSha256", digest)
            put("originalKernelSha256", UltraKernelSpec.sha256(UltraKernelPlan.readKernel(f.original)))
            put("recordSha256", UltraKernelSpec.sha256(inverse))
        }
        val prefix = "ultra-kernels/recovery/kernel-inverses/$digest"
        val archive = UltraKernelMemoryAssets(mapOf("$prefix.json" to metadata.toString().toByteArray(),
            "$prefix.bin" to inverse.copyOf().apply { if (corruptInverse) this[lastIndex]++ }))
        return f to archive
    }

    private fun removalRecord(f: Fixture) = JSONObject()
        .put("operation", "RESTORE_STOCK").put("restorationKind", "OWNED_WRITES_REMOVED")
        .put("stockRestoreTargets", JSONArray(listOf("boot"))).put("stockRestoreSources", JSONObject())
        .put("stockRestoreCoverage", "IMAGE_OWNED_RECORD")
        .put("originalSource", "maplesu-owned").put("ownedRemovalSource", "IMAGE_BOUND_KERNEL_REVERSE")
        .put("ownedRemovalProof", JSONObject().put("boot", f.snapshot.partitions.getValue("boot").sha256))
        .put("originals", JSONObject().put("boot", hash(f.original)))

    private class MemoryDevice(val bytes: ByteArray) : BlockDeviceTransaction.Device {
        var writes = 0
        var failFirstWrite = false
        override fun size() = bytes.size.toLong()
        override fun revalidate() = Unit
        override fun read(offset: Long, buffer: ByteArray, length: Int): Int {
            bytes.copyInto(buffer, 0, offset.toInt(), offset.toInt() + length); return length
        }
        override fun write(offset: Long, buffer: ByteArray, start: Int, length: Int): Int {
            writes++
            if (failFirstWrite && writes == 1) {
                bytes[offset.toInt()] = buffer[start]
                throw IOException("INSTALLER_DEVICE_WRITE_FAILED")
            }
            buffer.copyInto(bytes, offset.toInt(), start, start + length); return length
        }
        override fun sync() = Unit
        override fun close() = Unit
    }

    private fun fixture(keepReceipts: Boolean = false): Fixture {
        val release = "6.6.89-android15-owned-removal-fixture"
        val raw = ByteArray(8192).apply {
            "ARMd".toByteArray().copyInto(this, 56)
            "Linux version $release (fixture)".toByteArray().copyInto(this, 128)
        }
        val original = temporary.newFile().apply {
            writeBytes(ByteArray(16384).apply {
                ByteBuffer.wrap(this).order(ByteOrder.LITTLE_ENDIAN).apply {
                    put("ANDROID!".toByteArray()); putInt(8, raw.size); putInt(20, 1584); putInt(40, 4)
                }
                raw.copyInto(this, 4096)
            })
        }
        val credential = UltraKernelCredential.of("Ab1".repeat(16))
        val plan = UltraKernelPlan.fromRecords(release,
            listOf(UltraKernelPlan.PatchRecord("fixture", 1024, ByteArray(48), credential.copySecret()),
                UltraKernelPlan.PatchRecord("path", 2048, ByteArray(UltraKernelCredential.INIT_PATH_FIELD),
                    credential.initPathField(UltraKernelCredential.INIT_PATH_FIELD))),
            credential, baseKernelSha256 = UltraKernelSpec.sha256(raw)).let { it.withDerived(it.apply(raw).derived) }
        val text = plan.specText(plan.credential)
        val directory = temporary.newFolder()
        val candidate = UltraKernelBuilder(directory).generate(original,
            UltraKernelGeneratedAsset.of(plan, original.length(), 0, text), UltraKernelSpec.parse(text)).image
        val boot = temporary.newFile().apply { writeBytes(candidate.readBytes()) }
        if (!keepReceipts) directory.deleteRecursively()
        val companion = temporary.newFile().apply {
            writeBytes(ByteArray(4096).apply {
                ByteBuffer.wrap(this).order(ByteOrder.LITTLE_ENDIAN).apply {
                    put("ANDROID!".toByteArray()); putInt(20, 1584); putInt(40, 4)
                }
                this[44] = 0x43
            })
        }
        return Fixture(original, boot, mapOf("boot" to boot, "init_boot" to companion), companion.readBytes(), release, directory)
    }

    private class Fixture(val original: File, val boot: File, val live: Map<String, File>,
                          val companionBytes: ByteArray, private val release: String, val receipts: File) {
        val snapshot get() = snapshot()
        fun snapshot(images: Map<String, File> = live) = InstallerSnapshot(release, "fixture", "_a", "Enforcing",
            images.mapValues { (name, image) -> BootPartitionSnapshot(name, "/dev/block/by-name/${name}_a",
                "/dev/block/$name", image.length(), UltraKernelSpec.sha256(image)) })
    }
}
