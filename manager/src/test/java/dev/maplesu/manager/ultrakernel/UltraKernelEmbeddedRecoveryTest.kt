package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.BootImageRebuilder
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/** Real generated images must carry their inverse independently of Manager-local files. */
class UltraKernelEmbeddedRecoveryTest {
    @get:Rule val temporary = TemporaryFolder()
    private val assets = UltraKernelMemoryAssets(emptyMap())

    @Test fun emptyCatalogueAndReceiptsStillPreviewTheOriginalKernelWithoutWrites() {
        val fixture = fixture()
        val before = files(fixture.directory)
        val restored = UltraKernelOriginalRecovery(assets).generatedKernel(fixture.image, fixture.emptyReceipts)
        assertNotNull("a generated image must retain its own inverse after local receipt/spec removal", restored)
        assertArrayEquals(fixture.raw, restored)
        assertEquals("preview must not create or change files", before, files(fixture.directory))
    }

    @Test fun emptyCatalogueAndReceiptsStillRecoverTheOriginalKernel() {
        val fixture = fixture()
        val restored = UltraKernelOriginalRecovery(assets).recover(fixture.image, fixture.emptyReceipts,
            emptyList(), File(fixture.directory, "recovered"), generatedOnly = true)
        assertNotNull("generated upgrade recovery must use the inverse carried by the image", restored)
        assertEquals("IMAGE_BOUND_KERNEL_REVERSE", restored!!.source.name)
        assertArrayEquals(fixture.raw, UltraKernelPlan.readKernel(restored.image))
        assertNull("a pristine recovery output must remove the old inverse", BootImageRebuilder.readRecoveryRecord(restored.image))
    }

    @Test fun movedImageRecoversAfterAllLocalReceiptAndSpecFilesAreRemoved() {
        val fixture = fixture()
        val replacement = temporary.newFolder("replacement-manager-workspace")
        val image = File(replacement, "installed.img")
        fixture.image.copyTo(image)
        fixture.directory.deleteRecursively()
        val receipts = File(replacement, "empty-receipts").apply { mkdirs() }
        val before = files(replacement)
        val recovery = UltraKernelOriginalRecovery(assets)
        assertArrayEquals(fixture.raw, recovery.generatedKernel(image, receipts))
        assertEquals(before, files(replacement))
        val restored = recovery.recover(image, receipts, emptyList(), File(replacement, "restored"), generatedOnly = true)
        assertNotNull(restored)
        assertEquals("IMAGE_BOUND_KERNEL_REVERSE", restored!!.source.name)
        assertArrayEquals(fixture.raw, UltraKernelPlan.readKernel(restored.image))
        assertEquals("the installed image must remain unchanged", before["installed.img"], UltraKernelSpec.sha256(image))
    }

    @Test fun rawInverseAloneDoesNotClaimAnExactStockContainer() {
        val fixture = fixture()
        assertNull("the image-bound inverse proves kernel bytes, not the original stock-container digest",
            UltraKernelOriginalRecovery(assets).recover(fixture.image, fixture.emptyReceipts,
                emptyList(), File(fixture.directory, "stock-recovery"), generatedOnly = false))
    }

    @Test fun newImageWithRetainedReceiptStillRestoresTheExactStockContainer() {
        val fixture = fixture()
        val workspace = File(fixture.directory, "retained-receipt")
        val image = build(fixture.base, fixture.raw, UltraKernelCredential.of("Aa1".repeat(16)), workspace)
        val restored = UltraKernelOriginalRecovery(assets).recover(image, workspace,
            emptyList(), File(fixture.directory, "exact-stock"))
        assertNotNull("embedding a new inverse must preserve the existing receipt-backed stock recovery", restored)
        assertEquals("EXACT_SPEC_REVERSE", restored!!.source.name)
        assertArrayEquals(fixture.base.readBytes(), restored.image.readBytes())
    }

    @Test fun changedPatchedRangeDoesNotProduceAnOriginalKernel() {
        val fixture = fixture()
        val bytes = fixture.image.readBytes()
        bytes[4096 + 1024] = (bytes[4096 + 1024].toInt() xor 1).toByte()
        fixture.image.writeBytes(bytes)
        val before = files(fixture.directory)
        val recovery = UltraKernelOriginalRecovery(assets)
        fails("ULTRA_KERNEL_RECOVERY_CURRENT_MISMATCH") { recovery.generatedKernel(fixture.image, fixture.emptyReceipts) }
        fails("ULTRA_KERNEL_RECOVERY_CURRENT_MISMATCH") {
            recovery.recover(fixture.image, fixture.emptyReceipts, emptyList(),
                File(fixture.directory, "changed-recovery"), generatedOnly = true)
        }
        assertEquals(before, files(fixture.directory))
    }

    @Test fun unrelatedKernelAndContainerChangesArePreservedWithoutFingerprintGates() {
        val fixture = fixture()
        val bytes = fixture.image.readBytes().apply { this[44] = 'x'.code.toByte(); this[4096 + 4095] = 22 }
        fixture.image.writeBytes(bytes)
        val expected = fixture.raw.clone().apply { this[4095] = 22 }
        val before = files(fixture.directory)
        val recovery = UltraKernelOriginalRecovery(assets)
        assertArrayEquals(expected, recovery.generatedKernel(fixture.image, fixture.emptyReceipts))
        assertEquals(before, files(fixture.directory))
        val restored = recovery.recover(fixture.image, fixture.emptyReceipts, emptyList(),
            File(fixture.directory, "third-party-recovery"), generatedOnly = true)
        assertNotNull(restored)
        assertArrayEquals(expected, UltraKernelPlan.readKernel(restored!!.image))
        assertEquals('x'.code.toByte(), restored.image.readBytes()[44])
    }

    @Test fun brokenLocalReceiptAndSpecDoNotBlockTheImageBoundInverse() {
        val fixture = fixture()
        File(fixture.emptyReceipts, "candidate-generated-broken.json").writeText("{")
        File(fixture.emptyReceipts, "candidate-generated-broken.spec").writeText("invalid")
        val before = files(fixture.directory)
        assertArrayEquals(fixture.raw,
            UltraKernelOriginalRecovery(assets).generatedKernel(fixture.image, fixture.emptyReceipts))
        assertEquals(before, files(fixture.directory))
        assertNotNull(UltraKernelOriginalRecovery(assets).recover(fixture.image, fixture.emptyReceipts, emptyList(),
            File(fixture.directory, "broken-local-recovery"), generatedOnly = true))
    }

    @Test fun recoveredBaselineRegeneratesSameAndRotatedCredentialsLikeTheCleanBaseline() {
        val fixture = fixture()
        val restored = UltraKernelOriginalRecovery(assets).recover(fixture.image, fixture.emptyReceipts, emptyList(),
            File(fixture.directory, "rotation-recovery"), generatedOnly = true)
        assertNotNull(restored)
        for (key in listOf("Aa1".repeat(16), "Bb2".repeat(16))) {
            val clean = build(fixture.base, fixture.raw, UltraKernelCredential.of(key),
                File(fixture.directory, "clean-${key.take(3)}"))
            val upgraded = build(restored!!.image, fixture.raw, UltraKernelCredential.of(key),
                File(fixture.directory, "upgraded-${key.take(3)}"))
            assertArrayEquals("regeneration matches a clean-baseline build for each credential",
                clean.readBytes(), upgraded.readBytes())
            if (key.startsWith("Aa1")) assertArrayEquals("same-key regeneration remains byte-identical",
                fixture.image.readBytes(), upgraded.readBytes())
        }
    }

    @Test fun missingOrInvalidRecordDoesNotUseAnUnprovenKernelPreimage() {
        val fixture = fixture()
        val recovery = UltraKernelOriginalRecovery(assets)
        val missing = withRecord(fixture, null, "missing")
        assertNull(recovery.generatedKernel(missing, fixture.emptyReceipts))
        assertNull(recovery.recover(missing, fixture.emptyReceipts, emptyList(),
            File(fixture.directory, "missing-recovery"), generatedOnly = true))
        val record = requireNotNull(BootImageRebuilder.readRecoveryRecord(fixture.image))
        val cases = listOf(
            "ULTRA_KERNEL_RECOVERY_CHECKSUM" to record.clone().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() },
            "ULTRA_KERNEL_RECOVERY_FORMAT" to changedRecordInt(record, 8, 99),
            "ULTRA_KERNEL_RECOVERY_HEADER_LENGTH" to changedRecordInt(record, 12, record.size - 1),
            "ULTRA_KERNEL_RECOVERY_CURRENT_LENGTH" to changedRecordInt(record, 32, fixture.raw.size + 1),
        )
        for ((index, case) in cases.withIndex()) {
            val malformed = withRecord(fixture, case.second, "invalid-$index")
            val before = files(fixture.directory)
            fails(case.first) { recovery.generatedKernel(malformed, fixture.emptyReceipts) }
            fails(case.first) { recovery.recover(malformed, fixture.emptyReceipts, emptyList(),
                File(fixture.directory, "invalid-recovery-$index"), generatedOnly = true) }
            assertEquals(before, files(fixture.directory))
        }
    }

    @Test fun twoUpgradeRoundsKeepOneInverseAndAlwaysRestoreTheCleanKernel() {
        val fixture = fixture()
        var installed = fixture.image
        for ((index, key) in listOf("Bb2".repeat(16), "Cc3".repeat(16)).withIndex()) {
            val restored = UltraKernelOriginalRecovery(assets).recover(installed, fixture.emptyReceipts, emptyList(),
                File(fixture.directory, "round-$index-recovery"), generatedOnly = true)
            assertNotNull(restored)
            assertArrayEquals(fixture.raw, UltraKernelPlan.readKernel(restored!!.image))
            assertNull(BootImageRebuilder.readRecoveryRecord(restored.image))
            installed = build(restored.image, fixture.raw, UltraKernelCredential.of(key),
                File(fixture.directory, "round-$index-builder"))
            val inverse = requireNotNull(BootImageRebuilder.readRecoveryRecord(installed))
            assertArrayEquals(fixture.raw, UltraKernelRecoveryRecord.decode(inverse).restore(UltraKernelPlan.readKernel(installed)))
            assertEquals("the record occupies one region rather than appending a chain", fixture.image.length(), installed.length())
            val marker = byteArrayOf(77, 83, 85, 82, 82, 69, 71, 0)
            val bytes = installed.readBytes()
            val occurrences = (0..bytes.size - marker.size).count { offset ->
                marker.indices.all { bytes[offset + it] == marker[it] }
            }
            assertEquals("the controlled fixture contains one recovery envelope", 1, occurrences)
        }
    }

    private fun changedRecordInt(record: ByteArray, offset: Int, value: Int): ByteArray = record.clone().apply {
        ByteBuffer.wrap(this).order(ByteOrder.LITTLE_ENDIAN).putInt(offset, value)
        MessageDigest.getInstance("SHA-256").run {
            update(this@apply, 0, this@apply.size - 32); digest().copyInto(this@apply, this@apply.size - 32)
        }
    }

    private fun withRecord(fixture: Fixture, record: ByteArray?, name: String): File {
        val report = BootImageInspector.inspect(fixture.image)
        val component = ByteArray(report.kernelSize.toInt())
        RandomAccessFile(fixture.image, "r").use { it.seek(report.kernelOffset); it.readFully(component) }
        val kernel = File(fixture.directory, "$name-kernel.component").apply { writeBytes(component) }
        val output = File(fixture.directory, "$name.img")
        BootImageRebuilder.rebuild(fixture.image, kernel, output, record)
        return output
    }

    private fun files(directory: File): Map<String, String> = directory.walkTopDown().filter { it.isFile }
        .associate { it.relativeTo(directory).invariantSeparatorsPath to UltraKernelSpec.sha256(it) }

    private fun fails(expected: String, action: () -> Unit) {
        try { action(); fail("expected $expected") }
        catch (error: Exception) { assertEquals(expected, error.message) }
    }

    private fun fixture(): Fixture {
        val directory = temporary.newFolder("fixture-${System.nanoTime()}")
        val raw = ByteArray(8192).apply {
            "ARMd".toByteArray().copyInto(this, 56)
            "Linux version 6.6.89-embedded-recovery (fixture)".toByteArray().copyInto(this, 128)
        }
        val base = File(directory, "original.img")
        val bytes = ByteArray(12288)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("ANDROID!".toByteArray()); putInt(8, raw.size); putInt(20, 1584); putInt(40, 4)
        }
        raw.copyInto(bytes, 4096)
        base.writeBytes(bytes)
        val workspace = File(directory, "builder")
        val image = build(base, raw, UltraKernelCredential.of("Aa1".repeat(16)), workspace)
        workspace.listFiles().orEmpty().filter { it != image }.forEach { it.deleteRecursively() }
        val empty = File(directory, "empty-receipts").apply { mkdirs() }
        return Fixture(directory, raw, image, empty, base)
    }

    private fun build(base: File, raw: ByteArray, credential: UltraKernelCredential, workspace: File): File {
        val plan = UltraKernelPlan.fromRecords("6.6.89-embedded-recovery",
            listOf(UltraKernelPlan.PatchRecord("fixture", 1024, ByteArray(48), credential.copySecret()),
                UltraKernelPlan.PatchRecord("path", 2048, ByteArray(UltraKernelCredential.INIT_PATH_FIELD),
                    credential.initPathField(UltraKernelCredential.INIT_PATH_FIELD))),
            credential, baseKernelSha256 = UltraKernelSpec.sha256(raw))
            .let { it.withDerived(it.apply(raw).derived) }
        val text = plan.specText(plan.credential)
        val asset = UltraKernelGeneratedAsset.of(plan, base.length(), 0, text)
        val image = UltraKernelBuilder(workspace).generate(base, asset, UltraKernelSpec.parse(text)).image
        return image
    }

    private class Fixture(val directory: File, val raw: ByteArray, val image: File,
        val emptyReceipts: File, val base: File)
}
