package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.BootImageRebuilder
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class UltraKernelGeneratedRecoveryTest {
    @get:Rule val temporary = TemporaryFolder()
    private val assets = UltraKernelMemoryAssets(emptyMap())
    private val release = "6.18.21-android17-generated-recovery-fixture"

    @Test fun generatedBuildRetainsTheExactSpecBoundByItsReceipt() {
        val fixture = fixture()
        assertTrue("generated spec must survive for subsequent upgrades", fixture.spec.isFile)
        assertEquals(fixture.asset.specSha256, UltraKernelSpec.sha256(fixture.spec))
    }

    @Test fun generatedReceiptRestoresTheExactOriginalWithoutACatalogueOrStockCopy() {
        val fixture = fixture()
        val recovered = recover(fixture)
        assertNotNull("a verified generated candidate must retain its reversible preimage", recovered)
        assertEquals(UltraKernelOriginalRecovery.Source.EXACT_SPEC_REVERSE, recovered!!.source)
        assertArrayEquals(fixture.base.readBytes(), recovered.image.readBytes())
    }

    @Test fun unrelatedHistoricalReceiptsDoNotHideTheMatchingInstalledImage() {
        val fixture = fixture()
        repeat(32) { index ->
            File(fixture.workspace, "candidate-generated-interrupted-$index.json").writeText("{")
        }
        assertNotNull("all retained receipts must be searched independently", recover(fixture))
        val raw = UltraKernelOriginalRecovery(assets).generatedKernel(fixture.candidate.image, fixture.workspace)
        assertArrayEquals(UltraKernelPlan.readKernel(fixture.base), raw)
        assertEquals("{", File(fixture.workspace, "candidate-generated-interrupted-31.json").readText())
    }

    @Test fun absentOrChangedLocalSpecDoesNotProduceAnOriginal() {
        val fixture = fixture()
        fixture.spec.writeText("#kernel=$release\n1024|00|02")
        assertNull(recover(fixture))
        fixture.spec.delete()
        assertNull(recover(fixture))
    }

    @Test fun modifiedCandidateOrOutsidePatchBytesDoNotProduceAnOriginal() {
        val fixture = fixture()
        val bytes = fixture.candidate.image.readBytes().apply { this[64] = 88 }
        fixture.candidate.image.writeBytes(bytes)
        assertNull(recover(fixture))
        rewrite(fixture) { put("candidateBootSha256", UltraKernelSpec.sha256(bytes)) }
        assertNull(recover(fixture))
    }

    @Test fun wrongOriginalDigestDoesNotProduceAnOriginal() {
        val fixture = fixture()
        rewrite(fixture) { put("baseKernelSha256", "0".repeat(64)) }
        assertNull(recover(fixture))
    }

    @Test fun zeroPaddedPartitionIsProvenButANonzeroTailIsRejected() {
        val fixture = fixture()
        val partition = File(fixture.base.parentFile, "partition.img")
        partition.writeBytes(fixture.candidate.image.readBytes().copyOf(65536))
        val recovered = recover(fixture, partition)
        assertNotNull(recovered)
        assertArrayEquals(fixture.base.readBytes(), recovered!!.image.readBytes())
        partition.writeBytes(partition.readBytes().apply { this[lastIndex] = 1 })
        assertNull(recover(fixture, partition))
    }

    @Test fun generatedUpgradeCanRestoreTheKernelAfterContainerSignaturesWereRemoved() {
        val fixture = fixture(signature = true)
        val before = UltraKernelSpec.sha256(fixture.candidate.image)
        assertNull("exact stock recovery must still require the original container digest", recover(fixture))
        val recovered = UltraKernelOriginalRecovery(assets).recover(fixture.candidate.image,
            fixture.workspace, emptyList(), temporary.newFolder("kernel-preimage"), generatedOnly = true)
        assertNotNull("a proven installed container must support kernel-only upgrade recovery", recovered)
        assertArrayEquals(UltraKernelPlan.readKernel(fixture.base), UltraKernelPlan.readKernel(recovered!!.image))
        assertFalse(fixture.base.readBytes().contentEquals(recovered.image.readBytes()))
        assertEquals(before, UltraKernelSpec.sha256(fixture.candidate.image))
    }

    @Test fun generatedUpgradeRecoveryCanBeRepeatedInTheSameWorkspace() {
        val fixture = fixture()
        val output = temporary.newFolder("repeated-kernel-preimage")
        repeat(2) {
            assertNotNull("a previous recovery output must not break the next upgrade",
                UltraKernelOriginalRecovery(assets).recover(fixture.candidate.image,
                    fixture.workspace, emptyList(), output, generatedOnly = true))
        }
    }

    @Test fun generatedUpgradePreservesChangesOutsideTheRecordedWriteRanges() {
        val fixture = fixture(signature = true)
        val bytes = fixture.candidate.image.readBytes().apply { this[4096 + 4095] = 1 }
        fixture.candidate.image.writeBytes(bytes)
        rewrite(fixture) { put("candidateBootSha256", UltraKernelSpec.sha256(bytes)) }
        val recovered = UltraKernelOriginalRecovery(assets).recover(fixture.candidate.image,
            fixture.workspace, emptyList(), temporary.newFolder("changed-kernel"), generatedOnly = true)
        assertNotNull(recovered)
        val expected = UltraKernelPlan.readKernel(fixture.base).apply { this[4095] = 1 }
        assertArrayEquals(expected, UltraKernelPlan.readKernel(recovered!!.image))
        assertEquals("IMAGE_BOUND_KERNEL_REVERSE", recovered.source.name)
    }

    @Test fun generatedPreviewRestoresKernelBytesWithoutWritingOrChangingAnyFile() {
        val fixture = fixture(signature = true)
        fun files() = fixture.workspace.walkTopDown().filter { it.isFile }
            .associate { it.relativeTo(fixture.workspace).path to UltraKernelSpec.sha256(it) }
        val before = files()
        val raw = UltraKernelOriginalRecovery(assets).generatedKernel(fixture.candidate.image, fixture.workspace)
        assertNotNull("the selection page must recognize a verified generated candidate", raw)
        assertArrayEquals(UltraKernelPlan.readKernel(fixture.base), raw)
        assertEquals(before, files())
    }

    @Test fun generatedPreviewUsesImageBoundInverseDespiteChangedLocalSpecOrContainerHeader() {
        val fixture = fixture()
        val recovery = UltraKernelOriginalRecovery(assets)
        val valid = fixture.spec.readBytes()
        fixture.spec.appendText("# changed")
        assertArrayEquals(UltraKernelPlan.readKernel(fixture.base),
            recovery.generatedKernel(fixture.candidate.image, fixture.workspace))
        fixture.spec.writeBytes(valid)
        fixture.candidate.image.writeBytes(fixture.candidate.image.readBytes().apply { this[44] = 'x'.code.toByte() })
        assertArrayEquals(UltraKernelPlan.readKernel(fixture.base),
            recovery.generatedKernel(fixture.candidate.image, fixture.workspace))
    }

    @Test fun legacyReceiptOnlyImageStillRecoversWithoutAnEmbeddedInverse() {
        val fixture = fixture()
        val report = BootImageInspector.inspect(fixture.candidate.image)
        val bytes = ByteArray(report.kernelSize.toInt())
        RandomAccessFile(fixture.candidate.image, "r").use { it.seek(report.kernelOffset); it.readFully(bytes) }
        val component = File(fixture.workspace, "legacy-kernel.component").apply { writeBytes(bytes) }
        val legacy = File(fixture.workspace, "legacy.img")
        BootImageRebuilder.rebuild(fixture.candidate.image, component, legacy, null)
        legacy.copyTo(fixture.candidate.image, overwrite = true)
        rewrite(fixture) {
            put("candidateBootSha256", UltraKernelSpec.sha256(fixture.candidate.image))
            put("candidateImageBytes", fixture.candidate.image.length())
        }
        assertNull(BootImageRebuilder.readRecoveryRecord(fixture.candidate.image))
        val recovery = UltraKernelOriginalRecovery(assets)
        assertArrayEquals(UltraKernelPlan.readKernel(fixture.base),
            recovery.generatedKernel(fixture.candidate.image, fixture.workspace))
        val recovered = recovery.recover(fixture.candidate.image, fixture.workspace, emptyList(),
            temporary.newFolder("legacy-kernel-recovery"), generatedOnly = true)
        assertNotNull(recovered)
        assertEquals("RECEIPT_BOUND_KERNEL_REVERSE", recovered!!.source.name)
        assertArrayEquals(UltraKernelPlan.readKernel(fixture.base), UltraKernelPlan.readKernel(recovered.image))
        assertNotNull("legacy exact-stock receipt proof must remain available", recover(fixture))
    }

    private fun recover(fixture: Fixture, current: File = fixture.candidate.image) =
        UltraKernelOriginalRecovery(assets).recover(current, fixture.workspace, emptyList(),
            temporary.newFolder("recovery-${System.nanoTime()}"))

    private fun rewrite(fixture: Fixture, changes: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit) {
        val original = Json.parseToJsonElement(fixture.receipt.readText()) as JsonObject
        fixture.receipt.writeText(buildJsonObject {
            original.forEach { (key, value) -> put(key, value) }
            changes()
        }.toString())
    }

    private fun fixture(signature: Boolean = false): Fixture {
        val directory = temporary.newFolder("fixture-${System.nanoTime()}")
        val raw = ByteArray(8192).apply {
            "ARMd".toByteArray().copyInto(this, 56)
            "Linux version $release (fixture)".toByteArray().copyInto(this, 128)
        }
        val base = File(directory, "original.img")
        val bytes = ByteArray(if (signature) 16384 else 12288)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("ANDROID!".toByteArray()); putInt(8, raw.size); putInt(20, 1584); putInt(40, 4)
            if (signature) putInt(1580, 4096)
        }
        raw.copyInto(bytes, 4096)
        base.writeBytes(bytes)
        val plan = UltraKernelPlan.fromRecords(release,
            listOf(UltraKernelPlan.PatchRecord("fixture", 1024, ByteArray(48), "Aa1".repeat(16).toByteArray()),
                UltraKernelPlan.PatchRecord("path", 2048, ByteArray(UltraKernelCredential.INIT_PATH_FIELD),
                    UltraKernelCredential.of("Aa1".repeat(16)).initPathField(UltraKernelCredential.INIT_PATH_FIELD))),
            UltraKernelCredential.of("Aa1".repeat(16)), baseKernelSha256 = UltraKernelSpec.sha256(raw))
            .let { it.withDerived(it.apply(raw).derived) }
        val text = plan.specText(plan.credential)
        val asset = UltraKernelGeneratedAsset.of(plan, base.length(), 0, text)
        val workspace = File(directory, "work")
        val candidate = UltraKernelBuilder(workspace).generate(base, asset, UltraKernelSpec.parse(text))
        return Fixture(base, workspace, asset, candidate,
            File(workspace, "candidate-${asset.id}.json"),
            File(workspace, "candidate-${asset.id}-${asset.specSha256}.spec"))
    }

    private class Fixture(val base: File, val workspace: File, val asset: UltraKernelGeneratedAsset,
        val candidate: UltraKernelBuilder.Candidate, val receipt: File, val spec: File)
}
