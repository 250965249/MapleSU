package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.BootImageRebuilder
import dev.maplesu.image.BootImageRecovery
import dev.maplesu.image.KernelCompression
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Synthetic data records only; no recipe renderer, executable payload, SDK or device. */
class UltraKernelContainerIntegrationTest {
    @get:Rule val temporary = TemporaryFolder()
    private val release = "6.6.89-container-data-fixture"
    private val assets = UltraKernelMemoryAssets(emptyMap())

    private data class Input(val image: File, val raw: ByteArray)

    private fun input(spare: Boolean = true): Input {
        val raw = ByteArray(65537)
        "ARMd".toByteArray().copyInto(raw, 56)
        "Linux version $release (opaque-data)".toByteArray().copyInto(raw, 128)
        val encoded = KernelCompression.encode(raw, "GZIP")
        val ramdisk = ((4096 + encoded.size + 4095) / 4096) * 4096
        val bytes = ByteArray(ramdisk + 4096 + if (spare) 65536 else 0)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("ANDROID!".toByteArray()); putInt(8, encoded.size); putInt(12, 31)
            putInt(20, 1584); putInt(40, 4)
        }
        encoded.copyInto(bytes, 4096)
        bytes.fill(37, 4096 + encoded.size, ramdisk)
        bytes.fill(19, ramdisk, ramdisk + 31)
        bytes.fill(29, ramdisk + 31, ramdisk + 4096)
        return Input(temporary.newFile().apply { writeBytes(bytes) }, raw)
    }

    private fun build(input: Input, workspace: File, value: Int,
                      retained: File? = null): UltraKernelBuilder.Candidate {
        val spec = UltraKernelSpec.parse("#kernel=$release\n1024|00|${"%02x".format(value)}")
        val unbound = UltraKernelPlan.fromSpec(spec, UltraKernelPlan.Origin.GENERATED)
        val plan = unbound.withDerived(unbound.apply(input.raw).derived)
        val text = plan.specText()
        val asset = UltraKernelGeneratedAsset.of(plan, input.image.length(), 31, text)
        return UltraKernelBuilder(workspace).generate(input.image, asset, UltraKernelSpec.parse(text),
            retainedRecoveryImage = retained)
    }

    private fun receipt(candidate: UltraKernelBuilder.Candidate): JsonObject = Json.parseToJsonElement(
        File(candidate.image.parentFile, "candidate-${candidate.image.name.substringAfter("candidate-").substringBeforeLast('-')}.json")
            .readText()) as JsonObject

    @Test fun exactFirstInputSurvivesRepeatedBuildAndRecoveryWithoutReceipts() {
        val first = input()
        val expected = first.image.readBytes()
        var source = first
        repeat(2) { iteration ->
            val work = temporary.newFolder()
            val candidate = build(source, work, iteration + 7)
            assertEquals("FIRST_INPUT_EXACT", receipt(candidate)["recoveryCoverage"]!!.jsonPrimitive.content)
            val record = File(temporary.newFolder(), "record.bin")
            assertTrue(BootImageRebuilder.extractRecoveryRecord(candidate.image, record,
                BootImageRebuilder.OutputPolicy.STRICT))
            UltraKernelRecoveryEnvelope.read(record, temporary.root).use {
                assertEquals(UltraKernelSpec.sha256(expected), BootImageRecovery.read(it.snapshot!!).originalImageSha256)
            }
            val recovered = UltraKernelOriginalRecovery(assets).recover(candidate.image,
                File(temporary.root, "no-receipts"), emptyList(), temporary.newFolder(), generatedOnly = true)!!
            assertEquals(UltraKernelOriginalRecovery.Source.IMAGE_BOUND_EXACT_INPUT, recovered.source)
            assertArrayEquals(expected, recovered.image.readBytes())
            assertEquals(listOf(recovered.image.name), recovered.image.parentFile!!.listFiles()!!.map { it.name })
            assertNull(BootImageRebuilder.readRecoveryRecord(recovered.image))
            source = Input(recovered.image, first.raw)
        }
        assertArrayEquals(expected, first.image.readBytes())
    }

    @Test fun insufficientContainerSpaceKeepsKernelRecoveryAndRecordsItsActualCoverage() {
        val f = input(spare = false)
        val candidate = build(f, temporary.newFolder(), 7)
        val receipt = receipt(candidate)
        assertEquals("KERNEL_WRITES_ONLY", receipt["recoveryCoverage"]!!.jsonPrimitive.content)
        assertEquals("RECOVERY_RECORD_CAPACITY_LIMIT", receipt["recoveryFallback"]!!.jsonPrimitive.content)
        val recovered = UltraKernelOriginalRecovery(assets).recover(candidate.image,
            File(temporary.root, "no-receipts"), emptyList(), temporary.newFolder(), generatedOnly = true)!!
        assertEquals(UltraKernelOriginalRecovery.Source.IMAGE_BOUND_KERNEL_REVERSE, recovered.source)
        assertArrayEquals(f.raw, UltraKernelPlan.readKernel(recovered.image))
    }

    @Test fun earlyRetainedRecordMismatchCleansOnlyOwnedTemporaryFiles() {
        val f = input()
        val first = build(f, temporary.newFolder(), 7)
        val workspace = temporary.newFolder()
        val keep = File(workspace, "keep.txt").apply { writeText("keep") }
        val failure = assertThrows(IllegalStateException::class.java) { build(f, workspace, 8, first.image) }
        assertEquals("ULTRA_KERNEL_RECOVERY_RETAINED_MISMATCH", failure.message)
        assertEquals(listOf(keep.name), workspace.listFiles()!!.map { it.name })
        assertEquals("keep", keep.readText())
    }

    @Test fun originalEncodingIsRestoredEvenAfterTheCurrentKernelIsRecompressed() {
        val f = input()
        val first = build(f, temporary.newFolder(), 7)
        val replacement = temporary.newFile().apply {
            writeBytes(KernelCompression.encode(UltraKernelPlan.readKernel(first.image), "LZ4_FRAME"))
        }
        val repacked = File(temporary.newFolder(), "repacked.img")
        BootImageRebuilder.rebuild(first.image, replacement, repacked)
        assertEquals("LZ4_FRAME", BootImageInspector.inspect(repacked).compression)
        val recovered = UltraKernelOriginalRecovery(assets).recover(repacked,
            File(temporary.root, "no-receipts"), emptyList(), temporary.newFolder(), generatedOnly = true)!!
        assertArrayEquals(f.image.readBytes(), recovered.image.readBytes())
    }
    @Test fun foreignKernelAndRamdiskEditsKeepTheExistingKernelOnlyRecovery() {
        for (region in listOf("kernel", "ramdisk")) {
            val f = input()
            val candidate = build(f, temporary.newFolder(), 7)
            val layout = BootImageInspector.inspect(candidate.image)
            val replacement = temporary.newFile().apply {
                writeBytes(KernelCompression.encode(UltraKernelPlan.readKernel(candidate.image).apply {
                    if (region == "kernel") this[4096] = 91
                }, layout.compression))
            }
            val changed = File(temporary.newFolder(), "foreign-edit.img")
            BootImageRebuilder.rebuild(candidate.image, replacement, changed)
            if (region == "ramdisk") java.io.RandomAccessFile(changed, "rw").use {
                it.seek(BootImageInspector.inspect(changed).ramdiskOffset); it.write(91)
            }
            val before = changed.readBytes()
            val result = UltraKernelOriginalRecovery(assets).recover(changed,
                File(temporary.root, "no-receipts"), emptyList(), temporary.newFolder(), generatedOnly = true)!!
            assertEquals(UltraKernelOriginalRecovery.Source.IMAGE_BOUND_KERNEL_REVERSE, result.source)
            val expected = f.raw.clone().apply { if (region == "kernel") this[4096] = 91 }
            assertArrayEquals(expected, UltraKernelPlan.readKernel(result.image))
            if (region == "ramdisk") java.io.RandomAccessFile(result.image, "r").use {
                it.seek(BootImageInspector.inspect(result.image).ramdiskOffset); assertEquals(91, it.read())
            }
            assertArrayEquals(before, changed.readBytes())
        }
    }

    @Test fun changedOwnedBytesRemainAnErrorInsteadOfFallingBack() {
        val f = input()
        val candidate = build(f, temporary.newFolder(), 7)
        val raw = UltraKernelPlan.readKernel(candidate.image).apply { this[1024] = 92 }
        val replacement = temporary.newFile().apply { writeBytes(KernelCompression.encode(raw, "GZIP")) }
        val changed = File(temporary.newFolder(), "owned-edit.img")
        BootImageRebuilder.rebuild(candidate.image, replacement, changed)
        val output = temporary.newFolder()
        val failure = assertThrows(IllegalArgumentException::class.java) {
            UltraKernelOriginalRecovery(assets).recover(changed,
                File(temporary.root, "no-receipts"), emptyList(), output, generatedOnly = true)
        }
        assertEquals("ULTRA_KERNEL_RECOVERY_CURRENT_MISMATCH", failure.message)
        assertTrue(output.listFiles().isNullOrEmpty())
    }


    private fun inputWithRecoveryMetadataLimit(spans: Boolean): Input {
        val f = input()
        val layout = BootImageInspector.inspect(f.image)
        val end = ((layout.ramdiskOffset + layout.ramdiskSize + 4095) / 4096) * 4096
        val auxiliary = if (spans) 3840L + 8193L * 8192 else 64L * 1024 * 1024 + 4096
        val metadataBytes = 256 + auxiliary
        val image = temporary.newFile()
        java.io.RandomAccessFile(image, "rw").use { file ->
            file.write(f.image.readBytes().copyOf(end.toInt()))
            file.setLength(end + metadataBytes + 65536 + 64)
            val header = ByteBuffer.allocate(256).order(ByteOrder.BIG_ENDIAN).apply {
                put("AVB0".toByteArray()); putLong(20, auxiliary)
            }.array()
            file.seek(end); file.write(header)
            if (spans) {
                val nonzero = ByteArray(4096) { 41 }
                repeat(8193) { file.seek(end + 4096 + it.toLong() * 8192); file.write(nonzero) }
            } else {
                val nonzero = ByteArray(64 * 1024) { 41 }
                file.seek(end + 256)
                var remaining = auxiliary
                while (remaining > 0) {
                    val count = minOf(remaining, nonzero.size.toLong()).toInt()
                    file.write(nonzero, 0, count); remaining -= count
                }
            }
            val footer = ByteBuffer.allocate(64).order(ByteOrder.BIG_ENDIAN).apply {
                put("AVBf".toByteArray()); putInt(4, 1)
                putLong(12, end); putLong(20, end); putLong(28, metadataBytes)
            }.array()
            file.seek(file.length() - 64); file.write(footer); file.fd.sync()
        }
        return Input(image, f.raw)
    }

    @Test fun optionalSnapshotByteAndSpanLimitsKeepBuildUsableWithoutSwallowingInvalidInputs() {
        for (spans in listOf(false, true)) {
            val f = inputWithRecoveryMetadataLimit(spans)
            val before = UltraKernelSpec.sha256(f.image)
            val candidate = build(f, temporary.newFolder(), 7)
            val receipt = receipt(candidate)
            assertEquals("KERNEL_WRITES_ONLY", receipt["recoveryCoverage"]!!.jsonPrimitive.content)
            assertEquals(if (spans) "BOOT_RECOVERY_SPAN_LIMIT" else "BOOT_RECOVERY_SNAPSHOT_SIZE_LIMIT",
                receipt["recoveryFallback"]!!.jsonPrimitive.content)
            assertEquals(before, UltraKernelSpec.sha256(f.image))
            assertNotNull(BootImageRebuilder.readRecoveryRecord(candidate.image))
        }
        val malformed = temporary.newFile().apply { writeBytes(ByteArray(8)) }
        val error = assertThrows(java.io.IOException::class.java) { BootImageRecovery.read(malformed) }
        assertEquals("BOOT_RECOVERY_SNAPSHOT_SIZE_LIMIT", error.message)
        assertFalse(error is BootImageRecovery.CapacityException)
    }


    private fun receiptBoundCandidate(input: Input, workspace: File): UltraKernelBuilder.Candidate {
        val credential = UltraKernelCredential.of("Aa1".repeat(16))
        val unbound = UltraKernelPlan.fromRecords(release,
            listOf(UltraKernelPlan.PatchRecord("opaque-data", 1024, ByteArray(48), credential.copySecret()),
                UltraKernelPlan.PatchRecord("opaque-path", 2048, ByteArray(UltraKernelCredential.INIT_PATH_FIELD),
                    credential.initPathField(UltraKernelCredential.INIT_PATH_FIELD))),
            credential, baseKernelSha256 = UltraKernelSpec.sha256(input.raw))
        val plan = unbound.withDerived(unbound.apply(input.raw).derived)
        val text = plan.specText(plan.credential)
        val asset = UltraKernelGeneratedAsset.of(plan, input.image.length(), 31, text)
        return UltraKernelBuilder(workspace).generate(input.image, asset, UltraKernelSpec.parse(text))
    }

    @Test fun completeReceiptUsesSavedFirstInputInsteadOfReencodingAwayItsPadding() {
        val f = input()
        val workspace = temporary.newFolder()
        val candidate = receiptBoundCandidate(f, workspace)
        val before = candidate.image.readBytes()
        assertEquals("FIRST_INPUT_EXACT", receipt(candidate)["recoveryCoverage"]!!.jsonPrimitive.content)
        val result = UltraKernelOriginalRecovery(assets).recover(candidate.image, workspace,
            emptyList(), temporary.newFolder())!!
        assertEquals(UltraKernelOriginalRecovery.Source.EXACT_SPEC_REVERSE, result.source)
        assertArrayEquals(f.image.readBytes(), result.image.readBytes())
        assertArrayEquals(before, candidate.image.readBytes())
        assertEquals(listOf(result.image.name), result.image.parentFile!!.listFiles()!!.map { it.name })
    }

    @Test fun savedFirstInputDoesNotOverrideAChangedReceiptOriginalDigest() {
        val f = input()
        val workspace = temporary.newFolder()
        val candidate = receiptBoundCandidate(f, workspace)
        val before = candidate.image.readBytes()
        val record = File(workspace, "candidate-generated-$release.json")
        val fields = Json.parseToJsonElement(record.readText()) as JsonObject
        record.writeText(kotlinx.serialization.json.buildJsonObject {
            fields.forEach { (key, value) -> put(key, value) }
            put("baseBootSha256", kotlinx.serialization.json.JsonPrimitive("0".repeat(64)))
        }.toString())
        val output = temporary.newFolder()
        assertNull(UltraKernelOriginalRecovery(assets).recover(candidate.image, workspace, emptyList(), output))
        assertArrayEquals(before, candidate.image.readBytes())
        assertFalse(output.walkTopDown().any { it.isFile && it.name == "original.img" && it.parentFile!!.name.startsWith("exact-recovery-") })
    }


    @Test fun signedCompleteReceiptReusesExactFirstInputAndRetainedUnsignedRecord() {
        val initial = input()
        val original = temporary.newFile().apply { writeBytes(initial.image.readBytes().copyOf(45056)) }
        val f = Input(original, initial.raw)
        val workspace = temporary.newFolder()
        val candidate = receiptBoundCandidate(f, workspace)
        val fixtureRoot = temporary.newFolder()
        java.util.zip.ZipFile("../image-core/src/test/resources/lenovo-avb-fixtures.zip").use { zip ->
            for (name in listOf("testkey_rsa2048.pem", "boot-SHA256_RSA2048.img", "vbmeta.img")) {
                zip.getInputStream(zip.getEntry(name)).use { source ->
                    File(fixtureRoot, name).outputStream().use { target -> source.copyTo(target) }
                }
            }
        }
        val key = dev.maplesu.image.LenovoAvbSigner.decodeKey(File(fixtureRoot, "testkey_rsa2048.pem").readBytes())
        val signed = dev.maplesu.image.LenovoAvbSigner.sign(dev.maplesu.image.LenovoAvbSigner.Mode.CHAINED, "boot", candidate.image,
            File(fixtureRoot, "boot-SHA256_RSA2048.img"), mapOf("vbmeta" to File(fixtureRoot, "vbmeta.img")),
            File(temporary.newFolder(), "signed"), { key }, {}).getValue("boot")
        val recovery = UltraKernelOriginalRecovery(assets)
        assertTrue(recovery.retainSignedCandidate(candidate.image, signed, workspace))
        val before = UltraKernelSpec.sha256(signed)
        val result = recovery.recover(signed, workspace, emptyList(), temporary.newFolder())!!
        assertEquals(UltraKernelOriginalRecovery.Source.EXACT_SPEC_REVERSE, result.source)
        assertArrayEquals(original.readBytes(), result.image.readBytes())
        assertEquals(before, UltraKernelSpec.sha256(signed))
    }

}
