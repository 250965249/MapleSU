package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.LenovoAvbSigner
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.util.zip.ZipFile
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class UltraKernelSignedRecoveryTest {
    @get:Rule val temporary = TemporaryFolder()
    private val assets = UltraKernelMemoryAssets(emptyMap())
    private val recovery = UltraKernelOriginalRecovery(assets)
    private val release = "6.18.21-android17-signed-recovery-fixture"

    @Test fun rsaSignedContainerKeepsItsUnsignedReconstructionAndCompleteSpec() {
        val fixture = fixture()
        val before = UltraKernelSpec.sha256(fixture.receipt)
        assertNotEquals(fixture.candidate.bootSha256, UltraKernelSpec.sha256(fixture.signed))
        assertTrue(recovery.retainSignedCandidate(fixture.candidate.image, fixture.signed, fixture.workspace))
        assertNotNull(recovery.installedSpec(fixture.signed, fixture.workspace))
        assertArrayEquals(UltraKernelPlan.readKernel(fixture.base), recovery.generatedKernel(fixture.signed, fixture.workspace))
        val exact = recovery.recover(fixture.signed, fixture.workspace, emptyList(), temporary.newFolder())
        assertNotNull("signed boot must restore the exact original through its unsigned container", exact)
        assertEquals(UltraKernelSpec.sha256(fixture.base), UltraKernelSpec.sha256(exact!!.image))
        val generated = recovery.recover(fixture.signed, fixture.workspace, emptyList(), temporary.newFolder(), generatedOnly = true)
        assertNotNull("the actual generated-upgrade recovery must also pass its complete replay", generated)
        val copied = Json.parseToJsonElement(File(binding(fixture), fixture.receipt.name).readText()) as JsonObject
        assertEquals(fixture.candidate.bootSha256, copied.getValue("candidateBootSha256").jsonPrimitive.content)
        assertEquals(before, UltraKernelSpec.sha256(fixture.receipt))
    }

    @Test fun oldSignedDataMigratesOnlyFromItsCompleteRetainedCandidateAndSpec() {
        val fixture = fixture()
        val before = originals(fixture)
        assertNull(recovery.installedSpec(fixture.signed, fixture.workspace))
        assertTrue(recovery.retainPreviouslySignedCandidate(fixture.signed, fixture.workspace))
        assertNotNull(recovery.installedSpec(fixture.signed, fixture.workspace))
        assertEquals(before, originals(fixture))
    }

    @Test fun validBindingIsReusedAndDamagedDerivedBindingCanBeRebuilt() {
        val fixture = fixture()
        val before = originals(fixture)
        assertTrue(recovery.retainSignedCandidate(fixture.candidate.image, fixture.signed, fixture.workspace))
        val record = File(binding(fixture), "binding.json")
        assertTrue(record.setLastModified(1_600_000_000_000L))
        val modified = record.lastModified()
        assertTrue(recovery.retainSignedCandidate(fixture.candidate.image, fixture.signed, fixture.workspace))
        assertEquals(modified, record.lastModified())
        for (damaged in listOf("{", "{}")) {
            record.writeText(damaged)
            assertTrue(recovery.retainSignedCandidate(fixture.candidate.image, fixture.signed, fixture.workspace))
            assertNotNull(recovery.installedSpec(fixture.signed, fixture.workspace))
            assertEquals(before, originals(fixture))
        }
    }

    @Test fun previousSignedEntryRebuildsDamagedBindingFromItsCompleteOriginalProof() {
        val fixture = fixture()
        val before = originals(fixture)
        assertTrue(recovery.retainSignedCandidate(fixture.candidate.image, fixture.signed, fixture.workspace))
        File(binding(fixture), "binding.json").writeText("{")
        assertTrue(recovery.retainPreviouslySignedCandidate(fixture.signed, fixture.workspace))
        assertNotNull(recovery.installedSpec(fixture.signed, fixture.workspace))
        assertEquals(before, originals(fixture))
    }

    @Test fun retainedUnsignedAndHardLinkedProofFilesAreNotCopiedOntoThemselves() {
        val fixture = fixture()
        val before = originals(fixture)
        assertTrue(recovery.retainSignedCandidate(fixture.candidate.image, fixture.signed, fixture.workspace))
        val directory = binding(fixture)
        val retained = File(directory, "unsigned.img")
        val unsignedSha = UltraKernelSpec.sha256(retained)
        val alias = File(temporary.newFolder(), "unsigned-alias.img")
        Files.createLink(alias.toPath(), retained.toPath())
        for (source in listOf(fixture.receipt, fixture.spec)) {
            val target = File(directory, source.name)
            assertTrue(target.delete())
            Files.createLink(target.toPath(), source.toPath())
        }
        for (source in listOf(retained, alias)) {
            File(directory, "binding.json").writeText("{")
            assertTrue(recovery.retainSignedCandidate(source, fixture.signed, fixture.workspace))
            assertEquals(unsignedSha, UltraKernelSpec.sha256(source))
            assertEquals(unsignedSha, UltraKernelSpec.sha256(retained))
            assertEquals(before, originals(fixture))
        }
    }

    @Test fun damagedBindingDoesNotReplaceMissingOriginalReceiptProof() {
        val fixture = fixture()
        assertTrue(recovery.retainSignedCandidate(fixture.candidate.image, fixture.signed, fixture.workspace))
        val record = File(binding(fixture), "binding.json").apply { writeText("{") }
        fixture.receipt.appendText("changed")
        val before = originals(fixture)
        assertFalse(recovery.retainSignedCandidate(fixture.candidate.image, fixture.signed, fixture.workspace))
        assertFalse(recovery.retainPreviouslySignedCandidate(fixture.signed, fixture.workspace))
        assertEquals("{", record.readText())
        assertEquals(before, originals(fixture))
    }

    @Test fun pendingWriteFailureKeepsFailureAndOriginalInputs() {
        val fixture = fixture()
        val before = originals(fixture)
        assertTrue(recovery.retainSignedCandidate(fixture.candidate.image, fixture.signed, fixture.workspace))
        val directory = binding(fixture)
        val record = File(directory, "binding.json").apply { writeText("{") }
        assertTrue(File(directory, "binding.json.pending").mkdir())
        assertFalse(recovery.retainSignedCandidate(fixture.candidate.image, fixture.signed, fixture.workspace))
        assertEquals("{", record.readText())
        assertEquals(before, originals(fixture))
    }

    @Test fun missingUnsignedContainerOrChangedOriginalReceiptRejectsMigration() {
        val fixture = fixture()
        val bytes = fixture.candidate.image.readBytes()
        fixture.candidate.image.delete()
        assertFalse(recovery.retainPreviouslySignedCandidate(fixture.signed, fixture.workspace))
        fixture.candidate.image.writeBytes(bytes)
        fixture.receipt.appendText("changed")
        assertFalse(recovery.retainPreviouslySignedCandidate(fixture.signed, fixture.workspace))
    }

    @Test fun evenValidRsaSignaturesCannotSubstituteDifferentHeaderOrRamdiskBytes() {
        val fixture = fixture()
        for (offset in listOf(64, 12288)) {
            val changed = File(temporary.newFolder(), "changed.img")
            changed.writeBytes(fixture.candidate.image.readBytes().also { it[offset] = 1 })
            assertFalse(recovery.retainSignedCandidate(fixture.candidate.image, sign(changed), fixture.workspace))
        }
    }

    @Test fun signedReceiptProofRemainsRequiredWhileTheEmbeddedKernelInverseIsIndependent() {
        val fixture = fixture()
        assertTrue(recovery.retainSignedCandidate(fixture.candidate.image, fixture.signed, fixture.workspace))
        val directory = binding(fixture)
        val archived = listOf(File(directory, "unsigned.img"), File(directory, fixture.receipt.name),
            directory.listFiles()!!.single { it.extension == "spec" }, File(directory, "binding.json"), fixture.signed)
        for (file in archived) {
            val before = file.readBytes()
            file.writeBytes(before.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() })
            assertNull(file.name, recovery.installedSpec(fixture.signed, fixture.workspace))
            assertArrayEquals(file.name, UltraKernelPlan.readKernel(fixture.base),
                recovery.generatedKernel(fixture.signed, fixture.workspace))
            assertNull(file.name, recovery.recover(fixture.signed, fixture.workspace, emptyList(),
                File(temporary.root, "unproven-stock-${file.name}")))
            file.writeBytes(before)
        }
        assertNotNull(recovery.installedSpec(fixture.signed, fixture.workspace))
    }

    @Test fun signingAnAlreadySignedCandidateRetainsTheFirstUnsignedProof() {
        val fixture = fixture()
        assertTrue(recovery.retainSignedCandidate(fixture.candidate.image, fixture.signed, fixture.workspace))
        val signedAgain = sign(fixture.signed, "boot-SHA512_RSA2048.img")
        assertNotEquals(UltraKernelSpec.sha256(fixture.signed), UltraKernelSpec.sha256(signedAgain))
        assertTrue(recovery.retainSignedCandidate(fixture.signed, signedAgain, fixture.workspace))
        assertNotNull(recovery.recover(signedAgain, fixture.workspace, emptyList(), temporary.newFolder(), generatedOnly = true))
    }

    private fun originals(f: Fixture) = listOf(f.base, f.candidate.image, f.receipt, f.spec)
        .associate { it.absolutePath to UltraKernelSpec.sha256(it) }

    private fun binding(f: Fixture) = File(f.workspace, "signed-candidates/${UltraKernelSpec.sha256(f.signed)}")

    private fun sign(image: File, sourceName: String = "boot.img"): File {
        val key = LenovoAvbSigner.decodeKey(fixtureAsset("testkey_rsa2048.pem").readBytes())
        return LenovoAvbSigner.sign(LenovoAvbSigner.Mode.CHAINED, "boot", image, fixtureAsset(sourceName),
            mapOf("vbmeta" to fixtureAsset("vbmeta.img")), File(temporary.newFolder(), "signed"), { key }, {})
            .getValue("boot")
    }

    private fun fixtureAsset(name: String): File = File(temporary.root, name).apply {
        if (!exists()) ZipFile("../image-core/src/test/resources/lenovo-avb-fixtures.zip").use { zip ->
            zip.getInputStream(zip.getEntry(name)).use { input -> outputStream().use(input::copyTo) }
        }
    }

    private fun fixture(): Fixture {
        val directory = temporary.newFolder()
        val raw = ByteArray(8192).apply {
            "ARMd".toByteArray().copyInto(this, 56)
            "Linux version $release (fixture)".toByteArray().copyInto(this, 128)
        }
        val base = File(directory, "original.img")
        val bytes = ByteArray(16384)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("ANDROID!".toByteArray()); putInt(8, raw.size); putInt(12, 256); putInt(20, 1584); putInt(40, 4)
        }
        raw.copyInto(bytes, 4096)
        base.writeBytes(bytes)
        val identity = UltraKernelCredential.of("Aa1".repeat(16))
        val plan = UltraKernelPlan.fromRecords(release, listOf(
            UltraKernelPlan.PatchRecord("identity", 1024, ByteArray(48), identity.copySecret()),
            UltraKernelPlan.PatchRecord("path", 2048, ByteArray(UltraKernelCredential.INIT_PATH_FIELD),
                identity.initPathField(UltraKernelCredential.INIT_PATH_FIELD))), identity,
            baseKernelSha256 = UltraKernelSpec.sha256(raw)).let { it.withDerived(it.apply(raw).derived) }
        val text = plan.specText(identity)
        val asset = UltraKernelGeneratedAsset.of(plan, base.length(), 256, text)
        val workspace = File(directory, "work")
        val candidate = UltraKernelBuilder(workspace).generate(base, asset, UltraKernelSpec.parse(text))
        return Fixture(base, workspace, candidate, File(workspace, "candidate-${asset.id}.json"),
            File(workspace, "candidate-${asset.id}-${asset.specSha256}.spec"), sign(candidate.image))
    }

    private class Fixture(val base: File, val workspace: File, val candidate: UltraKernelBuilder.Candidate,
        val receipt: File, val spec: File, val signed: File)
}
