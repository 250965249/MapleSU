package dev.maplesu.manager.workmode.service

import dev.maplesu.image.UltraInitBootProducer
import dev.maplesu.manager.installer.BootPartitionSnapshot
import dev.maplesu.manager.installer.InstallerSnapshot
import dev.maplesu.manager.installer.StockOriginalResolver
import dev.maplesu.manager.ksu.KsuRootCommandRunner
import dev.maplesu.manager.ultrakernel.*
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.switch.CandidateInput
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Real inverse/CPIO/Flow boundaries, file-only; no root process, module or signing qualification. */
class RecoveredDeploymentLineageTest {
    @get:Rule val temporary = TemporaryFolder()
    private val assets = UltraKernelMemoryAssets(emptyMap())
    private val credential = UltraKernelCredential.of("Aa1".repeat(16))

    @Test fun bothOuterBootRecoveriesKeepCleanBaselinesWhileVerifiedPreCarriesLineage() {
        val f = fixture()
        val record = namespace('A')
        val receipts = temporary.newFolder()
        val raw = bytes("kernel")
        val plan = UltraKernelPlan.fromRecords("6.6.1-fixture", listOf(
            UltraKernelPlan.PatchRecord("credential", 1024, ByteArray(48), credential.copySecret()),
            UltraKernelPlan.PatchRecord("path", 2048, ByteArray(UltraKernelCredential.INIT_PATH_FIELD),
                credential.initPathField(UltraKernelCredential.INIT_PATH_FIELD)),
            UltraKernelPlan.PatchRecord("manager_claim:deployment_namespace", 3072, ByteArray(24), record.record())),
            credential, baseKernelSha256 = UltraKernelSpec.sha256(raw)).let { it.withDerived(it.apply(raw).derived) }
        val text = plan.specText(plan.credential)
        val asset = UltraKernelGeneratedAsset.of(plan, f.artifact.targetBoot.length(), 0, text)
        val compact = UltraKernelBuilder(receipts).generate(f.artifact.targetBoot, asset, UltraKernelSpec.parse(text)).image
        // Recovery consumes a fixed partition PRE, not the compact producer export.
        val installed = fullSizeSwitchCandidate(compact, File(temporary.newFolder(), "boot.img"),
            f.artifact.targetBoot.length())
        val before = installed.readBytes()
        val snapshot = InstallerSnapshot("6.6.1-fixture", "fixture", "_a", "Enforcing", mapOf("boot" to
            BootPartitionSnapshot("boot", "", "", installed.length(), UltraKernelSpec.sha256(installed))))
        val resolved = StockOriginalResolver(assets, receipts, listOf(f.artifact.targetBoot))
            .resolve(snapshot, mapOf("boot" to installed), temporary.newFolder())
        assertArrayEquals(raw, UltraKernelPlan.readKernel(resolved.originals.getValue("boot")))
        assertArrayEquals(f.artifact.targetBoot.readBytes(), resolved.originals.getValue("boot").readBytes())
        val recovered = ModeSwitchSourceRecovery(assets, receipts, listOf(f.artifact.targetBoot), "unused",
            KsuRootCommandRunner { _, _ -> error("unexpected ksud") }).recover(
                WorkMode.LITE, "boot", installed, temporary.newFolder(), true)
        assertTrue(recovered.detail, recovered.ok)
        assertArrayEquals(raw, UltraKernelPlan.readKernel(requireNotNull(recovered.image)))
        assertArrayEquals(f.artifact.targetBoot.readBytes(), requireNotNull(recovered.image).readBytes())
        val lineage = runBlocking {
            val input = CandidateInput("transaction", WorkMode.LITE, "init_boot", f.source,
                UltraKernelSpec.sha256(f.source), temporary.newFolder(), "", "6.6.1-fixture")
            ModeSwitchCandidateInput(assets, receipts).prepare(input,
                status(listOf(row("boot", installed), row("init_boot", f.source))),
                Captured(mapOf("boot" to installed, "init_boot" to f.source))).deploymentNamespace
        }
        assertArrayEquals(record.record(), requireNotNull(lineage).record())
        val candidate = build(f.source, f.artifact, lineage)
        assertArrayEquals(record.record(), UltraInitBootProducer.readDeploymentNamespace(candidate))
        assertArrayEquals(before, installed.readBytes())
    }

    @Test fun transactionPreExportsRestoreInitBootLineageIntoTheActualCandidateInput() = runBlocking {
        val f = fixture()
        val record = namespace('B')
        val installed = fullSizeSwitchCandidate(build(f.source, f.artifact, record),
            File(temporary.newFolder(), "init_boot.img"), f.source.length())
        val before = installed.readBytes()
        val recovery = ModeSwitchSourceRecovery(assets, temporary.newFolder(), emptyList(), "unused",
            KsuRootCommandRunner { _, _ -> error("unexpected ksud") }).recover(
                WorkMode.LITE, "init_boot", installed, temporary.newFolder(), true)
        assertTrue(recovery.detail, recovery.ok)
        val baseline = requireNotNull(recovery.image)
        assertArrayEquals(f.source.readBytes(), baseline.readBytes())
        assertNull(UltraInitBootProducer.readDeploymentNamespace(baseline))
        val work = temporary.newFolder()
        val input = CandidateInput("transaction", WorkMode.LITE, "init_boot", baseline,
            recovery.sha256, work, "", "6.6.1-fixture")
        val row = row("init_boot", installed)
        val status = status(listOf(row))
        val client = Captured(mapOf("init_boot" to installed))
        val prepared = ModeSwitchCandidateInput(assets, temporary.newFolder()).prepare(input, status, client)
        assertArrayEquals(record.record(), requireNotNull(prepared.deploymentNamespace).record())
        val candidate = build(prepared.baselineImage, f.artifact, prepared.deploymentNamespace)
        assertArrayEquals(record.record(), UltraInitBootProducer.readDeploymentNamespace(candidate))
        assertEquals(listOf("PRE:init_boot"), client.exports)
        assertTrue(work.listFiles().orEmpty().isEmpty())
        assertNull(input.deploymentNamespace)
        assertArrayEquals(before, installed.readBytes())
    }

    @Test fun conflictingOrChangedCapturedSourcesFailBeforeAnyCandidateAndKeepNoTemporaryExport() = runBlocking {
        val f = fixture()
        val first = build(f.source, f.artifact, namespace('C'))
        val second = build(f.source, f.artifact, namespace('D'))
        val rows = listOf(row("boot", first), row("init_boot", second))
        val work = temporary.newFolder()
        val reader = ModeSwitchCandidateInput(assets, temporary.newFolder())
        val conflict = runCatching { reader.readCaptured(rows, work) { name, destination ->
            (if (name == "boot") first else second).copyTo(destination, overwrite = true); true
        } }.exceptionOrNull()
        assertEquals("SOURCE_RECOVERY_DEPLOYMENT_CONFLICT", conflict?.message)
        assertTrue(work.listFiles().orEmpty().isEmpty())
        val changed = runCatching { reader.readCaptured(rows.take(1), work) { _, destination ->
            destination.writeBytes(first.readBytes().apply { this[0] = 0 }); true
        } }.exceptionOrNull()
        assertEquals("SOURCE_RECOVERY_PRE_IMAGE_CHANGED", changed?.message)
        assertTrue(work.listFiles().orEmpty().isEmpty())
        val firstError = java.io.IOException("EXPORT_FIRST_ERROR")
        val failedCleanup = runCatching { reader.readCaptured(rows.take(1), work) { _, destination ->
            java.nio.file.Files.delete(destination.toPath())
            check(destination.mkdir())
            File(destination, "held").writeText("fixture")
            throw firstError
        } }.exceptionOrNull()
        assertSame(firstError, failedCleanup)
        assertEquals(1, firstError.suppressed.size)
    }

    @Test fun knownLineageHasAnExplicitUnsupportedErrorWhileAnOwnedSourceWinsOverTheHint() {
        val f = fixture()
        val record = namespace('E')
        val installed = build(f.source, f.artifact, record)
        assertArrayEquals(record.record(), UltraInitBootProducer.readDeploymentNamespace(
            build(installed, f.artifact, namespace('F'))))
        val legacy = fixture(support = false)
        val work = temporary.newFolder()
        val failure = runCatching { UltraKernelFlow(work, assets).prepareTarget(legacy.source,
            credential, null, legacy.artifact, record) }.exceptionOrNull()
        assertEquals("ULTRA_KERNEL_DEPLOYMENT_SUPPORT_MISSING", failure?.message)
        assertTrue(work.listFiles().orEmpty().isEmpty())
    }

    private fun build(source: File, artifact: UltraInitBootProducer.Artifact,
                      record: UltraKernelDeploymentNamespace?): File =
        requireNotNull(UltraKernelFlow(temporary.newFolder(), assets)
            .prepareTarget(source, credential, null, artifact, record).candidate).image

    private fun namespace(name: Char) = UltraKernelDeploymentNamespace.decode(
        ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN).putInt(0x4e44534d)
            .putShort(1).putShort(24).put(ByteArray(16) { name.code.toByte() }).array())

    private fun row(name: String, image: File) = ClientPartition(name, "RESTORE_SOURCE", image.length(),
        UltraKernelSpec.sha256(image), "", "", "SNAPSHOT")

    private fun status(rows: List<ClientPartition>) = ClientStatus("transaction", "SNAPSHOT", "", "",
        "KSU", "LITE", "", "", "", false, false, false, false, 0, rows)

    private class Captured(private val images: Map<String, File>) : ModeSwitchClient {
        val exports = mutableListOf<String>()
        override suspend fun exportImage(switchId: String, kind: String, partition: String, destination: File): Boolean {
            check(switchId == "transaction" && kind == "PRE")
            exports += "$kind:$partition"
            images.getValue(partition).copyTo(destination, overwrite = true)
            return true
        }
        override suspend fun preflight(switchId: String, planFields: Map<String, String>): ClientResult = error("unexpected")
        override suspend fun begin(switchId: String, planFields: Map<String, String>, superuserJson: File, settingsMirrorJson: File): ClientResult = error("unexpected")
        override suspend fun snapshot(switchId: String): ClientResult = error("unexpected")
        override suspend fun submitCandidate(switchId: String, partition: String, candidate: File, candidateSha256: String): ClientResult = error("unexpected")
        override suspend fun commit(switchId: String): ClientResult = error("unexpected")
        override suspend fun rollback(switchId: String): ClientResult = error("unexpected")
        override suspend fun abort(switchId: String): ClientResult = error("unexpected")
        override fun status(switchId: String): ClientStatus? = error("unexpected")
        override suspend fun verify(switchId: String): ClientResult = error("unexpected")
        override suspend fun markRebootRequested(switchId: String): Boolean = error("unexpected")
        override suspend fun exportLog(switchId: String, destination: File): File? = error("unexpected")
    }

    private data class Fixture(val source: File, val artifact: UltraInitBootProducer.Artifact)

    private fun fixture(support: Boolean = true): Fixture {
        val directory = temporary.newFolder()
        val kernel = bytes("kernel")
        val module = bytes("parameterModule", 32)
        if (support) {
            val header = ByteBuffer.wrap(module).order(ByteOrder.LITTLE_ENDIAN)
            val section = header.getLong(40).toInt() + 5 * header.getShort(58).toInt()
            val at = header.getLong(section + 24).toInt()
            val count = header.getLong(section + 32).toInt()
            val parameter = "parmtype=deployment_namespace:string\u0000".toByteArray(Charsets.US_ASCII)
            parameter.copyInto(module, at + count)
            header.putLong(section + 32, (count + parameter.size).toLong())
        }
        val files = mapOf("target.img" to bytes("image", kernel, ByteArray(0)),
            "init" to bytes("handoff"), "bridge.ko" to module)
        files.forEach { (name, content) -> File(directory, name).writeBytes(content) }
        val manifest = File(directory, "manifest.json")
        manifest.writeText(buildJsonObject {
            put("schemaVersion", 1); put("kernelRelease", "6.6.1-fixture")
            put("kernelSha256", UltraKernelSpec.sha256(kernel))
            put("credentialMode", "module-parameter"); put("metadataDisplacement", 4064)
            for ((field, path) in mapOf("targetBoot" to "target.img", "handoff" to "init", "bridge" to "bridge.ko")) {
                put(field, path); put(field + "Sha256", UltraKernelSpec.sha256(files.getValue(path)))
            }
        }.toString())
        return Fixture(File(directory, "source.img").apply {
            writeBytes(bytes("image", ByteArray(0), bytes("stock", false, false)))
        }, UltraInitBootProducer.readArtifact(manifest))
    }

    private fun bytes(name: String, vararg args: Any): ByteArray {
        val types = args.map { when (it) {
            is Boolean -> java.lang.Boolean.TYPE
            is Int -> java.lang.Integer.TYPE
            else -> it.javaClass
        } }.toTypedArray()
        return Class.forName("dev.maplesu.image.UltraInitBootProducerTest").getDeclaredMethod(name, *types)
            .apply { isAccessible = true }.invoke(null, *args) as ByteArray
    }
}
