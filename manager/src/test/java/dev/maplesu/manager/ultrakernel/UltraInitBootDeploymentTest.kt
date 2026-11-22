package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.RamdiskInspector
import dev.maplesu.image.UltraInitBootProducer
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Real producer and typed namespace bytes only; no module, gateway or installation authority. */
class UltraInitBootDeploymentTest {
    @get:Rule val temporary = TemporaryFolder()
    private val credential = UltraKernelCredential.of("Aa1".repeat(16))

    @Test fun oneFlowReusesItsPublicNamespaceAcrossPreparationsAndCredentialChanges() {
        val input = fixture()
        val flow = flow()
        val first = build(flow, input.source, input.artifact)
        val original = namespace(first)
        val second = flow.prepareTarget(input.source, UltraKernelCredential.of("Bb2".repeat(16)), null, input.artifact)
        assertArrayEquals(original, namespace(requireNotNull(second.candidate).image))
        assertArrayEquals(original, namespace(first))
        val returnedCopy = namespace(first).apply { this[8] = 'Z'.code.toByte() }
        assertArrayEquals(original, namespace(first))
        assertEquals(24, returnedCopy.size)
        val entry = RamdiskInspector.inspect(first).entries.single { it.path == ".maplesu_ultra/deployment" }
        assertEquals(24L, entry.size)
        assertEquals(0x180, entry.permissions())
        assertEquals(UltraKernelSpec.sha256(original), entry.sha256)
    }

    @Test fun installedSourceWinsOverEarlierFreshPreviewAndSurvivesExactRestore() {
        val input = fixture()
        val installed = build(flow(), input.source, input.artifact)
        val original = namespace(installed)
        val retryFlow = flow()
        build(retryFlow, input.source, input.artifact)
        val upgrade = build(retryFlow, installed, input.artifact)
        assertArrayEquals(original, namespace(upgrade))
        assertArrayEquals(original, namespace(build(retryFlow, input.source, input.artifact)))
        assertFalse(UltraKernelFlow.initBootUpdateRequired(upgrade, input.artifact, credential))
        val restored = File(temporary.root, "exact-restored.img")
        UltraInitBootProducer.restore(upgrade, restored)
        assertArrayEquals(input.source.readBytes(), restored.readBytes())
    }

    @Test fun typedBootLineageHandoffWinsWhenInitBootHasNoRecord() {
        val input = fixture()
        val flow = flow()
        val record = UltraKernelDeploymentNamespace.create().record()
        val typed = UltraKernelDeploymentNamespace.decode(record)
        // The real HOST recovery consumers call this exact private boundary with their typed result.
        // This fixture covers that handoff, not boot inverse recovery or a separate Flow transfer.
        UltraKernelFlow::class.java.getDeclaredMethod("specGenerator", UltraKernelDeploymentNamespace::class.java)
            .apply { isAccessible = true }.invoke(flow, typed)
        assertArrayEquals(record, namespace(build(flow, input.source, input.artifact)))
    }

    @Test fun oldArtifactsKeepLegacyNewInstallsAndPreserveExistingSourceNamespace() {
        val old = fixture(support = false)
        val oldImage = build(flow(), old.source, old.artifact)
        assertFalse(old.artifact.supportsDeploymentNamespace)
        assertNull(UltraInitBootProducer.readDeploymentNamespace(oldImage))
        val current = fixture()
        val installed = build(flow(), current.source, current.artifact)
        val original = namespace(installed)
        val legacyUpgrade = build(flow(), installed, old.artifact)
        assertArrayEquals(original, namespace(legacyUpgrade))
        assertFalse(UltraKernelFlow.initBootUpdateRequired(legacyUpgrade, old.artifact, credential))
        assertTrue(UltraKernelFlow.initBootUpdateRequired(oldImage, current.artifact, credential))
    }

    @Test fun failedBindingDoesNotRotateTheFlowsAlreadySelectedNamespace() {
        val input = fixture()
        val flow = flow()
        val first = build(flow, input.source, input.artifact)
        val original = namespace(first)
        val rejected = fixture(pinnedHash = "0".repeat(64))
        val failure = runCatching { build(flow, input.source, rejected.artifact) }.exceptionOrNull()
        assertEquals("ULTRA_INIT_BOOT_CREDENTIAL_HASH", failure?.message)
        assertArrayEquals(original, namespace(build(flow, input.source, input.artifact)))
    }

    @Test fun identicalRepatchReportsAlreadyInstalledAfterFullProducerReadback() {
        val input = fixture()
        val flow = flow()
        val first = flow.prepareTarget(input.source, credential, null, input.artifact)
        assertFalse(first.alreadyInstalled)
        val installed = requireNotNull(first.candidate)
        val before = installed.image.readBytes()
        val repeated = flow.prepareTarget(installed.image, credential, null, input.artifact)
        assertTrue(repeated.alreadyInstalled)
        assertEquals(installed.bootSha256, requireNotNull(repeated.candidate).bootSha256)
        assertArrayEquals(before, installed.image.readBytes())
    }

    @Test fun corruptOwnedInputFailsBeforeAnyNamespaceReplacementOrCandidate() {
        val input = fixture()
        val installed = build(flow(), input.source, input.artifact)
        val bad = File(temporary.root, "damaged.img")
        val layout = BootImageInspector.inspect(installed)
        bad.writeBytes(installed.readBytes().apply {
            val at = layout.ramdiskOffset.toInt() + 128
            this[at] = (this[at].toInt() xor 1).toByte()
        })
        val before = bad.readBytes()
        val workspace = temporary.newFolder()
        val failure = runCatching { build(UltraKernelFlow(workspace, UltraKernelMemoryAssets(emptyMap())), bad, input.artifact) }
            .exceptionOrNull()
        assertEquals("ULTRA_INIT_BOOT_RECOVERY_CHECKSUM", failure?.message)
        assertTrue(workspace.listFiles().orEmpty().isEmpty())
        assertArrayEquals(before, bad.readBytes())
    }

    private fun flow() = UltraKernelFlow(temporary.newFolder(), UltraKernelMemoryAssets(emptyMap()))

    private fun build(flow: UltraKernelFlow, source: File, artifact: UltraInitBootProducer.Artifact): File =
        requireNotNull(flow.prepareTarget(source, credential, null, artifact).candidate).image

    private fun namespace(image: File): ByteArray =
        requireNotNull(UltraInitBootProducer.readDeploymentNamespace(image))

    private data class Fixture(val source: File, val artifact: UltraInitBootProducer.Artifact)

    private fun fixture(support: Boolean = true, pinnedHash: String? = null): Fixture {
        val directory = temporary.newFolder()
        val helpers = Class.forName("dev.maplesu.image.UltraInitBootProducerTest")
        fun bytes(name: String, vararg args: Any): ByteArray {
            val types = args.map { when (it) {
                is Boolean -> java.lang.Boolean.TYPE
                is Int -> java.lang.Integer.TYPE
                else -> it.javaClass
            } }.toTypedArray()
            return helpers.getDeclaredMethod(name, *types).apply { isAccessible = true }
                .invoke(null, *args) as ByteArray
        }
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
        val files = mapOf("target-boot.img" to bytes("image", kernel, ByteArray(0)),
            "ultra-init" to bytes("handoff"), "bridge.ko" to module)
        files.forEach { (name, content) -> File(directory, name).writeBytes(content) }
        val manifest = File(directory, "manifest.json")
        manifest.writeText(buildJsonObject {
            put("schemaVersion", 1)
            put("kernelRelease", "6.6.1-fixture")
            put("kernelSha256", UltraKernelSpec.sha256(kernel))
            put("credentialMode", "module-parameter")
            put("metadataDisplacement", 4096 - 32)
            pinnedHash?.let { put("credentialSha256", it) }
            for ((field, path) in mapOf("targetBoot" to "target-boot.img", "handoff" to "ultra-init", "bridge" to "bridge.ko")) {
                put(field, path)
                put(field + "Sha256", UltraKernelSpec.sha256(files.getValue(path)))
            }
        }.toString())
        val source = File(directory, "init_boot.img").also {
            it.writeBytes(bytes("image", ByteArray(0), bytes("stock", false, false)))
        }
        return Fixture(source, UltraInitBootProducer.readArtifact(manifest))
    }
}
