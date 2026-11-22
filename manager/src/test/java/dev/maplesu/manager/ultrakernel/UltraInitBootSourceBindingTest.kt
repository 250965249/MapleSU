package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageInspector
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

/** Real producer inverses prove only input lineage, not bridge loading or device compatibility. */
class UltraInitBootSourceBindingTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun exactCurrentBytesNeedNoSecondCapture() {
        val input = fixture()
        val installed = install(input)
        val result = UltraInitBootSourceBinding.requireSource(installed, installed.length(), sha(installed), temporary.root) {
            error("UNEXPECTED_CAPTURE")
        }
        assertNull(result)
    }

    @Test fun reselectedOriginalMatchesOnlyItsLiveOwnedInverseAndKeepsNamespace() {
        val input = fixture()
        val installed = install(input)
        val beforeSource = input.source.readBytes()
        val beforeInstalled = installed.readBytes()
        assertNotEquals(sha(input.source), sha(installed))
        var captures = 0
        val retained = UltraInitBootSourceBinding.requireSource(input.source, installed.length(), sha(installed), temporary.root) {
            captures++
            installed
        }
        assertEquals(1, captures)
        assertArrayEquals(UltraInitBootProducer.readDeploymentNamespace(installed), requireNotNull(retained).record())
        val next = UltraKernelFlow(temporary.newFolder(), UltraKernelMemoryAssets(emptyMap()))
            .prepareTarget(input.source, input.credential, null, input.artifact, retained)
        assertArrayEquals(retained.record(), UltraInitBootProducer.readDeploymentNamespace(requireNotNull(next.candidate).image))
        assertArrayEquals(beforeSource, input.source.readBytes())
        assertArrayEquals(beforeInstalled, installed.readBytes())
        assertTrue(temporary.root.listFiles().orEmpty().none { it.name.startsWith("init-boot-source-") })
    }

    @Test fun sameSizeAndReleaseDoNotAcceptAnotherOriginal() {
        val input = fixture()
        val installed = install(input)
        val foreign = File(temporary.root, "foreign.img").also {
            it.writeBytes(input.source.readBytes().apply { this[3000] = (this[3000].toInt() xor 1).toByte() })
        }
        val failure = runCatching {
            UltraInitBootSourceBinding.requireSource(foreign, installed.length(), sha(installed), temporary.root) { installed }
        }.exceptionOrNull()
        assertEquals("ULTRA_INIT_PAIRED_BOOT_SOURCE_MISMATCH", failure?.message)
    }

    @Test fun changedCurrentCaptureFailsBeforeInverseMatching() {
        val input = fixture()
        val installed = install(input)
        val failure = runCatching {
            UltraInitBootSourceBinding.requireSource(input.source, installed.length(), "0".repeat(64), temporary.root) { installed }
        }.exceptionOrNull()
        assertEquals("INSTALLER_IMAGE_CHANGED", failure?.message)
    }

    @Test fun corruptedOwnedRecoveryIsRejectedAndTemporaryFilesAreRemoved() {
        val input = fixture()
        val installed = install(input)
        val layout = BootImageInspector.inspect(installed)
        installed.writeBytes(installed.readBytes().apply {
            val at = layout.ramdiskOffset.toInt() + 128
            this[at] = (this[at].toInt() xor 1).toByte()
        })
        val failure = runCatching {
            UltraInitBootSourceBinding.requireSource(input.source, installed.length(), sha(installed), temporary.root) { installed }
        }.exceptionOrNull()
        assertEquals("ULTRA_INIT_BOOT_RECOVERY_CHECKSUM", failure?.message)
        assertTrue(temporary.root.listFiles().orEmpty().none { it.name.startsWith("init-boot-source-") })
    }

    @Test fun stockCurrentWithNoOwnedInverseDoesNotAuthorizeOtherInput() {
        val input = fixture()
        val foreign = File(temporary.root, "other.img").also {
            it.writeBytes(input.source.readBytes().apply { this[3000] = (this[3000].toInt() xor 1).toByte() })
        }
        val failure = runCatching {
            UltraInitBootSourceBinding.requireSource(foreign, input.source.length(), sha(input.source), temporary.root) { input.source }
        }.exceptionOrNull()
        assertEquals("ULTRA_INIT_BOOT_RECOVERY_MISSING", failure?.message)
    }

    private fun sha(file: File) = UltraKernelSpec.sha256(file)
    private fun install(input: Fixture): File = requireNotNull(
        UltraKernelFlow(temporary.newFolder(), UltraKernelMemoryAssets(emptyMap()))
            .prepareTarget(input.source, input.credential, null, input.artifact).candidate).image

    private data class Fixture(val source: File, val artifact: UltraInitBootProducer.Artifact,
                               val credential: UltraKernelCredential)

    private fun fixture(): Fixture {
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
        val header = ByteBuffer.wrap(module).order(ByteOrder.LITTLE_ENDIAN)
        val section = header.getLong(40).toInt() + 5 * header.getShort(58).toInt()
        val at = header.getLong(section + 24).toInt()
        val count = header.getLong(section + 32).toInt()
        val parameter = "parmtype=deployment_namespace:string\u0000".toByteArray(Charsets.US_ASCII)
        parameter.copyInto(module, at + count)
        header.putLong(section + 32, (count + parameter.size).toLong())
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
            for ((field, path) in mapOf("targetBoot" to "target-boot.img", "handoff" to "ultra-init", "bridge" to "bridge.ko")) {
                put(field, path)
                put(field + "Sha256", UltraKernelSpec.sha256(files.getValue(path)))
            }
        }.toString())
        val source = File(directory, "init_boot.img").also {
            it.writeBytes(bytes("image", ByteArray(0), bytes("stock", false, false)))
        }
        return Fixture(source, UltraInitBootProducer.readArtifact(manifest), UltraKernelCredential.of("Aa1".repeat(16)))
    }
}
