package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.RamdiskInspector
import dev.maplesu.image.UltraInitBootProducer
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Actual namespace-binding seam and Producer; target resolver/Android PRE are separate tests. */
class UltraInitBootRepatchNamespaceTest {
    @get:Rule val temporary = TemporaryFolder()
    private val flow by lazy { UltraKernelFlow(temporary.newFolder(), UltraKernelMemoryAssets(emptyMap())) }

    @Test fun matchingNamespaceRepatchRetainsOriginalContainerAndKeyBytes() {
        val fixture = fixture()
        val bound = bind(fixture.installed, fixture.artifact, fixture.namespace)
            .withCredential(fixture.credential.copySecret())
        val next = File(temporary.newFolder(), "next.img")
        UltraInitBootProducer.produce(fixture.installed, next, bound)
        assertArrayEquals(fixture.namespace.record(), UltraInitBootProducer.readDeploymentNamespace(next))
        assertEquals(RamdiskInspector.inspect(fixture.installed).entry(".maplesu_ultra/credential").sha256,
            RamdiskInspector.inspect(next).entry(".maplesu_ultra/credential").sha256)
        val restored = File(temporary.newFolder(), "original.img")
        UltraInitBootProducer.restore(next, restored)
        assertArrayEquals(fixture.original.readBytes(), restored.readBytes())
    }

    @Test fun differentRecoveredNamespaceStopsBeforeSelectionMutation() {
        val fixture = fixture()
        val failure = runCatching { bind(fixture.installed, fixture.artifact,
            UltraKernelDeploymentNamespace.create()) }.exceptionOrNull()
        assertEquals("ULTRA_INIT_BOOT_DEPLOYMENT_NAMESPACE_CONFLICT", failure?.message)
        assertNull(UltraKernelFlow::class.java.getDeclaredField("selectedDeploymentNamespace")
            .apply { isAccessible = true }.get(flow))
        assertArrayEquals(fixture.namespace.record(), UltraInitBootProducer.readDeploymentNamespace(fixture.installed))
    }

    private fun bind(source: File, artifact: UltraInitBootProducer.Artifact,
                     recovered: UltraKernelDeploymentNamespace): UltraInitBootProducer.Artifact = try {
        UltraKernelFlow::class.java.getDeclaredMethod("withInitBootDeployment", File::class.java,
            UltraInitBootProducer.Artifact::class.java, UltraKernelDeploymentNamespace::class.java)
            .apply { isAccessible = true }.invoke(flow, source, artifact, recovered) as UltraInitBootProducer.Artifact
    } catch (wrapped: InvocationTargetException) { throw wrapped.targetException }

    private data class Fixture(val original: File, val installed: File, val artifact: UltraInitBootProducer.Artifact,
                               val namespace: UltraKernelDeploymentNamespace, val credential: UltraKernelCredential)

    private fun fixture(): Fixture {
        val directory = temporary.newFolder()
        val helpers = Class.forName("dev.maplesu.image.UltraInitBootProducerTest")
        fun bytes(name: String, vararg args: Any): ByteArray {
            val types = args.map { when (it) {
                is Boolean -> java.lang.Boolean.TYPE
                is Int -> java.lang.Integer.TYPE
                else -> it.javaClass
            } }.toTypedArray()
            return helpers.getDeclaredMethod(name, *types).apply { isAccessible = true }.invoke(null, *args) as ByteArray
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
            put("schemaVersion", 1); put("kernelRelease", "6.6.1-fixture")
            put("kernelSha256", UltraKernelSpec.sha256(kernel)); put("credentialMode", "module-parameter")
            put("metadataDisplacement", 4096 - 32)
            for ((field, path) in mapOf("targetBoot" to "target-boot.img", "handoff" to "ultra-init", "bridge" to "bridge.ko")) {
                put(field, path); put(field + "Sha256", UltraKernelSpec.sha256(files.getValue(path)))
            }
        }.toString())
        val artifact = UltraInitBootProducer.readArtifact(manifest)
        val namespace = UltraKernelDeploymentNamespace.create()
        val credential = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(artifact.metadataDisplacement)
        val original = File(directory, "original.img").also {
            it.writeBytes(bytes("image", ByteArray(0), bytes("stock", false, false)))
        }
        val installed = File(directory, "installed.img")
        val secret = credential.copySecret()
        try { UltraInitBootProducer.produce(original, installed,
            artifact.withDeploymentNamespace(namespace.record()).withCredential(secret)) }
        finally { secret.fill(0) }
        return Fixture(original, installed, artifact, namespace, credential)
    }
}
