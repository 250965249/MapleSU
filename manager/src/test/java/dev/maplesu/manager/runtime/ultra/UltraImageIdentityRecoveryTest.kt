package dev.maplesu.manager.runtime.ultra

import java.io.File
import java.nio.file.Files
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

class UltraImageIdentityRecoveryTest {
    @Test fun onlyKnownPrivateImagesAreListedInRuntimeThenNewestCandidateOrder() {
        val root = Files.createTempDirectory("ultra-image-keys").toFile()
        try {
            fun image(path: String) = File(root, path).apply { requireNotNull(parentFile).mkdirs(); writeText("fixture") }
            val imported = image("images/imported.img")
            val current = image("ultra-flash/boot-current.img")
            val old = image("ultra-flash/candidate-old.img").apply { setLastModified(1000) }
            val recent = image("ultra-flash/candidate-recent.img").apply { setLastModified(2000) }
            image("ultra-flash/candidate-old.json")
            image("ultra-flash/original.img")
            image("images/unrelated.img")
            image("unrelated/candidate-secret.img")
            assertEquals(listOf(imported, current, recent, old), UltraImageIdentityRecovery.images(root))
        } finally { root.deleteRecursively() }
    }

    @Test fun missingAndMalformedImagesDoNotReachNativeExtraction() {
        val root = Files.createTempDirectory("ultra-image-keys").toFile()
        try {
            assertTrue(UltraImageIdentityRecovery.candidates(root) { error("no image") }.none())
            File(root, "ultra-flash").mkdirs()
            File(root, "ultra-flash/candidate-broken.img").writeText("not a boot image")
            assertTrue(UltraImageIdentityRecovery.candidates(root) { error("invalid image") }.none())
        } finally { root.deleteRecursively() }
    }

    @Test fun productionDecodeAndLazyFallbackFeedOnlyLiveVerifiedIdentity() {
        val supplied = System.getProperty("maplesu.test.recovery.image")
        assumeTrue("host integration fixture supplied by test runner", supplied != null)
        val root = Files.createTempDirectory("ultra-image-keys").toFile()
        try {
            File(root, "images").mkdirs()
            File(requireNotNull(supplied)).copyTo(File(root, "images/imported.img"))
            val key = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(4096)
                .copySecret().toString(Charsets.US_ASCII)
            for (rootUid in listOf(10500, 0)) {
                var buffer: ByteArray? = null
                var saved: String? = null
                var maintained = false
                val candidates = UltraImageIdentityRecovery.candidates(root) { kernel ->
                    assertEquals("ARMd", kernel.copyOfRange(56, 60).toString(Charsets.US_ASCII))
                    buffer = kernel
                    listOf(key)
                }
                assertNull("decoding is lazy", buffer)
                val result = UltraIdentityResolution.recover(object : UltraIdentityResolution.Port {
                    override fun currentKey() = saved
                    override fun blocked() = false
                    override fun bootId() = "test-boot"
                    override fun rootUid(key: String) = rootUid
                    override fun brokerKey(): String? = null
                    override fun backupKey(): String? = null
                    override fun imageKeys() = candidates
                    override fun store(expected: String?, key: String): Boolean { saved = key; return true }
                    override fun accepted(key: String) { maintained = true }
                })
                assertEquals(if (rootUid == 0) "RECOVERED" else "RECOVERY_ROOT_NOT_VERIFIED", result)
                assertEquals(if (rootUid == 0) key else null, saved)
                assertEquals(rootUid == 0, maintained)
                assertTrue("decoded bytes are cleared before live proof", requireNotNull(buffer).all { it == 0.toByte() })
            }
        } finally { root.deleteRecursively() }
    }
}
