package dev.maplesu.manager.parasite

import dev.maplesu.manager.workmode.Hashes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/** Web 资源打包约定：常量与生成脚本一致/必需路由/目录清单/缺失检测/不可用诚实。 */
class ParasiteWebAssetsTest {
    private fun tempDir(): File = Files.createTempDirectory("maplesu-parasite-web-").toFile()

    @Test
    fun constantsMatchPackagingScript() {
        assertEquals("parasite_web_assets", ParasiteWebAssets.BUNDLE_NAME)
        assertEquals("zip", ParasiteWebAssets.BUNDLE_FORMAT)
        assertEquals("parasite_web_assets_bundle.generated.h", ParasiteWebAssets.GENERATED_HEADER)
        assertTrue(ParasiteWebAssets.SOURCE_DIR.endsWith("parasite_app/web_assets/src"))
    }

    @Test
    fun expectedManifestHasRequiredRoutesAndFiles() {
        val manifest = ParasiteWebAssets.expectedManifest()
        assertEquals(ParasiteWebAssets.BUNDLE_NAME, manifest.bundleName)
        assertEquals("zip", manifest.bundleFormat)
        assertEquals(
            listOf("status", "authorizations", "backup", "restore", "detach"),
            manifest.routes,
        )
        assertEquals(listOf("index.html", "app.js", "styles.css"), manifest.entries.map { it.path })
        assertEquals("text/html", manifest.entries.first().mime)
    }

    @Test
    fun readFromDirectoryComputesShaSizesAndMimeSorted() {
        val root = tempDir()
        File(root, "index.html").writeText("<html>status</html>")
        File(root, "app.js").writeText("console.log('x')")
        File(root, "styles.css").writeText("body{}")
        File(root, "extra").mkdirs()
        File(root, "extra/icon.svg").writeText("<svg/>")
        val manifest = ParasiteWebAssets.readFromDirectory(root)
        assertEquals(
            listOf("app.js", "extra/icon.svg", "index.html", "styles.css"),
            manifest.entries.map { it.path },
        )
        val index = manifest.entries.first { it.path == "index.html" }
        assertEquals("<html>status</html>".toByteArray().size.toLong(), index.size)
        assertEquals(Hashes.sha256("<html>status</html>".toByteArray()), index.sha256)
        assertEquals("text/html", index.mime)
        assertEquals("image/svg+xml", manifest.entries.first { it.path.endsWith(".svg") }.mime)
        assertEquals(ParasiteWebAssets.REQUIRED_ROUTES, manifest.routes)
    }

    @Test
    fun verifyDirectoryDetectsMissingRequiredFiles() {
        val root = tempDir()
        File(root, "index.html").writeText("<html/>")
        val verification = ParasiteWebAssets.verifyDirectory(root)
        assertFalse(verification.ok)
        assertEquals(listOf("app.js", "styles.css"), verification.missing)

        File(root, "app.js").writeText("x")
        File(root, "styles.css").writeText("x")
        assertTrue(ParasiteWebAssets.verifyDirectory(root).ok)
    }

    @Test
    fun unavailableBundleIsHonest() {
        assertNull(UnavailableParasiteWebBundle.bytes())
        assertEquals(0, UnavailableParasiteWebBundle.size())
        assertEquals(ParasiteWebAssets.BUNDLE_NAME, UnavailableParasiteWebBundle.bundleName)
        assertEquals(ParasiteWebAssets.BUNDLE_FORMAT, UnavailableParasiteWebBundle.bundleFormat)
    }
}
