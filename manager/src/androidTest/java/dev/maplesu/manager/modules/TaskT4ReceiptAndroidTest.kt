package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.data.repository.ModuleRepositoryImpl
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.ModuleArchiveInspector.Report
import dev.maplesu.manager.runtime.MapleSuRuntime
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.Properties
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * T4: the structured receipt and the visible "unsupported" capability.
 *
 * A module that ships `system/` content is installable, but this backend never projects
 * it. The receipt has to say so (`unsupported`), every stage has to be represented
 * (`stages`), and the applied/failed properties have to be their own section - so
 * "installed" can never be read as "everything took effect".
 *
 * Opt-in: `-e verifyMapleSuBoot true`.
 */
class TaskT4ReceiptAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private data class Fixture(val id: String, val archive: File, val report: Report,
                               val receipt: File, val revision: File)

    private fun requireOptIn() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue("Requires the paired MapleSU boot runtime", MapleSuRuntime.refresh(context))
    }

    private fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"

    private fun root(command: String): List<String> = MapleSuRuntime.openShell(context).use { shell ->
        shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec().out
    }

    private fun properties(file: File): Properties =
        Properties().apply { file.inputStream().use { load(it) } }

    private fun simulatePreviousBoot(receipt: File) {
        val values = properties(receipt)
        values.setProperty("installedBootId", UUID.randomUUID().toString())
        receipt.outputStream().use { values.store(it, null) }
    }

    @Test(timeout = 180_000) fun receiptCarriesStagesPropsAndUnsupported() {
        requireOptIn()
        val id = "maplesu_t4_receipt_" + UUID.randomUUID().toString().replace("-", "")
        val archive = File.createTempFile("t4-receipt-", ".zip", context.cacheDir)
        ZipOutputStream(archive.outputStream()).use { output ->
            val files = mapOf(
                "module.prop" to "id=$id\nname=T4 receipt fixture\nversion=1\nversionCode=1\n" +
                    "author=MapleSU\ndescription=Receipt and capability fixture\n",
                "customize.sh" to "# receipt fixture\n",
                // SYSTEM_OVERLAY content: installable, but never projected (mount is
                // unsupported), which is exactly what the receipt has to disclose.
                "system/etc/hosts" to "127.0.0.1 maplesu-t4-probe\n",
                "system.prop" to "maplesu.t4.prop=delta\n",
            )
            files.forEach { (name, content) ->
                output.putNextEntry(ZipEntry(name)); output.write(content.toByteArray()); output.closeEntry()
            }
        }
        val report = ModuleArchiveInspector.inspect(archive)
        val key = MessageDigest.getInstance("SHA-256")
            .digest("${report.type}\n${report.id}\n${report.sha256}".toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        val revision = File(context.filesDir, "module-runtime/revisions/$key")
        val receipt = File(context.filesDir, "module-runtime/receipts/$key.properties")
        val fixture = Fixture(id, archive, report, receipt, revision)
        val backend = LiteScriptModuleBackend(context)
        val catalog = ModuleCatalog(File(context.filesDir, "module-catalog"))
        val out = mutableListOf<String>()
        val err = mutableListOf<String>()
        try {
            // (1) system/ content is installable (it used to be rejected or silently
            // ignored); the receipt is what carries the honesty.
            assertEquals((out + err).joinToString("\n"), 0,
                backend.install(archive, report, out::add, err::add).code)
            simulatePreviousBoot(receipt)
            backend.applySystemProperties(report, out::add, err::add)

            // (2) Receipt: every documented key present, single-line values.
            val values = properties(receipt)
            assertEquals("mount,zygisk,sepolicy-apply", values.getProperty("unsupported"))
            assertEquals("ok", values.getProperty("stage.install.status"))
            assertEquals("0", values.getProperty("stage.install.code"))
            assertNotNull(values.getProperty("stage.install.detail"))
            assertEquals("maplesu.t4.prop=delta", values.getProperty("props.applied"))
            assertEquals("", values.getProperty("props.failed"))
            values.stringPropertyNames().forEach { name ->
                assertFalse("receipt value for $name must be a single line",
                    values.getProperty(name).contains('\n'))
            }

            // (3) listJson carries the same facts for the UI.
            val listed = JSONArray(backend.listJson()).let { array ->
                (0 until array.length()).map { array.getJSONObject(it) }.single { it.getString("id") == id }
            }
            assertEquals("mount,zygisk,sepolicy-apply",
                listed.getJSONArray("unsupported").let { a -> (0 until a.length()).joinToString(",") { a.getString(it) } })
            assertEquals("ok", listed.getJSONObject("stages").getJSONObject("install").getString("status"))
            assertEquals(1, listed.getJSONObject("props").getJSONArray("applied").length())
            assertEquals(0, listed.getJSONObject("props").getJSONArray("failed").length())

            // (4) The UI model parses the same JSON through the production repository.
            val modules = runBlocking { ModuleRepositoryImpl().getModules() }.getOrThrow()
            val mine = modules.single { it.id == id }
            assertTrue("the module card must be able to say mount is unavailable: ${mine.unsupported}",
                mine.unsupported.contains("mount"))
            assertTrue(mine.propsApplied.contains("maplesu.t4.prop=delta"))

            // (5) The unsupported claim is not vacuous: the revision really does carry
            // system/ content that stays unprojected, and the mount table stayed clean.
            assertTrue("the fixture must actually ship system/ content",
                root("/system/bin/ls ${quote(File(revision, "system/etc").absolutePath)}").contains("hosts"))
            assertEquals(listOf("204"), root("/system/bin/wc -l < /proc/self/mountinfo"))
            assertEquals("0", root("/system/bin/grep -c maplesu /proc/self/mountinfo || true")
                .joinToString("").trim())

            println("MAPLESU_EVIDENCE task=T4 unsupported=mount,zygisk,sepolicy-apply " +
                "stages=install propsApplied=1 propsFailed=0 mountinfo=204")
        } finally {
            runCatching {
                root("/data/adb/maplesu/bin/resetprop -d maplesu.t4.prop >/dev/null 2>&1; true")
            }
            runCatching {
                assertEquals(context.filesDir.resolve("module-runtime/revisions").canonicalFile,
                    revision.parentFile.canonicalFile)
                ModuleTree.unlink(context, id, revision.absolutePath)
                root("rm -rf -- ${quote(revision.absolutePath)}")
            }
            runCatching {
                catalog.get(report.type, id)?.takeIf { it.report.sha256 == report.sha256 }
                    ?.let { catalog.uninstall(report.type, id) }
            }
            receipt.delete()
            archive.delete()
        }
        assertTrue("the probe property must be gone after cleanup",
            root("getprop maplesu.t4.prop").joinToString("").trim().isEmpty())
    }
}
