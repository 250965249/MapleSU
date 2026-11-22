package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Opt-in: exercises actual authenticated root execution, never substitutes an existing su. */
class LiteScriptModuleAndroidTest {
    @Test(timeout = 90_000) fun installedLiteScriptHasRealActionsAndState() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("Requires the paired MapleSU boot runtime", MapleSuRuntime.refresh(context))
        val id = "maplesu_lite_fixture_${UUID.randomUUID().toString().replace("-", "")}" 
        val archive = File.createTempFile("lite-module-", ".zip", context.cacheDir)
        ZipOutputStream(archive.outputStream()).use { output ->
            val files = mapOf(
                "module.prop" to "id=$id\nname=Lite workflow fixture\nversion=1\nversionCode=1\nauthor=MapleSU\ndescription=Temporary script fixture\n",
                "customize.sh" to "printf '%s' \"\$MODPATH\" > \"\$MODPATH/customized-path\"\nset_perm \"\$MODPATH/customized-path\" 0 0 0644\nprintf 'CUSTOMIZE:%s\\n' \"\$MODPATH\"\n",
                // Lifecycle scripts get no MODPATH/MODDIR from the pinned KSU userspace:
                // module.rs:63-88 exports KSU_MODULE, PATH, ASH_STANDALONE and the
                // version fields only. The contract is "$0" = the script's absolute
                // path with cwd = its parent, so the fixture derives the directory the
                // way real modules do and prints "$0" to prove it.
                "action.sh" to "dir=\${0%/*}\nprintf 'ACTION:%s\\n' \"\$dir\"\nprintf 'SELF:%s\\n' \"\$0\"\nprintf 'ran\\n' >> \"\$dir/action-count\"\n",
            )
            files.forEach { (name, content) ->
                output.putNextEntry(ZipEntry(name)); output.write(content.toByteArray()); output.closeEntry()
            }
        }
        val report = ModuleArchiveInspector.inspect(archive)
        val backend = LiteScriptModuleBackend(context)
        val output = mutableListOf<String>()
        val errors = mutableListOf<String>()
        val catalog = ModuleCatalog(File(context.filesDir, "module-catalog"))
        val key = MessageDigest.getInstance("SHA-256").digest("${report.type}\n${report.id}\n${report.sha256}".toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        val revisionRoot = File(context.filesDir, "module-runtime/revisions")
        val revision = File(revisionRoot, key)
        fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
        fun root(command: String): List<String> = MapleSuRuntime.openShell(context).use { shell ->
            val result = shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec()
            assertTrue(result.err.joinToString("\n"), result.isSuccess)
            result.out
        }
        fun actionCount() = root("cat ${quote(File(revision, "action-count").absolutePath)}")
        fun listed(): JSONObject = JSONArray(backend.listJson()).let { array ->
            (0 until array.length()).map { array.getJSONObject(it) }.single { it.getString("id") == id }
        }
        try {
            val installed = backend.install(archive, report, output::add, errors::add)
            assertEquals((output + errors).joinToString("\n"), 0, installed.code)
            assertFalse(installed.needsReboot)
            assertEquals(revision.absolutePath, File(revision, "customized-path").readText())
            assertTrue(output.contains("CUSTOMIZE:${revision.absolutePath}"))
            assertEquals("installed", listed().getString("runtimeStatus"))
            assertTrue(listed().getBoolean("action"))
            assertEquals(0, backend.action(id, output::add, errors::add))
            assertTrue(output.contains("ACTION:${revision.absolutePath}"))
            // M13: "$0" must be the script's own absolute path, not the runner's.
            // A sourced script would report the runner here and break MODDIR=${0%/*}.
            assertTrue("action.sh must see its own path as \$0; output=${output.joinToString(" | ")}",
                output.contains("SELF:${File(revision, "action.sh").absolutePath}"))
            assertEquals(listOf("ran"), actionCount())
            assertEquals(listOf("0"), root("stat -c '%u' ${quote(File(revision, "action-count").absolutePath)}"))
            assertTrue(backend.setEnabled(id, false))
            assertFalse(listed().getBoolean("enabled"))
            assertTrue(runCatching { backend.action(id, output::add, errors::add) }.isFailure)
            assertEquals(listOf("ran"), actionCount())
            assertTrue(backend.setEnabled(id, true))
            assertTrue(listed().getBoolean("enabled"))
            assertEquals(0, backend.action(id, output::add, errors::add))
            assertEquals(listOf("ran", "ran"), actionCount())
            assertTrue(backend.markRemove(id, true))
            assertTrue(listed().getBoolean("remove"))
            assertEquals("remove_pending", listed().getString("runtimeStatus"))
            assertTrue(runCatching { backend.action(id, output::add, errors::add) }.isFailure)
            assertEquals(listOf("ran", "ran"), actionCount())
            assertTrue(backend.markRemove(id, false))
            assertFalse(listed().getBoolean("remove"))
            assertEquals("installed", listed().getString("runtimeStatus"))
            File(context.filesDir, "lite-module-result.json").writeText(JSONObject()
                .put("id", id).put("installed", true).put("actionExit", 0)
                .put("disabledActionRejected", true).put("removeMarkerVerified", true)
                .put("bootStageTested", false).toString())
        } finally {
            // Delete only this uniquely named fixture and its exact catalog revision.
            try {
                assertEquals(revisionRoot.canonicalFile, revision.parentFile.canonicalFile)
                root("rm -rf -- ${quote(revision.absolutePath)}")
                assertFalse(revision.exists())
                catalog.get(report.type, id)?.takeIf { it.report.sha256 == report.sha256 }?.let { catalog.uninstall(report.type, id) }
                File(context.filesDir, "module-runtime/receipts/$key.properties").delete()
            } finally { archive.delete() }
        }
    }
}
