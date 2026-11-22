package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * M07 safety property: the standard `/data/adb/modules/<id>` path belongs to whoever
 * created it first.
 *
 * A module id is not a namespace MapleSU owns. If another manager already published
 * that path, installing our module must fail and leave the foreign entry untouched --
 * silently replacing it would let a MapleSU install break an unrelated module.
 *
 * Opt-in: `-e verifyMapleSuBoot true`
 */
class ModuleTreeAndroidTest {

    @Test(timeout = 180_000) fun foreignStandardPathIsNeverOverwritten() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("Requires the paired MapleSU boot runtime", MapleSuRuntime.refresh(context))
        val id = "maplesu_tree_fixture_${UUID.randomUUID().toString().replace("-", "")}"
        val archive = File.createTempFile("tree-module-", ".zip", context.cacheDir)
        ZipOutputStream(archive.outputStream()).use { output ->
            val files = mapOf(
                "module.prop" to "id=$id\nname=Tree fixture\nversion=1\nversionCode=1\n" +
                    "author=MapleSU\ndescription=Standard path fixture\n",
                "customize.sh" to "printf 'TREE:%s\\n' \"\$MODPATH\"\n",
            )
            files.forEach { (name, content) ->
                output.putNextEntry(ZipEntry(name)); output.write(content.toByteArray()); output.closeEntry()
            }
        }
        val report = ModuleArchiveInspector.inspect(archive)
        val backend = LiteScriptModuleBackend(context)
        val catalog = ModuleCatalog(File(context.filesDir, "module-catalog"))
        val key = MessageDigest.getInstance("SHA-256")
            .digest("${report.type}\n${report.id}\n${report.sha256}".toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        val revisionRoot = File(context.filesDir, "module-runtime/revisions")
        val revision = File(revisionRoot, key)
        val standard = ModuleTree.standardPath(id)
        val foreignTarget = "/data/local/tmp/maplesu-foreign-$id"
        fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
        fun root(command: String): List<String> = MapleSuRuntime.openShell(context).use { shell ->
            val result = shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec()
            assertTrue(result.err.joinToString("\n"), result.isSuccess)
            result.out
        }
        try {
            // 1) Simulate another manager owning this id.
            root("mkdir -p ${quote(foreignTarget)} && ln -sfn ${quote(foreignTarget)} ${quote(standard)}")
            assertEquals(listOf(foreignTarget), root("readlink ${quote(standard)}"))

            val out1 = mutableListOf<String>()
            val err1 = mutableListOf<String>()
            val blocked = backend.install(archive, report, out1::add, err1::add)
            println("MAPLESU_TREE_EVIDENCE conflictInstall code=${blocked.code} " +
                "stderr=${quote(err1.joinToString(" | "))}")
            assertNotEquals("a foreign standard path must block the install", 0, blocked.code)
            assertTrue("the conflict reason must be reported; stderr=${err1.joinToString(" | ")}",
                (out1 + err1).joinToString(" ").contains("MODULE_TREE_CONFLICT"))
            // The foreign entry must be byte-for-byte unchanged.
            assertEquals("the foreign link must not be replaced",
                listOf(foreignTarget), root("readlink ${quote(standard)}"))

            // 2) Remove the foreign entry and confirm a normal install publishes ours.
            root("rm -f ${quote(standard)} && rmdir ${quote(foreignTarget)} 2>/dev/null || true")
            val out2 = mutableListOf<String>()
            val err2 = mutableListOf<String>()
            val installed = backend.install(archive, report, out2::add, err2::add)
            assertEquals((out2 + err2).joinToString("\n"), 0, installed.code)
            val published = root("readlink ${quote(standard)}").joinToString("").trim()
            println("MAPLESU_TREE_EVIDENCE normalInstall code=${installed.code} " +
                "standardTarget=$published revision=${revision.absolutePath}")
            assertEquals("our install must point at our revision", revision.absolutePath, published)
        } finally {
            runCatching { root("rm -f ${quote(standard)}") }
            runCatching { root("rmdir ${quote(foreignTarget)} 2>/dev/null || true") }
            runCatching {
                assertTrue(revisionRoot.canonicalFile == revision.parentFile?.canonicalFile)
                ModuleTree.unlink(context, id, revision.absolutePath)
                root("rm -rf -- ${quote(revision.absolutePath)}")
                catalog.get(report.type, id)?.takeIf { it.report.sha256 == report.sha256 }
                    ?.let { catalog.uninstall(report.type, id) }
                File(context.filesDir, "module-runtime/receipts/$key.properties").delete()
            }
            archive.delete()
        }
    }
}
