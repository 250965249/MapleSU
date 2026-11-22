package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * M09 measurement: what permissions a `customize.sh` module's files end up with.
 *
 * This is deliberately a *measurement*, not a pass/fail opinion about the contract:
 * the pinned installer applies `set_permissions` after `customize.sh` for modern
 * modules too, so a file the module created with an unusual mode tells us whether
 * that default pass runs here. The observed mode is printed either way.
 *
 * Opt-in: `-e verifyMapleSuBoot true`
 */
class ModulePermissionsAndroidTest {

    @Test(timeout = 120_000) fun customizeModuleRecordsEffectivePermissions() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("Requires the paired MapleSU boot runtime", MapleSuRuntime.refresh(context))
        val id = "maplesu_perm_fixture_${UUID.randomUUID().toString().replace("-", "")}"
        val archive = File.createTempFile("perm-module-", ".zip", context.cacheDir)
        ZipOutputStream(archive.outputStream()).use { output ->
            val files = mapOf(
                "module.prop" to "id=$id\nname=Permission fixture\nversion=1\nversionCode=1\n" +
                    "author=MapleSU\ndescription=Effective permission fixture\n",
                // Create two files with deliberately unusual modes and set no
                // permission at all, so the observed modes are whatever the backend
                // leaves behind.
                "customize.sh" to "printf 'loose\\n' > \"\$MODPATH/loose-file\"\n" +
                    "chmod 0777 \"\$MODPATH/loose-file\"\n" +
                    "printf 'tight\\n' > \"\$MODPATH/tight-file\"\n" +
                    "chmod 0600 \"\$MODPATH/tight-file\"\n" +
                    // Applies an *existing* type only: no rule is loaded and no policy
                    // is modified. This is the M05/M09 context-parameter contract.
                    "printf 'ctx\\n' > \"\$MODPATH/ctx-file\"\n" +
                    "set_perm \"\$MODPATH/ctx-file\" 0 0 0640 u:object_r:system_file:s0\n" +
                    "printf 'PERM:%s\\n' \"\$MODPATH\"\n",
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
        val key = MessageDigest.getInstance("SHA-256")
            .digest("${report.type}\n${report.id}\n${report.sha256}".toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        val revisionRoot = File(context.filesDir, "module-runtime/revisions")
        val revision = File(revisionRoot, key)
        fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
        fun root(command: String): List<String> = MapleSuRuntime.openShell(context).use { shell ->
            val result = shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec()
            assertTrue(result.err.joinToString("\n"), result.isSuccess)
            result.out
        }
        try {
            val installed = backend.install(archive, report, output::add, errors::add)
            assertEquals((output + errors).joinToString("\n"), 0, installed.code)
            val loose = root("stat -c '%u:%g:%a' ${quote(File(revision, "loose-file").absolutePath)}")
                .joinToString("").trim()
            val tight = root("stat -c '%u:%g:%a' ${quote(File(revision, "tight-file").absolutePath)}")
                .joinToString("").trim()
            val ctxFile = File(revision, "ctx-file")
            val ctxMode = root("stat -c '%u:%g:%a' ${quote(ctxFile.absolutePath)}").joinToString("").trim()
            val ctxLabel = root("/system/bin/ls -Z ${quote(ctxFile.absolutePath)}")
                .joinToString(" ").trim().split(Regex("\\s+")).firstOrNull().orEmpty()
            println("MAPLESU_PERM_EVIDENCE id=$id code=${installed.code} " +
                "loose(created0777)=$loose tight(created0600)=$tight " +
                "ctxAfterSetPerm=$ctxMode ctxLabel=$ctxLabel " +
                "standardPath=${ModuleTree.standardPath(id)}")
            // The record itself is the deliverable; only sanity-check that the files exist.
            assertTrue("loose file must exist", loose.isNotEmpty())
            // M05/M09: the 5th argument must apply an existing type, not abort.
            assertEquals("u:object_r:system_file:s0", ctxLabel)
        } finally {
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
