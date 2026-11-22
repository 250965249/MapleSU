package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * M04 acceptance: a legacy `install.sh` module.
 *
 * The legacy contract is not "run install.sh as a script". The pinned userspace
 * sources it (`installer.sh:392-410`) so the callbacks it defines exist, then calls
 * `print_modname`, `on_install`, applies the SKIPMOUNT/PROPFILE/POSTFSDATA/
 * LATESTARTSERVICE flags and finally runs `set_permissions`. This test asserts the
 * observable results of that sequence rather than the exit code alone: a created
 * file, the permission it received, and the `skip_mount` marker.
 *
 * Opt-in: `-e verifyMapleSuBoot true`
 */
class LegacyInstallAndroidTest {

    private val script = listOf(
        "ui_print() { printf '%s\\n' \"\$*\"; }",
        "set_perm() {",
        "    chown \"\$2:\$3\" \"\$1\" || return 1",
        "    chmod \"\$4\" \"\$1\" || return 1",
        "    return 0",
        "}",
        "print_modname() { ui_print \"- \$(grep_prop name)\"; }",
        "on_install() {",
        "    ui_print \"- legacy on_install\"",
        "    printf 'LEGACY:%s\\n' \"\$MODPATH\"",
        "    printf 'legacy-ok\\n' > \"\$MODPATH/legacy-marker\"",
        "    set_perm \"\$MODPATH/legacy-marker\" 0 0 0600",
        "    SKIPMOUNT=true",
        "}",
        "",
    ).joinToString("\n")

    @Test(timeout = 120_000) fun legacyInstallRunsCallbacksAndFlags() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("Requires the paired MapleSU boot runtime", MapleSuRuntime.refresh(context))
        val id = "maplesu_legacy_fixture_${UUID.randomUUID().toString().replace("-", "")}"
        val archive = File.createTempFile("legacy-module-", ".zip", context.cacheDir)
        ZipOutputStream(archive.outputStream()).use { output ->
            val files = mapOf(
                "module.prop" to "id=$id\nname=Legacy fixture\nversion=1\nversionCode=1\n" +
                    "author=MapleSU\ndescription=Legacy install.sh fixture\n",
                // A legacy module: no customize.sh, callbacks defined by install.sh.
                "install.sh" to script,
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
        fun listed() = JSONArray(backend.listJson()).let { array ->
            (0 until array.length()).map { array.getJSONObject(it) }.singleOrNull { it.getString("id") == id }
        }
        try {
            val installed = backend.install(archive, report, output::add, errors::add)
            assertEquals((output + errors).joinToString("\n"), 0, installed.code)

            // on_install must have actually run and written into the module tree.
            val marker = File(revision, "legacy-marker")
            assertEquals(listOf("legacy-ok"), root("cat ${quote(marker.absolutePath)}"))
            // set_perm from install.sh ran, but installer.sh applies the permission
            // pass *after* on_install. This fixture defines no `set_permissions`, so
            // the default recursive pass (0755 dirs / 0644 files) legitimately
            // overrides the 0600 that on_install set. Asserting 0644 pins that order;
            // a module needing a stricter mode must define its own set_permissions.
            assertEquals(listOf("0:0:644"), root("stat -c '%u:%g:%a' ${quote(marker.absolutePath)}"))
            // SKIPMOUNT=true set inside on_install must be honoured afterwards.
            assertTrue("skip_mount marker missing",
                File(revision, "skip_mount").let { file ->
                    root("test -f ${quote(file.absolutePath)}; echo \$?").joinToString("").trim() == "0"
                })
            assertTrue("the module must be listed as installed",
                listed()?.getString("runtimeStatus") == "installed")
            assertFalse("a legacy install must not claim a reboot requirement", installed.needsReboot)
            println("MAPLESU_LEGACY_EVIDENCE id=$id code=${installed.code} " +
                "markerMode=0:0:644 skipMount=true status=installed revision=${revision.absolutePath}")
        } finally {
            runCatching {
                assertTrue(revisionRoot.canonicalFile == revision.parentFile?.canonicalFile)
                root("rm -rf -- ${quote(revision.absolutePath)}")
                catalog.get(report.type, id)?.takeIf { it.report.sha256 == report.sha256 }
                    ?.let { catalog.uninstall(report.type, id) }
                File(context.filesDir, "module-runtime/receipts/$key.properties").delete()
            }
            archive.delete()
        }
    }
}
