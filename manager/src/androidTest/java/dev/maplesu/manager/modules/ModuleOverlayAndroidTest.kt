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
 * "No mount consumer" — the negative claim this backend is built on.
 *
 * A module's `system/` content must **never** be visible to a process running on this
 * device, and installing a module must not add a mount entry. That is not a missing
 * feature to be worked around later: it is the C2 invariant (zero mounts, mountinfo
 * stays at the baseline), and a global bind would satisfy visibility while failing it.
 *
 * The test therefore asserts the opposite of a projection:
 *  1. the module's `action.sh` cannot read the module's own `system/etc/hosts`;
 *  2. `/proc/self/mountinfo` keeps its baseline line count and contains no `maplesu`
 *     entry, from the Manager's own root shell.
 *
 * Opt-in: `-e verifyMapleSuBoot true`
 */
class ModuleOverlayAndroidTest {

    @Test(timeout = 180_000) fun moduleContentIsNeverProjected() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("Requires the paired MapleSU boot runtime", MapleSuRuntime.refresh(context))
        val id = "maplesu_mount_fixture_${UUID.randomUUID().toString().replace("-", "")}"
        val archive = File.createTempFile("mount-module-", ".zip", context.cacheDir)
        val action = """
            printf 'MARKER:%s\n' "$(head -n1 /system/etc/hosts 2>/dev/null || echo missing)"
            printf 'HOSTS_GREP:%s\n' "$(grep -c 'maplesu-mount-probe' /system/etc/hosts 2>/dev/null || true)"
        """.trimIndent() + "\n"
        ZipOutputStream(archive.outputStream()).use { output ->
            val files = mapOf(
                "module.prop" to "id=$id\nname=Mount isolation fixture\nversion=1\nversionCode=1\n" +
                    "author=MapleSU\ndescription=Module content must stay unprojected\n",
                "customize.sh" to "printf 'mount fixture installed\\n'\n",
                "action.sh" to action,
                // Content a mounting backend would have projected onto /system/etc/hosts.
                "system/etc/hosts" to "127.0.0.1 maplesu-mount-probe\n",
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
        fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
        fun root(command: String): List<String> = MapleSuRuntime.openShell(context).use { shell ->
            shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec().out
        }
        val out = mutableListOf<String>()
        val err = mutableListOf<String>()
        try {
            val mountsBefore = root("wc -l < /proc/self/mountinfo").joinToString("").trim()
            assertEquals("install must succeed: $out $err", 0,
                backend.install(archive, report, out::add, err::add).code)
            val helpers = File(context.filesDir, "module-runtime").listFiles()
                ?.joinToString(",") { it.name }.orEmpty()
            println("MAPLESU_MOUNT_SETUP installCode=0 helpers=${helpers.take(300)}")

            assertEquals(0, backend.action(id, out::add, err::add))
            val text = out.joinToString("\n")
            println("MAPLESU_MOUNT_EVIDENCE id=$id " +
                "marker=${out.firstOrNull { it.contains("MARKER:") }} " +
                "hostsGrep=${out.firstOrNull { it.contains("HOSTS_GREP:") }} mountsBefore=$mountsBefore")
            // The module's own hosts file must not be what the action reads.
            assertTrue("module content must NOT be visible; output=$text",
                !text.contains("MARKER:127.0.0.1 maplesu-mount-probe"))
            assertTrue("the action must see the platform hosts file, not the module copy; output=$text",
                !text.contains("HOSTS_GREP:1"))

            // C2: the mount table must not change and must not name this product.
            val mountsAfter = root("wc -l < /proc/self/mountinfo").joinToString("").trim()
            assertEquals("the mount table must not change; was $mountsBefore, now $mountsAfter",
                mountsBefore, mountsAfter)
            assertEquals("0", root("grep -c maplesu /proc/self/mountinfo || true")
                .joinToString("").trim())
        } finally {
            runCatching {
                assertEquals(revisionRoot.canonicalFile, revision.parentFile.canonicalFile)
                ModuleTree.unlink(context, id, revision.absolutePath)
                root("rm -rf -- ${quote(revision.absolutePath)}")
            }
            runCatching {
                catalog.get(report.type, id)?.takeIf { it.report.sha256 == report.sha256 }
                    ?.let { catalog.uninstall(report.type, id) }
            }
            File(context.filesDir, "module-runtime/receipts/$key.properties").delete()
            archive.delete()
        }
    }
}
