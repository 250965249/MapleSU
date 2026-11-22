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
 * M05: the installer helpers the pinned packages actually call.
 *
 * Measured offline from the three fixed ZIPs: `grep_prop` and `check_sepolicy` are
 * both expected from the installer, and neither existed in `runner.sh` before. This
 * test drives them from a real `customize.sh` and asserts their observable results,
 * including that `check_sepolicy` rejects a malformed rule file (a checker that
 * always returns 0 would be worse than none).
 *
 * Opt-in: `-e verifyMapleSuBoot true`
 */
class ModuleHelpersAndroidTest {

    @Test(timeout = 120_000) fun installerHelpersAreUsableFromCustomize() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("Requires the paired MapleSU boot runtime", MapleSuRuntime.refresh(context))
        val id = "maplesu_helper_fixture_${UUID.randomUUID().toString().replace("-", "")}"
        val archive = File.createTempFile("helper-module-", ".zip", context.cacheDir)
        val customize = """
            printf 'GREP:%s\n' "$(grep_prop name)"
            printf 'GREPV:%s\n' "$(grep_prop version)"
            printf 'BOGUS:%s\n' "$(grep_prop no_such_key)"
            if [ -f "${'$'}TMPDIR/module.prop" ]; then printf 'TMPPROP:1\n'; else printf 'TMPPROP:0\n'; fi
            printf 'GREPTMP:%s\n' "$(grep_prop version "${'$'}TMPDIR/module.prop")"
            printf 'type maple_policy_helper_t;\n' > "${'$'}TMPDIR/good.rule"
            if check_sepolicy "${'$'}TMPDIR/good.rule"; then printf 'CHECK_GOOD:0\n'; else printf 'CHECK_GOOD:1\n'; fi
            printf 'this is not a policy rule at all\n' > "${'$'}TMPDIR/bad.rule"
            if check_sepolicy "${'$'}TMPDIR/bad.rule"; then printf 'CHECK_BAD:0\n'; else printf 'CHECK_BAD:1\n'; fi
        """.trimIndent() + "\n"
        ZipOutputStream(archive.outputStream()).use { output ->
            val files = mapOf(
                "module.prop" to "id=$id\nname=Helper fixture\nversion=9.9\nversionCode=99\n" +
                    "author=MapleSU\ndescription=Installer helper fixture\n",
                "customize.sh" to customize,
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
            val text = output.joinToString("\n")
            println("MAPLESU_HELPER_EVIDENCE id=$id code=${installed.code} " +
                "grepName=${text.lineSequence().firstOrNull { it.startsWith("GREP:") }} " +
                "grepVersion=${text.lineSequence().firstOrNull { it.startsWith("GREPV:") }} " +
                "bogusEmpty=${text.contains("BOGUS:")} " +
                "tmpProp=${text.lineSequence().firstOrNull { it.startsWith("TMPPROP:") }} " +
                "grepTmp=${text.lineSequence().firstOrNull { it.startsWith("GREPTMP:") }} " +
                "checkGood=${text.lineSequence().firstOrNull { it.startsWith("CHECK_GOOD:") }} " +
                "checkBad=${text.lineSequence().firstOrNull { it.startsWith("CHECK_BAD:") }}")
            assertTrue("grep_prop must read module.prop; output=$text", text.contains("GREP:Helper fixture"))
            assertTrue("grep_prop must read version; output=$text", text.contains("GREPV:9.9"))
            assertTrue("grep_prop must stay empty for a missing key; output=$text", text.contains("BOGUS:\n") || text.endsWith("BOGUS:"))
            // KSU stages module.prop into TMPDIR before customize.sh, and real modules
            // read it there (TEESimulator does exactly this).
            assertTrue("module.prop must be staged in TMPDIR; output=$text", text.contains("TMPPROP:1"))
            assertTrue("grep_prop must read the TMPDIR copy; output=$text", text.contains("GREPTMP:9.9"))
            assertTrue("a valid rule must pass the checker; output=$text", text.contains("CHECK_GOOD:0"))
            // A checker that always succeeds would be worse than no checker.
            assertTrue("a malformed rule must be rejected; output=$text", text.contains("CHECK_BAD:1"))
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
