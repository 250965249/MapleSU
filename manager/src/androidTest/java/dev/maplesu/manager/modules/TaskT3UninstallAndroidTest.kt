package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.ModuleArchiveInspector.Report
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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
 * T3: the `remove` lifecycle.
 *
 * Contract: `markRemove(true)` writes a marker; the **next** boot runs `uninstall.sh`
 * (KSU `module.rs:423-479`, `prune_modules`) and only then removes the revision, the
 * standard path and the catalog record. Like KSU, hook failures are recorded while
 * pruning continues, and uninstalling one module must never touch another.
 *
 * Opt-in: `-e verifyMapleSuBoot true`.
 */
class TaskT3UninstallAndroidTest {
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

    private fun treeExists(fixture: Fixture): Boolean {
        val path = quote(ModuleTree.standardPath(fixture.id))
        return root("if [ -e $path ] || [ -L $path ]; then echo present; else echo absent; fi") == listOf("present")
    }

    private fun properties(file: File): Properties =
        Properties().apply { file.inputStream().use { load(it) } }

    private fun fixture(id: String, uninstall: String?): Fixture {
        val archive = File.createTempFile("t3-uninstall-", ".zip", context.cacheDir)
        ZipOutputStream(archive.outputStream()).use { output ->
            val files = linkedMapOf(
                "module.prop" to "id=$id\nname=T3 uninstall fixture\nversion=1\nversionCode=1\n" +
                    "author=MapleSU\ndescription=Uninstall lifecycle fixture\n",
                "customize.sh" to "# uninstall lifecycle fixture\n",
            )
            uninstall?.let { files["uninstall.sh"] = it }
            files.forEach { (name, content) ->
                output.putNextEntry(ZipEntry(name)); output.write(content.toByteArray()); output.closeEntry()
            }
        }
        val report = ModuleArchiveInspector.inspect(archive)
        val key = MessageDigest.getInstance("SHA-256")
            .digest("${report.type}\n${report.id}\n${report.sha256}".toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        return Fixture(id, archive, report,
            File(context.filesDir, "module-runtime/receipts/$key.properties"),
            File(context.filesDir, "module-runtime/revisions/$key"))
    }

    /**
     * `markRemove` records the request against the boot it happened in, so the uninstall
     * correctly waits for the next boot. The test moves both ids back one boot so the
     * scheduler sees a pending removal from a previous boot.
     */
    private fun simulateNextBoot(receipt: File) {
        val values = properties(receipt)
        val previous = UUID.randomUUID().toString()
        if (values.getProperty("installedBootId") != null) values.setProperty("installedBootId", previous)
        if (values.getProperty("removeRequestedBootId") != null) values.setProperty("removeRequestedBootId", previous)
        receipt.outputStream().use { values.store(it, null) }
    }

    private fun install(fixture: Fixture, backend: LiteScriptModuleBackend,
                        out: MutableList<String>, err: MutableList<String>) {
        assertEquals((out + err).joinToString("\n"), 0,
            backend.install(fixture.archive, fixture.report, out::add, err::add).code)
    }

    private fun teardown(fixture: Fixture, catalog: ModuleCatalog) {
        runCatching {
            assertEquals(context.filesDir.resolve("module-runtime/revisions").canonicalFile,
                fixture.revision.parentFile.canonicalFile)
            ModuleTree.unlink(context, fixture.id, fixture.revision.absolutePath)
            root("rm -rf -- ${quote(fixture.revision.absolutePath)}")
            val trees = RootModuleTree(ModuleScriptRunner { command ->
                MapleSuRuntime.openShell(context).use { shell ->
                    val result = shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec()
                    ModuleScriptOutput(result.code, result.out.joinToString("\n"), result.err.joinToString("\n"))
                }
            })
            val state = trees.snapshot(listOf(fixture.id)).getValue(fixture.id)
            if (state.directory) trees.remove(fixture.id, state.revision,
                state.metadata?.toByteArray()?.let { bytes -> MessageDigest.getInstance("SHA-256").digest(bytes)
                    .joinToString("") { "%02x".format(it.toInt() and 255) } }, state.identity)
        }
        runCatching {
            catalog.get(fixture.report.type, fixture.id)?.let { catalog.uninstall(fixture.report.type, fixture.id) }
        }
        fixture.receipt.delete()
        fixture.archive.delete()
    }

    @Test(timeout = 240_000) fun uninstallRunsScriptThenRemovesOnlyThatModule() {
        requireOptIn()
        val suffix = UUID.randomUUID().toString().replace("-", "")
        val marker = "/data/local/tmp/maplesu-t3-$suffix.log"
        val ok = fixture("maplesu_t3_ok_$suffix",
            "#!/system/bin/sh\n/system/bin/printf 'A\\n' >> ${quote(marker)}\n")
        val plain = fixture("maplesu_t3_plain_$suffix", null)
        val failing = fixture("maplesu_t3_fail_$suffix",
            "#!/system/bin/sh\n/system/bin/printf 'C\\n' >> ${quote(marker)}\n" +
                "/system/bin/printf 'overlay is required\\n' >&2\nexit 3\n")
        val backend = LiteScriptModuleBackend(context)
        val catalog = ModuleCatalog(File(context.filesDir, "module-catalog"))
        val out = mutableListOf<String>()
        val err = mutableListOf<String>()
        try {
            root("rm -f ${quote(marker)} && true")
            listOf(ok, plain, failing).forEach { install(it, backend, out, err) }

            assertTrue(backend.markRemove(ok.id, true))
            assertTrue(backend.markRemove(failing.id, true))
            assertEquals("remove_pending", listJson(backend, ok.id).getString("runtimeStatus"))

            simulateNextBoot(ok.receipt)
            simulateNextBoot(failing.receipt)
            val tasks = backend.prepareBootTasks()
            val okTask = tasks.single { it.id == ok.id && it.stage == "uninstall" }
            val failingTask = tasks.single { it.id == failing.id && it.stage == "uninstall" }
            assertFalse("a module that is not pending removal must not get an uninstall task",
                tasks.any { it.id == plain.id && it.stage == "uninstall" })

            // (1) Successful removal.
            backend.runBootTask(okTask, out::add, err::add)
            val markerLines = root("/system/bin/cat ${quote(marker)}").filter { it.isNotBlank() }
            assertTrue("uninstall.sh must have run: $markerLines", markerLines.contains("A"))
            assertFalse("the standard module tree must be gone", treeExists(ok))
            assertNull("the catalog entry must be gone", catalog.get(ok.report.type, ok.id))
            assertEquals("the standard path must be gone",
                listOf("absent"), root("if [ -e ${quote("/data/adb/modules/${ok.id}")} ] || [ -L ${quote("/data/adb/modules/${ok.id}")} ]; " +
                    "then echo present; else echo absent; fi"))
            // T3: the receipt survives as the durable final state.
            assertTrue("the uninstall receipt must survive as a tombstone", ok.receipt.isFile)
            val okReceipt = properties(ok.receipt)
            assertEquals("ok", okReceipt.getProperty("stage.uninstall.status"))
            assertEquals("0", okReceipt.getProperty("stage.uninstall.code"))

            // (2) A hook failure is recorded but does not veto the user's removal.
            backend.runBootTask(failingTask, out::add, err::add)
            assertTrue("the failing uninstaller must have run",
                root("/system/bin/cat ${quote(marker)}").contains("C"))
            assertFalse("a failed hook must still remove the module tree", treeExists(failing))
            assertNull("a failed hook must still remove the catalog entry",
                catalog.get(failing.report.type, failing.id))
            val failedReceipt = properties(failing.receipt)
            assertEquals("failed", failedReceipt.getProperty("stage.uninstall.status"))
            assertEquals("3", failedReceipt.getProperty("stage.uninstall.code"))
            assertTrue("the failure reason must be recorded: " +
                failedReceipt.getProperty("stage.uninstall.detail"),
                failedReceipt.getProperty("stage.uninstall.detail").orEmpty().contains("overlay is required"))
            assertFalse(JSONArray(backend.listJson()).let { array ->
                (0 until array.length()).any { array.getJSONObject(it).getString("id") == failing.id }
            })

            // (3) Re-running the scheduler after a successful uninstall must not touch
            // the remaining module.
            val after = backend.prepareBootTasks()
            assertFalse("an uninstalled module must not be scheduled again",
                after.any { it.id == ok.id || it.id == failing.id })
            assertTrue("an unrelated module must be untouched", treeExists(plain))
            assertNotNull(catalog.get(plain.report.type, plain.id))

            println("MAPLESU_EVIDENCE task=T3 uninstalled=2 hookFailed=1 kept=1 marker=${markerLines.joinToString(",")} " +
                "standardPath=absent receipt=ok")
        } finally {
            runCatching { root("/system/bin/rm -f ${quote(marker)} && true") }
            teardown(ok, catalog)
            teardown(failing, catalog)
            teardown(plain, catalog)
        }
    }

    private fun listJson(backend: LiteScriptModuleBackend, id: String): org.json.JSONObject =
        JSONArray(backend.listJson()).let { array ->
            (0 until array.length()).map { array.getJSONObject(it) }.single { it.getString("id") == id }
        }
}
