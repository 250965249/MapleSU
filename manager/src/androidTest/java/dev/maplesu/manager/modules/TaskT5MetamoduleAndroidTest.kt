package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.ModuleArchiveInspector.Report
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
 * T5: metamodule dispatch.
 *
 * KSU keeps one `/data/adb/metamodule` pointer (`metamodule.rs:124-153`), and a boot
 * stage calls its `metamount.sh` (`init_event.rs:110-118`). MapleSU does the dispatch
 * but has no mount consumer, so the expected result is a **recorded failure** with the
 * script's own reason - never a silent success.
 *
 * Opt-in: `-e verifyMapleSuBoot true`.
 */
class TaskT5MetamoduleAndroidTest {
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

    /**
     * The pointer is device-global. A leftover of this project's earlier metamodule
     * testing is dropped; anything else is **moved aside**, not destroyed, and the
     * caller restores it in `finally`. Stealing another owner's pointer silently is
     * exactly what the product refuses to do, so the test must not do it either.
     */
    private fun preparePointer(suffix: String): String? {
        val raw = root("if [ -L /data/adb/metamodule ]; then " +
            "/system/bin/readlink /data/adb/metamodule; else echo absent; fi").joinToString("").trim()
        if (raw == "absent") return null
        // An earlier build published `/data/adb/modules/<id>` as a symlink into the
        // app's revision store, so the pointer can name that path instead of the store.
        val resolved = root("if [ -e ${quote(raw)} ]; then /system/bin/readlink -f ${quote(raw)}; " +
            "else echo missing; fi").joinToString("").trim()
        println("MAPLESU_EVIDENCE task=T5 pointerBefore=$raw resolved=$resolved " +
            "filesDir=${context.filesDir.absolutePath}")
        if (resolved.startsWith(context.filesDir.absolutePath)) {
            root("/system/bin/rm -f /data/adb/metamodule")
            return null
        }
        val backup = "/data/adb/metamodule.maplesu-stale-$suffix"
        root("/system/bin/mv /data/adb/metamodule ${quote(backup)}")
        println("MAPLESU_EVIDENCE task=T5 pointerPreserved=$backup")
        return backup
    }

    private fun fixture(id: String, metamodule: Boolean, metamount: String?): Fixture {
        val archive = File.createTempFile("t5-metamodule-", ".zip", context.cacheDir)
        ZipOutputStream(archive.outputStream()).use { output ->
            val files = linkedMapOf(
                "module.prop" to "id=$id\nname=T5 metamodule fixture\nversion=1\nversionCode=1\n" +
                    "author=MapleSU\ndescription=Metamodule dispatch fixture\n" +
                    (if (metamodule) "metamodule=1\n" else ""),
                "customize.sh" to "# metamodule fixture\n",
            )
            metamount?.let { files["metamount.sh"] = it }
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

    private fun simulatePreviousBoot(receipt: File, resetRemoval: Boolean) {
        val values = properties(receipt)
        val previous = UUID.randomUUID().toString()
        values.setProperty("installedBootId", previous)
        if (resetRemoval) values.setProperty("removeRequestedBootId", previous)
        receipt.outputStream().use { values.store(it, null) }
    }

    @Test(timeout = 240_000) fun mountHookIsDispatchedAndItsFailureIsRecorded() {
        requireOptIn()
        val suffix = UUID.randomUUID().toString().replace("-", "")
        val stalePointer = preparePointer(suffix)
        val mm = fixture("maplesu_t5_meta_$suffix", metamodule = true,
            metamount = "#!/system/bin/sh\n/system/bin/printf 'overlay is required for this metamodule\\n' >&2\nexit 7\n")
        val second = fixture("maplesu_t5_second_$suffix", metamodule = true,
            metamount = "#!/system/bin/sh\nexit 0\n")
        val backend = LiteScriptModuleBackend(context)
        val catalog = ModuleCatalog(File(context.filesDir, "module-catalog"))
        val out = mutableListOf<String>()
        val err = mutableListOf<String>()
        try {
            // (1) Install publishes the single pointer.
            val installed = backend.install(mm.archive, mm.report, out::add, err::add)
            assertEquals((out + err).joinToString("\n"), 0, installed.code)
            assertTrue("a metamodule with metamount.sh needs a boot", installed.needsReboot)
            assertEquals(listOf(mm.revision.absolutePath), root("/system/bin/readlink /data/adb/metamodule"))
            val listed = JSONArray(backend.listJson()).let { array ->
                (0 until array.length()).map { array.getJSONObject(it) }.single { it.getString("id") == mm.id }
            }
            assertTrue("listJson must report the declared metamodule fact", listed.getBoolean("metamodule"))

            // (2) A second metamodule must be refused, not silently steal the pointer.
            val secondResult = backend.install(second.archive, second.report, out::add, err::add)
            assertEquals("a second metamodule must be rejected", 1, secondResult.code)
            assertTrue("the conflict reason must be explicit: $err",
                err.any { it.contains("METAMODULE_CONFLICT") })
            assertEquals("the first pointer must survive the rejected install",
                listOf(mm.revision.absolutePath), root("/system/bin/readlink /data/adb/metamodule"))
            assertNull("a rejected metamodule must not be installed",
                catalog.get(second.report.type, second.id))

            // (3) The boot dispatch calls metamount.sh and records the refusal instead of
            // pretending a mount happened.
            simulatePreviousBoot(mm.receipt, resetRemoval = false)
            val mountTask = backend.prepareBootTasks().single { it.id == mm.id && it.stage == "mount" }
            backend.runBootTask(mountTask, out::add, err::add)
            val receipt = properties(mm.receipt)
            assertEquals("failed", receipt.getProperty("stage.mount.status"))
            assertEquals("7", receipt.getProperty("stage.mount.code"))
            assertTrue("the script's own reason must be kept: ${receipt.getProperty("stage.mount.detail")}",
                receipt.getProperty("stage.mount.detail").orEmpty()
                    .contains("overlay is required for this metamodule"))

            // (4) Uninstall executes the T3 lifecycle and drops the pointer.
            assertTrue(backend.markRemove(mm.id, true))
            simulatePreviousBoot(mm.receipt, resetRemoval = true)
            val uninstall = backend.prepareBootTasks().single { it.id == mm.id && it.stage == "uninstall" }
            backend.runBootTask(uninstall, out::add, err::add)
            assertEquals(listOf("absent"), root("if [ -L /data/adb/metamodule ]; " +
                "then echo present; else echo absent; fi"))
            assertFalse(mm.revision.exists())
            assertNull(catalog.get(mm.report.type, mm.id))
            assertEquals("ok", properties(mm.receipt).getProperty("stage.uninstall.status"))

            println("MAPLESU_EVIDENCE task=T5 metamodule=1 conflict=1 mountFailed=7 pointer=absent")
        } finally {
            runCatching { root("/system/bin/rm -f /data/adb/metamodule") }
            // Restore whatever pointer was there before this fixture (a real owner's
            // pointer must survive the test; only this test's own pointer is removed).
            if (stalePointer != null) {
                runCatching { root("/system/bin/mv ${quote(stalePointer)} /data/adb/metamodule") }
            }
            listOf(mm, second).forEach { fixture ->
                runCatching {
                    ModuleTree.unlink(context, fixture.id, fixture.revision.absolutePath)
                    root("rm -rf -- ${quote(fixture.revision.absolutePath)}")
                }
                runCatching {
                    catalog.get(fixture.report.type, fixture.id)
                        ?.let { catalog.uninstall(fixture.report.type, fixture.id) }
                }
                fixture.receipt.delete()
                fixture.archive.delete()
            }
        }
    }
}
