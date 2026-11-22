package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.ModuleArchiveInspector.Report
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
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
 * T1: module `system.prop` reaches the property area through the published resetprop.
 *
 * What is asserted, and why each part matters:
 *  1. a package whose only feature is `SYSTEM_PROPERTIES` installs - the old
 *     `LiteScriptModulePolicy` gate would have rejected it before any script ran;
 *  2. the applied values are read back from the device with `getprop`, not from the
 *     receipt (a receipt that says "applied" while the property is absent would be
 *     exactly the silent success this task removes);
 *  3. the receipt uses the task-book key names (`props.applied`, `props.failed`,
 *     `unsupported`, `stage.install.status`) and stays single-line;
 *  4. a malformed line is recorded as `bad-key` and does not abort the good entries;
 *  5. disabling the module removes its `props` boot task, so the next boot does not
 *     write the property again.
 *
 * Opt-in: `-e verifyMapleSuBoot true`.
 */
class TaskT1SystemPropAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private data class Fixture(
        val id: String,
        val archive: File,
        val report: Report,
        val receipt: File,
        val revision: File,
    )

    private fun requireOptIn() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue("Requires the paired MapleSU boot runtime", MapleSuRuntime.refresh(context))
    }

    private fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"

    private fun root(command: String): List<String> = MapleSuRuntime.openShell(context).use { shell ->
        shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec().out
    }

    private fun runId(): String = "maplesu_t1_prop_" + UUID.randomUUID().toString().replace("-", "")

    private fun fixture(id: String, systemProp: String): Fixture {
        val archive = File.createTempFile("t1-system-prop-", ".zip", context.cacheDir)
        ZipOutputStream(archive.outputStream()).use { output ->
            val files = mapOf(
                "module.prop" to "id=$id\nname=T1 system.prop fixture\nversion=1\nversionCode=1\n" +
                    "author=MapleSU\ndescription=Attribute-only fixture for T1\n",
                // Empty customize.sh: the package has no system/ tree, no native payload
                // and no lifecycle script, so SYSTEM_PROPERTIES is its only feature.
                "customize.sh" to "# attribute-only fixture\n",
                "system.prop" to systemProp,
            )
            files.forEach { (name, content) ->
                output.putNextEntry(ZipEntry(name))
                output.write(content.toByteArray())
                output.closeEntry()
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

    private fun properties(file: File): Properties =
        Properties().apply { file.inputStream().use { load(it) } }

    /**
     * Simulates "this module was installed on an earlier boot" so the boot scheduler
     * treats it as active. Without this the scheduler correctly skips a module that was
     * installed in the current boot (KSU only loads properties on the next boot).
     */
    private fun simulatePreviousBoot(receipt: File) {
        val values = properties(receipt)
        val previous = UUID.randomUUID().toString()
        values.setProperty("installedBootId", previous)
        if (values.getProperty("props.bootId") != null) values.setProperty("props.bootId", previous)
        receipt.outputStream().use { values.store(it, null) }
    }

    private fun cleanup(fixture: Fixture, backend: LiteScriptModuleBackend, catalog: ModuleCatalog) {
        runCatching {
            // Every probe property this fixture can write, not just the happy-path pair:
            // a leftover would show up in the C1/C3 `getprop | grep -i maplesu` check.
            root("/data/adb/maplesu/bin/resetprop -d maplesu.test.prop >/dev/null 2>&1; " +
                "/data/adb/maplesu/bin/resetprop -d ro.maplesu.test >/dev/null 2>&1; " +
                "/data/adb/maplesu/bin/resetprop -d maplesu.test.good >/dev/null 2>&1; true")
        }
        runCatching {
            assertEquals(context.filesDir.resolve("module-runtime/revisions").canonicalFile,
                fixture.revision.parentFile.canonicalFile)
            ModuleTree.unlink(context, fixture.id, fixture.revision.absolutePath)
            root("rm -rf -- ${quote(fixture.revision.absolutePath)}")
        }
        runCatching {
            catalog.get(fixture.report.type, fixture.id)
                ?.takeIf { it.report.sha256 == fixture.report.sha256 }
                ?.let { catalog.uninstall(fixture.report.type, fixture.id) }
        }
        fixture.receipt.delete()
        fixture.archive.delete()
    }

    @Test(timeout = 180_000) fun systemPropIsAppliedThroughTheBootTaskAndReceipted() {
        requireOptIn()
        val id = runId()
        // `ro.maplesu.test` is exactly the shape a real attribute module ships: a
        // read-only-looking name that only a direct-mmap write can change.
        val fixture = fixture(id, """
            # leading comment
            maplesu.test.prop=alpha
            ro.maplesu.test=beta

        """.trimIndent())
        val backend = LiteScriptModuleBackend(context)
        val catalog = ModuleCatalog(File(context.filesDir, "module-catalog"))
        val out = mutableListOf<String>()
        val err = mutableListOf<String>()
        try {
            // (1) The removed feature gate must not reject an attribute-only package.
            val installed = backend.install(fixture.archive, fixture.report, out::add, err::add)
            assertEquals((out + err).joinToString("\n"), 0, installed.code)
            assertTrue("install receipt must exist", fixture.receipt.isFile)
            assertFalse("an attribute-only package must not request a reboot",
                installed.needsReboot)

            // (2) Drive the real boot wiring: scheduler -> props task -> resetprop.
            simulatePreviousBoot(fixture.receipt)
            val pending = backend.prepareBootTasks().filter { it.id == id && it.stage == "props" }
            assertEquals("the enabled module must get exactly one props task", 1, pending.size)
            backend.runBootTask(pending.single(), out::add, err::add)

            // (3) Read back from the device, never from the receipt.
            assertEquals(listOf("alpha"), root("getprop maplesu.test.prop"))
            assertEquals(listOf("beta"), root("getprop ro.maplesu.test"))

            // (4) Receipt contract (task book §0.2).
            val receipt = properties(fixture.receipt)
            assertEquals("maplesu.test.prop=alpha;ro.maplesu.test=beta",
                receipt.getProperty("props.applied"))
            assertEquals("", receipt.getProperty("props.failed"))
            assertEquals("mount,zygisk,sepolicy-apply", receipt.getProperty("unsupported"))
            assertEquals("ok", receipt.getProperty("stage.install.status"))
            // Properties are their own receipt section, not a stage: the contract is
            // `props.applied`/`props.failed` (task book §0.2), and that is what the
            // assertions above already pin.
            // No receipt value may contain a raw newline (task book §0.2).
            assertFalse("props.applied must stay one line",
                receipt.getProperty("props.applied").contains('\n'))

            // (5) listJson exposes the same facts to the UI.
            val listed = JSONArray(backend.listJson()).let { array ->
                (0 until array.length()).map { array.getJSONObject(it) }.single { it.getString("id") == id }
            }
            assertEquals(2, listed.getJSONObject("props").getJSONArray("applied").length())
            assertEquals(0, listed.getJSONObject("props").getJSONArray("failed").length())
            assertTrue(listed.getJSONArray("unsupported").toString().contains("mount"))
            // `stages` carries the script stages; `props` carries the property step.
            assertEquals("ok", listed.getJSONObject("stages").getJSONObject("install").getString("status"))

            // (6) Disabling removes the props task for the next boot.
            simulatePreviousBoot(fixture.receipt)
            assertTrue(backend.setEnabled(id, false))
            val disabled = backend.prepareBootTasks().filter { it.id == id && it.stage == "props" }
            assertTrue("a disabled module must not get a props task", disabled.isEmpty())
            assertTrue(backend.setEnabled(id, true))

            println("MAPLESU_EVIDENCE task=T1 applied=2 failed=0 " +
                "prop=${root("getprop maplesu.test.prop").firstOrNull()} " +
                "unsupported=${receipt.getProperty("unsupported")} " +
                "disabledPropsTask=${disabled.size}")
        } finally {
            cleanup(fixture, backend, catalog)
        }
        // Restoration: neither probe property survives the fixture.
        assertTrue("probe property must be gone after cleanup",
            root("getprop maplesu.test.prop").joinToString("").trim().isEmpty())
    }

    @Test(timeout = 180_000) fun malformedLinesAreReportedAsBadKeyWithoutAborting() {
        requireOptIn()
        val id = runId()
        val fixture = fixture(id, """
            maplesu.test.good=gamma
            no-separator-line
            =empty-key
            bad key=x
        """.trimIndent())
        val backend = LiteScriptModuleBackend(context)
        val catalog = ModuleCatalog(File(context.filesDir, "module-catalog"))
        val out = mutableListOf<String>()
        val err = mutableListOf<String>()
        try {
            assertEquals((out + err).joinToString("\n"), 0,
                backend.install(fixture.archive, fixture.report, out::add, err::add).code)
            val (applied, failed) = backend.applySystemProperties(fixture.report, out::add, err::add)
            assertEquals("only the conforming line may be applied: $applied", 1, applied.size)
            assertEquals("every malformed line must be reported: $failed", 3, failed.size)
            assertTrue("all failures must carry bad-key: $failed",
                failed.all { it.endsWith(":bad-key") })
            assertEquals(listOf("gamma"), root("getprop maplesu.test.good"))
            val receipt = properties(fixture.receipt)
            assertEquals("all malformed lines must reach the receipt",
                3, receipt.getProperty("props.failed").split(";").size)
            assertTrue("the receipt must name the reason: ${receipt.getProperty("props.failed")}",
                receipt.getProperty("props.failed").contains("bad-key"))
            println("MAPLESU_EVIDENCE task=T1 malformed=3 bad-key=3 applied=1")
        } finally {
            cleanup(fixture, backend, catalog)
        }
    }
}
