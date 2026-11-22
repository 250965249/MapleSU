package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.ModuleArchiveInspector.Report
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.json.JSONArray
import org.junit.Assert.assertEquals
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
 * T2: the public `post-fs-data.d` / `service.d` / `boot-completed.d` hooks.
 *
 * The claim is the KSU contract (`.research/KernelSU/userspace/ksud/src/module.rs:385-405`):
 * executable regular files run in filename order, a non-executable file is skipped
 * without failing the stage, a failing entry does not stop the following ones, and the
 * common directory runs **before** the modules' own stage scripts.
 *
 * Opt-in: `-e verifyMapleSuBoot true`.
 */
class TaskT2StageDirAndroidTest {
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

    /** Writes one fixture script through the app cache (the app UID cannot write /data/adb). */
    private fun stageScript(name: String, body: String, executable: Boolean): String {
        val local = File(context.cacheDir, "t2-$name-${body.hashCode()}").apply { writeText(body) }
        val target = "/data/adb/maplesu/service.d/$name"
        root("/system/bin/cp ${quote(local.absolutePath)} ${quote(target)} && " +
            "/system/bin/chown 0:0 ${quote(target)} && " +
            "/system/bin/chmod ${if (executable) "0755" else "0644"} ${quote(target)} && " +
            "/system/bin/printf 'MAPLESU_T2_WRITTEN:%s\\n' ${quote(target)}")
        local.delete()
        return target
    }

    @Test(timeout = 180_000) fun publicServiceDirectoryRunsInOrderAndRecordsEachEntry() {
        requireOptIn()
        val id = "maplesu_t2_stage_" + UUID.randomUUID().toString().replace("-", "")
        val log = "/data/local/tmp/$id.log"
        val names = listOf("t2-10-ok.sh", "t2-20-fail.sh", "t2-30-skip.sh", "t2-40-after.sh")
        val archive = File.createTempFile("t2-stage-dir-", ".zip", context.cacheDir)
        ZipOutputStream(archive.outputStream()).use { output ->
            val files = mapOf(
                "module.prop" to "id=$id\nname=T2 stage dir fixture\nversion=1\nversionCode=1\n" +
                    "author=MapleSU\ndescription=Public stage directory fixture\n",
                "customize.sh" to "# stage directory fixture\n",
                // The module's own stage script must run after the common directory.
                "service.sh" to "printf 'module\\n' >> ${quote(log)}\n",
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
            root("/system/bin/mkdir -p /data/adb/maplesu/service.d && " +
                "/system/bin/rm -f ${quote(log)} && true")
            stageScript(names[0], "#!/system/bin/sh\nprintf 'ok\\n' >> ${quote(log)}\n", true)
            stageScript(names[1], "#!/system/bin/sh\nprintf 'fail\\n' >> ${quote(log)}\nexit 3\n", true)
            stageScript(names[2], "#!/system/bin/sh\nprintf 'skip\\n' >> ${quote(log)}\n", false)
            stageScript(names[3], "#!/system/bin/sh\nprintf 'after\\n' >> ${quote(log)}\n", true)

            assertEquals((out + err).joinToString("\n"), 0,
                backend.install(archive, report, out::add, err::add).code)
            simulatePreviousBoot(receipt)

            val tasks = backend.prepareBootTasks()
            val common = tasks.single { it.common && it.stage == "service" }
            val module = tasks.single { it.id == id && it.stage == "service" }
            assertTrue("the public service.d hook must run before the module's service.sh",
                tasks.indexOf(common) < tasks.indexOf(module))
            backend.runBootTask(common, out::add, err::add)
            backend.runBootTask(module, out::add, err::add)

            // Filename order: 10-ok, 20-fail (exit 3), 40-after still runs, then the module.
            val lines = root("/system/bin/cat ${quote(log)}").filter { it.isNotBlank() }
            assertEquals(listOf("ok", "fail", "after", "module"), lines)

            // The non-executable entry was skipped and the stage still ran.
            assertTrue("a non-executable entry must be reported as skipped: $out",
                out.any { it.contains("MAPLESU_STAGE_SKIP") && it.contains(names[2]) })
            assertTrue("a skipped entry must not be executed",
                lines.none { it == "skip" })

            // Per-entry receipt (task book §0.2) on the common receipt.
            val commonReceipt = File(context.filesDir, "module-runtime/receipts/_common.properties")
            assertTrue("common receipt must exist", commonReceipt.isFile)
            val values = properties(commonReceipt)
            assertEquals("failed", values.getProperty("stage.service.status"))
            val detail = values.getProperty("stage.service.detail").orEmpty()
            assertTrue("detail must start with the first entry: $detail",
                detail.startsWith("${names[0]}:0"))
            assertTrue("the failing entry must be recorded: $detail",
                detail.contains("${names[1]}:3"))
            assertTrue("the entry after the failure must still be recorded: $detail",
                detail.contains("${names[3]}:0"))
            assertEquals(names[1], values.getProperty("stage.service.failure"))

            // The module receipt records its own stage, separate from the common receipt.
            assertEquals("ok", properties(receipt).getProperty("stage.service.status"))

            val listed = JSONArray(backend.listJson()).let { array ->
                (0 until array.length()).map { array.getJSONObject(it) }.single { it.getString("id") == id }
            }
            assertEquals("ok", listed.getJSONObject("stages").getJSONObject("service").getString("status"))

            println("MAPLESU_EVIDENCE task=T2 entries=3 failed=1 skipped=1 " +
                "order=${lines.joinToString(",")} detail=${detail}")
        } finally {
            runCatching {
                names.forEach { root("/system/bin/rm -f ${quote("/data/adb/maplesu/service.d/$it")}") }
                root("/system/bin/rm -f ${quote(log)} && true")
            }
            runCatching {
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
    }
}
