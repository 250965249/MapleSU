package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.ModuleArchiveInspector.ModuleType
import dev.maplesu.manager.ModuleArchiveInspector.Report
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * T1, reboot-level acceptance: a real module `system.prop` is applied by the **next
 * boot**, and disabling the module stops it from being written on the boot after that.
 *
 * The four phases run as separate instrumentations with reboots in between (the goal is
 * to observe what the device does, not to simulate it in one process):
 *
 *   adb shell am instrument -w -e verifyMapleSuBoot true -e t1Phase install \
 *       -e class 'dev.maplesu.manager.modules.TaskT1RebootAndroidTest#install' <runner>
 *   adb reboot; <wait for sys.boot_completed>
 *   ... -e t1Phase assert-applied -e class '...#assertApplied'
 *   ... -e t1Phase disable        -e class '...#disable`
 *   adb reboot; <wait>
 *   ... -e t1Phase assert-restored -e class '...#assertRestored'
 *
 * Each method ignores any phase that was not requested, so the class is safe to list in
 * a suite (it becomes a no-op there) while a phase run still executes exactly one step.
 */
class TaskT1RebootAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private val id = "maplesu_t1_reboot"
    private val prop = "maplesu.t1.reboot"

    private fun phase(name: String) {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue("run with -e t1Phase=$name",
            InstrumentationRegistry.getArguments().getString("t1Phase") == name)
        assumeTrue("Requires the paired MapleSU boot runtime", MapleSuRuntime.refresh(context))
    }

    private fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"

    private fun root(command: String): List<String> = MapleSuRuntime.openShell(context).use { shell ->
        shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec().out
    }

    private fun backend() = LiteScriptModuleBackend(context)

    private fun catalog() = ModuleCatalog(File(context.filesDir, "module-catalog"))

    private fun revisionOf(report: Report): File {
        val key = MessageDigest.getInstance("SHA-256")
            .digest("${report.type}\n${report.id}\n${report.sha256}".toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        return File(context.filesDir, "module-runtime/revisions/$key")
    }

    private fun receiptOf(report: Report): File =
        File(context.filesDir, "module-runtime/receipts/${revisionOf(report).name}.properties")

    /** Removes any previous fixture state (there is one fixed id, so phases can find it). */
    private fun reset() {
        catalog().get(ModuleType.KERNEL_SU, id)?.let { entry ->
            val revision = revisionOf(entry.report)
            runCatching { ModuleTree.unlink(context, id, revision.absolutePath) }
            runCatching { root("rm -rf -- ${quote(revision.absolutePath)}") }
            runCatching { catalog().uninstall(entry.report.type, entry.report.id) }
            runCatching { receiptOf(entry.report).delete() }
        }
        runCatching { root("/data/adb/maplesu/bin/resetprop -d $prop >/dev/null 2>&1; true") }
    }

    private fun install(): Report {
        reset()
        val archive = File(context.cacheDir, "t1-reboot-fixture.zip")
        archive.delete()
        ZipOutputStream(archive.outputStream()).use { output ->
            val files = mapOf(
                "module.prop" to "id=$id\nname=T1 reboot fixture\nversion=1\nversionCode=1\n" +
                    "author=MapleSU\ndescription=Real system.prop across a reboot\n",
                "customize.sh" to "# reboot fixture\n",
                "system.prop" to "$prop=alpha\n",
            )
            files.forEach { (name, content) ->
                output.putNextEntry(ZipEntry(name)); output.write(content.toByteArray()); output.closeEntry()
            }
        }
        val report = ModuleArchiveInspector.inspect(archive)
        val out = mutableListOf<String>()
        val err = mutableListOf<String>()
        assertEquals((out + err).joinToString("\n"), 0,
            backend().install(archive, report, out::add, err::add).code)
        return report
    }

    private fun listed(): org.json.JSONObject = JSONArray(backend().listJson()).let { array ->
        (0 until array.length()).map { array.getJSONObject(it) }.single { it.getString("id") == id }
    }

    @Test(timeout = 180_000) fun installPhase() {
        phase("install")
        val report = install()
        assertTrue("the module must be installed with a receipt", receiptOf(report).isFile)
        assertTrue("the property must be owned by the module, not yet written by this phase",
            root("getprop $prop").joinToString("").trim() != "alpha")
        println("MAPLESU_EVIDENCE task=T1 phase=install installed=1 id=$id prop=$prop rebootRequired=1")
    }

    private fun waitForProperty(value: String, seconds: Int): Boolean {
        repeat(seconds) {
            if (root("getprop $prop").joinToString("").trim() == value) return true
            Thread.sleep(1000)
        }
        return false
    }

    @Test(timeout = 240_000) fun assertApplied() {
        phase("assert-applied")
        // The device was rebooted. On this OPlus build the system may DEFER the app's
        // BOOT_COMPLETED under memory pressure ("DEFER_BY_OPLUS"), and deliver it when
        // the app process starts (which is exactly what an instrumentation run does).
        // Both paths end in the same receiver, so this waits for the real result and
        // only then asks the service directly as a fallback.
        var applied = waitForProperty("alpha", 45)
        if (!applied) {
            runCatching { LiteModuleBootService.request(context) }
            applied = waitForProperty("alpha", 45)
        }
        assertEquals("the next boot must apply the module's system.prop (bootId=" +
            root("cat /proc/sys/kernel/random/boot_id").joinToString("").trim() + ")",
            listOf("alpha"), root("getprop $prop"))
        assertTrue(listed().getBoolean("enabled"))
        println("MAPLESU_EVIDENCE task=T1 phase=assert-applied prop=$prop value=alpha")
    }

    @Test(timeout = 120_000) fun disable() {
        phase("disable")
        assertEquals(listOf("alpha"), root("getprop $prop"))
        assertTrue(backend().setEnabled(id, false))
        assertEquals("disabling must not rewrite the value before the reboot",
            listOf("alpha"), root("getprop $prop"))
        println("MAPLESU_EVIDENCE task=T1 phase=disable enabled=0")
    }

    @Test(timeout = 180_000) fun assertRestored() {
        phase("assert-restored")
        // The second reboot rebuilt the property area. Starting this instrumentation
        // started the app process, which is when this OPlus build delivers the deferred
        // BOOT_COMPLETED; give the boot service time to finish before judging the result.
        Thread.sleep(12_000)
        assertTrue("a disabled module must not write its property on the next boot",
            root("getprop $prop").joinToString("").trim().isEmpty())
        val entry = requireNotNull(catalog().get(ModuleType.KERNEL_SU, id))
        val boot = root("cat /proc/sys/kernel/random/boot_id").joinToString("").trim()
        // Non-vacuousness: prove the boot service really ran this boot by finding any
        // other module whose receipt is bound to the current boot id.
        val bootRan = runCatching {
            catalog().list().any { other ->
                val file = File(context.filesDir, "module-runtime/receipts/" +
                    "${revisionOf(other.report).name}.properties")
                if (!file.isFile) return@any false
                val values = java.util.Properties().apply { file.inputStream().use { load(it) } }
                values.getProperty("props.bootId") == boot ||
                    values.getProperty("stage.service.bootId") == boot ||
                    values.getProperty("stage.mount.bootId") == boot
            }
        }.getOrDefault(false)
        assertTrue("the boot service must have run on this boot (boot=$boot)", bootRan)
        val receipt = java.util.Properties().apply {
            receiptOf(entry.report).inputStream().use { load(it) }
        }
        assertTrue("props must not have been re-applied this boot (receipt=" +
            receipt.getProperty("props.bootId") + ", boot=" + boot + ")",
            receipt.getProperty("props.bootId") != boot)
        reset()
        assertNull(catalog().get(ModuleType.KERNEL_SU, id))
        assertTrue("the property must be gone after cleanup",
            root("getprop $prop").joinToString("").trim().isEmpty())
        println("MAPLESU_EVIDENCE task=T1 phase=assert-restored prop=$prop value=empty " +
            "propsBootId=${receipt.getProperty("props.bootId")} boot=$boot restored=1")
    }
}
