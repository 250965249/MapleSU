package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector.ModuleType
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * Restores the test device after the T1–T7 work: removes module fixtures left behind by
 * aborted runs and deletes the probe properties. It only touches ids this project's
 * tests create (`maplesu_*`) plus the known broken `zygisk_lsposed` leftover whose
 * daemon cannot execute; anything else is left alone.
 */
class ResidueCleanupAndroidTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"

    private fun root(command: String): List<String> = MapleSuRuntime.openShell(context).use { shell ->
        shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec().out
    }

    @Test(timeout = 240_000) fun removeAbortedTestModulesAndProperties() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assertTrue(MapleSuRuntime.refresh(context))
        val catalog = ModuleCatalog(File(context.filesDir, "module-catalog"))
        val removed = mutableListOf<String>()
        catalog.list().forEach { entry ->
            val id = entry.report.id
            if (entry.report.type != ModuleType.KERNEL_SU) return@forEach
            if (!id.startsWith("maplesu_") && id != "zygisk_lsposed") return@forEach
            val key = MessageDigest.getInstance("SHA-256")
                .digest("${entry.report.type}\n$id\n${entry.report.sha256}".toByteArray())
                .joinToString("") { "%02x".format(it.toInt() and 255) }
            val revision = File(context.filesDir, "module-runtime/revisions/$key")
            runCatching { ModuleTree.unlink(context, id, revision.absolutePath) }
            runCatching { root("rm -rf -- ${quote(revision.absolutePath)}") }
            runCatching { catalog.uninstall(entry.report.type, id) }
            File(context.filesDir, "module-runtime/receipts/$key.properties").delete()
            removed += id
        }
        root("/data/adb/maplesu/bin/resetprop -d maplesu.test.prop >/dev/null 2>&1; " +
            "/data/adb/maplesu/bin/resetprop -d ro.maplesu.test >/dev/null 2>&1; " +
            "/data/adb/maplesu/bin/resetprop -d maplesu.test.good >/dev/null 2>&1; " +
            "/data/adb/maplesu/bin/resetprop -d maplesu.t4.prop >/dev/null 2>&1; true")
        runCatching { root("rm -rf /data/adb/maplesu/tee && true") }
        // An earlier T6 packaging iteration used the upstream module id and published
        // this link; the current bundle is installed under `teesimulator-rs`, so the
        // link is stale (it points at a revision that no longer exists). Only a symlink
        // is removed - a real TrickyStore module directory is user data and stays.
        runCatching {
            root("if [ -L /data/adb/modules/tricky_store ]; then " +
                "/system/bin/rm -f /data/adb/modules/tricky_store; echo STALE_TEE_LINK_REMOVED=1; " +
                "else echo STALE_TEE_LINK_REMOVED=0; fi")
        }.onSuccess { println("MAPLESU_EVIDENCE cleanup tee_link=${it.joinToString(" ")}") }
        val remaining = catalog.list().map { it.report.id }
        println("MAPLESU_EVIDENCE cleanup removed=${removed.joinToString(",")} " +
            "remaining=${remaining.joinToString(",")}")
        assertTrue("the test-module prefixes must be gone",
            remaining.none { it.startsWith("maplesu_") || it == "zygisk_lsposed" })
    }
}
