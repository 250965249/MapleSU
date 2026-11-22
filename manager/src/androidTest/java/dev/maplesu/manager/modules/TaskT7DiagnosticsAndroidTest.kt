package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.data.repository.ModuleRepositoryImpl
import com.maplesu.core.ui.util.hasMagisk
import dev.maplesu.manager.runtime.MapleSuRuntime
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Diagnostics for the two report-driven questions (2026-10-27):
 *
 *  1. the module page's "conflict with Magisk" banner - it is driven by `hasMagisk()`;
 *     this proves the production probe now returns false and shows *why* it used to
 *     return true (a stale `magisk` shim inside the tool PATH);
 *  2. TEESimulator-RS "does not take effect" - this records the exact blocker: the
 *     kernel-side kit status and what the user-space core prints when started directly.
 *
 * Not a pass/fail opinion about the product: every value is printed so the delivery
 * record can quote the device instead of a guess.
 */
class TaskT7DiagnosticsAndroidTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"

    private fun root(command: String): List<String> = MapleSuRuntime.openShell(context).use { shell ->
        val result = shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec()
        result.out + result.err.map { "ERR:$it" }
    }

    @Test(timeout = 180_000) fun modulePageEnvironmentIsClean() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assertTrue(MapleSuRuntime.refresh(context))
        // Production path used by ModuleViewModel.refreshEnvironmentState().
        val magisk = hasMagisk()
        assertFalse("MapleSU's own shim must not be reported as another root", magisk)
        val probe = root(
            "echo COMMAND_V:$(command -v magisk 2>&1 || true); " +
                "echo BIN_LIST:$(/system/bin/ls -1 /data/adb/maplesu/bin 2>&1 | /system/bin/tr '\\n' ','); " +
                "echo COMPAT_LIST:$(/system/bin/ls -1 /data/adb/maplesu/bin/compat 2>&1 | /system/bin/tr '\\n' ',')")
        val binList = probe.firstOrNull { it.startsWith("BIN_LIST:") }
            ?.removePrefix("BIN_LIST:").orEmpty()
        // The production probe must ignore MapleSU's own shim, whatever the directory
        // content is; the raw listing is recorded because a stale bare `magisk` here is
        // exactly the historical cause of the false "Magisk conflict" banner.
        assertFalse("MapleSU's own shim must not be reported as another root", magisk)
        // The module page source of truth: the production repository must load.
        val modules = runBlocking { ModuleRepositoryImpl().getModules() }.getOrThrow()
        val listed = JSONArray(LiteScriptModuleBackend(context).listJson())
        assertEquals("the repository and the backend must agree", listed.length(), modules.size)
        println("MAPLESU_EVIDENCE diag=module_page magisk=$magisk modules=${modules.size} " +
            "bin=${binList.take(200)} probe=${probe.joinToString(" | ").take(300)}")
    }

    @Test(timeout = 240_000) fun teesimulatorCoreReportsItsBlocker() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assertTrue(MapleSuRuntime.refresh(context))
        val kit = root(
            "/system/bin/cat /data/adb/maplesu/kit/status 2>&1; /system/bin/echo ---MODULE---; " +
                "/system/bin/ls -la /data/adb/modules/tricky_store 2>&1 | /system/bin/head -12; " +
                "/system/bin/echo ---CONFIG---; " +
                "/system/bin/ls -la /data/adb/tricky_store 2>&1 | /system/bin/head -12")
        val catalog = ModuleCatalog(File(context.filesDir, "module-catalog"))
        val entry = catalog.get(dev.maplesu.manager.ModuleArchiveInspector.ModuleType.KERNEL_SU,
            "teesimulator-rs")
        assumeTrue("Install TEESimulator-RS manually before running this diagnostic", entry != null)
        val revision = File(context.filesDir, "module-runtime/revisions/" +
            revisionKey(entry!!.report))
        val core = File(revision, "core")
        assertTrue("the core assets must exist", core.isDirectory)
        val output = "/data/local/tmp/maplesu-tee-diag.out"
        // Control: does app_process work at all in this shell domain? `am` uses exactly
        // that mechanism, so this separates "app_process is restricted" from "this DEX
        // or invocation is rejected".
        val control = root(
            "CLASSPATH=/system/framework/am.jar /system/bin/timeout 6 /system/bin/app_process " +
                "/system/bin com.android.commands.am.Am --help > ${quote(output)}.ctl 2>&1; " +
                "/system/bin/echo CTL_EXIT:${'$'}?; /system/bin/head -5 ${quote(output)}.ctl 2>&1")
        // Bare invocation: the DEX class without any --nice-name option.
        val bare = root(
            "CORE=${quote(core.absolutePath)}; " +
                "CLASSPATH=\"${'$'}CORE/classes.dex\" /system/bin/timeout 6 /system/bin/app_process " +
                "\"${'$'}CORE\" org.matrix.TEESimulator.App > ${quote(output)}.bare 2>&1; " +
                "/system/bin/echo BARE_EXIT:${'$'}?; /system/bin/head -15 ${quote(output)}.bare 2>&1")
        // The packaged `core/daemon` exactly as the module runs it. The upstream
        // service.sh changes into the module directory first, and the core's injection
        // command is the relative `./inject`; without that chdir it is not found (127).
        val daemon = root(
            "CORE=${quote(core.absolutePath)}; " +
                "(cd \"${'$'}CORE\" && /system/bin/timeout 8 /system/bin/sh ./daemon .) " +
                "> ${quote(output)}.daemon 2>&1; " +
                "/system/bin/echo DAEMON_EXIT:${'$'}?; /system/bin/head -15 ${quote(output)}.daemon 2>&1")
        val pid = daemon.firstOrNull { it.startsWith("DAEMON_EXIT:") }
            ?: bare.firstOrNull { it.startsWith("BARE_EXIT:") }
        // Can a shell-domain process execute an ELF that lives in the app-private
        // revision at all? Compare the same tiny binary from app storage and from a
        // root-owned exec-capable directory.
        val exec = root(
            "CORE=${quote(core.absolutePath)}; " +
                "/system/bin/ls -l \"${'$'}CORE/inject\" \"${'$'}CORE/supervisor\" 2>&1; " +
                "OUT0=$(\"${'$'}CORE/inject\" 2>&1); echo INJ_EXIT:${'$'}?:${'$'}OUT0; " +
                "OUT1=$(\"${'$'}CORE/supervisor\" 2>&1); echo SUP_APP_EXIT:${'$'}?:${'$'}OUT1; " +
                "/system/bin/cp \"${'$'}CORE/supervisor\" /data/local/tmp/maplesu-supervisor-probe 2>&1; " +
                "/system/bin/chmod 0755 /data/local/tmp/maplesu-supervisor-probe; " +
                "OUT2=$(/data/local/tmp/maplesu-supervisor-probe 2>&1); echo SUP_TMP_EXIT:${'$'}?:${'$'}OUT2; " +
                "/system/bin/rm -f /data/local/tmp/maplesu-supervisor-probe; true")
        // The upstream `daemon` also accepts a `service.apk`; a bare .dex in CLASSPATH
        // may not be loadable on this ART. Build the archive on-device and try it.
        val jar = File(context.cacheDir, "tee-core-probe.jar")
        java.util.zip.ZipOutputStream(jar.outputStream()).use { zip ->
            zip.putNextEntry(java.util.zip.ZipEntry("classes.dex"))
            File(core, "classes.dex").inputStream().use { it.copyTo(zip) }
            zip.closeEntry()
        }
        val jarProbe = root(
            "CORE=${quote(core.absolutePath)}; JAR=${quote(jar.absolutePath)}; " +
                "CLASSPATH=\"${'$'}JAR\" /system/bin/timeout 6 " +
                "/system/bin/app_process \"${'$'}CORE\" org.matrix.TEESimulator.App " +
                "> ${quote(output)}.jar 2>&1; " +
                "/system/bin/echo JAR_EXIT:${'$'}?; /system/bin/head -15 ${quote(output)}.jar 2>&1; " +
                "echo JAR_PID:$(pidof TEESimulator 2>/dev/null || echo none); true")
        // Nothing may be left running by this diagnostic.
        assertEquals(listOf("none"), root("pidof TEESimulator 2>/dev/null || echo none").map { it.trim() })
        println("MAPLESU_EVIDENCE diag=teesimulator kit=${kit.joinToString(" ")} " +
            "pid=$pid control=${control.joinToString(" | ").take(200)} " +
            "bare=${bare.joinToString(" | ").take(200)} " +
            "daemon=${daemon.joinToString(" | ").take(300)} " +
            "jar=${jarProbe.joinToString(" | ").take(300)} " +
            "exec=${exec.joinToString(" | ").take(400)}")
    }

    private fun revisionKey(report: dev.maplesu.manager.ModuleArchiveInspector.Report): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest("${report.type}\n${report.id}\n${report.sha256}".toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 255) }
}
