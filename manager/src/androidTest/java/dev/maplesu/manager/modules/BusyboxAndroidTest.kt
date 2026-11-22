package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Verifies the published BusyBox on the device.
 *
 * M06 asks for a fixed, built-in BusyBox plus applet deployment, and for the
 * `ASH_STANDALONE` contract to be checked. The binary currently published is the
 * pinned upstream artifact described in `third_party/busybox/PROVENANCE.md`, which
 * is recorded as such and not as a MapleSU source build.
 *
 * Opt-in: `-e verifyMapleSuBoot true`
 */
class BusyboxAndroidTest {

    @Test(timeout = 120_000) fun publishedBusyboxServesModuleScripts() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("Requires the paired MapleSU boot runtime", MapleSuRuntime.refresh(context))
        val tool = ModuleToolDeployment.busyboxPath()

        fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
        data class Run(val code: Int, val out: List<String>, val err: List<String>)
        fun root(command: String): Run = MapleSuRuntime.openShell(context).use { shell ->
            val result = shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec()
            Run(result.code, result.out, result.err)
        }

        val present = root("test -x ${quote(tool)} && /system/bin/stat -c '%u:%g:%a' ${quote(tool)}")
        assertEquals("the BusyBox must be deployed executable at $tool; stderr=${present.err}",
            0, present.code)
        println("MAPLESU_BUSYBOX_EVIDENCE path=$tool ownerMode=${present.out.joinToString("").trim()}")

        val version = root("${quote(tool)} 2>&1 | /system/bin/head -1")
        assertEquals("BusyBox banner; stderr=${version.err}", 0, version.code)
        val banner = version.out.joinToString(" ").trim()
        assertTrue("BusyBox must identify itself; got $banner", banner.contains("BusyBox v"))
        println("MAPLESU_BUSYBOX_EVIDENCE banner=${quote(banner)}")

        // applet dispatch by argv[1] is what KSU relies on: <BUSYBOX_PATH> sh <script>
        val applets = root("${quote(tool)} --list | /system/bin/wc -l")
        assertEquals("applet list; stderr=${applets.err}", 0, applets.code)
        val appletCount = applets.out.joinToString("").trim().toIntOrNull() ?: 0
        assertTrue("BusyBox must expose applets; count=$appletCount", appletCount > 100)
        println("MAPLESU_BUSYBOX_EVIDENCE appletCount=$appletCount")

        val sh = root("${quote(tool)} sh -c 'echo busybox-sh-ok'")
        assertEquals("busybox sh; stderr=${sh.err}", 0, sh.code)
        assertEquals("busybox-sh-ok", sh.out.joinToString(" ").trim())
        println("MAPLESU_BUSYBOX_EVIDENCE sh=${quote(sh.out.joinToString(" ").trim())}")

        // Standalone ash: the env value is what KSU exports for every module script.
        // The payload is single-quoted for the outer Root shell, so it must not carry
        // extra backslash escaping - that would reach ash as a literal "\$" and turn
        // the arithmetic expansion into a subshell.
        val ash = root("ASH_STANDALONE=1 ${quote(tool)} ash -c 'echo ash-standalone-ok; echo \$((1+1))'")
        assertEquals("busybox ash with ASH_STANDALONE=1; stderr=${ash.err}", 0, ash.code)
        val ashOut = ash.out.joinToString(" ").trim()
        assertTrue("ash must run with ASH_STANDALONE=1; got $ashOut", ashOut.contains("ash-standalone-ok"))
        assertTrue("ash must evaluate arithmetic; got $ashOut", ashOut.contains("2"))
        println("MAPLESU_BUSYBOX_EVIDENCE ash=${quote(ashOut)}")
    }
}
