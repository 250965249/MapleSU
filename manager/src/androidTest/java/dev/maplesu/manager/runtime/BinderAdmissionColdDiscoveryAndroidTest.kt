package dev.maplesu.manager.runtime

import android.os.Bundle
import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Opt-in: each invocation launches a new app_process under the independent test APK's real UID. */
class BinderAdmissionColdDiscoveryAndroidTest {
    @Test(timeout = 75_000) fun freshOrdinaryUidDiscoversRootAndTransfersThreeFds() {
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(arguments.getString("verifyBinderColdDiscovery") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val manager = instrumentation.targetContext
        val test = instrumentation.context
        val testUid = manager.packageManager.getApplicationInfo(test.packageName, 0).uid
        assertNotEquals("Probe must run under a different installed APK UID", manager.applicationInfo.uid, testUid)
        val foreground = arguments.getString("binderColdForeground", "false")
        require(foreground == "true" || foreground == "false") { "binderColdForeground must be true|false" }
        val classpath = "${test.applicationInfo.sourceDir}:${manager.applicationInfo.sourceDir}"
        val invocation = "CLASSPATH=${quote(classpath)} /system/bin/app_process /system/bin " +
            "dev.maplesu.manager.runtime.BinderAdmissionColdClient $foreground"
        val command = "run-as ${quote(test.packageName)} /system/bin/sh -c ${quote(invocation)}"
        val output = instrumentation.uiAutomation.executeShellCommand(command).use { descriptor ->
            ParcelFileDescriptor.AutoCloseInputStream(descriptor).bufferedReader().use { it.readText() }
        }
        assertTrue("Cold client output exceeds bound", output.length <= 8192)
        val reports = output.lineSequence().filter { it.startsWith("{") && it.endsWith("}") }.toList()
        assertEquals(output, 1, reports.size)
        val report = JSONObject(reports.single())
        instrumentation.sendStatus(2, Bundle().apply { putString("binderColdDiscovery", report.toString()) })
        assertEquals(report.toString(), "pass", report.getString("status"))
        assertEquals(report.toString(), testUid, report.getInt("clientUID"))
        assertEquals(report.toString(), testUid, report.getInt("callingUID"))
        assertEquals(report.toString(), manager.applicationInfo.uid, report.getInt("callbackUID"))
        assertEquals(report.toString(), 0, report.getInt("rootUID"))
        assertTrue(report.toString(), report.getInt("rootPID") > 1)
        assertEquals(report.toString(), 37, report.getInt("exit37"))
        assertEquals("maplesu-binder-admission\n", report.getString("stdout"))
        assertEquals("maplesu-binder-stderr\n", report.getString("stderr"))
    }

    private fun quote(value: String): String = "'${value.replace("'", "'\\''")}'"
}
