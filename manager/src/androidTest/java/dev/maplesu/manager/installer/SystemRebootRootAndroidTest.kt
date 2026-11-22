package dev.maplesu.manager.installer

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.core.app.ActivityScenario
import com.maplesu.core.ui.MainActivity
import com.maplesu.core.ui.util.runRebootRootCommand
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Tests the reboot command's real Ultra transport using read-only commands; never reboots. */
class SystemRebootRootAndroidTest {
    @Test
    fun restoreExplicitlySelectedFailedInstall() {
        val taskId = InstrumentationRegistry.getArguments().getString("restoreFailedInstallTaskId")
        assumeTrue(taskId?.matches(Regex("[0-9a-f-]{36}")) == true)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        ActivityScenario.launch(MainActivity::class.java).use {
            val before = InstallerServiceClient.installationStatus(context, requireNotNull(taskId), InstallTargetMode.ULTRA)
            assertEquals(taskId, before.getString("taskId"))
            val restored = InstallerServiceClient.restoreInstallation(context, taskId)
            instrumentation.sendStatus(2, android.os.Bundle().apply {
                putString("restoreTaskId", taskId)
                putString("restoreState", restored.getString("state"))
                putString("restoreError", restored.getString("error"))
            })
            assertEquals("RESTORED", restored.getString("state"))
        }
    }

    @Test
    fun hookReadOnlyInstallationDiagnostics() {
        val taskId = InstrumentationRegistry.getArguments().getString("hookDiagnosticsTaskId")
        assumeTrue(taskId?.matches(Regex("[0-9a-f-]{36}")) == true)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        ActivityScenario.launch(MainActivity::class.java).use {
            val status = requireNotNull(dev.maplesu.manager.jailbreak.JailbreakStatus.read(context))
            val gate = dev.maplesu.manager.runtime.SuGate.read(context,
                status.carrier?.attemptId ?: status.attemptId,
                status.carrier?.bootId ?: status.bootId)
            assertTrue(gate.armed)
            val result = dev.maplesu.manager.runtime.NativeSu.executeScript(gate,
                "cat /data/adb/maplesu/installer/$taskId/record.json; " +
                    "printf '\\nLIVE_DIGESTS\\n'; " +
                    "sha256sum /dev/block/by-name/boot_a /dev/block/by-name/init_boot_a; " +
                    "dmesg | tail -100 | grep -E 'denied|maplesu|block|error'; true")
            instrumentation.sendStatus(2, android.os.Bundle().apply {
                putString("hookInstallationDiagnostics", result.out)
                putString("hookInstallationDiagnosticsError", result.err)
            })
            assertEquals(result.err, 0, result.code)
        }
    }

    @Test
    fun hookRebootTransportReportsItsActualIdentity() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyHookRebootRoot") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        ActivityScenario.launch(MainActivity::class.java).use {
            val status = requireNotNull(dev.maplesu.manager.jailbreak.JailbreakStatus.read(context))
            val gate = dev.maplesu.manager.runtime.SuGate.read(context,
                status.carrier?.attemptId ?: status.attemptId,
                status.carrier?.bootId ?: status.bootId)
            assertTrue(gate.armed)
            val result = dev.maplesu.manager.runtime.NativeSu.executeScript(gate,
                "/system/bin/id; /system/bin/id -Z; cat /proc/self/attr/current; " +
                    "grep Cap /proc/self/status; test -x /system/bin/svc && test -x /system/bin/reboot")
            instrumentation.sendStatus(2, android.os.Bundle().apply {
                putInt("hookReadOnlyCode", result.code)
                putString("hookReadOnlyOutput", result.out)
                putString("hookReadOnlyError", result.err)
            })
            assertEquals(result.err, 0, result.code)
            assertTrue(result.out.contains("uid=0"))
        }
    }

    @Test
    fun hookRebootProcessCanEnterThePlatformPowerControlDomain() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyHookPowerDomain") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        ActivityScenario.launch(MainActivity::class.java).use {
            val status = requireNotNull(dev.maplesu.manager.jailbreak.JailbreakStatus.read(context))
            val gate = dev.maplesu.manager.runtime.SuGate.read(context,
                status.carrier?.attemptId ?: status.attemptId,
                status.carrier?.bootId ?: status.bootId)
            assertTrue(gate.armed)
            val result = dev.maplesu.manager.runtime.NativeSu.executeScript(gate,
                "/system/bin/toybox runcon u:r:init:s0 /system/bin/id")
            instrumentation.sendStatus(2, android.os.Bundle().apply {
                putInt("hookDomainCode", result.code)
                putString("hookDomainOutput", result.out)
                putString("hookDomainError", result.err)
            })
            assertEquals(result.err, 0, result.code)
            assertTrue(result.out.contains("uid=0"))
            assertTrue(result.out.contains("context=u:r:init:s0"))
        }
    }

    @Test
    fun hookFrameworkServiceLookupFromPlatformDomain() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyHookFrameworkLookup") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        ActivityScenario.launch(MainActivity::class.java).use {
            val status = requireNotNull(dev.maplesu.manager.jailbreak.JailbreakStatus.read(context))
            val gate = dev.maplesu.manager.runtime.SuGate.read(context,
                status.carrier?.attemptId ?: status.attemptId,
                status.carrier?.bootId ?: status.bootId)
            assertTrue(gate.armed)
            val result = dev.maplesu.manager.runtime.NativeSu.executeScript(gate,
                "/system/bin/toybox runcon u:r:shell:s0 /system/bin/service check package")
            instrumentation.sendStatus(2, android.os.Bundle().apply {
                putInt("hookFrameworkCode", result.code)
                putString("hookFrameworkOutput", result.out)
                putString("hookFrameworkError", result.err)
            })
            assertEquals(result.err, 0, result.code)
            assertTrue(result.out.contains("Service package: found"))
        }
    }

    @Test
    fun ultraRebootTransportRequiresARealSuccessfulRootCommand() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyRebootRoot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        // Match foreground use; this ROM freezes background-only instrumentation processes.
        ActivityScenario.launch(MainActivity::class.java).use {
            assertEquals(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.refresh(context))
            val identity = RootExec.execute(context, "/system/bin/id -u; /system/bin/id -Z")
            assertTrue(identity.ok)
            assertEquals("0", identity.output.lineSequence().first())
            assertTrue(identity.output.lineSequence().any { it.startsWith("u:r:") })
            val failed = RootExec.execute(context, "printf MAPLESU_EXIT_PROBE; exit 7")
            assertEquals(RootBackend.ULTRA_ENV, failed.backend)
            assertFalse(failed.ok)
            assertEquals(7, failed.code)
            assertEquals("MAPLESU_EXIT_PROBE", failed.output)
            assertTrue(runRebootRootCommand(context, "test \"${'$'}(/system/bin/id -u)\" = 0"))
            assertTrue(runRebootRootCommand(context, "test -x /system/bin/reboot && test -x /system/bin/svc"))
            assertTrue(runRebootRootCommand(context, "/system/bin/sh -c 'exit 0'"))
            assertFalse(runRebootRootCommand(context, "/system/bin/sh -c 'exit 7'"))
            assertFalse(runRebootRootCommand(context, "printf 'MAPLESU_REBOOT_EXIT:0\\n'; /system/bin/sh -c 'exit 7'"))
            assertTrue(com.maplesu.core.ui.util.rootAvailable())
        }
    }
}
