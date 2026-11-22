package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.liteweb.*
import dev.maplesu.manager.recovery.*
import java.io.File
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class DaemonNormalHiddenTest {
    @get:Rule val temporary = TemporaryFolder()
    private class Kernel : DaemonShell {
        var state = false
        var failOperation: String? = null
        var malformed = false
        var failOff = false
        var failOnAfterWrite = false
        val operations = mutableListOf<String>()
        override fun run(script: String): DaemonShellResult {
            assertTrue(script.startsWith("'/data/adb/maplesu/recovery/lib/libksud_ksu.so' normal-recovery "))
            val op = script.substringAfterLast(' ')
            operations += op
            if (op == "off" && failOff) return DaemonShellResult(1, "fixture")
            if (op == failOperation) return DaemonShellResult(1, "MAPLESU_NORMAL_RECOVERY_V1 operation=$op error=READ_FAILED")
            if (op == "on") state = true
            if (op == "on" && failOnAfterWrite) return DaemonShellResult(1, "fixture")
            if (op == "off") state = false
            return DaemonShellResult(0, if (malformed) "Success" else "MAPLESU_NORMAL_RECOVERY_V1 operation=$op stealth=${if (state) 1 else 0}")
        }
    }
    private class Hidden : LiteHiddenPort {
        var value = false
        var failWrite = false
        override fun currentHidden(): Boolean = value
        override fun setHidden(hidden: Boolean, level: String?): LiteHiddenResult {
            if (failWrite) return LiteHiddenResult.Failed("fixture", "")
            value = hidden
            return LiteHiddenResult.Ok(hidden)
        }
    }
    private fun bundle(withHelper: Boolean = true): RecoveryBundle {
        val root = temporary.newFolder()
        val apk = temporary.newFile().apply { writeText("apk") }
        val helper = temporary.newFile().apply { writeText("helper") }
        val bundle = RecoveryBundle(LocalRecoveryFs(), root.absolutePath, locationPolicy = { true })
        val extras = if (withHelper) listOf(RecoverySource("NORMAL_RECOVERY_HELPER", helper.path, "lib/libksud_ksu.so", 0x1c0)) else emptyList()
        assertTrue(bundle.prepare("dev.maplesu.manager", 1, apk.path, extras) is RecoveryPrepareResult.Ok)
        return bundle
    }
    private fun service(
        kernel: Kernel = Kernel(), hidden: Hidden = Hidden(), mode: String? = "KSU",
        withHelper: Boolean = true, hostAbsent: Boolean = true, codeReady: Boolean = true, bootReady: Boolean = true,
        removed: () -> String = { DaemonNormalHidden.SUCCESS },
        installed: () -> Boolean? = { true },
    ) = DaemonNormalHidden(bundle(withHelper), { mode }, DaemonNormalKernel(kernel), hidden, removed, { hostAbsent }, { codeReady }, { bootReady }, installed)

    @Test fun helperParsesOnlyExactSuccessfulMachineReceipts() {
        val shell = Kernel()
        val kernel = DaemonNormalKernel(shell)
        assertTrue(kernel.ready())
        assertEquals(false, kernel.state())
        assertTrue(kernel.set(true))
        assertTrue(kernel.set(false))
        shell.malformed = true
        assertNull(kernel.state())
        assertFalse(kernel.ready())
    }

    @Test fun readinessRequiresExplicitNormalVerifiedHelperNoHostAndIndependentCode() {
        assertTrue(service().ready())
        assertFalse(service(mode = "LITE").ready())
        assertFalse(service(mode = null).ready())
        assertFalse(service(withHelper = false).ready())
        assertFalse(service(hostAbsent = false).ready())
        assertFalse(service(codeReady = false).ready())
        assertFalse(service(bootReady = false).ready())
        assertFalse(service(kernel = Kernel().apply { failOperation = "readiness" }).ready())
    }

    @Test fun activationVerifiesKernelAndCompatibilityStateBeforeSynchronousUninstall() {
        val kernel = Kernel()
        val hidden = Hidden()
        var removed = 0
        val service = service(kernel, hidden, removed = {
            assertTrue(kernel.state); assertTrue(hidden.value); removed++; DaemonNormalHidden.SUCCESS
        })
        assertEquals(DaemonNormalHidden.SUCCESS, service.activate())
        assertEquals(1, removed)
        assertTrue(kernel.state)
        assertTrue(hidden.value)
    }

    @Test fun normalActivationRoutesAreAuthenticatedFixedBodyAndSynchronous() {
        var removed = 0
        val token = "a".repeat(32)
        val core = LiteWebDaemonCore(LiteWebDaemonConfig(18427, token, "KSU"), normalHidden = service(removed = {
            removed++; DaemonNormalHidden.SUCCESS
        }))
        val path = "/x7k9f/$token/api/normal/activate"
        assertEquals(401, core.handle("POST", "/x7k9f/api/normal/activate", emptyMap(), "{}").status)
        assertEquals(404, core.handle("GET", path, emptyMap(), "").status)
        assertEquals(400, core.handle("POST", path, emptyMap(), """{"mode":"LITE"}""").status)
        assertEquals(0, removed)
        assertEquals(200, core.handle("GET", "/x7k9f/$token/api/normal/ready", emptyMap(), "").status)
        val response = core.handle("POST", path, emptyMap(), "{}")
        assertEquals(DaemonNormalHidden.SUCCESS, response.body)
        assertEquals(1, removed)
    }

    @Test fun failedKernelOrCompatibilityWriteNeverUninstalls() {
        var removed = 0
        val kernel = Kernel().apply { failOperation = "on" }
        assertTrue(service(kernel = kernel, removed = { removed++; "{}" }).activate().contains("NORMAL_STEALTH_ON_UNVERIFIED"))
        val hidden = Hidden().apply { failWrite = true }
        val second = Kernel()
        assertTrue(service(kernel = second, hidden = hidden, removed = { removed++; "{}" }).activate().contains("NORMAL_HIDDEN_STATE_UNVERIFIED"))
        assertEquals(0, removed)
        assertFalse(second.state)
    }

    @Test fun failedRemovalRollsBackStealthAndKeepsTheRecoverySession() {
        val kernel = Kernel()
        val hidden = Hidden()
        val service = service(kernel, hidden, removed = { """{"ok":false}""" })
        assertTrue(service.activate().contains("NORMAL_UNINSTALL_UNVERIFIED"))
        assertFalse(kernel.state)
        assertFalse(hidden.value)
        assertTrue(service.ready())
    }

    @Test fun removalFailureAfterPmAbsentKeepsKernelAndBootRecoveryEnabled() {
        val kernel = Kernel()
        val hidden = Hidden()
        var installed = true
        val service = service(kernel, hidden, removed = {
            installed = false
            """{"ok":false,"code":"MANAGER_UNINSTALL_UNVERIFIED"}"""
        }, installed = { installed })
        assertTrue(service.activate().contains("NORMAL_UNINSTALL_UNVERIFIED"))
        assertTrue(kernel.state)
        assertTrue(hidden.value)
        assertFalse(kernel.operations.contains("off"))
        assertTrue(service.ready())
    }

    @Test fun unknownPmStateAfterRemovalFailureKeepsRecoveryEnabled() {
        val kernel = Kernel()
        val hidden = Hidden()
        val service = service(kernel, hidden, removed = { "{}" }, installed = { null })
        assertTrue(service.activate().contains("NORMAL_UNINSTALL_UNVERIFIED"))
        assertTrue(kernel.state)
        assertTrue(hidden.value)
        assertFalse(kernel.operations.contains("off"))
    }

    @Test fun throwingPmStateAfterRemovalFailureKeepsRecoveryEnabled() {
        val kernel = Kernel()
        val hidden = Hidden()
        val service = service(kernel, hidden, removed = { error("PM interrupted") }, installed = { error("PM unavailable") })
        assertTrue(service.activate().contains("NORMAL_UNINSTALL_UNVERIFIED"))
        assertTrue(kernel.state)
        assertTrue(hidden.value)
        assertFalse(kernel.operations.contains("off"))
    }

    @Test fun unsuccessfulRollbackIsReportedAndRecoveryRemainsAvailable() {
        val kernel = Kernel().apply { failOff = true }
        val result = service(kernel = kernel, removed = { "{}" }).activate()
        assertTrue(result.contains("NORMAL_STEALTH_ROLLBACK_FAILED"))
        assertTrue(kernel.state)
        val early = Kernel().apply { failOff = true; failOnAfterWrite = true }
        val earlyResult = service(kernel = early).activate()
        assertTrue(earlyResult.contains("NORMAL_STEALTH_ROLLBACK_FAILED"))
        assertTrue(early.state)
    }

    @Test fun bootEntryRemovalRequiresOneExactSuccessReceipt() {
        val service = service()
        assertTrue(service.removeBootEntry { DaemonShellResult(0, "MAPLESU_NORMAL_BOOT_GONE\n") }.ok)
        assertFalse(service.removeBootEntry { DaemonShellResult(0, "Success") }.ok)
        assertFalse(service.removeBootEntry { DaemonShellResult(1, "MAPLESU_NORMAL_BOOT_GONE") }.ok)
    }

    @Test fun restoreRequiresKernelReadbackOffAndRejectsCrossModeCleanup() {
        val kernel = Kernel().apply { state = true }
        assertTrue(service(kernel = kernel).restoreKernel().ok)
        assertFalse(kernel.state)
        kernel.failOperation = "off"
        assertFalse(service(kernel = kernel).restoreKernel().ok)
        assertFalse(service(mode = "LITE").restoreKernel().ok)
        assertFalse(service(hostAbsent = false).restoreKernel().ok)
    }

    @Test fun normalNeverConstructsUltraSuperuserBackend() {
        var opened = 0
        val factory = { opened++; UnavailableSuperuserPort }
        assertTrue(daemonModeSuperuserPort("KSU", factory) is DaemonNormalSuperuserPort)
        assertSame(UnavailableSuperuserPort, daemonModeSuperuserPort(null, factory))
        assertEquals(0, opened)
        daemonModeSuperuserPort("LITE", factory)
        assertEquals(1, opened)
        assertEquals("KSU", DaemonNormalRuntimeFacts(DaemonNormalKernel(Kernel())).snapshot().mode)
        assertTrue(DaemonNormalRuntimeFacts(DaemonNormalKernel(Kernel())).ultraModules().error.isNotEmpty())
    }

    @Test fun recoveryCodeRejectsDataAppAndMixedClasspaths() {
        val apk = temporary.newFile("manager.apk")
        assertTrue(DaemonRecoveryCode.ready(apk.path, apk.path))
        assertFalse(DaemonRecoveryCode.ready("/data/app/dev.maplesu.manager/base.apk", apk.path))
        assertFalse(DaemonRecoveryCode.ready(apk.path + File.pathSeparator + "extra.apk", apk.path))
    }

    @Test fun normalFullRestoreInstallsBeforeKernelOffAndPreservesRetryOnCleanupFailure() {
        val bundle = bundle()
        val sha = requireNotNull(bundle.verify().manifest).apkSha256
        val kernel = Kernel().apply { state = true; failOff = true }
        val normal = DaemonNormalHidden(bundle, { "KSU" }, DaemonNormalKernel(kernel), Hidden(), { "{}" }, { true }, { true }, { true })
        var installed = false
        var bootRemoved = false
        val service = RecoveryRestoreService(bundle, { script ->
            when {
                script.startsWith("sha256sum") -> RecoveryCommandResult(0, "$sha  manager.apk")
                script.contains("pm install -r ") -> { installed = true; RecoveryCommandResult(0, "Success") }
                script.startsWith("pm path") -> RecoveryCommandResult(0, "package:/data/app/dev.maplesu.manager/base.apk")
                script.contains("MAPLESU_RESTORE_LAUNCHER_OK") -> RecoveryCommandResult(0, "MAPLESU_RESTORE_LAUNCHER_OK")
                script.contains("MAPLESU_RESTORE_DATA_OK") -> RecoveryCommandResult(0, "MAPLESU_RESTORE_DATA_OK")
                script.contains("MAPLESU_RESTORE_HIDDEN_OFF_OK") -> RecoveryCommandResult(0, "MAPLESU_RESTORE_HIDDEN_OFF_OK")
                else -> RecoveryCommandResult(0, "LITE_OK")
            }
        }, cleanup = { assertTrue(installed); normal.restoreKernel() }, finalizeRestoration = {
            bootRemoved = true
            normal.removeBootEntry { DaemonShellResult(0, "MAPLESU_NORMAL_BOOT_GONE") }
        })
        val failed = service.restoreFull()
        assertFalse(failed.ok)
        assertTrue(kernel.state)
        assertFalse(bootRemoved)
        kernel.failOff = false
        val restored = service.restoreFull()
        assertTrue(restored.toString(), restored.ok)
        assertFalse(kernel.state)
        assertTrue(bootRemoved)
        assertTrue(restored.steps.contains("kernel_stealth_off:ok"))
    }
}
