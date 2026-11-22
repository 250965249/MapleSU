package com.maplesu.core.ui.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RebootPolicyTest {
    private class Fixture(backend: RebootBackend) {
        val calls = mutableListOf<String>()
        var accepted = true
        val dispatcher = RebootDispatcher(
            backend,
            restartUltra = { calls += "ultra-sdk"; accepted },
            runRoot = { calls += it; accepted },
        )
    }

    @Test fun ultraUsesItsSdkAndNeverEntersKsuOrHardwareReboot() {
        val fixture = Fixture(RebootBackend.ULTRA)
        assertTrue(fixture.dispatcher.execute("soft_reboot"))
        assertEquals(listOf("ultra-sdk"), fixture.calls)
    }

    @Test fun normalUsesTheDeployedKsuDaemon() {
        val fixture = Fixture(RebootBackend.NORMAL)
        assertTrue(fixture.dispatcher.execute("soft_reboot"))
        assertEquals(listOf("/data/adb/ksud soft-reboot"), fixture.calls)
    }

    @Test fun directRestartsFrameworkThroughTheExistingPropertyRoute() {
        val fixture = Fixture(RebootBackend.DIRECT)
        assertTrue(fixture.dispatcher.execute("soft_reboot"))
        assertEquals(listOf("/system/bin/setprop ctl.restart zygote64 || " +
            "/system/bin/setprop ctl.restart zygote"), fixture.calls)
    }

    @Test fun hookRestartsOnlyZygoteWhenInitRejectsTheControlProperties() {
        val fixture = Fixture(RebootBackend.HOOK)
        assertTrue(fixture.dispatcher.execute("soft_reboot"))
        val command = fixture.calls.single()
        assertTrue(command.startsWith("/system/bin/setprop ctl.restart zygote64 || " +
            "/system/bin/setprop ctl.restart zygote || "))
        assertTrue(command.contains("/system/bin/pidof zygote64 zygote"))
        assertTrue(command.contains("[ -n \"${'$'}zygotes\" ] && /system/bin/kill -9 ${'$'}zygotes"))
        assertFalse(command.contains("/system/bin/reboot"))
        assertFalse(command.contains("sys.powerctl"))
    }

    @Test fun rejectedSoftRestartIsReportedWithoutFallingThroughToAnotherRoute() {
        RebootBackend.entries.forEach { backend ->
            val fixture = Fixture(backend).apply { accepted = false }
            assertFalse(fixture.dispatcher.execute("soft_reboot"))
            assertEquals(1, fixture.calls.size)
        }
    }

    @Test fun normalAndHookIdentityTakePriorityOverCachedUltraEvidence() {
        assertEquals(RebootBackend.NORMAL, RebootDispatcher.backend(true, true, true, false))
        assertEquals(RebootBackend.HOOK, RebootDispatcher.backend(false, true, true, false))
        assertEquals(RebootBackend.ULTRA, RebootDispatcher.backend(false, false, true, false))
        assertEquals(RebootBackend.DIRECT, RebootDispatcher.backend(false, false, false, false))
    }

    @Test fun verifiedUltraIdentityPrecedesAnOldHookRegardlessOfCachedAvailability() {
        listOf(false, true).forEach { ultraRunning ->
            listOf(false, true).forEach { hook ->
                assertEquals(RebootBackend.ULTRA,
                    RebootDispatcher.backend(false, hook, ultraRunning, true))
            }
        }
    }

    @Test fun normalIdentityStillPrecedesBothVerifiedUltraAndHook() {
        assertEquals(RebootBackend.NORMAL, RebootDispatcher.backend(true, true, true, true))
        assertEquals(RebootBackend.NORMAL, RebootDispatcher.backend(true, false, false, true))
    }

    @Test fun plainRebootUsesTheCurrentRootBackendWithoutAnInstallationLookup() {
        RebootBackend.entries.forEach { backend ->
            val fixture = Fixture(backend)
            assertTrue(fixture.dispatcher.execute(""))
            val expected = if (backend == RebootBackend.HOOK)
                "/system/bin/toybox runcon u:r:init:s0 /system/bin/reboot"
                else "/system/bin/svc power reboot || /system/bin/reboot"
            assertEquals(listOf(expected), fixture.calls)
        }
    }

    @Test fun hookHardwareRebootUsesThePlatformPowerDomainWithoutSvc() {
        listOf("", "userspace", "recovery", "bootloader", "download", "edl").forEach { reason ->
            val fixture = Fixture(RebootBackend.HOOK)
            assertTrue(fixture.dispatcher.execute(reason))
            val expected = (if (reason == "recovery") "/system/bin/input keyevent 26 >/dev/null 2>&1; " else "") +
                "/system/bin/toybox runcon u:r:init:s0 /system/bin/reboot" +
                if (reason.isEmpty()) "" else " $reason"
            assertEquals(listOf(expected), fixture.calls)
        }
    }

    @Test fun aRejectedPlainRebootDoesNotBindAHistoryTaskOrStartAnotherRoute() {
        val fixture = Fixture(RebootBackend.ULTRA).apply { accepted = false }
        assertFalse(fixture.dispatcher.execute(""))
        assertEquals(listOf("/system/bin/svc power reboot || /system/bin/reboot"), fixture.calls)
    }

    @Test fun hardwareReasonsRemainDistinctAndPreserveTheSelectedReason() {
        listOf("userspace", "recovery", "bootloader", "download", "edl").forEach { reason ->
            val fixture = Fixture(RebootBackend.NORMAL)
            assertTrue(fixture.dispatcher.execute(reason))
            val expected = (if (reason == "recovery") "/system/bin/input keyevent 26 >/dev/null 2>&1; " else "") +
                "/system/bin/svc power reboot $reason || /system/bin/reboot $reason"
            assertEquals(listOf(expected), fixture.calls)
        }
    }

    @Test fun invalidReasonsNeverEnterAnyPrivilegedOperation() {
        listOf("soft", "reboot,soft_reboot", "recovery; reboot", "bootloader\nreboot", "--help").forEach { reason ->
            val fixture = Fixture(RebootBackend.NORMAL)
            assertFalse(fixture.dispatcher.execute(reason))
            assertTrue(fixture.calls.isEmpty())
        }
    }

    @Test fun failedRootCommandDoesNotReportRebootSuccess() {
        val fixture = Fixture(RebootBackend.NORMAL).apply { accepted = false }
        assertFalse(fixture.dispatcher.execute("bootloader"))
        assertEquals(1, fixture.calls.size)
    }

    @Test fun uninstalledAndStillConfirmingHomeDoNotExposeRebootMenu() {
        assertTrue(RebootDispatcher.showMenu(installed = true, confirming = false))
        assertFalse(RebootDispatcher.showMenu(installed = false, confirming = false))
        assertFalse(RebootDispatcher.showMenu(installed = true, confirming = true))
        assertFalse(RebootDispatcher.showMenu(installed = false, confirming = true))
    }
}
