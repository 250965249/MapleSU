package dev.maplesu.manager.liteweb

import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExecResult
import org.junit.Assert.*
import org.junit.Test

class RecoveryWebUiControlTest {
    private fun receipt(text: String, code: Int = 0) = RootExecResult(RootBackend.ULTRA_ENV, code, text)

    @Test fun runningRequiresExplicitVerifiedReceipt() {
        assertEquals(RecoveryWebUiState.RUNNING,
            RecoveryWebUiControl { receipt("MAPLESU_WEBUI_CONTROL RUNNING OK\n") }.status().state)
    }

    @Test fun stoppedRequiresSuccessfulRootAndExactReceipt() {
        for (text in listOf("", "STOPPED", "MAPLESU_WEBUI_CONTROL STOPPED OK extra",
                "MAPLESU_WEBUI_CONTROL STOPPED OK\nMAPLESU_WEBUI_CONTROL RUNNING OK")) {
            assertEquals(text, RecoveryWebUiState.UNKNOWN, RecoveryWebUiControl { receipt(text) }.status().state)
        }
        assertEquals(RecoveryWebUiState.UNKNOWN,
            RecoveryWebUiControl { receipt("MAPLESU_WEBUI_CONTROL STOPPED OK", 1) }.status().state)
        assertEquals(RecoveryWebUiState.STOPPED,
            RecoveryWebUiControl { receipt("MAPLESU_WEBUI_CONTROL STOPPED OK") }.status().state)
    }

    @Test fun exceptionsAndReadFailuresRemainUnknown() {
        assertEquals(RecoveryWebUiState.UNKNOWN, RecoveryWebUiControl { error("fixture") }.status().state)
        val value = RecoveryWebUiControl { receipt("MAPLESU_WEBUI_CONTROL UNKNOWN PROC_UNREADABLE", 1) }.status()
        assertEquals(RecoveryWebUiState.UNKNOWN, value.state)
        assertEquals("PROC_UNREADABLE", value.error)
    }

    @Test fun stopNeverAcceptsStillRunningOrFailedReceipts() {
        assertEquals(RecoveryWebUiState.UNKNOWN,
            RecoveryWebUiControl { receipt("MAPLESU_WEBUI_CONTROL RUNNING OK") }.stop().state)
        assertEquals(RecoveryWebUiState.UNKNOWN,
            RecoveryWebUiControl { receipt("MAPLESU_WEBUI_CONTROL STOPPED OK", 1) }.stop().state)
    }

    @Test fun stopUsesDedicatedControlAndPreservesRecoveryMaterials() {
        var script = ""
        val result = RecoveryWebUiControl { script = it; receipt("MAPLESU_WEBUI_CONTROL STOPPED OK") }.stop()
        assertEquals(RecoveryWebUiState.STOPPED, result.state)
        assertTrue(script.contains("webui.paused"))
        assertFalse(script.contains("parasite-start.sh"))
        assertFalse(script.contains("lite_hidden"))
        assertFalse(script.contains("rootkey"))
        assertFalse(script.contains("host/"))
        assertFalse(script.contains("pkill"))
    }

    @Test fun scriptsVerifyUidCmdlineClasspathAndListeningSockets() {
        val script = RecoveryWebUiScripts.inspect()
        for (text in listOf("/status", "/cmdline", "/environ", "CLASSPATH=", "Uid:", "maplesu-liteweb", "|main|",
                "/data/app/", "dev.maplesu.manager-", "/proc/net/tcp", "/proc/net/tcp6", "0A",
                "CONFIG_UNREADABLE", "PROC_UNREADABLE", "SOCKETS_UNREADABLE")) {
            assertTrue(text, script.contains(text))
        }
        assertFalse(script.contains("kill -TERM"))
        assertFalse(script.contains("webui.paused.tmp"))
    }

    @Test fun stopConfirmsAbsenceAfterSignallingAndBeforeSuccess() {
        val script = RecoveryWebUiScripts.stop()
        assertTrue(script.indexOf("webui.paused.tmp") < script.indexOf("kill -TERM"))
        assertTrue(script.indexOf("kill -TERM") < script.lastIndexOf("inspect_state"))
        assertTrue(script.contains("kill -KILL"))
        assertTrue(script.contains("STOP_VERIFY_FAILED"))
        assertTrue(script.contains("identity \"\$TARGET\""))
    }

    @Test fun explicitStartClearsOnlyPauseMarker() {
        val script = RecoveryWebUiScripts.resume()
        assertTrue(script.contains("webui.paused"))
        assertTrue(script.contains("rm -f"))
        assertTrue(script.contains("PAUSE_CLEAR_FAILED"))
        assertFalse(script.contains("token"))
        assertFalse(script.contains("parasite-start.sh"))
    }
}
