package dev.maplesu.manager.recovery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException

class RecoveryTemporaryFilesTest {
    private val staged = "/data/local/tmp/maplesu-install-123.apk"

    @Test
    fun failedCopyRemovesThePartialApk() {
        val scripts = mutableListOf<String>()
        assertNull(stageApkForInstall({
            scripts += it
            RecoveryCommandResult(1, "")
        }, "/data/adb/maplesu/recovery/manager.apk"))
        assertEquals(2, scripts.size)
        assertTrue(scripts.last().startsWith("rm -f '/data/local/tmp/maplesu-install-"))
    }

    @Test
    fun lostCopyReceiptStillRemovesTheApk() {
        val scripts = mutableListOf<String>()
        assertNull(stageApkForInstall({
            scripts += it
            RecoveryCommandResult(0, "")
        }, "/data/adb/maplesu/recovery/manager.apk"))
        assertTrue(scripts.last().startsWith("rm -f "))
    }

    @Test
    fun interruptedCopyStillRunsCleanup() {
        val scripts = mutableListOf<String>()
        val interruption = IOException("copy interrupted")
        try {
            stageApkForInstall({
                scripts += it
                if (it.startsWith("cp -f ")) throw interruption
                RecoveryCommandResult(0, "LITE_OK")
            }, "/data/adb/maplesu/recovery/manager.apk")
            fail("copy interruption should propagate")
        } catch (error: IOException) {
            assertTrue(error === interruption)
        }
        assertTrue(scripts.last().startsWith("rm -f "))
    }

    @Test
    fun installSuccessAndFailureBothRemoveTheApkAndPreserveTheResult() {
        for (code in listOf(0, 1)) {
            val scripts = mutableListOf<String>()
            val result = RecoveryCommandResult(code, if (code == 0) "Success" else "Failure")
            assertEquals(result, installStagedApk({
                scripts += it
                if (it.contains("pm install -r ")) result else RecoveryCommandResult(0, "LITE_OK")
            }, staged))
            assertEquals(2, scripts.size)
            assertTrue(scripts.first().contains("trap 'rm -f \"$staged\"' EXIT"))
            assertTrue(scripts.first().contains("trap 'exit 143' TERM"))
            assertTrue(scripts.last().startsWith("rm -f '$staged'"))
        }
    }

    @Test
    fun interruptedInstallStillRunsCleanup() {
        val scripts = mutableListOf<String>()
        val interruption = IOException("install interrupted")
        try {
            installStagedApk({
                scripts += it
                if (it.contains("pm install -r ")) throw interruption
                RecoveryCommandResult(0, "LITE_OK")
            }, staged)
            fail("install interruption should propagate")
        } catch (error: IOException) {
            assertTrue(error === interruption)
        }
        assertTrue(scripts.last().startsWith("rm -f '$staged'"))
    }
}
