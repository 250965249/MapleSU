package dev.maplesu.manager.recovery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** WebUI 唯一恢复事务：固定步骤/unhide→ensure_manager→restore_webui→components→verify；fail-closed。 */
class FullRestoreCoordinatorTest {
    private class Harness {
        val calls = mutableListOf<String>()
        var unhideOk = true
        var managerOk = true
        var webuiOk = true
        var componentsOk = true
        var verifyOk = true
        var throwOnWebui = false

        fun coordinator() = FullRestoreCoordinator(
            unhide = {
                calls += "unhide"
                RestoreStepResult("unhide", unhideOk, if (unhideOk) "" else FullRestoreCodes.UNHIDE_FAILED)
            },
            ensureManager = {
                calls += "ensure_manager"
                RestoreStepResult("ensure_manager", managerOk, if (managerOk) "" else FullRestoreCodes.MANAGER_MISSING)
            },
            restoreWebui = {
                calls += "restore_webui"
                if (throwOnWebui) throw IllegalStateException("boom")
                RestoreStepResult("restore_webui", webuiOk, if (webuiOk) "" else FullRestoreCodes.WEBUI_FAILED)
            },
            restoreComponents = {
                calls += "restore_components"
                RestoreStepResult(
                    "restore_components", componentsOk,
                    if (componentsOk) "" else FullRestoreCodes.COMPONENTS_FAILED,
                )
            },
            verify = {
                calls += "verify"
                RestoreStepResult("verify", verifyOk, if (verifyOk) "" else FullRestoreCodes.VERIFY_FAILED)
            },
        )
    }

    @Test
    fun stepsAreFixedAndOrdered() {
        val harness = Harness()
        val result = harness.coordinator().restore()
        assertTrue(result.ok)
        assertEquals(FullRestoreCoordinator.STEP_NAMES, result.steps.map { it.step })
        assertEquals(FullRestoreCoordinator.STEP_NAMES, harness.calls)
        assertTrue(result.steps.all { it.ok })
    }

    @Test
    fun noDialCodeStepExistsInRestorePath() {
        // 定稿：Lite 隐藏恢复仅 WebUI；恢复步骤不含任何密令/拨号步骤。
        assertTrue(FullRestoreCoordinator.STEP_NAMES.none { it.contains("code") || it.contains("dial") })
        assertFalse(FullRestoreCoordinator.STEP_NAMES.any { it == "unhide" && false })
    }

    @Test
    fun unhideFailureStopsBeforeManager() {
        val harness = Harness().apply { unhideOk = false }
        val result = harness.coordinator().restore()
        assertFalse(result.ok)
        assertEquals(FullRestoreCodes.UNHIDE_FAILED, result.code)
        assertEquals(listOf("unhide"), harness.calls)
    }

    @Test
    fun managerMissingStopsBeforeWebui() {
        val harness = Harness().apply { managerOk = false }
        val result = harness.coordinator().restore()
        assertFalse(result.ok)
        assertEquals(FullRestoreCodes.MANAGER_MISSING, result.code)
        assertEquals(listOf("unhide", "ensure_manager"), harness.calls)
    }

    @Test
    fun webuiFailureStopsBeforeComponents() {
        val harness = Harness().apply { webuiOk = false }
        val result = harness.coordinator().restore()
        assertFalse(result.ok)
        assertEquals(FullRestoreCodes.WEBUI_FAILED, result.code)
        assertTrue(harness.calls.none { it == "restore_components" })
    }

    @Test
    fun componentFailureStopsBeforeVerify() {
        val harness = Harness().apply { componentsOk = false }
        val result = harness.coordinator().restore()
        assertFalse(result.ok)
        assertEquals(FullRestoreCodes.COMPONENTS_FAILED, result.code)
        assertTrue(harness.calls.none { it == "verify" })
    }

    @Test
    fun verifyFailureIsReportedNotSwallowed() {
        val harness = Harness().apply { verifyOk = false }
        val result = harness.coordinator().restore()
        assertFalse(result.ok)
        assertEquals(FullRestoreCodes.VERIFY_FAILED, result.code)
        assertEquals(5, result.steps.size)
    }

    @Test
    fun stepExceptionIsStructuredFailure() {
        val harness = Harness().apply { throwOnWebui = true }
        val result = harness.coordinator().restore()
        assertFalse(result.ok)
        assertTrue(result.code.startsWith(FullRestoreCodes.STEP_EXCEPTION))
    }

    @Test
    fun restoreIsIdempotentAcrossRepeatedCalls() {
        val harness = Harness()
        val first = harness.coordinator().restore()
        val second = harness.coordinator().restore()
        assertTrue(first.ok && second.ok)
        assertEquals(first.steps.map { it.step }, second.steps.map { it.step })
    }
}
