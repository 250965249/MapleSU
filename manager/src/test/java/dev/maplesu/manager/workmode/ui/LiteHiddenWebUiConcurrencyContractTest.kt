package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.liteweb.RecoveryWebUiControl
import dev.maplesu.manager.liteweb.RecoveryWebUiState
import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExecResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The Android-bound ViewModel has no injected dispatcher/runtime seam. These tests lock the
 * production guard/publication order and exercise the real receipt and recovery-link policies;
 * they do not claim to execute the ViewModel's Android lifecycle or coroutine scheduling.
 */
class LiteHiddenWebUiConcurrencyContractTest {
    private val source by lazy {
        File("src/main/java/dev/maplesu/manager/workmode/ui/LiteHiddenViewModel.kt").readText()
    }

    private fun function(name: String): String {
        val header = Regex("(?m)^    (?:private )?fun ${Regex.escape(name)}\\(")
            .find(source) ?: error("Missing production function $name")
        val next = Regex("(?m)^    (?:private )?fun ").find(source, header.range.last + 1)
        return source.substring(header.range.first, next?.range?.first ?: source.length)
    }

    private fun before(body: String, earlier: String, later: String) {
        val first = body.indexOf(earlier)
        val second = body.indexOf(later)
        assertTrue("Missing $earlier", first >= 0)
        assertTrue("Missing $later", second >= 0)
        assertTrue("$earlier must precede $later", first < second)
    }

    private fun guardContains(name: String, vararg conditions: String) {
        val guard = function(name).substringBefore("return")
        conditions.forEach { condition ->
            assertTrue("$name must guard $condition before returning or mutating state", guard.contains(condition))
        }
    }

    @Test fun listenerAndHiddenSnapshotsRejectReadsFromBeforeTheLatestTransaction() {
        val status = function("refreshWebUiStatus")
        before(status, "val revision = webUiStatusRevision", "webUiControl.status()")
        before(status, "webUiControl.status()", "if (revision != webUiStatusRevision) return@launch")
        before(status, "if (revision != webUiStatusRevision) return@launch", "it.copy(webUiState = status.state")

        val hidden = function("refresh")
        before(hidden, "val revision = webUiStatusRevision", "withContext(Dispatchers.IO)")
        before(hidden, "if (revision != webUiStatusRevision) return@launch", "webUiToken = tokenOf(snapshot.cachedUrl)")

        val invalidate = function("invalidateWebUiStatusRead")
        before(invalidate, "webUiStatusRevision++", "webUiStatusJob?.cancel()")
        before(invalidate, "webUiStatusJob?.cancel()", "webUiStatusJob = null")
    }

    @Test fun everyListenerMutatingTransactionInvalidatesOutstandingStatusReads() {
        listOf("confirmStopWebUi", "prepareRecoveryLink", "onConfirmDeactivate").forEach { name ->
            val body = function(name)
            before(body, "invalidateWebUiStatusRead()", "_uiState.update")
            before(body, "invalidateWebUiStatusRead()", "viewModelScope.launch")
        }
        before(function("onConfirmActivate"), "invalidateWebUiStatusRead()", "phase = HiddenCardPhase.ENABLING")
    }

    @Test fun preparationAndDeactivationCannotRunAcrossOneAnother() {
        guardContains("prepareRecoveryLink", "card.preparingLink", "card.stoppingWebUi",
            "card.hostPicker.isRunning", "card.deactivate.visible", "card.confirmStopWebUi")
        guardContains("onDeactivateClick", "card.preparingLink", "card.stoppingWebUi",
            "card.hostPicker.isRunning", "card.confirmStopWebUi")
        guardContains("onConfirmDeactivate", "deactivate.running", "card.preparingLink",
            "card.stoppingWebUi", "card.hostPicker.isRunning", "card.confirmStopWebUi")
    }

    @Test fun stopRechecksCurrentStateInsteadOfTrustingAnOldConfirmation() {
        guardContains("confirmStopWebUi", "!ui.confirmStopWebUi",
            "ui.webUiState != RecoveryWebUiState.RUNNING", "ui.checkingWebUi",
            "ui.stoppingWebUi", "ui.preparingLink", "ui.hostPicker.isRunning", "ui.deactivate.running")
        val stop = function("confirmStopWebUi")
        before(stop, "webUiLinkAvailable = false", "webUiControl.stop()")
        before(stop, "recoveryLinkSaved = false", "webUiControl.stop()")
    }

    @Test fun statusProbesCannotPublishInTheMiddleOfAListenerTransaction() {
        guardContains("refreshWebUiStatus", "webUiStatusJob?.isActive", "ui.stoppingWebUi",
            "ui.preparingLink", "ui.hostPicker.isRunning", "ui.deactivate.running")
        val status = function("refreshWebUiStatus")
        assertTrue(status.contains("webUiLinkAvailable = it.webUiLinkAvailable && running"))
        assertTrue(status.contains("recoveryLinkSaved = it.recoveryLinkSaved && running"))
        assertTrue(status.contains("confirmStopWebUi = it.confirmStopWebUi && running"))
    }

    @Test fun prepareFailureRechecksTheListenerWhichMayHaveStartedBeforeProbeFailure() {
        val failure = function("prepareRecoveryLink")
            .substringAfter("if (prepared == null) {").substringBefore("return@launch")
        assertTrue(failure.contains("preparingLink = false"))
        assertTrue(failure.contains("webUiState = RecoveryWebUiState.UNKNOWN"))
        assertTrue(failure.contains("webUiLinkAvailable = false"))
        assertTrue(failure.contains("recoveryLinkSaved = false"))
        before(failure, "preparingLink = false", "refreshWebUiStatus()")

        val listener = RecoveryWebUiControl {
            RootExecResult(RootBackend.ULTRA_ENV, 0, "MAPLESU_WEBUI_CONTROL RUNNING OK")
        }.status()
        assertEquals(RecoveryWebUiState.RUNNING, listener.state)
        assertFalse("A live listener alone is not an authenticated/saved recovery link",
            LiteHiddenRecoveryLinkPolicy.canActivate(true, false, false, false))
    }

    @Test fun successfulAndPartialDeactivationBothDiscardLinksAndRecheckAfterFinishing() {
        val deactivate = function("onConfirmDeactivate")
        before(deactivate, "webUiLinkAvailable = false", "LiteHiddenRuntimeProxy.deactivate(host)")
        before(deactivate, "recoveryLinkSaved = false", "LiteHiddenRuntimeProxy.deactivate(host)")
        val success = deactivate.substringAfter("if (ok) {").substringBefore("return@launch")
        before(success, "HostPickerPolicy.deactivateFinished(", "refreshWebUiStatus()")
        val failed = deactivate.substringAfter("val res = LiteHiddenRuntimeProxy.failureMessageRes(failure)")
        before(failed, "HostPickerPolicy.deactivateFinished(", "refreshWebUiStatus()")
        assertEquals(2, Regex("refreshWebUiStatus\\(\\)").findAll(deactivate).count())

        val stopped = RecoveryWebUiControl {
            RootExecResult(RootBackend.ULTRA_ENV, 0, "MAPLESU_WEBUI_CONTROL STOPPED OK")
        }.status()
        assertEquals(RecoveryWebUiState.STOPPED, stopped.state)
        assertFalse(LiteHiddenRecoveryLinkPolicy.canActivate(true, false, true, false))
    }

    @Test fun activationCannotReuseAStoppedOrUnpreparedRecoveryLink() {
        guardContains("onConfirmActivate", "!card.canActivate", "card.stoppingWebUi",
            "card.confirmStopWebUi", "card.deactivate.visible")
        assertFalse(LiteHiddenPageUi(webUiLinkAvailable = false, recoveryLinkSaved = true).canActivate)
        assertFalse(LiteHiddenRecoveryLinkPolicy.canActivate(true, true, true, true))
        assertTrue(LiteHiddenRecoveryLinkPolicy.canActivate(true, true, true, false))
    }
}
