package com.maplesu.core.ui.screen.settings

import dev.maplesu.manager.liteweb.RecoveryWebUiState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure confirmation rules. No Android runtime, controller or root operations. */
class NormalHiddenUiTest {
    private val ready = NormalHiddenUi(visible = true, linkAvailable = true,
        linkAccessed = true, linkSaved = true, webUiState = RecoveryWebUiState.RUNNING)

    @Test fun closedOrUnpreparedCannotConfirm() {
        assertFalse(NormalHiddenUi().canConfirm)
        assertFalse(NormalHiddenUi(visible = true).canConfirm)
        assertFalse(ready.copy(visible = false).canConfirm)
        assertFalse(ready.copy(linkAvailable = false).canConfirm)
    }

    @Test fun copyingOrOpeningAloneDoesNotConfirmSaved() {
        assertFalse(ready.copy(linkSaved = false).canConfirm)
        assertTrue(ready.copy(linkSaved = false).canSaveLink)
        assertFalse(ready.copy(linkAccessed = false).canConfirm)
        assertFalse(ready.copy(linkAccessed = false, linkSaved = false).canSaveLink)
    }

    @Test fun explicitSavedPreparedLinkAllowsConfirmation() {
        assertTrue(ready.canConfirm)
        assertFalse(ready.canSaveLink)
    }

    @Test fun preparingOrActivatingDisablesRepeatedConfirmation() {
        listOf(ready.copy(preparing = true), ready.copy(activating = true)).forEach {
            assertTrue(it.busy)
            assertFalse(it.canConfirm)
            assertFalse(it.canSaveLink)
        }
    }

    @Test fun failedPreparationAndActivationRequireAFreshLink() {
        listOf(NormalHiddenFailure.PREPARE, NormalHiddenFailure.ACTIVATE).forEach {
            val failed = NormalHiddenUi(visible = true, failure = it)
            assertFalse(failed.busy)
            assertFalse(failed.canConfirm)
            assertFalse(failed.canSaveLink)
        }
    }

    @Test fun readingPortBlocksPreparationAndConfirmation() {
        val reading = ready.copy(checkingWebUi = true)
        assertTrue(reading.busy)
        assertFalse(reading.canPrepare)
        assertFalse(reading.canConfirm)
        assertFalse(reading.canSaveLink)
    }

    @Test fun completedFlowCannotActivateAgain() {
        assertFalse(ready.copy(completed = true).canConfirm)
        assertFalse(ready.copy(completed = true, linkSaved = false).canSaveLink)
    }

    @Test fun portChangesInvalidateOnlyThePreparedConfirmation() {
        val changed = ready.withPort("18437")
        assertEquals("18437", changed.portText)
        assertTrue(changed.portValid)
        assertFalse(changed.linkAvailable)
        assertFalse(changed.linkAccessed)
        assertFalse(changed.linkSaved)
        assertFalse(changed.canConfirm)
        assertEquals(ready, ready.withPort(ready.portText))
        assertEquals(ready.copy(preparing = true), ready.copy(preparing = true).withPort("18437"))
        assertEquals(ready.copy(activating = true), ready.copy(activating = true).withPort("18437"))
    }

    @Test fun invalidPortsNeverAllowConfirmation() {
        for (port in listOf("", "0", "1023", "65536", "99999")) {
            assertFalse(port, ready.copy(portText = port).portValid)
            assertFalse(port, ready.copy(portText = port).canConfirm)
        }
        assertTrue(ready.copy(portText = "1024").portValid)
        assertTrue(ready.copy(portText = "65535").portValid)
    }
}
