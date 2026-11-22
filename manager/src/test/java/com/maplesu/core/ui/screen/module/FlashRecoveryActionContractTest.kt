package com.maplesu.core.ui.screen.module

import java.io.File
import org.junit.Assert.*
import org.junit.Test

class FlashRecoveryActionContractTest {
    private fun source(name: String): String {
        val path = "src/main/java/com/maplesu/core/ui/screen/flash/$name"
        return listOf(File(path), File("manager/$path")).first { it.isFile }.readText()
    }

    @Test fun recoveryCapabilityAndCallbackDefaultToInactive() {
        val source = source("FlashUiState.kt")
        assertTrue(source.contains("val canRestore: Boolean = false"))
        assertTrue(source.contains("val onRestore: () -> Unit = {}"))
        assertTrue(source.contains("val showCloseAction: Boolean = false"))
        assertTrue(source.contains("val actionInProgress: Boolean = false"))
        assertTrue(source.contains("val onClose: () -> Unit = {}"))
    }

    @Test fun bothThemesRenderRecoveryOnlyAfterRunningOperationsFinish() {
        listOf("FlashMaterial.kt", "FlashMiuix.kt").forEach { name ->
            val source = source(name).substringAfter("private fun FlashResultActions")
            val running = source.indexOf("if (state.flashingStatus == FlashingStatus.FLASHING) return")
            val recovery = source.indexOf("if (state.canRestore)")
            val otherActions = source.indexOf("if (!state.canSaveBoot && !state.showRebootAction && !state.showCloseAction) return")
            assertTrue(name, running >= 0 && recovery > running && otherActions > recovery)
            assertTrue(source.contains("R.string.flash_restore_pre_install"))
            assertTrue(source.contains("onClick = actions.onRestore"))
            assertTrue(source.contains("if (state.showRebootAction || state.showCloseAction)"))
            assertTrue(source.contains("onClick = { if (state.showRebootAction) actions.onReboot() else actions.onClose() }"))
            assertTrue(source.contains("if (state.actionInProgress)"))
            if (name == "FlashMaterial.kt") assertTrue(source.contains("enabled = !state.actionInProgress"))
            else assertTrue(source.indexOf("if (state.actionInProgress)") < source.indexOf("onClick = { if (state.showRebootAction)"))
        }
    }
}
