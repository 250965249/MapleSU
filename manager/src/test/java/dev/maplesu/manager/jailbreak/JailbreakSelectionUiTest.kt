package dev.maplesu.manager.jailbreak

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class JailbreakSelectionUiTest {
    @Test fun dirtyfragNeverRequestsGhostlockImages() {
        listOf(false, true).forEach { ready ->
            assertFalse(JailbreakSelectionUi(JailbreakMethod.DIRTYFRAG, ready).showGhostlockConfiguration)
        }
    }

    @Test fun onlyUnpreparedGhostlockShowsConfiguration() {
        assertTrue(JailbreakSelectionUi(JailbreakMethod.GHOSTLOCK, false).showGhostlockConfiguration)
        assertFalse(JailbreakSelectionUi(JailbreakMethod.GHOSTLOCK, true).showGhostlockConfiguration)
    }

    @Test fun dirtyfragDoesNotDependOnGhostlockProfileOrReplacement() {
        val dirtyfrag = JailbreakSelectionUi(JailbreakMethod.DIRTYFRAG, false)
        assertTrue(dirtyfrag.canStart(false, true, false, false, false))
        assertTrue(dirtyfrag.canStart(false, true, false, false, true))
    }

    @Test fun ghostlockStartsOnlyWithAReadyProfileAndConfirmedReplacement() {
        assertFalse(JailbreakSelectionUi(JailbreakMethod.GHOSTLOCK, false)
            .canStart(false, true, false, false, false))
        val ghostlock = JailbreakSelectionUi(JailbreakMethod.GHOSTLOCK, true)
        assertTrue(ghostlock.canStart(false, true, false, false, false))
        assertFalse(ghostlock.canStart(false, true, false, false, true))
    }

    @Test fun bothMethodsWaitForChecksAndParsingAndPreventDuplicateRuns() {
        JailbreakMethod.entries.forEach { method ->
            val ui = JailbreakSelectionUi(method, true)
            assertFalse(ui.canStart(true, true, false, false, false))
            assertFalse(ui.canStart(false, false, false, false, false))
            assertFalse(ui.canStart(false, true, true, false, false))
            assertFalse(ui.canStart(false, true, false, true, false))
        }
    }

    @Test fun productionWindowUsesThePresentationGateAndRetainsInputAcrossSelections() {
        val source = File("src/main/java/dev/maplesu/manager/jailbreak/JailbreakSelectionDialog.kt").readText()
        assertTrue(source.contains("if (selectionUi.showGhostlockConfiguration && ui.ghostlockDecided)"))
        assertTrue(source.contains("JailbreakSelectionDialogContent("))
        assertTrue(source.contains("onMethodSelected = { selected = it.name }"))
        assertTrue(source.contains("var otaUrl by rememberSaveable"))
        assertTrue(source.contains("var otaState by remember"))
        assertFalse(source.contains("LaunchedEffect(ghostlockEnabled, ghostlockDecided)"))
        assertFalse(source.contains("if (ghostlockDecided && !ghostlockEnabled)"))
        assertTrue(source.contains("checkedMethod == method && checkedStoreVersion == storeVersion"))
        assertTrue(source.contains("JailbreakController.run(context, method, rebootRequested, rootTarget)"))
        assertTrue(source.contains("JailbreakController.cancel(context)"))
    }

    @Test fun nativeComponentsFollowTheSelectedSkinAndActionsStayOutsideTheBody() {
        val source = File("src/main/java/dev/maplesu/manager/jailbreak/JailbreakSelectionDialog.kt").readText()
        listOf("HiddenFlowDialog(", "hiddenFlowColors()", "LocalUiMode.current",
            "top.yukonga.miuix.kmp.basic.TextField(", "top.yukonga.miuix.kmp.basic.RadioButton(",
            "top.yukonga.miuix.kmp.preference.SwitchPreference(", "OutlinedTextField(", "Surface(").forEach {
            assertTrue("missing native presentation: $it", source.contains(it))
        }
        assertFalse(source.contains("isSystemInDarkTheme"))
        assertFalse(source.contains("availableMethodColor"))
        assertFalse(source.contains("MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)"))
        assertTrue(source.contains("confirmEnabled = (ui.running || ui.canStart || ui.succeeded) && !ui.cancellationPending"))
        assertTrue(source.contains("dismissEnabled = !ui.running"))
    }

    @Test fun modeNamesUseTheRequestedProductCopy() {
        val zh = File("src/main/res/values-zh-rCN/maplesu_jailbreak.xml").readText()
        assertTrue(zh.contains("MapleSU_Ultra（无痕模式）"))
        assertTrue(zh.contains("MapleSU_Normal（玩机兼容模式）"))
        assertFalse(zh.contains("三种方式"))
    }
}
