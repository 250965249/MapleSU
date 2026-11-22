package com.maplesu.core.ui.screen.settings

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Source-order contracts for the Android VM; native tests exercise actual dialog interaction. */
class NormalHiddenUiContractTest {
    private val source = File("src/main/java/com/maplesu/core/ui/viewmodel/SettingsViewModel.kt").readText()

    private fun function(name: String): String {
        val start = Regex("(?m)^    (?:private |override )?fun ${Regex.escape(name)}\\(").find(source)
            ?: error("Missing $name")
        val next = Regex("(?m)^    (?:private |override )?fun ").find(source, start.range.last + 1)
        return source.substring(start.range.first, next?.range?.first ?: source.length)
    }

    private fun before(body: String, first: String, second: String) {
        assertTrue("Missing $first", body.contains(first))
        assertTrue("Missing $second", body.contains(second))
        assertTrue("$first precedes $second", body.indexOf(first) < body.indexOf(second))
    }

    @Test fun enableNoLongerBypassesTheRecoveryConfirmation() {
        val setter = function("setStealthEnabled")
        before(setter, "if (enabled)", "openNormalHidden()")
        before(setter, "openNormalHidden()", "applyToggle(")
        assertTrue(setter.contains("Stealth.setEnabledReporting(false)"))
        assertFalse(setter.contains("Stealth.setEnabledReporting(enabled)"))
        listOf("SettingsMiuix.kt", "SettingsMaterial.kt").forEach { name ->
            val skin = File("src/main/java/com/maplesu/core/ui/screen/settings/$name").readText()
            assertTrue(skin.contains("if (card.operable && !card.enabled)"))
            assertTrue(skin.contains("onClick = actions.onOpenNormalHidden"))
        }
    }

    @Test fun preparationRespondsBeforeIoAndSerializesCancelledRequests() {
        val body = function("prepareNormalHidden")
        before(body, "ui.canPrepare", "normalHiddenRevision")
        before(body, "preparing = true", "viewModelScope.launch")
        before(body, "previousPreparation?.join()", "NormalHiddenEnv.create(ksuApp)")
        before(body, "NormalHiddenEnv.create(ksuApp)", "controller?.prepare(ui.portText.toInt())")
        assertTrue(body.contains("revision != normalHiddenRevision"))
        assertFalse(body.contains("activate()"))
    }

    @Test fun cancelInvalidatesTheSessionWithoutHidingOrRemovingAnything() {
        val body = function("dismissNormalHidden")
        before(body, "normalHidden.activating", "normalHiddenRevision++")
        before(body, "normalHiddenRevision++", "normalHiddenController?.cancel()")
        assertTrue(body.contains("normalHiddenUrl = null"))
        assertFalse(body.contains("activate("))
        assertFalse(body.contains("Stealth."))
        assertFalse(body.contains("uninstall"))
    }

    @Test fun cancelledPreparationCannotOverwriteAnImmediatelyReopenedSession() {
        val prepare = function("prepareNormalHidden")
        val cancel = function("dismissNormalHidden")
        before(cancel, "normalHiddenRevision++", "normalHiddenController?.cancel()")
        before(prepare, "val revision = ++normalHiddenRevision", "previousPreparation?.join()")
        before(prepare, "previousPreparation?.join()", "NormalHiddenEnv.create(ksuApp)")
        val afterReceipt = prepare.substringAfter("controller?.prepare(ui.portText.toInt())")
        before(afterReceipt, "revision != normalHiddenRevision", "normalHiddenUrl = result?.recoveryUrl")
        assertTrue(afterReceipt.substringBefore("val ready").contains("controller?.cancel()"))
        val refresh = function("refresh")
        assertFalse("Background settings refresh must preserve the active confirmation", refresh.contains("normalHidden ="))
        val cleared = function("onCleared")
        assertTrue(cleared.contains("normalHiddenController?.cancel()"))
        assertFalse("Confirmed daemon activation must not be interrupted", cleared.contains("normalHiddenPreparation?.cancel()"))
    }

    @Test fun activationRequiresSavedLinkAndMarksBusyBeforeCallingBackend() {
        val body = function("confirmNormalHidden")
        before(body, "normalHidden.canConfirm", "activating = true")
        before(body, "activating = true", "controller.activate()")
        before(body, "result?.ok == true", "completed = true")
        assertTrue(body.contains("NormalHiddenFailure.ACTIVATE"))
        assertTrue(body.contains("normalHiddenUrl = null"))
    }

    @Test fun openingOnlyLoadsThePortAndPreparationStartsAfterUserConfirmation() {
        val open = function("openNormalHidden")
        assertTrue(open.contains("NormalHiddenEnv.configuredPort()"))
        assertFalse(open.contains("RecoveryWebUiControl().status()"))
        assertFalse(open.contains("prepareNormalHidden()"))
        val dialog = File("src/main/java/com/maplesu/core/ui/screen/settings/NormalHiddenDialog.kt").readText()
        assertTrue(dialog.contains("onConfirm = onPrepare"))
        assertTrue(dialog.contains("onSaveLink(); onConfirm()"))
        assertFalse(dialog.contains("normal_hidden_webui_stop"))
    }

    @Test fun probeAndPreparationReleaseBusyStateOnEveryExitWithoutClobberingANewerSession() {
        val open = function("openNormalHidden")
        val prepare = function("prepareNormalHidden")
        for (body in listOf(open, prepare)) {
            assertTrue(body.contains("catch (cancelled: kotlinx.coroutines.CancellationException)"))
            assertTrue(body.contains("throw cancelled"))
            val cleanup = body.substringAfter("} finally {", "")
            assertTrue(cleanup.contains("revision == normalHiddenRevision"))
        }
        assertTrue(open.substringAfter("} finally {").contains("checkingWebUi = false"))
        val preparationCleanup = prepare.substringAfter("} finally {")
        assertTrue(preparationCleanup.contains("preparing = false"))
        assertTrue(preparationCleanup.contains("failure = NormalHiddenFailure.PREPARE"))
        assertFalse(preparationCleanup.contains("activate("))
    }

    @Test fun linksStayOutsideUiSnapshotsAndLogs() {
        val ui = File("src/main/java/com/maplesu/core/ui/screen/settings/NormalHiddenUi.kt").readText()
        assertFalse(ui.contains("val recoveryUrl"))
        assertFalse(ui.contains("val url"))
        assertTrue(source.contains("private var normalHiddenUrl: String? = null"))
        assertTrue(function("firstFrameState").contains("normalHidden = NormalHiddenUi()"))
        source.lineSequence().filter { it.contains("normalHiddenUrl") }.forEach { line ->
            assertFalse(line.contains("Log."))
            assertFalse(line.contains("repo."))
            assertFalse(line.contains("println"))
        }
    }

    @Test fun dialogUsesBothNativeSkinsAndExplainsActualRemoval() {
        val dialog = File("src/main/java/com/maplesu/core/ui/screen/settings/NormalHiddenDialog.kt").readText()
        val components = File("src/main/java/com/maplesu/core/ui/screen/host/HiddenFlowComponents.kt").readText()
        assertTrue(dialog.contains("HiddenFlowDialog("))
        assertTrue(dialog.contains("ui.canConfirm || ui.canSaveLink"))
        assertTrue(dialog.contains("dismissEnabled = !ui.activating"))
        assertTrue(components.contains("UiMode.Miuix -> WindowDialog("))
        assertTrue(components.contains("UiMode.Material -> AlertDialog("))
        val copy = File("src/main/res/values-zh-rCN/strings_normal_hidden.xml").readText()
        listOf("管理器将卸载", "配对数据保留", "保存恢复链接", "启动隐藏").forEach {
            assertTrue("Missing user-facing fact $it", copy.contains(it))
        }
    }
}
