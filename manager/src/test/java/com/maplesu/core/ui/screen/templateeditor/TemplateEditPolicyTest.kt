package com.maplesu.core.ui.screen.templateeditor

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class TemplateEditPolicyTest {
    @Test fun changedDraftRequiresConfirmation() {
        assertTrue(templateNeedsDiscardConfirmation("original", "draft", readOnly = false))
    }

    @Test fun unchangedOrReadOnlyDraftReturnsDirectly() {
        assertFalse(templateNeedsDiscardConfirmation("same", "same", readOnly = false))
        assertFalse(templateNeedsDiscardConfirmation("original", "draft", readOnly = true))
    }

    @Test fun revertingAllChangesRemovesTheConfirmation() {
        data class Template(val id: String, val name: String, val rules: List<String>)
        val original = Template("template.id", "Name", listOf("rule"))
        val reverted = original.copy(name = "Edited").copy(name = original.name)
        assertFalse(templateNeedsDiscardConfirmation(original, reverted, readOnly = false))
    }

    @Test fun screenUsesExplicitIoPersistenceAndNativeConfirmation() {
        val source = File("src/main/java/com/maplesu/core/ui/screen/templateeditor/TemplateEditorScreen.kt").readText()
        assertFalse(source.contains("val autoSave"))
        assertFalse(source.contains("isTemplateExist(value)"))
        assertTrue(source.contains("withContext(Dispatchers.IO)"))
        assertTrue(source.contains("saveTemplate(draft, isCreation)"))
        assertTrue(source.contains("deleteAppProfileTemplate(template.id)"))
        assertTrue(source.contains("NavigationBackHandler("))
        assertTrue(source.contains("confirmDialog.awaitConfirm("))
        for (name in listOf("TemplateEditorMaterial.kt", "TemplateEditorMiuix.kt")) {
            val skin = File("src/main/java/com/maplesu/core/ui/screen/templateeditor/$name").readText()
            assertTrue(name, skin.contains("isBusy = state.isBusy"))
            assertTrue(name, skin.contains("enabled = !isBusy"))
        }
    }
}
