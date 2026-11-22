"""Fast production-wiring checks; no Android SDK, device, or Gradle invocation."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / "manager/src/main/java/com/maplesu/core/ui"


class EditingWiringRegressionTest(unittest.TestCase):
    def test_grant_changes_preserve_existing_profile(self):
        source = (UI / "screen/appprofile/AppProfileScreen.kt").read_text(encoding="utf-8")
        self.assertIn("val profileToSave = updatedProfile.copy(", source)
        self.assertNotIn("val profileToSave = Natives.Profile(", source)

    def test_grant_writes_are_serial_and_stale_results_are_ignored(self):
        source = (UI / "screen/appprofile/AppProfileScreen.kt").read_text(encoding="utf-8")
        self.assertIn("saveMutex.withLock", source)
        self.assertIn("policy.complete(request, profileToSave, saved)", source)
        self.assertNotIn("profile = previousProfile", source)

    def test_pending_grant_does_not_claim_wiring_truth(self):
        source = (UI / "screen/appprofile/AppProfileScreen.kt").read_text(encoding="utf-8")
        self.assertIn("isSaving = saving", source)
        self.assertNotIn("suState = if (", source)
        self.assertIn("loadAttempt, saving)", source)
        self.assertIn("if (saving) return@LaunchedEffect", source)
        for skin in ("AppProfileMiuix.kt", "AppProfileMaterial.kt"):
            skin_source = (UI / "screen/appprofile" / skin).read_text(encoding="utf-8")
            self.assertIn("isSaving = state.isSaving", skin_source)
            self.assertIn("if (isSaving) R.string.ui_editing_saving_authorization else suStateLabel(suState)", skin_source)

    def test_template_edits_are_local_and_do_not_run_shell_per_key(self):
        source = (UI / "screen/templateeditor/TemplateEditorScreen.kt").read_text(encoding="utf-8")
        self.assertNotIn("val autoSave", source)
        self.assertNotIn("saveTemplate(updatedTemplate)", source)
        self.assertNotIn("isTemplateExist(value)", source)
        self.assertIn("currentTemplate = updatedTemplate", source)

    def test_template_persistence_is_explicit_and_off_main(self):
        source = (UI / "screen/templateeditor/TemplateEditorScreen.kt").read_text(encoding="utf-8")
        self.assertIn("withContext(Dispatchers.IO)", source)
        self.assertIn("saveTemplate(draft, isCreation)", source)
        self.assertIn("deleteAppProfileTemplate(template.id)", source)

    def test_dirty_template_back_has_a_confirmation(self):
        source = (UI / "screen/templateeditor/TemplateEditorScreen.kt").read_text(encoding="utf-8")
        self.assertIn("templateNeedsDiscardConfirmation(template, currentTemplate, readOnly)", source)
        self.assertIn("NavigationBackHandler(", source)
        self.assertIn("confirmDialog.awaitConfirm(", source)

    def test_both_skins_have_explicit_save_and_busy_controls(self):
        material = (UI / "screen/templateeditor/TemplateEditorMaterial.kt").read_text(encoding="utf-8")
        miuix = (UI / "screen/templateeditor/TemplateEditorMiuix.kt").read_text(encoding="utf-8")
        for source in (material, miuix):
            self.assertIn("isBusy = state.isBusy", source)
            self.assertIn("enabled = !isBusy", source)
        self.assertNotIn("!readOnly && !isCreation ->", miuix)


if __name__ == "__main__":
    unittest.main(verbosity=2)
