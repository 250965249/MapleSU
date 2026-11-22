package com.maplesu.core.ui.screen.templateeditor

import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.navigationevent.NavigationEventInfo
import androidx.navigationevent.compose.NavigationBackHandler
import androidx.navigationevent.compose.rememberNavigationEventState
import com.maplesu.core.R
import com.maplesu.core.toOrdinalList
import com.maplesu.core.toRootProfileFlags
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.dialog.ConfirmResult
import com.maplesu.core.ui.component.dialog.rememberConfirmDialog
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.util.deleteAppProfileTemplate
import com.maplesu.core.ui.viewmodel.TemplateViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun TemplateEditorScreen(template: TemplateViewModel.TemplateInfo, readOnly: Boolean) {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val uiMode = LocalUiMode.current
    val isCreation = template.id.isBlank()
    val scope = rememberCoroutineScope()
    val confirmDialog = rememberConfirmDialog()

    var currentTemplate by rememberSaveable { mutableStateOf(template) }
    var idErrorHint by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var prompting by remember { mutableStateOf(false) }

    val saveTemplateFailed = stringResource(id = R.string.app_profile_template_save_failed)
    val idConflictError = stringResource(id = R.string.app_profile_template_id_exist)
    val idInvalidError = stringResource(id = R.string.app_profile_template_id_invalid)
    val discardTitle = stringResource(R.string.ui_editing_discard_title)
    val discardContent = stringResource(R.string.ui_editing_discard_content)
    val discardAction = stringResource(R.string.ui_editing_discard)
    val keepEditing = stringResource(R.string.ui_editing_keep)
    val deleteTitle = stringResource(R.string.app_profile_template_delete)
    val deleteContent = stringResource(R.string.ui_editing_delete_content, template.name.ifBlank { template.id })
    val deleteFailed = stringResource(R.string.ui_editing_delete_failed)
    val waitMessage = stringResource(R.string.ui_editing_wait)
    val cancelAction = stringResource(android.R.string.cancel)

    fun showToast(message: String) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
    }

    fun finishEditing() {
        if (busy) {
            showToast(waitMessage)
            return
        }
        if (prompting) return
        if (!templateNeedsDiscardConfirmation(template, currentTemplate, readOnly)) {
            navigator.pop()
            return
        }
        prompting = true
        scope.launch {
            try {
                if (confirmDialog.awaitConfirm(
                        title = discardTitle, content = discardContent,
                        confirm = discardAction, dismiss = keepEditing,
                    ) == ConfirmResult.Confirmed) {
                    navigator.pop()
                }
            } finally {
                prompting = false
            }
        }
    }

    fun updateTemplate(updatedTemplate: TemplateViewModel.TemplateInfo) {
        if (readOnly || busy || prompting) return
        currentTemplate = updatedTemplate
    }

    NavigationBackHandler(
        state = rememberNavigationEventState(NavigationEventInfo.None),
        isBackEnabled = !confirmDialog.isShown,
        onBackCompleted = ::finishEditing,
    )

    val uiState = TemplateEditorUiState(
        template = currentTemplate,
        initialTemplate = template,
        readOnly = readOnly,
        isCreation = isCreation,
        idErrorHint = idErrorHint,
        isBusy = busy,
    )

    fun saveCurrentTemplate() {
        if (readOnly || busy || prompting) return
        val draft = currentTemplate
        if (!isTemplateValid(draft)) {
            idErrorHint = idInvalidError
            showToast(idInvalidError)
            return
        }
        busy = true
        scope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCatching {
                        when {
                            isCreation && isTemplateExist(draft.id) -> TemplateSaveResult.ID_CONFLICT
                            saveTemplate(draft, isCreation) -> TemplateSaveResult.SAVED
                            else -> TemplateSaveResult.FAILED
                        }
                    }.getOrDefault(TemplateSaveResult.FAILED)
                }
                when (result) {
                    TemplateSaveResult.SAVED -> navigator.setResult("template_edit", true)
                    TemplateSaveResult.ID_CONFLICT -> {
                        idErrorHint = idConflictError
                        showToast(idConflictError)
                    }
                    TemplateSaveResult.FAILED -> showToast(saveTemplateFailed)
                }
            } finally {
                busy = false
            }
        }
    }

    val actions = TemplateEditorActions(
        onBack = dropUnlessResumed { finishEditing() },
        onDelete = {
            if (!readOnly && !isCreation && !busy && !prompting) {
                prompting = true
                scope.launch {
                    try {
                        if (confirmDialog.awaitConfirm(
                                title = deleteTitle, content = deleteContent,
                                confirm = deleteTitle, dismiss = cancelAction,
                            ) == ConfirmResult.Confirmed) {
                            busy = true
                            val deleted = withContext(Dispatchers.IO) {
                                runCatching { deleteAppProfileTemplate(template.id) }.getOrDefault(false)
                            }
                            if (deleted) navigator.setResult("template_edit", true)
                            else showToast(deleteFailed)
                        }
                    } finally {
                        busy = false
                        prompting = false
                    }
                }
            }
        },
        onSave = ::saveCurrentTemplate,
        onNameChange = { value ->
            updateTemplate(currentTemplate.copy(name = value))
        },
        onIdChange = { value ->
            if (isCreation && !readOnly && !busy && !prompting) {
                idErrorHint = if (value.isNotEmpty() && !isValidTemplateId(value)) idInvalidError else ""
                currentTemplate = currentTemplate.copy(id = value)
            }
        },
        onAuthorChange = { value ->
            updateTemplate(currentTemplate.copy(author = value))
        },
        onDescriptionChange = { value ->
            updateTemplate(currentTemplate.copy(description = value))
        },
        onProfileChange = { profile ->
            updateTemplate(
                currentTemplate.copy(
                    uid = profile.uid,
                    gid = profile.gid,
                    groups = profile.groups,
                    capabilities = profile.capabilities,
                    context = profile.context,
                    namespace = profile.namespace,
                    rules = profile.rules.split("\n"),
                    flags = profile.flags.toRootProfileFlags().toOrdinalList(),
                )
            )
        },
    )

    when (uiMode) {
        UiMode.Miuix -> TemplateEditorScreenMiuix(
            state = uiState,
            actions = actions,
        )

        UiMode.Material -> TemplateEditorScreenMaterial(
            state = uiState,
            actions = actions,
        )
    }
}

private enum class TemplateSaveResult { SAVED, ID_CONFLICT, FAILED }
