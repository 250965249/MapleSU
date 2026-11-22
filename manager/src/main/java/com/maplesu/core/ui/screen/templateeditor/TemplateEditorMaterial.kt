package com.maplesu.core.ui.screen.templateeditor

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Save
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarScrollBehavior
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import com.maplesu.core.ui.component.material.ExpressiveScaffold
import com.maplesu.core.ui.component.material.SegmentedColumn
import com.maplesu.core.ui.component.material.SegmentedTextField
import com.maplesu.core.ui.component.material.TopBarBackButton
import com.maplesu.core.ui.component.material.expressiveTopAppBarColors
import com.maplesu.core.ui.component.profile.RootProfileConfig

@Composable
fun TemplateEditorScreenMaterial(
    state: TemplateEditorUiState,
    actions: TemplateEditorActions,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())

    ExpressiveScaffold(
        topBar = {
            TopBar(
                title = if (state.isCreation) {
                    stringResource(R.string.app_profile_template_create)
                } else if (state.readOnly) {
                    stringResource(R.string.app_profile_template_view)
                } else {
                    stringResource(R.string.app_profile_template_edit)
                },
                readOnly = state.readOnly,
                isCreation = state.isCreation,
                isBusy = state.isBusy,
                summary = state.titleSummary,
                onBack = actions.onBack,
                onDelete = actions.onDelete,
                onSave = actions.onSave,
                scrollBehavior = scrollBehavior
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .padding(top = 13.dp)
                .imePadding()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .verticalScroll(rememberScrollState())
        ) {
            SegmentedColumn(
                modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 13.dp),
                content = buildList {
                    add(
                        {
                            TemplateEditorListItem(
                                label = stringResource(id = R.string.app_profile_template_name),
                                value = state.template.name,
                                readOnly = state.readOnly || state.isBusy,
                                onValueChange = actions.onNameChange,
                            )
                        }
                    )
                    if (state.isCreation) {
                        add(
                            {
                                TemplateEditorListItem(
                                    label = stringResource(id = R.string.app_profile_template_id),
                                    value = state.template.id,
                                    errorHint = state.idErrorHint,
                                    isError = state.idErrorHint.isNotEmpty(),
                                    readOnly = state.readOnly || state.isBusy,
                                    onValueChange = actions.onIdChange,
                                )
                            }
                        )
                    }
                    add(
                        {
                            TemplateEditorListItem(
                                label = stringResource(id = R.string.module_author),
                                value = state.template.author,
                                readOnly = state.readOnly || state.isBusy,
                                onValueChange = actions.onAuthorChange,
                            )
                        }
                    )
                    add(
                        {
                            TemplateEditorListItem(
                                label = stringResource(id = R.string.app_profile_template_description),
                                value = state.template.description,
                                multiline = true,
                                readOnly = state.readOnly || state.isBusy,
                                onValueChange = actions.onDescriptionChange,
                            )
                        }
                    )
                }
            )

            RootProfileConfig(
                fixedName = true,
                enabled = !state.readOnly && !state.isBusy,
                profile = toNativeProfile(state.template),
                onProfileChange = actions.onProfileChange,
            )

            Spacer(
                Modifier.height(
                    WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()
                )
            )
        }
    }
}

@Composable
private fun TemplateEditorListItem(
    label: String,
    value: String,
    errorHint: String = "",
    isError: Boolean = false,
    multiline: Boolean = false,
    readOnly: Boolean = false,
    onValueChange: (String) -> Unit
) {
    SegmentedTextField(
        value = value,
        onValueChange = onValueChange,
        label = label,
        supportingContent = if (isError && errorHint.isNotEmpty()) {
            { Text(errorHint, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall) }
        } else null,
        isError = isError,
        singleLine = !multiline,
        minLines = 1,
        maxLines = if (multiline) 100 else 1,
        readOnly = readOnly
    )
}

@Composable
private fun TopBar(
    title: String,
    readOnly: Boolean,
    isCreation: Boolean,
    isBusy: Boolean,
    summary: String = "",
    onBack: () -> Unit,
    onDelete: () -> Unit = {},
    onSave: () -> Unit = {},
    scrollBehavior: TopAppBarScrollBehavior? = null
) {
    LargeFlexibleTopAppBar(
        title = {
            Column {
                Text(title)
                if (summary.isNotBlank()) {
                    Text(
                        text = summary,
                        style = MaterialTheme.typography.bodyMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        },
        navigationIcon = {
            TopBarBackButton(onClick = onBack)
        },
        actions = {
            if (readOnly) return@LargeFlexibleTopAppBar
            if (!isCreation) {
                IconButton(onClick = onDelete, enabled = !isBusy) {
                    Icon(
                        Icons.Filled.DeleteForever,
                        contentDescription = stringResource(id = R.string.app_profile_template_delete)
                    )
                }
            }
            IconButton(onClick = onSave, enabled = !isBusy) {
                if (isBusy) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                else Icon(
                        imageVector = Icons.Filled.Save,
                        contentDescription = stringResource(id = R.string.app_profile_template_save)
                    )
            }
        },
        colors = expressiveTopAppBarColors(),
        windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
        scrollBehavior = scrollBehavior
    )
}
