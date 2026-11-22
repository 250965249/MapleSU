package com.maplesu.core.ui.screen.templateeditor

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.captionBar
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import com.maplesu.core.ui.component.miuix.EditText
import com.maplesu.core.ui.component.profile.RootProfileConfig
import com.maplesu.core.ui.theme.LocalEnableBlur
import com.maplesu.core.ui.util.BlurredBar
import com.maplesu.core.ui.util.miuixBarColor
import com.maplesu.core.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.LayerBackdrop
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Delete
import top.yukonga.miuix.kmp.icon.extended.Ok
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

/**
 * @author weishu
 * @date 2023/10/20.
 */
@Composable
fun TemplateEditorScreenMiuix(
    state: TemplateEditorUiState,
    actions: TemplateEditorActions,
) {
    val scrollBehavior = MiuixScrollBehavior()
    val enableBlur = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val barColor = miuixBarColor(blurActive)

    Scaffold(
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
                onBack = actions.onBack,
                onDelete = actions.onDelete,
                onSave = actions.onSave,
                scrollBehavior = scrollBehavior,
                backdrop = backdrop,
                barColor = barColor,
            )
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        Box(modifier = if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxHeight()
                    .imePadding()
                    .scrollEndHaptic()
                    .overScrollVertical()
                    .nestedScroll(scrollBehavior.nestedScrollConnection),
                contentPadding = innerPadding,
                overscrollEffect = null
            ) {
                item {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                    ) {
                        TextEdit(
                            label = stringResource(id = R.string.app_profile_template_name),
                            text = state.template.name,
                            enabled = !state.readOnly && !state.isBusy,
                            onValueChange = actions.onNameChange,
                        )

                        TextEdit(
                            label = stringResource(id = R.string.app_profile_template_id),
                            text = state.template.id,
                            isError = state.idErrorHint.isNotEmpty(),
                            enabled = state.isCreation && !state.readOnly && !state.isBusy,
                            onValueChange = actions.onIdChange,
                        )
                        TextEdit(
                            label = stringResource(R.string.module_author),
                            text = state.template.author,
                            enabled = !state.readOnly && !state.isBusy,
                            onValueChange = actions.onAuthorChange,
                        )

                        TextEdit(
                            label = stringResource(id = R.string.app_profile_template_description),
                            text = state.template.description,
                            enabled = !state.readOnly && !state.isBusy,
                            onValueChange = actions.onDescriptionChange,
                        )

                        RootProfileConfig(
                            fixedName = true,
                            enabled = !state.readOnly && !state.isBusy,
                            profile = toNativeProfile(state.template),
                            onProfileChange = actions.onProfileChange,
                        )
                    }
                    Spacer(
                        Modifier.height(
                            WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() +
                                    WindowInsets.captionBar.asPaddingValues().calculateBottomPadding()
                        )
                    )
                }
            }
        }
    }
}


@Composable
private fun TopBar(
    title: String,
    readOnly: Boolean,
    isCreation: Boolean,
    isBusy: Boolean,
    onBack: () -> Unit,
    onDelete: () -> Unit = {},
    onSave: () -> Unit = {},
    scrollBehavior: ScrollBehavior,
    backdrop: LayerBackdrop?,
    barColor: Color,
) {
    BlurredBar(backdrop) {
        TopAppBar(
            color = barColor,
            title = title,
            navigationIcon = {
                IconButton(
                    onClick = onBack
                ) {
                    val layoutDirection = LocalLayoutDirection.current
                    Icon(
                        modifier = Modifier.graphicsLayer {
                            if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                        },
                        imageVector = MiuixIcons.Back,
                        contentDescription = stringResource(R.string.ui_d_back),
                        tint = colorScheme.onSurface
                    )
                }
            },
            actions = {
                if (!readOnly) {
                    if (!isCreation) {
                        IconButton(
                            onClick = onDelete,
                            enabled = !isBusy,
                        ) {
                            Icon(
                                imageVector = MiuixIcons.Delete,
                                contentDescription = stringResource(id = R.string.app_profile_template_delete),
                                tint = colorScheme.onBackground
                            )
                        }
                    }

                    IconButton(
                        onClick = onSave,
                        enabled = !isBusy,
                    ) {
                        if (isBusy) InfiniteProgressIndicator()
                        else Icon(
                                imageVector = MiuixIcons.Ok,
                                contentDescription = stringResource(id = R.string.app_profile_template_save),
                                tint = colorScheme.onBackground
                            )
                    }
                }
            },
            scrollBehavior = scrollBehavior
        )
    }
}

@Composable
private fun TextEdit(
    label: String,
    text: String,
    isError: Boolean = false,
    enabled: Boolean = true,
    onValueChange: (String) -> Unit = {}
) {
    EditText(
        title = label.uppercase(),
        value = text,
        onValueChange = onValueChange,
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Text,
        ),
        isError = isError,
        enabled = enabled,
    )
}

