package com.maplesu.core.ui.screen.install

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.material.SegmentedSwitchItem
import com.maplesu.core.ui.theme.miuixDialogColor
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.CheckboxPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton

/** One independent rounded card, shared behavior and theme-native controls. */
@Composable
internal fun InstallAdvancedOptions(state: InstallUiState, actions: InstallScreenActions, modifier: Modifier = Modifier) {
    val material = LocalUiMode.current == UiMode.Material
    val expandedLabel = stringResource(if (state.advancedExpanded) R.string.install_advanced_collapse else R.string.install_advanced_expand)
    val angle by animateFloatAsState(if (state.advancedExpanded) 180f else 0f, tween(260), label = "advanced-chevron")
    val content: @Composable () -> Unit = {
        Column {
            Row(
                Modifier.fillMaxWidth().semantics { stateDescription = expandedLabel }
                    .clickable(role = Role.Button, onClick = actions.onToggleAdvanced).padding(20.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (material) Text(stringResource(R.string.install_advanced_title), Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
                else MiuixText(stringResource(R.string.install_advanced_title), Modifier.weight(1f), color = MiuixTheme.colorScheme.onSurface)
                if (material) Text(expandedLabel, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelMedium)
                else MiuixText(expandedLabel, color = MiuixTheme.colorScheme.onSurfaceVariantSummary)
                Icon(Icons.Default.KeyboardArrowDown, null, Modifier.size(20.dp).rotate(angle),
                    tint = if (material) MaterialTheme.colorScheme.onSurfaceVariant else MiuixTheme.colorScheme.onSurfaceVariantSummary)
            }
            AnimatedVisibility(state.advancedExpanded,
                enter = expandVertically(tween(300)) + fadeIn(tween(200)),
                exit = shrinkVertically(tween(260)) + fadeOut(tween(160))) {
                Column(Modifier.padding(bottom = 8.dp)) {
                    if (state.installMethod == InstallMethod.DirectInstall) {
                        OriginalImageOptions(
                            restoreOriginalImage = state.restoreOriginalImage,
                            managers = state.originalManagers,
                            selectedPackage = state.originalManagerPackage,
                            onRestoreChange = actions.onRestoreOriginalImageChange,
                            onManagerChange = actions.onOriginalManagerChange,
                            enabled = state.targetSelectable,
                        )
                    }
                    if (state.vivoDevice) {
                        AdvancedAction(stringResource(R.string.install_vivo_title),
                            stringResource(if (state.installMethod is InstallMethod.SelectFile) R.string.install_vivo_file_summary
                                else R.string.install_vivo_direct_summary), false, {})
                        if (state.installMethod is InstallMethod.SelectFile) {
                            AdvancedAction(stringResource(R.string.install_vivo_select_image, "vendor_boot"),
                                state.vivoInputs.vendorBoot?.lastPathSegment?.substringAfterLast('/')
                                    ?: stringResource(R.string.install_vivo_image_needed),
                                state.targetSelectable, { actions.onSelectVivoImage("vendor_boot") })
                        }
                    }
                    if (material) SegmentedSwitchItem(
                        title = stringResource(R.string.install_lenovo_title), summary = stringResource(R.string.install_lenovo_summary),
                        checked = state.lenovoSigning.enabled, enabled = state.targetSelectable,
                        onCheckedChange = actions.onLenovoSigningChange,
                    ) else SwitchPreference(
                        title = stringResource(R.string.install_lenovo_title), summary = stringResource(R.string.install_lenovo_summary),
                        checked = state.lenovoSigning.enabled, enabled = state.targetSelectable,
                        onCheckedChange = actions.onLenovoSigningChange,
                    )
                    AnimatedVisibility(state.lenovoSigning.enabled,
                        enter = expandVertically(tween(260)) + fadeIn(tween(180)),
                        exit = shrinkVertically(tween(220)) + fadeOut(tween(140))) {
                        Column {
                            AdvancedAction(
                                title = stringResource(if (state.lenovoSigning.mode(state.partition.wire) == dev.maplesu.image.LenovoAvbSigner.Mode.AOSP) R.string.install_lenovo_aosp else R.string.install_lenovo_legacy),
                                summary = stringResource(R.string.install_lenovo_boot_target), enabled = state.targetSelectable,
                                onClick = actions.onConfigureLenovoSigning,
                            )
                            if (state.installMethod is InstallMethod.SelectFile) {
                                state.lenovoSigning.requiredImages(state.partition.wire).forEach { name ->
                                    val uri = state.lenovoSigning.uri(name)
                                    AdvancedAction(
                                        title = stringResource(R.string.install_lenovo_select_image, name),
                                        summary = uri?.lastPathSegment?.substringAfterLast('/')
                                            ?: stringResource(R.string.install_lenovo_image_needed),
                                        enabled = state.targetSelectable, onClick = { actions.onSelectSigningImage(name) },
                                    )
                                }
                            } else AdvancedAction(stringResource(R.string.install_lenovo_auto_images),
                                stringResource(R.string.install_lenovo_auto_images_summary), false, {})
                        }
                    }
                }
            }
        }
    }
    if (material) Surface(modifier.fillMaxWidth(), shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surfaceBright, content = content)
    else Card(modifier = modifier.fillMaxWidth()) { content() }
}

@Composable
private fun AdvancedAction(title: String, summary: String, enabled: Boolean, onClick: () -> Unit) {
    if (LocalUiMode.current == UiMode.Material) Column(
        Modifier.fillMaxWidth().clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(title, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurface)
        Text(summary, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    } else BasicComponent(title = title, summary = summary, enabled = enabled, onClick = onClick)
}

@Composable
internal fun LenovoSigningDialog(show: Boolean, aosp: Boolean, onAospChange: (Boolean) -> Unit,
                                 onConfirm: () -> Unit, onDismiss: () -> Unit) {
    if (!show) return
    val title = stringResource(R.string.install_lenovo_confirm_title)
    when (LocalUiMode.current) {
        UiMode.Material -> AlertDialog(onDismissRequest = onDismiss, title = { Text(title) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(R.string.install_lenovo_aosp_hint))
                    Row(Modifier.fillMaxWidth().toggleable(value = aosp, role = Role.Checkbox, onValueChange = onAospChange),
                        verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(aosp, null)
                        Text(stringResource(R.string.install_lenovo_aosp), Modifier.padding(start = 8.dp))
                    }
                }
            },
            confirmButton = { TextButton(onClick = onConfirm) { Text(stringResource(R.string.confirm)) } },
            dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(android.R.string.cancel)) } },
        )
        UiMode.Miuix -> OverlayDialog(show = true, title = title, backgroundColor = miuixDialogColor(), onDismissRequest = onDismiss) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                CheckboxPreference(title = stringResource(R.string.install_lenovo_aosp),
                    summary = stringResource(R.string.install_lenovo_aosp_hint), checked = aosp, onCheckedChange = onAospChange)
                MiuixTextButton(text = stringResource(R.string.confirm), onClick = onConfirm,
                    colors = ButtonDefaults.textButtonColorsPrimary(), modifier = Modifier.fillMaxWidth())
                MiuixTextButton(text = stringResource(android.R.string.cancel), onClick = onDismiss, modifier = Modifier.fillMaxWidth())
            }
        }
    }
}

@Composable
internal fun VivoBootChoiceDialog(show: Boolean, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    if (!show) return
    val title = stringResource(R.string.install_vivo_boot_title)
    val body = stringResource(R.string.install_vivo_boot_warning)
    when (LocalUiMode.current) {
        UiMode.Material -> AlertDialog(onDismissRequest = onDismiss, title = { Text(title) }, text = { Text(body) },
            confirmButton = { TextButton(onClick = onConfirm) { Text(stringResource(R.string.confirm)) } },
            dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(android.R.string.cancel)) } })
        UiMode.Miuix -> OverlayDialog(show = true, title = title, backgroundColor = miuixDialogColor(), onDismissRequest = onDismiss) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                MiuixText(body)
                MiuixTextButton(text = stringResource(R.string.confirm), onClick = onConfirm,
                    colors = ButtonDefaults.textButtonColorsPrimary(), modifier = Modifier.fillMaxWidth())
                MiuixTextButton(text = stringResource(android.R.string.cancel), onClick = onDismiss, modifier = Modifier.fillMaxWidth())
            }
        }
    }
}
