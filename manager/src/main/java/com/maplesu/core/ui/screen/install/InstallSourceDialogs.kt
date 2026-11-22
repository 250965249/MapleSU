package com.maplesu.core.ui.screen.install

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults as MaterialButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.material.SegmentedColumn
import com.maplesu.core.ui.component.material.SegmentedDropdownItem
import com.maplesu.core.ui.component.material.SegmentedSwitchItem
import com.maplesu.core.ui.theme.miuixDialogColor
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.OverlayDropdownPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.Button as MiuixButton

@Composable
internal fun UltraModuleChoiceDialog(
    state: UltraModuleChoiceViewModel.State,
    onKeep: () -> Unit,
    onRemove: () -> Unit,
    onDismiss: () -> Unit,
) {
    if (!state.show) return
    val title = stringResource(R.string.install_keep_modules_title)
    val body = stringResource(R.string.install_keep_modules_body)
    val blue = Color(0xFF007AFF)
    val dismiss = { if (!state.busy) onDismiss() }
    val message = body + when {
        state.busy -> "\n\n" + stringResource(R.string.install_modules_cleaning)
        state.failed -> "\n\n" + stringResource(R.string.install_modules_cleanup_failed)
        else -> ""
    }
    when (LocalUiMode.current) {
        UiMode.Material -> AlertDialog(
            onDismissRequest = dismiss,
            title = { Text(title) },
            text = { Text(message) },
            // One row fixes the requested physical order: gray Confirm on the left, blue No on the right.
            confirmButton = {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(onClick = onKeep, enabled = !state.busy, modifier = Modifier.weight(1f),
                        colors = MaterialButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                            contentColor = MaterialTheme.colorScheme.onSurface,
                        )) { Text(stringResource(R.string.confirm)) }
                    Button(onClick = onRemove, enabled = !state.busy, modifier = Modifier.weight(1f),
                        colors = MaterialButtonDefaults.buttonColors(containerColor = blue, contentColor = Color.White)) {
                        Text(stringResource(R.string.install_keep_modules_no))
                    }
                }
            },
        )
        UiMode.Miuix -> OverlayDialog(
            show = true, title = title, backgroundColor = miuixDialogColor(), onDismissRequest = dismiss,
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                MiuixText(message, color = MiuixTheme.colorScheme.onSurfaceVariantSummary)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    MiuixButton(onClick = onKeep, enabled = !state.busy, modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(color = MiuixTheme.colorScheme.secondaryContainer)) {
                        MiuixText(stringResource(R.string.confirm), color = MiuixTheme.colorScheme.onSurface)
                    }
                    MiuixButton(onClick = onRemove, enabled = !state.busy, modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(color = blue)) {
                        MiuixText(stringResource(R.string.install_keep_modules_no), color = Color.White)
                    }
                }
            }
        }
    }
}

@Composable
internal fun OriginalImageOptions(
    restoreOriginalImage: Boolean,
    managers: List<OriginalRootManager>,
    selectedPackage: String?,
    onRestoreChange: (Boolean) -> Unit,
    onManagerChange: (String?) -> Unit,
    enabled: Boolean = true,
) {
    val restoreTitle = stringResource(R.string.install_restore_original_image)
    val restoreSummary = stringResource(R.string.install_restore_original_image_summary)
    val managerTitle = stringResource(R.string.install_original_manager)
    val managerOptions = listOf(stringResource(R.string.install_original_manager_auto)) + managers.map { it.label }
    val selectedIndex = managers.indexOfFirst { it.packageName == selectedPackage }.let { if (it < 0) 0 else it + 1 }
    val selectManager: (Int) -> Unit = { index -> onManagerChange(managers.getOrNull(index - 1)?.packageName) }
    when (LocalUiMode.current) {
        UiMode.Material -> SegmentedColumn(
            content = buildList {
                add {
                    SegmentedSwitchItem(
                        title = restoreTitle, summary = restoreSummary,
                        checked = restoreOriginalImage, onCheckedChange = onRestoreChange,
                        enabled = enabled,
                    )
                }
                if (restoreOriginalImage) {
                    add {
                        SegmentedDropdownItem(
                            title = managerTitle, items = managerOptions, selectedIndex = selectedIndex,
                            onItemSelected = selectManager,
                            enabled = enabled,
                        )
                    }
                }
            },
        )
        UiMode.Miuix -> Column {
            SwitchPreference(
                title = restoreTitle, summary = restoreSummary,
                checked = restoreOriginalImage, onCheckedChange = onRestoreChange,
                enabled = enabled,
            )
            if (restoreOriginalImage) {
                OverlayDropdownPreference(
                    title = managerTitle, items = managerOptions, selectedIndex = selectedIndex,
                    onSelectedIndexChange = selectManager,
                    enabled = enabled,
                )
            }
        }
    }
}
