package com.maplesu.core.ui.component.uninstalldialog

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.maplesu.core.ui.component.material.SegmentedColumn
import com.maplesu.core.ui.component.material.SegmentedListItem
import com.maplesu.core.ui.theme.materialDialogColor

/** Material：干净的列表弹窗，确认窗沿用 M3 Dialog。 */
@Composable
internal fun UninstallChooserMaterial(
    show: Boolean,
    title: String,
    choices: List<UninstallChoice>,
    onChoose: (UninstallChoice) -> Unit,
    onDismissRequest: () -> Unit,
) {
    if (!show) return
    AlertDialog(
        onDismissRequest = onDismissRequest,
        containerColor = materialDialogColor(),
        title = { Text(title) },
        text = {
            SegmentedColumn(
                modifier = Modifier,
                content = choices.map { choice ->
                    {
                        SegmentedListItem(
                            onClick = { onChoose(choice) },
                            enabled = choice.disabledReason == null,
                            headlineContent = { Text(choice.title) },
                            supportingContent = choice.disabledReason?.let { reason -> { Text(reason) } },
                            leadingContent = { Icon(imageVector = choice.icon, contentDescription = null) },
                            trailingContent = {
                                Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null)
                            },
                        )
                    }
                },
            )
        },
        confirmButton = {
            TextButton(onClick = onDismissRequest) {
                Text(stringResource(android.R.string.cancel))
            }
        },
    )
}
