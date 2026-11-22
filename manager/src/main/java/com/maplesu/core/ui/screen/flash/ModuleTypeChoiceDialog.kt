package com.maplesu.core.ui.screen.flash

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.material.SegmentedColumn
import com.maplesu.core.ui.component.material.SegmentedRadioItem
import com.maplesu.core.ui.screen.host.HiddenFlowDialog
import com.maplesu.core.ui.screen.host.HiddenFlowText
import dev.maplesu.manager.modules.ModuleType
import kotlinx.coroutines.CompletableDeferred
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.RadioButton
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.utils.PressFeedbackType

internal data class ModuleTypeChoiceRequest(
    val moduleName: String,
    val allowedTypes: Set<ModuleType>,
    val result: CompletableDeferred<ModuleType?> = CompletableDeferred(),
)

@Composable
internal fun ModuleTypeChoiceDialog(request: ModuleTypeChoiceRequest) {
    var selectedName by rememberSaveable(request.moduleName) { mutableStateOf<String?>(null) }
    val selected = ModuleType.entries.firstOrNull { it.name == selectedName }
    val confirmEnabled = selected != null && selected in request.allowedTypes
    val options = listOf(ModuleType.MAPLESU, ModuleType.KERNELSU)
    val labels = mapOf(
        ModuleType.MAPLESU to stringResource(R.string.module_type_maplesu),
        ModuleType.KERNELSU to stringResource(R.string.module_type_ksu),
    )
    val summaries = mapOf(
        ModuleType.MAPLESU to stringResource(R.string.module_install_type_maplesu_summary),
        ModuleType.KERNELSU to stringResource(R.string.module_install_type_ksu_summary),
    )
    HiddenFlowDialog(
        title = stringResource(R.string.module_install_type_title),
        onDismiss = { request.result.complete(null) },
        confirmLabel = stringResource(R.string.module_install),
        onConfirm = { if (confirmEnabled) request.result.complete(selected) },
        dismissLabel = stringResource(android.R.string.cancel),
        confirmEnabled = confirmEnabled,
    ) {
        HiddenFlowText(request.moduleName, maxLines = 2)
        HiddenFlowText(stringResource(R.string.module_install_type_hint), secondary = true)
        when (LocalUiMode.current) {
            UiMode.Material -> SegmentedColumn(
                modifier = Modifier.selectableGroup(),
                content = options.map { type ->
                    {
                        SegmentedRadioItem(
                            title = labels.getValue(type), summary = summaries.getValue(type),
                            selected = selected == type, enabled = type in request.allowedTypes,
                            onClick = { selectedName = type.name },
                        )
                    }
                },
            )
            UiMode.Miuix -> Column(
                modifier = Modifier.selectableGroup(),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                options.forEach { type ->
                    val enabled = type in request.allowedTypes
                    val background by animateColorAsState(
                        if (selected == type) MiuixTheme.colorScheme.primary.copy(alpha = 0.12f)
                        else MiuixTheme.colorScheme.surfaceContainer,
                        label = "moduleTypeOption",
                    )
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.defaultColors(color = background),
                        insideMargin = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                        showIndication = enabled,
                        pressFeedbackType = if (enabled) PressFeedbackType.Sink else PressFeedbackType.None,
                        onClick = { if (enabled) selectedName = type.name },
                    ) {
                        Row(Modifier.fillMaxWidth().heightIn(min = 52.dp), verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(selected = selected == type, onClick = null, enabled = enabled)
                            Spacer(Modifier.width(14.dp))
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                HiddenFlowText(labels.getValue(type), secondary = !enabled)
                                HiddenFlowText(summaries.getValue(type), secondary = true)
                            }
                        }
                    }
                }
            }
        }
    }
}
