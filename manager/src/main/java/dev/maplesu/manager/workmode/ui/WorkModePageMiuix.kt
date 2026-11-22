package dev.maplesu.manager.workmode.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.maplesu.core.R
import top.yukonga.miuix.kmp.basic.*
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

@Composable
internal fun WorkModePageMiuix(
    title: String,
    onBack: () -> Unit,
    backEnabled: Boolean = true,
    content: @Composable ColumnScope.() -> Unit,
) {
    Scaffold(
        topBar = {
            SmallTopAppBar(
                title = title, color = colorScheme.surface,
                navigationIcon = {
                    IconButton(onClick = onBack, enabled = backEnabled) {
                        Icon(Icons.AutoMirrored.Rounded.ArrowBack,
                            contentDescription = stringResource(R.string.work_mode_back),
                            tint = colorScheme.onBackground)
                    }
                },
            )
        },
        popupHost = {},
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout)
            .only(WindowInsetsSides.Horizontal + WindowInsetsSides.Bottom),
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).consumeWindowInsets(padding)
                .verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            content = content,
        )
    }
}

@Composable
internal fun WorkModeSectionMiuix(content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp), content = content)
    }
}

@Composable
internal fun WorkModeTechnicalInfoMiuix(lines: List<String>) {
    if (lines.isEmpty()) return
    var expanded by rememberSaveable { mutableStateOf(false) }
    WorkModeSectionMiuix {
        TextButton(
            text = stringResource(R.string.diagnosis_technical_info) + " · " +
                stringResource(if (expanded) R.string.diagnosis_collapse else R.string.diagnosis_expand),
            onClick = { expanded = !expanded }, modifier = Modifier.fillMaxWidth(),
        )
        AnimatedVisibility(expanded) {
            SelectionContainer {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    lines.forEach { Text(it, fontSize = 12.sp, color = colorScheme.onSurfaceVariantSummary) }
                }
            }
        }
    }
}
