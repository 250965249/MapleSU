package dev.maplesu.manager.jailbreak

import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.collectIsDraggedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.screen.host.HiddenFlowButton
import com.maplesu.core.ui.screen.host.HiddenFlowText
import com.maplesu.core.ui.screen.host.hiddenFlowColors
import kotlinx.coroutines.flow.collect

/** Native themed chrome around a high-contrast, selectable console. */
@Composable
internal fun JailbreakLogPanel(
    ui: JailbreakSelectionState,
    snapshot: JailbreakLogReader.Snapshot,
    busy: Boolean,
    onCopy: () -> Unit,
    onExport: () -> Unit,
    onShare: () -> Unit,
    onDismiss: () -> Unit,
    onCancel: () -> Unit,
) {
    val colors = hiddenFlowColors()
    val scroll = rememberLazyListState()
    val dragging by scroll.interactionSource.collectIsDraggedAsState()
    var following by remember { mutableStateOf(true) }
    LaunchedEffect(scroll) {
        snapshotFlow { dragging to scroll.canScrollForward }.collect { (dragged, canForward) ->
            if (dragged && canForward) following = false
            else if (!canForward) following = true
        }
    }
    LaunchedEffect(snapshot.lines, following) {
        if (following && snapshot.lines.isNotEmpty()) scroll.scrollToItem(snapshot.lines.lastIndex)
    }
    val screenHeight = LocalConfiguration.current.screenHeightDp
    val compact = screenHeight < 550
    val maxHeight = (screenHeight * .78f).dp
    Column(Modifier.fillMaxWidth().heightIn(max = maxHeight).navigationBarsPadding()
        .padding(horizontal = 18.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                val method = if (ui.method == JailbreakMethod.GHOSTSAM) "GhostSam" else stringResource(when (ui.method) {
                    JailbreakMethod.GHOSTLOCK -> R.string.maplesu_jailbreak_ghostlock
                    JailbreakMethod.DIRTYFRAG -> R.string.maplesu_jailbreak_dirtyfrag
                    JailbreakMethod.MAPLESU_93260 -> R.string.maplesu_jailbreak_93260
                    JailbreakMethod.GHOSTSAM -> R.string.maplesu_jailbreak_ghostlock
                })
                val mode = stringResource(if (ui.rootTarget == JailbreakRequest.BACKEND_HOOK)
                    R.string.maplesu_jailbreak_target_ultra else R.string.maplesu_jailbreak_target_normal)
                HiddenFlowText(if (compact) "$method · $mode" else method, title = !compact, maxLines = 1)
                if (!compact) HiddenFlowText(mode, secondary = true)
            }
            val copyLabel = stringResource(R.string.maplesu_jailbreak_copy_logs)
            val copyEnabled = !busy && snapshot.lines.isNotEmpty()
            val copyIcon: @Composable () -> Unit = {
                androidx.compose.material3.Icon(Icons.Outlined.ContentCopy, copyLabel,
                    tint = colors.text.copy(alpha = if (copyEnabled) 1f else .38f), modifier = Modifier.size(20.dp))
            }
            if (LocalUiMode.current == UiMode.Miuix) {
                top.yukonga.miuix.kmp.basic.IconButton(onClick = onCopy, enabled = copyEnabled,
                    modifier = Modifier.size(48.dp), content = copyIcon)
            } else {
                androidx.compose.material3.IconButton(onClick = onCopy, enabled = copyEnabled,
                    modifier = Modifier.size(48.dp), content = copyIcon)
            }
            HiddenFlowButton(stringResource(R.string.maplesu_jailbreak_logs_close), onDismiss,
                enabled = !busy, modifier = Modifier.heightIn(min = 48.dp))
        }
        Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp))
            .background(colors.primary.copy(alpha = .08f)).padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(Modifier.size(8.dp).clip(CircleShape).background(
                    if (ui.outcome?.failure != null) colors.error else colors.primary))
                HiddenFlowText(stringResource(jailbreakStageDescription(ui.outcome?.stage ?: snapshot.stage ?: ui.observedStage)),
                    color = if (ui.outcome?.failure != null) colors.error else colors.primary)
            }
            if (!compact) HiddenFlowText(stringResource(if (ui.running) R.string.maplesu_jailbreak_logs_live
                else R.string.maplesu_jailbreak_logs_retained), secondary = true)
            ui.outcome?.failure?.let { HiddenFlowText(jailbreakFailureText(it), secondary = true,
                color = colors.error, maxLines = if (compact) 2 else Int.MAX_VALUE) }
        }
        Box(Modifier.fillMaxWidth().weight(1f).clip(RoundedCornerShape(14.dp))
            .background(Color(0xFF0B1220)).padding(12.dp)) {
            if (snapshot.lines.isEmpty()) {
                BasicText(stringResource(if (ui.running) R.string.maplesu_jailbreak_logs_waiting
                    else R.string.maplesu_jailbreak_logs_empty),
                    style = TextStyle(color = Color(0xFFBAC5D8), fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp, lineHeight = 18.sp), modifier = Modifier.align(Alignment.Center))
            } else SelectionContainer {
                LazyColumn(state = scroll, modifier = Modifier.fillMaxWidth().testTag("jailbreak-log-console"),
                    verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    itemsIndexed(snapshot.lines) { index, line ->
                        Column {
                            if (index == 0 || snapshot.lines[index - 1].source != line.source) {
                                BasicText(line.source, style = TextStyle(color = Color(0xFF95A8C5),
                                    fontFamily = FontFamily.Monospace, fontSize = 10.sp),
                                    modifier = Modifier.padding(top = 6.dp, bottom = 3.dp))
                            }
                            BasicText(line.text, style = TextStyle(fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp, lineHeight = 17.sp, color = when (line.tone) {
                                    JailbreakLogReader.Tone.ERROR -> Color(0xFFFF9B9B)
                                    JailbreakLogReader.Tone.SUCCESS -> Color(0xFF8EDBB0)
                                    JailbreakLogReader.Tone.STEP -> Color(0xFFF0D48A)
                                    JailbreakLogReader.Tone.DETAIL -> Color(0xFFD3DCEA)
                                }))
                        }
                    }
                }
            }
        }
        if (!compact || !following) Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            HiddenFlowText(stringResource(R.string.maplesu_jailbreak_logs_line_count, snapshot.lines.size),
                modifier = Modifier.weight(1f), secondary = true)
            if (!following) HiddenFlowButton(stringResource(R.string.maplesu_jailbreak_logs_latest),
                onClick = { following = true })
        }
        if (snapshot.omitted > 0 && !compact) HiddenFlowText(stringResource(R.string.maplesu_jailbreak_logs_window), secondary = true)
        val exportLabel = stringResource(R.string.maplesu_jailbreak_export_logs)
        val shareLabel = stringResource(R.string.maplesu_jailbreak_share_logs)
        val actionStyle = TextStyle(fontSize = 14.sp)
        val measurer = rememberTextMeasurer()
        val density = LocalDensity.current
        val labelWidth = maxOf(measurer.measure(exportLabel, actionStyle, softWrap = false).size.width,
            measurer.measure(shareLabel, actionStyle, softWrap = false).size.width)
        BoxWithConstraints(Modifier.fillMaxWidth()) {
            // At large font scales use full-width buttons, keeping each label on one line.
            val stack = maxWidth < with(density) { labelWidth.toDp() * 2 + 64.dp }
            if (stack) Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                JailbreakLogActionButton(exportLabel, onExport, Modifier.fillMaxWidth(), !busy)
                JailbreakLogActionButton(shareLabel, onShare, Modifier.fillMaxWidth(), !busy, primary = true)
            } else Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                JailbreakLogActionButton(exportLabel, onExport, Modifier.weight(1f), !busy)
                JailbreakLogActionButton(shareLabel, onShare, Modifier.weight(1f), !busy, primary = true)
            }
        }
        if (busy) HiddenFlowText(stringResource(R.string.maplesu_jailbreak_logs_exporting), secondary = true)
        if (ui.running) HiddenFlowButton(stringResource(if (ui.cancellationPending)
            R.string.maplesu_jailbreak_cancel_pending else R.string.maplesu_jailbreak_cancel), onCancel,
            Modifier.fillMaxWidth(), enabled = !ui.cancellationPending && !busy)
        if (ui.cancellationFailed) HiddenFlowText(stringResource(R.string.maplesu_jailbreak_cancel_unconfirmed),
            secondary = true, color = colors.error)
    }
}

@Composable
private fun JailbreakLogActionButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier,
    enabled: Boolean,
    primary: Boolean = false,
) {
    val buttonModifier = modifier.heightIn(min = 48.dp)
    val padding = PaddingValues(horizontal = 12.dp, vertical = 12.dp)
    if (LocalUiMode.current == UiMode.Miuix) {
        val scheme = top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
        top.yukonga.miuix.kmp.basic.Button(onClick = onClick, modifier = buttonModifier, enabled = enabled,
            insideMargin = padding, colors = if (primary) top.yukonga.miuix.kmp.basic.ButtonDefaults.buttonColorsPrimary()
            else top.yukonga.miuix.kmp.basic.ButtonDefaults.buttonColors()) {
            top.yukonga.miuix.kmp.basic.Text(text, fontSize = 14.sp, maxLines = 1, softWrap = false,
                color = (if (primary) scheme.onPrimary else scheme.onSurface).copy(alpha = if (enabled) 1f else .38f))
        }
    } else if (primary) {
        androidx.compose.material3.Button(onClick = onClick, modifier = buttonModifier, enabled = enabled,
            contentPadding = padding) {
            androidx.compose.material3.Text(text, fontSize = 14.sp, maxLines = 1, softWrap = false)
        }
    } else {
        androidx.compose.material3.OutlinedButton(onClick = onClick, modifier = buttonModifier, enabled = enabled,
            contentPadding = padding) {
            androidx.compose.material3.Text(text, fontSize = 14.sp, maxLines = 1, softWrap = false)
        }
    }
}
