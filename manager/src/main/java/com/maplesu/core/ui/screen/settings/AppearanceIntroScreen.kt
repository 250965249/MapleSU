package com.maplesu.core.ui.screen.settings

import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Layers
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.foundation.selection.selectable
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.maplesu.core.R
import com.maplesu.core.ui.UiMode
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** A real full-screen skin preview; no runtime probes or backend state are needed to choose a style. */
@Composable
fun AppearanceIntroScreen(mode: UiMode, onSelect: (UiMode) -> Unit, onFinish: () -> Unit,
    comic: Boolean = true, onComicChange: (Boolean) -> Unit = {}) {
    val miuix = mode == UiMode.Miuix
    val background = if (miuix) MiuixTheme.colorScheme.background else MaterialTheme.colorScheme.background
    val text = if (miuix) MiuixTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurface
    val muted = if (miuix) MiuixTheme.colorScheme.onSurfaceVariantSummary else MaterialTheme.colorScheme.onSurfaceVariant
    val primary = if (miuix) MiuixTheme.colorScheme.primary else MaterialTheme.colorScheme.primary
    val surface = if (miuix) MiuixTheme.colorScheme.surface else MaterialTheme.colorScheme.surfaceContainer
    val description = when {
        !miuix -> R.string.appearance_intro_material
        comic -> R.string.appearance_intro_miuix
        else -> R.string.ui_d_comic_plain_style_summary
    }
    BoxWithConstraints(Modifier.fillMaxSize().background(background).safeDrawingPadding()) {
        val wide = maxWidth > 600.dp && maxWidth > maxHeight
        val scroll = maxHeight < 680.dp || LocalDensity.current.fontScale > 1.3f
        val body = if (scroll) Modifier.fillMaxSize().verticalScroll(rememberScrollState()) else Modifier.fillMaxSize()
        Column(body.padding(horizontal = 28.dp, vertical = 16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            IntroText(stringResource(R.string.appearance_intro_title), mode, text, 30, FontWeight.SemiBold)
            IntroText(stringResource(R.string.appearance_intro_subtitle), mode, muted, 14)
            if (wide) {
                Row((if (scroll) Modifier.height(360.dp) else Modifier.weight(1f)).fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(32.dp), verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.weight(1f).fillMaxHeight(), contentAlignment = Alignment.Center) {
                        AppearancePhonePreview(mode, primary, surface, text, muted, comic)
                    }
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(20.dp)) {
                        AppearanceStyleChoices(mode, onSelect, surface, primary, text)
                        IntroText(stringResource(description), mode, muted, 15)
                    }
                }
            } else {
                Box((if (scroll) Modifier.height(320.dp) else Modifier.weight(1f)).fillMaxWidth(), contentAlignment = Alignment.Center) {
                    AppearancePhonePreview(mode, primary, surface, text, muted, comic)
                }
                AppearanceStyleChoices(mode, onSelect, surface, primary, text)
                Box(Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                    IntroText(stringResource(description), mode, muted, 14)
                }
            }
            if (miuix) {
                top.yukonga.miuix.kmp.basic.Card(Modifier.fillMaxWidth()) {
                    top.yukonga.miuix.kmp.preference.SwitchPreference(
                        title = stringResource(R.string.ui_d_comic_intro),
                        summary = stringResource(R.string.ui_d_comic_intro_summary),
                        checked = comic,
                        onCheckedChange = onComicChange,
                    )
                }
                top.yukonga.miuix.kmp.basic.TextButton(
                    text = stringResource(R.string.appearance_intro_start), onClick = onFinish,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp),
                    colors = top.yukonga.miuix.kmp.basic.ButtonDefaults.textButtonColorsPrimary(),
                )
            } else {
                androidx.compose.material3.Button(onClick = onFinish, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
                    androidx.compose.material3.Text(stringResource(R.string.appearance_intro_start))
                }
            }
            IntroText(stringResource(R.string.appearance_intro_later), mode, muted, 12)
        }
    }
}

@Composable
private fun AppearanceStyleChoices(mode: UiMode, onSelect: (UiMode) -> Unit, surface: Color, primary: Color, text: Color) {
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        val stacked = maxWidth < 280.dp || LocalDensity.current.fontScale > 1.3f
        if (stacked) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                for (style in UiMode.entries) {
                    AppearanceStyleChoice(style, mode, onSelect, surface, primary, text, Modifier.fillMaxWidth())
                }
            }
        } else {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                for (style in UiMode.entries) {
                    AppearanceStyleChoice(style, mode, onSelect, surface, primary, text, Modifier.weight(1f))
                }
            }
        }
    }
}

@Composable
private fun AppearanceStyleChoice(style: UiMode, mode: UiMode, onSelect: (UiMode) -> Unit, surface: Color, primary: Color, text: Color, modifier: Modifier) {
    val chosen = style == mode
    val shape = RoundedCornerShape(if (mode == UiMode.Miuix) 22.dp else 16.dp)
    Row(
        modifier.clip(shape).background(if (chosen) primary.copy(alpha = .12f) else surface)
            .border(if (chosen) 1.5.dp else 1.dp, if (chosen) primary else text.copy(alpha = .08f), shape)
            .selectable(chosen, role = Role.RadioButton, onClick = { onSelect(style) })
            .heightIn(min = 58.dp).padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IntroText(if (style == UiMode.Miuix) "Miuix" else "Material", mode, if (chosen) primary else text, 16, FontWeight.Medium, modifier = Modifier.weight(1f))
        if (chosen) {
            Spacer(Modifier.width(8.dp))
            androidx.compose.material3.Icon(Icons.Outlined.CheckCircle, null, tint = primary, modifier = Modifier.size(20.dp))
        }
    }
}

@Composable
private fun BoxScope.AppearancePhonePreview(mode: UiMode, primary: Color, surface: Color, text: Color, muted: Color, comic: Boolean) {
    val miuix = mode == UiMode.Miuix
    val shape = RoundedCornerShape(32.dp)
    val density = LocalDensity.current
    CompositionLocalProvider(LocalDensity provides Density(density.density, 1f)) {
    BoxWithConstraints(Modifier.fillMaxHeight().widthIn(max = 264.dp).aspectRatio(.5f, matchHeightConstraintsFirst = true).clip(shape).border(1.dp, text.copy(alpha = .16f), shape).background(surface.copy(alpha = .45f)).padding(14.dp).clearAndSetSemantics { contentDescription = if (miuix) "Miuix" else "Material" }, contentAlignment = Alignment.Center) {
        // A compact composition uses the actual active palette, rather than a static screenshot.
        val scale = minOf(maxWidth / 220.dp, maxHeight / 480.dp).coerceAtMost(1f)
        Column(Modifier.requiredSize(220.dp, 480.dp).graphicsLayer { scaleX = scale; scaleY = scale }, verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Box(Modifier.align(Alignment.CenterHorizontally).size(40.dp, 4.dp).clip(RoundedCornerShape(4.dp)).background(text.copy(alpha = .22f)))
            Spacer(Modifier.height(6.dp))
            IntroText("MapleSU", mode, text, 23, FontWeight.Medium)
            Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(if (miuix) 22.dp else 14.dp))
                .background(if (miuix) Brush.linearGradient(listOf(primary.copy(alpha = .22f), primary.copy(alpha = .08f))) else Brush.linearGradient(listOf(surface, surface)))
            ) {
                if (miuix && comic) {
                    androidx.compose.foundation.Image(
                        painter = androidx.compose.ui.res.painterResource(R.drawable.art_default),
                        contentDescription = null, contentScale = androidx.compose.ui.layout.ContentScale.Crop,
                        modifier = Modifier.matchParentSize(),
                    )
                    Box(Modifier.matchParentSize().background(Color.Black.copy(alpha = .56f)))
                } else {
                    androidx.compose.material3.Icon(Icons.Outlined.CheckCircle, null, tint = primary,
                        modifier = Modifier.align(Alignment.BottomEnd).padding(8.dp).size(54.dp))
                }
                Column(Modifier.fillMaxWidth().heightIn(min = if (miuix && comic) 220.dp else 100.dp).padding(16.dp),
                    verticalArrangement = Arrangement.SpaceBetween) {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        IntroText(stringResource(R.string.appearance_intro_preview_ready), mode, if (miuix && comic) Color.White else text, 16, FontWeight.Medium)
                        IntroText(stringResource(R.string.appearance_intro_preview_detail), mode, if (miuix && comic) Color.White else muted, 12)
                    }
                    if (miuix) IntroText("LKM", mode, if (comic) Color.White else text, 12)
                }
            }
            Column(Modifier.weight(1f).fillMaxWidth().clip(RoundedCornerShape(if (miuix) 20.dp else 12.dp)).background(surface).padding(14.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                IntroText(stringResource(R.string.appearance_intro_preview_device), mode, text, 14, FontWeight.Medium)
                repeat(2) { index ->
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.size(24.dp).clip(RoundedCornerShape(7.dp)).background(primary.copy(alpha = .1f)))
                        Box(Modifier.width(if (index == 1) 66.dp else 88.dp).height(5.dp).clip(RoundedCornerShape(3.dp)).background(muted.copy(alpha = .16f)))
                    }
                }
            }
            Row(Modifier.fillMaxWidth().padding(horizontal = if (miuix && comic) 7.dp else 0.dp, vertical = 4.dp)
                .clip(RoundedCornerShape(if (miuix && comic) 30.dp else 0.dp)).background(surface.copy(alpha = if (miuix && comic) .85f else 1f))
                .border(1.dp, text.copy(alpha = if (miuix && comic) .06f else 0f), RoundedCornerShape(30.dp)).padding(vertical = 12.dp),
                horizontalArrangement = Arrangement.SpaceEvenly) {
                listOf(Icons.Outlined.Home, Icons.Outlined.Security, Icons.Outlined.Layers, Icons.Outlined.Settings).forEachIndexed { index, icon ->
                    androidx.compose.material3.Icon(icon, null, tint = if (index == 0) primary else muted, modifier = Modifier.size(20.dp))
                }
            }
        }
    }
    }
}

@Composable
private fun IntroText(value: String, mode: UiMode, color: Color, size: Int, weight: FontWeight = FontWeight.Normal, modifier: Modifier = Modifier) {
    if (mode == UiMode.Miuix) top.yukonga.miuix.kmp.basic.Text(value, modifier = modifier, color = color, fontSize = size.sp, fontWeight = weight)
    else androidx.compose.material3.Text(value, modifier = modifier, color = color, fontSize = size.sp, fontWeight = weight)
}
