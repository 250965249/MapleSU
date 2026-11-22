package com.maplesu.core.ui.component.material

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.maplesu.core.data.repository.SettingsRepositoryImpl
import com.maplesu.core.ui.util.NavIcons
import com.maplesu.core.ui.util.StatusDecoration
import com.maplesu.core.ui.util.StatusDecorationImage
import com.maplesu.core.ui.util.WallpaperPrefs

/**
 * 个性化(美化类)里两个"带画面"的零件 —— Miuix 侧这两个是 SettingsMiuix.kt 里的私有函数,
 * Material 侧以前**完全没有**(整个个性化段都没建)。2026-09-16 第二批补齐时搬过来,
 * 保证两份界面的取景数学、渲染函数、配置键都只有一处定义。
 */

/**
 * 导航图标设置行右侧的小预览:显示当前选好的那张图(圆形/着色与导航栏一致)。
 *
 * 读 [WallpaperPrefs.observe] 是为了「导航图标裁成圆形」一拨开关预览就跟着变
 * —— 那个开关写的是 prefs,不订阅的话这里不会重组。
 */
@Composable
internal fun NavIconPreview(key: String) {
    val context = LocalContext.current
    val rev = WallpaperPrefs.observe()
    val circle = remember(rev) { SettingsRepositoryImpl().navIconCircle }
    val bitmap by produceState<ImageBitmap?>(null, context, key, NavIcons.version) {
        value = withContext(Dispatchers.IO) { NavIcons.load(context, key, 96) }
    }
    val image = bitmap ?: return
    Image(
        bitmap = image,
        contentDescription = null,
        modifier = Modifier
            .size(28.dp)
            .then(if (circle) Modifier.clip(CircleShape) else Modifier),
        contentScale = ContentScale.Crop,
    )
}

/**
 * 「自裁取景」弹窗(双皮肤):把卡片比例的一块区域当取景框,拖动/双指缩放调整。
 *
 * 预览用的是首页同一份渲染([StatusDecorationImage]),所以所见即所得;
 * 卡片比例也必须和首页共用 [StatusDecoration.CARD_ASPECT_RATIO]，
 * 否则取景框比例对不上。
 *
 * 弹窗与操作按钮由 ThemeDialog 按当前 MIUIX / Material 设计语言绘制。
 */
@Composable
internal fun DecorationCropDialog(
    onDismiss: () -> Unit,
    onApply: (biasX: Float, biasY: Float, zoom: Float) -> Unit,
) {
    val context = LocalContext.current
    val density = LocalDensity.current
    val config = LocalConfiguration.current
    val miuix = com.maplesu.core.ui.LocalUiMode.current == com.maplesu.core.ui.UiMode.Miuix
    val appearanceRevision = com.maplesu.core.ui.util.WallpaperPrefs.observe()
    val cardPrefs = remember(appearanceRevision) { SettingsRepositoryImpl() }
    val largeCard = miuix && cardPrefs.homeLargeCard
    val screenWidthPx = with(density) { config.screenWidthDp.dp.roundToPx() }
    val bitmap = com.maplesu.core.ui.util.rememberStatusDecoration(screenWidthPx)
    val repo = remember { SettingsRepositoryImpl() }
    var biasX by remember { mutableFloatStateOf(repo.statusDecorationBiasX) }
    var biasY by remember { mutableFloatStateOf(repo.statusDecorationBiasY) }
    var zoom by remember { mutableFloatStateOf(repo.statusDecorationZoom) }
    com.maplesu.core.ui.screen.settings.ThemeDialog(
        title = "自裁取景", onDismiss = onDismiss,
        onConfirm = { onApply(biasX,biasY,zoom) },
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Box(
                Modifier.fillMaxWidth()
                    .aspectRatio(if (largeCard) StatusDecoration.CARD_ASPECT_RATIO else StatusDecoration.COMPACT_PREVIEW_ASPECT_RATIO)
                    .clip(RoundedCornerShape(16.dp)).background(Color.Black)
                    .pointerInput(Unit) {
                        detectTransformGestures { _,pan,gestureZoom,_ ->
                            biasX=(biasX-pan.x/size.width.toFloat().coerceAtLeast(1f)*2f).coerceIn(-1f,1f)
                            biasY=(biasY-pan.y/size.height.toFloat().coerceAtLeast(1f)*2f).coerceIn(-1f,1f)
                            zoom=(zoom*gestureZoom).coerceIn(1f,4f)
                        }
                    },
            ) {
                bitmap?.let { StatusDecorationImage(it,biasX,biasY,zoom,Modifier.matchParentSize()) }
            }
            com.maplesu.core.ui.screen.settings.ThemeText(
                "拖动调位置 · 双指缩放 · 现在是 ${"%.1f".format(zoom)}×",Modifier.padding(top=8.dp))
            Row(Modifier.fillMaxWidth().padding(top=8.dp),horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                Box(Modifier.weight(1f)) { com.maplesu.core.ui.screen.settings.ThemeButton("缩小",zoom>1f) { zoom=(zoom-.25f).coerceAtLeast(1f) } }
                Box(Modifier.weight(1f)) { com.maplesu.core.ui.screen.settings.ThemeButton("放大",zoom<4f) { zoom=(zoom+.25f).coerceAtMost(4f) } }
                Box(Modifier.weight(1f)) { com.maplesu.core.ui.screen.settings.ThemeButton("复位") { biasX=0f; biasY=0f; zoom=1f } }
            }
        }
    }
}
