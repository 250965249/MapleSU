package com.maplesu.core.ui.util

import android.graphics.SurfaceTexture
import android.media.MediaPlayer
import android.view.Surface
import android.view.TextureView
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.BlurredEdgeTreatment
import androidx.compose.ui.draw.blur
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.maplesu.core.data.repository.SettingsRepositoryImpl

private const val TAG = "maplesu-wallpaper"

/**
 * v2.8:壁纸"粘住"用的缓存槽 —— 记住**上一次真的画出"用户自己那份"**的结果
 * (文件路径 + 画出来的那份),这样下一次"退级"时能继续用它,壁纸不会闪。
 * 为什么不是 `mutableStateOf`:它只是"上一帧的缓存",不需要参与快照/失效。
 * 详见 [WallpaperHost] 里那段注释。
 */
private class LastGoodDrawn {
    var pair: Pair<String?, WallpaperStore.Drawn.Img>? = null
}

/**
 * 个性化壁纸宿主:在内容底下画一层背景(图片或视频),再压一层暗色,最后才是界面。
 * 没有设置壁纸时它什么都不做,零开销。
 *
 * **分朝向**(v0.13.160):竖屏用竖屏那份,横屏优先用横屏那份;
 * 横屏那份没设(或文件丢了)→ 回退到竖屏那份 = 升级前的行为。
 * 朝向变了这里会重组(转屏时 Compose 的 configuration 变),所以是实时切换的。
 *
 * **v2.1(审计 P0-1)回退链已收窄（2026-10-30 去掉内置默认图）**:
 * 设置里写着"有壁纸"、但那份文件**读不出来**时:
 *   ① 先试**另一朝向**那份;
 *   ② 都读不出来 → 什么都不画,留纯主题背景(不报错、不弹 toast)。
 * 视频也一样:MediaPlayer 出错会退到另一槽;再不行也是纯主题背景。
 * 旧的"退到内置默认图"已彻底删除,APK 里也不再带默认壁纸资源。
 *
 * 界面能不能"透出来"由主题的颜色透明度决定(见 ui/theme 里的 translucent)。
 */
@Composable
fun WallpaperHost(page: Int = 0, content: @Composable () -> Unit) {
    com.maplesu.core.theme.ThemeBackground(page, legacy = { LegacyWallpaperHost(content) }, content = content)
}

@Composable
internal fun LegacyWallpaperHost(content: @Composable () -> Unit) {
    val context = LocalContext.current
    // 现在该用哪一份壁纸:竖屏用竖屏那份,横屏优先用横屏那份
    val slot = rememberWallpaperSlot()

    // 壁纸设置一变就重组(靠 WallpaperPrefs 的 revision + WallpaperStore 的 version)
    val rev = WallpaperPrefs.observe()
    val storeVer = WallpaperStore.version
    val repo = remember(rev, storeVer) { SettingsRepositoryImpl() }

    // 自愈:设置里写了有壁纸、但文件**真的没了** → 复原成"未设置"并告诉用户。
    // ⚠️ v2.1(审计 P2-7):这段以前是组合期里的 `remember(rev, storeVer) { healIfBroken() }`
    //    —— 那等于**在主线程 stat/试读文件**,而且拖"壁纸可见度"滑杆时 rev 每帧都变,
    //    每帧都在主线程碰两次盘(掉帧来源)。现在挪到 LaunchedEffect + withContext(IO)。
    //    只以 storeVer 为 key:自愈是"清理",渲染侧的回退链已经不依赖它了。
    LaunchedEffect(storeVer) {
        val msg = withContext(Dispatchers.IO) {
            if (!WallpaperStore.healIfBroken()) return@withContext null
            if (WallpaperStore.kind(WallpaperStore.Slot.PORTRAIT) != "none") {
                // 竖屏那份还在 → 丢的是横屏那份,横屏已改回用竖屏那张
                "横屏壁纸文件已丢失(可能清过数据或换过安装包),横屏已改回用竖屏那张"
            } else {
                "壁纸文件已丢失(可能清过数据或换过安装包),已重置为未设置,请重新选一张"
            }
        }
        if (msg != null) {
            android.widget.Toast.makeText(context, msg, android.widget.Toast.LENGTH_LONG).show()
        }
    }

    // 实际生效的槽位:横屏没单独设 → 回退竖屏那份
    val kind = remember(rev, storeVer, slot) { WallpaperStore.effectiveKind(slot) }
    val dim = remember(rev, storeVer) { repo.wallpaperDim }
    val blurPx = remember(rev, storeVer) { repo.wallpaperBlur }

    // ⚠️ v0.13.157:隐身时**照常画壁纸**(原来这里有个 `StealthLook.isPlain()` 的"素颜"判断,已撤)。
    //    壁纸不是 root 特征 —— 一个没 root 的用户点进来同样有他自己设的背景图,
    //    隐身只该改"显示什么内容",不该改"长什么样"。设置本来就没动,这里只是不再拦。
    if (!AppearancePrefsPolicy.hasWallpaper(kind)) {
        content()
        return
    }

    // 视频播放失败 → 置 true,渲染链重新算一次(跳过视频,退到图/内置图)
    var videoFailed by remember(storeVer, slot) { mutableStateOf(false) }

    // 只拿【路径】当键,不用 rev ——
    // rev 在拖"壁纸可见度"滑杆时每帧都变,否则会每拖一下都重新解码一遍大图。
    // storeVer(v2.1,审计 P1-5)必须有:save/clear/heal 时 +1,换壁纸**立即生效**,不用转屏/重启。
    val primaryPath = remember(rev, storeVer, slot) { WallpaperStore.effectiveFile(slot)?.absolutePath }

    var loaded by remember(storeVer, slot, primaryPath, videoFailed) { mutableStateOf(false) }
    // Decode before the startup barrier opens; later changes retain the last good image.
    val resolved by produceState<WallpaperStore.Drawn?>(
        initialValue = null,
        storeVer, slot, primaryPath, videoFailed,
    ) {
        value = withContext(Dispatchers.IO) { WallpaperStore.resolveDrawn(slot, skipVideo = videoFailed) }
        loaded = true
    }
    com.maplesu.core.theme.ThemeStartupResource(loaded)

    // ⚠️ v2.8:壁纸**粘住** —— 解码是异步的,解码中 / 这次没解出来,都**不许**把上一次
    //    成功画出来的那张换掉(用户 2026-09-21 的验收要求:全程不消失、不闪)。
    //
    //    2026-10-30 去掉内置默认图后,`resolveDrawn` 失败时返回 null(纯主题背景)。
    //    为了不让"偶发解码失败"把用户眼前那张壁纸擦掉,这里仍然记住**上一次真的画出
    //    用户自己那份**的结果:只要还是同一个文件(`primaryPath` 没变)就继续用它,
    //    直到真的解出新的;真换了文件 / 真解码成功 → 立刻替换。
    //
    // 只记 [WallpaperStore.Drawn.Img]:视频失败时**就是要**退下来
    // (粘住一张放不出来的视频 = 一直黑屏),所以视频不参与粘滞。
    //
    // 用普通字段而不是 `mutableStateOf`:这是"上一帧的缓存",在组合期写入快照状态
    // 会多触发一轮重组;而它只在 `resolved` 变化时被读取,普通字段完全够用。
    val lastGood = remember { LastGoodDrawn() }
    // ⚠️ 先取成局部变量:`resolved` 是 `by` 委托属性,**不能智能转换**
    //    (Kotlin 对带自定义 getter 的属性不做 smart cast)。
    val now = resolved
    if (now is WallpaperStore.Drawn.Img && kind == "image") {
        lastGood.pair = primaryPath to now
    }
    val drawn: WallpaperStore.Drawn? = run {
        val sticky = lastGood.pair
        when {
            // 用户自己那份这次真的画成了 → 永远用最新的
            now is WallpaperStore.Drawn.Img -> now
            // 这次没解出来,但同一份文件上一次成功过 → 继续用它(壁纸不中断)
            now == null && sticky != null && primaryPath != null && sticky.first == primaryPath -> sticky.second
            else -> now
        }
    }

    val wallpaperModifier = Modifier
        .fillMaxSize()
        .then(
            if (blurPx > 0f) {
                Modifier.blur(blurPx.dp, edgeTreatment = BlurredEdgeTreatment.Unbounded)
            } else Modifier
        )

    Box(modifier = Modifier.fillMaxSize()) {
        // 只画用户自己那份。`null` = 读不出来/还没解析完 → 不画背景(纯主题背景),
        // 不报错、不弹 toast,也不存在任何内置默认图。
        when (val d = drawn) {
            is WallpaperStore.Drawn.Vid -> VideoLayer(d.path) { videoFailed = true }

            is WallpaperStore.Drawn.Img -> Image(
                bitmap = d.bitmap,
                contentDescription = null,
                modifier = wallpaperModifier,
                contentScale = ContentScale.Crop,
            )

            null -> Unit
        }

        // 暗度:只有真的画出壁纸时才压暗;纯主题背景不叠黑。
        if (drawn != null && dim > 0f) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Color.Black.copy(alpha = dim.coerceIn(0f, 0.9f)))
            )
        }

        content()
    }
}

/**
 * 视频壁纸:TextureView + MediaPlayer,静音循环播放,自动裁切铺满。
 *
 * · 用 key(path) 包住 → 换视频时旧播放器会被释放并重建
 * · 监听生命周期 → 切到后台暂停,回前台继续,不做无谓的解码耗电
 * · **v2.1(审计 P0-1)监听错误**:以前没有 `setOnErrorListener`,
 *   视频文件坏了 / 编码不支持时 MediaPlayer 只会静默黑屏,界面一直空着,
 *   用户以为"壁纸没了"。现在任何播放错误都回调 [onError],
 *   宿主据此跳过视频、退到另一槽;都没有就留纯主题背景。
 */
@Composable
internal fun VideoLayer(path: String, volume: Float = 0f, onError: () -> Unit) {
    val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current
    val playerHolder = remember { mutableStateOf<MediaPlayer?>(null) }
    val preparedHolder = remember { mutableStateOf(false) }
    // factory 只会跑一次,回调必须取"最新那个":用 rememberUpdatedState 包一层
    val onErrorState = rememberUpdatedState(onError)

    DisposableEffect(lifecycleOwner) {
        val observer = androidx.lifecycle.LifecycleEventObserver { _, event ->
            val p = playerHolder.value ?: return@LifecycleEventObserver
            if (!preparedHolder.value) return@LifecycleEventObserver
            runCatching {
                when (event) {
                    androidx.lifecycle.Lifecycle.Event.ON_STOP ->
                        if (p.isPlaying) p.pause()

                    androidx.lifecycle.Lifecycle.Event.ON_START ->
                        if (!p.isPlaying) p.start()

                    else -> Unit
                }
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    DisposableEffect(path, volume) {
        onDispose {
            preparedHolder.value = false
            runCatching { playerHolder.value?.release() }
            playerHolder.value = null
        }
    }

    key(path, volume) {
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { ctx ->
                TextureView(ctx).apply {
                    surfaceTextureListener = object : TextureView.SurfaceTextureListener {
                        private var player: MediaPlayer? = null
                        private var surface: Surface? = null

                        override fun onSurfaceTextureAvailable(st: SurfaceTexture, w: Int, h: Int) {
                            val candidate = MediaPlayer()
                            preparedHolder.value = false
                            player = runCatching {
                                candidate.apply {
                                    surface = Surface(st)
                                    setSurface(requireNotNull(surface))
                                    setDataSource(path)
                                    isLooping = true
                                    setVolume(volume.coerceIn(0f,1f), volume.coerceIn(0f,1f))
                                    setVideoScalingMode(MediaPlayer.VIDEO_SCALING_MODE_SCALE_TO_FIT_WITH_CROPPING)
                                    setOnPreparedListener {
                                        preparedHolder.value = true
                                        if (lifecycleOwner.lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED)) it.start()
                                    }
                                    // v2.1:播放中/解码出错 → 交给宿主退级(返回 true = 已处理,
                                    // 免得系统再弹一个"无法播放此视频")
                                    setOnErrorListener { _, what, extra ->
                                        android.util.Log.w(TAG, "视频壁纸播放出错 what=$what extra=$extra path=$path")
                                        onErrorState.value()
                                        true
                                    }
                                    prepareAsync()
                                }
                            }.onFailure {
                                candidate.release()
                                // setDataSource 就炸(文件没了/读不出来)也要退级 —— 这条路上
                                // MediaPlayer 不会回调 OnErrorListener,得自己报。
                                android.util.Log.w(TAG, "视频壁纸起不来:${it.javaClass.simpleName} ${it.message}")
                            }.getOrNull()
                            playerHolder.value = player
                            if (player == null) onErrorState.value()
                        }

                        override fun onSurfaceTextureSizeChanged(st: SurfaceTexture, w: Int, h: Int) {}

                        override fun onSurfaceTextureDestroyed(st: SurfaceTexture): Boolean {
                            preparedHolder.value = false
                            runCatching { player?.release() }
                            player = null
                            runCatching { surface?.release() }
                            surface = null
                            if (playerHolder.value === player) playerHolder.value = null
                            playerHolder.value = null
                            return true
                        }

                        override fun onSurfaceTextureUpdated(st: SurfaceTexture) {}
                    }
                }
            },
        )
    }
}
