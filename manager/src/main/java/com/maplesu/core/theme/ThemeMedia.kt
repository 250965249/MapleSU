package com.maplesu.core.theme

import android.graphics.ImageDecoder
import android.graphics.drawable.Animatable
import android.graphics.drawable.Drawable
import android.media.MediaPlayer
import android.widget.ImageView
import android.widget.ImageView.ScaleType
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

internal data class ThemePhoto(val file: File, val drawable: Drawable, val luminance: Float)
private data class ThemePhotoLoad(val path: String?, val photo: ThemePhoto?)
internal val LocalThemePhotoContent = staticCompositionLocalOf<Color?> { null }
internal val LocalThemeHomeForeground = staticCompositionLocalOf { true }

@Composable
internal fun rememberThemePhoto(file: File?): ThemePhoto? {
    // Keep the last decoded frame until its replacement is ready; a page change is not a removal.
    val path = file?.absolutePath
    val loaded by produceState(ThemePhotoLoad(null, null), path) {
        val photo = file?.let { withContext(Dispatchers.IO) {
            runCatching {
                val drawable = ImageDecoder.decodeDrawable(ImageDecoder.createSource(it)) { decoder, info, _ ->
                    val scale = (2048f / maxOf(info.size.width, info.size.height)).coerceAtMost(1f)
                    decoder.setTargetSize((info.size.width*scale).toInt().coerceAtLeast(1),(info.size.height*scale).toInt().coerceAtLeast(1))
                }
                ThemePhoto(it,drawable,imageLuminance(it))
            }.getOrNull()
        } }
        value = ThemePhotoLoad(path, photo)
    }
    ThemeStartupResource(path == null || loaded.path == path)
    return if (file == null) null else loaded.photo
}

/** Decode off the UI thread; animated GIFs stop when their owning page leaves the foreground. */
@Composable
fun ThemeImage(file: File?, modifier: Modifier = Modifier, description: String? = null, scaleType: ScaleType = ScaleType.CENTER_CROP) {
    ThemePhotoImage(rememberThemePhoto(file),modifier,description,scaleType)
}

@Composable
internal fun ThemePhotoImage(photo: ThemePhoto?, modifier: Modifier = Modifier, description: String? = null, scaleType: ScaleType = ScaleType.CENTER_CROP) {
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val drawable = photo?.drawable
    val foreground = LocalThemeHomeForeground.current
    DisposableEffect(drawable, lifecycle, foreground) {
        val animation = drawable as? Animatable
        if (foreground && lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) animation?.start()
        val observer = LifecycleEventObserver { _, event ->
            if (foreground && event == Lifecycle.Event.ON_START) animation?.start()
            if (event == Lifecycle.Event.ON_STOP) animation?.stop()
        }
        lifecycle.addObserver(observer)
        onDispose { animation?.stop(); lifecycle.removeObserver(observer) }
    }
    AndroidView(modifier = modifier.clipToBounds(), factory = { ImageView(it).apply { this.scaleType = scaleType } },
        update = { if (it.drawable !== drawable) it.setImageDrawable(drawable); it.scaleType=scaleType; it.contentDescription = description })
}

@Composable
fun ThemeSurfaceBox(base: String, modifier: Modifier = Modifier, content: @Composable BoxScope.() -> Unit) {
    val j = ThemeRuntime.observe()
    val context = LocalContext.current
    val dark = com.maplesu.core.ui.theme.isInDarkTheme()
    val surface = ThemeSurface.read(j, base, dark)
    val file = remember(j, base) { if (base.isNotEmpty() && surface.enabled) ThemeRuntime.file(context, base) else null }
    val photo = rememberThemePhoto(file)?.takeIf { surface.opacity > 0f }
    val foreground = photo?.let { themePhotoForeground(it.luminance,surface.dim) }
    Box(modifier) {
        if (photo != null) {
            ThemePhotoImage(photo, Modifier.matchParentSize().alpha(surface.opacity))
            Box(Modifier.matchParentSize().background((if (foreground == Color.White) Color.Black else Color.White).copy(alpha = surface.dim)))
        }
        CompositionLocalProvider(LocalThemePhotoContent provides foreground) { content() }
    }
}

internal fun themePhotoForeground(luminance: Float, dim: Float): Color =
    if (luminance >= 0f && luminance*(1f-dim.coerceIn(0f,1f)) > .5f) Color(0xFF141218) else Color.White

object ThemeMusic {
    var requested by mutableStateOf(false)
        internal set
    var playing by mutableStateOf(false)
        internal set
    fun toggle() { requested = !requested }
}

/** One player per active resource; controls change playback without preparing another decoder. */
@Composable
fun ThemeMediaHost() {
    val context = LocalContext.current
    val j = ThemeRuntime.observe()
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val generation = ThemeRuntime.generation(context)?.name
    val enabled = j.optBoolean("isMusicEnabled")
    val filename = j.optString("musicFilename")
    val autoplay = j.optBoolean("isAutoPlayEnabled")
    val looping = j.optBoolean("isLoopingEnabled")
    val volume = j.optDouble("musicVolume", 1.0).toFloat().coerceIn(0f, 1f)
    val requested = rememberUpdatedState(ThemeMusic.requested)
    var player by remember { mutableStateOf<MediaPlayer?>(null) }
    var ready by remember { mutableStateOf(false) }
    LaunchedEffect(generation, enabled, filename) { ThemeMusic.requested = enabled && autoplay }
    DisposableEffect(generation, enabled, filename, lifecycle) {
        val file = if (enabled) ThemeRuntime.namedFile(context, filename) else null
        var prepared = false
        ready = false
        val current = file?.let { MediaPlayer() }
        player = current
        if (file != null && current != null) runCatching {
            current.setDataSource(file.absolutePath)
            current.isLooping = looping; current.setVolume(volume, volume)
            current.setOnErrorListener { _, _, _ -> ready = false; ThemeMusic.playing = false; ThemeMusic.requested = false; true }
            current.setOnCompletionListener { ThemeMusic.playing = false; ThemeMusic.requested = false }
            current.setOnPreparedListener {
                prepared = true
                ready = true
                if (requested.value && lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                    it.start(); ThemeMusic.playing = true
                }
            }
            current.prepareAsync()
        }.onFailure { current.release(); player = null; ThemeMusic.requested = false }
        val observer = LifecycleEventObserver { _, event -> runCatching {
            if (prepared && event == Lifecycle.Event.ON_STOP) { current?.pause(); ThemeMusic.playing = false }
            if (prepared && requested.value && event == Lifecycle.Event.ON_START) { current?.start(); ThemeMusic.playing = true }
            if (event == Lifecycle.Event.ON_STOP) ThemeSound.stop()
        } }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer); runCatching { current?.release() }; player = null; ThemeMusic.playing = false; ThemeSound.stop() }
    }
    LaunchedEffect(ThemeMusic.requested, player, ready, looping, volume) {
        if (!ready) return@LaunchedEffect
        runCatching {
            player?.let {
                it.isLooping = looping; it.setVolume(volume, volume)
                if (ThemeMusic.requested && lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) { it.start(); ThemeMusic.playing = true }
                else if (it.isPlaying) { it.pause(); ThemeMusic.playing = false }
            }
        } // A preparing player starts from its prepared callback.
    }
}

object ThemeSound {
    private var player: MediaPlayer? = null
    fun play(context: android.content.Context, bottomBar: Boolean) {
        val j = ThemeRuntime.document(context)
        if (!j.optBoolean("isSoundEffectEnabled") || !bottomBar && j.optString("soundEffectScope", "global") == "bottom_bar") return
        val file = ThemeRuntime.namedFile(context, j.optString("soundEffectFilename")) ?: return
        player?.release()
        val next = MediaPlayer()
        player = next
        runCatching {
            next.setDataSource(file.absolutePath)
            next.setOnPreparedListener { if (player === it) it.start() }
            next.setOnCompletionListener { it.release(); if (player === it) player = null }
            next.setOnErrorListener { p, _, _ -> p.release(); if (player === p) player = null; true }
            next.prepareAsync()
        }.onFailure { next.release(); if (player === next) player = null }
    }
    fun stop() { player?.release(); player = null }
}
