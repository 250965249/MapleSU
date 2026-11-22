package com.maplesu.core.theme

import android.graphics.Bitmap
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toPixelMap
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import java.io.File

/** A page change must not clear the frame that is already on screen while decoding. */
class ThemeWallpaperTransitionDeviceTest {
    @get:Rule val compose = createComposeRule()

    @Test fun decodedPageChangesKeepTheLastFrameWhileLoading() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = File(context.cacheDir, "wallpaper-transition").apply { mkdirs() }
        val files = listOf(android.graphics.Color.RED, android.graphics.Color.BLUE).mapIndexed { i, color ->
            File(directory, "page-$i.png").also { file ->
                Bitmap.createBitmap(2048, 2048, Bitmap.Config.ARGB_8888).let { bitmap ->
                    bitmap.eraseColor(color)
                    file.outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
                    bitmap.recycle()
                }
            }
        }
        var requested by mutableStateOf<File?>(files.first())
        var drawn: ThemePhoto? = null
        val frames = mutableListOf<Pair<File?, File?>>()
        compose.setContent {
            val photo = rememberThemePhoto(requested)
            SideEffect { drawn = photo; frames += requested to photo?.file }
            ThemePhotoImage(photo, Modifier.fillMaxSize())
        }
        compose.waitUntil(10_000) { drawn?.file == files.first() }
        compose.runOnIdle { frames.clear(); requested = files.last() }
        compose.waitUntil(10_000) { drawn?.file == files.last() }
        repeat(12) { index ->
            compose.runOnIdle { requested = files[index % files.size] }
            compose.waitUntil(10_000) { drawn?.file == files[index % files.size] }
        }
        compose.runOnIdle {
            assertTrue("Page switch cleared a decoded wallpaper: $frames", frames.none { it.first != null && it.second == null })
            requested = null
        }
        compose.waitUntil(10_000) { drawn == null }
        directory.deleteRecursively()
    }

    @Test fun renderedFadeKeepsThePreviousWallpaperOpaqueUntilTheNewFrameCoversIt() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.endsWith(".themetest"))
        val prefs = com.maplesu.core.ui.util.AppearancePreferences.prefs(context)
        val previous = prefs.getString("theme_document",null)
        val directory = File(context.cacheDir,"wallpaper-fade").apply { mkdirs() }
        val files = listOf(android.graphics.Color.RED,android.graphics.Color.BLUE).mapIndexed { index,color ->
            File(directory,"$index.png").also { file ->
                Bitmap.createBitmap(128,128,Bitmap.Config.ARGB_8888).let { bitmap ->
                    bitmap.eraseColor(color)
                    file.outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG,100,it) }
                    bitmap.recycle()
                }
            }
        }
        try {
            prefs.edit().putString("theme_document","{\"isBackgroundEnabled\":true,\"isDualBackgroundDimEnabled\":true,\"backgroundDayDim\":0,\"backgroundNightDim\":0}").commit()
            var requested by mutableStateOf(files.first())
            var drawn: ThemePhoto? = null
            compose.mainClock.autoAdvance=false
            compose.setContent {
                val photo = rememberThemePhoto(requested)
                SideEffect { drawn=photo }
                CompositionLocalProvider(com.maplesu.core.ui.LocalUiMode provides com.maplesu.core.ui.UiMode.Material,
                    LocalThemeWallpaperFrame provides ThemeWallpaperFrame(ThemeBackgroundSelection(image=requested),photo),
                    LocalThemeWallpaperStyle provides ThemeWallpaperStyle(1f,false,0f)) {
                    androidx.compose.material3.MaterialTheme(colorScheme=androidx.compose.material3.lightColorScheme(surface=Color.Green)) {
                        ThemeBackground(0,legacy={},content={})
                    }
                }
            }
            compose.waitUntil(10_000) { compose.mainClock.advanceTimeByFrame(); drawn?.file == files.first() }
            compose.mainClock.advanceTimeBy(300)
            compose.runOnIdle { requested=files.last() }
            compose.waitUntil(10_000) { compose.mainClock.advanceTimeByFrame(); drawn?.file == files.last() }
            repeat(10) {
                compose.mainClock.advanceTimeBy(16)
                val pixels=compose.onRoot().captureToImage().toPixelMap()
                val pixel=pixels[pixels.width/2,pixels.height/2]
                assertTrue("Fallback leaked into a transition frame: $pixel",pixel.green < .04f && pixel.red+pixel.blue > .95f)
            }
        } finally {
            prefs.edit().putString("theme_document",previous).commit()
            directory.deleteRecursively()
        }
    }
}
