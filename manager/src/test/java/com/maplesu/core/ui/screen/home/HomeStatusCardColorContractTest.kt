package com.maplesu.core.ui.screen.home

import com.materialkolor.dynamiccolor.ColorSpec
import com.materialkolor.dynamiccolor.MaterialDynamicColors
import com.materialkolor.hct.Hct
import com.materialkolor.scheme.SchemeTonalSpot
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import javax.imageio.ImageIO
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow

/** Source wiring and pixel contrast checks, not an Android rendering test. */
class HomeStatusCardColorContractTest {
    private fun source(name: String) =
        File("src/main/java/com/maplesu/core/ui/screen/home/$name.kt").readText()

    @Test fun miuixStatusTextUsesItsOwnTypographyAndExplicitForeground() {
        val source = source("HomeMiuix")
        assertFalse(source.contains("import androidx.compose.material3.LocalContentColor"))
        assertFalse(source.contains("import androidx.compose.material3.LocalTextStyle"))
        val card = source.substringAfter("internal fun StatusCard(").substringBefore("state.kernelVersion.isGKI() ->")
        assertTrue(card.contains("MiuixTheme.textStyles.main"))
        assertTrue(card.contains("contentColor = statusContentColor"))
        assertTrue(Regex("color = statusContentColor").findAll(card).count() >= 3)
        assertTrue(card.contains("decoration != null -> Color.White"))
        assertTrue(card.contains("themeArt.file != null -> themeArt.foreground"))
        assertTrue(card.contains("else -> homeStatusContentColor()"))
    }

    @Test fun defaultCardsShareReadableGreenSurfacesAcrossEveryArrangement() {
        for (name in listOf("HomeMiuix", "HomeMaterial", "HomeThemeLayouts")) {
            assertTrue(name, source(name).contains("homeStatusContainerColor()"))
        }
        for ((foreground, background) in listOf(0x164A29 to 0xDFFAE4, 0xB8E8C5 to 0x1A3825)) {
            assertTrue("green status text contrast", contrast(foreground, background) >= 4.5)
        }
    }

    @Test fun imageTextHasAThemeIndependentMinimumScrimAtBothEdges() {
        val source = source("HomeMiuix")
        assertTrue(source.contains("val textScrimFloor = if (decorHideText) 0f else 0.56f"))
        assertTrue(source.contains("maxOf(decorDim, textScrimFloor)"))
        assertTrue(source.contains("maxOf(decorDim * 0.33f, textScrimFloor)"))
        assertTrue(source.contains("if (decorDim > 0f || textScrimFloor > 0f)"))
        val whiteAfterScrim = blendBlack(0xFFFFFF, 0.56)
        assertTrue("worst-case white artwork", contrast(0xFFFFFF, whiteAfterScrim) >= 4.5)
    }

    @Test fun bundledArtworkKeepsReadableWhiteTextAcrossEveryPixelInBothThemes() {
        val image = ImageIO.read(File("src/main/res/drawable-nodpi/art_default.jpg"))
        var lowestContrast = Double.POSITIVE_INFINITY
        for (y in 0 until image.height) for (x in 0 until image.width) {
            lowestContrast = min(lowestContrast, contrast(0xFFFFFF, blendBlack(image.getRGB(x, y), 0.56)))
        }
        assertTrue("bundled artwork minimum contrast=$lowestContrast", lowestContrast >= 4.5)
    }

    @Test fun materialStatusAndLoadingCardsKeepOpaqueSemanticPairs() {
        val source = source("HomeMaterial")
        val status = source.substringAfter("internal fun MaterialStatusCard(").substringBefore("private fun About7kCard(")
        assertTrue(status.contains("if (ksuActive)"))
        assertTrue(status.contains("MaterialTheme.colorScheme.onSecondaryContainer"))
        assertTrue(status.contains("MaterialTheme.colorScheme.onErrorContainer"))
        assertTrue(status.contains("supportingContentColor = contentColor"))
        assertFalse(status.contains("contentColor.copy(alpha ="))
        assertFalse(status.contains("contentColorFor(containerColor)"))
    }

    @Test fun selectedThemeSeedsKeepReadableMaterialStatusPairsInBothSpecsAndModes() {
        val colors = MaterialDynamicColors()
        val seeds = Regex("Color\\(0x([A-Fa-f0-9]{8})\\)")
            .findAll(File("src/main/java/com/maplesu/core/ui/theme/Colors.kt").readText())
            .map { it.groupValues[1].toLong(16).toInt() }.toList()
        assertTrue(seeds.isNotEmpty())
        for (seed in seeds) for (dark in listOf(false, true)) for (spec in ColorSpec.SpecVersion.entries) {
            val scheme = SchemeTonalSpot(Hct.fromInt(seed), dark, 0.0, spec)
            val secondary = contrast(colors.onSecondaryContainer().getArgb(scheme), colors.secondaryContainer().getArgb(scheme))
            val error = contrast(colors.onErrorContainer().getArgb(scheme), colors.errorContainer().getArgb(scheme))
            assertTrue("seed=$seed dark=$dark spec=$spec secondary=$secondary", secondary >= 4.5)
            assertTrue("seed=$seed dark=$dark spec=$spec error=$error", error >= 4.5)
        }
    }

    private fun blendBlack(rgb: Int, alpha: Double): Int {
        fun channel(shift: Int) = (((rgb shr shift) and 255) * (1.0 - alpha)).toInt()
        return (channel(16) shl 16) or (channel(8) shl 8) or channel(0)
    }

    private fun luminance(rgb: Int): Double {
        fun channel(shift: Int): Double {
            val value = ((rgb shr shift) and 255) / 255.0
            return if (value <= 0.04045) value / 12.92 else ((value + 0.055) / 1.055).pow(2.4)
        }
        return 0.2126 * channel(16) + 0.7152 * channel(8) + 0.0722 * channel(0)
    }

    private fun contrast(a: Int, b: Int): Double {
        val first = luminance(a)
        val second = luminance(b)
        return (max(first, second) + 0.05) / (min(first, second) + 0.05)
    }
}
