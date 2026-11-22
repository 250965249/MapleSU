package com.maplesu.core.ui

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Layout contracts complement device checks; these do not render Compose. */
class AppearanceIntroContractTest {
    private val source = File("src/main/java/com/maplesu/core/ui/screen/settings/AppearanceIntroScreen.kt").readText()

    @Test fun shortWindowsAndLargeTextKeepTheStartActionReachable() {
        assertTrue(source.contains("maxHeight < 680.dp || LocalDensity.current.fontScale > 1.3f"))
        assertTrue(source.contains("verticalScroll(rememberScrollState())"))
        assertTrue(source.contains("onClick = onFinish"))
    }

    @Test fun largeTextChoicesStackAndReserveSpaceForTheSelectionIcon() {
        assertTrue(source.contains("maxWidth < 280.dp || LocalDensity.current.fontScale > 1.3f"))
        assertTrue(source.contains("AppearanceStyleChoice(style, mode, onSelect, surface, primary, text, Modifier.fillMaxWidth())"))
        assertTrue(source.contains("modifier = Modifier.weight(1f)"))
        assertTrue(source.contains("Role.RadioButton"))
    }

    @Test fun miniaturePreviewDoesNotScaleTheRealActionText() {
        val preview = source.substringAfter("private fun BoxScope.AppearancePhonePreview")
            .substringBefore("private fun IntroText")
        assertTrue(preview.contains("Density(density.density, 1f)"))
        assertTrue(preview.contains("graphicsLayer { scaleX = scale; scaleY = scale }"))
        assertTrue(source.substringBefore("private fun BoxScope.AppearancePhonePreview").contains("appearance_intro_start"))
    }

    @Test fun bothSkinsUseTheirActualPaletteAndControls() {
        assertTrue(source.contains("MiuixTheme.colorScheme.primary else MaterialTheme.colorScheme.primary"))
        assertTrue(source.contains("top.yukonga.miuix.kmp.basic.TextButton("))
        assertTrue(source.contains("androidx.compose.material3.Button("))
    }
}
