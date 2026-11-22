package com.maplesu.core.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Both theme and root-scaffold branches must move the same navigation composition. */
class NavigationSkinIdentityContractTest {
    private fun source(path: String) = File("src/main/java/com/maplesu/core/ui/$path").readText()

    @Test fun skinContentMovesWithoutRememberingTheFirstCallback() {
        val helper = source("theme/SkinContent.kt")
        assertTrue(helper.contains("val currentContent by rememberUpdatedState(content)"))
        assertTrue(helper.contains("return remember { movableContentOf { currentContent() } }"))
        assertFalse(helper.contains("remember(content)"))
    }

    @Test fun themeKeepsOneContentIdentityAcrossBothNativeProviders() {
        val theme = source("theme/Theme.kt").substringAfter("fun KernelSUTheme(").substringBefore("@Composable\n@ReadOnlyComposable")
        assertTrue(theme.contains("val skinContent = rememberSkinContent(content)"))
        assertTrue(theme.indexOf("val skinContent") < theme.indexOf("when (uiMode)"))
        assertEquals(2, Regex("content = skinContent").findAll(theme).count())
    }

    @Test fun rootScaffoldsPlaceOneMovableNavDisplay() {
        val activity = source("MainActivity.kt")
        assertTrue(activity.contains("val navDisplay = rememberSkinContent {"))
        assertEquals(1, Regex("NavDisplay\\(").findAll(activity).count())
        assertEquals(2, Regex("\\{ navDisplay\\(\\) }").findAll(activity).count())
        assertTrue(activity.contains("UiMode.Miuix -> Scaffold { navDisplay() }"))
    }

    @Test fun mainPagerMovesAcrossPhoneRailAndNativeScaffoldsWithCurrentInsets() {
        val activity = source("MainActivity.kt")
        val pagerStart = activity.indexOf("val pagerContent = rememberSkinContentWithParameter { bottomInnerPadding: Dp ->")
        assertTrue(pagerStart > 0)
        assertTrue(pagerStart < activity.indexOf("if (useNavigationRail) {"))
        val helper = source("theme/SkinContent.kt")
        assertTrue(helper.contains("movableContentOf<T> { parameter -> currentContent(parameter) }"))
    }

    @Test fun firstRunSceneAndRevealHostStayOutsideNavigation() {
        val activity = source("MainActivity.kt")
        assertTrue(activity.indexOf("val navigator = rememberNavigator") < activity.indexOf("SkinTransitionHost(skin)"))
        assertTrue(activity.contains("if (!skin.appliedScene)"))
        assertTrue(activity.contains("AppearanceIntroScreen(uiMode, viewModel::selectUiMode, viewModel::finishAppearanceIntro,"))
        assertTrue(activity.contains("uiState.introComic, viewModel::setIntroComic"))
        assertTrue(activity.contains("onBackEnabledChange = { enabled ->"))
    }

    @Test fun settingsKeepsBothNativeScrollPositionsOutsideSkinBranches() {
        val screen = source("screen/settings/SettingsScreen.kt")
        listOf("val miuixListState = rememberLazyListState()", "val materialScrollState = rememberScrollState()", "val miuixTopBarState", "val materialTopBarState").forEach {
            assertTrue(it, screen.indexOf(it) in 0 until screen.indexOf("when (LocalUiMode.current)"))
        }
        val miuix = source("screen/settings/SettingsMiuix.kt")
        assertTrue(miuix.contains("state = listState"))
        assertTrue(miuix.contains("MiuixScrollBehavior(topBarState)"))
        val material = source("screen/settings/SettingsMaterial.kt")
        assertTrue(material.contains(".verticalScroll(scrollState)"))
        assertFalse(material.contains("rememberScrollState()"))
        assertTrue(material.contains("exitUntilCollapsedScrollBehavior(topBarState)"))
    }
}
