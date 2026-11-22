package com.maplesu.core.ui.screen.home

import com.maplesu.core.R
import org.junit.Assert.assertEquals
import org.junit.Test

class AboutCreditContractTest {
    @Test fun finasuCreditHasTheOfficialLinkAndRequestedRole() {
        val credit = ABOUT_CREDITS.single { it.name == "FinaSU" }
        assertEquals("https://github.com/LyraVoid/FinaSU", credit.url)
        assertEquals(R.string.about_maple_credit_finasu, credit.role)
    }

    @Test fun officialChannelUsesTheSharedDestination() {
        assertEquals("https://t.me/KernelMapleSU", ABOUT_TELEGRAM_URL)
        val text = aboutCommunityText("官方频道", androidx.compose.ui.graphics.Color.Blue)
        assertEquals("官方频道\nTelegram · @KernelMapleSU", text.text)
        val link = text.getLinkAnnotations(0, text.length).single().item as androidx.compose.ui.text.LinkAnnotation.Url
        assertEquals(ABOUT_TELEGRAM_URL, link.url)
    }

    @Test fun creditsDescribeTheReferencesBeforeTheDirectBase() {
        assertEquals(listOf("FinaSU", "KernelSU", "7kimisu", "KernelPatch", "SKRoot"),
            ABOUT_CREDITS.map { it.name })
        assertEquals("https://github.com/abcz316/SKRoot-linuxKernelRoot", ABOUT_CREDITS.last().url)
        assertEquals(R.string.about_maple_credit_sdk, ABOUT_CREDITS.last().role)
    }

    @Test fun overviewAndBothModeIntroductionsRemainAvailable() {
        assertEquals(R.string.about_maple_overview, aboutOverview(true))
        assertEquals(R.string.about_maple_overview_plain, aboutOverview(false))
        assertEquals(listOf(R.string.about_maple_ultra_point_kernel,
            R.string.about_maple_ultra_point_selinux, R.string.about_maple_ultra_point_side_channel),
            ABOUT_ULTRA_POINTS)
    }
}
