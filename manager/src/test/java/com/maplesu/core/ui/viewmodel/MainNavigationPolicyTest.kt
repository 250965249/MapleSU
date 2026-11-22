package com.maplesu.core.ui.viewmodel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MainNavigationPolicyTest {
    private fun homeOnly(
        installedVersion: Boolean = false,
        liteInstalled: Boolean = false,
        gki: Boolean = true,
        pending: Boolean = false,
        masking: Boolean = false,
        confirming: Boolean = false,
    ) = MainNavigationPolicy.isHomeOnly(
        hasInstalledVersion = installedVersion,
        liteInstalled = liteInstalled,
        isGkiKernel = gki,
        litePending = pending,
        hiddenMasking = masking,
        hiddenConfirming = confirming,
    )

    @Test fun settledUninstalledKernelShowsOnlyHome() {
        assertTrue(homeOnly())
    }

    @Test fun activeInstallationKeepsNavigation() {
        assertFalse(homeOnly(installedVersion = true))
        assertFalse(homeOnly(liteInstalled = true))
    }

    @Test fun pairedUltraColdStartRetainsNavigationWhileRuntimeIsUnknown() {
        assertFalse(homeOnly(liteInstalled = true, pending = true))
    }

    @Test fun initialDetectionIsNotAnUninstalledResult() {
        assertFalse(homeOnly(pending = true))
    }

    @Test fun hiddenConfirmationHasPriorityOverMasking() {
        assertFalse(homeOnly(installedVersion = true, masking = true, confirming = true))
    }

    @Test fun confirmedHiddenProjectionMatchesUninstalledHome() {
        assertTrue(homeOnly(installedVersion = true, liteInstalled = true, masking = true))
        assertTrue(homeOnly(pending = true, masking = true))
    }

    @Test fun unsupportedKernelDoesNotBecomeUninstalled() {
        assertFalse(homeOnly(gki = false))
    }

    @Test fun restoringOtherPagesReturnsToHomeWhenUninstalled() {
        (0 until MainPagerConfig.PAGE_COUNT).forEach { page ->
            assertEquals(0, MainNavigationPolicy.resolvePage(page, homeOnly = true))
        }
    }

    @Test fun installedNavigationKeepsAndBoundsRestoredPage() {
        (0 until MainPagerConfig.PAGE_COUNT).forEach { page ->
            assertEquals(page, MainNavigationPolicy.resolvePage(page, homeOnly = false))
        }
        assertEquals(0, MainNavigationPolicy.resolvePage(-1, homeOnly = false))
        assertEquals(MainPagerConfig.LAST_PAGE_INDEX, MainNavigationPolicy.resolvePage(100, homeOnly = false))
    }
}
