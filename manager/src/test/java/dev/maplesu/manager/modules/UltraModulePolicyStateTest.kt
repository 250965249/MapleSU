package dev.maplesu.manager.modules

import com.maplesu.core.R
import com.maplesu.core.ui.screen.settings.statusRes
import com.maplesu.core.ui.screen.settings.hideUnavailableRes
import org.junit.Assert.*
import org.junit.Test

class UltraModulePolicyStateTest {
    @Test fun defaultsNeverClaimBackendReady() {
        val state = UltraModulePolicyState()
        assertFalse(state.loadRequested)
        assertFalse(state.hideRequested)
        assertFalse(state.operable)
        assertFalse(state.pendingReboot)
    }
    @Test fun savedAndEffectiveStayIndependent() {
        val state = UltraModulePolicyState.fromBackend(0, 0, 3).withLoad(true).withHide(true)
        assertEquals(3, state.requested)
        assertEquals(0, state.effective)
        assertTrue(state.pendingReboot)
        assertFalse(state.effectiveLoadAllowed)
    }
    @Test fun disablingLoadAlsoDisablesHiddenPreference() {
        val state = UltraModulePolicyState.fromBackend(3, 3, 3).withLoad(false)
        assertEquals(0, state.requested)
        assertFalse(state.hideRequested)
        assertEquals(3, state.effective)
        assertTrue(state.effectiveLoadAllowed)
        assertTrue(state.pendingReboot)
    }
    @Test fun hiddenPreferenceNeverEnablesLoadOnItsOwn() {
        val state = UltraModulePolicyState.fromBackend(0, 0, 3)
        assertEquals(state, state.withHide(true))
    }
    @Test fun repeatedEnableRetainsHiddenPreference() {
        val state = UltraModulePolicyState.fromBackend(3, 3, 3)
        assertEquals(state, state.withLoad(true))
    }
    @Test fun loadOnlyBackendDoesNotClaimHide() {
        val state = UltraModulePolicyState.fromBackend(1, 1, 1)
        assertTrue(state.operable)
        assertFalse(state.hideOperable)
    }
    @Test fun verifiedCompatibilityEnablesHideWithoutRiskConfirmation() {
        for (canTryUnverified in listOf(false, true)) {
            val state = UltraModulePolicyState.fromBackend(1, 1, 3, canTryUnverified = canTryUnverified)
            assertTrue(state.hideOperable)
            assertFalse(state.hideNeedsRiskConfirmation)
            val enabled = state.withHide(true)
            assertEquals(3, enabled.requested)
            assertFalse(enabled.unverifiedHide)
            assertEquals(1, enabled.effective)
            assertTrue(enabled.pendingReboot)
            assertFalse(enabled.hideNeedsRiskConfirmation)
        }
    }
    @Test fun unverifiedKernelRequiresConsentBeforeSavingHide() {
        val state = UltraModulePolicyState.fromBackend(1, 1, 1, canTryUnverified = true)
        assertTrue(state.hideOperable)
        assertTrue(state.hideNeedsRiskConfirmation)
        assertEquals(state, state.withHide(true))
        val accepted = state.withHide(true, acceptUnverified = true)
        assertEquals(3, accepted.requested)
        assertTrue(accepted.unverifiedHide)
        assertEquals(1, accepted.effective)
        assertEquals(1, accepted.capabilities)
        assertTrue(accepted.pendingReboot)
        assertFalse(accepted.withHide(false).unverifiedHide)
        assertFalse(accepted.withLoad(false).unverifiedHide)
    }
    @Test fun failedExperimentalBootStillAllowsDisabling() {
        for (experimental in listOf(false, true)) {
            val failed = UltraModulePolicyState.fromBackend(3, null, 0, unverifiedHide = experimental)
            assertTrue(failed.operable)
            assertTrue(failed.hideOperable)
            assertNull(failed.effective)
            assertEquals(1, failed.withHide(false).requested)
            assertEquals(0, failed.withLoad(false).requested)
        }
    }
    @Test fun consentNeverChangesCurrentBootOrFabricatesCapability() {
        val state = UltraModulePolicyState.fromBackend(3, 1, 1, unverifiedHide = true, canTryUnverified = true)
        assertTrue(state.hideRequested)
        assertFalse(state.hideNeedsRiskConfirmation)
        assertEquals(1, state.effective)
        assertEquals(1, state.capabilities)
        assertThrows(IllegalArgumentException::class.java) {
            UltraModulePolicyState.fromBackend(1, 1, 1, unverifiedHide = true)
        }
    }
    @Test fun oldEnvironmentCanSaveLoadWithoutClaimingAnEffectiveBackend() {
        val state = UltraModulePolicyState.fromBackend(0, null, 0)
        assertTrue(state.operable)
        assertTrue(state.needsEnvironmentUpgrade)
        assertFalse(state.hideOperable)
        val enabled = state.withLoad(true)
        assertEquals(1, enabled.requested)
        assertNull(enabled.effective)
        assertEquals(0, enabled.capabilities)
        assertTrue(enabled.needsEnvironmentUpgrade)
        assertFalse(state.effectiveLoadAllowed)
        assertFalse(enabled.effectiveLoadAllowed)
        assertFalse(enabled.pendingReboot)
        assertEquals(0, enabled.withLoad(false).requested)
    }

    @Test fun temporaryHookNeedsSessionPreparationNotBootUpgrade() {
        val state = UltraModulePolicyState.fromBackend(0, null, 0, backend = UltraModulePolicyBackend.HOOK)
        assertTrue(state.operable)
        assertTrue(state.needsSessionPreparation)
        assertFalse(state.needsEnvironmentUpgrade)
        assertFalse(state.hideOperable)
        assertEquals(R.string.ultra_module_policy_session_pending, state.statusRes())
        assertEquals(R.string.ultra_module_policy_hook_hide_unavailable, state.hideUnavailableRes())
    }

    @Test fun appliedHookGateDoesNotClaimToHidePreviouslyLoadedPolicies() {
        val state = UltraModulePolicyState.fromBackend(1, 1, 1, backend = UltraModulePolicyBackend.HOOK)
        assertTrue(state.effectiveLoadAllowed)
        assertFalse(state.pendingReboot)
        assertFalse(state.needsSessionPreparation)
        assertFalse(state.hideOperable)
        assertEquals(state, state.withHide(true, acceptUnverified = true))
        assertNull(state.statusRes())
    }

    @Test fun hookReadFailureDoesNotRecommendEnvironmentUpgrade() {
        val state = UltraModulePolicyState(backend = UltraModulePolicyBackend.HOOK, loaded = true, error = "ROOT_BACKEND_UNAVAILABLE")
        assertFalse(state.needsEnvironmentUpgrade)
        assertEquals(R.string.ultra_module_policy_read_failed, state.hideUnavailableRes())
    }

    @Test fun failedOrIncompleteReadsCannotSavePreferences() {
        assertFalse(UltraModulePolicyState().operable)
        assertFalse(UltraModulePolicyState(loaded = true, error = "read failed").operable)
        assertFalse(UltraModulePolicyState.fromBackend(1, 1, 1).needsEnvironmentUpgrade)
    }

    @Test fun uiSeparatesSavedLegacyPreferencesFromReadFailuresAndEffectiveLoading() {
        assertNull(UltraModulePolicyState().statusRes())
        val legacy = UltraModulePolicyState.fromBackend(1, null, 0)
        assertEquals(R.string.ultra_module_policy_unavailable, legacy.statusRes())
        assertEquals(R.string.ultra_module_policy_read_failed, legacy.copy(error = "read failed").statusRes())
        assertNull(UltraModulePolicyState.fromBackend(1, 1, 1).statusRes())
        assertEquals(R.string.ultra_module_policy_hide_fallback,
            UltraModulePolicyState.fromBackend(1, 1, 1, hideFailed = true).statusRes())
    }
    @Test fun warningCoversPendingEnableAndPendingDisable() {
        assertTrue(UltraModulePolicyState.fromBackend(0, 1, 3).shouldWarn(true, false))
        assertTrue(UltraModulePolicyState.fromBackend(1, 0, 3).shouldWarn(true, false))
        assertFalse(UltraModulePolicyState.fromBackend(1, 1, 3).shouldWarn(true, false))
        assertFalse(UltraModulePolicyState().shouldWarn(true, true))
        assertFalse(UltraModulePolicyState().shouldWarn(false, false))
    }
    @Test fun hideFallbackPreservesLoadingAndAllowsRetry() {
        val state = UltraModulePolicyState.fromBackend(1, 1, 1, canTryUnverified = true, hideFailed = true)
        assertTrue(state.hideFailed)
        assertTrue(state.operable)
        assertTrue(state.effectiveLoadAllowed)
        assertFalse(state.hideRequested)
        assertFalse(state.pendingReboot)
        val retried = state.withHide(true, acceptUnverified = true)
        assertEquals(3, retried.requested)
        assertEquals(1, retried.effective)
        assertTrue(retried.pendingReboot)
    }
    @Test fun malformedBackendDataIsRejected() {
        for ((requested, effective, capabilities) in listOf(Triple(2, 0, 3), Triple(0, 2, 3),
            Triple(0, null, 1), Triple(3, 3, 1), Triple(0, 0, 0), Triple(0, 0, 2))) {
            assertThrows(IllegalArgumentException::class.java) {
                UltraModulePolicyState.fromBackend(requested, effective, capabilities)
            }
        }
    }
}
