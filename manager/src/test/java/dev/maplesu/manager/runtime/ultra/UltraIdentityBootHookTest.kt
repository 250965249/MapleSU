package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraIdentityBootHookTest {
    @Test fun oldEnvironmentPreservesTheLegacyModule() {
        assertEquals("IDENTITY_ENVIRONMENT_UPGRADE_REQUIRED", UltraIdentityBootHook.ensure(false, false) { error("premature removal") })
    }

    @Test fun upgradeCanPrepareNewBrokerBeforeNewBootstrapIsInstalled() {
        assertEquals("IDENTITY_UPGRADE_PREPARED", UltraIdentityBootHook.ensure(false, true) { error("premature removal") })
    }

    @Test fun verifiedEnvironmentRetiresOnlyAfterBrokerHandshake() {
        var calls = 0
        assertEquals("IDENTITY_READY", UltraIdentityBootHook.ensure(true, false) { calls++; null })
        assertEquals(1, calls)
    }

    @Test fun incompleteRetirementIsReportedAndRetried() {
        assertEquals("IDENTITY_LEGACY_RETIRE_FAILED", UltraIdentityBootHook.ensure(true, false) { "IDENTITY_LEGACY_RETIRE_FAILED" })
        assertEquals("IDENTITY_READY", UltraIdentityBootHook.ensure(true, false) { null })
    }
}
