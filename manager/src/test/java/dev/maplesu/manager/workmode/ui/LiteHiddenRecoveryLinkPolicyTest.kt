package dev.maplesu.manager.workmode.ui

import org.junit.Assert.*
import org.junit.Test

class LiteHiddenRecoveryLinkPolicyTest {
    @Test fun kernelRootServiceUsesRecoveryDaemonPath() {
        assertTrue(LiteHiddenRecoveryLinkPolicy.usesDirectDaemon(kernelRootService = true))
        assertFalse(LiteHiddenRecoveryLinkPolicy.usesDirectDaemon(kernelRootService = false))
    }

    @Test fun preparedConfigOrOpenPortAloneIsNotReady() {
        assertFalse(LiteHiddenRecoveryLinkPolicy.isReady(false, 18427, 18427, true))
        assertFalse(LiteHiddenRecoveryLinkPolicy.isReady(true, 18427, 18427, false))
        assertFalse(LiteHiddenRecoveryLinkPolicy.isReady(true, 18428, 18427, true))
        assertFalse(LiteHiddenRecoveryLinkPolicy.isReady(true, -1, -1, true))
    }

    @Test fun actualServicePortMustMatchDeliveredLink() {
        assertTrue(LiteHiddenRecoveryLinkPolicy.isReady(true, 18428, 18428, true))
        assertTrue(LiteHiddenRecoveryLinkPolicy.isReady(true, 1024, 1024, true))
        assertTrue(LiteHiddenRecoveryLinkPolicy.isReady(true, 65535, 65535, true))
        assertFalse(LiteHiddenRecoveryLinkPolicy.isReady(true, 1023, 1023, true))
        assertFalse(LiteHiddenRecoveryLinkPolicy.isReady(true, 65536, 65536, true))
    }

    @Test fun activationRequiresSelectionVerifiedLinkAndDeliveredCopy() {
        assertTrue(LiteHiddenRecoveryLinkPolicy.canActivate(true, true, true, false))
        assertFalse(LiteHiddenRecoveryLinkPolicy.canActivate(false, true, true, false))
        assertFalse(LiteHiddenRecoveryLinkPolicy.canActivate(true, false, true, false))
        assertFalse(LiteHiddenRecoveryLinkPolicy.canActivate(true, true, false, false))
        assertFalse(LiteHiddenRecoveryLinkPolicy.canActivate(true, true, true, true))
    }
}
