package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import org.junit.Assert.*
import org.junit.Test

class UltraInstallCredentialTransitionTest {
    private val old = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(-9188272)
    private val key = old.copySecret().toString(Charsets.US_ASCII)
    private val next = old.withMetadataDisplacement(-9191328)
    private val boot = "11111111-1111-4111-8111-111111111111"
    private val reboot = "22222222-2222-4222-8222-222222222222"
    private val sha = "a".repeat(64)
    private fun pending() = UltraInstallCredentialTransition.stage(key, next, "install", sha, boot)
    private fun committed() = pending().confirm("install", sha, boot, key)

    @Test fun generationAndPreparationNeverActivateACandidateEvenAfterReboot() {
        val pending = pending()
        assertFalse(pending.committed)
        assertNull(pending.afterBoot(boot, key, false))
        assertNull(pending.afterBoot(reboot, key, false))
    }

    @Test fun aSuccessfulWriteKeepsTheRunningKeyUntilAnActualReboot() {
        val committed = committed()
        assertTrue(committed.committed)
        assertNull(committed.afterBoot(boot, key, false))
        assertEquals(next, committed.afterBoot(reboot, key, false))
    }

    @Test fun aRestartedManagerInTheSameBootKeepsTheRunningIdentity() {
        val restored = committed().copy()
        repeat(3) { assertNull(restored.afterBoot(boot, key, false)) }
        assertEquals(next, restored.afterBoot(reboot, key, false))
    }

    @Test fun onlyTheExactTaskDigestAndSourceBootConfirmTheWrite() {
        val pending = pending()
        for ((task, hash, id) in listOf(Triple("other", sha, boot),
            Triple("install", "b".repeat(64), boot), Triple("install", sha, reboot))) {
            assertThrows(IllegalStateException::class.java) { pending.confirm(task, hash, id, key) }
        }
        assertFalse(pending.committed)
    }

    @Test fun aConcurrentPairingCannotBeOverwrittenAtCommitOrAfterBoot() {
        val other = "C".repeat(48)
        assertThrows(IllegalStateException::class.java) { pending().confirm("install", sha, boot, other) }
        assertNull(committed().afterBoot(reboot, other, false))
        assertNull(committed().afterBoot(reboot, null, false))
    }

    @Test fun suspensionAndAnUnknownBootPreventActivation() {
        assertNull(committed().afterBoot(reboot, key, true))
        assertNull(committed().afterBoot("", key, false))
        assertNull(committed().afterBoot("unknown", key, false))
    }

    @Test fun anExplicitNewIdentityActivatesOnlyAfterItsExactWriteAndReboot() {
        val other = UltraKernelCredential.of("C".repeat(48)).withMetadataDisplacement(-9191328)
        val pending = UltraInstallCredentialTransition.stage(key, other, "install", sha, boot)
        assertNull(pending.afterBoot(reboot, key, false))
        val committed = pending.confirm("install", sha, boot, key)
        assertNull(committed.afterBoot(boot, key, false))
        assertEquals(other, committed.afterBoot(reboot, key, false))
    }

    @Test fun aRepeatedSuccessReceiptIsIdempotent() {
        val committed = committed()
        assertEquals(committed, committed.confirm("install", sha, boot, key))
    }

    @Test fun invalidReceiptsNeverProduceAnActivatableIdentity() {
        for ((id, hash) in listOf("" to sha, boot to "bad")) {
            assertThrows(IllegalArgumentException::class.java) {
                UltraInstallCredentialTransition.stage(key, next, "install", hash, id)
            }
        }
    }
}
