package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import org.junit.Assert.*
import org.junit.Test

class UltraInstallAuthorizationEvidenceTest {
    private val key = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(4096)
        .copySecret().toString(Charsets.US_ASCII)
    private val sourceBoot = "11111111-1111-4111-8111-111111111111"
    private val currentBoot = "22222222-2222-4222-8222-222222222222"

    @Test fun exportedCandidateInTheSameBootIsNotInstallationEvidence() {
        val prefs = UltraPendingInstallCredentialStoreTest.MemoryPreferences()
        assertTrue(UltraKeyPairedStore.storeInstallKeyIfAbsent(prefs, key, "image-export", sourceBootId = sourceBoot,
            freshCandidate = true))
        assertFalse(UltraKeyPairedStore.hasInstallKey(prefs, "image-export", sourceBoot))
        assertTrue(UltraKeyPairedStore.hasInstallKey(prefs, "image-export", currentBoot))
        assertFalse(UltraKeyPairedStore.hasInstallKey(prefs, "other-task", currentBoot))
    }

    @Test fun pairingDoesNotEraseTheExactInstallationProvenance() {
        val prefs = UltraPendingInstallCredentialStoreTest.MemoryPreferences()
        assertTrue(UltraKeyPairedStore.storeInstallKeyIfAbsent(prefs, key, "install", sourceBootId = sourceBoot,
            freshCandidate = true))
        prefs.edit().putBoolean("keyVerified", true).commit()
        assertTrue(UltraKeyPairedStore.hasInstallKey(prefs, "install", currentBoot))
        prefs.edit().putString("rootKey", key.reversed()).commit()
        assertFalse(UltraKeyPairedStore.hasInstallKey(prefs, "install", currentBoot))
    }

    @Test fun sameKeyUpgradePreparationDoesNotCreateInstallationEvidence() {
        val prefs = UltraPendingInstallCredentialStoreTest.MemoryPreferences()
        prefs.edit().putString("rootKey", key).commit()
        assertTrue(UltraKeyPairedStore.storeInstallKeyIfAbsent(prefs, key, "upgrade", sourceBootId = sourceBoot,
            freshCandidate = true))
        assertFalse(UltraKeyPairedStore.hasInstallKey(prefs, "upgrade", currentBoot))
        val unproven = UltraPendingInstallCredentialStoreTest.MemoryPreferences()
        assertTrue(UltraKeyPairedStore.storeInstallKeyIfAbsent(unproven, key, "candidate", sourceBootId = sourceBoot))
        assertFalse(UltraKeyPairedStore.hasInstallKey(unproven, "candidate", currentBoot))
    }

    @Test fun unknownBootSuspensionAndCompletedInitializationNeverReinitializeAuthority() {
        val prefs = UltraPendingInstallCredentialStoreTest.MemoryPreferences()
        assertTrue(UltraKeyPairedStore.storeInstallKeyIfAbsent(prefs, key, "install"))
        assertFalse(UltraKeyPairedStore.hasInstallKey(prefs, "install", currentBoot))
        prefs.edit().putString("installCredentialSourceBoot", sourceBoot).commit()
        assertFalse(UltraKeyPairedStore.hasInstallKey(prefs, "install", null))
        prefs.edit().putString("environmentRemoval", "permanent").commit()
        assertFalse(UltraKeyPairedStore.hasInstallKey(prefs, "install", currentBoot))
        prefs.edit().remove("environmentRemoval").putString("installAuthorizationObservedForKey",
            prefs.getString("installCredentialForKey", null)).commit()
        assertFalse(UltraKeyPairedStore.hasInstallKey(prefs, "install", currentBoot))
    }
}
