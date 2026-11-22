package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import org.junit.Assert.*
import org.junit.Test

class UltraInstallCredentialPolicyTest {
    private val key = "Aa1".repeat(16)

    private class Store(var key: String? = null, var suspended: String? = null, var device: ByteArray? = null) {
        var creates = 0
        var knownNonUltra = true
        var returned: ByteArray? = null
        val policy get() = UltraInstallCredentialPolicy({ key }, { suspended },
            { device?.copyOf()?.also { returned = it } },
            { creates++; ("Bb2".repeat(16).toByteArray()).also { device = it.copyOf(); returned = it } },
            { knownNonUltra })
    }

    @Test fun confirmedNormalFirstInstallCreatesOneDurableCredentialAndReusesItAfterRestart() {
        val store = Store()
        val first = requireNotNull(store.policy.forCandidate())
        val second = requireNotNull(store.policy.forCandidate())
        assertEquals(first, second)
        assertEquals(1, store.creates)
        assertTrue(store.returned!!.all { it == 0.toByte() })
        assertNull("candidate preparation must not claim live pairing", store.key)
    }

    @Test fun previewIsReadOnlyAndDoesNotCreateAnIdentity() {
        val store = Store()
        assertNull(store.policy.existing())
        assertEquals(0, store.creates)
    }

    @Test fun explicitDirectInstallCreatesCandidateWithoutRuntimePairingOrDetection() {
        val store = Store().apply { knownNonUltra = false }
        val candidate = requireNotNull(store.policy.forCandidate())
        assertEquals(candidate, store.policy.forCandidate())
        assertEquals(1, store.creates)
        assertNull("Preparing the next boot must not claim a running identity", store.key)
    }

    @Test fun selectedImageCreatesAndReusesAnIdentityWithoutDeviceDetectionOrPairing() {
        val store = Store().apply { knownNonUltra = false }
        val first = store.policy.forCandidate()
        assertEquals(first, store.policy.forCandidate())
        assertEquals(1, store.creates)
        assertNull(store.key)
        assertTrue(store.returned!!.all { it == 0.toByte() })
    }

    @Test fun selectedImageReusesActiveAndSuspendedCredentialsWithoutChangingTheirState() {
        listOf(Store(key = key), Store(suspended = key)).forEach { store ->
            store.knownNonUltra = false
            assertEquals(UltraKernelCredential.of(key), store.policy.forCandidate())
            assertEquals(0, store.creates)
            assertTrue(store.key == key || store.suspended == key)
        }
    }

    @Test fun exportedImageArchivesItsExactKeyWithoutReplacingActiveOrSuspendedPairing() {
        val original = UltraKernelCredential.of(key).withMetadataDisplacement(-9188272)
        val originalKey = original.copySecret().toString(Charsets.US_ASCII)
        val relocated = original.withMetadataDisplacement(-9191328)
        listOf(Store(key = originalKey), Store(suspended = originalKey)).forEach { store ->
            store.knownNonUltra = false
            var archived: String? = null
            store.policy.retainForExport(relocated, { archived = it }) {
                fail("file patching must preserve this device's identity")
                false
            }
            assertEquals(relocated, UltraKernelCredential.of(requireNotNull(archived)))
            assertTrue(store.key == originalKey || store.suspended == originalKey)
            assertEquals(0, store.creates)
        }
    }

    @Test fun unpairedExportRetainsItsBoundKeyForTheFirstBootWithoutLivePairing() {
        val store = Store()
        val bound = store.policy.forCandidate()
            .withMetadataDisplacement(-9188272)
        var archived: String? = null
        store.policy.retainForExport(bound, { archived = it }) { store.key = it; true }
        assertEquals(archived, store.key)
        assertEquals(bound, store.policy.existing())
        assertTrue(bound.sdkMetadataValid)
    }

    @Test fun firstInstallExportRetainsPendingIdentityEvenBeforeDetectionSettles() {
        val store = Store().apply { knownNonUltra = false }
        val credential = store.policy.forCandidate()
        var archived: String? = null
        store.policy.retainForExport(credential, { archived = it }) {
            store.key = it
            true
        }
        assertEquals(credential, UltraKernelCredential.of(requireNotNull(archived)))
        assertEquals(archived, store.key)
    }

    @Test fun aConcurrentPairingDoesNotDiscardOrBlockTheExportedImageKey() {
        val store = Store()
        var archived: String? = null
        store.policy.retainForExport(UltraKernelCredential.of(key), { archived = it }) {
            store.key = "C".repeat(48)
            false
        }
        assertEquals(key, archived)
        assertEquals("C".repeat(48), store.key)
    }

    @Test fun existingAndSuspendedKeysWinWithoutCreatingOrChangingPairing() {
        listOf(Store(key = key), Store(suspended = key)).forEach { store ->
            assertEquals(UltraKernelCredential.of(key), store.policy.forCandidate())
            assertEquals(0, store.creates)
        }
    }

    @Test fun malformedStoredCandidatesDoNotBlockDurablePreparationOrReplaceTheLiveKey() {
        listOf(Store(key = "broken"), Store(suspended = "broken"), Store(device = "broken".toByteArray())).forEach { store ->
            val previous = store.key
            val candidate = store.policy.forCandidate()
            assertEquals(candidate, store.policy.forCandidate())
            assertEquals(1, store.creates)
            assertEquals(previous, store.key)
        }
    }

    @Test fun unreadableLegacyStorageDoesNotBlockTheIndependentInstallSeed() {
        var creates = 0
        val policy = UltraInstallCredentialPolicy({ null }, { null }, { error("old Keystore missing") },
            { creates++; key.toByteArray() }, { false })
        assertEquals(UltraKernelCredential.of(key), policy.forCandidate())
        assertEquals(1, creates)
    }

    @Test fun encryptedCredentialIsReusedAndTemporaryBytesAreCleared() {
        val store = Store(device = key.toByteArray())
        assertEquals(UltraKernelCredential.of(key), store.policy.forCandidate())
        assertTrue(store.returned!!.all { it == 0.toByte() })
        assertEquals(0, store.creates)
        assertEquals(key, store.device!!.toString(Charsets.US_ASCII))
    }
    @Test fun validatedCandidateHandsOffItsOwnIdentityWithoutPairing() {
        val store = Store()
        val credential = requireNotNull(store.policy.forCandidate())
        var writes = 0
        store.policy.retain(credential) { writes++; store.key = it; true }
        assertEquals(1, writes)
        assertEquals(credential, store.policy.existing())
        assertEquals(1, store.creates)
    }

    @Test fun differentExistingIdentityAndSuspensionArePreservedBeforeFlash() {
        listOf(Store(key = key), Store(suspended = key)).forEach { store ->
            var wrote = false
            try {
                store.policy.retain(UltraKernelCredential.of("Bb2".repeat(16))) { wrote = true; true }
                fail("expected identity conflict")
            } catch (expected: IllegalStateException) {
                assertTrue(expected.message!!.startsWith("ULTRA_KERNEL_CREDENTIAL_"))
            }
            assertFalse(wrote)
            assertTrue(store.key == key || store.suspended == key)
        }
    }

    @Test fun concurrentStoreOnlyAcceptsTheSameIdentity() {
        val credential = UltraKernelCredential.of(key)
        val store = Store()
        store.policy.retain(credential) { store.key = it; false }
        assertEquals(key, store.key)
        val other = Store()
        try {
            other.policy.retain(credential) { other.key = "C".repeat(48); false }
            fail("expected concurrent identity conflict")
        } catch (expected: IllegalStateException) {
            assertEquals("ULTRA_KERNEL_CREDENTIAL_CHANGED", expected.message)
        }
    }

    @Test fun retryWithTheSameIdentityRenewsTheCurrentInstallHandoff() {
        val store = Store(key = key)
        var retained = false
        store.policy.retain(UltraKernelCredential.of(key)) {
            assertEquals(key, it)
            retained = true
            true
        }
        assertTrue("The pending task must follow the retry rather than the cancelled attempt", retained)
        assertEquals(key, store.key)
    }

    @Test fun generatedCandidateRetainsItsBoundIdentityInsteadOfTheInvalidRandomSeed() {
        val store = Store(key = key)
        val bound = UltraKernelCredential.of(key).withMetadataDisplacement(-9188272)
        store.policy.retain(bound) { store.key = it; true }
        assertEquals(bound, store.policy.existing())
        assertNotEquals(key, store.key)
        assertEquals(0, store.creates)
    }

    @Test fun anUnverifiedExportCanBeRelocatedForInstallationAfterDetectionBecomesUnresolved() {
        val store = Store()
        val first = store.policy.forCandidate()
            .withMetadataDisplacement(-9188272)
        store.policy.retainForExport(first, {}) { store.key = it; true }
        // The pending export is not a live pairing. Its presence can make detection unbound.
        store.knownNonUltra = false
        val relocated = first.withMetadataDisplacement(-9191328)
        var staged: String? = null
        store.policy.retain(relocated, stageForReboot = { staged = it; true }) {
            fail("The current kernel still needs its original key")
            false
        }
        assertEquals(relocated, UltraKernelCredential.of(requireNotNull(staged)))
        assertEquals(first, store.policy.existing())
        assertEquals(1, store.creates)
    }

    @Test fun anExplicitReinstallStagesANewIdentityAndPropagatesAConcurrentChange() {
        val first = UltraKernelCredential.of(key).withMetadataDisplacement(-9188272)
        val store = Store(key = first.copySecret().toString(Charsets.US_ASCII)).apply { knownNonUltra = false }
        val newIdentity = UltraKernelCredential.of("C".repeat(48)).withMetadataDisplacement(-9191328)
        var staged: String? = null
        store.policy.retain(newIdentity, stageForReboot = { staged = it; true }) {
            fail("preparation must preserve the running key"); false
        }
        assertEquals(newIdentity, UltraKernelCredential.of(requireNotNull(staged)))
        assertThrows(IllegalStateException::class.java) {
            store.policy.retain(first.withMetadataDisplacement(-9191328), stageForReboot = { false }) { true }
        }
        assertEquals(first, store.policy.existing())
    }

    @Test fun anActiveUltraKeyIsNotReplacedByAnotherImagesMetadataBinding() {
        val working = UltraKernelCredential.of(key).withMetadataDisplacement(-9188272)
        val store = Store(key = working.copySecret().toString(Charsets.US_ASCII)).apply {
            knownNonUltra = false
        }
        var wrote = false
        assertThrows(IllegalStateException::class.java) {
            store.policy.retain(working.withMetadataDisplacement(-9191328)) { wrote = true; true }
        }
        assertFalse(wrote)
        assertEquals(working, store.policy.existing())
    }

    @Test fun evenAKnownForeignModeCannotReplaceAValidKeyBeforeTheImageWrite() {
        val working = UltraKernelCredential.of(key).withMetadataDisplacement(-9188272)
        val store = Store(key = working.copySecret().toString(Charsets.US_ASCII))
        val relocated = working.withMetadataDisplacement(-256)
        var staged: String? = null
        store.policy.retain(relocated, stageForReboot = { staged = it; true }) {
            fail("the image has not been written yet"); false
        }
        assertEquals(relocated, UltraKernelCredential.of(requireNotNull(staged)))
        assertEquals(working, store.policy.existing())
        assertEquals(0, store.creates)
    }

}
