package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraInstallCredentialReinstallTest {
    private val old = "Aa1".repeat(16)
    private val next = "Bb2".repeat(16)

    @Test fun anExplicitReinstallAtomicallyResumesOnlyItsObservedRemovalAndKey() {
        for (removal in listOf("permanent", "temporary")) {
            val prefs = UltraPendingInstallCredentialStoreTest.MemoryPreferences().apply {
                values.putAll(mapOf("rootKey" to old, "keyVerified" to true, "environmentRemoval" to removal))
            }
            assertTrue(UltraKeyPairedStore.storeInstallKeyIfAbsent(prefs, next, "reinstall", old, removal))
            assertEquals(next, prefs.getString("rootKey", null))
            assertEquals("reinstall", prefs.getString("installCredentialTaskId", null))
            assertFalse(prefs.contains("environmentRemoval"))
            assertFalse(prefs.getBoolean("keyVerified", false))
        }
    }

    @Test fun exportsAndAutomaticRecoveryKeepExplicitRemovalInEffect() {
        val prefs = UltraPendingInstallCredentialStoreTest.MemoryPreferences().apply {
            values.putAll(mapOf("rootKey" to old, "environmentRemoval" to "permanent"))
        }
        assertFalse(UltraKeyPairedStore.storeInstallKeyIfAbsent(prefs, next, "image-export", old))
        assertEquals(old, prefs.getString("rootKey", null))
        assertEquals("permanent", prefs.getString("environmentRemoval", null))
    }

    @Test fun aConcurrentRemovalOrPairingWinsOverThePreparedReinstall() {
        for (change in listOf("pairing", "removal", "suspension")) {
            val prefs = UltraPendingInstallCredentialStoreTest.MemoryPreferences().apply {
                values.putAll(mapOf("rootKey" to old, "environmentRemoval" to "temporary"))
                when (change) {
                    "pairing" -> values["rootKey"] = "C".repeat(48)
                    "removal" -> values["environmentRemoval"] = "permanent"
                    "suspension" -> values["rootKeySuspended"] = old
                }
            }
            assertFalse(change, UltraKeyPairedStore.storeInstallKeyIfAbsent(prefs, next, "reinstall", old, "temporary"))
            assertNotEquals(next, prefs.getString("rootKey", null))
            assertTrue(prefs.contains("environmentRemoval"))
        }
    }

    @Test fun aFailedDurableStorePreservesRemovalAndThePreviousIdentity() {
        val prefs = UltraPendingInstallCredentialStoreTest.MemoryPreferences().apply {
            values.putAll(mapOf("rootKey" to old, "environmentRemoval" to "permanent"))
            failCommit = true
        }
        assertThrows(IllegalStateException::class.java) {
            UltraKeyPairedStore.storeInstallKeyIfAbsent(prefs, next, "reinstall", old, "permanent")
        }
        assertEquals(old, prefs.getString("rootKey", null))
        assertEquals("permanent", prefs.getString("environmentRemoval", null))
    }
}
