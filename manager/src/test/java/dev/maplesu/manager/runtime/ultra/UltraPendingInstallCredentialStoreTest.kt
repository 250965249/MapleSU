package dev.maplesu.manager.runtime.ultra

import android.content.SharedPreferences
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import org.junit.Assert.*
import org.junit.Test

class UltraPendingInstallCredentialStoreTest {
    private val old = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(-9188272)
    private val key = old.copySecret().toString(Charsets.US_ASCII)
    private val next = old.withMetadataDisplacement(-9191328)
    private val sha = "a".repeat(64)
    private val boot = "11111111-1111-4111-8111-111111111111"
    private val reboot = "22222222-2222-4222-8222-222222222222"

    private inner class Fixture {
        val prefs = MemoryPreferences().apply { values.putAll(mapOf("rootKey" to key, "keyVerified" to true)) }
        var bootId = boot
        val store get() = UltraPendingInstallCredentialStore(prefs) { bootId }
        fun stage() = assertTrue(store.stage(key, next, "install", sha))
        fun confirm() = store.observe("install", "REBOOT_REQUIRED", sha)
        fun current() = prefs.getString("rootKey", null)
    }

    @Test fun anotherInstallBeforeRebootReplacesOnlyThePromotionReceipt() {
        val f = Fixture()
        f.stage(); f.confirm()
        val later = next.withMetadataDisplacement(-9194000)
        val laterHash = "b".repeat(64)
        assertTrue(f.store.stage(key, later, "later-install", laterHash))
        assertEquals(key, f.current())
        assertEquals(later, f.store.credential("later-install", laterHash))
        // A delayed reply from the superseded install cannot promote the old image identity.
        f.store.observe("install", "REBOOT_REQUIRED", sha)
        f.store.observe("later-install", "REBOOT_REQUIRED", laterHash)
        f.bootId = reboot
        f.store.activateAfterBoot()
        assertEquals(later, UltraKernelCredential.of(requireNotNull(f.current())))
    }

    @Test fun signingCanRebindTheSameTaskToItsFinalImageAfterAConfirmedWrite() {
        val f = Fixture()
        f.stage(); f.confirm()
        val signedHash = "b".repeat(64)
        assertTrue(f.store.stage(key, next, "install", signedHash))
        f.bootId = reboot
        f.store.activateAfterBoot()
        assertEquals("The replacement digest needs its own write receipt", key, f.current())
    }

    @Test fun aFailedLaterAttemptStillRecoversTheEarlierImageThatActuallyBooted() {
        val f = Fixture()
        val archive = MemoryPreferences()
        val firstKey = next.copySecret().toString(Charsets.US_ASCII)
        UltraInstallCredentials.archiveCandidate(archive, sha, next)
        f.stage(); f.confirm()
        val later = next.withMetadataDisplacement(-9194000)
        val laterHash = "b".repeat(64)
        UltraInstallCredentials.archiveCandidate(archive, laterHash, later)
        assertTrue(f.store.stage(key, later, "later-install", laterHash))
        f.store.observe("later-install", "FAILED_BEFORE_WRITE", laterHash)
        f.bootId = reboot
        f.store.activateAfterBoot()
        assertEquals(key, f.current())
        val result = UltraIdentityResolution.recover(object : UltraIdentityResolution.Port {
            override fun currentKey() = f.current()
            override fun blocked() = false
            override fun bootId() = f.bootId
            override fun rootUid(key: String) = if (key == firstKey) 0 else null
            override fun brokerKey(): String? = null
            override fun backupKey(): String? = null
            override fun installKeys() = UltraIdentityResolution.installCandidates(
                f.store.recoveryCredentials().map { it.copySecret().toString(Charsets.US_ASCII) }, archive.getAll())
            override fun store(expected: String?, key: String) = expected == f.current() &&
                f.prefs.edit().putString("rootKey", key).commit()
            override fun accepted(key: String) = Unit
        })
        assertEquals("RECOVERED", result)
        assertEquals(firstKey, f.current())
        assertTrue(archive.contains(sha))
        assertTrue(archive.contains(laterHash))
    }

    @Test fun externalFlashMayReadPendingCandidateWithoutPromotingItOrBypassingSuspension() {
        val f = Fixture()
        f.stage()
        f.bootId = reboot
        assertEquals(next, f.store.recoveryCredential())
        f.store.activateAfterBoot()
        assertEquals(key, f.current())
        f.prefs.values["rootKeySuspended"] = key
        assertNull(f.store.recoveryCredential())
    }

    @Test fun exactCandidateSurvivesManagerRestartAndActivatesOnlyAfterConfirmedReboot() {
        val f = Fixture()
        f.stage()
        assertEquals(next, f.store.credential("install", sha))
        assertEquals(key, f.current())
        f.confirm()
        f.store.activateAfterBoot()
        assertEquals(key, f.current())
        assertTrue(f.prefs.getBoolean("keyVerified", false))
        f.bootId = reboot
        f.store.activateAfterBoot()
        assertEquals(next, UltraKernelCredential.of(requireNotNull(f.current())))
        assertFalse(f.prefs.getBoolean("keyVerified", false))
        assertEquals("install", f.prefs.getString("installCredentialTaskId", null))
        assertFalse(f.prefs.contains(UltraPendingInstallCredentialStore.RECORD))
    }

    @Test fun aPreparedButUnwrittenImageNeverReplacesTheRunningKey() {
        val f = Fixture()
        f.stage()
        f.store.observe("install", "PREPARED", sha)
        f.bootId = reboot
        f.store.activateAfterBoot()
        assertEquals(key, f.current())
    }

    @Test fun cancelledOrFailedInstallKeepsEveryArchivedImageKeyForLaterExternalFlashing() {
        for (state in listOf("FAILED_BEFORE_WRITE", "CANCELLED", "RESTORED", "ROLLED_BACK")) {
            val f = Fixture()
            val archive = MemoryPreferences()
            // Same order as production retainCandidate: durable image identity, then staging.
            UltraInstallCredentials.archiveCandidate(archive, sha, next)
            f.stage()
            f.store.observe("install", state, sha)
            f.bootId = reboot
            f.store.activateAfterBoot()
            assertEquals(key, f.current())
            assertFalse(f.prefs.contains(UltraPendingInstallCredentialStore.RECORD))
            val candidates = UltraIdentityResolution.installCandidates(null, archive.getAll())
            assertEquals(listOf(next.copySecret().toString(Charsets.US_ASCII)), candidates)
        }
    }

    @Test fun archiveWriteFailureAndAnotherImageDoNotDiscardTheFirstImageKey() {
        val archive = MemoryPreferences()
        UltraInstallCredentials.archiveCandidate(archive, sha, next)
        archive.failCommit = true
        assertThrows(IllegalStateException::class.java) {
            UltraInstallCredentials.archiveCandidate(archive, "b".repeat(64), old)
        }
        assertEquals(listOf(next.copySecret().toString(Charsets.US_ASCII)),
            UltraIdentityResolution.installCandidates(null, archive.getAll()))
        archive.failCommit = false
        UltraInstallCredentials.archiveCandidate(archive, "b".repeat(64), old)
        assertEquals(setOf(old, next), UltraIdentityResolution.installCandidates(null, archive.getAll())
            .map(UltraKernelCredential::of).toSet())
    }

    @Test fun rotatingTheFullIdentityPreservesThePreviousBootFallbackKey() {
        val f = Fixture()
        val rotated = UltraKernelCredential.of("Cc3".repeat(16)).withMetadataDisplacement(-9191328)
        assertTrue(f.store.stage(key, rotated, "install", sha))
        f.confirm()
        f.bootId = reboot
        f.store.activateAfterBoot()
        assertEquals(rotated, UltraKernelCredential.of(requireNotNull(f.current())))
        assertEquals(old, f.store.recoveryCredential())
        val later = rotated.withMetadataDisplacement(-9194000)
        assertTrue(f.store.stage(f.current(), later, "later-install", "b".repeat(64)))
        assertEquals(listOf(later, old), f.store.recoveryCredentials())
    }

    @Test fun aBootFallbackRecoversThePreviousIdentityWithoutABrokerOrBackup() {
        val f = Fixture()
        f.stage(); f.confirm()
        f.bootId = reboot
        f.store.activateAfterBoot()
        val attempts = mutableListOf<String>()
        val result = UltraIdentityResolution.recover(object : UltraIdentityResolution.Port {
            override fun currentKey() = f.current()
            override fun blocked() = false
            override fun bootId() = f.bootId
            override fun rootUid(key: String): Int? {
                attempts += key
                return if (key == this@UltraPendingInstallCredentialStoreTest.key) 0 else null
            }
            override fun brokerKey(): String? = null
            override fun backupKey(): String? = null
            override fun installKeys(): List<String> {
                val bytes = f.store.recoveryCredential()?.copySecret() ?: return emptyList()
                return try { listOf(bytes.toString(Charsets.US_ASCII)) } finally { bytes.fill(0) }
            }
            override fun store(expected: String?, key: String): Boolean {
                if (expected != f.current()) return false
                return f.prefs.edit().putString("rootKey", key).commit()
            }
            override fun accepted(key: String) = Unit
        })
        assertEquals("RECOVERED", result)
        assertEquals(key, f.current())
        assertEquals(listOf(next.copySecret().toString(Charsets.US_ASCII), key), attempts)
    }

    @Test fun thePreviousIdentityRemainsACandidateAfterVerificationAndLaterReboots() {
        val f = Fixture()
        f.stage(); f.confirm()
        f.bootId = reboot
        f.store.activateAfterBoot()
        f.prefs.values["keyVerified"] = true
        f.bootId = "33333333-3333-4333-8333-333333333333"
        f.store.activateAfterBoot()
        assertEquals(next, UltraKernelCredential.of(requireNotNull(f.current())))
        assertEquals(old, f.store.recoveryCredential())
    }

    @Test fun aPreviousIdentityCannotCrossAChangedPairingSuspensionOrRemoval() {
        for (scope in listOf("pairing", "suspension", "removal", "binding")) {
            val f = Fixture()
            f.stage(); f.confirm()
            f.bootId = reboot
            f.store.activateAfterBoot()
            when (scope) {
                "pairing" -> f.prefs.values["rootKey"] = "C".repeat(48)
                "suspension" -> f.prefs.values["rootKeySuspended"] = key
                "removal" -> f.prefs.values["environmentRemoval"] = "temporary"
                "binding" -> f.prefs.values[UltraPendingInstallCredentialStore.PREVIOUS_RECORD] =
                    """{"key":"$key","forKeySha256":"${"b".repeat(64)}"}"""
            }
            assertNull(scope, f.store.recoveryCredential())
        }
    }

    @Test fun aFailedActivationWritePreservesTheOldIdentityAndPendingReceipt() {
        val f = Fixture()
        f.stage(); f.confirm()
        f.bootId = reboot
        f.prefs.failCommit = true
        assertThrows(IllegalStateException::class.java) { f.store.activateAfterBoot() }
        assertEquals(key, f.current())
        assertTrue(f.prefs.contains(UltraPendingInstallCredentialStore.RECORD))
        assertFalse(f.prefs.contains(UltraPendingInstallCredentialStore.PREVIOUS_RECORD))
    }

    @Test fun failureCancellationAndRollbackDiscardPendingPromotion() {
        for (state in listOf("FAILED_BEFORE_WRITE", "RESTORED", "CANCELLED", "ROLLED_BACK")) {
            val f = Fixture()
            f.stage()
            f.confirm()
            f.store.observe("install", state, sha)
            f.bootId = reboot
            f.store.activateAfterBoot()
            assertEquals(state, key, f.current())
            assertFalse(f.prefs.contains(UltraPendingInstallCredentialStore.RECORD))
        }
    }

    @Test fun otherTransactionsAndChangedDigestsCannotConfirmTheCandidate() {
        val f = Fixture()
        f.stage()
        f.store.observe("other", "REBOOT_REQUIRED", sha)
        assertThrows(IllegalStateException::class.java) { f.store.observe("install", "REBOOT_REQUIRED", "b".repeat(64)) }
        assertNull(f.store.credential("other", sha))
        assertNull(f.store.credential("install", "b".repeat(64)))
        f.bootId = reboot
        f.store.activateAfterBoot()
        assertEquals(key, f.current())
    }

    @Test fun concurrentPairingIsPreservedBeforeStagingAtConfirmationAndAfterReboot() {
        for (step in 0..2) {
            val f = Fixture()
            if (step > 0) f.stage()
            if (step > 1) f.confirm()
            f.prefs.values["rootKey"] = "C".repeat(48)
            when (step) {
                0 -> assertFalse(f.store.stage(key, next, "install", sha))
                1 -> assertThrows(IllegalStateException::class.java) { f.confirm() }
            }
            f.bootId = reboot
            f.store.activateAfterBoot()
            assertEquals("C".repeat(48), f.current())
        }
    }

    @Test fun suspensionAndRemovalPreventStagingAndActivation() {
        for ((name, value) in listOf("rootKeySuspended" to key, "environmentRemoval" to "temporary")) {
            val fresh = Fixture()
            fresh.prefs.values[name] = value
            assertFalse(fresh.store.stage(key, next, "install", sha))
            val f = Fixture()
            f.stage(); f.confirm()
            f.prefs.values[name] = value
            f.bootId = reboot
            f.store.activateAfterBoot()
            assertEquals(key, f.current())
        }
    }

    @Test fun signingRebindsTheReceiptToTheSignedDigestWithoutChangingItsCredential() {
        val f = Fixture()
        f.stage()
        val signedSha = "b".repeat(64)
        assertTrue(f.store.stage(key, requireNotNull(f.store.credential("install", sha)), "install", signedSha))
        assertNull(f.store.credential("install", sha))
        assertThrows(IllegalStateException::class.java) { f.confirm() }
        f.store.observe("install", "REBOOT_REQUIRED", signedSha)
        f.bootId = reboot
        f.store.activateAfterBoot()
        assertEquals(next, UltraKernelCredential.of(requireNotNull(f.current())))
    }

    @Test fun aFailedDurableWritePreservesTheOldRuntimeIdentity() {
        val f = Fixture()
        f.prefs.failCommit = true
        assertThrows(IllegalStateException::class.java) { f.stage() }
        assertEquals(key, f.current())
        assertFalse(f.prefs.contains(UltraPendingInstallCredentialStore.RECORD))
    }

    @Test fun aRollbackRebootRequestDiscardsTheCandidateInsteadOfConfirmingIt() {
        val f = Fixture()
        f.stage(); f.confirm()
        f.store.observe("install", "REBOOT_REQUESTED", sha, "RESTORED")
        f.bootId = reboot
        f.store.activateAfterBoot()
        assertEquals(key, f.current())
        assertFalse(f.prefs.contains(UltraPendingInstallCredentialStore.RECORD))
    }

    @Test fun recoveryAndRestorationPreventDelayedSuccessFromRearmingTheCandidate() {
        for (state in listOf("RESTORING", "ROLLING_BACK", "RECOVERY_REQUIRED", "FAILED_PRE_WRITE")) {
            val f = Fixture()
            f.stage(); f.confirm()
            f.store.observe("install", state, sha)
            f.store.observe("install", "REBOOT_REQUIRED", sha)
            f.bootId = reboot
            f.store.activateAfterBoot()
            assertEquals(state, key, f.current())
            assertFalse(f.prefs.contains(UltraPendingInstallCredentialStore.RECORD))
        }
    }

    @Test fun anIdenticalPreparationRetryPreservesTheConfirmedReceipt() {
        val f = Fixture()
        f.stage(); f.confirm(); f.stage()
        assertEquals(next, f.store.credential("install"))
        assertNull(f.store.credential("other"))
        f.bootId = reboot
        f.store.activateAfterBoot()
        assertEquals(next, UltraKernelCredential.of(requireNotNull(f.current())))
    }

    @Test fun conflictingSuccessDigestDisarmsAnAlreadyConfirmedReceipt() {
        val f = Fixture()
        f.stage(); f.confirm()
        assertThrows(IllegalStateException::class.java) {
            f.store.observe("install", "REBOOT_REQUIRED", "b".repeat(64))
        }
        f.bootId = reboot
        f.store.activateAfterBoot()
        assertEquals(key, f.current())
    }

    @Test fun aDelayedWritingStatusDoesNotInvalidateALaterSuccessfulWrite() {
        val f = Fixture()
        f.stage(); f.confirm()
        f.store.observe("install", "WRITING", sha)
        f.store.observe("install", "COMMIT", sha)
        f.bootId = reboot
        f.store.activateAfterBoot()
        assertEquals(next, UltraKernelCredential.of(requireNotNull(f.current())))
    }

    @Test fun successReceiptsAfterRebootDoNotReconfirmAgainstThePreviousBootId() {
        val f = Fixture()
        f.stage(); f.confirm()
        f.bootId = reboot
        f.store.observe("install", "REBOOT_REQUIRED", sha)
        f.store.activateAfterBoot()
        assertEquals(next, UltraKernelCredential.of(requireNotNull(f.current())))
    }

    internal class MemoryPreferences : SharedPreferences {
        val values = mutableMapOf<String, Any?>()
        var failCommit = false
        override fun getAll() = values.toMap()
        override fun getString(key: String?, defValue: String?) = values[key] as? String ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean) = values[key] as? Boolean ?: defValue
        override fun getInt(key: String?, defValue: Int) = values[key] as? Int ?: defValue
        override fun getLong(key: String?, defValue: Long) = values[key] as? Long ?: defValue
        override fun getFloat(key: String?, defValue: Float) = values[key] as? Float ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?) = defValues
        override fun contains(key: String?) = values.containsKey(key)
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val updates = mutableMapOf<String, Any?>()
            private var clear = false
            override fun putString(key: String, value: String?) = apply { updates[key] = value }
            override fun putStringSet(key: String, value: MutableSet<String>?) = apply { updates[key] = value }
            override fun putInt(key: String, value: Int) = apply { updates[key] = value }
            override fun putLong(key: String, value: Long) = apply { updates[key] = value }
            override fun putFloat(key: String, value: Float) = apply { updates[key] = value }
            override fun putBoolean(key: String, value: Boolean) = apply { updates[key] = value }
            override fun remove(key: String) = apply { updates[key] = null }
            override fun clear() = apply { clear = true }
            override fun commit(): Boolean {
                if (failCommit) return false
                if (clear) values.clear()
                updates.forEach { (key, value) -> if (value == null) values.remove(key) else values[key] = value }
                return true
            }
            override fun apply() { commit() }
        }
    }
}
