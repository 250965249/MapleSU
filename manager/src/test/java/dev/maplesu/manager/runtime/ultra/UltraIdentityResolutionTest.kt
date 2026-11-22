package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import org.junit.Assert.*
import org.junit.Test

class UltraIdentityResolutionTest {
    private val good = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(4096)
        .copySecret().toString(Charsets.US_ASCII)
    private val old = UltraKernelCredential.of("Bb2".repeat(16)).withMetadataDisplacement(8192)
        .copySecret().toString(Charsets.US_ASCII)

    private inner class Port : UltraIdentityResolution.Port {
        var local: String? = null
        var kernel: String? = null
        var broker: String? = null
        var backup: String? = null
        var bootRestore: String? = null
        var bootRestoreCalls = 0
        var installs = emptyList<String>()
        var boot = "boot-1"
        var paused = false
        var throwingKeys = emptySet<String>()
        var duringProbe: (() -> Unit)? = null
        var duringKernel: (() -> Unit)? = null
        var storeOk = true
        val events = mutableListOf<String>()
        var maintained: String? = null
        override fun currentKey() = local
        override fun blocked() = paused
        override fun bootId() = boot
        override fun rootUid(key: String): Int? {
            events += if (key == good) "verify-good" else "verify-old"
            if (key in throwingKeys) error("stale source")
            duringProbe?.invoke()
            return if (key == good) 0 else null
        }
        override fun kernelKey() = kernel.also { events += "kernel"; duringKernel?.invoke() }
        override fun brokerKey() = broker.also { events += "broker" }
        override fun backupKey() = backup.also { events += "backup" }
        override fun restoreBootSession() = bootRestore.also { bootRestoreCalls++ }
        override fun installKeys() = installs.also { events += "installs" }
        override fun store(expected: String?, key: String): Boolean {
            events += "store"
            assertEquals(expected, local)
            if (storeOk) local = key
            return storeOk
        }
        override fun accepted(key: String) { events += "maintenance"; maintained = key }
    }

    @Test fun savedCandidatesAreDistinctAndPreferPendingThenEveryRecentExport() {
        val recent = "a".repeat(64)
        val legacy = "b".repeat(64)
        assertEquals(listOf(old, good), UltraIdentityResolution.installCandidates(old,
            mapOf(recent to good, "at:$recent" to 1L, legacy to old, "seed" to good)))
        assertEquals(listOf(good), UltraIdentityResolution.installCandidates(null,
            mapOf(legacy to good, recent to "invalid", "seed" to old)))
        val many = (1..20).associate { index ->
            index.toString(16).padStart(64, '0') to UltraKernelCredential.of("Cc3".repeat(16))
                .withMetadataDisplacement(index * 4096).copySecret().toString(Charsets.US_ASCII)
        }
        assertEquals(20, UltraIdentityResolution.installCandidates(null, many).size)
    }

    @Test fun theWorkingKeyBeyondEightFailedCandidatesIsStillVerified() {
        val keys = (1..12).map { index -> UltraKernelCredential.of("Cc3".repeat(16))
            .withMetadataDisplacement(index * 4096).copySecret().toString(Charsets.US_ASCII) }
        val port = Port().apply { installs = keys + good }
        assertEquals("RECOVERED", UltraIdentityResolution.recover(port))
        assertEquals(good, port.local)
        assertEquals(12, port.events.count { it == "verify-old" })
        assertEquals(1, port.events.count { it == "verify-good" })
    }

    @Test fun flashedImageCandidateRecoversAfterLocalAndPermanentKeysFail() {
        val port = Port().apply { local = old; broker = old; backup = old; installs = listOf(old, good) }
        assertEquals("RECOVERED", UltraIdentityResolution.recover(port))
        assertEquals(good, port.local)
        assertEquals(1, port.events.count { it == "verify-old" })
        assertFalse("the cached image key already paired", "backup" in port.events)
    }

    @Test fun anExceptionFromAnEarlierKeyStillAllowsTheLaterSavedKey() {
        val port = Port().apply {
            local = old
            throwingKeys = setOf(old)
            installs = listOf(old, good)
        }
        assertEquals("RECOVERED", UltraIdentityResolution.recover(port))
        assertEquals(good, port.local)
        assertEquals(1, port.events.count { it == "verify-old" })
        assertEquals(1, port.events.count { it == "verify-good" })
    }

    @Test fun exportedButUnflashedImageNeverReplacesTheWorkingLocalKey() {
        val port = Port().apply { local = good; installs = listOf(old) }
        assertEquals("RECOVERY_LOCAL_KEY_VERIFIED", UltraIdentityResolution.recover(port))
        assertEquals(good, port.local)
        assertFalse(port.events.contains("installs"))
    }

    @Test fun staleExportCannotReplaceLocalOrRefreshPermanentBackups() {
        val port = Port().apply { local = old; installs = listOf(old) }
        assertEquals("RECOVERY_ROOT_NOT_VERIFIED", UltraIdentityResolution.recover(port))
        assertEquals(old, port.local)
        assertNull(port.maintained)
    }

    @Test fun healthyLocalKeyWinsOverEveryBackupAndRefreshesPersistence() {
        val port = Port().apply { local = good; broker = old; backup = old }
        assertEquals("RECOVERY_LOCAL_KEY_VERIFIED", UltraIdentityResolution.recover(port))
        assertEquals(good, port.local)
        assertEquals(listOf("verify-good", "store", "maintenance"), port.events)
    }

    @Test fun staleWellFormedLocalKeyFallsBackToValidatedPermanentBackup() {
        val port = Port().apply { local = old; broker = old; backup = good }
        assertEquals("RECOVERED", UltraIdentityResolution.recover(port))
        assertEquals(good, port.local)
        assertEquals(listOf("verify-old", "kernel", "installs", "broker", "backup", "verify-good", "store", "maintenance"), port.events)
    }

    @Test fun fullyRemovedAppCanRecoverWithoutItsOldUidOrPreferences() {
        for (brokerAvailable in listOf(true, false)) {
            val port = Port().apply { if (brokerAvailable) broker = good else backup = good }
            assertEquals("RECOVERED", UltraIdentityResolution.recover(port))
            assertEquals(good, port.local)
            assertEquals(good, port.maintained)
        }
    }

    @Test fun invalidAndStaleBackupsNeverOverwriteLocalKeyOrRefreshBackups() {
        for (candidate in listOf(old, "bad", "A".repeat(48), null)) {
            val port = Port().apply { local = old; broker = candidate; backup = candidate }
            assertNotEquals("RECOVERED", UltraIdentityResolution.recover(port))
            assertEquals(old, port.local)
            assertNull(port.maintained)
            assertFalse(port.events.contains("store"))
            assertEquals(1, port.events.count { it == "verify-old" })
        }
    }

    @Test fun bootKeyAndSuspensionChangesDuringProbeCancelBeforePersistence() {
        for (change in listOf("boot", "key", "pause")) {
            val port = Port().apply {
                broker = good
                duringProbe = {
                    when (change) {
                        "boot" -> boot = "boot-2"
                        "key" -> local = old
                        "pause" -> paused = true
                    }
                }
            }
            assertEquals("RECOVERY_SCOPE_CHANGED", UltraIdentityResolution.recover(port))
            assertFalse(port.events.contains("store"))
            assertNull(port.maintained)
        }
    }

    @Test fun failedDurableStoreDoesNotClaimRecoveryOrUpdateBackups() {
        val port = Port().apply { broker = good; storeOk = false }
        assertEquals("RECOVERY_STORE_FAILED", UltraIdentityResolution.recover(port))
        assertNull(port.local)
        assertNull(port.maintained)
    }

    @Test fun localImageCacheIsVerifiedBeforeOpeningBrokerOrNoKeySu() {
        val port = Port().apply { local = old; installs = listOf(old, good); broker = old; backup = old }
        assertEquals("RECOVERED", UltraIdentityResolution.recover(port))
        assertEquals(good, port.local)
        assertFalse("a cached matching key needs no broker lookup", "broker" in port.events)
        assertFalse("foreign no-key root is not the source of Ultra identity", "backup" in port.events)
        assertEquals(1, port.events.count { it == "verify-old" })
    }

    @Test fun noCandidateDoesNotInventABuiltInKeyOrPersistPairing() {
        val port = Port()
        assertEquals("RECOVERY_ROOT_NOT_VERIFIED", UltraIdentityResolution.recover(port))
        assertTrue(port.events.none { it.startsWith("verify-") || it == "store" || it == "maintenance" })
    }

    @Test fun suspensionBlocksAllCredentialAndRootProbes() {
        val port = Port().apply { paused = true; broker = good }
        assertEquals("RECOVERY_SUSPENDED", UltraIdentityResolution.recover(port))
        assertTrue(port.events.isEmpty())
    }

    @Test fun brokerRootSuccessDoesNotDependOnNoKeySuOrBackupReadability() {
        val port = Port().apply { broker = good }
        assertEquals("RECOVERED", UltraIdentityResolution.recover(port))
        assertFalse(port.events.contains("backup"))
    }

    @Test fun cleanManagerRecoversFromKernelWithoutEnvironmentOrSuPrerequisites() {
        val port = Port().apply { kernel = good; broker = old; backup = old }
        assertEquals("RECOVERED", UltraIdentityResolution.recover(port))
        assertEquals(good, port.local)
        assertEquals(good, port.maintained)
        assertEquals(listOf("kernel", "verify-good", "store", "maintenance"), port.events)
    }

    @Test fun aWorkingLocalKeyWinsAndARejectedKernelAllowsSavedInstallCandidates() {
        for (localWins in listOf(true, false)) {
            val port = Port().apply {
                if (localWins) local = good else installs = listOf(good)
                kernel = old
            }
            assertEquals(if (localWins) "RECOVERY_LOCAL_KEY_VERIFIED" else "RECOVERED",
                UltraIdentityResolution.recover(port))
            assertEquals(!localWins, "kernel" in port.events)
            assertEquals(good, port.local)
        }
    }

    @Test fun absentOldKernelAndStaleKernelRepliesContinueToExistingFallbacks() {
        for (candidate in listOf(null, old)) {
            val port = Port().apply { kernel = candidate; broker = good }
            assertEquals("RECOVERED", UltraIdentityResolution.recover(port))
            assertEquals(good, port.local)
            assertTrue(port.events.indexOf("kernel") < port.events.indexOf("broker"))
            assertFalse("backup" in port.events)
        }
    }

    @Test fun malformedKernelRepliesNeverProbeOrPersistAnIdentity() {
        for (candidate in listOf(null, "", "A".repeat(47), "A".repeat(49), "A".repeat(48),
            "!" + good.drop(1), good + "\n", "中" + good.drop(1))) {
            val port = Port().apply { kernel = candidate }
            assertEquals("RECOVERY_ROOT_NOT_VERIFIED", UltraIdentityResolution.recover(port))
            assertTrue(port.events.none { it.startsWith("verify-") || it == "store" || it == "maintenance" })
            assertNull(port.local)
        }
    }

    @Test fun rejectedKernelCandidateNeverClaimsRootOrSavesPairing() {
        val port = Port().apply { kernel = old }
        assertEquals("RECOVERY_ROOT_NOT_VERIFIED", UltraIdentityResolution.recover(port))
        assertNull(port.local)
        assertNull(port.maintained)
        assertFalse("store" in port.events)
    }

    @Test fun scopeChangeWhileClaimingKernelIdentityStopsBeforeRootOrStorage() {
        for (change in listOf("boot", "key", "pause")) {
            val port = Port().apply {
                kernel = good
                duringKernel = {
                    when (change) {
                        "boot" -> boot = "boot-2"
                        "key" -> local = old
                        "pause" -> paused = true
                    }
                }
            }
            assertEquals("RECOVERY_SCOPE_CHANGED", UltraIdentityResolution.recover(port))
            assertTrue(port.events.none { it.startsWith("verify-") || it == "store" || it == "maintenance" })
        }
    }

    @Test fun kernelCandidateUsesTheExistingAtomicStoreAndAcceptedPath() {
        val port = Port().apply { kernel = good; storeOk = false }
        assertEquals("RECOVERY_STORE_FAILED", UltraIdentityResolution.recover(port))
        assertNull(port.local)
        assertNull(port.maintained)
    }

    @Test fun healthyIdentityDoesNotWaitForBootSuOrRecoveryMaterial() {
        for (source in listOf("local", "kernel", "install")) {
            val port = Port().apply {
                when (source) {
                    "local" -> local = good
                    "kernel" -> kernel = good
                    else -> installs = listOf(good)
                }
                bootRestore = "BOOT_SDK_RESTORED"
            }
            assertEquals(if (source == "local") "RECOVERY_LOCAL_KEY_VERIFIED" else "RECOVERED",
                UltraIdentityResolution.recover(port))
            assertEquals(0, port.bootRestoreCalls)
            assertFalse("broker" in port.events)
            assertFalse("backup" in port.events)
        }
    }

    @Test fun restoredBootSessionNeverEntersPermanentBrokerOrStores() {
        val port = Port().apply { bootRestore = "BOOT_SDK_RESTORED"; broker = good }
        assertEquals("BOOT_SDK_RESTORED", UltraIdentityResolution.recover(port))
        assertEquals(1, port.bootRestoreCalls)
        assertNull(port.local)
        assertFalse("broker" in port.events)
        assertFalse("store" in port.events)
    }
}
