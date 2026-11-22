package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import org.junit.Assert.*
import org.junit.Test

class UltraIdentityRecoveryFallbackTest {
    private val key = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(4096)
        .copySecret().toString(Charsets.US_ASCII)

    private inner class Port : UltraIdentityResolution.Port {
        var saved: String? = null
        var brokerReads = 0
        var probes = 0
        var maintained = false
        var uid: Int? = 0
        override fun currentKey() = saved
        override fun blocked() = false
        override fun bootId() = "current-boot"
        override fun rootUid(key: String): Int? { probes++; return uid }
        override fun brokerKey() = key.also { brokerReads++ }
        override fun backupKey(): String? = null
        override fun store(expected: String?, key: String): Boolean { saved = key; return true }
        override fun accepted(key: String) { maintained = true }
    }

    @Test fun noKeySuFailureAndStaleTemporaryRecordsStillTryThePermanentBroker() {
        for (temporaryResult in listOf(null, "BOOT_SDK_RECOVERY_UNREADABLE",
            "BOOT_SDK_RECOVERY_EXPIRED_OR_INVALID", "BOOT_SDK_RUNTIME_UNVERIFIED",
            "BOOT_SDK_RECOVERY_IDENTITY_MISSING", "BOOT_SDK_RECOVERY_STORE_FAILED",
            "BOOT_SDK_BOOT_CHANGED")) {
            val port = Port()
            assertEquals(temporaryResult, "RECOVERED", UltraIdentityResolution.recover(port, temporaryResult))
            assertEquals(key, port.saved)
            assertEquals(1, port.brokerReads)
            assertEquals(1, port.probes)
            assertTrue(port.maintained)
        }
    }

    @Test fun workingTemporarySessionKeepsPermanentIdentityUntouched() {
        for (temporaryResult in listOf("BOOT_SDK_CURRENT", "BOOT_SDK_RESTORED")) {
            val port = Port()
            assertEquals(temporaryResult, UltraIdentityResolution.recover(port, temporaryResult))
            assertNull(port.saved)
            assertEquals(0, port.brokerReads)
            assertEquals(0, port.probes)
            assertFalse(port.maintained)
        }
    }

    @Test fun failedTemporaryReadDoesNotTurnAnUnverifiedBrokerIntoRoot() {
        for (uid in listOf(null, 10123)) {
            val port = Port().apply { this.uid = uid }
            assertEquals("RECOVERY_ROOT_NOT_VERIFIED",
                UltraIdentityResolution.recover(port, "BOOT_SDK_RECOVERY_UNREADABLE"))
            assertEquals(1, port.brokerReads)
            assertNull(port.saved)
            assertFalse(port.maintained)
        }
    }

    @Test fun cachedImageFallbackRunsAfterOtherSourcesAndStillNeedsLiveRoot() {
        for (uid in listOf(null, 10123, 0)) {
            val port = Port().apply { this.uid = uid }
            var imageReads = 0
            val fallback = object : UltraIdentityResolution.Port by port {
                override fun brokerKey(): String? = null
                override fun imageKeys() = sequence { imageReads++; yield(key) }
            }
            assertEquals(if (uid == 0) "RECOVERED" else "RECOVERY_ROOT_NOT_VERIFIED",
                UltraIdentityResolution.recover(fallback, "BOOT_SDK_RECOVERY_UNREADABLE"))
            assertEquals(1, imageReads)
            assertEquals(if (uid == 0) key else null, port.saved)
            assertEquals(uid == 0, port.maintained)
        }
    }

    @Test fun cachedImagesAreLazyAndDoNotRunWhenTheBrokerAlreadyRecovered() {
        val port = Port()
        val fallback = object : UltraIdentityResolution.Port by port {
            override fun imageKeys(): Sequence<String> = error("a healthy broker needs no image scan")
        }
        assertEquals("RECOVERED", UltraIdentityResolution.recover(fallback))
        assertEquals(key, port.saved)
    }

    @Test fun cachedImageLoopStopsAtTheFirstLiveVerifiedCandidate() {
        val port = Port()
        val fallback = object : UltraIdentityResolution.Port by port {
            override fun brokerKey(): String? = null
            override fun imageKeys() = sequence {
                yield("malformed")
                yield(key)
                error("later cached images must not be read after success")
            }
        }
        assertEquals("RECOVERED", UltraIdentityResolution.recover(fallback))
        assertEquals(1, port.probes)
        assertEquals(key, port.saved)
    }

    @Test fun cachedImageIoFailureDoesNotCrashOrClaimRecovery() {
        val port = Port()
        val fallback = object : UltraIdentityResolution.Port by port {
            override fun brokerKey(): String? = null
            override fun imageKeys() = sequence<String> { throw java.io.IOException("cache disappeared") }
        }
        assertEquals("RECOVERY_ROOT_NOT_VERIFIED", UltraIdentityResolution.recover(fallback))
        assertNull(port.saved)
    }

    @Test fun cachedImageCancellationPropagatesAndInterruptRemainsSet() {
        val port = Port()
        for (interrupt in listOf(false, true)) {
            val fallback = object : UltraIdentityResolution.Port by port {
                override fun brokerKey(): String? = null
                override fun imageKeys() = sequence<String> {
                    if (interrupt) throw InterruptedException("cancelled")
                    throw java.util.concurrent.CancellationException("cancelled")
                }
            }
            if (interrupt) {
                try {
                    assertEquals("RECOVERY_SCOPE_CHANGED", UltraIdentityResolution.recover(fallback))
                    assertTrue(Thread.currentThread().isInterrupted)
                } finally { Thread.interrupted() }
            } else {
                assertThrows(java.util.concurrent.CancellationException::class.java) {
                    UltraIdentityResolution.recover(fallback)
                }
            }
            assertNull(port.saved)
        }
    }

    @Test fun cancellationFromEveryRecoveryPortStopsBeforeAnotherSourceOrStore() {
        for (source in listOf("root", "install", "kernel", "broker", "backup")) {
            val port = Port().apply { if (source == "root") saved = key }
            var laterReads = 0
            val fallback = object : UltraIdentityResolution.Port by port {
                override fun rootUid(key: String): Int? =
                    if (source == "root") throw java.util.concurrent.CancellationException(source) else 0
                override fun installKeys(): List<String> =
                    if (source == "install") throw java.util.concurrent.CancellationException(source) else emptyList()
                override fun kernelKey(): String? =
                    if (source == "kernel") throw java.util.concurrent.CancellationException(source) else null
                override fun brokerKey(): String? =
                    if (source == "broker") throw java.util.concurrent.CancellationException(source) else null
                override fun backupKey(): String? {
                    if (source == "backup") throw java.util.concurrent.CancellationException(source)
                    laterReads++
                    return key
                }
                override fun imageKeys() = sequence { laterReads++; yield(key) }
            }
            assertThrows(source, java.util.concurrent.CancellationException::class.java) {
                UltraIdentityResolution.recover(fallback)
            }
            assertEquals(source, 0, laterReads)
            assertEquals(source, if (source == "root") key else null, port.saved)
            assertFalse(source, port.maintained)
        }
    }

    @Test fun interruptedRecoveryPortsPreserveInterruptAndNeverContinueOrStore() {
        for (source in listOf("root", "install", "kernel", "broker", "backup")) {
            val port = Port().apply { if (source == "root") saved = key }
            var laterReads = 0
            val fallback = object : UltraIdentityResolution.Port by port {
                override fun rootUid(key: String): Int? =
                    if (source == "root") throw InterruptedException(source) else 0
                override fun installKeys(): List<String> =
                    if (source == "install") throw InterruptedException(source) else emptyList()
                override fun kernelKey(): String? =
                    if (source == "kernel") throw InterruptedException(source) else null
                override fun brokerKey(): String? =
                    if (source == "broker") throw InterruptedException(source) else null
                override fun backupKey(): String? {
                    if (source == "backup") throw InterruptedException(source)
                    laterReads++
                    return key
                }
                override fun imageKeys() = sequence { laterReads++; yield(key) }
            }
            try {
                assertEquals(source, "RECOVERY_SCOPE_CHANGED", UltraIdentityResolution.recover(fallback))
                assertTrue(source, Thread.currentThread().isInterrupted)
                assertEquals(source, 0, laterReads)
                assertEquals(source, if (source == "root") key else null, port.saved)
                assertFalse(source, port.maintained)
            } finally { Thread.interrupted() }
        }
    }

    @Test fun kernelClaimStillRequiresActualUidZeroBeforePairing() {
        for (uid in listOf(null, 10123, 0)) {
            val port = Port().apply { this.uid = uid }
            val fallback = object : UltraIdentityResolution.Port by port {
                override fun kernelKey() = key
            }
            assertEquals(if (uid == 0) "RECOVERED" else "RECOVERY_ROOT_NOT_VERIFIED",
                UltraIdentityResolution.recover(fallback))
            assertEquals(if (uid == 0) key else null, port.saved)
            assertEquals(uid == 0, port.maintained)
            assertEquals(1, port.probes)
        }
    }

    @Test fun kernelClaimIoFailureContinuesToTheExistingBroker() {
        val port = Port()
        val fallback = object : UltraIdentityResolution.Port by port {
            override fun kernelKey(): String? = throw java.io.IOException("identity path unavailable")
        }
        assertEquals("RECOVERED", UltraIdentityResolution.recover(fallback))
        assertEquals(key, port.saved)
        assertEquals(1, port.brokerReads)
        assertEquals(1, port.probes)
    }

    @Test fun aSuspendedRecoveryNeverCallsTheNoKeyKernelClaim() {
        val port = Port()
        val fallback = object : UltraIdentityResolution.Port by port {
            override fun blocked() = true
            override fun kernelKey(): String? = error("suspended native request")
        }
        assertEquals("RECOVERY_SUSPENDED", UltraIdentityResolution.recover(fallback))
        assertNull(port.saved)
        assertEquals(0, port.brokerReads)
        assertEquals(0, port.probes)
    }
}
