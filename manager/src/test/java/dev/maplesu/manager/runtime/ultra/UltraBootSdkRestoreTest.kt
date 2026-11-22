package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.litehidden.RecoveryIdentity
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import org.junit.Assert.*
import org.junit.Test

class UltraBootSdkRestoreTest {
    private val boot = "11111111-2222-4333-8444-555555555555"
    private val identity = RecoveryIdentity("0123456789abcdef", "dev.maplesu.manager", 10123)
    private val key = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(-4096)
        .copySecret().toString(Charsets.US_ASCII)
    private val material get() = requireNotNull(UltraBootSdkRecovery.seal(
        requireNotNull(UltraBootSdkSession.create(boot, key)), identity))
    private inner class Port : UltraBootSdkRestore.Port {
        var bootId: String? = boot
        var ready = true
        var saved: UltraBootSdkSession? = null
        var storeResult = true
        override fun currentBootId() = bootId
        override fun verified(session: UltraBootSdkSession): Boolean = ready
        override fun store(session: UltraBootSdkSession): Boolean {
            if (storeResult) saved = session
            return storeResult
        }
    }

    @Test fun coldSameBootRestoreKeepsTheHotloadSubmissionGuard() {
        val port = Port()
        assertEquals("BOOT_SDK_RESTORED", UltraBootSdkRestore.restore(material, identity, port))
        assertEquals(key, port.saved?.key)
        assertEquals(true, port.saved?.installSubmitted)
    }

    @Test fun changedBootPackageUidOrAndroidIdentityNeverStoresAKey() {
        for (other in listOf(identity.copy(uid = 10124), identity.copy(packageName = "dev.other.manager"),
            identity.copy(androidId = "fedcba9876543210"))) {
            val port = Port()
            assertEquals("BOOT_SDK_RECOVERY_EXPIRED_OR_INVALID", UltraBootSdkRestore.restore(material, other, port))
            assertNull(port.saved)
        }
        val port = Port().apply { bootId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }
        assertEquals("BOOT_SDK_RECOVERY_EXPIRED_OR_INVALID", UltraBootSdkRestore.restore(material, identity, port))
        assertNull(port.saved)
    }

    @Test fun runtimeVerificationAndStorageAreRequired() {
        val port = Port().apply { ready = false }
        assertEquals("BOOT_SDK_RUNTIME_UNVERIFIED", UltraBootSdkRestore.restore(material, identity, port))
        assertNull(port.saved)
        port.ready = true
        port.storeResult = false
        assertEquals("BOOT_SDK_RECOVERY_STORE_FAILED", UltraBootSdkRestore.restore(material, identity, port))
        assertNull(port.saved)
    }

    @Test fun bootChangeDuringVerificationNeverPersistsTheCandidate() {
        var stored = false
        var current = boot
        val port = object : UltraBootSdkRestore.Port {
            override fun currentBootId() = current
            override fun verified(session: UltraBootSdkSession): Boolean { current = "other"; return true }
            override fun store(session: UltraBootSdkSession): Boolean { stored = true; return true }
        }
        assertEquals("BOOT_SDK_BOOT_CHANGED", UltraBootSdkRestore.restore(material, identity, port))
        assertFalse(stored)
    }
}
