package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.litehidden.RecoveryIdentity
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class UltraBootSdkSessionTest {
    private val boot = "11111111-2222-4333-8444-555555555555"
    private val nextBoot = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val pkg = "dev.maplesu.manager"
    private val identity = requireNotNull(RecoveryIdentity.of("0123456789abcdef", pkg, 10_123))
    private val key = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(-4096)
        .copySecret().toString(Charsets.US_ASCII)
    private fun session() = requireNotNull(UltraBootSdkSession.create(boot, key))

    @Test fun serializedSubmissionGuardSurvivesReload() {
        val restored = requireNotNull(UltraBootSdkSession.parse(session().submitted().encode()))
        assertEquals(boot, restored.bootId)
        assertEquals(key, restored.key)
        assertTrue(restored.installSubmitted)
        assertTrue(restored.current(boot))
        assertFalse(restored.current(nextBoot))
        assertFalse(restored.current(null))
    }

    @Test fun malformedBootAndUnboundCredentialsAreRejected() {
        assertNull(UltraBootSdkSession.create(null, key))
        assertNull(UltraBootSdkSession.create("invalid", key))
        assertNull(UltraBootSdkSession.create(boot, "Aa1".repeat(16)))
        assertNull(UltraBootSdkSession.create(boot, null))
    }

    @Test fun corruptedAndUnsupportedRecordsAreRejected() {
        for (text in listOf(null, "", "garbage", "{}", "x".repeat(1025),
            JSONObject(session().encode()).put("v", 2).toString())) {
            assertNull(UltraBootSdkSession.parse(text))
        }
        val missingGuard = JSONObject(session().encode()).apply { remove("installSubmitted") }
        assertNull(UltraBootSdkSession.parse(missingGuard.toString()))
    }

    @Test fun recoveryIsIndependentAndBoundToTheSameBootAndPackage() {
        val sealed = requireNotNull(UltraBootSdkRecovery.seal(session(), identity))
        val restored = requireNotNull(UltraBootSdkRecovery.open(sealed, boot, pkg))
        assertEquals(key, restored.key)
        assertTrue(restored.installSubmitted)
        assertNull(UltraBootSdkRecovery.open(sealed, nextBoot, pkg))
        assertNull(UltraBootSdkRecovery.open(sealed, null, pkg))
        assertNull(UltraBootSdkRecovery.open(sealed, boot, "dev.other.manager"))
        assertFalse(sealed.contains(key))
    }

    @Test fun editedBootAndEncryptedMaterialFailIntegrityChecks() {
        val record = JSONObject(requireNotNull(UltraBootSdkRecovery.seal(session(), identity)))
        record.put("bootId", nextBoot)
        assertNull(UltraBootSdkRecovery.open(record.toString(), nextBoot, pkg))
        record.put("bootId", boot).put("sealedKey", "corrupt")
        assertNull(UltraBootSdkRecovery.open(record.toString(), boot, pkg))
        assertNull(UltraBootSdkRecovery.open("x".repeat(8193), boot, pkg))
    }

    @Test fun diagnosticsExposeNeitherTheSecretNorItsInitDirectory() {
        val description = session().toString()
        assertFalse(description.contains(key))
        assertFalse(description.contains(key.take(16)))
        assertFalse(description.contains(boot))
    }
}
