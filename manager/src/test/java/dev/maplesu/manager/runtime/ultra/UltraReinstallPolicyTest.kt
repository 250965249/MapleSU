package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

class UltraReinstallPolicyTest {
    private val packageName = "dev.maplesu.manager"
    private val signers = setOf("a".repeat(64))
    private val trust = UltraReinstallTrust(packageName, 0, signers)
    private val key = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(4096)
        .copySecret().toString(Charsets.US_ASCII)

    private fun identity(uid: Int = 10500, name: String = packageName, certificates: Set<String> = signers) =
        ApplicationIdentity(uid, name, listOf(name), certificates, 10L, 11L, "/data/app/new/base.apk")

    @Test fun reinstallWithAnotherUidAndNoAppDataRetainsEnvironmentTrust() {
        assertTrue(trust.allows(10500, identity()))
        assertTrue(trust.allows(10999, identity(10999)))
    }

    @Test fun privilegedTransportIsNotAnInstalledManagerIdentity() {
        for (peer in listOf(-1, 0, 1000, 9999, 20000, 99000, 110500)) {
            assertFalse("peer=$peer without identity", trust.allows(peer, null))
            assertFalse("peer=$peer with another UID's identity", trust.allows(peer, identity()))
        }
    }

    @Test fun rootTransportRequiresAnOriginalManagerUid() {
        for (version in 1..3) {
            val request = ByteArrayOutputStream().apply { DataOutputStream(this).writeInt(version) }
            val response = ByteArrayOutputStream()
            UltraIdentityHandshake.serve(trust, 0, { error("root transport has no package") },
                ByteArrayInputStream(request.toByteArray()), response, { error("direct root reads no key") })
            assertEquals(0, response.size())
        }
    }

    @Test fun forgedPackageSignerDifferentUserAndMismatchingPeerAreRejected() {
        assertFalse(trust.allows(10500, identity(name = "other.package")))
        assertFalse(trust.allows(10500, identity(certificates = setOf("b".repeat(64)))))
        assertFalse(trust.allows(110500, identity(110500)))
        assertFalse(trust.allows(10501, identity()))
        assertFalse(trust.allows(10500, null))
    }

    @Test fun cleanAppPairsAfterLiveRootAndRefreshesAuthorization() {
        val events = mutableListOf<String>()
        var stored: String? = null
        val result = UltraReinstallPairing.recover(key,
            { events += "root"; 0 }, { events += "auth"; true }, { events += "store"; stored = it })
        assertEquals("RECOVERED", result)
        assertEquals(listOf("root", "store", "auth"), events)
        assertEquals(key, stored)
    }

    @Test fun invalidKeyAndNonRootResultsNeverPair() {
        for (failure in listOf("key", "root")) {
            var stored = false
            val result = UltraReinstallPairing.recover(if (failure == "key") "bad" else key,
                { if (failure == "root") 10500 else 0 }, { error("non-root must not authorize") }, { stored = true })
            assertNotEquals("RECOVERED", result)
            assertFalse(failure, stored)
        }
    }

    @Test fun verifiedRootRetainsTheKeyWhenSuAuthorizationFailsOrThrows() {
        for (throws in listOf(false, true)) {
            var stored: String? = null
            var authorizationScheduled = false
            assertEquals("RECOVERED", UltraReinstallPairing.recover(key, { 0 },
                {
                    assertEquals(key, stored)
                    authorizationScheduled = true
                    if (throws) error("temporary auth failure")
                }, { stored = it }))
            assertEquals(key, stored)
            assertTrue(authorizationScheduled)
        }
    }

    @Test fun printableButSdkInvalidCredentialsNeverReachTheKernel() {
        for (candidate in listOf("!".repeat(48), "A".repeat(48), " $key ")) {
            assertEquals("RECOVERY_KEY_INVALID", UltraReinstallPairing.recover(candidate,
                { error("must not probe") }, { error("must not authorize") }, { error("must not store") }))
        }
    }

    @Test fun trustedReinstalledUidReceivesOnlyTheFixedCredentialResponse() {
        val output = ByteArrayOutputStream()
        val request = ByteArrayOutputStream().apply { DataOutputStream(this).writeInt(UltraIdentityHandshake.VERSION) }
        UltraIdentityHandshake.serve(trust, 10999, { identity(10999) },
            ByteArrayInputStream(request.toByteArray()), output, { key })
        assertEquals(4 + 48, output.size())
        DataInputStream(ByteArrayInputStream(output.toByteArray())).use { input ->
            assertEquals(UltraIdentityHandshake.VERSION, input.readInt())
            val secret = ByteArray(48); input.readFully(secret)
            assertEquals(key, secret.toString(Charsets.US_ASCII))
            assertEquals(-1, input.read())
        }
    }

    @Test fun clearedDataAndChangedAndroidIdRestoreFromTheEnvironmentWithTheNewUid() {
        val oldAndroidId = "0123456789abcdef"
        val encrypted = requireNotNull(UltraRecoveryKey.seal(key, oldAndroidId, packageName))
        assertNull(UltraRecoveryKey.open(encrypted, "fedcba9876543210", packageName))
        val request = ByteArrayOutputStream().apply { DataOutputStream(this).writeInt(UltraIdentityHandshake.VERSION) }
        val response = ByteArrayOutputStream()
        UltraIdentityHandshake.serve(trust, 10999, { identity(10999) },
            ByteArrayInputStream(request.toByteArray()), response,
            { UltraRecoveryKey.open(encrypted, oldAndroidId, packageName) })
        val input = DataInputStream(ByteArrayInputStream(response.toByteArray()))
        assertEquals(UltraIdentityHandshake.VERSION, input.readInt())
        val bytes = ByteArray(48).also { input.readFully(it) }
        val recovered = bytes.toString(Charsets.US_ASCII)
        var localKey: String? = null
        assertEquals("RECOVERED", UltraReinstallPairing.recover(recovered,
            { if (it == key) 0 else 10999 }, { true }, { localKey = it }))
        assertEquals(key, localKey)
    }

    @Test fun untrustedPeersNeverMakeTheServerReadTheRequestOrDecryptTheKey() {
        val neverRead = object : java.io.InputStream() { override fun read(): Int = error("untrusted read") }
        for (record in listOf(null, identity(name = "other.app"),
                identity(certificates = setOf("b".repeat(64))), identity(110500))) {
            val output = ByteArrayOutputStream()
            UltraIdentityHandshake.serve(trust, 10500, { record }, neverRead, output, { error("untrusted key read") })
            assertEquals(0, output.size())
        }
    }

    @Test fun installChangesDuringHandshakeAndWrongVersionsReturnNoSecret() {
        for (version in listOf(1, 2, 3, 4)) {
            var reads = 0
            val request = ByteArrayOutputStream().apply { DataOutputStream(this).writeInt(version) }
            val output = ByteArrayOutputStream()
            UltraIdentityHandshake.serve(trust, 10500,
                { if (++reads == 1) identity() else identity(certificates = setOf("b".repeat(64))) },
                ByteArrayInputStream(request.toByteArray()), output,
                { check(version in 1..3); key }, deploymentIdentity = { "a".repeat(64) })
            assertEquals(0, output.size())
        }
    }

    @Test fun rootServiceDelegatesTheOriginalManagerUidInsteadOfRootTrust() {
        val request = ByteArrayOutputStream().apply {
            DataOutputStream(this).apply { writeInt(4); writeInt(10999); writeInt(1) }
        }
        val response = ByteArrayOutputStream()
        UltraIdentityHandshake.serve(trust, 0, { identity(10999) },
            ByteArrayInputStream(request.toByteArray()), response, { key })
        DataInputStream(ByteArrayInputStream(response.toByteArray())).use { input ->
            assertEquals(1, input.readInt())
            val bytes = ByteArray(48).also { input.readFully(it) }
            assertEquals(key, bytes.toString(Charsets.US_ASCII))
        }
    }

    @Test fun rootServiceNeverConvertsAnUntrustedDelegatedUidIntoAKey() {
        for (origin in listOf(0, 10999, 110999)) {
            for (signer in listOf(signers, setOf("b".repeat(64)))) {
                if (origin == 10999 && signer == signers) continue
                val request = ByteArrayOutputStream().apply {
                    DataOutputStream(this).apply { writeInt(4); writeInt(origin); writeInt(1) }
                }
                val response = ByteArrayOutputStream()
                UltraIdentityHandshake.serve(trust, 0, { if (origin == 0) null else identity(origin, certificates = signer) },
                    ByteArrayInputStream(request.toByteArray()), response, { error("untrusted delegated read") })
                assertEquals(0, response.size())
            }
        }
    }

    @Test fun appPeersNeverSubmitTheRootServiceDelegationProtocol() {
        val request = ByteArrayOutputStream().apply {
            DataOutputStream(this).apply { writeInt(4); writeInt(10500); writeInt(1) }
        }
        val response = ByteArrayOutputStream()
        UltraIdentityHandshake.serve(trust, 10500, { identity() },
            ByteArrayInputStream(request.toByteArray()), response, { error("app delegated read") })
        assertEquals(0, response.size())
    }
}
