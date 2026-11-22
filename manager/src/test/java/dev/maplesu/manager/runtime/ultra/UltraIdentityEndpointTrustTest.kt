package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import org.junit.Assert.*
import org.junit.Test

class UltraIdentityEndpointTrustTest {
    private val signers = setOf("a".repeat(64))
    private val trust = UltraReinstallTrust("dev.maplesu.manager", 0, signers)
    private val key = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(4096)
        .copySecret().toString(Charsets.US_ASCII)
    private val deployment = "b".repeat(64)
    private fun manager(uid: Int = 10500, signer: Set<String> = signers, name: String = trust.packageName) =
        ApplicationIdentity(uid, name, listOf(name), signer, 10L, 11L, "/data/app/current/base.apk")
    private fun request(vararg values: Int) = ByteArrayOutputStream().apply {
        DataOutputStream(this).apply { values.forEach(::writeInt) }
    }.toByteArray()
    private fun serve(peer: Int, request: ByteArray, identity: (Int) -> ApplicationIdentity?,
                      read: () -> String? = { key }, build: () -> String? = { "test-build" },
                      installed: () -> String? = { deployment }): ByteArray = ByteArrayOutputStream().also {
        UltraIdentityHandshake.serve(trust, peer, identity, ByteArrayInputStream(request), it, read, build, installed)
    }.toByteArray()
    private fun verify(reply: ByteArray, version: Int) = DataInputStream(ByteArrayInputStream(reply)).use {
        assertEquals(version, it.readInt())
        assertEquals(key, ByteArray(48).also(it::readFully).toString(Charsets.US_ASCII))
        if (version >= 2) assertEquals("test-build", it.readUTF())
        if (version == 3) assertEquals(deployment, it.readUTF())
        assertEquals(-1, it.read())
    }

    @Test fun rootDirectLegacyVersionsNeverReadKeyBuildOrDeployment() {
        for (version in 1..3) assertEquals(0, serve(0, request(version),
            { error("root transport has no app identity") }, { error("root direct read") },
            { error("root direct build") }, { error("root direct deployment") }).size)
    }

    @Test fun trustedManagerDirectRetainsAllThreeWireFormatsAndTwoPmReads() {
        for (version in 1..3) {
            var reads = 0
            verify(serve(10500, request(version), { reads++; manager() }), version)
            assertEquals(2, reads)
        }
    }

    @Test fun rootDelegationRetainsAllThreeWireFormatsAndTwoIndependentPmReads() {
        for (version in 1..3) {
            var reads = 0
            verify(serve(0, request(4, 10999, version), { uid -> reads++; manager(uid) }), version)
            assertEquals(2, reads)
        }
    }

    @Test fun everyDelegatedRequestRereadsPmInsteadOfCachingAnEarlierSuccess() {
        var record: ApplicationIdentity? = manager(10999)
        verify(serve(0, request(4, 10999, 1), { record }), 1)
        record = null
        assertEquals(0, serve(0, request(4, 10999, 1), { record }, { error("unknown delegated read") }).size)
        record = manager(10999, setOf("b".repeat(64)))
        assertEquals(0, serve(0, request(4, 10999, 1), { record }, { error("changed signer read") }).size)
    }

    @Test fun unknownDirectPeerDoesNotReadTheRequestOrCredential() {
        val unread = object : java.io.InputStream() { override fun read(): Int = error("unknown input") }
        val output = ByteArrayOutputStream()
        UltraIdentityHandshake.serve(trust, 10500, { null }, unread, output, { error("unknown key") })
        assertEquals(0, output.size())
    }

    @Test fun unknownOrUnrelatedOrDifferentSignerDirectPeersReceiveNoCredential() {
        for (record in listOf(null, manager(name = "other.app"), manager(signer = setOf("b".repeat(64))))) {
            for (version in 1..3) assertEquals(0, serve(10500, request(version), { record },
                { error("untrusted direct read") }).size)
        }
    }

    @Test fun previousManagerUidReusedByAnotherSignerGetsNoDirectOrDelegatedKey() {
        var record = manager()
        verify(serve(10500, request(1), { record }), 1)
        record = manager(signer = setOf("b".repeat(64)))
        for (payload in listOf(request(1), request(4, 10500, 1))) {
            val peer = if (payload.size == 4) 10500 else 0
            assertEquals(0, serve(peer, payload, { record }, { error("reused UID read") }).size)
        }
    }

    @Test fun delegatedUnknownSignerPackageOrDifferentUserGetsNoKey() {
        for (record in listOf(null, manager(10999, setOf("b".repeat(64))),
                manager(10999, name = "other.app"), manager(110999))) {
            val uid = record?.uid ?: 10999
            assertEquals(0, serve(0, request(4, uid, 1), { record }, { error("untrusted delegate read") }).size)
        }
    }

    @Test fun trustedAppStillDoesNotSubmitRootDelegation() {
        var reads = 0
        assertEquals(0, serve(10500, request(4, 10500, 1), { reads++; manager() },
            { error("app forged delegation") }).size)
        assertEquals(1, reads)
    }

    @Test fun rootDoesNotDelegateRootSystemOrNonApplicationUids() {
        for (uid in listOf(-1, 0, 1000, 9999, 20000)) {
            assertEquals(0, serve(0, request(4, uid, 1), { error("invalid delegate PM") },
                { error("invalid delegate key") }).size)
        }
    }

    @Test fun signerChangeDuringDirectOrDelegatedDecryptionPublishesNoKey() {
        for (delegated in listOf(false, true)) {
            var record = manager()
            val reply = serve(if (delegated) 0 else 10500,
                if (delegated) request(4, 10500, 1) else request(1), { record },
                { record = manager(signer = setOf("b".repeat(64))); key })
            assertEquals(0, reply.size)
        }
    }

    @Test fun reinstallDuringBuildOrDeploymentReadPublishesNoKey() {
        for (version in 2..3) {
            var record = manager()
            val reply = serve(0, request(4, 10500, version), { record }, build = {
                if (version == 2) record = manager(10999)
                "test-build"
            }, installed = { record = manager(10999); deployment })
            assertEquals(0, reply.size)
        }
    }

    @Test fun wrongPeerUidDoesNotInheritTheManagersIdentity() {
        assertEquals(0, serve(10501, request(1), { manager() }, { error("wrong peer read") }).size)
        assertEquals(0, serve(0, request(4, 10501, 1), { manager() }, { error("wrong delegate read") }).size)
    }

    @Test fun unsupportedAndTruncatedDelegationsReadNoCredential() {
        for (payload in listOf(request(4), request(4, 10500), request(4, 10500, 0), request(4, 10500, 5))) {
            assertEquals(0, serve(0, payload, { manager() }, { error("invalid protocol read") }).size)
        }
    }

    @Test fun endpointRestrictionDoesNotRemoveManualThirdPartySuEntries() {
        val packages = mutableListOf("third.party.manual")
        var grants = 0
        val session = UltraManagerSignatureAuthorization.Session(trust)
        assertEquals("OK", session.refresh({ manager() }, { packages.toList() },
            { grants++; packages += trust.packageName; "OK" }, { error("unexpected revoke") }))
        assertEquals(listOf("third.party.manual", trust.packageName), packages)
        assertEquals(1, grants)
    }

    private fun publicIdentityClaim() = ByteArrayOutputStream().apply {
        DataOutputStream(this).apply {
            writeInt(1)
            writeUTF(trust.packageName)
            writeUTF(signers.single())
        }
    }.toByteArray()

    @Test fun otherPackageWithTrustedPublicCertificateAndManagerClaimReadsNoKey() {
        val pmIdentity = manager(name = "other.package")
        assertEquals(0, serve(pmIdentity.uid, publicIdentityClaim(), { pmIdentity },
            { error("public certificate and package claim grant no credential") }).size)
    }

    @Test fun samePackageWithDifferentPmSignerDoesNotOverrideItWithAPublicClaim() {
        val pmIdentity = manager(signer = setOf("b".repeat(64)))
        assertEquals(0, serve(pmIdentity.uid, publicIdentityClaim(), { pmIdentity },
            { error("client signer claim must not replace PM facts") }).size)
    }

    @Test fun extraCurrentPmSignerIsNotIgnoredWhenClientClaimsThePinnedSigner() {
        val pmIdentity = manager(signer = signers + "b".repeat(64))
        assertEquals(0, serve(pmIdentity.uid, publicIdentityClaim(), { pmIdentity },
            { error("all current PM signers must match") }).size)
    }

    @Test fun sharedOrDuplicatePackageUidClaimsAreNotTrustedApplicationIdentities() {
        for (packages in listOf(listOf(trust.packageName, "other.package"),
                listOf(trust.packageName, trust.packageName))) {
            try {
                ApplicationIdentity(10500, trust.packageName, packages, signers,
                    10L, 11L, "/data/app/current/base.apk")
                fail("A UID identity must have exactly one package")
            } catch (_: IllegalArgumentException) { }
        }
    }
}
