package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import java.io.File
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class UltraManagerIdentityClaimTest {
    private val key = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(4096)
        .copySecret().toString(Charsets.US_ASCII)

    private fun receipt(candidate: String? = key, verified: Boolean? = false,
                        ok: Boolean = true, error: String = "OK",
                        operation: String = "claim_manager_identity"): NativeReceipt {
        val data = JSONObject()
        if (candidate != null) data.put("candidate", candidate)
        if (verified != null) data.put("liveRootVerified", verified)
        return requireNotNull(NativeReceipt.parse(JSONObject().put("schemaVersion", 1)
            .put("backend", "maplesu_ultra").put("bridgeVersion", 1)
            .put("operation", operation).put("ok", ok).put("sdkError", error)
            .put("sdkErrorCode", if (ok && error == "OK") 0 else -1001)
            .put("data", data).toString()))
    }

    @Test fun completeKernelCandidateIsDecodedWithoutActivatingIt() {
        assertEquals(key, parseManagerIdentityCandidate(receipt()))
        assertEquals(false, receipt().bool("liveRootVerified"))
    }

    @Test fun absentOldKernelReplyHasNoCandidateOrEnvironmentInference() {
        assertNull(parseManagerIdentityCandidate(receipt(candidate = null)))
        assertNull(parseManagerIdentityCandidate(NativeReceipt.bridgeFailure(
            "claim_manager_identity", "MAPLESU_BRIDGE_UNAVAILABLE", null)))
    }

    @Test fun exactLengthAlphabetAndSdkMetadataAreRequiredForCandidate() {
        for (candidate in listOf("", key.drop(1), key + "A", key + "\n", "!" + key.drop(1),
            "中" + key.drop(1), "A".repeat(48))) {
            assertNull(parseManagerIdentityCandidate(receipt(candidate)))
        }
    }

    @Test fun malformedOrFailedEnvelopeNeverProducesACandidate() {
        assertNull(parseManagerIdentityCandidate(receipt(verified = null)))
        assertNull(parseManagerIdentityCandidate(receipt(verified = true)))
        assertNull(parseManagerIdentityCandidate(receipt(ok = false)))
        assertNull(parseManagerIdentityCandidate(receipt(error = "MAPLESU_BRIDGE_EXCEPTION")))
        assertNull(parseManagerIdentityCandidate(receipt(operation = "get_maplesu_environment_state")))
    }

    private fun source(name: String): String {
        val relative = "src/main/java/dev/maplesu/manager/runtime/ultra/$name"
        return listOf(File(relative), File("manager/$relative")).first { it.isFile }.readText()
    }

    @Test fun productionRecoveryChecksSuspensionBeforeAnyRestoreOrNativeClaim() {
        val recovery = source("UltraIdentityRecovery.kt").substringAfter("fun recover(context: Context): String {")
            .substringBefore("internal fun uid(")
        assertTrue(recovery.indexOf("if (blocked(app))") >= 0)
        assertTrue(recovery.indexOf("if (blocked(app))") < recovery.indexOf("UltraSdkSession.restore(app)"))
        val claim = recovery.substringAfter("override fun kernelKey(): String? =")
            .substringBefore("override fun brokerKey()")
        assertTrue(claim.contains("if (blocked()) null else UltraRuntimeClient().claimManagerIdentity()"))
        assertFalse(claim.contains("environmentState"))
        assertFalse(claim.contains("rootUid"))
        assertFalse(claim.contains("UltraSuChannel"))
    }

    @Test fun productionClientUsesLocalNoKeyEntry() {
        val client = source("UltraRuntimeClient.kt").substringAfter("internal fun claimManagerIdentity(): String? =")
            .substringBefore("/** Reads structural credential candidates")
        assertTrue(client.contains("localCall(\"claim_manager_identity\")"))
        assertTrue(client.contains("NativeBridge.claimManagerIdentity()"))
        assertFalse(client.contains("key()"))
    }
}
