package dev.maplesu.manager.runtime.ultra

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class UltraSdkOptimizationTest {
    private fun managerIdentity() = ApplicationIdentity(10500, "dev.maplesu.manager",
        listOf("dev.maplesu.manager"), setOf("a".repeat(64)), 10L, 11L, "/data/app/current/base.apk")
    private val manager = File(System.getProperty("user.dir") ?: ".").let {
        if (File(it, "src/main/java").isDirectory) it else File(it, "manager")
    }
    private fun source(name: String) = File(manager,
        "src/main/java/dev/maplesu/manager/runtime/ultra/$name").readText()

    @Test fun currentBuildLabelsRecoverTheRealSdkVersion() {
        for (label in listOf("maplesu-ultra-5.1.0-parasite-r7-20261105", "maplesu-ultra-5.1.0-optimized-r8-20261106")) {
            assertEquals("5.1.0", UltraEnvironmentVersion.displayOf(null, label))
        }
        assertEquals("5.0.5", UltraEnvironmentVersion.displayOf("5.0.5", "maplesu-ultra-5.1.0-optimized-r8-20261106"))
        for (bad in listOf("maplesu-ultra-5.1.0-", "maplesu-ultra-5.1.0-../bad", "maplesu-ultra-5.1.0\nfoo", "maplesu-ultra-5.1.0/extra")) {
            assertNull(bad, UltraEnvironmentVersion.displayOf(null, bad))
        }
    }

    @Test fun helperSizeComesFromTheActualReleaseManifest() {
        val manifest = JSONObject(File(manager.parentFile, "runtime/maplesu-sdk/SDK-RELEASE.json").readText())
        assertEquals(manifest.getJSONObject("helper").getLong("size"), UltraInstalledIdentityProbe.bundledHelperSizeBytes())
    }

    @Test fun aDifferentSizedInstalledHelperIsHashedInTheSameReadback() {
        val bundledSize = 1_179_976L
        val actualSize = 1_163_328L
        val path = "/data/0123456789abcdef/init"
        val sha = "c".repeat(64)
        val receipt = NativeReceipt.parse(JSONObject()
            .put("schemaVersion", 1).put("backend", UltraRuntimeClient.BACKEND).put("bridgeVersion", 1)
            .put("operation", "read_installed_helper").put("ok", true).put("sdkError", "OK").put("sdkErrorCode", 0)
            .put("data", JSONObject().put("abiVersion", 1).put("complete", true).put("rootVerified", true)
                .put("sha256", sha).put("path", path).put("size", actualSize)
                .put("bytesRead", actualSize).put("normalizedOffset", 182_886L))
            .toString())
        assertNotEquals(bundledSize, actualSize)
        val observed = UltraInstalledIdentityProbe.parseReadback(receipt, path, 182_886L)
        assertEquals(sha, observed?.sha256)
        assertEquals(actualSize, observed?.size)
    }

    @Test fun pairingReturnsBeforeRecoveryMaintenance() {
        for (file in listOf("UltraAutoPair.kt", "UltraKeyProvisioning.kt")) {
            val text = source(file)
            assertFalse(file, text.contains("UltraEnvironmentInstaller.backupKey("))
            assertFalse(file, text.contains("UltraSelfWhitelist.ensure("))
            assertTrue(file, text.contains("UltraPairingMaintenance.request("))
        }
    }

    @Test fun pairingAppliesLogPolicyBeforeReturningAndMaintenanceRunsAtBackgroundPriority() {
        for (file in listOf("UltraAutoPair.kt", "UltraKeyProvisioning.kt")) {
            val text = source(file)
            val policy = text.indexOf("UltraSdkLogging.ensureDisabled(")
            val deferred = text.indexOf("UltraPairingMaintenance.request(")
            assertTrue(file, policy >= 0 && policy < deferred)
        }
        val text = source("UltraPairingMaintenance.kt")
        val priority = text.indexOf("Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND)")
        assertTrue(priority >= 0 && priority < text.indexOf("task.run()"))
    }

    @Test fun localVersionAndIdentityDoNotAcquireTheMutatingSdkLock() {
        val text = source("UltraRuntimeClient.kt")
        assertFalse(text, text.contains("fun sdkVersion(): NativeReceipt = call("))
        assertFalse(text, text.contains("fun sdkBuildIdentity(): NativeReceipt = call("))
    }

    @Test fun settingsReadsOnlyProbeAndSkipsRootIdentityWhenVersionIsKnown() {
        val text = File(manager, "src/main/java/com/maplesu/core/ui/screen/settings/UltraEnvironmentSettings.kt").readText()
        val body = text.substringAfter("private suspend fun readFacts(").substringBefore("private fun readVersion(")
        assertFalse(body.contains("UltraAutoPair.ensure("))
        assertTrue(text.substringAfter("private fun readVersion(").substringBefore("private fun applyFacts(")
            .contains("if (raw != null) return@runCatching"))
    }

    @Test fun runtimeIdentityHasNoHistoricalSdkVersion() {
        val manifest = File(manager.parentFile, "runtime/maplesu-sdk/SDK-RELEASE.json").readText()
        val cmake = File(manager.parentFile, "runtime/maplesu-sdk/SDK-IDENTITY.cmake").readText()
        assertFalse(manifest.contains("4.6.5"))
        assertFalse(cmake.contains("4.6.5"))
        assertEquals(UltraSdkBuild.SDK_VERSION, JSONObject(manifest).getString("sdkVersion"))
    }

    @Test fun upgradedIdentityHandshakeReportsItsRunningBuild() {
        val key = dev.maplesu.manager.ultrakernel.UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(4096).copySecret().toString(Charsets.US_ASCII)
        val trust = UltraReinstallTrust("dev.maplesu.manager", 0, setOf("a".repeat(64)))
        val request = ByteArrayOutputStream().apply { DataOutputStream(this).writeInt(2) }
        val response = ByteArrayOutputStream()
        UltraIdentityHandshake.serve(trust, 10500, { managerIdentity() }, ByteArrayInputStream(request.toByteArray()), response, { key })
        assertTrue("New protocol must answer while v1 stays compatible", response.size() > 52)
        DataInputStream(ByteArrayInputStream(response.toByteArray())).use { input ->
            assertEquals(2, input.readInt())
            assertEquals(key, ByteArray(48).also { input.readFully(it) }.toString(Charsets.US_ASCII))
            assertEquals(UltraSdkBuild.BUILD_ID, input.readUTF())
            assertEquals(-1, input.read())
        }
    }
    @Test fun serviceBuildReceiptsRequireALiveIdentityWhileLegacyRecoveryStaysCompatible() {
        val key = dev.maplesu.manager.ultrakernel.UltraKernelCredential.of("Aa1".repeat(16))
            .withMetadataDisplacement(4096).copySecret().toString(Charsets.US_ASCII)
        val trust = UltraReinstallTrust("dev.maplesu.manager", 0, setOf("a".repeat(64)))
        for (version in listOf(1, 2)) {
            val request = ByteArrayOutputStream().apply { DataOutputStream(this).writeInt(version) }
            val response = ByteArrayOutputStream()
            var buildReads = 0
            UltraIdentityHandshake.serve(trust, 10500, { managerIdentity() }, ByteArrayInputStream(request.toByteArray()), response,
                { key }, buildIdentity = { buildReads++; null })
            assertEquals(if (version == 1) 52 else 0, response.size())
            assertEquals(if (version == 1) 0 else 1, buildReads)
        }
        val broker = source("UltraIdentityBroker.kt")
        assertTrue(broker.contains("UltraRuntimeClient().sdkBuildIdentity()"))
        assertTrue(broker.contains("receipt.string(\"sdkSha256\") == UltraSdkBuild.SDK_SHA256"))
    }

}
