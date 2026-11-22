package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import org.junit.Assert.*
import org.junit.Test

class UltraIdentityDeploymentTest {
    private val key = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(4096)
        .copySecret().toString(Charsets.US_ASCII)
    private val deployment = "a".repeat(64)
    private val trust = UltraReinstallTrust("dev.maplesu.manager", 0, setOf("b".repeat(64)))
    private val manager = ApplicationIdentity(10500, "dev.maplesu.manager", listOf("dev.maplesu.manager"),
        setOf("b".repeat(64)), 10L, 11L, "/data/app/current/base.apk")

    private fun reply(version: Int, build: () -> String? = { UltraSdkBuild.BUILD_ID },
                      installed: () -> String? = { deployment }): ByteArray {
        val request = ByteArrayOutputStream().apply { DataOutputStream(this).writeInt(version) }
        return ByteArrayOutputStream().also { output ->
            UltraIdentityHandshake.serve(trust, manager.uid, { manager },
                ByteArrayInputStream(request.toByteArray()), output, { key }, build, installed)
        }.toByteArray()
    }

    @Test fun liveDeploymentReceiptSurvivesANewManagerProcessWithoutRootMaintenance() {
        repeat(2) {
            val response = reply(3)
            assertTrue("A running broker must attest its deployed identity", response.size > 52)
            DataInputStream(ByteArrayInputStream(response)).use { input ->
                assertEquals(3, input.readInt())
                assertEquals(key, ByteArray(48).also(input::readFully).toString(Charsets.US_ASCII))
                assertEquals(UltraSdkBuild.BUILD_ID, input.readUTF())
                assertEquals(deployment, input.readUTF())
                assertEquals(-1, input.read())
            }
        }
    }

    @Test fun legacyClientsKeepTheirOriginalWireFormat() {
        for (version in listOf(1, 2)) {
            val response = reply(version, installed = { error("legacy clients need no deployment lookup") })
            DataInputStream(ByteArrayInputStream(response)).use { input ->
                assertEquals(version, input.readInt())
                assertEquals(key, ByteArray(48).also(input::readFully).toString(Charsets.US_ASCII))
                if (version == 2) assertEquals(UltraSdkBuild.BUILD_ID, input.readUTF())
                assertEquals(-1, input.read())
            }
        }
    }

    @Test fun absentOrMalformedDeploymentNeverAttestsReadiness() {
        for (value in listOf(null, "", "a".repeat(63), "A".repeat(64), "a".repeat(64) + "\n")) {
            assertEquals(value, 0, reply(3, installed = { value }).size)
        }
        assertEquals(0, reply(3, build = { null }).size)
    }

    @Test fun unsupportedVersionDoesNotReadDeployment() {
        assertEquals(0, reply(4, build = { error("unsupported") }, installed = { error("unsupported") }).size)
    }

    @Test fun unrelatedPackageGetsNoCredentialOrDeploymentReceipt() {
        val input = ByteArrayOutputStream().apply { DataOutputStream(this).writeInt(3) }
        val output = ByteArrayOutputStream()
        UltraIdentityHandshake.serve(trust, 10500, { null }, ByteArrayInputStream(input.toByteArray()), output,
            { error("untrusted key read") }, { error("untrusted build read") }, { error("untrusted deployment read") })
        assertEquals(0, output.size())
    }

    private fun source(file: String): String {
        val relative = "src/main/java/dev/maplesu/manager/runtime/ultra/$file"
        return listOf(File(relative), File("manager/$relative")).first { it.isFile }.readText()
    }

    @Test fun productionReuseRequiresLiveDeploymentInsteadOfAProcessLocalFlag() {
        val recovery = source("UltraIdentityRecovery.kt")
        assertFalse(recovery.contains("preparedFor"))
        assertTrue(recovery.contains("UltraIdentityBrokerDeployment.ensure(force"))
        val policy = source("UltraIdentityBrokerDeployment.kt")
        assertTrue(policy.contains("if (!force && running.matches) return complete()"))
        assertTrue(policy.substringAfter("fun complete(): String {").substringBefore("val running =")
            .contains("if (!eligible()) return \"IDENTITY_SUSPENDED\""))
        val reuse = recovery.substringAfter("val running = observed.identity").substringBefore("override fun prepare()")
        assertTrue(reuse.contains("running?.key == key"))
        assertTrue(reuse.contains("running.buildId == UltraSdkBuild.BUILD_ID"))
        assertTrue(reuse.contains("running.deploymentId == fingerprint"))
        assertTrue(policy.contains("if (current.matches) return complete()"))
    }

    @Test fun brokerAttestsTheConfigItStartedWithNotAReplacementConfig() {
        val broker = source("UltraIdentityBroker.kt")
        assertTrue(broker.contains("val deployment = config.optString(\"deploymentId\")"))
        assertTrue(broker.contains("reply(it, user, deployment)"))
        assertTrue(broker.contains("deploymentIdentity = { deployment }"))
    }
}
