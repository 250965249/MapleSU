package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraFreshKernelRepairTest {
    private val fresh = observed("Unknown", "ERR_MAPLESU_ENV_UNPREPARED", -19916)

    private fun observed(state: String, error: String, code: Int): UltraEnvFacts {
        val installed = receipt("get_installed_maplesu_environment_version", error, code)
        val bundled = receipt("get_sdk_version", "OK", 0, "5.2.1")
        return UltraEnvironmentUpgrade.versionFacts(state, installed, bundled, kernelRootVerified = true).copy(
            bundledAppVersion = "5.2.1", bundledHelperSha256 = "a".repeat(64))
    }

    private fun receipt(operation: String, error: String, code: Int, version: String? = null): NativeReceipt {
        val data = if (version == null) "{}" else """{"version":"$version"}"""
        return checkNotNull(NativeReceipt.parse("""{"schemaVersion":1,"backend":"maplesu_ultra","bridgeVersion":1,"operation":"$operation","ok":${code == 0},"sdkError":"$error","sdkErrorCode":$code,"data":$data}"""))
    }

    @Test fun aLiveKernelCanInstallItsFirstHelper() {
        for (state in listOf("Unknown", "NotInstalled")) {
            val facts = observed(state, "ERR_MAPLESU_ENV_UNPREPARED", -19916)
            assertFalse(facts.readUnknown)
            assertTrue(UltraEnvironmentUpgrade.faultRepairAllowed(state, facts, kernelRootVerified = true))
            assertFalse(UltraEnvironmentUpgrade.faultRepairAllowed(state, facts))
        }
        assertFalse(UltraEnvironmentUpgrade.faultRepairAllowed("Fault", fresh))
        assertFalse(UltraEnvironmentUpgrade.faultRepairAllowed("Unknown",
            fresh.copy(freshKernelInstall = false), kernelRootVerified = true))
        assertFalse(UltraEnvironmentUpgrade.faultRepairAllowed("NotInstalled",
            fresh.copy(installedVersion = "5.2.1"), kernelRootVerified = true))
    }

    @Test fun versionReadFailuresAndPartialInstallationsAreNotFreshAbsence() {
        for ((error, code) in listOf("MAPLESU_BRIDGE_EXCEPTION" to -1001,
            "ERR_MODULE_READ_FILE" to -19932, "ERR_MODULE_FILE_NOT_EXIST" to -19936,
            "ERR_READ_CHILD_STRING" to -19913, "ERR_MAPLESU_ENV_UNPREPARED" to -1001)) {
            val facts = observed("Unknown", error, code)
            assertTrue("error=$error code=$code", facts.readUnknown)
            assertFalse(UltraEnvironmentUpgrade.faultRepairAllowed("Unknown", facts, kernelRootVerified = true))
        }
    }
    @Test fun aLiveKernelKeepsPendingAndUnreadableFactsBlocked() {
        for (facts in listOf(fresh.copy(readUnknown = true), fresh.copy(running = true),
            fresh.copy(submittedThisBoot = true), fresh.copy(suspended = true), fresh.copy(quiescing = true),
            fresh.copy(bundledHelperSha256 = "invalid"), fresh.copy(installedVersion = "broken"))) {
            assertFalse(UltraEnvironmentUpgrade.faultRepairAllowed("Unknown", facts, kernelRootVerified = true))
        }
    }
    @Test fun kernelProofDoesNotPermitDowngradesOrEraseKnownHelperIdentity() {
        for (facts in listOf(fresh.copy(installedVersion = "5.2.2"),
            fresh.copy(installedAppVersion = "5.2.2"), fresh.copy(installedHelperSha256 = "b".repeat(64)))) {
            assertFalse(UltraEnvironmentUpgrade.faultRepairAllowed("Unknown", facts, kernelRootVerified = true))
        }
    }
}
