package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.File
import java.io.IOException

class UltraModuleStagedArchiveRollbackTest {

    @Test
    fun discardsOnlyTheCurrentTokenBeforeCallingHost() {
        assertRollback(cleanupFailure = null)
    }

    @Test
    fun keepsTheReadFailureAndAttachesTheCleanupFailure() {
        assertRollback(cleanupFailure = IOException("staged archive cleanup failed"))
    }

    private fun assertRollback(cleanupFailure: IOException?) {
        val calls = mutableListOf<String>()
        val token = "0123456789abcdef0123456789abcdef"
        val readFailure = IOException("staged archive unreadable")
        val receipt = NativeReceipt(
            schemaVersion = 1,
            backend = UltraRuntimeClient.BACKEND,
            bridgeVersion = 1,
            operation = "get_maplesu_environment_state",
            ok = true,
            sdkError = "OK",
            sdkErrorCode = 0,
            reason = null,
            data = null,
            raw = "{}",
        )
        val host = object : UltraModuleHost {
            override fun environmentState() = error("Unexpected host environment call")
            override fun parseModuleDescriptor(zipPath: String) = error("Unexpected host descriptor call")
            override fun installModule(zipPath: String, devRunOnce: Boolean) = error("Unexpected host install call")
            override fun uninstallModule(id32: String) = error("Unexpected host uninstall call")
            override fun modules() = error("Unexpected host module-list call")
            override fun openModuleWebUI(id32: String) = error("Unexpected host WebUI call")
        }
        val transaction = UltraModuleInstallTransaction(
            host = host,
            environmentProbe = { UltraModuleEnvironmentObservation(receipt, "Running") },
            catalog = object : UltraModuleCatalogPort {
                override fun stage(source: File, confirmedArchiveSha256: String): String {
                    calls.add("stage")
                    return token
                }

                override fun stagedArchive(token: String): File {
                    calls.add("stagedArchive:$token")
                    throw readFailure
                }

                override fun commit(token: String) = error("Unexpected catalog commit")

                override fun discard(token: String) {
                    calls.add("discard:$token")
                    cleanupFailure?.let { throw it }
                }
            },
            journal = { _, _, _ -> error("Unexpected journal write") },
            evidence = { UltraModuleEvidenceRecordResult.Dropped("fixture") },
            facts = { UltraModuleDeviceFacts.of() },
            clockMillis = { 1_700_000_000_123L },
            buildDigest = { UltraModuleBuildDigest.of("9f".repeat(32)) },
            bootId = { "1f2e3d4c-5b6a-4978-8c9d-0e1f2a3b4c5d" },
            processPid = { 4242 },
            receiptData = { error("Unexpected receipt data") },
        )
        val request = UltraModuleInstallRequest(
            source = File("source.zip"),
            identity = UltraModulePackageIdentity(token, "1.0", "ed".repeat(32)),
            manifestVersion = "1.0",
            devRunOnce = false,
            action = UltraModuleAction.INSTALL,
        )

        val actual = assertThrows(IOException::class.java) { transaction.install(request, {}, {}) }

        assertSame(readFailure, actual)
        assertEquals(listOfNotNull(cleanupFailure), actual.suppressed.toList())
        assertEquals(listOf("stage", "stagedArchive:$token", "discard:$token"), calls)
    }
}
