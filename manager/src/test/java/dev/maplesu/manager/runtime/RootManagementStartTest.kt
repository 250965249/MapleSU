package dev.maplesu.manager.runtime

import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class RootManagementStartTest {

    @Test fun ultraHookStartsStreamingRootTasksWithoutLegacyCredentials() {
        for (mode in listOf(WorkMode.LITE, null)) {
            val process = RootManagement.startRouted(
                mode = mode, usesSdk = false, usesHook = true,
                openSdk = { error("Unexpected SDK launch") },
                openCredential = { error("MANAGEMENT_CREDENTIAL_UNAVAILABLE") },
                openHook = { FinishedProcess(0, "0\n") },
            )
            assertEquals(0, process.waitFor())
            assertEquals("0\n", process.inputStream.bufferedReader().readText())
        }
    }

    @Test fun hookStartFailureIsNotRetriedWithLegacyCredentials() {
        val expected = IllegalStateException("MANAGEMENT_HOOK_LAUNCH_FAILED")
        val actual = assertThrows(IllegalStateException::class.java) {
            RootManagement.startRouted(
                mode = WorkMode.LITE, usesSdk = false, usesHook = true,
                openSdk = { error("Unexpected SDK launch") },
                openCredential = { error("MANAGEMENT_CREDENTIAL_UNAVAILABLE") },
                openHook = { throw expected },
            )
        }
        assertSame(expected, actual)
    }
    @Test fun ultraCustomizeStartsThroughSdkInsteadOfExiting69() {
        for (mode in listOf(WorkMode.LITE, null)) {
            var legacyCalls = 0
            val process = RootManagement.startRouted(
                mode = mode,
                usesSdk = true,
                openSdk = { FinishedProcess(0, "CUSTOMIZE_ENTERED\n") },
                openCredential = {
                    legacyCalls++
                    FinishedProcess(69, "", "MapleSU credential was not accepted")
                },
            )
            assertEquals("mode=$mode must use the paired Pro SDK", 0, process.waitFor())
            assertEquals("CUSTOMIZE_ENTERED\n", process.inputStream.bufferedReader().readText())
            assertEquals(0, legacyCalls)
        }
    }

    @Test fun sdkLaunchFailureIsNotReplayedThroughLegacyCredentials() {
        val expected = IllegalStateException("MANAGEMENT_SDK_LAUNCH_FAILED")
        val actual = assertThrows(IllegalStateException::class.java) {
            RootManagement.startRouted(
                mode = WorkMode.LITE,
                usesSdk = true,
                openSdk = { throw expected },
                openCredential = { FinishedProcess(0) },
            )
        }
        assertSame(expected, actual)
    }

    @Test fun unpairedEnvironmentsKeepTheirCredentialTransport() {
        for ((mode, usesSdk) in listOf(WorkMode.LITE to false, null to false)) {
            val credential = FinishedProcess(0)
            assertSame(credential, RootManagement.startRouted(
                mode = mode,
                usesSdk = usesSdk,
                openSdk = { throw AssertionError("Unexpected SDK launch: $mode/$usesSdk") },
                openCredential = { credential },
            ))
        }
    }

    @Test fun normalStartsThroughKsuWithoutLegacyCredentialsOrSdk() {
        for (usesSdk in listOf(true, false)) {
            val ksu = FinishedProcess(37, "normal output", "normal error")
            val process = RootManagement.startRouted(
                mode = WorkMode.KSU, usesSdk = usesSdk, usesHook = true,
                openSdk = { error("Unexpected SDK launch") },
                openCredential = { error("MANAGEMENT_CREDENTIAL_UNAVAILABLE") },
                openKsu = { ksu },
                openHook = { error("Unexpected Hook launch") },
            )
            assertSame(ksu, process)
            assertEquals(37, process.waitFor())
            assertEquals("normal output", process.inputStream.bufferedReader().readText())
            assertEquals("normal error", process.errorStream.bufferedReader().readText())
        }
    }

    @Test fun normalLaunchFailureIsNotReplayedThroughAnotherBackend() {
        val expected = IllegalStateException("MANAGEMENT_KSU_LAUNCH_FAILED")
        val actual = assertThrows(IllegalStateException::class.java) {
            RootManagement.startRouted(
                mode = WorkMode.KSU, usesSdk = true, usesHook = true,
                openKsu = { throw expected },
                openSdk = { error("Unexpected SDK retry") },
                openCredential = { error("Unexpected credential retry") },
                openHook = { error("Unexpected Hook retry") },
            )
        }
        assertSame(expected, actual)
    }

    @Test fun moduleExitCodeIsPreservedWithoutRunningItTwice() {
        var sdkCalls = 0
        val process = RootManagement.startRouted(
            mode = WorkMode.LITE,
            usesSdk = true,
            openSdk = { sdkCalls++; FinishedProcess(69, "CUSTOMIZE_ENTERED\n", "module error") },
            openCredential = { throw AssertionError("A module exit code is not a launch failure") },
        )
        assertEquals(69, process.waitFor())
        assertEquals("module error", process.errorStream.bufferedReader().readText())
        assertEquals(1, sdkCalls)
    }

    private class FinishedProcess(private val status: Int, out: String = "", err: String = "") : Process() {
        private val input = ByteArrayInputStream(out.toByteArray())
        private val error = ByteArrayInputStream(err.toByteArray())
        private val output = ByteArrayOutputStream()
        override fun getInputStream() = input
        override fun getErrorStream() = error
        override fun getOutputStream() = output
        override fun waitFor() = status
        override fun exitValue() = status
        override fun destroy() = Unit
    }
}
