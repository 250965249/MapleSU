// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime

import com.topjohnwu.superuser.Shell
import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.TimeUnit

/**
 * Routing guarantees of [RootManagement.openShell] (host-testable seam, no Android calls).
 *
 * Normal (KSU) mode must try the registered Mode B channel first and only fall back to the
 * pre-existing credential transport. Paired SDK environments must use the SDK shell.
 */
class RootManagementRoutingTest {

    @Test fun ultraHookOpensManagementShellWithoutLegacyCredentials() {
        for (mode in listOf(WorkMode.LITE, null)) {
            val hook = FakeShell()
            assertSame(hook, RootManagement.openShellRouted(
                mode = mode, usesSdk = false, usesHook = true,
                openSdk = { error("Unexpected SDK launch") },
                openKsu = { error("Unexpected KSU launch") },
                openCredential = { error("MANAGEMENT_CREDENTIAL_UNAVAILABLE") },
                openHook = { hook },
            ))
        }
    }

    @Test fun hookShellFailureIsNotReplayedThroughAnotherRootSource() {
        val expected = IllegalStateException("SU_GATE_NOT_ARMED")
        val actual = assertThrows(IllegalStateException::class.java) {
            RootManagement.openShellRouted(
                mode = WorkMode.LITE, usesSdk = false, usesHook = true,
                openSdk = { error("Unexpected SDK launch") },
                openKsu = { error("Unexpected KSU launch") },
                openCredential = { error("MANAGEMENT_CREDENTIAL_UNAVAILABLE") },
                openHook = { throw expected },
            )
        }
        assertSame(expected, actual)
    }

    @Test fun pairedSdkAndNormalKeepTheirOwnIdentityWhenHookIsPresent() {
        for (mode in listOf(WorkMode.LITE, WorkMode.KSU, null)) {
            val expected = FakeShell()
            assertSame(expected, RootManagement.openShellRouted(
                mode = mode, usesSdk = true, usesHook = true,
                openSdk = { expected }, openKsu = { expected },
                openCredential = { error("Unexpected credential launch") },
                openHook = { error("Unexpected Hook launch") },
            ))
        }
    }

    @Test
    fun pairedSdkUsesItsOwnShellEvenBeforeModeActivation() {
        for (mode in listOf(WorkMode.LITE, null)) {
            val sdk = FakeShell()
            assertSame(sdk, RootManagement.openShellRouted(
                mode = mode,
                usesSdk = true,
                openSdk = { sdk },
                openKsu = { throw AssertionError("Unexpected KSU launch") },
                openCredential = { throw AssertionError("SDK is not a legacy credential") },
            ))
        }
    }

    @Test
    fun sdkFailurePropagatesWithoutReplayingThroughAnotherBackend() {
        val expected = IllegalStateException("MANAGEMENT_SDK_LAUNCH_FAILED")
        val observed = assertThrows(IllegalStateException::class.java) {
            RootManagement.openShellRouted(
                mode = WorkMode.LITE,
                usesSdk = true,
                openSdk = { throw expected },
                openKsu = { throw AssertionError("Unexpected KSU launch") },
                openCredential = { throw AssertionError("Unexpected legacy launch") },
            )
        }
        assertSame(expected, observed)
    }

    @Test
    fun ksuModeUsesKsuChannelFirst() {
        val ksu = FakeShell()
        val credential = FakeShell()
        val order = mutableListOf<String>()
        val opened = RootManagement.openShellRouted(
            mode = WorkMode.KSU,
            usesSdk = true,
            openSdk = { throw AssertionError("KSU must keep its own channel") },
            openKsu = { order += "ksu"; ksu },
            openCredential = { order += "credential"; credential },
        )
        assertSame(ksu, opened)
        assertEquals(listOf("ksu"), order)
    }

    @Test
    fun ksuFailureFallsBackToCredentialTransport() {
        val credential = FakeShell()
        val order = mutableListOf<String>()
        val opened = RootManagement.openShellRouted(
            mode = WorkMode.KSU,
            usesSdk = true,
            openSdk = { throw AssertionError("KSU must keep its own channel") },
            openKsu = {
                order += "ksu"
                throw IllegalStateException("KSU_ROOT_CHANNEL_UNAVAILABLE:SHELL_NOT_ROOT")
            },
            openCredential = { order += "credential"; credential },
        )
        assertSame(credential, opened)
        assertEquals(listOf("ksu", "credential"), order)
    }

    @Test
    fun bothFailKeepsCredentialErrorAndAttachesKsuFailure() {
        val failure = assertThrows(IllegalStateException::class.java) {
            RootManagement.openShellRouted(
                mode = WorkMode.KSU,
                usesSdk = true,
                openSdk = { throw AssertionError("KSU must keep its own channel") },
                openKsu = {
                    throw IllegalStateException("KSU_ROOT_CHANNEL_UNAVAILABLE:LAUNCH_FAILED:IOException")
                },
                openCredential = { throw IllegalStateException("MANAGEMENT_CREDENTIAL_UNAVAILABLE") },
            )
        }
        // Fail-closed: the original error stays the primary failure; KSU is evidence only.
        assertEquals("MANAGEMENT_CREDENTIAL_UNAVAILABLE", failure.message)
        assertEquals(1, failure.suppressed.size)
        assertTrue(
            failure.suppressed[0].message.orEmpty().startsWith("KSU_ROOT_CHANNEL_UNAVAILABLE:"),
        )
    }

    @Test
    fun nonKsuModesNeverTouchTheKsuChannel() {
        for (mode in listOf(WorkMode.LITE, null)) {
            var ksuCalls = 0
            val credential = FakeShell()
            val opened = RootManagement.openShellRouted(
                mode = mode,
                usesSdk = false,
                openSdk = { throw AssertionError("SDK must require verified pairing") },
                openKsu = {
                    ksuCalls++
                    throw AssertionError("KSU channel must not be used outside KSU")
                },
                openCredential = { credential },
            )
            assertSame(credential, opened)
            assertEquals("mode=$mode must not call the KSU channel", 0, ksuCalls)
        }
    }

    @Test
    fun nonKsuKeepsTheOriginalErrorVerbatim() {
        val failure = assertThrows(IllegalStateException::class.java) {
            RootManagement.openShellRouted(
                mode = WorkMode.LITE,
                usesSdk = false,
                openSdk = { throw AssertionError("SDK must require verified pairing") },
                openKsu = { throw AssertionError("KSU channel must not be used outside KSU") },
                openCredential = { throw IllegalStateException("MANAGEMENT_CREDENTIAL_UNAVAILABLE") },
            )
        }
        assertEquals("MANAGEMENT_CREDENTIAL_UNAVAILABLE", failure.message)
        assertEquals(0, failure.suppressed.size)
    }
}

/** Minimal libsu shell double: enough to be a distinct `Shell` instance in routing tests. */
private class FakeShell : Shell() {
    override fun isAlive(): Boolean = true

    override fun execTask(task: Shell.Task) = throw UnsupportedOperationException("execTask")

    override fun submitTask(task: Shell.Task) = throw UnsupportedOperationException("submitTask")

    override fun newJob(): Shell.Job = throw UnsupportedOperationException("newJob")

    override fun getStatus(): Int = Shell.ROOT_SHELL

    override fun waitAndClose(timeout: Long, unit: TimeUnit): Boolean = false

    override fun close() = Unit
}

