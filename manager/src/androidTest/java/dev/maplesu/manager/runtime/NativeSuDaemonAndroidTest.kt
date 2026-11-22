package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.system.Os
import android.system.OsConstants
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.io.IOException

/** Separate prepare/revoke/restore steps let the host stop the target APK between requests. */
class NativeSuDaemonAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val saved get() = File(context.noBackupFilesDir, "su-lifecycle-test-state")
    private val peerUid get() = context.packageManager.getApplicationInfo(instrumentation.context.packageName, 0).uid

    private fun requireOptIn() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
    }

    @Test fun absentSocketStartsDaemonButAccessDenialDoesNot() {
        LocalSocket().use { socket ->
            val failure = runCatching {
                socket.connect(LocalSocketAddress("maplesu-missing-${java.util.UUID.randomUUID()}",
                    LocalSocketAddress.Namespace.ABSTRACT))
            }.exceptionOrNull()
            assertTrue(failure is IOException && NativeSuDaemon.endpointMissing(failure))
        }
        assertFalse(NativeSuDaemon.endpointMissing(IOException(Os.strerror(OsConstants.EACCES))))
        assertFalse(NativeSuDaemon.endpointMissing(IOException(Os.strerror(OsConstants.EPERM))))
    }

    @Test fun socketPolicyValidatesWithoutCommit() {
        requireOptIn()
        val checked = NativeSuDaemonPolicy.check(context)
        instrumentation.sendStatus(2, android.os.Bundle().apply { putString("socketPolicyCheck", checked) })
    }

    @Test fun prepareExternalLifecycleFixture() {
        requireOptIn()
        val policy = ManagerAuthorizations.policy(context)
        check(!saved.exists()) { "Restore the previous lifecycle fixture first" }
        saved.writeText("${policy.isEnabled}\n${policy.hasCurrentGrant(peerUid)}\n")
        policy.setEnabled(true)
        policy.grant(peerUid)
        RuntimeDeployment.deploy(context)
        NativeSuDaemon.ensure(context)
        assertTrue(policy.hasCurrentGrant(peerUid))
    }

    @Test fun revokeExternalLifecycleFixture() {
        requireOptIn()
        check(saved.isFile)
        ManagerAuthorizations.policy(context).revoke(peerUid)
    }

    @Test fun restoreExternalLifecycleFixture() {
        requireOptIn()
        val before = saved.readLines()
        check(before.size == 2)
        val policy = ManagerAuthorizations.policy(context)
        if (before[1].toBooleanStrict()) policy.grant(peerUid) else policy.revoke(peerUid)
        policy.setEnabled(before[0].toBooleanStrict())
        check(saved.delete())
    }
}
