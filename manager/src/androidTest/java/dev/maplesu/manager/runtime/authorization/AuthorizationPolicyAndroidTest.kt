package dev.maplesu.manager.runtime.authorization

import android.content.pm.PackageManager
import android.os.Process as AndroidProcess
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.TimeUnit

/** Ordinary application-UID execution only; no Binder caller authentication or MapleSU elevation. */
@RunWith(AndroidJUnit4::class)
class AuthorizationPolicyAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val uid = AndroidProcess.myUid()
    private val identities = AndroidApplicationIdentities(context)
    private lateinit var directory: File
    private lateinit var store: File

    @Before fun setup() {
        assertEquals(context.applicationInfo.uid, uid)
        assertNotEquals(0, uid)
        directory = Files.createTempDirectory(context.filesDir.toPath(), "auth-device-test-").toFile()
        store = File(directory, "policy.bin")
    }

    @After fun cleanup() {
        if (::directory.isInitialized) assertTrue(directory.deleteRecursively())
    }

    private fun newPolicy() = AuthorizationPolicy(store.toPath(), identities)

    @Suppress("DEPRECATION")
    @Test fun readsCurrentPackageManagerIdentityAndRejectsUnsupportedUids() {
        val identity = requireNotNull(identities.read(uid))
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val expectedSigners = requireNotNull(info.signingInfo).apkContentsSigners.map { certificate ->
            MessageDigest.getInstance("SHA-256").digest(certificate.toByteArray())
                .joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 255) }
        }.toSet()
        assertEquals(uid, identity.uid)
        assertEquals(context.packageName, identity.packageName)
        assertEquals(expectedSigners, identity.signers)
        assertEquals(info.firstInstallTime, identity.firstInstallTime)
        assertEquals(info.lastUpdateTime, identity.lastUpdateTime)
        assertEquals(requireNotNull(info.applicationInfo).sourceDir, identity.apkPath)
        for (other in listOf(-1, 0, 2000, 20000, 99999, uid + 100_000)) {
            assertNull("Unexpected identity for UID $other", identities.read(other))
        }
    }

    @Test fun defaultDenialThenGrantStartsRealCommandAtApplicationUid() {
        val policy = newPolicy()
        var started = false
        val denied = assertThrows(SecurityException::class.java) {
            policy.authorizeAndStart(uid) { started = true }
        }
        assertEquals("AUTH_DISABLED", denied.message)
        assertFalse(started)
        policy.grant(uid)
        policy.setEnabled(true)
        val process = policy.authorizeAndStart(uid) { identity ->
            assertEquals(uid, identity.uid)
            ProcessBuilder("/system/bin/sh", "-c", "/system/bin/id -u; exit 37")
                .redirectErrorStream(true).start()
        }
        try {
            process.outputStream.close()
            assertTrue("Ordinary command timed out", process.waitFor(10, TimeUnit.SECONDS))
            assertEquals(37, process.exitValue())
            assertEquals(uid.toString(), process.inputStream.readBytes().decodeToString().trim())
        } finally {
            process.destroyForcibly()
            process.outputStream.close()
            process.inputStream.close()
            process.errorStream.close()
        }
    }

    @Test fun persistedGrantReopensAndRevocationRefusesTaskCreation() {
        var policy = newPolicy()
        policy.grant(uid)
        policy.setEnabled(true)
        policy = newPolicy()
        assertTrue(policy.isEnabled)
        assertTrue(policy.hasCurrentGrant(uid))
        assertEquals(context.packageName, policy.authorizeAndStart(uid) { it.packageName })
        policy.revoke(uid)
        policy = newPolicy()
        assertFalse(policy.hasCurrentGrant(uid))
        var started = false
        val denied = assertThrows(SecurityException::class.java) {
            policy.authorizeAndStart(uid) { started = true }
        }
        assertEquals("AUTH_NOT_GRANTED", denied.message)
        assertFalse(started)
    }

    @Test fun grantDoesNotAuthorizeTheSeparatelyInstalledTestApkUid() {
        val otherApp = instrumentation.context.applicationInfo
        assertNotEquals(context.packageName, instrumentation.context.packageName)
        assertNotEquals(uid, otherApp.uid)
        val policy = newPolicy()
        policy.grant(uid)
        policy.setEnabled(true)
        var started = false
        val denied = assertThrows(SecurityException::class.java) {
            policy.authorizeAndStart(otherApp.uid) { started = true }
        }
        assertTrue(denied.message in setOf("AUTH_NOT_GRANTED", "AUTH_IDENTITY_UNAVAILABLE"))
        assertFalse(started)
    }
}
