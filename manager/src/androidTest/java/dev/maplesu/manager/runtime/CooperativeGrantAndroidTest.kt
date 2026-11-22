package dev.maplesu.manager.runtime

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters

/**
 * Manager-side half of the cooperative-entry acceptance.
 *
 * The consumer app runs under its own Linux uid, so it cannot grant itself, cannot
 * prepare the Root executor, and cannot read the authorization store. Everything it
 * needs has to be set up from the Manager's own uid through the real management
 * Binder - which is what these steps do, and why they are separate instrumented
 * invocations that the run order depends on:
 *
 * ```
 * a_prepareExecutor      executor published, consumer still unauthorized
 * b_revokeConsumerUid    consumer definitively unauthorized
 *   -> run :maplesu-consumer with -e expectGranted false
 * c_grantConsumerUid     real grant recorded for the consumer uid
 *   -> run :maplesu-consumer with -e expectGranted true
 * d_modeSwitchIsQueryable
 * ```
 *
 * Nothing here bypasses the single authorization owner: every step calls the same
 * `IRootManagementService` a UI action would call.
 */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class CooperativeGrantAndroidTest {
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun consumerUid(): Int = try {
        context.packageManager.getPackageUid(CONSUMER_PACKAGE, 0)
    } catch (_: PackageManager.NameNotFoundException) {
        fail("$CONSUMER_PACKAGE is not installed; install the :maplesu-consumer app first")
        error("unreachable")
    }

    /**
     * Runs the same "prepare" the Manager itself runs. This is a Manager-uid-only
     * provider method, so the instrumentation (same uid as the Manager) is the only
     * caller that can reach it.
     */
    private fun prepare(): IRootManagementService {
        val result = context.contentResolver.call(
            Uri.parse("content://${NativeSuDirectoryProvider.AUTHORITY}"), "prepare", null, null)
        val binder = result?.getBinder("manager")
            ?: error("SU_EXECUTOR_UNAVAILABLE: the trusted Root transport did not answer")
        return IRootManagementService.Stub.asInterface(binder)
    }

    @Test
    fun a_prepareExecutor() {
        val service = prepare()
        val status = service.status()
        assertEquals("executor must be real UID 0", 0, status.getInt("rootUid", -1))
        assertEquals("executor must belong to this installation",
            context.applicationInfo.uid, status.getInt("managerUid", -1))
        assertEquals("protocol", 1, status.getInt("protocol"))
        println("MAPLESU_EXECUTOR: rootPid=${status.getInt("rootPid", -1)} " +
            "activeSessions=${status.getInt("activeSessions", -1)}")
    }

    @Test
    fun b_revokeConsumerUid() {
        val service = prepare()
        val uid = consumerUid()
        service.revoke(uid)
        assertFalse("consumer must not be granted before the negative run", service.hasGrant(uid))
        println("MAPLESU_CONSUMER_UID: $uid granted=false")
    }

    @Test
    fun c_grantConsumerUid() {
        val service = prepare()
        val uid = consumerUid()
        service.grant(uid)
        assertTrue("the single authorization owner must record the grant", service.hasGrant(uid))
        println("MAPLESU_CONSUMER_UID: $uid granted=true")
    }

    @Test
    fun d_modeSwitchIsQueryable() {
        val original = SuEntryMode.read(context)
        try {
            SuEntryMode.write(context, SuEntryMode.Mode.COOPERATIVE_MINIMAL)
            val minimal = SuEntryMode.describe(context)
            assertEquals("cooperative", minimal.getString("mode"))
            assertFalse("minimal mode must not enable the publisher", minimal.getBoolean("publisherEnabled"))

            SuEntryMode.write(context, SuEntryMode.Mode.TRADITIONAL_COMPAT)
            val traditional = SuEntryMode.describe(context)
            assertEquals("traditional", traditional.getString("mode"))
            assertTrue("traditional mode keeps the publisher", traditional.getBoolean("publisherEnabled"))
        } finally {
            // Never leave the device in a mode the operator did not choose.
            SuEntryMode.write(context, original)
            assertEquals("mode must be restored", original, SuEntryMode.read(context))
        }
    }

    /**
     * Binds the installed bytes to the build output.
     *
     * A concurrent session shares this working tree and its build directory, so a
     * file hash taken on the host can describe a build that was never installed.
     * Reading the digest of this process's own `sourceDir` produces the identity of
     * the bytes that are actually running, which is what a review needs.
     */
    @Test
    fun e_installedApkIdentity() {
        val apk = java.io.File(context.applicationInfo.sourceDir)
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        apk.inputStream().use { stream ->
            val buffer = ByteArray(1 shl 16)
            while (true) {
                val read = stream.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        val sha256 = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        println("MAPLESU_EVIDENCE installedApk sha256=$sha256 bytes=${apk.length()} " +
            "versionCode=${info.longVersionCode} path=${apk.absolutePath}")
        assertTrue("installed APK must not be empty", apk.length() > 0)
    }

    private companion object {
        const val CONSUMER_PACKAGE = "dev.maplesu.consumer"
    }
}
