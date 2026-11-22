package dev.maplesu.manager.runtime.authorization

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.ultra.UltraAuthorization
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Runs against the real Ultra SDK; preserves the device's existing grants. */
class UltraShellAuthorizationAndroidTest {
    private fun context() = InstrumentationRegistry.getInstrumentation().targetContext.also {
        assumeTrue("Requires a running Ultra environment", UltraEnvironmentProbe.refresh(it) == UltraEnvironmentProbe.State.Running)
        assertTrue(UltraAuthorization.refresh(it))
    }

    @Test fun shellAndSharedSystemUidProfilesAreReadable() {
        val context = context()
        for (name in listOf("com.android.shell", "android")) {
            val uid = context.packageManager.getApplicationInfo(name, 0).uid
            val profile = ManagerAuthorizations.profile(context, name, uid)
            assertNotNull("Profile unavailable for $name uid=$uid", profile)
            assertEquals(name, profile!!.name)
            assertEquals(uid, profile.currentUid)
            assertEquals(UltraAuthorization.isGranted(name), profile.allowSu)
        }
    }

    @Test fun mismatchedAndMissingPackagesNeverProduceProfilesOrWriteGrants() {
        val context = context()
        val uid = context.packageManager.getApplicationInfo("com.android.shell", 0).uid
        assertNull(ManagerAuthorizations.profile(context, "com.android.shell", uid + 1))
        assertNull(ManagerAuthorizations.profile(context, "dev.maplesu.missing.shell.fixture", uid))
        val bad = com.maplesu.core.Natives.Profile("com.android.shell", currentUid = uid + 1, allowSu = true)
        assertFalse(ManagerAuthorizations.saveProfile(context, bad))
    }

    @Test fun shellGrantAndRevokeRoundTripThroughTheRealProfileEntryPoints() {
        val context = context()
        val uid = context.packageManager.getApplicationInfo("com.android.shell", 0).uid
        val before = ManagerAuthorizations.profile(context, "com.android.shell", uid)
        assertNotNull("Shell profile must load before a write", before)
        val original = before!!
        try {
            assertTrue(ManagerAuthorizations.saveProfile(context, original.copy(allowSu = true)))
            assertTrue(ManagerAuthorizations.profile(context, original.name, uid)!!.allowSu)
            assertTrue(ManagerAuthorizations.saveProfile(context, original.copy(allowSu = false)))
            assertFalse(ManagerAuthorizations.profile(context, original.name, uid)!!.allowSu)
        } finally {
            assertTrue("Restore the original Shell grant", ManagerAuthorizations.saveProfile(context, original))
        }
    }
}
