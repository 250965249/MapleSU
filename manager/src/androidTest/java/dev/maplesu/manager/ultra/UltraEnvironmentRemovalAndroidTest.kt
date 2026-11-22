package dev.maplesu.manager.ultra

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.modules.UltraRootKeyStore
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Exercises real manager preferences without uninstalling the device environment. */
class UltraEnvironmentRemovalAndroidTest {
    @Test fun removalKeepsTemporaryCredentialsAndRepairsLegacySuspension() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("environmentRemovalDevice") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val prefs = context.getSharedPreferences("maplesu-ultra", 0)
        val keys = listOf("rootKey", "rootKeySuspended", "environmentRemoval")
        val before = keys.associateWith { prefs.getString(it, null) }
        val fixtureKey = "a".repeat(48)
        try {
            assertTrue(prefs.edit().remove("rootKey").remove("environmentRemoval")
                .putString("rootKeySuspended", fixtureKey).commit())
            assertEquals(fixtureKey, UltraRootKeyStore.read(context))
            assertFalse(prefs.contains("rootKeySuspended"))
            UltraRootKeyStore.recordRemoval(context, permanent = false)
            assertEquals(fixtureKey, UltraRootKeyStore.read(context))
            assertTrue(UltraRootKeyStore.isSuspended(context))
            UltraRootKeyStore.allowEnvironmentInstall(context)
            assertFalse(UltraRootKeyStore.isSuspended(context))
            assertEquals(fixtureKey, UltraRootKeyStore.read(context))
            UltraRootKeyStore.recordRemoval(context, permanent = true)
            assertNull(UltraRootKeyStore.read(context))
            assertTrue(UltraRootKeyStore.isSuspended(context))
            assertEquals(fixtureKey, prefs.getString("rootKey", null))
        } finally {
            assertTrue(prefs.edit().apply { before.forEach { (key, value) ->
                if (value == null) remove(key) else putString(key, value)
            } }.commit())
        }
    }
}
