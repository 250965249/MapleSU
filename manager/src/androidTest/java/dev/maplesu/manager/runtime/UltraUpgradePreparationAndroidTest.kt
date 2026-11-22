package dev.maplesu.manager.runtime

import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentInstaller
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Exercises the real upgrade preparation without submitting a Boot installation. */
class UltraUpgradePreparationAndroidTest {
    @Test fun runningEnvironmentPreparesTheCurrentBrokerBeforeUpgradeSubmission() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyUpgradePreparation") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assertEquals(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.refresh(context))

        val prepared = UltraEnvironmentInstaller.backupKey(context, forceIdentity = true, preparingUpgrade = true)
        assertNotNull("Upgrade preparation returned no receipt", prepared)
        val identityStatus = prepared?.reason?.substringAfterLast(';')
        instrumentation.sendStatus(2, Bundle().apply {
            putString("upgradePreparationOk", prepared?.ok.toString())
            putString("upgradeIdentityStatus", identityStatus)
        })
        assertTrue("Upgrade preparation did not complete: $identityStatus", prepared?.ok == true)
        assertTrue(identityStatus == "IDENTITY_READY" || identityStatus == "IDENTITY_UPGRADE_PREPARED")
    }
}
