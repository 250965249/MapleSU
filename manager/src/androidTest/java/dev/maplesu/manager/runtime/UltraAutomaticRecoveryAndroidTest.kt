package dev.maplesu.manager.runtime

import android.os.Bundle
import android.os.Process
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.ultra.UltraIdentityRecovery
import dev.maplesu.manager.runtime.ultra.UltraKeyPairedStore
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** The host reinstalls the signed Manager with empty data before selecting this test. */
class UltraAutomaticRecoveryAndroidTest {
    @Test fun startupRestoresTheRunningUltraIdentityWithoutManualPairing() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyUltraRecovery") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val deadline = SystemClock.elapsedRealtime() + 45_000L
        fun ready(): Boolean = ModeRuntime.active == WorkMode.LITE &&
            UltraRootKeyStore.read(context)?.let { UltraKeyPairedStore.matchesVerifiedKey(context, it) } == true
        while (!ready() && SystemClock.elapsedRealtime() < deadline) Thread.sleep(250L)

        val key = requireNotNull(UltraRootKeyStore.read(context)) { "Startup did not recover a local identity" }
        assertTrue("Recovered identity format", UltraKernelCredential.isValid(key))
        assertTrue("Recovered SDK metadata", UltraKernelCredential.of(key).sdkMetadataValid)
        assertTrue("Startup did not verify pairing", UltraKeyPairedStore.matchesVerifiedKey(context, key))
        assertEquals(WorkMode.LITE, ModeRuntime.active)
        val client = UltraRuntimeClient { key }
        assertEquals(0, UltraIdentityRecovery.uid(client))
        assertEquals(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.refresh(context))
        instrumentation.sendStatus(2, Bundle().apply {
            putString("automaticRecoveryUid", Process.myUid().toString())
            putString("automaticRecoveryMode", ModeRuntime.active?.name)
            putString("automaticRecoveryRootUid", "0")
            putString("automaticRecoveryPaired", "true")
        })
    }
}
