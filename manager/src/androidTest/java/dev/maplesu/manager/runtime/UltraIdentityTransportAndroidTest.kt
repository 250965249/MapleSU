package dev.maplesu.manager.runtime

import android.os.Process
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.installer.InstallerServiceClient
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import dev.maplesu.manager.runtime.ultra.UltraSdkBuild
import org.junit.Assert.*
import org.junit.Test

/** Uses the real caller-verified root Binder and live broker; credentials never enter test output. */
class UltraIdentityTransportAndroidTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun rootTransportAttestsTheDeployedBrokerWithoutAnAppSocketConnection() {
        val key = requireNotNull(UltraRootKeyStore.read(context))
        val observed = InstallerServiceClient.withService(context, persistent = true) { it.readUltraIdentity(true) }
        assertEquals(0, observed.getInt("serviceUid", -1))
        assertEquals(Process.myUid(), observed.getInt("callerUid", -1))
        assertTrue(observed.getInt("brokerPid", -1) > 1)
        assertTrue("Broker credential mismatch", key == observed.getString("key"))
        assertEquals(UltraSdkBuild.BUILD_ID, observed.getString("buildId"))
        assertTrue(observed.getString("deploymentId").orEmpty().matches(Regex("[0-9a-f]{64}")))
    }

    @Test fun restoringCurrentUidMappingsPreservesExactlyTheSavedPackageGrants() {
        val key = requireNotNull(UltraRootKeyStore.read(context))
        val client = UltraRuntimeClient { key }
        val before = client.suAuthSnapshot()
        assertTrue(before.ok)
        val result = InstallerServiceClient.withService(context, persistent = true) { it.refreshUltraAuthorization(key) }
        assertEquals("OK", result)
        val after = client.suAuthSnapshot()
        assertTrue(after.ok)
        assertEquals(before.packages.toSet(), after.packages.toSet())
    }
}
