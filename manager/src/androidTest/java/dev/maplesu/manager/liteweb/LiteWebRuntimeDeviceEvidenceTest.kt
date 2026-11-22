package dev.maplesu.manager.liteweb

import android.os.Bundle
import android.provider.Settings
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.litehidden.RecoveryIdentity
import dev.maplesu.manager.litehidden.RecoveryIdentityScripts
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.runtime.ultra.UltraRecoveryKey
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Explicitly selected evidence only. Never installs an environment or changes any grant. */
class LiteWebRuntimeDeviceEvidenceTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext

    @Test fun pairedSdkFactsAreReadableWithoutManagerBootstrap() {
        requireOptIn()
        val client = client()
        val environment = client.environmentState()
        assertTrue("environment receipt", environment.succeeded)
        assertEquals("Running", environment.string("state"))
        val modules = client.moduleList()
        assertTrue("module receipt", modules.succeeded)
        val grants = client.suAuthSnapshot()
        assertTrue("grant receipt", grants.receipt.succeeded)
        assertTrue("grant array is explicit", grants.receipt.array("packages") != null)
        instrumentation.sendStatus(2, Bundle().apply {
            putString("ultraState", environment.string("state"))
            putInt("ultraModuleCount", checkNotNull(modules.array("modules")).length())
            putInt("ultraGrantCount", grants.count)
        })
    }

    @Test fun repairMissingDaemonIdentityWithoutReplacingRecoveryKey() {
        requireOptIn()
        assumeTrue(InstrumentationRegistry.getArguments().getString("repairLiteWebIdentity") == "true")
        val client = client()
        assertEquals("Running", client.environmentState().string("state"))
        val identity = checkNotNull(RecoveryIdentity.of(
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID),
            context.packageName, context.applicationInfo.uid,
        ))
        val before = client.runRootCommand("cat /data/adb/maplesu/recovery/rootkey 2>/dev/null")
        assertTrue("recovery key is readable", before.succeeded)
        val payload = client.decodeText(before.string("result"))?.trim()
        // Check the actual existing encrypted backup before writing identity metadata.
        assertTrue("existing recovery key must match paired key",
            UltraRootKeyStore.read(context) == UltraRecoveryKey.open(payload, identity.androidId, identity.packageName))
        val write = client.runRootCommand(RecoveryIdentityScripts.write(identity))
        assertTrue("identity write receipt", write.succeeded)
        val read = client.runRootCommand(RecoveryIdentityScripts.read())
        assertTrue("identity read receipt", read.succeeded)
        assertEquals(identity, RecoveryIdentity.parse(client.decodeText(read.string("result"))))
        val after = client.runRootCommand("cat /data/adb/maplesu/recovery/rootkey 2>/dev/null")
        assertTrue("recovery key bytes stay unchanged", before.string("result") == after.string("result"))
        instrumentation.sendStatus(2, Bundle().apply { putString("daemonIdentity", "verified; key unchanged") })
    }

    private fun client(): UltraRuntimeClient {
        val key = checkNotNull(UltraRootKeyStore.read(context)) { "ULTRA_KEY_MISSING" }
        return UltraRuntimeClient { key }
    }

    private fun requireOptIn() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyLiteWebRuntime") == "true")
    }
}

