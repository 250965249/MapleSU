package dev.maplesu.manager.installer

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import dev.maplesu.manager.ultrakernel.UltraKernelSpec
import dev.maplesu.manager.runtime.ultra.UltraInstallCredentialRecovery
import dev.maplesu.manager.runtime.ultra.UltraInstallCredentials
import dev.maplesu.manager.runtime.ultra.UltraKeyPairedStore
import java.io.File
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test

/** Isolated local storage checks: no SDK, root sessions, flash or reboot. */
class UltraImageExportIdentityAndroidTest {
    private fun isolated(block: (Context) -> Unit) {
        val base = InstrumentationRegistry.getInstrumentation().context
        val prefix = "export-identity-${UUID.randomUUID()}-"
        val stores = mutableSetOf<String>()
        val context = object : ContextWrapper(base) {
            override fun getApplicationContext(): Context = this
            override fun getSharedPreferences(name: String, mode: Int): SharedPreferences {
                val isolated = prefix + name
                stores += isolated
                return base.getSharedPreferences(isolated, mode)
            }
        }
        try { block(context) } finally { stores.forEach(base::deleteSharedPreferences) }
    }

    @Test fun exportedImageKeepsItsExactKeyAndCanInitializeWithoutAFlashTransaction() = isolated { context ->
        val image = File.createTempFile("candidate-", ".img", context.cacheDir)
        val credential = UltraKernelCredential.of("Ab1".repeat(16)).withMetadataDisplacement(-9188272)
        try {
            image.writeBytes(ByteArray(4096) { (it % 127).toByte() })
            UltraInstallCredentials.retainCandidate(context, image, UltraKernelSpec.sha256(image),
                credential, UltraInstallCredentials.IMAGE_EXPORT_OPERATION)
            assertEquals(credential, UltraKernelCredential.of(requireNotNull(UltraRootKeyStore.read(context))))
            assertNull(InstallerServiceClient.lastTaskId(context))
            assertTrue(UltraInstallCredentialRecovery.hasPendingInstallCredential(context))
            assertFalse("Exporting alone must not claim a running SDK identity", UltraKeyPairedStore.isPaired(context))
        } finally { image.delete() }
    }

    @Test fun aChangedExportCannotPublishItsKeyOrEnableStartup() = isolated { context ->
        val image = File.createTempFile("candidate-", ".img", context.cacheDir)
        try {
            image.writeText("candidate before readback")
            val sha = UltraKernelSpec.sha256(image)
            image.appendText("changed")
            assertThrows(IllegalStateException::class.java) {
                UltraInstallCredentials.retainCandidate(context, image, sha,
                    UltraKernelCredential.of("Ab1".repeat(16)), UltraInstallCredentials.IMAGE_EXPORT_OPERATION)
            }
            assertNull(UltraRootKeyStore.read(context))
            assertFalse(UltraInstallCredentialRecovery.hasPendingInstallCredential(context))
        } finally { image.delete() }
    }

    @Test fun previousGeneratedExportsAlsoResumeWithoutATransaction() = isolated { context ->
        val image = File.createTempFile("candidate-", ".img", context.cacheDir)
        try {
            image.writeText("previous generated candidate")
            UltraInstallCredentials.retainCandidate(context, image, UltraKernelSpec.sha256(image),
                UltraKernelCredential.of("Ab1".repeat(16)), "generated-export")
            assertTrue(UltraInstallCredentialRecovery.hasPendingInstallCredential(context))
            assertFalse(UltraKeyPairedStore.isPaired(context))
        } finally { image.delete() }
    }
}
