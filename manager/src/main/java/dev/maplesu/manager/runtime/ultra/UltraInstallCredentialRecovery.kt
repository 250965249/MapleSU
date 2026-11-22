package dev.maplesu.manager.runtime.ultra

import android.content.Context
import android.util.Log
import dev.maplesu.manager.installer.InstallTargetMode
import dev.maplesu.manager.installer.InstallerServiceClient
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.ultrakernel.UltraKernelContextAssets
import java.io.File

/** Recover environment identity first; private install receipts remain a legacy fallback. */
internal object UltraInstallCredentialRecovery {
    @Synchronized
    fun recover(context: Context): UltraInstallCredentialHandoff.Outcome {
        val app = context.applicationContext
        if (UltraIdentityRecovery.recover(app) == "RECOVERED") return UltraInstallCredentialHandoff.Outcome.Recovered
        val taskId = InstallerServiceClient.lastTaskId(app)
        val target = taskId?.let { InstallerServiceClient.installTargetOf(app, it) }
        return UltraInstallCredentialHandoff(UltraKernelContextAssets(app)).recover(
            dev.maplesu.manager.compat.UltraStateStorage.flash(app.filesDir), target?.wire,
            UltraRootKeyStore.read(app), UltraRootKeyStore.isSuspended(app),
        ) { key ->
            UltraKeyPairedStore.storeInstallKeyIfAbsent(app, key, requireNotNull(taskId))
        }.also { Log.i("MapleSUUltraInstall", "credential handoff outcome=$it") }
    }

    /** Exports have no flash transaction; their exact candidate key still permits first setup. */
    fun hasPendingInstallCredential(context: Context): Boolean {
        if (UltraKeyPairedStore.hasPendingInstallKey(context, UltraInstallCredentials.IMAGE_EXPORT_OPERATION) ||
            UltraKeyPairedStore.hasPendingInstallKey(context, "generated-export")) return true
        val taskId = InstallerServiceClient.lastTaskId(context) ?: return false
        return InstallerServiceClient.installTargetOf(context, taskId) == InstallTargetMode.ULTRA &&
            UltraKeyPairedStore.hasPendingInstallKey(context, taskId)
    }

    /** A fresh first-install key or committed handoff still needs a later live matching SDK key. */
    fun hasVerifiedInstallCredential(context: Context): Boolean {
        if (!UltraEnvironmentProbe.hasCurrentRootProof(context) ||
            UltraSdkCredentials.read(context) != UltraRootKeyStore.read(context)) return false
        if (UltraKeyPairedStore.hasInstallKey(context, UltraInstallCredentials.IMAGE_EXPORT_OPERATION) ||
            UltraKeyPairedStore.hasInstallKey(context, "generated-export")) return true
        val taskId = InstallerServiceClient.lastTaskId(context) ?: return false
        return InstallerServiceClient.installTargetOf(context, taskId) == InstallTargetMode.ULTRA &&
            UltraKeyPairedStore.hasInstallKey(context, taskId)
    }
}
