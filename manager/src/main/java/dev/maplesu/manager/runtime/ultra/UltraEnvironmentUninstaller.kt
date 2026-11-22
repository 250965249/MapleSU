package dev.maplesu.manager.runtime.ultra

import android.content.Context
import dev.maplesu.manager.installer.InstallerServiceClient
import dev.maplesu.manager.installer.ImageRestorationKind
import dev.maplesu.manager.modules.UltraRootKeyStore
import java.util.UUID

/** Explicit settings removal. Keep credentials for temporary removal and inhibit auto setup. */
internal object UltraEnvironmentUninstaller {
    data class Outcome(val ok: Boolean, val stockRestored: Boolean, val sdkError: String,
                       val receipt: NativeReceipt? = null) {
        val sdkErrorCode: Int? get() = receipt?.sdkErrorCode
        val reason: String? get() = receipt?.reason

        override fun toString(): String = "Outcome(ok=$ok, stockRestored=$stockRestored, " +
            "sdkError=${UltraSdkLogging.redact(sdkError)}, sdkErrorCode=$sdkErrorCode)"
    }
    data class Restoration(val completed: Boolean, val stockRestored: Boolean)

    fun uninstall(context: Context, permanent: Boolean): Outcome {
        val app = context.applicationContext
        // Bind before permanent disable hides this key from normal manager operations.
        val key = UltraRootKeyStore.read(app)
        val client = UltraRuntimeClient { key }
        val taskId = UUID.randomUUID().toString()
        return uninstall(permanent,
            restoreStock = {
                val receipt = InstallerServiceClient.restoreStockImages(app, taskId)
                Restoration(receipt.getString("operation") == "RESTORE_STOCK" && receipt.getString("error").isNullOrEmpty() &&
                    receipt.getString("state") in setOf("REBOOT_REQUIRED", "REBOOT_REQUESTED", "BOOT_IMAGE_VERIFIED"),
                    ImageRestorationKind.fromWire(receipt.getString("restorationKind")) == ImageRestorationKind.EXACT_STOCK)
            },
            persistRemoval = {
                UltraIdentityRecovery.suspend(client)
                UltraRootKeyStore.recordRemoval(app, permanent)
                UltraKeyPairedStore.clear(app)
                UltraInstalledIdentityProbe.clear(app)
                UltraEnvironmentProbe.invalidateAvailability()
            },
            removeSdk = client::uninstallEnvironment,
            rebootStock = { InstallerServiceClient.rebootAfterInstallation(app, taskId) },
        )
    }

    /** Persist intent before SDK teardown: a successful SDK call schedules reboot in 3 seconds. */
    internal fun uninstall(permanent: Boolean, restoreStock: () -> Restoration,
                           persistRemoval: () -> Unit, removeSdk: () -> NativeReceipt,
                           rebootStock: () -> Boolean = { true }): Outcome {
        val restoration = if (permanent) runCatching { restoreStock() }.getOrDefault(Restoration(false, false))
            else Restoration(false, false)
        if (permanent && !restoration.completed) return Outcome(false, false, "ULTRA_STOCK_RESTORE_FAILED")
        persistRemoval()
        if (restoration.completed) {
            val rebooted = rebootStock()
            return Outcome(rebooted, restoration.stockRestored, if (rebooted) "OK" else "ULTRA_STOCK_REBOOT_FAILED")
        }
        val receipt = removeSdk()
        return Outcome(receipt.succeeded, false,
            receiptErrorName(receipt.succeeded, receipt.sdkError), receipt)
    }
}
