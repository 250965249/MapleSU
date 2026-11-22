package dev.maplesu.manager.runtime.ultra

/** Called only after the deployed broker's key, build and deployment handshake matches. */
internal object UltraIdentityBootHook {
    fun ensure(environmentVerified: Boolean, preparingUpgrade: Boolean,
               retireLegacy: () -> String?): String {
        if (!environmentVerified) return if (preparingUpgrade) "IDENTITY_UPGRADE_PREPARED"
            else "IDENTITY_ENVIRONMENT_UPGRADE_REQUIRED"
        return retireLegacy() ?: "IDENTITY_READY"
    }
}
