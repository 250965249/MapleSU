package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelCredential

/** Explicit candidate preparation is separate from authentication of a running Ultra kernel. */
internal class UltraInstallCredentialPolicy(
    private val currentKey: () -> String?,
    private val suspendedKey: () -> String?,
    private val loadDevice: () -> ByteArray?,
    private val createDevice: () -> ByteArray,
    private val knownNonUltra: () -> Boolean,
) {
    fun existing(): UltraKernelCredential? {
        val active = currentKey()?.takeIf(UltraKernelCredential::isValid)
        val parked = suspendedKey()?.takeIf(UltraKernelCredential::isValid)
        if (active != null) return UltraKernelCredential.of(active)
        if (parked != null) return UltraKernelCredential.of(parked)
        val bytes = runCatching(loadDevice).getOrNull() ?: return null
        return try { runCatching { UltraKernelCredential.of(bytes) }.getOrNull() } finally { bytes.fill(0) }
    }

    fun forCandidate(): UltraKernelCredential {
        existing()?.let { return it }
        val bytes = createDevice()
        return try { UltraKernelCredential.of(bytes) } finally { bytes.fill(0) }
    }

    /** Keep an exported image's exact identity without changing an existing device pairing. */
    fun retainForExport(credential: UltraKernelCredential, archive: (String) -> Unit,
                        storeIfAbsent: (String) -> Boolean) {
        val bytes = credential.copySecret()
        try {
            val key = bytes.toString(Charsets.US_ASCII)
            archive(key)
            if (currentKey().isNullOrBlank() && suspendedKey().isNullOrBlank()) {
                // First-install exports may be flashed externally. A concurrent pairing wins.
                storeIfAbsent(key)
            }
        } finally {
            bytes.fill(0)
        }
    }

    /** Called only with the identity carried by a successfully read-back candidate, before flashing. */
    fun retain(credential: UltraKernelCredential, stageForReboot: ((String) -> Boolean)? = null,
               storeIfAbsent: (String) -> Boolean) {
        check(suspendedKey().isNullOrBlank()) { "ULTRA_KERNEL_CREDENTIAL_SUSPENDED" }
        val bytes = credential.copySecret()
        try {
            val key = bytes.toString(Charsets.US_ASCII)
            val active = currentKey()?.takeIf { it.isNotBlank() }
            if (active != null && active != key) {
                val original = active.takeIf(UltraKernelCredential::isValid)?.let(UltraKernelCredential::of)
                check(credential.sdkMetadataValid) { "ULTRA_KERNEL_CREDENTIAL_CHANGED" }
                if (original?.sdkMetadataValid == true || !knownNonUltra()) {
                    // Keep the running kernel's exact key. Only a successful write may arm the
                    // candidate identity for the next boot; preparation is not a live pairing.
                    check(stageForReboot?.invoke(key) == true) { "ULTRA_KERNEL_CREDENTIAL_CHANGED" }
                    return
                }
            }
            check(storeIfAbsent(key) || currentKey() == key) { "ULTRA_KERNEL_CREDENTIAL_CHANGED" }
        } finally {
            bytes.fill(0)
        }
    }
}
