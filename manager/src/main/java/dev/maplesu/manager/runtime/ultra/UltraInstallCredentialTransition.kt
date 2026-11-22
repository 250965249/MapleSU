package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import dev.maplesu.manager.ultrakernel.UltraKernelSpec

/** A candidate identity belongs to a verified image write and becomes active after reboot. */
internal data class UltraInstallCredentialTransition(
    val credential: UltraKernelCredential,
    val previousKeySha256: String,
    val operationId: String,
    val bootSha256: String,
    val sourceBootId: String,
    val committed: Boolean = false,
) {
    init {
        require(credential.sdkMetadataValid && previousKeySha256.matches(SHA256) &&
            bootSha256.matches(SHA256) && operationId.isNotBlank() && sourceBootId.matches(BOOT_ID)) {
            "ULTRA_KERNEL_CREDENTIAL_TRANSITION_INVALID"
        }
    }

    fun confirm(taskId: String, imageSha256: String, bootId: String, current: String?): UltraInstallCredentialTransition {
        check(taskId == operationId && imageSha256 == bootSha256 && bootId == sourceBootId &&
            current?.let(::fingerprint) == previousKeySha256) { "ULTRA_KERNEL_CREDENTIAL_CHANGED" }
        return copy(committed = true)
    }

    fun afterBoot(bootId: String, current: String?, suspended: Boolean): UltraKernelCredential? =
        credential.takeIf {
            committed && !suspended && bootId.matches(BOOT_ID) && bootId != sourceBootId &&
                current?.let(::fingerprint) == previousKeySha256
        }

    companion object {
        private val SHA256 = Regex("[0-9a-f]{64}")
        private val BOOT_ID = Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

        fun stage(previous: String, candidate: UltraKernelCredential, taskId: String, sha256: String,
                  bootId: String): UltraInstallCredentialTransition {
            // An explicit reinstall can bind a new identity when the old key is stale/lost.
            // The exact previous key, task, digest and boot still own confirmation/promotion.
            check(previous.isNotBlank() && candidate.sdkMetadataValid) {
                "ULTRA_KERNEL_CREDENTIAL_CHANGED"
            }
            return UltraInstallCredentialTransition(candidate, fingerprint(previous), taskId, sha256, bootId)
        }

        private fun fingerprint(key: String): String {
            val bytes = key.toByteArray(Charsets.US_ASCII)
            return try { UltraKernelSpec.sha256(bytes) } finally { bytes.fill(0) }
        }
    }
}
