package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.compat.ultraPreferences

import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import dev.maplesu.manager.ultrakernel.UltraKernelSpec
import dev.maplesu.manager.workmode.detect.ProcBootIdSource
import org.json.JSONObject

/** Persist preparation separately from the identity used by this boot's root transport. */
internal class UltraPendingInstallCredentialStore(
    private val prefs: SharedPreferences,
    private val currentBootId: () -> String,
) {
    constructor(context: Context) : this(context.ultraPreferences("maplesu-ultra", Context.MODE_PRIVATE),
        ProcBootIdSource::read)

    companion object {
        const val RECORD = "pendingKernelCredential"
        const val PREVIOUS_RECORD = "previousInstallCredential"
        private val LOCK = UltraRootKeyStore
    }
    private fun suspended(prefs: SharedPreferences) = !prefs.getString("rootKeySuspended", null).isNullOrBlank() ||
        prefs.getString("environmentRemoval", null) != null

    private fun read(prefs: SharedPreferences): UltraInstallCredentialTransition? {
        val text = prefs.getString(RECORD, null) ?: return null
        return runCatching {
            val json = JSONObject(text)
            UltraInstallCredentialTransition(UltraKernelCredential.of(json.getString("key")),
                json.getString("previousKeySha256"), json.getString("taskId"), json.getString("bootSha256"),
                json.getString("sourceBootId"), json.getBoolean("committed"))
        }.getOrNull()
    }

    private fun save(prefs: SharedPreferences, pending: UltraInstallCredentialTransition) {
        val bytes = pending.credential.copySecret()
        try {
            val json = JSONObject().put("key", bytes.toString(Charsets.US_ASCII))
                .put("previousKeySha256", pending.previousKeySha256).put("taskId", pending.operationId)
                .put("bootSha256", pending.bootSha256).put("sourceBootId", pending.sourceBootId)
                .put("committed", pending.committed)
            check(prefs.edit().putString(RECORD, json.toString()).commit()) { "ULTRA_PAIRING_STORE_FAILED" }
        } finally { bytes.fill(0) }
    }

    fun stage(expected: String?, credential: UltraKernelCredential, taskId: String,
              sha256: String): Boolean = synchronized(LOCK) {
        if (expected == null || prefs.getString("rootKey", null)?.trim() != expected || suspended(prefs)) return@synchronized false
        val previous = read(prefs)
        // Candidate keys are archived by image digest before staging. The latest explicit
        // attempt replaces only promotion intent, including a write repeated before reboot.
        val staged = UltraInstallCredentialTransition.stage(expected, credential, taskId, sha256, currentBootId())
        if (previous != staged && previous != staged.copy(committed = true)) save(prefs, staged)
        true
    }

    fun credential(taskId: String, sha256: String? = null): UltraKernelCredential? = synchronized(LOCK) {
        read(prefs)?.takeIf { it.operationId == taskId && (sha256 == null || it.bootSha256 == sha256) }?.credential
    }

    /** External flashing may omit a receipt; live Root verification still permits recovery. */
    fun recoveryCredential(): UltraKernelCredential? = recoveryCredentials().firstOrNull()

    fun recoveryCredentials(): List<UltraKernelCredential> = synchronized(LOCK) {
        if (suspended(prefs)) return@synchronized emptyList()
        listOfNotNull(read(prefs)?.credential, previousCredential()).distinct()
    }

    /** A bootloader may boot the previous slot after a successful image write. */
    private fun previousCredential(): UltraKernelCredential? {
        val text = prefs.getString(PREVIOUS_RECORD, null) ?: return null
        val current = prefs.getString("rootKey", null)?.trim() ?: return null
        val bytes = current.toByteArray(Charsets.US_ASCII)
        return try {
            runCatching {
                val json = JSONObject(text)
                val active = UltraKernelCredential.of(current)
                val previous = UltraKernelCredential.of(json.getString("key"))
                previous.takeIf {
                    json.getString("forKeySha256") == UltraKernelSpec.sha256(bytes) &&
                        active.sdkMetadataValid && previous.sdkMetadataValid
                }
            }.getOrNull()
        } finally { bytes.fill(0) }
    }

    /** Only a root-service success receipt for this exact task and digest can arm promotion. */
    fun observe(status: Bundle) = observe(status.getString("taskId"), status.getString("state"),
        status.getString("candidateSha256"), status.getString("rebootSourceState"))

    fun observe(taskId: String?, state: String?, imageSha256: String?,
                rebootSourceState: String? = null): Unit = synchronized(LOCK) {
        val pending = read(prefs) ?: return@synchronized
        if (taskId != pending.operationId) return@synchronized
        val effectiveState = if (state == "REBOOT_REQUESTED" && rebootSourceState == "RESTORED") "RESTORED" else state
        when (effectiveState) {
            "REBOOT_REQUIRED", "REBOOT_REQUESTED" -> {
                if (pending.committed && currentBootId() != pending.sourceBootId) return@synchronized
                val confirmed = try {
                    check(!suspended(prefs)) { "ULTRA_KERNEL_CREDENTIAL_SUSPENDED" }
                    pending.confirm(pending.operationId, imageSha256.orEmpty(),
                        currentBootId(), prefs.getString("rootKey", null)?.trim())
                } catch (error: IllegalStateException) {
                    if (pending.committed) save(prefs, pending.copy(committed = false))
                    throw error
                }
                if (confirmed != pending) save(prefs, confirmed)
            }
            // Removal also prevents a delayed success receipt from rearming a rollback.
            "RESTORING", "ROLLING_BACK", "RECOVERY_REQUIRED",
            "FAILED_BEFORE_WRITE", "FAILED_PRE_WRITE", "RESTORED", "CANCELLED", "ROLLED_BACK" -> {
                check(prefs.edit().remove(RECORD).commit()) { "ULTRA_PAIRING_STORE_FAILED" }
            }
        }
    }

    /** Called before returning any runtime key, including startup probes in a new process. */
    fun activateAfterBoot(): Unit = synchronized(LOCK) {
        val pending = read(prefs) ?: return@synchronized
        val credential = pending.afterBoot(currentBootId(), prefs.getString("rootKey", null)?.trim(), suspended(prefs))
            ?: return@synchronized
        val bytes = credential.copySecret()
        try {
            val previous = JSONObject().put("key", prefs.getString("rootKey", null))
                .put("forKeySha256", UltraKernelSpec.sha256(bytes))
            check(prefs.edit().putString("rootKey", bytes.toString(Charsets.US_ASCII))
                .putString(PREVIOUS_RECORD, previous.toString())
                .remove("keyVerified").remove("keyVerifiedFor")
                .putString("installCredentialTaskId", pending.operationId)
                .putString("installCredentialForKey", UltraKernelSpec.sha256(bytes))
                .putString("installCredentialSourceBoot", pending.sourceBootId)
                .putString("installCredentialProvenance", "committed")
                .remove("installAuthorizationObservedForKey")
                .remove(RECORD).commit()) { "ULTRA_PAIRING_STORE_FAILED" }
        } finally { bytes.fill(0) }
    }
}
