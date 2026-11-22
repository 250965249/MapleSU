package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.litehidden.RecoveryIdentity
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import org.json.JSONObject

/** A credential supplied by the resident SDK gateway, scoped to one kernel boot. */
internal class UltraBootSdkSession private constructor(
    val bootId: String,
    val key: String,
    val installSubmitted: Boolean,
) {
    fun current(currentBootId: String?): Boolean = currentBootId == bootId

    fun submitted(): UltraBootSdkSession = UltraBootSdkSession(bootId, key, true)

    fun encode(): String = JSONObject().put("v", 1).put("bootId", bootId)
        .put("key", key).put("installSubmitted", installSubmitted).toString()

    /** Diagnostics must never print either the key or its derived init directory. */
    override fun toString(): String = "UltraBootSdkSession(installSubmitted=$installSubmitted)"

    companion object {
        private val BOOT_ID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

        fun create(bootId: String?, key: String?, installSubmitted: Boolean = false): UltraBootSdkSession? {
            if (bootId == null || !BOOT_ID.matches(bootId) || key == null ||
                !UltraKernelCredential.isValid(key) || !UltraKernelCredential.of(key).sdkMetadataValid) return null
            return UltraBootSdkSession(bootId, key, installSubmitted)
        }

        fun parse(text: String?): UltraBootSdkSession? = runCatching {
            if (text.isNullOrEmpty() || text.length > 1024) return null
            val record = JSONObject(text)
            if (record.getInt("v") != 1) return null
            create(record.getString("bootId"), record.getString("key"), record.getBoolean("installSubmitted"))
        }.getOrNull()
    }
}

/** Self-contained recovery material; permanent rootkey and identity files remain separate. */
internal object UltraBootSdkRecovery {
    const val FILE_NAME = "sdk-session"
    const val PATH = "/data/adb/maplesu/recovery/$FILE_NAME"

    fun seal(session: UltraBootSdkSession, identity: RecoveryIdentity): String? {
        if (!identity.isValid) return null
        val encrypted = UltraRecoveryKey.seal(session.key, identity.androidId, domain(identity, session.bootId))
            ?: return null
        return JSONObject().put("v", 1).put("bootId", session.bootId)
            .put("identity", identity.toJson()).put("sealedKey", encrypted).toString()
    }

    fun open(text: String?, currentBootId: String?, managerPackage: String,
        expectedIdentity: RecoveryIdentity? = null): UltraBootSdkSession? = runCatching {
        if (text.isNullOrEmpty() || text.length > 8192 || currentBootId.isNullOrEmpty()) return null
        val record = JSONObject(text)
        if (record.getInt("v") != 1 || record.getString("bootId") != currentBootId) return null
        val identity = RecoveryIdentity.parse(record.getString("identity")) ?: return null
        if (identity.packageName != managerPackage || (expectedIdentity != null && identity != expectedIdentity)) return null
        val key = UltraRecoveryKey.open(record.getString("sealedKey"), identity.androidId,
            domain(identity, currentBootId)) ?: return null
        UltraBootSdkSession.create(currentBootId, key, installSubmitted = true)
    }.getOrNull()

    private fun domain(identity: RecoveryIdentity, bootId: String) =
        "${identity.packageName}|maplesu-boot-sdk-v1|$bootId"
}

/** App recovery requires the same install identity and live SDK evidence before persistence. */
internal object UltraBootSdkRestore {
    interface Port {
        fun currentBootId(): String?
        fun verified(session: UltraBootSdkSession): Boolean
        fun store(session: UltraBootSdkSession): Boolean
    }

    fun restore(material: String, identity: RecoveryIdentity, port: Port): String {
        val candidate = UltraBootSdkRecovery.open(material, port.currentBootId(), identity.packageName, identity)
            ?: return "BOOT_SDK_RECOVERY_EXPIRED_OR_INVALID"
        if (!port.verified(candidate)) return "BOOT_SDK_RUNTIME_UNVERIFIED"
        if (!candidate.current(port.currentBootId())) return "BOOT_SDK_BOOT_CHANGED"
        if (!port.store(candidate)) return "BOOT_SDK_RECOVERY_STORE_FAILED"
        return "BOOT_SDK_RESTORED"
    }
}

/** HotLoad has one durable submission. A lost reply is reconciled through observations only. */
internal object UltraBootSdkInstall {
    interface Port {
        fun current(): Boolean
        fun channelVerified(): Boolean
        fun kernelBaseVerified(): Boolean
        fun environmentState(): String?
        fun prepare(): Boolean
        fun markSubmitted(): Boolean
        fun submit(): NativeReceipt
        fun rootVerified(): Boolean
        fun whitelistVerified(): Boolean
        fun managerSuVerified(): Boolean
        fun moduleListVerified(): Boolean
    }

    /** Fixed receipt fields only; raw SDK details can contain credential-derived paths. */
    data class Submission(val succeeded: Boolean, val operation: String, val sdkError: String, val sdkErrorCode: Int)

    data class Result(val ready: Boolean, val submitted: Boolean, val reason: String, val submission: Submission? = null)

    fun ensure(alreadySubmitted: Boolean, port: Port): Result {
        var submitted = false
        var submission: Submission? = null
        fun failed(reason: String) = Result(false, submitted, reason, submission)
        return try {
            if (!port.current()) return failed("SESSION_CHANGED")
            if (!port.channelVerified()) return failed("SDK_CHANNEL_UNVERIFIED")
            if (!port.current()) return failed("SESSION_CHANGED")
            if (!port.kernelBaseVerified()) return failed("SDK_METADATA_UNVERIFIED")
            if (!port.current()) return failed("SESSION_CHANGED")
            when (port.environmentState()) {
                "Running" -> Unit
                "NotInstalled" -> {
                    if (alreadySubmitted) return failed("HOTLOAD_RECONCILIATION_REQUIRED")
                    if (!port.current()) return failed("SESSION_CHANGED")
                    if (!port.prepare()) return failed("HOTLOAD_PREPARATION_FAILED")
                    if (!port.current()) return failed("SESSION_CHANGED")
                    if (!port.markSubmitted()) return failed("HOTLOAD_GUARD_STORE_FAILED")
                    if (!port.current()) return failed("SESSION_CHANGED")
                    submitted = true
                    // A throwable may follow a successful submission. It grants no retry.
                    try {
                        val receipt = port.submit()
                        submission = Submission(receipt.succeeded, receipt.operation, receipt.sdkError, receipt.sdkErrorCode)
                    } catch (error: Exception) {
                        if (error is InterruptedException) Thread.currentThread().interrupt()
                    }
                    if (!port.current()) return failed("SESSION_CHANGED")
                    if (port.environmentState() != "Running") {
                        val detail = submission?.takeUnless { it.succeeded }?.let {
                            ":${it.operation}:${it.sdkError}:${it.sdkErrorCode}"
                        }.orEmpty()
                        return failed("HOTLOAD_RECONCILIATION_REQUIRED$detail")
                    }
                }
                "Fault" -> return failed("ENVIRONMENT_FAULT")
                else -> return failed("ENVIRONMENT_STATE_UNKNOWN")
            }
            if (!port.current()) return failed("SESSION_CHANGED")
            if (!port.rootVerified()) return failed("SDK_ROOT_UNVERIFIED")
            if (!port.current()) return failed("SESSION_CHANGED")
            if (!port.whitelistVerified()) return failed("SELF_WHITELIST_UNVERIFIED")
            if (!port.current()) return failed("SESSION_CHANGED")
            if (!port.managerSuVerified()) return failed("MANAGER_SU_UNVERIFIED")
            if (!port.current()) return failed("SESSION_CHANGED")
            if (!port.moduleListVerified()) return failed("MODULE_LIST_UNVERIFIED")
            if (!port.current()) return failed("SESSION_CHANGED")
            Result(true, submitted, "RUNNING_VERIFIED", submission)
        } catch (error: Exception) {
            if (error is InterruptedException) Thread.currentThread().interrupt()
            failed("SDK_OBSERVATION_FAILED")
        }
    }
}
