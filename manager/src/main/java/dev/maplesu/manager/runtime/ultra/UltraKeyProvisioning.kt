package dev.maplesu.manager.runtime.ultra

import android.content.Context
import android.util.Log
import dev.maplesu.manager.modules.UltraRootKeyStore

class UltraKeyProvisioning(context: Context) {

    private val applicationContext = context.applicationContext

    data class Result(
        val ok: Boolean,
        val environmentState: String? = null,
        val failure: String? = null,
        val detail: String? = null,
    )

    fun pair(key: String): Result {
        val normalized = key.trim()
        if (normalized.isEmpty()) {
            return Result(false, failure = "ULTRA_KEY_EMPTY", detail = "Ultra root key is empty")
        }
        if (normalized.length != CREDENTIAL_LENGTH) {
            return Result(
                false,
                failure = "ULTRA_KEY_FORMAT",
                detail = "Ultra root key must be $CREDENTIAL_LENGTH ASCII characters",
            )
        }

        val bootId = UltraEnvironmentAutoSetup.currentBootId()
        val expectedKey = UltraRootKeyStore.read(applicationContext)
        fun current(key: String?) = !Thread.currentThread().isInterrupted && bootId != null &&
            UltraEnvironmentAutoSetup.currentBootId() == bootId &&
            UltraRootKeyStore.read(applicationContext) == key && !UltraIdentityRecovery.blocked(applicationContext)
        if (!current(expectedKey)) return Result(false, failure = "RECOVERY_SUSPENDED")
        val client = UltraRuntimeClient { normalized.takeIf { current(expectedKey) } }
        val receipt = try {
            client.environmentState()
        } catch (error: Throwable) {
            // P0 安全：异常文本也可能携带 key，日志/回执一律先脱敏。
            Log.w(TAG, "Ultra key verification failed: ${UltraSdkLogging.redact(error.message)}")
            return Result(
                false,
                failure = "ULTRA_KEY_PROBE_FAILED",
                detail = UltraSdkLogging.redact(error.toString()),
            )
        }
        val stateName = receipt.string("state")
        if (!receipt.succeeded) {
            return Result(false, failure = receipt.sdkError, detail = receipt.reason)
        }
        if (stateName != "Running") {
            return Result(
                false,
                failure = "ULTRA_ENVIRONMENT_NOT_RUNNING",
                detail = "state=$stateName",
            )
        }

        val rootVerified = recoveryCandidate { UltraIdentityRecovery.uid(client) } == 0
        if (!current(expectedKey)) return Result(false, environmentState = stateName, failure = "ULTRA_KEY_CHANGED")
        if (!rootVerified) return Result(false, environmentState = stateName, failure = "SDK_ROOT_UNVERIFIED")
        try {
            val stored = synchronized(UltraRootKeyStore) {
                if (!current(expectedKey)) false else {
                    if (expectedKey == normalized) UltraKeyPairedStore.markPaired(applicationContext, normalized)
                    else UltraKeyPairedStore.storeVerifiedKey(applicationContext, normalized)
                    true
                }
            }
            if (!stored) return Result(false, environmentState = stateName, failure = "ULTRA_KEY_CHANGED")
        } catch (error: Throwable) {
            Log.w(TAG, "Ultra root key persistence failed: ${UltraSdkLogging.redact(error.message)}")
            return Result(false, failure = "ULTRA_KEY_STORE_FAILED",
                detail = UltraSdkLogging.redact(error.message ?: error.toString()))
        }
        if (!current(normalized)) return Result(false, environmentState = stateName, failure = "ULTRA_KEY_CHANGED")
        val ready = UltraAutoPair.ensure(applicationContext)
        if (!current(normalized)) {
            return Result(false, environmentState = ready.state.name, failure = "ULTRA_KEY_CHANGED")
        }
        return Result(ready.paired, environmentState = ready.state.name,
            failure = ready.reason.takeUnless { ready.paired })
    }

    companion object {
        private const val TAG = "MapleSUUltraKeys"
        private const val CREDENTIAL_LENGTH = 48
    }
}
