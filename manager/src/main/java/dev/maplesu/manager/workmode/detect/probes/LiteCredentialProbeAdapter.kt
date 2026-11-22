package dev.maplesu.manager.workmode.detect.probes

import android.content.Context
import android.os.Looper
import dev.maplesu.manager.runtime.MapleSuCredentialStore
import dev.maplesu.manager.runtime.MapleSuRuntime
import dev.maplesu.manager.workmode.detect.LiteCredentialProbe
import dev.maplesu.manager.workmode.detect.LiteHandshakeProbe

/**
 * Lite 凭据探针适配器。
 *
 * 刻意拆成两个端口，防止启动期拿 root：
 * - [LiteCredentialProbe.probe]：**只读存在性**（`MapleSuCredentialStore.load()` 走 Keystore
 *   解密，不起 root），启动阶段一可调用；返回值恒 `(present, null)`；
 * - [LiteHandshakeProbe.probe]：凭据 → UID0 executor 的握手（**特权动作**），
 *   只有 `allowLiteExecutor=true` 的阶段二才会被 [dev.maplesu.manager.workmode.detect.DefaultModeDetector] 调用。
 *
 * 握手三态（不得混同）：
 * - 凭据不在 → null（NOT_ATTEMPTED）；
 * - 主线程 → null（不允许在首帧做特权探测；阶段二在后台线程执行）；
 * - 后台且实际尝试 → true / false（`MapleSuRuntime.isReady` 内部完成独立校验，
 *   false = 已尝试但失败 ≠ 未知）；抛异常 = null（UNKNOWN，绝不把异常写成失败）。
 */
class LiteCredentialProbeAdapter(
    context: Context,
    private val loadCredential: () -> ByteArray? = {
        MapleSuCredentialStore(context.applicationContext).load()
    },
    private val isMainThread: () -> Boolean = {
        Looper.myLooper() == Looper.getMainLooper()
    },
    private val probeHandshake: () -> Boolean = {
        MapleSuRuntime.isReady(context.applicationContext)
    },
) : LiteCredentialProbe, LiteHandshakeProbe {

    @Volatile
    private var lastKnownPresent: Boolean? = null

    /** 只读存在性；**绝不**在这里尝试握手（启动期禁止起 root）。 */
    override fun probe(): Pair<Boolean, Boolean?> {
        val present = runCatching { loadCredential() != null }.getOrDefault(false)
        lastKnownPresent = present
        return present to null
    }

    /** 凭据 → UID0 握手；只允许后台线程 + allowLiteExecutor=true 的阶段二。 */
    override fun handshake(): Boolean? {
        val present = lastKnownPresent
            ?: runCatching { loadCredential() != null }.getOrDefault(false).also { lastKnownPresent = it }
        if (!present) return LiteProbeRules.evaluate(credentialPresent = false, outcome = HandshakeOutcome.NOT_ATTEMPTED).second
        val onMainThread = runCatching { isMainThread() }.getOrDefault(true)
        if (onMainThread) {
            return LiteProbeRules.evaluate(credentialPresent = true, outcome = HandshakeOutcome.NOT_ATTEMPTED).second
        }
        val outcome = runCatching { probeHandshake() }.fold(
            onSuccess = { ready -> if (ready) HandshakeOutcome.SUCCEEDED else HandshakeOutcome.FAILED },
            onFailure = { HandshakeOutcome.UNKNOWN },
        )
        return LiteProbeRules.evaluate(credentialPresent = true, outcome = outcome).second
    }
}

/** 握手尝试结果（可区分 NOT_ATTEMPTED / SUCCEEDED / FAILED / UNKNOWN）。 */
enum class HandshakeOutcome { NOT_ATTEMPTED, SUCCEEDED, FAILED, UNKNOWN }

/** 纯映射：凭据存在性 + 握手结果 → 端口返回值 `(present, handshakeOk?)`。 */
object LiteProbeRules {
    fun evaluate(credentialPresent: Boolean, outcome: HandshakeOutcome): Pair<Boolean, Boolean?> = when {
        !credentialPresent -> false to null
        outcome == HandshakeOutcome.SUCCEEDED -> true to true
        outcome == HandshakeOutcome.FAILED -> true to false
        // NOT_ATTEMPTED / UNKNOWN 一律 null：未尝试 ≠ 失败（01 §2.7 handshakeNullIsNotFalse）。
        else -> true to null
    }
}
