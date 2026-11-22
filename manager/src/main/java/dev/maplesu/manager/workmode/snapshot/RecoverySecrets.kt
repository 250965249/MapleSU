package dev.maplesu.manager.workmode.snapshot

import android.content.Context
import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.detect.RootEvidenceSession
import kotlinx.serialization.Serializable

/**
 * 设备侧恢复材料。
 *
 * 边界（必须写进 UI）：Lite 凭据的 Android Keystore 密钥随 App 数据一起删除；
 * 没有 Ultra/KSU 通道时无法自动恢复。因此 `secrets/` 只能是"root 0600 明文 + 用户显式开启"，
 * 且必须由**独立于 Lite 的 root 通道**读取后再加密进新 Keystore。
 */
@Serializable
data class SecretsManifest(
    val schema: Int = SCHEMA,
    /** 不存凭据本体之外的任何派生。 */
    val credentialSha256: String,
    val writtenAt: Long,
    val bootId: String,
    /** 写入时使用过的通道："A_DIRECT" | "A_ULTRA" | "B_KSU"。 */
    val channel: String,
    /** 必须 true，否则不得写。 */
    val userConsented: Boolean,
) {
    companion object { const val SCHEMA = 1 }
}

interface RecoverySecrets {
    /** 设置项，默认 OFF。 */
    fun isEnabled(context: Context): Boolean
    fun write(session: RootEvidenceSession, credential: ByteArray, channel: String)
    /** 48B；校验 sha 与长度/字符集。 */
    fun read(session: RootEvidenceSession): ByteArray?
    fun clear(session: RootEvidenceSession)
}

/** 恢复材料写入/读取的纯规则（主机可测，不做 I/O）。 */
object RecoverySecretsRules {
    const val CREDENTIAL_SIZE = 48
    const val CHANNEL_A_DIRECT = "A_DIRECT"
    const val CHANNEL_A_ULTRA = "A_ULTRA"
    const val CHANNEL_B_KSU = "B_KSU"
    val CHANNELS: Set<String> = setOf(CHANNEL_A_DIRECT, CHANNEL_A_ULTRA, CHANNEL_B_KSU)
    private val ALPHABET = ("0123456789abcdefghijklmnopqrstuvwxyz" +
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ+-").toSet()

    /** null = 允许写；否则返回错误码。 */
    fun canWrite(enabled: Boolean, userConsented: Boolean, credential: ByteArray?): String? = when {
        !enabled -> "RECOVERY_SECRETS_DISABLED"
        !userConsented -> "RECOVERY_SECRETS_NO_CONSENT"
        credential == null || !isValidCredential(credential) -> "RECOVERY_SECRETS_INVALID_CREDENTIAL"
        else -> null
    }

    fun isValidCredential(credential: ByteArray): Boolean =
        credential.size == CREDENTIAL_SIZE &&
            credential.all { it.toInt().toChar() in ALPHABET }

    fun manifest(credential: ByteArray, at: Long, bootId: String, channel: String, userConsented: Boolean): SecretsManifest {
        require(channel in CHANNELS) { "RECOVERY_SECRETS_CHANNEL_INVALID" }
        require(isValidCredential(credential)) { "RECOVERY_SECRETS_INVALID_CREDENTIAL" }
        return SecretsManifest(
            credentialSha256 = Hashes.sha256(credential),
            writtenAt = at,
            bootId = bootId,
            channel = channel,
            userConsented = userConsented,
        )
    }

    /** 读回后校验：长度/字符集/sha 三者都必须过。 */
    fun verifyRead(credential: ByteArray, manifest: SecretsManifest): Boolean =
        isValidCredential(credential) && Hashes.sha256(credential) == manifest.credentialSha256
}
