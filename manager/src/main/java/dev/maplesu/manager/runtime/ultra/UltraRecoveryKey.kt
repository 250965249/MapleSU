// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.compat.StoredInputs
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object UltraRecoveryKey {
    const val KEY_LENGTH = 48
    const val MAGIC = "MAPLESU-RK2"
    private const val SALT = "maplesu-ultra-recovery-v2"
    private const val NONCE_BYTES = 12
    private const val GCM_TAG_BITS = 128
    private const val CIPHER = "AES/GCM/NoPadding"
    private const val MAX_PAYLOAD_CHARS = 4_096
    private val magicBytes = MAGIC.toByteArray(Charsets.US_ASCII)
    private val inputMagicBytes = StoredInputs.RECOVERY_MAGIC.toByteArray(Charsets.US_ASCII)
    private val random = SecureRandom()

    fun isValidKeyFormat(value: String?): Boolean {
        val text = value?.trim() ?: return false
        return text.length == KEY_LENGTH && text.all { it.code in 0x21..0x7e }
    }

    fun deriveKey(androidId: String?, packageName: String): ByteArray = deriveKey(SALT, androidId, packageName)

    private fun deriveKey(salt: String, androidId: String?, packageName: String): ByteArray =
        MessageDigest.getInstance("SHA-256")
            .digest("$salt|${androidId.orEmpty()}|${packageName.trim()}".toByteArray(Charsets.UTF_8))

    fun seal(key: String?, androidId: String?, packageName: String): String? {
        val text = key?.trim()
        if (!isValidKeyFormat(text)) return null
        return runCatching {
            val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
            val cipher = Cipher.getInstance(CIPHER)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(deriveKey(androidId, packageName), "AES"),
                GCMParameterSpec(GCM_TAG_BITS, nonce))
            Base64.getEncoder().encodeToString(magicBytes + nonce + cipher.doFinal(text!!.toByteArray(Charsets.UTF_8)))
        }.getOrNull()
    }

    fun open(payload: String?, androidId: String?, packageName: String): String? {
        val raw = decode(payload) ?: return null
        val salt = when {
            hasMagic(raw, magicBytes) -> SALT
            hasMagic(raw, inputMagicBytes) -> StoredInputs.RECOVERY_SALT
            else -> return null
        }
        if (raw.size <= magicBytes.size + NONCE_BYTES) return null
        return runCatching {
            val cipher = Cipher.getInstance(CIPHER)
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(deriveKey(salt, androidId, packageName), "AES"),
                GCMParameterSpec(GCM_TAG_BITS, raw, magicBytes.size, NONCE_BYTES))
            cipher.doFinal(raw, magicBytes.size + NONCE_BYTES, raw.size - magicBytes.size - NONCE_BYTES)
                .toString(Charsets.UTF_8).trim().takeIf(::isValidKeyFormat)
        }.getOrNull()
    }

    fun looksLikeRecoveryPayload(payload: String?): Boolean = decode(payload)?.let {
        hasMagic(it, magicBytes) || hasMagic(it, inputMagicBytes)
    } ?: false

    fun isCurrentPayload(payload: String?): Boolean = decode(payload)?.let { hasMagic(it, magicBytes) } ?: false

    private fun decode(payload: String?): ByteArray? {
        val text = payload?.trim()
        if (text.isNullOrEmpty() || text.length > MAX_PAYLOAD_CHARS ||
            !text.all { it.isLetterOrDigit() || it == '+' || it == '/' || it == '=' }) return null
        return runCatching { Base64.getDecoder().decode(text) }.getOrNull()
    }

    private fun hasMagic(raw: ByteArray, magic: ByteArray): Boolean =
        raw.size >= magic.size && magic.indices.all { raw[it] == magic[it] }
}
