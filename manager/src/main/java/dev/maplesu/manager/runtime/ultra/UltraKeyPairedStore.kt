package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.compat.ultraPreferences

import android.content.Context
import android.content.SharedPreferences
import java.security.MessageDigest

/**
 * 「配对已完成」标记：与 [dev.maplesu.manager.modules.UltraRootKeyStore] 共用 `maplesu-ultra`
 * SharedPreferences，只多一个 boolean `keyVerified`。
 *
 * 为什么需要它：绑定时要区分「用户填过 key」和「这次 key 已通过 bridge 校验并落盘」。
 * 过去这件事由 [dev.maplesu.manager.runtime.MapleSuCredentialStore.pair] 兼职（它开一个
 * UID-0 shell 再写 Keystore 凭据），而在 Ultra 内核上那条 `libmaplesu_runtime.so` 路径
 * 会触发系统重启。现在标记写入就是纯磁盘操作：**不加载 libmaplesu_runtime、不开任何 shell**。
 *
 * 注意：这个标记是「这个 key 曾通过 Running 校验或 Key 通道 uid-0 实测」的
 * 事实记录，**不是** root 能力的证明，也不参与任何鉴权判定。
 */
object UltraKeyPairedStore {
    private const val PREFS = "maplesu-ultra"
    private const val KEY = "keyVerified"
    private const val ROOT_KEY = "rootKey"
    private const val VERIFIED_KEY = "keyVerifiedFor"
    private const val INSTALL_TASK = "installCredentialTaskId"
    private const val INSTALL_KEY = "installCredentialForKey"
    private const val INSTALL_BOOT = "installCredentialSourceBoot"
    private const val INSTALL_PROVENANCE = "installCredentialProvenance"
    private const val INSTALL_AUTHORIZATION = "installAuthorizationObservedForKey"

    fun isPaired(context: Context): Boolean = context
        .ultraPreferences(PREFS, Context.MODE_PRIVATE)
        .getBoolean(KEY, false)

    fun markPaired(context: Context, verifiedKey: String? = null) {
        val prefs = context.ultraPreferences(PREFS, Context.MODE_PRIVATE)
        val key = verifiedKey ?: prefs.getString(ROOT_KEY, null)?.trim()
        check(prefs.edit()
            .putBoolean(KEY, true)
            .putString(VERIFIED_KEY, key?.let(::fingerprint))
            .commit()) { "ULTRA_PAIRING_STORE_FAILED" }
    }

    /** Called off-main only after bridge verification; one durable legacy-format record. */
    fun storeVerifiedKey(context: Context, key: String): Unit = synchronized(dev.maplesu.manager.modules.UltraRootKeyStore) {
        check(context.ultraPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(ROOT_KEY, key)
            .remove(UltraPendingInstallCredentialStore.RECORD)
            .remove(UltraPendingInstallCredentialStore.PREVIOUS_RECORD)
            .putBoolean(KEY, true)
            .putString(VERIFIED_KEY, fingerprint(key.trim()))
            .commit()) { "ULTRA_PAIRING_STORE_FAILED" }
    }

    /** Restoring a stopped environment keeps only a matching, previously verified identity. */
    fun storeRecoveredKey(context: Context, key: String): Unit = synchronized(dev.maplesu.manager.modules.UltraRootKeyStore) {
        val normalized = key.trim()
        val prefs = context.ultraPreferences(PREFS, Context.MODE_PRIVATE)
        val wasVerified = prefs.getBoolean(KEY, false) &&
            prefs.getString(VERIFIED_KEY, null) == fingerprint(normalized)
        val editor = prefs.edit().putString(ROOT_KEY, normalized)
        if (prefs.getString(ROOT_KEY, null)?.trim() != normalized) editor
            .remove(UltraPendingInstallCredentialStore.RECORD)
            .remove(UltraPendingInstallCredentialStore.PREVIOUS_RECORD)
        if (!wasVerified) editor.remove(KEY).remove(VERIFIED_KEY)
        check(editor.commit()) { "ULTRA_PAIRING_STORE_FAILED" }
    }

    /** A validated local install hands off a pending identity without replacing a user's key. */
    internal fun storeInstallKeyIfAbsent(context: Context, key: String, taskId: String,
                                         expectedInvalidKey: String? = null,
                                         expectedRemoval: String? = null,
                                         freshCandidate: Boolean = false): Boolean = storeInstallKeyIfAbsent(
        context.ultraPreferences(PREFS, Context.MODE_PRIVATE), key, taskId, expectedInvalidKey, expectedRemoval,
        UltraEnvironmentAutoSetup.currentBootId(), freshCandidate)

    internal fun storeInstallKeyIfAbsent(prefs: SharedPreferences, key: String, taskId: String,
                                         expectedInvalidKey: String? = null,
                                         expectedRemoval: String? = null,
                                         sourceBootId: String? = null,
                                         freshCandidate: Boolean = false): Boolean = synchronized(dev.maplesu.manager.modules.UltraRootKeyStore) {
        val current = prefs.getString(ROOT_KEY, null)?.takeIf { it.isNotBlank() }
        if (current != null && current != key && current != expectedInvalidKey ||
            prefs.getString("environmentRemoval", null) != expectedRemoval ||
            !prefs.getString("rootKeySuspended", null).isNullOrBlank()) return@synchronized false
        if (current == key) return@synchronized true
        val editor = prefs.edit()
            .remove(UltraPendingInstallCredentialStore.RECORD)
            .remove(UltraPendingInstallCredentialStore.PREVIOUS_RECORD)
            .putString(ROOT_KEY, key)
            .putString(INSTALL_TASK, taskId)
            .putString(INSTALL_KEY, fingerprint(key))
            .putString(INSTALL_BOOT, sourceBootId)
            .remove(INSTALL_AUTHORIZATION)
        if (freshCandidate && current == null && expectedInvalidKey == null && expectedRemoval == null)
            editor.putString(INSTALL_PROVENANCE, "fresh-candidate")
        else editor.remove(INSTALL_PROVENANCE)
        if (expectedRemoval != null) editor.remove("environmentRemoval")
        if (current != key) editor.remove(KEY).remove(VERIFIED_KEY)
        check(editor.commit()) { "ULTRA_PAIRING_STORE_FAILED" }
        true
    }

    /** Local installation provenance only; this flag never grants a runtime capability. */
    internal fun hasInstallKey(context: Context, taskId: String): Boolean = hasInstallKey(
        context.ultraPreferences(PREFS, Context.MODE_PRIVATE), taskId, UltraEnvironmentAutoSetup.currentBootId())

    internal fun hasInstallKey(prefs: SharedPreferences, taskId: String, currentBoot: String?): Boolean {
        val key = prefs.getString(ROOT_KEY, null)?.trim()?.takeIf(String::isNotEmpty) ?: return false
        val sourceBoot = prefs.getString(INSTALL_BOOT, null) ?: return false
        if (currentBoot == null) return false
        return prefs.getString(INSTALL_PROVENANCE, null) in setOf("fresh-candidate", "committed") &&
            sourceBoot != currentBoot && prefs.getString(INSTALL_TASK, null) == taskId &&
            prefs.getString(INSTALL_KEY, null) == fingerprint(key) &&
            prefs.getString(INSTALL_AUTHORIZATION, null) != fingerprint(key) &&
            prefs.getString("rootKeySuspended", null).isNullOrBlank() &&
            prefs.getString("environmentRemoval", null) == null
    }

    /** Records completed initialization work only; every SU use still consults the authority. */
    internal fun markInstallAuthorizationObserved(context: Context, expectedKey: String): Boolean =
        synchronized(dev.maplesu.manager.modules.UltraRootKeyStore) {
            val prefs = context.ultraPreferences(PREFS, Context.MODE_PRIVATE)
            if (prefs.getString(ROOT_KEY, null)?.trim() != expectedKey) return@synchronized false
            prefs.edit().putString(INSTALL_AUTHORIZATION, fingerprint(expectedKey)).commit()
        }

    /** Preparation remains distinct from a later boot accepting the exact image key. */
    internal fun hasPendingInstallKey(context: Context, taskId: String): Boolean {
        val prefs = context.ultraPreferences(PREFS, Context.MODE_PRIVATE)
        val key = prefs.getString(ROOT_KEY, null)?.trim()?.takeIf(String::isNotEmpty) ?: return false
        return !prefs.getBoolean(KEY, false) &&
            prefs.getString(INSTALL_TASK, null) == taskId &&
            prefs.getString(INSTALL_KEY, null) == fingerprint(key) &&
            prefs.getString("rootKeySuspended", null).isNullOrBlank()
    }

    fun clear(context: Context) {
        check(context.ultraPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .remove(KEY)
            .remove(VERIFIED_KEY)
            .commit()) { "ULTRA_PAIRING_STORE_FAILED" }
    }

    /** Legacy boolean-only records are upgraded after their next successful live probe. */
    fun matchesVerifiedKey(context: Context, key: String): Boolean {
        val prefs = context.ultraPreferences(PREFS, Context.MODE_PRIVATE)
        return prefs.getBoolean(KEY, false) &&
            prefs.getString(VERIFIED_KEY, null) == fingerprint(key)
    }

    private fun fingerprint(key: String): String = buildString(64) {
        val hex = "0123456789abcdef"
        MessageDigest.getInstance("SHA-256").digest(key.toByteArray(Charsets.UTF_8)).forEach { byte ->
            val value = byte.toInt() and 0xff
            append(hex[value ushr 4])
            append(hex[value and 0x0f])
        }
    }
}
