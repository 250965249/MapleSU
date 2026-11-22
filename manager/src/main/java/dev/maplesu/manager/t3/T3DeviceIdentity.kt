package dev.maplesu.manager.t3

import android.annotation.SuppressLint
import android.content.Context
import android.media.MediaDrm
import android.provider.Settings
import java.security.MessageDigest
import java.util.UUID

internal object T3DeviceIdentity {
    private val widevine = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")

    @SuppressLint("HardwareIds")
    fun resolve(context: Context): String? = derive(
        drmId = {
            MediaDrm(widevine).use { drm ->
                drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)
                    .takeIf { bytes -> bytes.isNotEmpty() && bytes.any { it != 0.toByte() } }
            }
        },
        androidId = { Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) },
    )

    internal fun derive(drmId: () -> ByteArray?, androidId: () -> String?): String? {
        val drm = runCatching(drmId).getOrNull()?.takeIf { it.isNotEmpty() && it.any { b -> b != 0.toByte() } }
        val source = if (drm != null) {
            "widevine:".toByteArray() + drm
        } else {
            val id = runCatching(androidId).getOrNull()?.trim()
                ?.takeIf { it.isNotBlank() && it != "9774d56d682e549c" && it.any { c -> c != '0' } }
                ?: return null
            "android:$id".toByteArray()
        }
        return MessageDigest.getInstance("SHA-256").digest(source)
            .take(16).joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}
