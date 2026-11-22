package dev.maplesu.manager.installer

import android.net.Uri
import android.os.Parcelable
import dev.maplesu.image.LenovoAvbSigner
import kotlinx.parcelize.Parcelize

/** Immutable per-attempt choices. Fingerprint detection is a convenience, not a prerequisite. */
@Parcelize
data class LenovoSigningOptions(
    val enabled: Boolean = false,
    val aosp: Boolean = false,
    val vbmeta: Uri? = null,
    val recovery: Uri? = null,
    val vbmetaSystem: Uri? = null,
) : Parcelable {
    fun mode(partition: String): LenovoAvbSigner.Mode = when (partition) {
        "boot" -> if (aosp) LenovoAvbSigner.Mode.AOSP else LenovoAvbSigner.Mode.CHAINED
        "init_boot" -> LenovoAvbSigner.Mode.NON_CHAINED
        else -> error("LENOVO_AVB_PARTITION_INVALID")
    }

    fun requiredImages(partition: String): List<String> = when {
        !enabled -> emptyList()
        mode(partition) == LenovoAvbSigner.Mode.AOSP -> listOf("recovery", "vbmeta_system", "vbmeta")
        mode(partition) == LenovoAvbSigner.Mode.NON_CHAINED -> listOf("vbmeta")
        else -> emptyList()
    }

    fun uri(name: String): Uri? = when (name) {
        "vbmeta" -> vbmeta
        "recovery" -> recovery
        "vbmeta_system" -> vbmetaSystem
        else -> null
    }

    fun fileInputsReady(partition: String): Boolean =
        (!enabled || partition in setOf("boot", "init_boot") && requiredImages(partition).all { uri(it) != null })
}

internal fun lenovoFingerprint(fingerprint: String?): Boolean = fingerprint?.startsWith("LENOVO", ignoreCase = true) == true
