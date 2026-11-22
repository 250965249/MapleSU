package dev.maplesu.manager.installer

import android.net.Uri
import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
data class VivoCompatibilityInputs(val vendorBoot: Uri? = null, val initBoot: Uri? = null) : Parcelable {
    // Both modes filter at boot time; additional images are optional cold removal inputs.
    fun ready(@Suppress("UNUSED_PARAMETER") needsInitBoot: Boolean) = true
}
