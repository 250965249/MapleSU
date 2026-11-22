package dev.maplesu.manager.ultrakernel

import android.content.Context

/**
 * APK `assets/` implementation of [UltraKernelAssetSource]. This is the only Android touch point
 * of the release catalogue; everything else (meta parsing, gates, selection) runs on a plain JVM.
 */
internal class UltraKernelContextAssets(private val context: Context) : UltraKernelAssetSource {
    override fun list(directory: String): List<String> =
        context.assets.list(directory).orEmpty().toList()

    override fun read(path: String): ByteArray =
        context.assets.open(path).use { stream ->
            readBoundedAsset(stream, UltraKernelCatalog.MAX_ASSET_BYTES)
        }
}
