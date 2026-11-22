package com.maplesu.core.ui.util

import com.maplesu.core.ui.util.module.LatestVersionInfo
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject

internal const val MANAGER_UPDATE_URL =
    "https://api.github.com/repos/FengQiuFQ/MapleSU/releases/latest"

/** Same release endpoint and APK version-code convention as KernelSU. */
internal fun fetchLatestManagerVersion(client: OkHttpClient): LatestVersionInfo = runCatching {
    client.newCall(
        Request.Builder().url(MANAGER_UPDATE_URL)
            .header("Accept", "application/vnd.github+json")
            .build(),
    ).execute().use { response ->
        if (!response.isSuccessful) return@use LatestVersionInfo()
        parseManagerRelease(response.body.string())
    }
}.getOrDefault(LatestVersionInfo())

internal fun parseManagerRelease(body: String): LatestVersionInfo {
    val release = JSONObject(body)
    if (release.optBoolean("draft") || release.optBoolean("prerelease")) return LatestVersionInfo()
    val assets = release.optJSONArray("assets") ?: return LatestVersionInfo()
    val changelog = release.optString("body", "")
    val apkAssets = (0 until assets.length()).mapNotNull { assets.optJSONObject(it) }
        .filter { it.optString("name").endsWith(".apk") }
    // KSU publishes e.g. MapleSU_v5.1.10_50110-release.apk.
    for (asset in apkAssets) {
        val code = Regex("v(.+?)_(\\d+)-").find(asset.optString("name"))
            ?.groupValues?.get(2)?.toIntOrNull() ?: continue
        val url = asset.optString("browser_download_url")
        if (code > 0 && url.isNotBlank()) return LatestVersionInfo(code, url, changelog)
    }
    // Also support plain manager-release.apk releases tagged with MapleSU's x.y.z version.
    val version = Regex("v?(\\d+)\\.(\\d+)\\.(\\d+)").matchEntire(release.optString("tag_name"))
        ?: return LatestVersionInfo()
    val (major, minor, patch) = version.destructured
    val parts = listOf(major, minor, patch).map { it.toLongOrNull() ?: return LatestVersionInfo() }
    if (parts[0] > Int.MAX_VALUE / 10_000 || parts[1] > 99 || parts[2] > 99) return LatestVersionInfo()
    val code = parts[0] * 10_000 + parts[1] * 100 + parts[2]
    if (code !in 1..Int.MAX_VALUE.toLong()) return LatestVersionInfo()
    val asset = apkAssets.firstOrNull { it.optString("browser_download_url").isNotBlank() }
        ?: return LatestVersionInfo()
    return LatestVersionInfo(code.toInt(), asset.getString("browser_download_url"), changelog)
}
