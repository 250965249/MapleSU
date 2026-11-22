package com.maplesu.core.theme

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** A catalog endpoint is independent of theme authorship, UI skin and download mode. */
data class ThemeStoreSource(val id: String, val url: String) {
    val urls: List<String> get() = if (this == Maple) listOf(url, MAPLE_BACKUP) else listOf(url)

    companion object {
        val Maple = ThemeStoreSource("maplesu", "https://fengqiufq.github.io/maplesu-theme-market/index.json")
        val Fina = ThemeStoreSource("finasu", "https://folk.mysqil.com/api/themes")
        const val MAPLE_BACKUP = "https://raw.githubusercontent.com/FengQiuFQ/maplesu-theme-market/main/index.json"
        const val PREFERENCE = "theme_store_source"
        const val CUSTOM_URL = "theme_store_custom_url"

        fun custom(value: String): ThemeStoreSource {
            val url = requireNotNull(value.trim().toHttpUrlOrNull()) { "Invalid theme index URL" }
            require(url.isHttps && url.username.isEmpty() && url.password.isEmpty() && url.fragment == null) {
                "Use an HTTPS theme index URL without credentials or a fragment"
            }
            return ThemeStoreSource("custom", url.toString())
        }

        internal fun resolve(id: String?, customUrl: String): ThemeStoreSource = when (id) {
            Maple.id -> Maple
            "custom" -> custom(customUrl)
            else -> Fina
        }
    }
}
