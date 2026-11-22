package dev.maplesu.manager.market

import java.io.IOException
import java.math.BigInteger

data class MarketModule(
    val id: String,
    val name: String,
    val englishName: String,
    val version: String,
    val description: String,
    val author: String,
    val type: String,
    val updatedAt: String,
    val sourceUrl: String,
    val downloadAlert: String,
    val compatibilityModes: List<String>,
    val sha256: String,
    val size: Long,
    val downloadUrls: List<String>,
    val changelogUrl: String,
    val installable: Boolean,
    val banned: Boolean = false,
    val changelogUrls: List<String> = emptyList(),
    val catalogIdentity: String = "",
) {
    /** Catalog aliases never replace a module's runtime identity. Bound to verified package bytes. */
    val installedModuleId: String
        get() = if (id == "maplesu-tee" &&
            sha256 == "dba45d22c7d721c6b1ea9c2ef6af981f7e1d2f98b3547875c3bd4f633fc826ef") {
            "teesimulator601skpro202607210000"
        } else id

    /** Suffixes such as -r3 have no universal ordering; leave those choices to the user. */
    fun isNewerThan(installedVersion: String): Boolean {
        fun parts(value: String): List<BigInteger>? {
            val normalized = value.trim().removePrefix("v").removePrefix("V")
            if (normalized.length > 128 || !Regex("[0-9]+(?:\\.[0-9]+)*").matches(normalized)) return null
            return normalized.split('.').map(::BigInteger)
        }
        val candidate = parts(version) ?: return false
        val installed = parts(installedVersion) ?: return false
        for (index in 0 until maxOf(candidate.size, installed.size)) {
            val comparison = (candidate.getOrNull(index) ?: BigInteger.ZERO)
                .compareTo(installed.getOrNull(index) ?: BigInteger.ZERO)
            if (comparison != 0) return comparison > 0
        }
        return false
    }
}

data class MarketSource(val url: String, val key: String, val isOfficial: Boolean)

data class MarketCatalog(
    val modules: List<MarketModule>,
    val stale: Boolean = false,
    val error: Throwable? = null,
)

enum class MarketErrorCode {
    INVALID_SOURCE, SIGNATURE_INVALID, CATALOG_INVALID, NETWORK,
    CACHE_INVALID, DOWNLOAD_INTEGRITY, MODULE_UNAVAILABLE,
}

class MarketException(
    val code: MarketErrorCode,
    message: String,
    cause: Throwable? = null,
) : IOException(message, cause)
