package dev.maplesu.manager.market

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONArray
import org.json.JSONObject

/** The key and mirror roots are trusted app configuration, never accepted from the manifest. */
internal object MarketCatalogCodec {
    const val MAX_CATALOG_BYTES = 4 * 1024 * 1024
    const val MAX_SIGNATURE_BYTES = 1024
    const val MAX_CHANGELOG_BYTES = 512 * 1024
    const val MAX_MODULE_BYTES = 256L * 1024 * 1024
    const val OFFICIAL_URL = "https://fengqiufq.github.io/maplesu-module-market/market.json"
    const val OFFICIAL_BACKUP_URL = "https://raw.githubusercontent.com/FengQiuFQ/maplesu-module-market/main/market.json"
    const val OFFICIAL_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP+Ef8XU/21h7ZRK8ugZo9wSf4jiA4tcs97Uk4bHaCcQ4/z+zZGg83Uf3gTbhSrYtuB6x2rXqzF04KmYmNOrcLw=="

    fun source(url: String, key: String, official: Boolean = false): MarketSource {
        val parsed = httpsUrl(url.trim())
        val normalizedKey = key.trim()
        publicKey(normalizedKey)
        return MarketSource(parsed.toString(), normalizedKey,
            official && parsed.toString() == OFFICIAL_URL && normalizedKey == OFFICIAL_KEY)
    }

    fun endpoints(source: MarketSource): List<String> =
        if (source.isOfficial && source.url == OFFICIAL_URL && source.key == OFFICIAL_KEY)
            listOf(OFFICIAL_URL, OFFICIAL_BACKUP_URL) else listOf(source.url)

    fun identity(source: MarketSource): String = sha256((source.url + "\n" + source.key).toByteArray())

    fun signatureUrl(catalogUrl: String): String = httpsUrl(catalogUrl).newBuilder()
        .encodedPath(httpsUrl(catalogUrl).encodedPath + ".sig").build().toString()

    fun verify(bytes: ByteArray, signature: ByteArray, key: String) {
        if (bytes.isEmpty() || bytes.size > MAX_CATALOG_BYTES || signature.isEmpty() ||
            signature.size > MAX_SIGNATURE_BYTES) fail(MarketErrorCode.SIGNATURE_INVALID, "市场清单或签名大小异常")
        try {
            val encoded = ascii(signature).trim()
            val decoded = Base64.getDecoder().decode(encoded)
            if (decoded.size !in 8..80) fail(MarketErrorCode.SIGNATURE_INVALID, "市场清单签名格式异常")
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(publicKey(key))
            verifier.update(bytes)
            if (!verifier.verify(decoded)) fail(MarketErrorCode.SIGNATURE_INVALID, "市场清单签名校验失败")
        } catch (error: MarketException) {
            throw error
        } catch (error: Exception) {
            throw MarketException(MarketErrorCode.SIGNATURE_INVALID, "市场清单签名校验失败", error)
        }
    }

    fun parseVerified(bytes: ByteArray, signature: ByteArray, source: MarketSource, catalogUrl: String): List<MarketModule> {
        verify(bytes, signature, source.key)
        if (catalogUrl !in endpoints(source)) fail(MarketErrorCode.INVALID_SOURCE, "市场来源与可信地址不一致")
        try {
            val root = JSONObject(utf8(bytes))
            if (integer(root, "schema_version") != 1L) invalid("不支持的市场清单版本")
            val entries = root.get("module_list") as? JSONArray ?: invalid("模块列表格式异常")
            if (entries.length() > 1000) invalid("市场模块数量异常")
            val ids = HashSet<String>()
            val bases = (listOf(catalogUrl) + endpoints(source)).distinct()
            return List(entries.length()) { index ->
                val item = entries.get(index) as? JSONObject ?: invalid("模块条目格式异常")
                val id = text(item, "id32", 128, required = true)
                if (!Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}").matches(id) || !ids.add(id)) invalid("模块标识重复或无效")
                val type = text(item, "type", 64, required = true).let {
                    dev.maplesu.manager.compat.StoredInputs.moduleType(it)
                }
                val hash = text(item, "sha256", 64, required = true).lowercase()
                if (!Regex("[0-9a-f]{64}").matches(hash)) invalid("模块摘要格式异常")
                val size = integer(item, "size")
                if (size !in 1..MAX_MODULE_BYTES) invalid("模块大小超出安装器限制")
                val compatibility = item.get("compatibility") as? JSONObject ?: invalid("兼容模式格式异常")
                val modes = compatibility.get("modes") as? JSONArray ?: invalid("兼容模式格式异常")
                if (modes.length() !in 1..16) invalid("兼容模式格式异常")
                val modeNames = List(modes.length()) { modeIndex ->
                    (modes.get(modeIndex) as? String)?.takeIf { it.length in 1..64 }
                        ?: invalid("兼容模式格式异常")
                }
                val banned = if (!item.has("ban")) false else item.get("ban") as? Boolean ?: invalid("停用标记格式异常")
                val download = text(item, "download_url", 2048, required = true)
                val archive = item.get("package") as? JSONObject ?: invalid("模块包信息缺失")
                if (text(archive, "sha256", 64, required = true).lowercase() != hash ||
                    integer(archive, "size") != size || text(archive, "path", 2048, required = true) != download)
                    invalid("模块包信息不一致")
                val mirrors = item.opt("mirrors")?.let { it as? JSONObject ?: invalid("镜像格式异常") }
                val paths = listOf(download) + listOfNotNull(mirrors?.let { text(it, "primary", 2048, true) },
                    mirrors?.let { text(it, "backup", 2048, true) })
                val downloadUrls = bases.flatMap { base -> paths.map { resource(base, it) } }.distinct()
                val changelog = text(item, "changelog_url", 2048)
                val changelogs = if (changelog.isEmpty()) emptyList() else bases.map { resource(it, changelog) }.distinct()
                val sourcePath = text(item, "source_url", 2048)
                MarketModule(
                    id = id, name = text(item, "chn_name", 256, required = true),
                    englishName = text(item, "eng_name", 256), version = text(item, "ver", 128, required = true),
                    description = text(item, "desc", 16_384), author = text(item, "author", 256),
                    type = type, updatedAt = text(item, "update_date", 64),
                    sourceUrl = if (sourcePath.isEmpty()) "" else resource(catalogUrl, sourcePath),
                    downloadAlert = text(item, "download_chn_alert", 16_384),
                    compatibilityModes = modeNames, sha256 = hash, size = size, downloadUrls = downloadUrls,
                    changelogUrl = changelogs.firstOrNull().orEmpty(),
                    installable = !banned && type in setOf("MAPLESU", "KERNEL_SU") && "MapleSU_Ultra" in modeNames,
                    banned = banned, changelogUrls = changelogs, catalogIdentity = identity(source),
                )
            }
        } catch (error: MarketException) {
            throw error
        } catch (error: Exception) {
            throw MarketException(MarketErrorCode.CATALOG_INVALID, "市场清单格式异常", error)
        }
    }

    fun allowedResource(url: String, catalogs: List<String>): Boolean = runCatching {
        val parsed = httpsUrl(url)
        catalogs.any { catalog ->
            val root = httpsUrl(catalog).resolve("./")!!
            parsed.host == root.host && parsed.port == root.port &&
                parsed.encodedPath.startsWith(root.encodedPath) &&
                parsed.pathSegments.none { it == "." || it == ".." || it.any { char -> char == '/' || char == '\\' || char.code < 32 } }
        }
    }.getOrDefault(false)

    fun httpsUrl(value: String): HttpUrl {
        val url = value.toHttpUrlOrNull()
        if (url == null || !url.isHttps || url.username.isNotEmpty() || url.password.isNotEmpty() || url.fragment != null)
            fail(MarketErrorCode.INVALID_SOURCE, "市场地址需为不含账号或片段的 HTTPS 地址")
        return url
    }

    fun utf8(bytes: ByteArray): String = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString()

    private fun ascii(bytes: ByteArray): String = Charsets.US_ASCII.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString()

    private fun resource(catalogUrl: String, path: String): String {
        val resolved = httpsUrl(catalogUrl).resolve(path)?.toString() ?: invalid("模块资源地址无效")
        if (!allowedResource(resolved, listOf(catalogUrl))) invalid("模块资源需位于市场来源目录内")
        return resolved
    }

    private fun publicKey(encoded: String): ECPublicKey {
        try {
            if (encoded.length !in 1..1024) fail(MarketErrorCode.INVALID_SOURCE, "请填写 P-256 公钥")
            val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(encoded))) as? ECPublicKey
                ?: fail(MarketErrorCode.INVALID_SOURCE, "市场公钥类型不正确")
            val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(ECParameterSpec::class.java)
            if (key.params.curve != parameters.curve || key.params.generator != parameters.generator ||
                key.params.order != parameters.order || key.params.cofactor != parameters.cofactor)
                fail(MarketErrorCode.INVALID_SOURCE, "市场公钥需使用 P-256")
            return key
        } catch (error: MarketException) {
            throw error
        } catch (error: Exception) {
            throw MarketException(MarketErrorCode.INVALID_SOURCE, "市场公钥格式异常", error)
        }
    }

    private fun text(json: JSONObject, key: String, limit: Int, required: Boolean = false): String {
        if (!json.has(key) && !required) return ""
        val value = json.get(key) as? String ?: invalid("市场字段 $key 需为文字")
        if (value.length > limit || value.any { it == '\u0000' } || (required && value.isBlank())) invalid("市场字段 $key 无效")
        return value
    }

    private fun integer(json: JSONObject, key: String): Long = when (val value = json.get(key)) {
        is Int -> value.toLong()
        is Long -> value
        else -> invalid("市场字段 $key 需为整数")
    }

    private fun invalid(message: String): Nothing = fail(MarketErrorCode.CATALOG_INVALID, message)
    private fun fail(code: MarketErrorCode, message: String): Nothing = throw MarketException(code, message)

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }
}
