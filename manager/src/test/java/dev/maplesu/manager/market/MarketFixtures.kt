package dev.maplesu.manager.market

import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.json.JSONArray
import org.json.JSONObject

internal class MarketFixture {
    val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    val key: String = Base64.getEncoder().encodeToString(keyPair.public.encoded)
    val source = MarketCatalogCodec.source("https://market.example.test/modules/market.json", key)
    val packageBytes = ByteArrayOutputStream().also { bytes ->
        ZipOutputStream(bytes).use { zip ->
            zip.putNextEntry(ZipEntry("module.prop"))
            zip.write("id=MixedCase_ID\nname=Module\nversion=1.2.3\n".toByteArray())
            zip.closeEntry()
        }
    }.toByteArray()
    val hash = MessageDigest.getInstance("SHA-256").digest(packageBytes).joinToString("") { "%02x".format(it) }

    fun module(): JSONObject = JSONObject()
        .put("id32", "MixedCase_ID").put("chn_name", "测试模块").put("eng_name", "Module")
        .put("ver", "1.2.3").put("desc", "模块简介").put("author", "MapleSU").put("type", "MAPLESU")
        .put("update_date", "2026-11-01").put("download_chn_alert", "安装提示")
        .put("source_url", "sources/module/index.json").put("changelog_url", "changelogs/module.md")
        .put("compatibility", JSONObject().put("modes", JSONArray().put("MapleSU_Ultra")))
        .put("download_url", "packages/module.zip").put("sha256", hash).put("size", packageBytes.size)
        .put("package", JSONObject().put("path", "packages/module.zip").put("sha256", hash).put("size", packageBytes.size))

    fun catalog(vararg modules: JSONObject): ByteArray = JSONObject().put("schema_version", 1)
        .put("module_list", JSONArray(modules.toList())).toString().toByteArray()

    fun sign(bytes: ByteArray): ByteArray = Base64.getEncoder().encode(
        Signature.getInstance("SHA256withECDSA").run { initSign(keyPair.private); update(bytes); sign() })

    fun parse(bytes: ByteArray): List<MarketModule> = MarketCatalogCodec.parseVerified(bytes, sign(bytes), source, source.url)
}
