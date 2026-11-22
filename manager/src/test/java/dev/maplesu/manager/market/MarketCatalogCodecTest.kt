package dev.maplesu.manager.market

import java.io.File
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class MarketCatalogCodecTest {
    @Test fun verifiesTheExactRawBytesBeforeParsing() {
        val fixture = MarketFixture()
        val bytes = fixture.catalog(fixture.module())
        val modules = fixture.parse(bytes)
        assertEquals("MixedCase_ID", modules.single().id)
        assertTrue(modules.single().installable)
        assertEquals("https://market.example.test/modules/packages/module.zip", modules.single().downloadUrls.single())
        rejects(MarketErrorCode.SIGNATURE_INVALID) {
            MarketCatalogCodec.parseVerified(bytes + '\n'.code.toByte(), fixture.sign(bytes), fixture.source, fixture.source.url)
        }
    }

    @Test fun rejectsInvalidSignatureBeforeAnInvalidJsonBody() {
        val fixture = MarketFixture()
        rejects(MarketErrorCode.SIGNATURE_INVALID) {
            MarketCatalogCodec.parseVerified("not JSON".toByteArray(), fixture.sign("other".toByteArray()), fixture.source, fixture.source.url)
        }
    }

    @Test fun rejectsACatalogSignedByAnUntrustedSelfDeclaredKey() {
        val trusted = MarketFixture()
        val attacker = MarketFixture()
        val bytes = JSONObject(String(attacker.catalog(attacker.module())))
            .put("public_key", attacker.key).toString().toByteArray()
        rejects(MarketErrorCode.SIGNATURE_INVALID) {
            MarketCatalogCodec.parseVerified(bytes, attacker.sign(bytes), trusted.source, trusted.source.url)
        }
    }

    @Test fun acceptsTheSignatureFilesTrailingNewline() {
        val fixture = MarketFixture()
        val bytes = fixture.catalog(fixture.module())
        assertEquals(1, MarketCatalogCodec.parseVerified(bytes, fixture.sign(bytes) + '\n'.code.toByte(), fixture.source, fixture.source.url).size)
    }

    @Test fun rejectsOversizedCatalogAndSignature() {
        val fixture = MarketFixture()
        rejects(MarketErrorCode.SIGNATURE_INVALID) {
            MarketCatalogCodec.verify(ByteArray(MarketCatalogCodec.MAX_CATALOG_BYTES + 1), byteArrayOf(1), fixture.key)
        }
        rejects(MarketErrorCode.SIGNATURE_INVALID) {
            MarketCatalogCodec.verify(byteArrayOf(1), ByteArray(MarketCatalogCodec.MAX_SIGNATURE_BYTES + 1), fixture.key)
        }
    }

    @Test fun requiresAnExplicitHttpsSourceAndP256Key() {
        val fixture = MarketFixture()
        for (url in listOf("http://market.example.test/market.json", "https://user:pass@market.example.test/market.json", "https://market.example.test/market.json#fragment"))
            rejects(MarketErrorCode.INVALID_SOURCE) { MarketCatalogCodec.source(url, fixture.key) }
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair()
        rejects(MarketErrorCode.INVALID_SOURCE) {
            MarketCatalogCodec.source(fixture.source.url, Base64.getEncoder().encodeToString(key.public.encoded))
        }
    }

    @Test fun doesNotCoerceImportantFieldTypes() {
        for ((field, value) in listOf("ver" to 123, "size" to "100", "size" to 100.5,
            "ban" to "false", "chn_name" to JSONObject(), "sha256" to JSONObject.NULL)) {
            val fixture = MarketFixture()
            rejects(MarketErrorCode.CATALOG_INVALID) { fixture.parse(fixture.catalog(fixture.module().put(field, value))) }
        }
    }

    @Test fun permitsMissingOptionalTextButRejectsInvalidOptionalTypes() {
        val fixture = MarketFixture()
        val module = fixture.module()
        for (field in listOf("eng_name", "desc", "author", "update_date", "source_url", "changelog_url", "download_chn_alert")) module.remove(field)
        val parsed = fixture.parse(fixture.catalog(module)).single()
        assertEquals("", parsed.englishName)
        assertEquals("", parsed.changelogUrl)
        assertEquals("", parsed.sourceUrl)
        rejects(MarketErrorCode.CATALOG_INVALID) { fixture.parse(fixture.catalog(module.put("eng_name", false))) }
    }

    @Test fun rejectsDuplicateIdsWithoutRequiring32HexCharacters() {
        val fixture = MarketFixture()
        rejects(MarketErrorCode.CATALOG_INVALID) { fixture.parse(fixture.catalog(fixture.module(), fixture.module())) }
        val lower = fixture.module().put("id32", "mixedcase_id")
        assertEquals(listOf("MixedCase_ID", "mixedcase_id"), fixture.parse(fixture.catalog(fixture.module(), lower)).map { it.id })
    }

    @Test fun retainsBannedAndNormalEntriesButDisablesTheirInstallAction() {
        val fixture = MarketFixture()
        val banned = fixture.module().put("ban", true)
        assertFalse(fixture.parse(fixture.catalog(banned)).single().installable)
        assertTrue(fixture.parse(fixture.catalog(banned)).single().banned)
        val normal = fixture.module().put("compatibility", JSONObject().put("modes", JSONArray().put("MapleSU_Normal")))
        assertFalse(fixture.parse(fixture.catalog(normal)).single().installable)
    }

    @Test fun acceptsUltraScriptModulesWithoutEnablingUnknownOrBannedTypes() {
        val fixture = MarketFixture()
        val script = fixture.module().put("type", "KERNEL_SU")
        assertTrue(fixture.parse(fixture.catalog(script)).single().installable)
        assertFalse(fixture.parse(fixture.catalog(script.put("ban", true))).single().installable)
        assertFalse(fixture.parse(fixture.catalog(fixture.module().put("type", "UNKNOWN"))).single().installable)
    }

    @Test fun acceptsNativeModulesWithCurrentAndPublishedCatalogTypeNames() {
        val fixture = MarketFixture()
        for (type in listOf("MAPLESU", dev.maplesu.manager.compat.StoredInputs.MODULE_TYPE)) {
            val module = fixture.module().put("type", type)
            val entry = fixture.parse(fixture.catalog(module)).single()
            assertEquals("MAPLESU", entry.type)
            assertTrue(entry.installable)
            assertFalse(fixture.parse(fixture.catalog(module.put("ban", true))).single().installable)
        }
    }

    @Test fun rejectsMismatchedPackageMetadata() {
        for ((field, value) in listOf("sha256" to "0".repeat(64), "size" to 1, "path" to "packages/other.zip")) {
            val fixture = MarketFixture()
            val module = fixture.module()
            module.getJSONObject("package").put(field, value)
            rejects(MarketErrorCode.CATALOG_INVALID) { fixture.parse(fixture.catalog(module)) }
        }
    }

    @Test fun rejectsResourcesOutsideTheConfiguredOriginAndDirectory() {
        for (path in listOf("../outside.zip", "https://other.example.test/module.zip", "http://market.example.test/modules/module.zip", "packages/a%2fb.zip", "packages/%2e%2e/%2e%2e/outside.zip")) {
            val fixture = MarketFixture()
            val module = fixture.module().put("download_url", path)
            module.getJSONObject("package").put("path", path)
            rejects(MarketErrorCode.CATALOG_INVALID) { fixture.parse(fixture.catalog(module)) }
        }
    }

    @Test fun realOfficialSignedCatalogPreservesEveryEntryAndExactIdentifier() {
        val file = listOf(File("../maplesu-module-market/market.json"), File("maplesu-module-market/market.json")).first { it.isFile }
        val bytes = file.readBytes()
        val source = MapleMarketRepository.officialSource()
        val parsed = MarketCatalogCodec.parseVerified(bytes, File(file.parentFile, "market.json.sig").readBytes(), source, source.url)
        val items = JSONObject(String(bytes)).getJSONArray("module_list")
        assertEquals(items.length(), parsed.size)
        assertEquals(List(items.length()) { items.getJSONObject(it).getString("id32") }, parsed.map { it.id })
        assertEquals(listOf("maplesu-tee", "c45e8a7390b24987a4b01d6e2c5f9143", "zygisk_lsposed", "hma_oss_zygisk"),
            parsed.take(4).map { it.id })
        assertTrue(parsed.take(4).all { it.installable })
    }

    @Test fun installedIdentityAliasIsBoundToTheVerifiedTeeArchive() {
        val fixture = MarketFixture()
        val module = fixture.parse(fixture.catalog(fixture.module())).single()
        val tee = module.copy(id = "maplesu-tee",
            sha256 = "dba45d22c7d721c6b1ea9c2ef6af981f7e1d2f98b3547875c3bd4f633fc826ef")
        assertEquals("maplesu-tee", tee.id)
        assertEquals("teesimulator601skpro202607210000", tee.installedModuleId)
        assertEquals("maplesu-tee", tee.copy(sha256 = "0".repeat(64)).installedModuleId)
        assertEquals("another_id", tee.copy(id = "another_id").installedModuleId)
        val screen = listOf(File("src/main/java/com/maplesu/core/ui/screen/maplemarket/MapleMarketScreen.kt"),
            File("manager/src/main/java/com/maplesu/core/ui/screen/maplemarket/MapleMarketScreen.kt")).first { it.isFile }.readText()
        assertTrue(screen.contains("installedVersions[selected.installedModuleId]"))
        assertTrue(screen.contains("installedVersions[module.installedModuleId]"))
    }

    @Test fun cacheIdentityIncludesBothSourceUrlAndTrustedKey() {
        val fixture = MarketFixture()
        assertNotEquals(MarketCatalogCodec.identity(fixture.source), MarketCatalogCodec.identity(fixture.source.copy(url = fixture.source.url + "?v=2")))
        assertNotEquals(MarketCatalogCodec.identity(fixture.source), MarketCatalogCodec.identity(fixture.source.copy(key = MarketFixture().key)))
    }

    @Test fun comparesOnlyReliableNumericVersions() {
        val module = MarketFixture().run { parse(catalog(module())).single() }
        assertTrue(module.copy(version = "v1.10.0").isNewerThan("1.9.9"))
        assertFalse(module.copy(version = "1.0").isNewerThan("V1.0.0"))
        assertFalse(module.copy(version = "6.0.1-r3").isNewerThan("6.0.1-r2"))
        assertFalse(module.copy(version = "1.2.3").isNewerThan("custom"))
        assertTrue(module.copy(version = "999999999999999999999999999999999.0").isNewerThan("2.0"))
    }

    private fun rejects(code: MarketErrorCode, block: () -> Unit) {
        try { block(); fail("Expected $code") }
        catch (error: MarketException) { assertEquals(error.message, code, error.code) }
    }
}
