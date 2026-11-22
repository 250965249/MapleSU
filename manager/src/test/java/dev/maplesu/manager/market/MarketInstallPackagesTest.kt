package dev.maplesu.manager.market

import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.modules.ModuleInstallBackend
import dev.maplesu.manager.modules.ModuleInstallRouter
import dev.maplesu.manager.modules.ModuleTypeDetector
import dev.maplesu.manager.workmode.WorkMode
import java.io.File
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class MarketInstallPackagesTest {
    @Test fun publishedPackagesKeepTheirIdentityAndUseTheCorrectInstaller() {
        val catalogFile = listOf(File("../maplesu-module-market/market.json"),
            File("maplesu-module-market/market.json")).first { it.isFile }
        val source = MapleMarketRepository.officialSource()
        val catalog = MarketCatalogCodec.parseVerified(catalogFile.readBytes(),
            File(catalogFile.parentFile, "market.json.sig").readBytes(), source, source.url)
        val entries = JSONObject(catalogFile.readText()).getJSONArray("module_list")
        for (index in 1..3) {
            val module = catalog[index]
            val entry = entries.getJSONObject(index)
            val archive = File(catalogFile.parentFile, entry.getJSONObject("package").getString("path"))
            val report = ModuleArchiveInspector.inspect(archive)
            assertTrue(module.installable)
            assertEquals(module.id, report.id)
            assertEquals(module.version, report.properties["version"])
            assertEquals(module.sha256, report.sha256)
            assertEquals(module.size, archive.length())
            val detected = ModuleTypeDetector.detect(report)
            val routing = ModuleInstallRouter.route(WorkMode.LITE, detected.type)
            assertTrue(routing.ok)
            assertEquals(if (module.type == "MAPLESU") ModuleInstallBackend.MAPLESU_ULTRA
                else ModuleInstallBackend.LITE_SCRIPT, routing.backend)
            ModuleArchiveInspector.verifyUnchanged(archive, report)
        }
    }
}
