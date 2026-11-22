package dev.maplesu.manager.jailbreak

import org.junit.Assert.*
import org.junit.Test

class IrImagesL3FamilyTest {
    private val primary = IrImages.Module("l3/6.6.ko", "a".repeat(64), 100)
    private val current = IrImages.Module("l3/6.12.ko", "b".repeat(64), 120)

    @Test fun selects612WithoutReusingTheDefault66Module() {
        val inventory = IrImages.Inventory(null, emptyMap(), l3Module = primary,
            l3Modules = mapOf("android15-6.6" to primary, "android16-6.12" to current))
        assertEquals(current, inventory.l3For("6.12.58-android16-6-fixture"))
        assertEquals(current, inventory.l3For("6.12.99"))
        assertEquals(current, inventory.l3For("6.12.99-android17-1-fixture"))
        assertNull(inventory.l3For("6.1.25-android14-11-fixture"))
    }

    @Test fun parsesBothFamilyAssetsFromThePackagedManifest() {
        val inventory = IrImages.parseManifest("""{"ir":{
            "l3Module":{"asset":"l3/6.6.ko","sha256":"${primary.sha256}","bytes":100,"kmi":"android15-6.6"},
            "l3Modules":{"android16-6.12":{"asset":"l3/6.12.ko","sha256":"${current.sha256}","bytes":120}}
        }}""")
        assertEquals(current, inventory.l3For("6.12.58-android16-6-fixture"))
        assertEquals(primary, inventory.l3For("6.6.118-android15-8-fixture"))
        assertNull(inventory.l3For("6.18.21-android17-5-fixture"))
    }

    @Test fun legacyManifestWithOnly66IdentityDoesNotStageItFor612() {
        val inventory = IrImages.parseManifest("""{"ir":{"l3Module":{
            "asset":"l3/6.6.ko","sha256":"${primary.sha256}","bytes":100,"kmi":"android15-6.6"
        }}}""")
        assertNull(inventory.l3For("6.12.58-android16-6-fixture"))
    }

    @Test fun selectsEachPackagedKernelFamilyAndRejectsMissingFamilies() {
        val families = listOf("android13-5.15", "android14-6.1", "android15-6.6", "android16-6.12", "android17-6.18")
            .associateWith { IrImages.Module("l3/$it/maplesu_l3.ko", "a".repeat(64), 100) }
        val inventory = IrImages.Inventory(null, emptyMap(), l3Modules = families)
        assertTrue(inventory.hasL3)
        families.forEach { (family, module) ->
            assertEquals(module, inventory.l3For(family.substringAfter('-') + ".99-" + family.substringBefore('-') + "-1"))
        }
        assertNull(inventory.l3For("5.10.226-android12-9"))
        assertEquals(families["android13-5.15"], inventory.l3For("5.15.167-android13-8"))
        assertEquals(families["android13-5.15"], inventory.l3For("5.15.180"))
    }

    @Test fun selects510OnlyForItsMeasuredAndroidKmi() {
        val legacy = IrImages.Module("l3/android12-5.10/maplesu_l3.ko", "c".repeat(64), 140)
        val inventory = IrImages.Inventory(null, emptyMap(), l3Module = primary,
            l3Modules = mapOf("android15-6.6" to primary, "android12-5.10" to legacy))
        assertEquals(legacy, inventory.l3For("5.10.226-android12-9-fixture"))
        assertEquals(legacy, inventory.l3For("5.10.236-android12-9-fixture"))
        assertNull(inventory.l3For("5.10.245-android13-4-fixture"))
        assertNull(inventory.l3For("5.10.226"))
    }

    @Test fun unlabelledLegacyModuleDoesNotClaim510Support() {
        val inventory = IrImages.Inventory(null, emptyMap(), l3Module = primary)
        assertNull(inventory.l3For("5.10.226-android12-9-fixture"))
        assertNull(inventory.l3For("5.10"))
        assertEquals(primary, inventory.l3For("6.6.89-android15-8-fixture"))
    }
}
