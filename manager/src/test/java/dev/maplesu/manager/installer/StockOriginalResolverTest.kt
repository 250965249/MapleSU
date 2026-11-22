package dev.maplesu.manager.installer

import dev.maplesu.manager.ultrakernel.*
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class StockOriginalResolverTest {
    @get:Rule val temporary = TemporaryFolder()
    private val release = "6.6.89-android15-stock-fixture"

    @Test fun exactReceiptRestoresBeforeTryingAnotherSlotAndKeepsTheLivePreimage() {
        val f = fixture()
        val before = UltraKernelSpec.sha256(f.live)
        var alternateCalls = 0
        val resolved = StockOriginalResolver(f.assets, f.receipts, alternate = {
            alternateCalls++; error("alternate slot should not be read")
        }).resolve(f.snapshot, mapOf("boot" to f.live), temporary.newFolder())
        assertEquals("maplesu-receipt", resolved.family)
        assertEquals(ImageRestorationKind.EXACT_STOCK, resolved.kind)
        assertEquals("_a", resolved.sourceSlot)
        assertEquals(UltraKernelSpec.sha256(f.stock), UltraKernelSpec.sha256(resolved.originals.getValue("boot")))
        assertEquals(before, UltraKernelSpec.sha256(f.live))
        assertEquals(0, alternateCalls)
    }

    @Test fun explicitBootRestoreDoesNotRequireOrInspectTheNonTargetInitBoot() {
        val f = fixture()
        val companion = File(temporary.newFolder(), "third-party-init.img").apply { writeText("third-party-marker") }
        val snapshot = InstallerSnapshot(release, "firmware", "_a", "Enforcing", f.snapshot.partitions +
            ("init_boot" to BootPartitionSnapshot("init_boot", "", "", companion.length(), UltraKernelSpec.sha256(companion))))
        val result = StockOriginalResolver(f.assets, f.receipts).resolveForRestore(snapshot,
            mapOf("boot" to f.live, "init_boot" to companion), temporary.newFolder(), setOf("boot"))
        assertEquals(setOf("boot"), result.originals.keys)
        assertEquals(ImageRestorationKind.EXACT_STOCK, result.kind)
        assertArrayEquals(f.stock.readBytes(), result.originals.getValue("boot").readBytes())
        assertEquals("third-party-marker", companion.readText())
    }

    @Test fun explicitRestoreRejectsEmptyTargetsAndMissingTargetProof() {
        val f = fixture()
        assertError("INSTALLER_STOCK_TARGETS_INVALID") {
            StockOriginalResolver(f.assets, f.receipts).resolveForRestore(f.snapshot,
                mapOf("boot" to f.live), temporary.newFolder(), emptySet())
        }
        assertError("INSTALLER_STOCK_BACKUP_UNAVAILABLE") {
            StockOriginalResolver(null, null).resolveForRestore(f.snapshot,
                mapOf("boot" to f.stock), temporary.newFolder(), setOf("boot"))
        }
    }

    @Test fun historicalGeneratedBaselineIsRecoveredWithoutMutatingEitherPermanentCopy() {
        val f = fixture()
        val control = temporary.newFolder()
        val mirrors = temporary.newFolder()
        val clean = BaselineCleanlinessPort { images, _, _ ->
            BaselineCleanReport(true, dev.maplesu.manager.workmode.switch.PatchMarkers(),
                images.keys.associateWith { true }, emptyList(), "")
        }
        val directory = NativeStockBaseline.publish(f.snapshot, mapOf("boot" to f.live), control, mirrors, clean)!!
        val before = UltraKernelSpec.sha256(f.live)
        val restored = NativeStockBaseline.originals(f.snapshot, temporary.newFolder(), control, mirrors,
            clean, f.assets, receipts = f.receipts)!!
        assertEquals(UltraKernelSpec.sha256(f.stock), UltraKernelSpec.sha256(restored.getValue("boot")))
        assertEquals(before, UltraKernelSpec.sha256(File(directory, "boot.img")))
        assertEquals(before, UltraKernelSpec.sha256(File(mirrors, "${File(directory).name}/boot.img")))
        assertEquals(before, UltraKernelSpec.sha256(f.live))
    }

    @Test fun missingReceiptTriesTheOtherSlotWithoutChangingTheTargetSlot() {
        val f = fixture()
        f.receipts.listFiles()!!.filter { it.extension == "json" }.forEach { it.delete() }
        var calls = 0
        val result = StockOriginalResolver(f.assets, f.receipts, alternate = {
            calls++; AlternateSlotImages("_b", mapOf("boot" to f.stock))
        }).resolve(f.snapshot, mapOf("boot" to f.live), temporary.newFolder())
        assertEquals(1, calls)
        assertEquals("alternate-slot", result.family)
        assertEquals("_b", result.sourceSlot)
        assertEquals("_a", f.snapshot.slotSuffix)
        assertEquals(UltraKernelSpec.sha256(f.stock), UltraKernelSpec.sha256(result.originals.getValue("boot")))
    }

    @Test fun anExactlyProvenCompactOriginalIsZeroPaddedToTheActualPartitionSize() {
        val f = fixture(sourceSize = 12_288, partitionSize = 16_384)
        val result = StockOriginalResolver(f.assets, f.receipts).resolve(f.snapshot,
            mapOf("boot" to f.live), temporary.newFolder())
        assertEquals("maplesu-receipt", result.family)
        assertArrayEquals(f.stock.readBytes().copyOf(16_384), result.originals.getValue("boot").readBytes())
        assertEquals(UltraKernelSpec.sha256(f.live), f.snapshot.partitions.getValue("boot").sha256)
    }

    @Test fun previousOtaInTheOtherSlotIsRejectedEvenWhenTheSeriesAndSizeMatch() {
        val f = fixture()
        val old = File(temporary.newFolder(), "boot.img").apply {
            writeBytes(f.stock.readBytes().also { bytes ->
                val banner = "Linux version $release".toByteArray()
                val replacement = "Linux version ${release.replace("6.6.89", "6.6.66")}".toByteArray()
                replacement.copyInto(bytes, 4096 + 128)
                assertEquals(banner.size, replacement.size)
            })
        }
        assertError("INSTALLER_STOCK_SLOT_MISMATCH") {
            resolverWithoutReceipt(f, AlternateSlotImages("_b", mapOf("boot" to old)))
                .resolve(f.snapshot, mapOf("boot" to f.live), temporary.newFolder())
        }
    }

    @Test fun sameBannerAndMarkerlessRamdiskDoNotProveAnUnrecognisedKernelOriginal() {
        val f = fixture()
        val changed = File(temporary.newFolder(), "boot.img").apply {
            writeBytes(f.stock.readBytes().also { it[4096 + 2048] = 1 })
        }
        assertError("INSTALLER_STOCK_SLOT_UNVERIFIED") {
            resolverWithoutReceipt(f, AlternateSlotImages("_b", mapOf("boot" to changed)))
                .resolve(f.snapshot, mapOf("boot" to f.live), temporary.newFolder())
        }
    }

    @Test fun anotherSlotMayNotSupplyAnAlreadyPatchedKernel() {
        val f = fixture()
        assertError("INSTALLER_STOCK_SLOT_UNVERIFIED") {
            resolverWithoutReceipt(f, AlternateSlotImages("_b", mapOf("boot" to f.live)))
                .resolve(f.snapshot, mapOf("boot" to f.live), temporary.newFolder())
        }
    }

    @Test fun anotherSlotMustActuallyBeTheOppositeSlot() {
        val f = fixture()
        for (slot in listOf("_a", "", "_c")) assertError("INSTALLER_STOCK_SLOT_MISMATCH") {
            resolverWithoutReceipt(f, AlternateSlotImages(slot, mapOf("boot" to f.stock)))
                .resolve(f.snapshot, mapOf("boot" to f.live), temporary.newFolder())
        }
    }

    @Test fun slotlessDeviceDoesNotReadAnInventedSlot() {
        val f = fixture()
        val snapshot = InstallerSnapshot(release, "firmware", "", "Unknown", f.snapshot.partitions)
        var called = false
        f.receipts.listFiles()!!.filter { it.extension == "json" }.forEach { it.delete() }
        assertError("INSTALLER_STOCK_BACKUP_UNAVAILABLE") {
            StockOriginalResolver(f.assets, f.receipts, alternate = { called = true; null })
                .resolve(snapshot, mapOf("boot" to f.live), temporary.newFolder())
        }
        assertFalse(called)
    }

    @Test fun wrongPartitionSizeAndMissingCompanionCannotBecomeOriginals() {
        val f = fixture()
        val truncated = File(temporary.newFolder(), "boot.img").apply { writeBytes(f.stock.readBytes().copyOf(8192)) }
        assertError("INSTALLER_STOCK_SLOT_MISMATCH") {
            resolverWithoutReceipt(f, AlternateSlotImages("_b", mapOf("boot" to truncated)))
                .resolve(f.snapshot, mapOf("boot" to f.live), temporary.newFolder())
        }
        val snapshot = InstallerSnapshot(release, "firmware", "_a", "Unknown", f.snapshot.partitions +
            ("init_boot" to BootPartitionSnapshot("init_boot", "", "", 4096, "a".repeat(64))))
        assertError("INSTALLER_STOCK_SLOT_MISMATCH") {
            resolverWithoutReceipt(f, AlternateSlotImages("_b", mapOf("boot" to f.stock)))
                .resolve(snapshot, mapOf("boot" to f.live), temporary.newFolder())
        }
    }

    private fun resolverWithoutReceipt(f: Fixture, source: AlternateSlotImages): StockOriginalResolver {
        f.receipts.listFiles()!!.filter { it.extension == "json" }.forEach { it.delete() }
        return StockOriginalResolver(f.assets, f.receipts, alternate = { source })
    }

    private fun assertError(code: String, body: () -> Unit) {
        assertEquals(code, assertThrows(IllegalStateException::class.java, body).message)
    }

    private fun fixture(sourceSize: Int = 16_384, partitionSize: Int = sourceSize): Fixture {
        val directory = temporary.newFolder()
        val raw = ByteArray(8192).apply {
            "ARMd".toByteArray().copyInto(this, 56)
            "Linux version $release (fixture)".toByteArray().copyInto(this, 128)
        }
        val text = "#kernel=$release\n1024|00|01"
        val spec = UltraKernelSpec.parse(text)
        val assetPath = "ultra-kernels/releases/$release"
        val meta = buildJsonObject {
            put("schema", 1); put("kernelRelease", release); put("id", "fixture")
            put("spec", "fixture.spec"); put("specSha256", UltraKernelSpec.sha256(text.toByteArray()))
            put("patchCount", 1); put("baseKernelSha256", UltraKernelSpec.sha256(raw))
            put("expectedKernelSha256", UltraKernelSpec.sha256(spec.apply(raw).kernel))
            put("expectedImageSize", 16_384); put("verification", "experimental"); put("source", "model")
        }
        val assets = UltraKernelMemoryAssets(mapOf("$assetPath/meta.json" to meta.toString().toByteArray(),
            "$assetPath/fixture.spec" to text.toByteArray()))
        val stock = File(directory, "stock.img").apply {
            val image = ByteArray(sourceSize)
            ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN).apply {
                put("ANDROID!".toByteArray()); putInt(8, raw.size); putInt(20, 1584); putInt(40, 4)
            }
            raw.copyInto(image, 4096)
            writeBytes(image)
        }
        val receipts = File(directory, "receipts")
        val asset = UltraKernelReleaseCatalog.load(assets).assetsFor(release).single()
        val candidate = UltraKernelBuilder(receipts).generate(stock, asset, spec)
        val live = File(directory, "live.img").apply { writeBytes(candidate.image.readBytes().copyOf(partitionSize)) }
        return Fixture(stock, live, assets, receipts, InstallerSnapshot(release, "firmware", "_a", "Enforcing", mapOf(
            "boot" to BootPartitionSnapshot("boot", "/dev/block/by-name/boot_a", "/dev/block/boot", live.length(), UltraKernelSpec.sha256(live)))))
    }

    private class Fixture(val stock: File, val live: File, val assets: UltraKernelAssetSource,
        val receipts: File, val snapshot: InstallerSnapshot)
}
