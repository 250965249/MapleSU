package dev.maplesu.manager.installer

import dev.maplesu.image.LenovoAvbSigner
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile
import dev.maplesu.manager.ultrakernel.UltraKernelMemoryAssets
import dev.maplesu.manager.ultrakernel.UltraKernelSpec
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class StockOriginalAvbTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun originalChainedBootIsVerifiedAgainstCurrentMainMetadata() {
        LenovoAvbSigner.verifyOriginals(mapOf("boot" to fixture("boot.img"), "vbmeta" to fixture("vbmeta.img")))
    }

    @Test fun directlyHashedInitBootIsAlsoCovered() {
        LenovoAvbSigner.verifyOriginals(mapOf("init_boot" to fixture("init_boot.img"),
            "vbmeta" to fixture("vbmeta-nonchained.img")))
    }

    @Test fun aValidUnrelatedSelfSignatureDoesNotReplaceMainCoverage() {
        val error = assertThrows(IOException::class.java) {
            LenovoAvbSigner.verifyOriginals(mapOf("boot" to fixture("boot-SHA256_RSA4096.img"),
                "vbmeta" to fixture("vbmeta.img")))
        }
        assertTrue(error.message!!.contains("CHAIN_KEY_MISMATCH_boot"))
    }

    @Test fun changingPayloadBytesIsRejectedWithoutChangingTheOriginal() {
        val boot = fixture("boot.img")
        val before = boot.readBytes()
        boot.writeBytes(before.copyOf().also { it[4096] = (it[4096].toInt() xor 1).toByte() })
        val error = assertThrows(IOException::class.java) {
            LenovoAvbSigner.verifyOriginals(mapOf("boot" to boot, "vbmeta" to fixture("vbmeta.img")))
        }
        assertTrue(error.message!!.contains("HASH_MISMATCH"))
    }

    @Test fun noMainMetadataCannotBeMistakenForAProof() {
        assertThrows(IOException::class.java) { LenovoAvbSigner.verifyOriginals(mapOf("boot" to fixture("boot.img"))) }
    }

    @Test fun aSignedOppositeSlotWorksWithoutAnyPackagedKernelPinOrLocalReceipt() {
        val (stock, main, live, snapshot) = signedSource()
        val result = StockOriginalResolver(UltraKernelMemoryAssets(emptyMap()), null, alternate = {
            AlternateSlotImages("_b", mapOf("boot" to stock, "vbmeta" to main))
        }).resolve(snapshot, mapOf("boot" to live), temporary.newFolder())
        assertEquals("alternate-slot", result.family)
        assertEquals("_b", result.sourceSlot)
        assertEquals(UltraKernelSpec.sha256(stock), UltraKernelSpec.sha256(result.originals.getValue("boot")))
    }

    @Test fun signedSameReleaseFromDifferentMainMetadataDoesNotBecomeACurrentOriginal() {
        val (stock, main, live, snapshot) = signedSource()
        main.appendBytes(byteArrayOf(0))
        val error = assertThrows(IllegalStateException::class.java) {
            StockOriginalResolver(UltraKernelMemoryAssets(emptyMap()), null, alternate = {
                AlternateSlotImages("_b", mapOf("boot" to stock, "vbmeta" to main))
            }).resolve(snapshot, mapOf("boot" to live), temporary.newFolder())
        }
        assertEquals("INSTALLER_STOCK_SLOT_UNVERIFIED", error.message)
    }

    private fun signedSource(): SignedSource {
        val release = "6.6.89-android15-signed-stock-fixture"
        val image = File(temporary.newFolder(), "input.img").apply {
            val bytes = ByteArray(16_384)
            ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).apply {
                put("ANDROID!".toByteArray()); putInt(8, 8192); putInt(20, 1584); putInt(40, 4)
            }
            "ARMd".toByteArray().copyInto(bytes, 4096 + 56)
            "Linux version $release (fixture)".toByteArray().copyInto(bytes, 4096 + 128)
            writeBytes(bytes)
        }
        val key = LenovoAvbSigner.decodeKey(fixture("testkey_rsa2048.pem").readBytes())
        val main = fixture("vbmeta.img")
        val signed = LenovoAvbSigner.sign(LenovoAvbSigner.Mode.CHAINED, "boot", image, fixture("boot.img"),
            mapOf("vbmeta" to main), File(temporary.newFolder(), "signed"), { key }, {})
        val stock = signed.getValue("boot")
        val live = File(temporary.newFolder(), "live.img").apply {
            writeBytes(stock.readBytes().also { it[4096 + 1024] = 1 })
        }
        val snapshot = InstallerSnapshot(release, "firmware", "_a", "Enforcing", mapOf(
            "boot" to BootPartitionSnapshot("boot", "", "", live.length(), UltraKernelSpec.sha256(live)),
            "vbmeta" to BootPartitionSnapshot("vbmeta", "", "", main.length(), UltraKernelSpec.sha256(main))))
        return SignedSource(stock, main, live, snapshot)
    }

    private data class SignedSource(val stock: File, val main: File, val live: File, val snapshot: InstallerSnapshot)

    private fun fixture(name: String): File {
        val file = File(temporary.root, name)
        if (!file.exists()) ZipFile("../image-core/src/test/resources/lenovo-avb-fixtures.zip").use { zip ->
            zip.getInputStream(zip.getEntry(name)).use { input -> file.outputStream().use(input::copyTo) }
        }
        return file
    }
}
