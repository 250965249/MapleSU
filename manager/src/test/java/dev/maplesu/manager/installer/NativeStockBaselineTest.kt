package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.service.RootModeSwitchEnvironmentLifecycle
import dev.maplesu.manager.workmode.switch.PatchMarkers
import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNotEquals
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class NativeStockBaselineTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test
    fun aPinnedOldKernelIsRecoveredBeforePublishingANewOriginalBaseline() {
        val sample = File("../evidence/ultra-reinstall-pairing-20261104/baseline-boot.img")
        assumeTrue(sample.isFile)
        val control = tmp.newFolder()
        val mirrors = tmp.newFolder()
        val sourceSha = Hashes.sha256(sample)
        val snapshot = InstallerSnapshot("6.6-device", "firmware-device", "_a", "Enforcing", mapOf(
            "boot" to BootPartitionSnapshot("boot", "/dev/block/by-name/boot_a", "/dev/block/boot",
                sample.length(), sourceSha)))
        val clean = BaselineCleanlinessPort { images, _, _ ->
            BaselineCleanReport(true, PatchMarkers(), images.keys.associateWith { true }, emptyList(), "")
        }
        val old = NativeStockBaseline.publish(snapshot, mapOf("boot" to sample), control, mirrors, clean)!!
        val original = NativeStockBaseline.originals(snapshot, tmp.newFolder(), control, mirrors, clean,
            dev.maplesu.manager.ultrakernel.UltraKernelFileAssets(File("src/main/assets")))!!
        assertEquals("c07fd486b563c370d2294f580be02fb5b24feaf4966932d3111d6a61b219f243",
            Hashes.sha256(original.getValue("boot")))
        val published = NativeStockBaseline.publish(snapshot, original, control, mirrors, clean)!!
        assertNotEquals(old, published)
        assertEquals(sourceSha, Hashes.sha256(File(old, "boot.img")))
        assertEquals(sourceSha, Hashes.sha256(File(mirrors, "${File(old).name}/boot.img")))
        assertEquals(Hashes.sha256(original.getValue("boot")), Hashes.sha256(File(published, "boot.img")))
        assertEquals(sourceSha, Hashes.sha256(sample))
    }

    @Test
    fun publicationPreservesCanonicalAndPermanentOriginalsAndReturnsTheDirectory() {
        val fixture = Fixture()
        val directory = fixture.publish()
        assertNotNull(directory)
        val canonical = File(directory!!)
        fixture.assertImages(canonical)
        fixture.assertImages(File(fixture.mirrors, canonical.name))
        val manifest = File(canonical, "manifest.json").readBytes()
        assertEquals(directory, fixture.publish())
        assertArrayEquals(manifest, File(canonical, "manifest.json").readBytes())
    }

    @Test
    fun reuseDependsOnSlotPartitionsAndIntegrityAcrossChangedRuntimeState() {
        val fixture = Fixture()
        val directory = fixture.publish()!!
        val manifest = File(directory, "manifest.json").readBytes()
        val changed = fixture.snapshot(kernel = "6.12-other-sdk", firmware = "ota-description-changed", selinux = "Permissive")
        val originals = fixture.originals(changed)
        assertNotNull(originals)
        fixture.images.forEach { (name, source) -> assertArrayEquals(source.readBytes(), originals!!.getValue(name).readBytes()) }
        assertEquals(directory, NativeStockBaseline.publish(changed, originals!!, fixture.control, fixture.mirrors, fixture.cleanliness))
        assertArrayEquals(manifest, File(directory, "manifest.json").readBytes())
        assertEquals(1, fixture.mirrors.list()!!.size)
    }

    @Test
    fun permanentMirrorRemainsUsableAfterTheEntireCanonicalTreeIsDeleted() {
        val fixture = Fixture()
        val originalDirectory = fixture.publish()!!
        val manifest = File(originalDirectory, "manifest.json").readBytes()
        assertTrue(fixture.control.deleteRecursively())
        val originals = fixture.originals()
        assertNotNull(originals)
        fixture.images.forEach { (name, source) -> assertArrayEquals(source.readBytes(), originals!!.getValue(name).readBytes()) }
        assertTrue(fixture.mirrors.isDirectory)
        assertEquals(originalDirectory, fixture.publish())
        assertArrayEquals(manifest, File(originalDirectory, "manifest.json").readBytes())
    }

    @Test
    fun wrongSlotOrMissingRequiredPartitionNeverYieldsAnOriginal() {
        val fixture = Fixture()
        val directory = File(fixture.publish()!!)
        assertNull(fixture.originals(fixture.snapshot(slot = "_b")))
        assertTrue(File(directory, "init_boot.img").delete())
        assertTrue(File(fixture.mirrors, "${directory.name}/init_boot.img").delete())
        assertNull(fixture.originals())
    }

    @Test
    fun explicitRestoreReadsOnlyProvenTargetsWithoutRelaxingFullBaselineReads() {
        for (target in setOf("boot", "init_boot")) {
            val fixture = Fixture()
            val directory = File(fixture.publish()!!)
            val other = if (target == "boot") "init_boot" else "boot"
            assertTrue(File(directory, "$other.img").delete())
            assertTrue(File(fixture.mirrors, "${directory.name}/$other.img").delete())
            assertNull(fixture.originals())
            val result = NativeStockBaseline.originalsForRestore(fixture.snapshot(), tmp.newFolder(), setOf(target),
                fixture.control, fixture.mirrors, fixture.cleanliness)
            assertNotNull(result)
            assertEquals(setOf(target), result!!.keys)
            assertArrayEquals(fixture.images.getValue(target).readBytes(), result.getValue(target).readBytes())
            assertNull(fixture.publish())
        }
    }

    @Test
    fun explicitRestoreRejectsMissingTargetAndEmptyTargets() {
        val fixture = Fixture()
        val directory = File(fixture.publish()!!)
        assertTrue(File(directory, "boot.img").delete())
        assertTrue(File(fixture.mirrors, "${directory.name}/boot.img").delete())
        assertNull(NativeStockBaseline.originalsForRestore(fixture.snapshot(), tmp.newFolder(), setOf("boot"),
            fixture.control, fixture.mirrors, fixture.cleanliness))
        assertNull(NativeStockBaseline.originalsForRestore(fixture.snapshot(), tmp.newFolder(), emptySet(),
            fixture.control, fixture.mirrors, fixture.cleanliness))
    }

    @Test
    fun imageDigestCorruptionInBothCopiesIsRejectedWithoutChangingTheInput() {
        val fixture = Fixture()
        val directory = File(fixture.publish()!!)
        listOf(directory, File(fixture.mirrors, directory.name)).forEach { root ->
            File(root, "boot.img").apply { writeBytes(readBytes().also { it[10] = (it[10] + 1).toByte() }) }
        }
        assertNull(fixture.originals())
        assertEquals("stock-boot", fixture.images.getValue("boot").readText().trimEnd('\u0000'))
    }

    @Test
    fun corruptManifestDigestIsRejectedEvenWhenItsImagesRemainUnchanged() {
        val fixture = Fixture()
        val directory = File(fixture.publish()!!)
        listOf(directory, File(fixture.mirrors, directory.name)).forEach { root ->
            File(root, "manifest.json.sha256").writeText("0".repeat(64))
        }
        assertNull(fixture.originals())
    }

    @Test
    fun anExistingPermanentMirrorIsNeverOverwrittenByPublication() {
        val fixture = Fixture()
        val directory = File(fixture.publish()!!)
        val permanent = File(fixture.mirrors, "${directory.name}/boot.img")
        permanent.writeText("keep-this-existing-original")
        assertNull(fixture.publish())
        assertEquals("keep-this-existing-original", permanent.readText())
        fixture.assertImages(directory)
    }

    @Test
    fun aDeviceWithoutInitBootUsesOnlyTheRequiredBootImage() {
        val fixture = Fixture(includeInitBoot = false)
        assertNotNull(fixture.publish())
        assertEquals(setOf("boot"), fixture.originals()!!.keys)
    }

    @Test
    fun reuseStopsAfterTheFirstVerifiedCandidateInsteadOfRescanningItsMirror() {
        val fixture = Fixture()
        assertNotNull(fixture.publish())
        fixture.cleanlinessCalls = 0
        assertNotNull(fixture.originals())
        assertEquals(1, fixture.cleanlinessCalls)
    }

    @Test
    fun cleanlinessFailureDoesNotPublishOrReturnTheImages() {
        val fixture = Fixture()
        fixture.clean = false
        assertNull(fixture.publish())
        assertNull(fixture.originals())
        assertTrue(!fixture.mirrors.exists() || fixture.mirrors.list()!!.isEmpty())
    }

    @Test
    fun lifecycleAndNativePublicationUseTheSamePermanentMirrorRoot() {
        val fixture = Fixture()
        assertEquals("/data/local/maplesu-recovery/originals",
            RootModeSwitchEnvironmentLifecycle.RECOVERY_ROOT + "/originals")
        assertNotNull(fixture.publish())
        assertTrue(fixture.mirrors.listFiles()!!.all { it.isDirectory && !it.name.startsWith('.') })
    }

    private inner class Fixture(includeInitBoot: Boolean = true) {
        val control: File = tmp.newFolder()
        val mirrors = File(tmp.newFolder(), "maplesu-recovery/originals")
        val images = buildMap {
            put("boot", File(tmp.newFolder(), "boot.img").apply { writeBytes("stock-boot".toByteArray().copyOf(128)) })
            if (includeInitBoot) put("init_boot", File(tmp.newFolder(), "init_boot.img").apply {
                writeBytes("stock-init-boot".toByteArray().copyOf(256))
            })
        }
        var clean = true
        var cleanlinessCalls = 0
        val cleanliness = BaselineCleanlinessPort { inputs, _, _ ->
            cleanlinessCalls++
            BaselineCleanReport(clean, PatchMarkers(), inputs.keys.associateWith { true }, emptyList(),
                if (clean) "" else "UNCLEAN_FIXTURE")
        }

        fun snapshot(
            slot: String = "_a",
            kernel: String = "6.6-stock",
            firmware: String = "firmware-1",
            selinux: String = "Enforcing",
        ) = InstallerSnapshot(kernel, firmware, slot, selinux, images.mapValues { (name, image) ->
            // Active partition hashes deliberately differ from the stored originals.
            BootPartitionSnapshot(name, "/dev/block/by-name/$name$slot", "/dev/block/$name", image.length(), "a".repeat(64))
        })

        fun publish() = NativeStockBaseline.publish(snapshot(), images, control, mirrors, cleanliness)
        fun originals(snapshot: InstallerSnapshot = snapshot()) =
            NativeStockBaseline.originals(snapshot, tmp.newFolder(), control, mirrors, cleanliness)

        fun assertImages(directory: File) {
            images.forEach { (name, source) ->
                assertArrayEquals(source.readBytes(), File(directory, "$name.img").readBytes())
                assertEquals(Hashes.sha256(source), Hashes.sha256(File(directory, "$name.img")))
            }
            assertTrue(File(directory, "manifest.json").isFile)
            assertTrue(File(directory, "manifest.json.sha256").isFile)
        }
    }
}
