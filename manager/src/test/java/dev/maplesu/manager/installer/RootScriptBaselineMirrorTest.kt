package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.superuser.RootScriptRunner
import dev.maplesu.manager.workmode.switch.AvbFacts
import dev.maplesu.manager.workmode.switch.BaselineManifest
import dev.maplesu.manager.workmode.switch.BaselinePartition
import dev.maplesu.manager.workmode.switch.BaselineProvenance
import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import dev.maplesu.manager.workmode.switch.PatchMarkers
import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class RootScriptBaselineMirrorTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test
    fun initialPublicationStoresPermanentOriginalsBeforePublishingCanonical() {
        val fixture = Fixture()
        assertTrue(fixture.publish())
        fixture.assertOriginal(fixture.canonical)
        fixture.assertOriginal(fixture.mirror)
        assertTrue(fixture.scripts.single().indexOf("\"\$MTMP\" \"\$MIRROR\"") <
            fixture.scripts.single().indexOf("\"\$TMP\" \"\$DST\""))
    }

    @Test
    fun existingCanonicalAndPermanentCopiesAreNeverOverwritten() {
        val fixture = Fixture()
        assertTrue(fixture.publish())
        File(fixture.source, "boot.img").writeText("replacement")
        fixture.writeManifest("replacement-manifest")
        assertFalse(fixture.publish())
        fixture.assertOriginal(fixture.canonical)
        fixture.assertOriginal(fixture.mirror)
    }

    @Test
    fun republishingAfterControlDeletionUsesTheOriginalPermanentManifest() {
        val fixture = Fixture()
        assertTrue(fixture.publish())
        assertTrue(File(fixture.root, "control").deleteRecursively())
        fixture.writeManifest("new-request-metadata")
        assertTrue(fixture.publish())
        fixture.assertOriginal(fixture.canonical)
        fixture.assertOriginal(fixture.mirror)
    }

    @Test
    fun aCorruptPermanentImageIsRetainedAndNeverPromotedToCanonical() {
        val fixture = Fixture()
        assertTrue(fixture.publish())
        assertTrue(File(fixture.root, "control").deleteRecursively())
        File(fixture.mirror, "boot.img").writeText("damaged-original")
        assertFalse(fixture.publish())
        assertFalse(fixture.canonical.exists())
        assertEquals("damaged-original", File(fixture.mirror, "boot.img").readText())
    }

    @Test
    fun aCorruptManifestSidecarStopsPublicationBeforeEitherFinalCopyExists() {
        val fixture = Fixture()
        File(fixture.source, "manifest.json.sha256").writeText("0".repeat(64))
        assertFalse(fixture.publish())
        assertFalse(fixture.canonical.exists())
        assertFalse(fixture.mirror.exists())
    }

    @Test
    fun aSymbolicRecoveryParentIsRejectedBeforeAnyPermanentWrite() {
        val fixture = Fixture()
        val target = File(fixture.root, "unexpected").apply { mkdirs() }
        Files.createSymbolicLink(File(fixture.root, "recovery").toPath(), target.toPath())
        assertFalse(fixture.publish())
        assertTrue(target.list()!!.isEmpty())
        assertFalse(fixture.canonical.exists())
    }

    @Test
    fun bootOnlyDevicesPublishAndMirrorOnlyTheRequiredPartition() {
        val fixture = Fixture(includeInitBoot = false)
        assertTrue(fixture.publish())
        fixture.assertOriginal(fixture.canonical)
        fixture.assertOriginal(fixture.mirror)
        assertFalse(File(fixture.mirror, "init_boot.img").exists())
    }

    @Test
    fun aSourceImageMismatchLeavesNoCanonicalOrPermanentCopy() {
        val fixture = Fixture()
        val expected = fixture.expected()
        File(fixture.source, "boot.img").appendText("changed-after-hashing")
        assertFalse(fixture.bridge.publish(fixture.id, fixture.source, expected))
        assertFalse(fixture.canonical.exists())
        assertFalse(fixture.mirror.exists())
    }

    @Test
    fun probeRebuildsMissingCanonicalFromTheVerifiedPermanentMirror() {
        val fixture = Fixture()
        fixture.trustedManifest()
        assertTrue(fixture.publish())
        val originalManifest = File(fixture.mirror, "manifest.json").readBytes()
        assertTrue(File(fixture.root, "control").deleteRecursively())
        val restored = fixture.bridge.probe()!!
        assertEquals(listOf(fixture.id), restored.map { it.id })
        assertEquals("original-boot", File(fixture.canonical, "boot.img").readText())
        assertEquals(originalManifest.toList(), File(fixture.canonical, "manifest.json").readBytes().toList())
        assertEquals(originalManifest.toList(), File(fixture.mirror, "manifest.json").readBytes().toList())
        assertTrue(reusableBaselineEntry(restored, DeviceBootFacts("_a", "new-sdk-description", "6.12-active"),
            fixture.id, requireInitBoot = true) != null)
    }

    @Test
    fun probeDoesNotRestoreAnOriginalForAnotherSlot() {
        val fixture = Fixture()
        fixture.trustedManifest(slot = "_b")
        assertTrue(fixture.publish())
        assertTrue(File(fixture.root, "control").deleteRecursively())
        assertTrue(fixture.bridge.probe()!!.isEmpty())
        assertFalse(fixture.canonical.exists())
        assertTrue(fixture.mirror.exists())
    }

    @Test
    fun probeRejectsACorruptPermanentImageOrManifest() {
        val fixture = Fixture()
        fixture.trustedManifest()
        assertTrue(fixture.publish())
        assertTrue(File(fixture.root, "control").deleteRecursively())
        File(fixture.mirror, "boot.img").writeText("corrupt")
        assertTrue(fixture.bridge.probe()!!.isEmpty())
        assertFalse(fixture.canonical.exists())
        File(fixture.source, "boot.img").copyTo(File(fixture.mirror, "boot.img"), overwrite = true)
        File(fixture.mirror, "manifest.json.sha256").writeText("0".repeat(64))
        assertTrue(fixture.bridge.probe()!!.isEmpty())
        assertFalse(fixture.canonical.exists())
    }

    @Test
    fun probePreservesAnExistingCanonicalEvenIfItHasChanged() {
        val fixture = Fixture()
        fixture.trustedManifest()
        assertTrue(fixture.publish())
        File(fixture.canonical, "boot.img").writeText("retain-existing-canonical")
        fixture.bridge.probe()
        assertEquals("retain-existing-canonical", File(fixture.canonical, "boot.img").readText())
        assertEquals("original-boot", File(fixture.mirror, "boot.img").readText())
    }

    @Test
    fun probeRestoresABootOnlyOemOriginalWithoutInventingInitBoot() {
        val fixture = Fixture(includeInitBoot = false)
        fixture.trustedManifest()
        assertTrue(fixture.publish())
        assertTrue(File(fixture.root, "control").deleteRecursively())
        assertEquals(listOf(fixture.id), fixture.bridge.probe()!!.map { it.id })
        assertTrue(File(fixture.canonical, "boot.img").isFile)
        assertFalse(File(fixture.canonical, "init_boot.img").exists())
    }

    @Test
    fun probeRejectsASymbolicPermanentParentInsteadOfReadingThroughIt() {
        val fixture = Fixture()
        fixture.trustedManifest()
        assertTrue(fixture.publish())
        assertTrue(File(fixture.root, "control").deleteRecursively())
        val recovery = File(fixture.root, "recovery")
        val target = File(fixture.root, "retained-recovery")
        assertTrue(recovery.renameTo(target))
        Files.createSymbolicLink(recovery.toPath(), target.toPath())
        assertEquals(null, fixture.bridge.probe())
        assertFalse(fixture.canonical.exists())
    }

    private inner class Fixture(private val includeInitBoot: Boolean = true) {
        val root = tmp.newFolder()
        val source = tmp.newFolder()
        val id = "bl-a-stock"
        val canonical = File(root, "control/boot/baseline/$id")
        val mirror = File(root, "recovery/originals/$id")
        val scripts = mutableListOf<String>()
        val bridge = RootScriptBaselineBridge(RootScriptRunner(::execute),
            controlRoot = "/fixture/control", temporaryRoot = "/fixture/control/tmp",
            originalsRoot = "/fixture/recovery/originals", deviceSlot = { "_a" })

        init {
            File(source, "boot.img").writeText("original-boot")
            if (includeInitBoot) File(source, "init_boot.img").writeText("original-init-boot")
            writeManifest("original-manifest")
        }

        fun writeManifest(text: String) {
            val manifest = File(source, "manifest.json").apply { writeText(text) }
            File(source, "manifest.json.sha256").writeText(Hashes.sha256(manifest))
        }

        fun trustedManifest(slot: String = "_a") {
            writeManifest(ControlJsonCodec.encode(BaselineManifest(
                id = id, createdAt = 1L, provenance = BaselineProvenance.OEM_PACKAGE, clean = true,
                verifiedAt = 1L, slot = slot, firmware = "original-firmware", kernelRelease = "6.6-stock",
                partitions = expected().map { (name, hash) ->
                    BaselinePartition(name, File(source, "$name.img").length(), hash, true)
                }, avb = AvbFacts(false, verificationDisabled = false), patchMarkers = PatchMarkers(),
            )))
        }

        fun expected() = listOf("boot", "init_boot").filter { File(source, "$it.img").isFile }
            .associateWith { Hashes.sha256(File(source, "$it.img")) }
        fun publish() = bridge.publish(id, source, expected())

        fun assertOriginal(directory: File) {
            assertEquals("original-boot", File(directory, "boot.img").readText())
            if (includeInitBoot) assertEquals("original-init-boot", File(directory, "init_boot.img").readText())
            assertEquals("original-manifest", File(directory, "manifest.json").readText())
            assertEquals(Hashes.sha256(File(directory, "manifest.json")), File(directory, "manifest.json.sha256").readText())
        }

        fun execute(script: String): dev.maplesu.manager.workmode.superuser.RootScriptResult {
            scripts += script
            val mapped = script.replace("/system/bin/", "")
                .replace("'/fixture/", "'${root.absolutePath.replace('\\', '/')}/")
                .replace(source.absolutePath, source.absolutePath.replace('\\', '/'))
            val windows = System.getProperty("os.name", "").orEmpty().startsWith("Windows")
            val shell = if (windows) listOf("C:/Program Files/Git/bin/bash.exe", "--noprofile", "--norc", "-s")
                else listOf("/bin/sh", "-s")
            val process = ProcessBuilder(shell).redirectErrorStream(true).start()
            process.outputStream.bufferedWriter().use { it.write(mapped + "\n") }
            val output = process.inputStream.bufferedReader().readText()
            return dev.maplesu.manager.workmode.superuser.RootScriptResult(process.waitFor(), output)
        }
    }
}
