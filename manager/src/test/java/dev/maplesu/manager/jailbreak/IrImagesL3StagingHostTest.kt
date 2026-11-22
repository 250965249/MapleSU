package dev.maplesu.manager.jailbreak

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * L3 ABI v1 packaging -> staging contract, asserted on the host.
 *
 * <p>The staging write itself needs an Android `Context` (`AssetManager.open` plus
 * `Os.chmod`), so the decision surface and the wiring that binds it are checked here:
 *
 * 1. the model: `hasL3` is true only when the packaged manifest carries `l3Module`,
 *    and the stage-2 name and the "absent" marker are the fixed values the helper
 *    reads;
 * 2. the wiring: `IrImages.parseManifest` reads `l3Module` (not a copy of `root`),
 *    `stageHookModule` writes those bytes to `STAGE2_FILE`, and `DirtyfragAttempt`
 *    refuses only on `null` - so a build without an L3 module keeps the handover.
 *
 * <p>Source-level assertions are deliberate, in the style of `L3AbiSourceTest`: the
 * rule is structural ("the stage-2 slot may only ever carry the L3 bytes"), and the
 * method that would have to change to break it cannot run on the JVM.
 */
class IrImagesL3StagingHostTest {

    private val managerDir: File = sequenceOf(
        File("."), File("manager"), File("../manager"),
    ).map { it.absoluteFile.normalize() }
        .firstOrNull { File(it, "src/main/java").isDirectory }
        ?: error("cannot locate the manager module from " + File(".").absolutePath)

    private val repoRoot: File = managerDir.parentFile

    private val irImages = File(managerDir,
        "src/main/java/dev/maplesu/manager/jailbreak/IrImages.kt")
    private val dirtyfragAttempt = File(repoRoot,
        "jailbreak-providers/android/src/main/java/dev/maplesu/manager/jailbreak/DirtyfragAttempt.java")
    private val packagePy = File(repoRoot, "jailbreak-providers/package.py")

    private fun text(file: File): String {
        assertTrue("missing " + file.absolutePath, file.isFile)
        return file.readText(Charsets.UTF_8)
    }

    /** Whitespace-normalised source, so a re-indent does not fail a semantic assertion. */
    private fun normalized(file: File): String =
        text(file).replace(Regex("\\s+"), " ")

    /** The body of one Kotlin/Java method, from its declaration to the next method. */
    private fun body(source: String, marker: String, next: String): String {
        val start = source.indexOf(marker)
        assertTrue("source has no $marker", start >= 0)
        val end = source.indexOf(next, start + marker.length)
        return if (end > start) source.substring(start, end) else source.substring(start)
    }

    private val digest = "70566aa0f0fdc3845a3a841b35fe60aea2a71748637705472f954f63d95873e6"

    private val module = IrImages.Module("maplesu/ir/maplesu_ir.ko", digest, 15208)
    private val root = IrImages.Module("maplesu/root/maplesu_root.ko", digest, 9712)
    private val l3 = IrImages.Module("maplesu/l3/maplesu_l3.ko", digest, 12984)

    @Test
    fun `the stage-2 slot and the absent marker are the fixed values the helper reads`() {
        assertEquals("maplesu_stage2.ko", IrImages.STAGE2_FILE)
        // The helper decides by what it finds at the slot; the App must be able to say
        // "no kernel su" without inventing a digest.
        assertEquals("", IrImages.L3_ABSENT)
    }

    @Test
    fun `only a packaged l3 module arms su`() {
        val unarmed = IrImages.Inventory(module, emptyMap(), rootModule = root)
        assertNull(unarmed.l3Module)
        assertFalse("a root module alone must not arm su", unarmed.hasL3)

        val armed = IrImages.Inventory(module, emptyMap(),
            rootModule = root, l3Module = l3)
        assertNotNull(armed.l3Module)
        assertTrue(armed.hasL3)
        // The two slots are different products: the stage-2 copy is never the root
        // module under another name.
        assertEquals("maplesu/l3/maplesu_l3.ko", armed.l3Module!!.asset)
        assertEquals(12984L, armed.l3Module!!.bytes)
        assertTrue(armed.l3Module!!.asset != root.asset)
        assertTrue(armed.l3Module!!.bytes != root.bytes)
    }

    @Test
    fun `parse reads the l3Module key the packager writes`() {
        val parse = body(text(irImages), "fun parseManifest", "fun supports")
        val flat = parse.replace(Regex("\\s+"), " ")
        assertTrue(
            "parseManifest must read ir.l3Module (falling back to the document root)",
            flat.contains("""ir.optJSONObject("l3Module") ?: root.optJSONObject("l3Module")"""))
        assertTrue("the l3 block is parsed into the same Module shape as root",
            flat.contains("Module(asset = it.getString(\"asset\"), sha256 = it.getString(\"sha256\"), " +
                "bytes = it.getLong(\"bytes\"))"))
        assertTrue("the parser hands l3Module to the inventory",
            flat.contains("l3Module, l3Modules)"))
        // The packager's own statement of the key: both sides are named here so a
        // rename on either side is a test failure, not a manifest the App ignores.
        val packageSource = text(packagePy)
        assertTrue("package.py must write the l3Module key the parser reads",
            packageSource.contains("\"l3Module\": l3_block"))
    }

    @Test
    fun `the stage-2 slot is written from the l3 module, never from a root copy`() {
        val source = text(irImages)
        val flat = source.replace(Regex("\\s+"), " ")
        val stage = body(flat, "fun stageHookModule", "fun clear(")
        assertTrue("stageHookModule must read the packaged L3 block",
            stage.contains("val l3 = inventory.l3For(release)"))
        assertTrue("the staged bytes are the L3 asset, digest-verified",
            stage.contains("readVerified(context, l3.asset, l3.sha256, l3.bytes)"))
        assertTrue("those bytes go to the helper's fixed stage-2 name",
            stage.contains("write(directory, STAGE2_FILE, bytes)"))
        assertFalse("the stage-2 slot must not be filled from rootModule",
            stage.contains("rootModule.asset") || stage.contains("rootModule.sha256"))
        assertFalse("nor from the canary slot",
            stage.contains("canary.asset") || stage.contains("canary.sha256"))
        // A stale module from an earlier attempt cannot survive the no-L3 branch.
        assertTrue("a missing L3 module removes the stale stage-2 file",
            stage.contains("remove(directory, STAGE2_FILE)"))
    }

    @Test
    fun `ghostlock ultra stages the same kmi selected l3 and binds its digest`() {
        val handover = text(File(managerDir,
            "src/main/java/dev/maplesu/manager/jailbreak/GhostlockHandover.kt"))
        val ultra = handover.substringAfter("if (target == \"ultra\") {").substringBefore("} else {")
        assertTrue("Ghostlock must use the shared KMI selection",
            ultra.contains("IrImages.stageHookModule(context, directory)"))
        assertFalse("an existing Ghostlock root must not stage a second root module",
            ultra.contains("stageGhostlockRoot") || ultra.contains("rootModule"))
        assertTrue("the native helper must receive the selected L3 digest",
            handover.contains("stage2_sha256=\$rootDigest"))
    }

    @Test
    fun `a missing l3 module keeps the handover and only reports su unavailable`() {
        val flat = text(irImages).replace(Regex("\\s+"), " ")
        val stage = body(flat, "fun stageHookModule", "fun clear(")
        val absent = stage.indexOf("return L3_ABSENT")
        val refuse = stage.indexOf("if (inventory.rootModule == null && !inventory.isRootCanary) return null")
        assertTrue("the absent path exists", absent >= 0)
        assertTrue("refusing is the last resort, after the absent path", refuse >= 0 && refuse < absent)
        // The caller's gate is exactly `== null`, so the absent marker (a String) keeps
        // the attempt alive; only a build with no hook module at all is refused.
        val caller = text(dirtyfragAttempt).replace(Regex("\\s+"), " ")
        assertTrue("DirtyfragAttempt gates the handover on a null staging result",
            caller.contains("IrImages.stageHookModule(context, directory) == null"))
        assertTrue("and that branch is the MAPLESU_HOOK_NOT_PACKAGED refusal",
            Regex("stageHookModule\\(context, directory\\) == null\\)\\s*throw new IOException\\(" +
                "\"MAPLESU_HOOK_NOT_PACKAGED\"\\)").containsMatchIn(caller))
        assertEquals("the null gate appears exactly once", 1,
            Regex("IrImages\\.stageHookModule\\(").findAll(caller).count())
    }
}
