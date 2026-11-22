package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * Host regression for the pre-entry baseline (step-4 D2, design §2.1/§2.1.3).
 *
 * <p>The dangerous mistake here is not a crash, it is a *label*: if the App's own
 * reading is reported as the kernel's saved value, the evidence says "KERNEL_SAVED"
 * while the number came from a subject that could not read selinuxfs at all. So the two
 * properties below are pinned exactly:
 *
 * <ol>
 *   <li>[HookEnv.decide] is the whole decision, and it never invents a value it did not
 *       observe (a permissive boot keeps permissive; everything else is the documented
 *       baseline `1`);</li>
 *   <li>the line the helper parses is byte-for-byte the frozen five-key format, is
 *       within the helper's 192-byte bound, and is `0600` so the helper's `fstat`
 *       accepts it.</li>
 * </ol>
 */
class HookEnvHostTest {

    // -- decide: the four cases in design §3.5 item 21 -------------------------- //
    @Test
    fun `a real selinuxfs reading is used and labelled observed`() {
        assertEquals(HookEnv.Decision(0, HookEnv.SOURCE_OBSERVED),
            HookEnv.decide(0, "enforcing"))
        assertEquals(HookEnv.Decision(1, HookEnv.SOURCE_OBSERVED),
            HookEnv.decide(1, "permissive"))
    }

    @Test
    fun `a permissive boot keeps permissive, not the enforcing baseline`() {
        assertEquals(HookEnv.Decision(0, HookEnv.SOURCE_BASELINE),
            HookEnv.decide(-1, "permissive"))
        assertEquals(HookEnv.Decision(0, HookEnv.SOURCE_BASELINE),
            HookEnv.decide(-1, "PERMISSIVE"))
    }

    @Test
    fun `an unreadable property falls back to the documented baseline`() {
        assertEquals(HookEnv.Decision(1, HookEnv.SOURCE_BASELINE),
            HookEnv.decide(-1, "enforcing"))
        // R-D5: the hidden-API reflection may simply fail; that must not become "0".
        assertEquals(HookEnv.Decision(1, HookEnv.SOURCE_BASELINE),
            HookEnv.decide(-1, null))
        assertEquals(HookEnv.Decision(1, HookEnv.SOURCE_BASELINE),
            HookEnv.decide(-1, ""))
    }

    @Test
    fun `an impossible value is not observed`() {
        // Only 0 and 1 are readings; anything else is "no reading" and takes the
        // baseline branch, never the observed label.
        assertEquals(HookEnv.SOURCE_BASELINE, HookEnv.decide(7, null).source)
        assertEquals(HookEnv.SOURCE_BASELINE, HookEnv.decide(-2, null).source)
    }

    // -- the frozen line -------------------------------------------------------- //
    @Test
    fun `the line is exactly the five-key format`() {
        val line = HookEnv.line(ATTEMPT, BOOT, HookEnv.Decision(1, HookEnv.SOURCE_BASELINE))
        assertEquals("schema=maplesu.hook.env.v1 boot=$BOOT attempt=$ATTEMPT " +
            "expected=1 source=baseline", line)
        // The helper refuses anything it cannot parse in this order.
        val keys = line.split(" ").map { it.substringBefore("=") }
        assertEquals(listOf("schema", "boot", "attempt", "expected", "source"), keys)
        assertTrue(line.toByteArray(Charsets.UTF_8).size <= HookEnv.MAX_BYTES)
        assertFalse(line.contains("\n"))
    }

    @Test
    fun `every decided value round-trips as a parsable line`() {
        for (decision in listOf(HookEnv.decide(0, null), HookEnv.decide(1, null),
            HookEnv.decide(-1, "permissive"), HookEnv.decide(-1, "enforcing"))) {
            val line = HookEnv.line(ATTEMPT, BOOT, decision)
            assertTrue(line.endsWith("source=${decision.source}"))
            assertTrue(line.contains("expected=${decision.expected}"))
            assertTrue(line.toByteArray(Charsets.UTF_8).size <= HookEnv.MAX_BYTES)
        }
    }

    @Test
    fun `write produces the frozen line with a trailing newline and no group bits`() {
        val directory = Files.createTempDirectory("hook-env").toFile()
        try {
            assertTrue(HookEnv.write(directory, ATTEMPT, BOOT, -1))
            val file = File(directory, HookEnv.FILE)
            assertTrue(file.isFile)
            val text = file.readText()
            assertTrue("line must end with a newline: " + text, text.endsWith("\n"))
            assertEquals(1, text.count { it == '\n' })
            assertTrue(text.startsWith("schema=maplesu.hook.env.v1 boot=$BOOT attempt=$ATTEMPT "))
            assertEquals(1, Regex("expected=(0|1|-1)").findAll(text).count())
            assertEquals(1, Regex("source=(observed|baseline|unknown)").findAll(text).count())
            // `(mode & 0077) == 0` is what the helper's fstat enforces. Windows hosts have
            // no POSIX attribute view (the App that writes this file is Linux), so the
            // assertion is made only where the filesystem can express it.
            if (file.toPath().fileSystem.supportedFileAttributeViews().contains("posix")) {
                assertTrue("group/other bits set: " + file, HookEnv.permissionsOk(file))
            } else {
                assertTrue(file.isFile)
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun `write replaces a stale file instead of appending to it`() {
        val directory = Files.createTempDirectory("hook-env-stale").toFile()
        try {
            val file = File(directory, HookEnv.FILE)
            file.writeText("schema=maplesu.hook.env.v1 boot=stale attempt=stale " +
                "expected=0 source=observed\n")
            assertTrue(HookEnv.write(directory, ATTEMPT, BOOT, 1))
            val text = file.readText()
            assertFalse(text.contains("stale"))
            assertTrue(text.contains("attempt=$ATTEMPT"))
        } finally {
            directory.deleteRecursively()
        }
    }

    private companion object {
        const val ATTEMPT = "611efa15-0a4d-4c1f-9b7e-3f2f9c1d2e3f"
        const val BOOT = "a666f35b-2fd2-4f6e-9c2d-1a3b5c7d9e0f"
    }
}
