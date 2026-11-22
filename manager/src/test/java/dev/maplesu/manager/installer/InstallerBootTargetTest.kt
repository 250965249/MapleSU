package dev.maplesu.manager.installer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InstallerBootTargetTest {
    @Test
    fun inventoryDoesNotInventAnInitBootNode() {
        assertEquals(setOf("boot"), InstallerBootTarget.fromOutput("_a", "boot\n").availablePartitions)
        assertEquals(setOf("boot", "init_boot"),
            InstallerBootTarget.fromOutput("_b", "init_boot\nboot\n").availablePartitions)
    }

    @Test
    fun discoveryOnlyReadsNodesFromTheCurrentSlot() {
        val script = InstallerBootTarget.discoveryCommand("_b")
        assertTrue(script.contains("test -b /dev/block/by-name/boot_b"))
        assertTrue(script.contains("test -b /dev/block/by-name/init_boot_b"))
        assertFalse(script.contains("boot_a"))
        assertFalse(script.contains("dd "))
        val unslotted = InstallerBootTarget.discoveryCommand("")
        assertTrue(unslotted.contains("test -b /dev/block/by-name/boot;"))
        assertFalse(unslotted.contains("boot_a"))
    }
}
