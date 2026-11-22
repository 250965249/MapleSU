package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 2026-11-02 user directive: the "this boot already has a session" gate is removed
 * entirely. Start must never be blocked by a previous record; the new attempt clears
 * it and re-proves the carrier. This test pins that removal (deviation from §5 C5/T4,
 * recorded in the delivery notes).
 */
class RetryGuardTest {
    private fun root(): File =
        sequenceOf(File("."), File("..")).first { File(it, "manager").isDirectory }

    private fun source(relative: String): String = File(root(), relative).readText()

    @Test
    fun theControllerNeverReturnsSessionActive() {
        val controller = source(
            "manager/src/main/java/dev/maplesu/manager/jailbreak/JailbreakController.kt")
        assertFalse("the start gate must not exist any more",
            controller.contains("JAILBREAK_SESSION_ACTIVE"))
        assertFalse("no session predicate in the start path",
            controller.contains("jailbreakSessionActive"))
    }

    @Test
    fun startingReplacesAnyPreviousRecord() {
        val controller = source(
            "manager/src/main/java/dev/maplesu/manager/jailbreak/JailbreakController.kt")
        assertTrue("a previous record must be cleared so the attempt can start",
            controller.contains("JailbreakStatus.clear(context)"))
    }

    @Test
    fun theDialogNoLongerBlocksStart() {
        val dialog = source(
            "manager/src/main/java/dev/maplesu/manager/jailbreak/JailbreakSelectionDialog.kt")
        assertFalse(dialog.contains("JAILBREAK_SESSION_ACTIVE"))
        assertFalse(dialog.contains("jailbreakSessionActive"))
        assertTrue("canStart must not be gated by a session flag",
            dialog.contains("val canStart: Boolean get() = selection.canStart"))
    }
}
