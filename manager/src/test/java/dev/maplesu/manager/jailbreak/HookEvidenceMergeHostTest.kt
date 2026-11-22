package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/**
 * Host regression for the step-3 evidence merge (design §5.4 rules 1-4, §5.5).
 *
 * <p>The helper writes two records: the parent's `maplesu-hook.json` and the unload
 * child's `maplesu-hook-unload.json`. The dangerous mistakes are all "read a missing or
 * partial record as success", so each test here is one of those shapes:
 *
 * <ol>
 *   <li>main record missing -> no evidence at all (never OK);</li>
 *   <li>both records present -> the child's origin/readback/failures win (they are
 *       later and they are the ones the kernel's cleanup ran in);</li>
 *   <li>child record missing while the parent saw `unload=DONE` -> the restore can only
 *       be `RESTORED_UNCONFIRMED`, and the verdict cannot be OK;</li>
 *   <li>`unload=PENDING` -> DEGRADED, never success;</li>
 *   <li>a final readback that differs from `wantFinal` -> FAILED even when the parent
 *       wrote KERNEL_SAVED itself.</li>
 * </ol>
 *
 * <p>Review M3 added the schema-typing regression: the helper is C and writes
 * `"open":%d` / `"wrote":%d` (JSON **numbers**), and `org.json`'s `optBoolean` maps a
 * number to `false`. That made `window.open == false` on a fully open window, so every
 * good handover merged as DEGRADED and `escalateHook()` published
 * `MAPLESU_HOOK_RESTORE_UNVERIFIED`. The parser now uses the App's pinned
 * `kotlinx-serialization-json` reader and accepts both shapes, so the tests below drive
 * the **production** parse with the helper's real document and a number/boolean mix-up
 * cannot survive to the device run.
 */
class HookEvidenceMergeHostTest {

    private fun restore(
        wantFinal: String? = "1",
        readback: Int? = 1,
        origin: String? = "KERNEL_SAVED",
        failures: Int? = 0,
        wrote: Boolean = true,
    ) = HookEvidence.Restore(wantFinal = wantFinal, target = wantFinal, wrote = wrote,
        readbackPreUnload = readback, origin = origin, failures = failures)

    private fun mainRecord(
        restore: HookEvidence.Restore? = restore(),
        unloadState: String? = "DONE",
        verdict: String = "OK",
        token: String? = null,
        windowOpen: Boolean = true,
        stage2: String? = "NOT_EXERCISED",
        daemon: String? = "NOT_EXERCISED",
    ) = HookEvidence.Main(
        schema = HookEvidence.SCHEMA,
        helper = "/data/user/0/dev.maplesu.manager/bs",
        helperPid = 4242,
        bootId = BOOT,
        entry = HookEvidence.Entry(argv = "1", origin = "kernel-saved"),
        window = HookEvidence.Window(enforceBefore = 0, open = windowOpen),
        stage2 = HookEvidence.Stage2(state = stage2, path = "/x/maplesu_stage2.ko",
            rc = null, errno = null, name = null),
        daemon = HookEvidence.Daemon(state = daemon, path = "/x/maplesu-daemon", pid = null),
        restore = restore,
        unload = HookEvidence.Unload(name = "maplesu_root", state = unloadState),
        verdict = verdict,
        token = token,
    )

    private fun unloadRecord(
        origin: String? = "KERNEL_CLEANUP",
        readbackFinal: Int? = 1,
        readbackPostUnload: Int? = 1,
        failures: Int? = 0,
        rc: Int? = 0,
        errno: Int? = 0,
    ) = HookEvidence.UnloadRecord(
        schema = HookEvidence.UNLOAD_SCHEMA, rc = rc, errno = errno, attempts = 2,
        readbackPostUnload = readbackPostUnload, readbackFinal = readbackFinal,
        origin = origin, failures = failures,
    )

    @Test
    fun `rule 1 - a missing main record is no evidence, not success`() {
        assertNull(HookEvidence.merge(null, unloadRecord()))
        assertNull(HookEvidence.merge(null, null))
    }

    @Test
    fun `rule 2 - the child record supplies origin, value and failures`() {
        val merged = HookEvidence.merge(
            mainRecord(restore = restore(origin = "KERNEL_SAVED", readback = 1)),
            unloadRecord(origin = "BASELINE", readbackFinal = 1, failures = 0),
        )!!
        assertEquals("BASELINE", merged.origin)
        assertEquals("RESTORED_BASELINE", merged.restoreState)
        assertEquals(1, merged.enforcing)
        assertEquals(0, merged.failures)
        assertEquals("OK", merged.verdict)
        assertEquals(0, merged.unloadErrno)
        assertEquals(BOOT, merged.bootId)
        assertEquals("1", merged.entryArgv)
    }

    @Test
    fun `rule 2 - KERNEL_SAVED and KERNEL_CLEANUP map to their own states`() {
        val saved = HookEvidence.merge(mainRecord(), unloadRecord(origin = "KERNEL_SAVED"))!!
        assertEquals("RESTORED_KERNEL", saved.restoreState)
        val cleanup = HookEvidence.merge(mainRecord(), unloadRecord())!!
        assertEquals("RESTORED_KERNEL_CLEANUP", cleanup.restoreState)
    }

    @Test
    fun `rule 3 - child record missing but unload DONE is unconfirmed, not OK`() {
        val merged = HookEvidence.merge(mainRecord(), null)!!
        assertEquals("RESTORED_UNCONFIRMED", merged.restoreState)
        assertEquals("DEGRADED", merged.verdict)
        assertTrue(!merged.ok)
        // The parent's value is used only for the enforcing field, never as the origin.
        assertEquals(1, merged.enforcing)
    }

    @Test
    fun `rule 4 - PENDING is degraded and carries no errno`() {
        val merged = HookEvidence.merge(
            mainRecord(restore = restore(origin = "KERNEL_CLEANUP", failures = 0),
                unloadState = "PENDING", verdict = "DEGRADED", token = "MA_HOOK_UNLOAD_BUSY"),
            null,
        )!!
        assertEquals("DEGRADED", merged.verdict)
        assertNull(merged.unloadErrno)
        assertEquals("MA_HOOK_UNLOAD_BUSY", merged.token)
        assertTrue(merged.restoreState != "RESTORED_KERNEL")
    }

    @Test
    fun `a final readback that differs from the target fails the merge`() {
        val merged = HookEvidence.merge(
            mainRecord(restore = restore(readback = 1, origin = "KERNEL_SAVED")),
            unloadRecord(origin = "BASELINE", readbackFinal = 0, failures = 1,
                rc = 0, errno = 0),
        )!!
        assertEquals("FAILED", merged.verdict)
        assertEquals("FAILED", merged.restoreState)
        assertEquals(1, merged.failures)
    }

    @Test
    fun `rule 4 - a child record that settled a PENDING parent is DONE`() {
        // R12: the parent's wait is bounded (1500 ms) and the child's retry window is
        // longer, so a later child record with rc=0 settles the state.
        val merged = HookEvidence.merge(
            mainRecord(restore = restore(origin = "KERNEL_SAVED", failures = 0),
                unloadState = "PENDING", verdict = "DEGRADED"),
            unloadRecord(origin = "KERNEL_CLEANUP", readbackFinal = 1, failures = 0,
                rc = 0, errno = 0),
        )!!
        assertEquals("DONE", merged.unloadState)
        assertEquals(0, merged.unloadErrno)
        assertEquals("OK", merged.verdict)
        assertEquals("RESTORED_KERNEL_CLEANUP", merged.restoreState)
    }

    @Test
    fun `a parent verdict of FAILED cannot be upgraded by a later record`() {
        val merged = HookEvidence.merge(
            mainRecord(verdict = "FAILED", token = "MA_HOOK_RESTORE_FAILED",
                restore = restore(wantFinal = "0", readback = 0, origin = "FAILED", failures = 1)),
            unloadRecord(readbackFinal = 0, failures = 1),
        )!!
        assertEquals("FAILED", merged.verdict)
        assertEquals("MA_HOOK_RESTORE_FAILED", merged.token)
    }

    @Test
    fun `stage2 INVALID is a failed handover`() {
        val stage2 = HookEvidence.merge(mainRecord(stage2 = "INVALID"),
            unloadRecord())!!
        assertEquals("FAILED", stage2.verdict)
        assertEquals("INVALID", stage2.stage2)
    }

    @Test
    fun `stage2 LOAD_FAILED is informational and cannot lower the verdict (B1)`() {
        // B1: the L3 module is optional, so the kernel refusing to load it is not a
        // handover failure - bootstrap.c's hook_verdict() raises no token for it. The
        // App used to disagree and turned every good restore into FAILED as soon as
        // LOAD_FAILED appeared; the slot is now reported but decides nothing, because
        // L3 is answered by `suGate` alone. The refusal token stays absent, so a good
        // run still publishes STAGE_ROOT_WORKER_OBSERVED.
        val stage2 = HookEvidence.merge(mainRecord(stage2 = "LOAD_FAILED"),
            unloadRecord())!!
        assertEquals("OK", stage2.verdict)
        assertEquals("LOAD_FAILED", stage2.stage2)
        assertEquals("RESTORED_KERNEL_CLEANUP", stage2.restoreState)
        assertNull(HookEvidence.refusalToken(stage2))
    }

    @Test
    fun `daemon slot failure is degraded, not failed (step-4 D4-12)`() {
        // Changed by step-4 R7 on purpose: the daemon slot carries the second proof
        // (F2/F3), and collapsing it into FAILED erased the restore evidence F1 that the
        // App has to report when attestation is what broke. The refusal token still names
        // the cause, so the attempt is still refused - see `refusalToken`.
        val daemon = HookEvidence.merge(mainRecord(daemon = "EXEC_FAILED"),
            unloadRecord())!!
        assertEquals("DEGRADED", daemon.verdict)
        assertEquals("EXEC_FAILED", daemon.daemon)
        assertEquals("RESTORED_KERNEL_CLEANUP", daemon.restoreState)
    }

    @Test
    fun `a closed window is degraded even when the value is right`() {
        val merged = HookEvidence.merge(
            mainRecord(windowOpen = false, restore = restore(readback = 1, wrote = false,
                origin = "KERNEL_CLEANUP")),
            unloadRecord(),
        )!!
        assertEquals("DEGRADED", merged.verdict)
        assertEquals(0, merged.unloadErrno)
    }

    @Test
    fun `an unload FAILED is a failed handover`() {
        val merged = HookEvidence.merge(
            mainRecord(unloadState = "FAILED", verdict = "DEGRADED",
                token = "MA_HOOK_UNLOAD_BUSY"),
            unloadRecord(rc = -1, errno = 11, origin = "KERNEL_CLEANUP", failures = 1,
                readbackFinal = 1),
        )!!
        assertEquals("FAILED", merged.verdict)
        assertNull(merged.unloadErrno)
    }

    @Test
    fun `the two records disagreeing about the value is reported`() {
        val main = mainRecord(restore = restore(readback = 1))
        assertEquals("readbackPreUnload=1 != readbackPostUnload=0",
            HookEvidence.contradiction(main, unloadRecord(readbackPostUnload = 0)))
        assertNull(HookEvidence.contradiction(main, unloadRecord()))
    }

    // -- review M3: the helper writes JSON numbers where the schema says boolean ---- //

    /**
     * The parent record exactly as `hook_write_main_json()` emits it, with the two
     * boolean-shaped fields left as parameters so each test can vary only the typing.
     */
    private fun mainJson(window: String, restoreWrote: String = "\"wrote\":1"): String =
        """{"schema":"maplesu.hook.v1","mode":"umh",""" +
            """"helper":"/data/user/0/dev.maplesu.manager/bs","helperPid":4242,"uid":0,""" +
            """"domain":"u:r:kernel:s0","bootId":"$BOOT","attempt":null,""" +
            """"entry":{"argv":"1","origin":"kernel-saved"},"window":{$window},""" +
            """"stage2":{"state":"NOT_EXERCISED","path":"/x/maplesu_stage2.ko",""" +
            """"rc":null,"errno":null,"name":null},""" +
            """"daemon":{"state":"NOT_EXERCISED","path":"/x/maplesu-daemon","pid":null},""" +
            """"restore":{"wantFinal":"1","target":"1",$restoreWrote,""" +
            """"readbackPreUnload":1,"origin":"KERNEL_CLEANUP","failures":0},""" +
            """"unload":{"name":"maplesu_root","state":"DONE"},""" +
            """"klog":{"preRestore":"hook-pre-restore","postUnload":"hook-post-unload"},""" +
            """"verdict":"OK","token":null,"ts":1761734512}"""

    private fun unloadJson(): String =
        """{"schema":"maplesu.hook.unload.v1","rc":0,"errno":0,"attempts":1,""" +
            """"readbackPostUnload":1,"readbackFinal":1,""" +
            """"origin":"KERNEL_CLEANUP","failures":0}"""

    @Test
    fun `review M3 - window open parses the helper's Integer 1 and 0`() {
        val open = HookEvidence.parseMain(
            mainJson("\"enforceBefore\":0,\"open\":1"))!!.window!!
        assertEquals(true, open.open)
        assertEquals(0, open.enforceBefore)
        val closed = HookEvidence.parseMain(
            mainJson("\"enforceBefore\":1,\"open\":0"))!!.window!!
        assertEquals(false, closed.open)
    }

    @Test
    fun `review M3 - window open still parses JSON booleans`() {
        assertEquals(true, HookEvidence.parseMain(
            mainJson("\"enforceBefore\":0,\"open\":true"))!!.window!!.open)
        assertEquals(false, HookEvidence.parseMain(
            mainJson("\"enforceBefore\":1,\"open\":false"))!!.window!!.open)
    }

    @Test
    fun `review M3 - a missing or null open stays fail-closed`() {
        assertFalse(HookEvidence.parseMain(
            mainJson("\"enforceBefore\":0"))!!.window!!.open)
        assertFalse(HookEvidence.parseMain(
            mainJson("\"enforceBefore\":0,\"open\":null"))!!.window!!.open)
    }

    @Test
    fun `review M3 - restore wrote parses Integer and Boolean alike`() {
        assertEquals(true, HookEvidence.parseMain(
            mainJson("\"open\":1", "\"wrote\":1"))!!.restore!!.wrote)
        assertEquals(false, HookEvidence.parseMain(
            mainJson("\"open\":1", "\"wrote\":0"))!!.restore!!.wrote)
        assertEquals(true, HookEvidence.parseMain(
            mainJson("\"open\":1", "\"wrote\":true"))!!.restore!!.wrote)
        assertEquals(false, HookEvidence.parseMain(
            mainJson("\"open\":1", "\"wrote\":false"))!!.restore!!.wrote)
    }

    @Test
    fun `review M3 - coerceBoolean covers every value a JSON reader can produce`() {
        assertTrue(HookEvidence.coerceBoolean(Integer.valueOf(1), false))
        assertFalse(HookEvidence.coerceBoolean(Integer.valueOf(0), true))
        assertTrue(HookEvidence.coerceBoolean(java.lang.Boolean.TRUE, false))
        assertFalse(HookEvidence.coerceBoolean(java.lang.Boolean.FALSE, true))
        assertTrue(HookEvidence.coerceBoolean("1", false))
        assertFalse(HookEvidence.coerceBoolean("0", true))
        // Anything unreadable keeps the caller's fail-closed default, never "open":
        // parseMain passes `false` for `open`, so a missing/garbled value stays closed.
        assertTrue(HookEvidence.coerceBoolean(null, true))
        assertFalse(HookEvidence.coerceBoolean(null, false))
        assertTrue(HookEvidence.coerceBoolean(mapOf("open" to 1), true))
        assertFalse(HookEvidence.coerceBoolean(mapOf("open" to 1), false))
    }

    @Test
    fun `review M3 - a good run merges OK and publishes no refusal token`() {
        val merged = HookEvidence.merge(
            HookEvidence.parseMain(mainJson("\"enforceBefore\":0,\"open\":1")),
            HookEvidence.parseUnload(unloadJson()),
        )!!
        assertEquals("OK", merged.verdict)
        assertTrue(merged.ok)
        assertEquals("RESTORED_KERNEL_CLEANUP", merged.restoreState)
        assertEquals(1, merged.enforcing)
        assertEquals(0, merged.failures)
        // The exact branch escalateHook() takes: null = STAGE_ROOT_WORKER_OBSERVED.
        assertNull(HookEvidence.refusalToken(merged))
    }

    @Test
    fun `review M3 - a closed window still publishes the restore-unverified token`() {
        val merged = HookEvidence.merge(
            HookEvidence.parseMain(mainJson("\"enforceBefore\":1,\"open\":0")),
            HookEvidence.parseUnload(unloadJson()),
        )!!
        assertEquals("DEGRADED", merged.verdict)
        assertEquals(HookEvidence.TOKEN_RESTORE_UNVERIFIED,
            HookEvidence.refusalToken(merged))
    }

    @Test
    fun `review M3 - a specific token wins over the generic refusal token`() {
        val merged = HookEvidence.merge(
            mainRecord(unloadState = "FAILED", verdict = "DEGRADED",
                token = "MA_HOOK_UNLOAD_BUSY"),
            unloadRecord(rc = -1, errno = 11, failures = 1),
        )!!
        assertEquals("MA_HOOK_UNLOAD_BUSY", HookEvidence.refusalToken(merged))
    }

    @Test
    fun `read merges the two files from the attempt directory`() {
        val directory = Files.createTempDirectory("hook-evidence").toFile()
        try {
            java.io.File(directory, HookEvidence.MAIN_FILE)
                .writeText(mainJson("\"enforceBefore\":0,\"open\":1"))
            java.io.File(directory, HookEvidence.UNLOAD_FILE).writeText(unloadJson())
            val merged = HookEvidence.read(directory)!!
            assertEquals("OK", merged.verdict)
            assertNull(HookEvidence.refusalToken(merged))
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun `read without the parent record is no evidence`() {
        val directory = Files.createTempDirectory("hook-evidence-empty").toFile()
        try {
            java.io.File(directory, HookEvidence.UNLOAD_FILE).writeText(unloadJson())
            assertNull(HookEvidence.read(directory))
        } finally {
            directory.deleteRecursively()
        }
    }

    // ======================================================================== //
    // Step-4 (D2/D4-12/R5/R6): what the hook route may and may not conclude.
    // ======================================================================== //

    private val attemptId = "611efa15-0a4d-4c1f-9b7e-3f2f9c1d2e3f"

    /** The helper's document as step-4 emits it: real attempt, restore.source, wrote. */
    private fun step4MainJson(attempt: String? = "\"$attemptId\"",
                              origin: String = "BASELINE",
                              source: String = "baseline",
                              daemon: String = "STARTED"): String =
        """{"schema":"maplesu.hook.v1","mode":"umh",""" +
            """"helper":"/data/user/0/dev.maplesu.manager/bs","helperPid":4242,"uid":0,""" +
            """"domain":"u:r:kernel:s0","bootId":"$BOOT","attempt":$attempt,""" +
            """"entry":{"argv":"0","origin":"kernel-saved"},""" +
            """"window":{"enforceBefore":0,"open":1},""" +
            """"stage2":{"state":"NOT_EXERCISED","path":"","rc":null,"errno":null,""" +
            """"name":null},""" +
            """"daemon":{"state":"$daemon","path":"/data/user/0/dev.maplesu.manager/bs",""" +
            """"pid":18001},""" +
            """"restore":{"wantFinal":"1","target":"1","wrote":0,""" +
            """"readbackPreUnload":0,"origin":"$origin","source":"$source","failures":0},""" +
            """"unload":{"name":"maplesu_root","state":"DONE"},""" +
            """"klog":{"preRestore":"hook-pre-restore","postUnload":"hook-post-unload"},""" +
            """"verdict":"OK","token":null,"ts":1761734512}"""

    private fun step4UnloadJson(wrote: String = "1"): String =
        """{"schema":"maplesu.hook.unload.v1","rc":0,"errno":0,"attempts":1,""" +
            """"readbackPostUnload":0,"readbackFinal":1,"origin":"BASELINE",""" +
            """"wrote":$wrote,"failures":0}"""

    @Test
    fun `step-4 - a good hook run parses attempt, source and the child wrote field`() {
        val main = HookEvidence.parseMain(step4MainJson())!!
        assertEquals(attemptId, main.attempt)
        assertEquals("baseline", main.restore!!.source)
        assertEquals(false, main.restore!!.wrote)
        val unload = HookEvidence.parseUnload(step4UnloadJson())!!
        assertEquals(1, unload.wrote)
        val merged = HookEvidence.merge(main, unload)!!
        assertEquals("OK", merged.verdict)
        assertEquals("RESTORED_BASELINE", merged.restoreState)
        assertEquals(attemptId, merged.attempt)
        assertNull(HookEvidence.refusalToken(merged))
        assertNull(HookEvidence.bindingRefusal(merged, BOOT, attemptId))
    }

    @Test
    fun `step-4 - foreign boot or attempt is refused before anything is published`() {
        val merged = HookEvidence.merge(
            HookEvidence.parseMain(step4MainJson()), HookEvidence.parseUnload(step4UnloadJson()))!!
        assertEquals(HookEvidence.TOKEN_FOREIGN_BOOT,
            HookEvidence.bindingRefusal(merged, "another-boot", attemptId))
        assertEquals(HookEvidence.TOKEN_FOREIGN_ATTEMPT,
            HookEvidence.bindingRefusal(merged, BOOT, "00000000-0000-0000-0000-000000000000"))
        // Nothing asked, nothing to compare: only the record's own silence can refuse it
        // (see the next test).
        assertNull(HookEvidence.bindingRefusal(merged, BOOT, null))
    }

    @Test
    fun `step-4 - an absent record has no attempt, so it cannot bind`() {
        val merged = HookEvidence.merge(
            HookEvidence.parseMain(step4MainJson(attempt = "null")),
            HookEvidence.parseUnload(step4UnloadJson()))!!
        assertNull(merged.attempt)
        assertEquals(HookEvidence.TOKEN_FOREIGN_ATTEMPT,
            HookEvidence.bindingRefusal(merged, BOOT, attemptId))
    }

    @Test
    fun `step-4 - daemon INVALID is DEGRADED, and the restore evidence survives`() {
        // D4-12/MF-12: a failed attestation worker must not erase F1. The token still
        // names the cause, so the attempt is refused - but restoreState stays readable,
        // which is the whole point of keeping the two proofs separate.
        val merged = HookEvidence.merge(
            HookEvidence.parseMain(step4MainJson(daemon = "INVALID")),
            HookEvidence.parseUnload(step4UnloadJson()))!!
        assertEquals("DEGRADED", merged.verdict)
        assertEquals("INVALID", merged.daemon)
        assertEquals("RESTORED_BASELINE", merged.restoreState)
        assertEquals(1, merged.enforcing)
        assertEquals(0, merged.failures)
        assertEquals(HookEvidence.TOKEN_RESTORE_UNVERIFIED,
            HookEvidence.refusalToken(merged))
    }

    @Test
    fun `step-4 - stage-2 INVALID is FAILED while LOAD_FAILED no longer decides`() {
        // B1: only INVALID survives as a stage-2 failure - the stager handed over bytes
        // that are not a module image at all. LOAD_FAILED is the optional L3 module
        // being refused, which the helper's hook_verdict() already ignores and which
        // the App now mirrors (L3 gates `suGate`, not the handover verdict).
        val loadFailed = HookEvidence.merge(
            HookEvidence.parseMain(step4MainJson()
                .replace("\"stage2\":{\"state\":\"NOT_EXERCISED\"",
                    "\"stage2\":{\"state\":\"LOAD_FAILED\"")),
            HookEvidence.parseUnload(step4UnloadJson()))!!
        assertEquals("LOAD_FAILED", loadFailed.stage2)
        assertEquals("OK", loadFailed.verdict)
        assertNull(HookEvidence.refusalToken(loadFailed))

        val invalid = HookEvidence.merge(
            HookEvidence.parseMain(step4MainJson()
                .replace("\"stage2\":{\"state\":\"NOT_EXERCISED\"",
                    "\"stage2\":{\"state\":\"INVALID\"")),
            HookEvidence.parseUnload(step4UnloadJson()))!!
        assertEquals("INVALID", invalid.stage2)
        assertEquals("FAILED", invalid.verdict)
    }

    @Test
    fun `step-4 - unreadable and missing are different readings`() {
        val directory = Files.createTempDirectory("hook-reading").toFile()
        try {
            // Missing: no file at all -> no problem recorded, no evidence.
            val missing = HookEvidence.inspect(directory)
            assertFalse(missing.present)
            assertNull(missing.unreadable)
            assertNull(HookEvidence.read(directory))

            // Present but unreadable: the directory itself is a directory, so readText()
            // throws. That is the case R3 produced with a 0600 file (EACCES) and it must
            // NOT be reported as "no evidence".
            java.io.File(directory, HookEvidence.MAIN_FILE).mkdirs()
            val unreadable = HookEvidence.inspect(directory)
            assertFalse(unreadable.present)
            assertTrue("expected an unreadable marker, got " + unreadable.unreadable,
                unreadable.unreadable!!.startsWith(HookEvidence.MAIN_FILE))
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun `step-4 - malformed evidence is unreadable, not silently absent`() {
        val directory = Files.createTempDirectory("hook-malformed").toFile()
        try {
            java.io.File(directory, HookEvidence.MAIN_FILE).writeText("{not json")
            val reading = HookEvidence.inspect(directory)
            assertFalse(reading.present)
            assertEquals(HookEvidence.MAIN_FILE + ":malformed", reading.unreadable)
        } finally {
            directory.deleteRecursively()
        }
    }

    private companion object {
        const val BOOT = "51534979"
    }
}