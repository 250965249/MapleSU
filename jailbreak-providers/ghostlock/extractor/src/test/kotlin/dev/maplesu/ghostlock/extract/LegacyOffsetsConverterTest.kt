package dev.maplesu.ghostlock.extract

import com.ghostlock.app.data.ValueMap
import com.ghostlock.app.data.asValueMap
import com.ghostlock.app.data.valueMapOf
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * `offsets.conf` v2 import and `offsets.json` v1 conversion.
 *
 * The conversion cases are ports of the reference's own
 * `LegacyProfileConverterTest` (Apache-2.0, commit 437b3b2) and the JSON sample
 * is the same remote/main-era report the reference ships in
 * `app/src/test/resources/remote-main-6x-offsets.json` (first entry).
 */
class LegacyOffsetsConverterTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test
    fun `upstream extractor report converts to current profile layout`() {
        val entry = valueMapOf(
            "release" to "6.1.118-test",
            "kimage_text_base" to 0x100000L,
            "btf_size" to 4096,
            "compact_waiter" to 1,
            "pselect_waiter_shift" to 1,
            "mm_struct_sz" to 0x400,
            "struct_fields" to valueMapOf("task_prio" to 132),
            "symbols" to valueMapOf("off_init_task" to 33420800L),
        )
        LegacyOffsetsConverter.convertValue(entry)
        assertFalse(entry.containsKey("kimage_text_base"))
        assertFalse(entry.containsKey("btf_size"))
        assertEquals(0x400, entry["kernelsnitch"].asValueMap()!!["mm_struct_sz"])
        assertEquals(132, entry["task_struct"].asValueMap()!!["prio"])
        assertEquals(33420800L, entry["offset"].asValueMap()!!["init_task"])
        assertEquals("tcp_zerocopy", entry["route"].asValueMap()!!.keys.first())
    }

    @Test
    fun `tcp report keeps pselect as explicit select fallback`() {
        val entry = valueMapOf(
            "release" to "r",
            "kernel_major" to 6,
            "compact_waiter" to 1,
            "pselect_waiter_shift" to 1,
            "struct_fields" to valueMapOf("task_prio" to 132),
            "symbols" to valueMapOf("off_init_task" to 33420800L),
        )
        LegacyOffsetsConverter.convertValue(entry)
        assertEquals("tcp_zerocopy", entry["route"].asValueMap()!!.keys.first())
        assertEquals("select_stack", entry["fallback"].asValueMap()!!["to"])
        assertEquals(
            1,
            entry["fallback"].asValueMap()!!["route"].asValueMap()!!
                ["select_stack"].asValueMap()!!["waiter_shift"],
        )
        assertEquals(132, entry["task_struct"].asValueMap()!!["prio"])
        assertEquals(33420800L, entry["offset"].asValueMap()!!["init_task"])
    }

    @Test
    fun `select report without pselect has no fallback and no empty branch`() {
        val entry = valueMapOf(
            "release" to "r",
            "kernel_major" to 6,
            "struct_fields" to valueMapOf("task_prio" to 132),
        )
        LegacyOffsetsConverter.convertValue(entry)
        assertFalse(entry.containsKey("route"))
        assertEquals("none", entry["fallback"].asValueMap()!!["to"])
    }

    @Test
    fun `conversion is idempotent`() {
        val entry = valueMapOf(
            "release" to "r",
            "kernel_major" to 6,
            "compact_waiter" to 1,
            "pselect_waiter_shift" to 1,
        )
        LegacyOffsetsConverter.convertValue(entry)
        val once = entry.toString()
        LegacyOffsetsConverter.convertValue(entry)
        assertEquals(once, entry.toString())
    }

    @Test
    fun `empty route branch from old switches is dropped`() {
        val entry = valueMapOf(
            "release" to "r",
            "kernel_major" to 5,
            "route" to valueMapOf("select_stack" to valueMapOf()),
        )
        LegacyOffsetsConverter.convertValue(entry)
        assertFalse(entry.containsKey("route"))
    }

    @Test
    fun `imported 6x report gains kernel_major and shared defaults`() {
        val entry = valueMapOf(
            "release" to "6.12.38-android16-5-gbe6292a1543d-ab14525421-4k",
            "kernel_phys_load" to 3347054592L,
            "pselect_waiter_shift" to 0,
            "struct_fields" to valueMapOf("task_prio" to 148, "struct_mm_struct" to 1216),
            "offset" to valueMapOf("init_task" to 37801728L),
        )
        LegacyOffsetsConverter.convertValue(entry)
        assertEquals(6L, entry["kernel_major"])
        val cred = entry["cred"].asValueMap()!!
        assertEquals(136L, cred["copy_size"])
        assertEquals(48L, cred["caps_offset"])
        assertEquals(5L, cred["caps_count"])
        assertEquals(4L, entry["kernelsnitch"].asValueMap()!!["collisions"])
    }

    @Test
    fun `v2 document is normalised but not seeded`() {
        val entry = valueMapOf(
            "release" to "6.6.89-android15-8-test",
            "schema_version" to 1,
            "kernel_major" to 6,
            "offset" to valueMapOf("init_task" to 7L),
        )
        LegacyOffsetsConverter.convertValue(entry)
        /*
         * The reference normalises every document: with no route declared it
         * infers the select branch (empty, so it is dropped) and records an
         * explicit `fallback { to = "none" }`. It does not seed the 6.x shared
         * templates for a v2 document, which is the part that would mask a real
         * gap.
         */
        assertFalse(entry.containsKey("cred"))
        assertFalse(entry.containsKey("route"))
        assertEquals("none", entry["fallback"].asValueMap()!!["to"])
        assertEquals(7L, entry["offset"].asValueMap()!!["init_task"])
    }

    @Test
    fun `v1 json import produces a usable profile`() {
        val json = V1_JSON_6_1_118
        val outcome = GhostlockExtractionPipeline.parse(
            ExtractInput.OffsetsJson("remote-main-6x-offsets.json", json),
            workDir = temporary.newFolder("import"),
        )
        val profile = (outcome as ExtractionOutcome.Generated).profiles.single()
        assertEquals("6.1.118-android14-11-ga3b9c44908dd-ab13320413", profile.release)
        assertTrue("invalid: ${profile.validation.invalidFields}", profile.complete)
        assertEquals("offsets_json", profile.provenance.kind)
        assertTrue(profile.document.contains("compact_waiter = 1"))
        assertTrue(profile.document.contains("waiter_shift = 1"))
        assertTrue(profile.document.contains("init_task = 33420800"))
        assertTrue(profile.document.contains("copy_size = 136"))
        assertNotNull(profile.validation.wire)
    }

    @Test
    fun `v2 conf import without required fields is rejected as a candidate`() {
        val conf = """
            release = "6.6.89-android15-8-incomplete"
            schema_version = 1
            kernel_major = 6
            route { select_stack { waiter_shift = -2 } }
            fallback { to = "none" }
            task_struct { prio = 132 }
            cred { copy_size = 136, caps_count = 5 }
            offset { init_task = 4096 }
        """.trimIndent()
        val outcome = GhostlockExtractionPipeline.parse(
            ExtractInput.OffsetsConf("incomplete.conf", conf),
            workDir = temporary.newFolder("import-conf"),
        )
        val profile = (outcome as ExtractionOutcome.Generated).profiles.single()
        assertFalse(profile.complete)
        assertTrue(profile.validation.invalidFields.contains("offset.init_cred"))
        val flow = GhostlockOtaFlow(profile.release).finish(outcome)
        assertEquals(OtaParseState.Failed(OtaFailure.INCOMPLETE_PROFILE), flow)
    }

    @Test
    fun `document without release is AlreadyPresent`() {
        val outcome = GhostlockExtractionPipeline.parse(
            ExtractInput.OffsetsConf("empty.conf", "kernel_major = 6"),
            workDir = temporary.newFolder("import-empty"),
        )
        assertEquals(ExtractionOutcome.AlreadyPresent, outcome)
    }

    companion object {
        /** The reference's own v1 sample (first entry, verbatim values). */
        private const val V1_JSON_6_1_118 = """
        {
          "release": "6.1.118-android14-11-ga3b9c44908dd-ab13320413",
          "pselect_waiter_shift": 1,
          "compact_waiter": 1,
          "mm_struct_sz": 1024,
          "symbols": {
            "off_init_cred": 33495656,
            "off_init_task": 33420800,
            "off_root_task_group": 35411328,
            "off_security_hook_heads": 22752408,
            "off_selinux_blob_sizes": 22754216,
            "off_selinux_enforcing": 35746768,
            "off_slide_boot_id": 35882072,
            "off_slide_loggers_0_1": 33368344,
            "off_slide_nfulnl_logger": 33368520
          },
          "struct_fields": {
            "task_atomic_flags": 1520,
            "task_comm": 2120,
            "task_cred": 2104,
            "task_normal_prio": 140,
            "task_pi_blocked_on": 2384,
            "task_pi_lock": 2340,
            "task_pi_top_task": 2376,
            "task_pi_waiters": 2360,
            "task_pid": 1584,
            "task_prio": 132,
            "task_real_cred": 2096,
            "task_sched_task_group": 840,
            "task_seccomp": 2304,
            "task_tasks": 1360,
            "task_tgid": 1588
          }
        }
        """
    }
}
