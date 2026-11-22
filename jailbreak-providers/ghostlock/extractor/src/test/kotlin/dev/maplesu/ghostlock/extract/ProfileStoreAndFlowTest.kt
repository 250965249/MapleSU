package dev.maplesu.ghostlock.extract

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Store, gate and OTA state-machine tests: the parts that decide whether a
 * profile may be offered. Every negative case must refuse, never "allow
 * because unknown".
 */
class ProfileStoreAndFlowTest {
    @get:Rule val temporary = TemporaryFolder()

    private val release = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
    private val document = """
        release = "$release"
        schema_version = 1
        kernel_major = 6
        route { select_stack { waiter_shift = -2 } }
        fallback { to = "none" }
        kernelsnitch { collisions = 4 }
        task_struct { prio = 132, normal_prio = 140, sched_task_group = 840, pi_lock = 2316,
          pi_waiters = 2336, pi_top_task = 2352, pi_blocked_on = 2360, pid = 1560, tgid = 1564,
          atomic_flags = 1496, real_cred = 2072, cred = 2080, comm = 2096, tasks = 1360,
          seccomp = 2280 }
        cred { copy_size = 136, caps_offset = 48, caps_count = 5, usage_value = 1, caps_value = -1 }
        offset { init_task = 34595456, init_cred = 34669896, root_task_group = 36656512,
          selinux_enforcing = 36925088 }
    """.trimIndent()

    private fun entry(
        name: String = "$release.conf",
        text: String = document,
        confirmedAt: Long? = null,
    ) = GhostlockProfileStore.Entry(
        name = name,
        text = text,
        releases = listOf(release),
        source = "ota_url",
        input = "https://example.com/ota.zip",
        createdAt = 1L,
        confirmedAt = confirmedAt,
        documentSha256 = GhostlockProfileStore.sha256(text.toByteArray(Charsets.UTF_8)),
        generatedAt = "2026-10-31T00:00:00Z",
        referenceCommit = GhostlockNativeExtractor.REFERENCE_COMMIT,
    )

    @Test
    fun `old image derived profiles require parsing again while manual imports remain usable`() {
        for (source in listOf("local_image", "local_ota", "ota_url")) {
            for (commit in listOf("", "437b3b2")) {
                val directory = temporary.newFolder()
                val store = GhostlockProfileStore.openIn(directory)
                assertTrue(store.save(entry(confirmedAt = 2L).copy(source = source, referenceCommit = commit)))
                val reopened = GhostlockProfileStore.openIn(directory)
                assertTrue(reopened.has(release))
                assertNull(reopened.confirmedFor(release))
                assertTrue(reopened.confirmedReleases().isEmpty())
                assertTrue(GhostlockProfileGate.offersParser(
                    GhostlockProfileGate.decide(release, false, reopened)))
            }
        }
        for (source in listOf("offsets_conf", "offsets_json")) {
            val directory = temporary.newFolder()
            val store = GhostlockProfileStore.openIn(directory)
            assertTrue(store.save(entry(confirmedAt = 2L).copy(source = source, referenceCommit = "")))
            assertNotNull(GhostlockProfileStore.openIn(directory).confirmedFor(release))
        }
    }

    @Test
    fun `reference extraction provenance survives storage and keeps the profile usable`() {
        val directory = temporary.newFolder()
        val store = GhostlockProfileStore.openIn(directory)
        val original = profile()
        val reference = GeneratedProfile(original.release, original.route, original.document,
            original.provenance.copy(referenceCommit = "b67359641c8663e5184abba73ecdf2c456dce3e7"),
            original.validation)
        assertTrue(store.save(store.entryFor(reference)))
        assertTrue(store.confirm(release))
        assertNotNull(GhostlockProfileStore.openIn(directory).confirmedFor(release))
        assertTrue(File(directory, GhostlockProfileStore.FILE_NAME).readText()
            .contains("\"referenceCommit\":\"b67359641c8663e5184abba73ecdf2c456dce3e7\""))
    }

    @Test
    fun `candidate is stored but never offered`() {
        val store = GhostlockProfileStore.inMemory()
        assertTrue(store.save(entry()))
        assertTrue(store.has(release))
        assertNull(store.confirmedFor(release))
        assertEquals(emptySet<String>(), store.confirmedReleases())
        val decision = GhostlockProfileGate.decide(release, packagedSupported = false, store = store)
        assertEquals(
            GhostlockProfileGate.Decision.Unsupported(GhostlockProfileGate.Reason.NOT_LISTED, release),
            decision,
        )
    }

    @Test
    fun `confirmed exact profile is offered`() {
        val store = GhostlockProfileStore.inMemory()
        assertTrue(store.save(entry(confirmedAt = 2L)))
        assertNotNull(store.confirmedFor(release))
        val decision = GhostlockProfileGate.decide(release, packagedSupported = false, store = store)
        assertEquals(GhostlockProfileGate.Decision.Imported("$release.conf"), decision)
        assertTrue(GhostlockProfileGate.isOffered(decision))
    }

    @Test
    fun `packaged list wins and mismatch refuses`() {
        val store = GhostlockProfileStore.inMemory()
        assertTrue(store.save(entry(confirmedAt = 2L)))
        assertEquals(
            GhostlockProfileGate.Decision.Packaged,
            GhostlockProfileGate.decide(release, packagedSupported = true, store = store),
        )
        assertEquals(
            GhostlockProfileGate.Decision.Unsupported(
                GhostlockProfileGate.Reason.NOT_LISTED,
                "6.6.89-android15-8-g7e1f3c083cc6-other",
            ),
            GhostlockProfileGate.decide(
                "6.6.89-android15-8-g7e1f3c083cc6-other", packagedSupported = false, store = store),
        )
        // A release that is a prefix/suffix of the stored one is not a match.
        assertNull(store.confirmedFor(release.removeSuffix("-4k")))
        assertEquals(
            GhostlockProfileGate.Decision.Unsupported(GhostlockProfileGate.Reason.KERNEL_UNKNOWN),
            GhostlockProfileGate.decide("", packagedSupported = false, store = store),
        )
        assertEquals(
            GhostlockProfileGate.Decision.Unsupported(GhostlockProfileGate.Reason.LIST_MISSING),
            GhostlockProfileGate.decide(
                "6.6.1-other", packagedSupported = false, store = null, packagedListUsable = false),
        )
    }

    @Test
    fun `store survives a round trip and fails closed on corruption`() {
        val directory = temporary.newFolder("store")
        val store = GhostlockProfileStore.openIn(directory)
        assertTrue(store.save(entry(confirmedAt = 3L)))
        val reopened = GhostlockProfileStore.openIn(directory)
        assertEquals(1, reopened.all().size)
        assertNotNull(reopened.confirmedFor(release))
        // Provenance survives the round trip: source, input, digest and time.
        val stored = reopened.all().single()
        assertEquals("ota_url", stored.source)
        assertEquals("https://example.com/ota.zip", stored.input)
        assertEquals(64, stored.documentSha256.length)
        assertEquals("2026-10-31T00:00:00Z", stored.generatedAt)
        assertEquals(1L, stored.createdAt)

        File(directory, GhostlockProfileStore.FILE_NAME).writeText("{not json")
        assertTrue(GhostlockProfileStore.openIn(directory).all().isEmpty())
        assertNull(GhostlockProfileStore.openIn(directory).confirmedFor(release))
    }

    @Test
    fun `edited document is rejected even when the index still lists it`() {
        val directory = temporary.newFolder("store-edit")
        val store = GhostlockProfileStore.openIn(directory)
        assertTrue(store.save(entry(confirmedAt = 3L)))
        val index = File(directory, GhostlockProfileStore.FILE_NAME)
        val edited = index.readText().replace("prio = 132", "prio = 999")
        index.writeText(edited)
        assertTrue(GhostlockProfileStore.openIn(directory).all().isEmpty())
    }

    @Test
    fun `overwrite replaces the superseded document`() {
        val store = GhostlockProfileStore.inMemory()
        assertTrue(store.save(entry()))
        assertTrue(store.dropSuperseded(setOf(release)))
        assertTrue(store.all().isEmpty())
    }

    @Test
    fun `parser is offered only when nothing matches`() {
        val store = GhostlockProfileStore.inMemory()
        assertTrue(GhostlockProfileGate.offersParser(
            GhostlockProfileGate.decide(release, packagedSupported = false, store = store)))
        assertTrue(store.save(entry(confirmedAt = 2L)))
        val imported = GhostlockProfileGate.decide(release, packagedSupported = false, store = store)
        assertTrue(GhostlockProfileGate.isOffered(imported))
        assertFalse(GhostlockProfileGate.offersParser(imported))
        assertFalse(GhostlockProfileGate.offersParser(
            GhostlockProfileGate.decide(release, packagedSupported = true, store = null)))
    }

    @Test
    fun `ota flow copy is the agreed wording`() {
        assertEquals(
            "当前机型没有内置 Ghostlock 配置。粘贴系统更新包直链，解析成功后即可尝试。",
            OtaCopy.MISSING_PROFILE,
        )
        assertEquals("正在解析…", OtaCopy.PARSING)
        assertEquals("解析成功，可以尝试 Ghostlock。", OtaCopy.SUCCESS)
        assertEquals("解析失败：链接无效", OtaCopy.failureLine(OtaFailure.INVALID_URL))
        assertEquals("解析失败：内核版本与本机不一致", OtaCopy.failureLine(OtaFailure.KERNEL_MISMATCH))
        assertEquals("解析失败：包里找不到内核", OtaCopy.failureLine(OtaFailure.NO_KERNEL))
        assertEquals("解析失败：无法下载更新包", OtaCopy.failureLine(OtaFailure.DOWNLOAD_FAILED))
        for (reason in OtaFailure.entries) {
            assertTrue(OtaCopy.failureLine(reason).startsWith("解析失败："))
        }
    }

    @Test
    fun `ota flow transitions are complete and never silently succeed`() {
        val flow = GhostlockOtaFlow(release)
        assertEquals(OtaParseState.Idle, flow.state)
        assertNull(OtaCopy.lineFor(OtaParseState.Idle))
        assertEquals(OtaParseState.Failed(OtaFailure.EMPTY_URL), flow.start(""))
        assertEquals(OtaParseState.Failed(OtaFailure.INVALID_URL), flow.start("ftp://x"))
        assertEquals(OtaParseState.Parsing, flow.start("https://example.com/ota.zip"))
        assertEquals("正在解析…", OtaCopy.lineFor(OtaParseState.Parsing))

        val failure = ExtractionOutcome.Failure(FailureKind.KALLSYMS, "kallsyms recovery failed")
        assertEquals(OtaParseState.Failed(OtaFailure.KALLSYMS_FAILED), flow.finish(failure))
        flow.reset()
        assertEquals(OtaParseState.Idle, flow.state)

        val generated = ExtractionOutcome.Generated(listOf(profile()))
        assertEquals(OtaParseState.Succeeded(release), flow.finish(generated))
        assertEquals("解析成功，可以尝试 Ghostlock。", OtaCopy.lineFor(flow.state))
    }

    @Test
    fun `incomplete profile is never reported as success`() {
        val incomplete = ExtractionOutcome.Generated(listOf(profile(invalid = true)))
        val flow = GhostlockOtaFlow(release)
        assertEquals(OtaParseState.Failed(OtaFailure.INCOMPLETE_PROFILE), flow.finish(incomplete))
        assertFalse(GhostlockProfileGate.isOffered(
            GhostlockProfileGate.decide(release, false, GhostlockProfileStore.inMemory())))
    }

    private fun profile(invalid: Boolean = false): GeneratedProfile {
        val validation = if (invalid) {
            ProfileValidation(listOf("task_struct.prio"), null)
        } else {
            ProfileValidation(emptyList(), ByteArray(32))
        }
        return GeneratedProfile(
            release = release,
            route = "select_stack",
            document = document,
            provenance = ProfileProvenance(
                kind = "ota_url",
                input = "https://example.com/ota.zip",
                generatedAt = "2026-10-31T00:00:00Z",
                documentSha256 = "0".repeat(64),
            ),
            validation = validation,
        )
    }
}
