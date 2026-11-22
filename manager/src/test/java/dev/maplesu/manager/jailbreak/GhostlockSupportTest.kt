package dev.maplesu.manager.jailbreak

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host proof of the Ghostlock option gate.
 *
 * <p>The packaged list is GhostLock-App's `docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md`
 * (`https://github.com/YuKongA/ghostlock-app/blob/main/docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md`).
 * These tests run on the JVM against the real packaged bytes, so they pin three
 * separate things:
 *
 * 1. integrity: the asset still carries the provenance header and the row counts
 *    of the document it was generated from (source sha256 / entry counts);
 * 2. policy: matching is exact `uname -r` equality - a case change, a suffix, a
 *    prefix or a whitespace difference all miss;
 * 3. fail-closed: a missing, malformed, provenance-less or count-tampered list
 *    reads as UNSUPPORTED for every release, never as a silent allow.
 */
class GhostlockSupportTest {

    /** The measured device of this workspace (OnePlus 13 / PLQ110, OxygenOS 16). */
    private val measured = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"

    /** A release that *is* in the upstream table, used as the positive control. */
    private val listedOnePlus13 = "6.6.89-android15-8-gf4dc45704e54-abogki446052083-4k"

    private val assetFile: File = sequenceOf(
        File("src/main/assets/ghostlock/supported-devices.json"),
        File("manager/src/main/assets/ghostlock/supported-devices.json"),
    ).firstOrNull { it.isFile }
        ?: throw AssertionError("packaged asset not found under " + File("").absolutePath)

    private val assetText: String by lazy { assetFile.readText(Charsets.UTF_8) }
    private val list: GhostlockSupport by lazy { GhostlockSupport.fromJson(assetText) }
    private val root: JsonObject by lazy { Json.parseToJsonElement(assetText).jsonObject }

    // --- integrity of the packaged asset ---------------------------------------

    @Test
    fun assetCarriesTheProvenanceItWasGeneratedFrom() {
        assertEquals(
            "https://raw.githubusercontent.com/YuKongA/ghostlock-app/main/" +
                "docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md",
            list.provenance?.sourceUrl,
        )
        assertEquals(
            "https://github.com/YuKongA/ghostlock-app/blob/main/" +
                "docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md",
            root.string("sourcePageUrl"),
        )
        // sha256 of the fetched document bytes. Pinned: regenerating from a
        // different revision of the upstream table must fail here first.
        assertEquals(
            "34793b22a2485033f2cc61058f72a62bd772cf5cdeeef8b8a45a60c602e9bab2",
            list.provenance?.sourceSha256,
        )
        assertEquals("437b3b257462e17d395cfd2cd8fb81536d6c6358", list.provenance?.commit)
        assertEquals("2026-10-31T09:44:13Z", list.provenance?.fetchedAt)
        // 11247 bytes is the size of that document; a different size means the
        // digest and the list no longer describe the same file.
        assertEquals(11247, root.int("sourceBytes") ?: -1)
    }

    @Test
    fun assetRowAndReleaseCountsMatchTheUpstreamTable() {
        // The upstream table lists 76 rows and one kernel twice.
        assertEquals(76, root.int("entryCount") ?: -1)
        assertEquals(75, root.int("uniqueReleaseCount") ?: -1)
        assertEquals(76, root.array("devices").size)
        assertEquals(76, list.rowCount)
        assertEquals(75, list.releaseCount)
        assertTrue(list.isUsable)
    }

    @Test
    fun everyPackagedRowIsAMatchableUnameRelease() {
        for (row in root.array("devices")) {
            val entry = row.jsonObject
            val release = entry.string("unameRelease").orEmpty()
            assertTrue("blank release in $entry", release.isNotBlank())
            assertFalse("whitespace release in $entry", release.any { it.isWhitespace() })
            assertNotNull("row $release is not matchable", list.device(release))
            // Round-trip: every packaged row must be SUPPORTED by the verifier.
            assertEquals(GhostlockSupport.Support.SUPPORTED, list.isSupported(release))
            assertTrue("blank device for $release", entry.string("device").orEmpty().isNotBlank())
        }
    }

    @Test
    fun upstreamNotesAndDeviceNamesSurviveTheParse() {
        assertEquals("推荐Shizuku",
            list.device("5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412")?.note)
        assertEquals("建议使用 Shizuku",
            list.device("6.6.30-android15-8-g24ffe62b0a0e-abogki387229724-4k")?.note)
        assertEquals("MEIZU 20 Pro",
            list.device("5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412")?.device)
        // Commas and slashes are part of the device name, not separators.
        assertEquals("Xiaomi Civi 5 Pro, REDMI K90 / 4 Turbo, POCO F7",
            list.device("6.6.77-android15-8-g4a507830d890-ab13636293-4k")?.device)
        assertEquals("", list.device("6.6.77-android15-8-g4a507830d890-ab13636293-4k")?.note)
    }

    // --- the measured device of this workspace ---------------------------------

    @Test
    fun thisWorkspaceDeviceIsNotInTheUpstreamList() {
        val verdict = list.isSupported(measured)
        assertTrue("measured device unexpectedly listed: $verdict",
            verdict is GhostlockSupport.Support.UNSUPPORTED)
        assertEquals(GhostlockSupport.Reason.NOT_IN_SUPPORTED_LIST,
            (verdict as GhostlockSupport.Support.UNSUPPORTED).reason)
        assertNull(list.device(measured))
        // The list is not simply empty: the closest OnePlus 13 build is present
        // and is a different kernel (different g-hash and different abogki id).
        assertEquals(GhostlockSupport.Support.SUPPORTED, list.isSupported(listedOnePlus13))
        assertEquals("OnePlus 13", list.device(listedOnePlus13)?.device)
    }

    // --- exact matching, by construction --------------------------------------

    @Test
    fun matchingIsExactAndNeverApproximate() {
        val misses = listOf(
            listedOnePlus13.uppercase(),                 // case
            listedOnePlus13.dropLast(1),                 // prefix / truncation
            listedOnePlus13 + "-dirty",                  // suffix
            listedOnePlus13 + " ",
            " $listedOnePlus13",
            "$listedOnePlus13\n",
            listedOnePlus13.replace("6.6.89", "6.6.8"),   // near-miss version
            listedOnePlus13.substringBefore("-abogki"),   // shorter form
            listedOnePlus13.replace("android15", "android16"), // KMI change
        )
        for (candidate in misses) {
            val verdict = list.isSupported(candidate)
            assertTrue("approximate match admitted: $candidate",
                verdict is GhostlockSupport.Support.UNSUPPORTED)
            assertEquals(candidate, GhostlockSupport.Reason.NOT_IN_SUPPORTED_LIST,
                (verdict as GhostlockSupport.Support.UNSUPPORTED).reason)
        }
        assertEquals(GhostlockSupport.Reason.KERNEL_RELEASE_EMPTY,
            (list.isSupported("") as GhostlockSupport.Support.UNSUPPORTED).reason)
    }

    // --- fail-closed ----------------------------------------------------------

    @Test
    fun aMissingListDisablesEveryRelease() {
        val missing = GhostlockSupport.unavailable(GhostlockSupport.Reason.LIST_MISSING)
        assertFalse(missing.isUsable)
        assertEquals(0, missing.releaseCount)
        assertNull(missing.provenance)
        for (release in listOf(listedOnePlus13, measured, "", "anything")) {
            val verdict = missing.isSupported(release)
            assertEquals(GhostlockSupport.Reason.LIST_MISSING,
                (verdict as GhostlockSupport.Support.UNSUPPORTED).reason)
        }
    }

    @Test
    fun anUnparseableListDisablesEveryRelease() {
        for (text in listOf(
            "",
            "   ",
            "not json at all",
            "[]",
            "{}",
            """{"sourceUrl":"x"}""",
            """{"devices":[]}""",
            """{"sourceUrl":"x","sourceSha256":"zz","devices":[]}""",
        )) {
            val parsed = GhostlockSupport.fromJson(text)
            assertFalse("accepted: $text", parsed.isUsable)
            val verdict = parsed.isSupported(listedOnePlus13)
            assertTrue("list accepted for $text",
                verdict is GhostlockSupport.Support.UNSUPPORTED)
            assertEquals(GhostlockSupport.Reason.LIST_UNPARSEABLE,
                (verdict as GhostlockSupport.Support.UNSUPPORTED).reason)
        }
    }

    @Test
    fun aListWithoutProvenanceOrWithTamperedCountsFailsClosed() {
        val cases = mapOf(
            "provenance-missing:sourceUrl" to assetWith { remove("sourceUrl") },
            "provenance-missing:sourceSha256" to assetWith { remove("sourceSha256") },
            "provenance-invalid:sourceSha256" to assetWith {
                put("sourceSha256", JsonPrimitive("not-a-digest"))
            },
            "entry-count-mismatch" to assetWith { put("entryCount", JsonPrimitive(77)) },
            "unique-count-mismatch" to assetWith { put("uniqueReleaseCount", JsonPrimitive(76)) },
            "devices-missing" to assetWith { remove("devices") },
            "devices-empty" to assetWith { put("devices", JsonArray(emptyList())) },
            "release-whitespace" to oneRow("$listedOnePlus13 "),
            "release-empty" to oneRow(""),
        )
        for ((expected, text) in cases) {
            val parsed = GhostlockSupport.fromJson(text)
            assertFalse("accepted a tampered asset ($expected)", parsed.isUsable)
            val verdict = parsed.isSupported(listedOnePlus13)
            val detail = (verdict as GhostlockSupport.Support.UNSUPPORTED).detail
            assertEquals("wrong reason for $expected: $detail",
                GhostlockSupport.Reason.LIST_UNPARSEABLE, verdict.reason)
            assertTrue("detail lost the cause ($expected): $detail",
                detail.startsWith(expected))
        }
    }

    @Test
    fun theDuplicateUpstreamRowCollapsesButStillMatches() {
        // `6.1.134-android14-11-maybe-dirty` is listed twice upstream (both rows
        // name the same firmware). One entry, still matchable.
        val duplicate = "6.1.134-android14-11-maybe-dirty"
        assertEquals("Boox Onyx NoteAir6C", list.device(duplicate)?.device)
        assertEquals(GhostlockSupport.Support.SUPPORTED, list.isSupported(duplicate))
    }

    // --- helpers --------------------------------------------------------------

    private fun JsonObject.string(key: String): String? =
        (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

    private fun JsonObject.int(key: String): Int? =
        (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.let { it.content.toIntOrNull() }

    private fun JsonObject.array(key: String): JsonArray =
        this[key] as? JsonArray ?: throw AssertionError("missing array: $key")

    /** The real asset with one header/body change, re-serialized. */
    private fun assetWith(block: MutableMap<String, JsonElement>.() -> Unit): String {
        val mutable = root.toMutableMap()
        mutable.block()
        return JsonObject(mutable).toString()
    }

    /** A provenance-complete asset whose only row is [release]. */
    private fun oneRow(release: String): String = JsonObject(
        root.toMutableMap().apply {
            put("devices", buildJsonArray {
                add(buildJsonObject {
                    put("unameRelease", JsonPrimitive(release))
                    put("device", JsonPrimitive("OnePlus 13"))
                    put("note", JsonPrimitive(""))
                })
            })
            put("entryCount", JsonPrimitive(1))
            put("uniqueReleaseCount", JsonPrimitive(1))
        },
    ).toString()
}
