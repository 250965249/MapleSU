package dev.maplesu.manager.ultra

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.ModuleArchiveInspector.Failure
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * A09 negative cases, exercised against the product's own archive inspector on device.
 *
 * Each case mutates a real, already-recognised archive (the vendor's `module_hello_world.zip`)
 * so the rejection is attributable to exactly one property:
 *
 *   1. the module ELF is not at the archive root        -> not routed to the Ultra backend
 *   2. `module.prop` is present next to the ELF         -> ambiguous module type
 *   3. the descriptor id32 carries an underscore        -> invalid MapleSU module
 *   4. the archive is truncated                         -> invalid archive
 *
 * Case 3 is the documented market conflict: the SDK's compile-time check only enforces
 * length 33 (32 characters), while the product's descriptor parser requires
 * `[A-Za-z0-9]{32}`. This test pins the product's current decision instead of relaxing it.
 *
 * Opt-in: `-e verifyUltraNegatives true`. Expects `hw-vendor.zip` in the app external files dir.
 */
class UltraModuleRejectionAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val results = JSONArray()

    private fun baseZip(): File {
        val zip = File(context.getExternalFilesDir(null), "hw-vendor.zip")
        assertTrue("push the vendor sample to ${zip.absolutePath}", zip.isFile)
        return zip
    }

    private fun record(case: String, outcome: String, detail: String?) {
        results.put(JSONObject().put("case", case).put("outcome", outcome).put("detail", detail ?: ""))
        android.util.Log.i("MAPLESU_EVIDENCE", "ultra-negative $case -> $outcome (${detail ?: ""})")
    }

    private fun entryBytes(zip: File, name: String): ByteArray =
        ZipFile(zip).use { archive -> archive.getInputStream(archive.getEntry(name)).readBytes() }

    private fun writeZip(target: File, entries: List<Pair<String, ByteArray>>) {
        ZipOutputStream(target.outputStream()).use { out ->
            entries.forEach { (name, data) ->
                out.putNextEntry(ZipEntry(name))
                out.write(data)
                out.closeEntry()
            }
        }
    }

    private fun indexOfBytes(haystack: ByteArray, needle: ByteArray, from: Int): Int {
        for (index in from..haystack.size - needle.size) {
            var match = true
            for (offset in needle.indices) {
                if (haystack[index + offset] != needle[offset]) { match = false; break }
            }
            if (match) return index
        }
        fail("marker not found in the archive")
        return -1
    }

    private fun expectFailure(case: String, file: File): String? {
        return try {
            val report = ModuleArchiveInspector.inspect(file)
            record(case, "unexpectedly-accepted", "type=${report.type} id=${report.id}")
            null
        } catch (failure: Failure) {
            record(case, "rejected", failure.code)
            failure.code
        } catch (error: Exception) {
            record(case, "rejected-throw", "${error.javaClass.simpleName}: ${error.message}")
            error.javaClass.simpleName
        }
    }

    @Test
    fun mutatedArchivesAreRejectedForTheExpectedReason() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyUltraNegatives") == "true")
        val base = baseZip()
        val so = entryBytes(base, "libmodule_hello_world.so")
        val cache = File(context.cacheDir, "ultra-negative").apply { mkdirs() }

        // 1. nested ELF: the host only treats a root-level .so as the module binary
        val nested = File(cache, "nested.zip")
        writeZip(nested, listOf("lib/libmodule_hello_world.so" to so))
        val nestedCode = expectFailure("nested-elf", nested)
        assertEquals("MISSING_MODULE_METADATA", nestedCode)

        // 2. module.prop next to the ELF: two metadata sources are ambiguous
        val ambiguous = File(cache, "ambiguous.zip")
        val prop = "id=demo\nname=demo\nversion=1.0.0\nversionCode=1\n".toByteArray()
        writeZip(ambiguous, listOf("libmodule_hello_world.so" to so, "module.prop" to prop))
        assertEquals("AMBIGUOUS_MODULE_TYPE", expectFailure("module-prop-present", ambiguous))

        // 3. underscore in id32: legal to the SDK's length check, rejected by the product parser.
        // The value sits between the id begin/end TAG markers, so locate it through those and
        // patch inside the value region - not the first textual occurrence, which may sit in
        // another section and would leave the descriptor intact.
        val idBegin = "b33dcddd88c07d079a8e0e9ec6ab976f15f2edba46cab91a61234cfbb982111c".toByteArray()
        val idEnd = "3020d9a6c07a30e2649dd29a72d7e57121f0c0ca457b6d21dca5a69acbe6c2c4".toByteArray()
        val patched = so.copyOf()
        val valueStart = indexOfBytes(patched, idBegin, 0) + idBegin.size
        val valueEnd = indexOfBytes(patched, idEnd, valueStart)
        val originalId = String(patched, valueStart, valueEnd - valueStart, Charsets.UTF_8)
        assertEquals("3608c9af28db4dcfc05c32bbc584753e", originalId)
        patched[valueEnd - 1] = '_'.code.toByte()
        val underscore = File(cache, "underscore.zip")
        writeZip(underscore, listOf("libmodule_hello_world.so" to patched))
        assertEquals("INVALID_MAPLESU_MODULE", expectFailure("underscore-id32", underscore))

        // 4. truncated archive
        val truncated = File(cache, "truncated.zip")
        val whole = base.readBytes()
        truncated.writeBytes(whole.copyOf(whole.size / 2))
        val truncatedCode = expectFailure("truncated-archive", truncated)
        assertTrue("truncated archive must be refused, got $truncatedCode", truncatedCode != null)

        val output = File(context.filesDir, "ultra-negative-cases.json")
        output.writeText(results.toString(2))
        assertTrue("every negative case was recorded", results.length() == 4)
    }
}
