package me.yuki.fina.adbroot.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.zip.GZIPInputStream

/**
 * Retained payloads, verified against the packaged source inventory before use.
 *
 * The inventory carries one payload set per packaged kernel profile:
 * - [KernelEngine.RETAINED] publishes the four names the retained flow reads
 *   verbatim (`louise`, `louise_cmd.sh`, `probe`, `PD2546-symbols.json`);
 * - [KernelEngine.PLANT] publishes one per-kernel plant as `plant`.
 *
 * The retained names are fixed on purpose: `RootFlow.kallsyms` reads the symbol
 * snapshot by that exact name, and renaming it would change the retained flow.
 */
object Payload {
    /** The symbol snapshot name the retained flow reads. */
    const val SYMBOLS = "PD2546-symbols.json"

    /** The device-side name of a per-kernel plant. */
    const val RUNNER = "plant"

    val names: Set<String> = setOf("louise", "louise_cmd.sh", "probe", SYMBOLS)

    private const val PAYLOAD_PREFIX = "maplesu-93260/payload/"
    private const val RUNNER_PREFIX = "maplesu-93260/plant/"

    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }

    private fun document(context: Context): JSONObject = try {
        context.assets.open("maplesu-jailbreak-artifacts.json").use {
            JSONObject(it.bufferedReader().readText())
        }
    } catch (error: Exception) {
        throw IOException("MAPLESU_93260_PAYLOAD_INVENTORY_INVALID", error)
    }

    private fun block(context: Context): JSONObject =
        document(context).optJSONObject("maplesu93260")
            ?: throw IOException("MAPLESU_93260_PAYLOAD_INVENTORY_INVALID")

    /** The catalog this APK carries; the compiled default is always included. */
    fun catalog(context: Context): KernelCatalog = KernelCatalog.parse(block(context))

    private fun entry(block: JSONObject, profile: KernelProfile): JSONObject? =
        block.optJSONArray("profiles")?.let { array ->
            (0 until array.length()).mapNotNull { array.optJSONObject(it) }
                .firstOrNull { it.optString("id") == profile.id }
        }

    /**
     * Files of one retained profile, in packaged order. A profile without an
     * inventory entry is not usable - it must never fall back to another
     * profile's files.
     */
    private fun files(block: JSONObject, profile: KernelProfile): JSONArray {
        val entry = entry(block, profile)
        val files = when {
            entry != null -> entry.optJSONArray("files")
            profile.id == KernelProfiles.DEFAULT_ID -> block.optJSONArray("files")
            else -> null
        } ?: throw IOException("MAPLESU_93260_PAYLOAD_PROFILE_MISSING:" + profile.id)
        val declared = when {
            entry != null -> entry.optString("kernelRelease").trim()
            else -> block.optString("kernelRelease").trim()
        }
        if (declared.isNotEmpty() && !profile.serves(declared))
            throw IOException("MAPLESU_93260_PAYLOAD_TARGET_MISMATCH")
        val devices = (0 until files.length()).mapNotNull {
            files.optJSONObject(it)?.optString("device")?.trim()?.takeIf(String::isNotEmpty)
        }
        if (devices.size != files.length() || devices.size != names.size ||
            devices.toSet() != names || devices.distinct().size != devices.size)
            throw IOException("MAPLESU_93260_PAYLOAD_INVENTORY_INVALID")
        return files
    }

    /** The single plant artifact of a per-kernel profile. */
    private fun runner(block: JSONObject, profile: KernelProfile): JSONObject {
        val entry = entry(block, profile)
            ?: throw IOException("MAPLESU_93260_PAYLOAD_PROFILE_MISSING:" + profile.id)
        // `runner` is the profile identity; `runnerFile` is its digest record.
        // A mismatch means the inventory and the catalog disagree: fail closed.
        if (entry.optString("runner").trim() != profile.runner)
            throw IOException("MAPLESU_93260_PAYLOAD_TARGET_MISMATCH")
        val runner = entry.optJSONObject("runnerFile")
            ?: throw IOException("MAPLESU_93260_PAYLOAD_PROFILE_MISSING:" + profile.id)
        val declared = entry.optString("kernelRelease").trim()
        if (declared.isNotEmpty() && !profile.serves(declared))
            throw IOException("MAPLESU_93260_PAYLOAD_TARGET_MISMATCH")
        return runner
    }

    private fun readAsset(context: Context, item: JSONObject, prefix: String): ByteArray {
        val asset = item.getString("asset")
        if (!asset.startsWith(prefix) || asset.contains(".."))
            throw IOException("MAPLESU_93260_PAYLOAD_PATH_INVALID")
        val bytes = context.assets.open(asset).use { it.readBytes() }
        if (bytes.size.toLong() != item.getLong("bytes") || digest(bytes) != item.getString("sha256"))
            throw IOException("MAPLESU_93260_PAYLOAD_DIGEST_MISMATCH:$asset")
        return bytes
    }

    private fun read(context: Context, item: JSONObject): ByteArray = readAsset(context, item, PAYLOAD_PREFIX)

    /** Verifies every profile this APK claims to carry. */
    fun verify(context: Context) {
        val block = block(context)
        val catalog = KernelCatalog.parse(block)
        for (profile in catalog.profiles) {
            when (profile.engine) {
                KernelEngine.RETAINED -> {
                    val files = files(block, profile)
                    for (i in 0 until files.length()) read(context, files.getJSONObject(i))
                }
                KernelEngine.PLANT -> readAsset(context, runner(block, profile), RUNNER_PREFIX)
            }
        }
    }

    /**
     * Local directory for one profile's decoded payloads. The compiled default
     * keeps its historical path so an update over an existing install does not
     * orphan the files a previous run published.
     */
    fun dir(context: Context, profile: KernelProfile = KernelMap.profile): File {
        val root = File(context.filesDir, "maplesu-93260/payload")
        return if (profile.id == KernelProfiles.DEFAULT_ID) root
        else File(root, profile.payloadKey)
    }

    fun ensure(context: Context, profile: KernelProfile = KernelMap.profile): File {
        val block = block(context)
        val out = dir(context, profile)
        if (!out.isDirectory && !out.mkdirs()) throw IOException("MAPLESU_93260_PAYLOAD_DIRECTORY")
        when (profile.engine) {
            KernelEngine.RETAINED -> {
                val files = files(block, profile)
                for (i in 0 until files.length()) {
                    val item = files.getJSONObject(i)
                    val bytes = read(context, item)
                    publish(out, item.getString("device"), item, bytes, decode = true)
                }
            }
            KernelEngine.PLANT -> {
                val item = runner(block, profile)
                val bytes = readAsset(context, item, RUNNER_PREFIX)
                publish(out, RUNNER, item, bytes, decode = false)
            }
        }
        return out
    }

    private fun publish(out: File, name: String, item: JSONObject, bytes: ByteArray, decode: Boolean) {
        val dst = File(out, name)
        val want = item.getString("decodedSha256")
        if (dst.isFile && digest(dst.readBytes()) == want) return
        val tmp = File(out, name + ".tmp")
        try {
            if (!decode) {
                tmp.writeBytes(bytes)
            } else {
                // Same GZIP transform as the supplied implementation.
                val stream = if (item.getBoolean("gzip")) GZIPInputStream(bytes.inputStream(), 1 shl 16)
                    else bytes.inputStream()
                stream.use { input -> tmp.outputStream().use { input.copyTo(it, 1 shl 16) } }
            }
            if (tmp.length() != item.getLong("decodedBytes") || digest(tmp.readBytes()) != want)
                throw IOException("MAPLESU_93260_PAYLOAD_DECODE_MISMATCH:$name")
            if (!tmp.renameTo(dst)) throw IOException("MAPLESU_93260_PAYLOAD_PUBLISH_FAILED")
            dst.setExecutable(true, true)
        } finally { tmp.delete() }
    }
}
