package dev.maplesu.ghostlock.extract

import com.ghostlock.app.data.HoconSupport
import com.ghostlock.app.data.ValueMap
import com.ghostlock.app.data.asValueMap
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.io.File
import java.io.IOException
import java.security.MessageDigest

/**
 * Imported Ghostlock profiles (documents the user parsed or imported), with the
 * provenance the product promises to keep.
 *
 * The store is a single JSON index. Every read is fail-closed: an unreadable,
 * malformed or partially written file yields an empty list, so a corrupted store
 * can never make a kernel look supported. Writes are atomic (temp file +
 * rename), so a crash mid-write keeps the previous document set.
 *
 * A document is a *candidate* until [confirm] is called. Only confirmed
 * documents participate in the Ghostlock availability gate, and only on an exact
 * `uname -r` match (never a prefix or KMI-family match).
 */
class GhostlockProfileStore private constructor(private val file: File?) {
    /** Backing entries when there is no file (tests, and callers with no storage). */
    private var memory: List<Entry> = emptyList()
    /** One stored document. [confirmedAt] is null while the document is a candidate. */
    data class Entry(
        val name: String,
        val text: String,
        val releases: List<String>,
        val source: String,
        val input: String,
        val createdAt: Long,
        val confirmedAt: Long?,
        val documentSha256: String,
        /** ISO-8601 UTC generation time recorded by the extractor, when known. */
        val generatedAt: String = "",
        val referenceCommit: String = "",
    ) {
        // Cached image-derived offsets from the old JVM recipe need reparsing.
        // Explicit document imports retain their existing confirmation behavior.
        val confirmed: Boolean get() = confirmedAt != null && when (source) {
            "local_image", "local_ota", "ota_url" ->
                referenceCommit == GhostlockNativeExtractor.REFERENCE_COMMIT
            else -> true
        }
    }

    private val lock = Any()

    /** Every readable entry, in insertion order. Never throws. */
    fun all(): List<Entry> = synchronized(lock) { read() }

    /** True when any stored document (candidate or confirmed) carries [release]. */
    fun has(release: String): Boolean = all().any { release in it.releases }

    /** The exact confirmed document for [release], or null. */
    fun confirmedFor(release: String): Entry? = all().firstOrNull { entry ->
        entry.confirmed && release in entry.releases && documentCarries(entry.text, release)
    }

    /** Releases a confirmed imported document can serve (exact strings). */
    fun confirmedReleases(): Set<String> = all()
        .filter { it.confirmed }
        .flatMap { it.releases }
        .toSet()

    /** Insert or replace one document by [Entry.name]. Returns false on IO failure. */
    fun save(entry: Entry): Boolean = synchronized(lock) {
        val entries = read().toMutableList()
        entries.removeAll { it.name == entry.name }
        entries.add(entry)
        write(entries)
    }

    /** Mark every document carrying [release] confirmed at [now]. */
    fun confirm(release: String, now: Long = System.currentTimeMillis()): Boolean = synchronized(lock) {
        val entries = read().map { entry ->
            if (release in entry.releases) entry.copy(confirmedAt = entry.confirmedAt ?: now) else entry
        }
        write(entries)
    }

    /** Drop documents fully superseded by [releases] (the reference's overwrite rule). */
    fun dropSuperseded(releases: Set<String>): Boolean = synchronized(lock) {
        val entries = read().filterNot { entry ->
            entry.releases.isNotEmpty() && entry.releases.all { it in releases }
        }
        write(entries)
    }

    fun delete(name: String): Boolean = synchronized(lock) {
        write(read().filterNot { it.name == name })
    }

    fun deleteAll(): Boolean = synchronized(lock) { write(emptyList()) }

    /** Names currently stored, for diagnostics. */
    fun names(): List<String> = all().map { it.name }

    private fun read(): List<Entry> {
        val target = file ?: return memory
        if (!target.isFile) return emptyList()
        val text = try {
            target.readText()
        } catch (error: IOException) {
            return emptyList()
        }
        val root = try {
            Json.parseToJsonElement(text).jsonObject
        } catch (error: RuntimeException) {
            return emptyList()
        }
        if (root["schemaVersion"]?.jsonPrimitive?.longOrNull != SCHEMA_VERSION) return emptyList()
        val profiles = root["profiles"]?.jsonArray ?: return emptyList()
        val out = ArrayList<Entry>()
        for (element in profiles) {
            val item = element as? JsonObject ?: continue
            val name = item["name"]?.jsonPrimitive?.contentOrEmpty() ?: continue
            val document = item["text"]?.jsonPrimitive?.contentOrEmpty() ?: continue
            if (name.isEmpty() || document.isEmpty()) continue
            val releases = (item["releases"] as? JsonArray)
                ?.mapNotNull { it.jsonPrimitive.contentOrEmpty()?.takeIf(String::isNotEmpty) }
                ?: emptyList()
            if (releases.isEmpty()) continue
            val source = item["source"]?.jsonPrimitive?.contentOrEmpty() ?: ""
            val input = item["input"]?.jsonPrimitive?.contentOrEmpty() ?: ""
            val createdAt = item["createdAt"]?.jsonPrimitive?.longOrNull ?: 0L
            val confirmedAt = item["confirmedAt"]?.jsonPrimitive?.longOrNull
            val digest = item["documentSha256"]?.jsonPrimitive?.contentOrEmpty()
                ?: sha256(document.toByteArray(Charsets.UTF_8))
            val generatedAt = item["generatedAt"]?.jsonPrimitive?.contentOrEmpty() ?: ""
            val referenceCommit = item["referenceCommit"]?.jsonPrimitive?.contentOrEmpty() ?: ""
            // A stored digest that no longer matches the document means an edited
            // or corrupted store: refuse the entry rather than trust it.
            if (digest != sha256(document.toByteArray(Charsets.UTF_8))) continue
            out.add(Entry(name, document, releases, source, input, createdAt, confirmedAt, digest,
                generatedAt, referenceCommit))
        }
        return out
    }

    private fun write(entries: List<Entry>): Boolean {
        val target = file ?: run {
            memory = entries.toList()
            return true
        }
        return try {
            target.parentFile?.mkdirs()
            val document = buildJsonObject {
                put("schemaVersion", JsonPrimitive(SCHEMA_VERSION))
                put("profiles", buildJsonArray {
                    for (entry in entries) {
                        add(buildJsonObject {
                            put("name", JsonPrimitive(entry.name))
                            put("text", JsonPrimitive(entry.text))
                            put("releases", buildJsonArray {
                                entry.releases.forEach { add(JsonPrimitive(it)) }
                            })
                            put("source", JsonPrimitive(entry.source))
                            put("input", JsonPrimitive(entry.input))
                            put("createdAt", JsonPrimitive(entry.createdAt))
                            entry.confirmedAt?.let { put("confirmedAt", JsonPrimitive(it)) }
                            put("documentSha256", JsonPrimitive(entry.documentSha256))
                            if (entry.generatedAt.isNotEmpty()) {
                                put("generatedAt", JsonPrimitive(entry.generatedAt))
                            }
                            if (entry.referenceCommit.isNotEmpty()) {
                                put("referenceCommit", JsonPrimitive(entry.referenceCommit))
                            }
                        })
                    }
                })
            }
            val temporary = File(target.parentFile, target.name + ".tmp")
            temporary.writeText(document.toString())
            if (target.exists()) target.delete()
            temporary.renameTo(target) || run {
                target.writeText(document.toString())
                temporary.delete()
                true
            }
        } catch (error: IOException) {
            false
        }
    }

    /** True when [text] parses and carries exactly this [release]. */
    private fun documentCarries(text: String, release: String): Boolean = try {
        val parsed = HoconSupport.parseValue(text)
        val entries: List<ValueMap> = when (parsed) {
            is Map<*, *> -> listOfNotNull(parsed.asValueMap())
            is List<*> -> parsed.mapNotNull { it.asValueMap() }
            else -> emptyList()
        }
        entries.any { candidate ->
            if (LegacyOffsetsConverter.isLegacy(candidate)) LegacyOffsetsConverter.convertValue(candidate)
            candidate["release"] == release
        }
    } catch (error: RuntimeException) {
        false
    }

    companion object {
        const val SCHEMA_VERSION = 1L
        const val FILE_NAME = "ghostlock-imported.json"

        /** Store backed by [file] (created on first write). */
        fun open(file: File): GhostlockProfileStore = GhostlockProfileStore(file)

        /** Store backed by `directory/ghostlock-imported.json`. */
        fun openIn(directory: File): GhostlockProfileStore =
            GhostlockProfileStore(File(directory, FILE_NAME))

        /** In-memory store for tests and for a call that has no storage. */
        fun inMemory(): GhostlockProfileStore = GhostlockProfileStore(null)

        fun sha256(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

        private fun JsonPrimitive.contentOrEmpty(): String? = content.takeIf { it.isNotEmpty() }
    }

    /** Convenience: build an entry for a generated document. */
    fun entryFor(
        profile: GeneratedProfile,
        name: String = profile.release + ".conf",
        createdAt: Long = System.currentTimeMillis(),
    ): Entry = Entry(
        name = name,
        text = profile.document,
        releases = listOf(profile.release),
        source = profile.provenance.kind,
        input = profile.provenance.input,
        createdAt = createdAt,
        confirmedAt = null,
        documentSha256 = sha256(profile.document.toByteArray(Charsets.UTF_8)),
        generatedAt = profile.provenance.generatedAt,
        referenceCommit = profile.provenance.referenceCommit,
    )
}
