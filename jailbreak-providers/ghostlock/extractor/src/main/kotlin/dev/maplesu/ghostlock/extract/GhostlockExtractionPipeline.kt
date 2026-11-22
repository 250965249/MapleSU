package dev.maplesu.ghostlock.extract

import com.ghostlock.app.data.asValueMap
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.time.Instant

/** What the user pointed the extractor at. */
sealed interface ExtractInput {
    /** A pasted full-OTA ZIP link; the payload is read by range requests. */
    data class OtaUrl(val url: String) : ExtractInput

    /** A local boot image, optionally with `xbl_config.img` / `uefi.img` / `vendor_boot.img`. */
    data class BootImageFile(
        val boot: File,
        val xblConfig: File? = null,
        val uefi: File? = null,
        val vendorBoot: File? = null,
    ) : ExtractInput

    /** A local full-OTA ZIP or a raw `payload.bin`. */
    data class LocalArchive(val file: File) : ExtractInput

    /** `offsets.conf` v2 (HOCON) import. */
    data class OffsetsConf(val name: String, val text: String) : ExtractInput

    /** `offsets.json` v1 import (converted in memory, like the reference). */
    data class OffsetsJson(val name: String, val text: String) : ExtractInput
}

/** Where a stored document came from. */
data class ProfileProvenance(
    /** Wire name of the source kind: `ota_url`, `local_image`, `local_ota`, `offsets_conf`, `offsets_json`. */
    val kind: String,
    /** URL or file path as the user supplied it. */
    val input: String,
    /** ISO-8601 UTC generation timestamp. */
    val generatedAt: String,
    /** SHA-256 of the generated document. */
    val documentSha256: String,
    /** SHA-256 of the local source file, when there was one. */
    val sourceSha256: String? = null,
    /** The reference commit this pipeline follows, recorded with every artefact. */
    val referenceCommit: String = REFERENCE_COMMIT,
) {
    companion object {
        const val REFERENCE_COMMIT = "437b3b2"
    }
}

/**
 * One generated (or imported) profile document.
 *
 * `invalidFields` and [wire] are computed by the same validation the executor
 * runs; the document is a candidate until it validates *and* the user confirms
 * it (image/OTA paths auto-confirm on an exact device-release match, which is
 * the product's flow).
 */
class GeneratedProfile(
    val release: String,
    val route: String?,
    val document: String,
    val provenance: ProfileProvenance,
    val validation: ProfileValidation,
) {
    /** False while any required field is missing/invalid: never a runnable profile. */
    val complete: Boolean get() = validation.complete
}

/** Outcome of one user-triggered extraction/import action. */
sealed interface ExtractionOutcome {
    /** At least one document was produced; [profiles] may still be incomplete. */
    data class Generated(val profiles: List<GeneratedProfile>) : ExtractionOutcome

    /** Every release in the input is already stored; ask before replacing it. */
    data class NeedsOverwrite(
        val releases: List<String>,
        val profiles: List<GeneratedProfile>,
    ) : ExtractionOutcome

    /** The input is a valid document but carries no `release`. */
    data object AlreadyPresent : ExtractionOutcome

    /** Fail-closed failure. [message] is diagnostics, never user copy. */
    data class Failure(val kind: FailureKind, val message: String) : ExtractionOutcome
}

/**
 * The user-triggered extraction pipeline: OTA link / local image / local archive
 * / `offsets.conf` / `offsets.json` -> generated v2 profile document.
 *
 * The App supplies [GhostlockNativeExtractor], built from the retained reference
 * source, for image-derived geometry, credentials and physical addresses.
 * A caller without an image extractor gets the limited JVM recipe used by the
 * synthetic fixtures. Both paths validate the candidate before it is offered.
 *
 * Nothing is downloaded or read unless [parse] is called; there is no background
 * work and no implicit network access.
 */
object GhostlockExtractionPipeline {
    /** Hard bound for a locally read boot image / archive. */
    const val MAX_LOCAL_IMAGE_BYTES = 512L * 1024 * 1024

    /** The largest release string the wire accepts (`GhostlockWire`). */
    private val WIRE_RELEASE = Regex("^[A-Za-z0-9._+\\-]{1,255}$")

    /**
     * Parse [input].
     *
     * @param workDir a writable directory for OTA extraction artefacts.
     * @param validator the field validator (defaults to the pure-JVM recipe).
     * @param imageExtractor the complete retained extractor used by the App.
     */
    fun parse(
        input: ExtractInput,
        workDir: File,
        validator: ProfileValidator = HoconProfileValidator(),
        imageExtractor: KernelImageExtractor? = null,
        onLog: (String) -> Unit = {},
    ): ExtractionOutcome = try {
        when (input) {
            is ExtractInput.OtaUrl -> parseOtaUrl(input, workDir, validator, imageExtractor, onLog)
            is ExtractInput.BootImageFile -> {
                val provenance = ProfileProvenance(
                    kind = "local_image",
                    input = input.boot.absolutePath,
                    generatedAt = Instant.now().toString(),
                    documentSha256 = "",
                    sourceSha256 = sha256(input.boot),
                )
                deriveImage(input, provenance, validator, imageExtractor, workDir, onLog)
            }

            is ExtractInput.LocalArchive -> parseLocalArchive(input, workDir, validator, imageExtractor, onLog)
            is ExtractInput.OffsetsConf -> importDocument(input.name, input.text, false, validator)
            is ExtractInput.OffsetsJson -> importDocument(input.name, input.text, true, validator)
        }
    } catch (error: ExtractionException) {
        ExtractionOutcome.Failure(error.kind, error.message ?: error.kind.name)
    } catch (error: IOException) {
        ExtractionOutcome.Failure(FailureKind.GENERIC, error.message ?: "io error")
    } catch (error: RuntimeException) {
        ExtractionOutcome.Failure(FailureKind.GENERIC, error.message ?: error.javaClass.simpleName)
    }

    private fun parseOtaUrl(
        input: ExtractInput.OtaUrl,
        workDir: File,
        validator: ProfileValidator,
        imageExtractor: KernelImageExtractor?,
        onLog: (String) -> Unit,
    ): ExtractionOutcome {
        if (!HttpRangeSource.isSupported(input.url)) {
            throw ExtractionException(FailureKind.GENERIC, "not an http(s) OTA URL")
        }
        val source = HttpRangeSource(input.url)
        val extracted = OtaPayloadExtractor.extractPartitions(source, workDir, onLog)
        try {
            val provenance = ProfileProvenance(
                kind = "ota_url",
                input = input.url,
                generatedAt = Instant.now().toString(),
                documentSha256 = "",
            )
            return deriveImage(
                extracted.images(), provenance, validator, imageExtractor, workDir, onLog,
            )
        } finally {
            extracted.delete()
        }
    }

    private fun parseLocalArchive(
        input: ExtractInput.LocalArchive,
        workDir: File,
        validator: ProfileValidator,
        imageExtractor: KernelImageExtractor?,
        onLog: (String) -> Unit,
    ): ExtractionOutcome {
        val source = FileRangeSource(input.file)
        val head = source.read(0, 8) ?: throw IOException("cannot read ${input.file.name}")
        val provenanceBase = ProfileProvenance(
            kind = "local_ota",
            input = input.file.absolutePath,
            generatedAt = Instant.now().toString(),
            documentSha256 = "",
            sourceSha256 = sha256(input.file),
        )
        if (head.size >= 4 && head.copyOfRange(0, 4).contentEquals(PayloadBin.PAYLOAD_MAGIC)) {
            val extracted = OtaPayloadExtractor.extractPartitions(source, workDir, onLog)
            try {
                return deriveImage(
                    extracted.images(), provenanceBase, validator, imageExtractor, workDir, onLog,
                )
            } finally {
                extracted.delete()
            }
        }
        if (head.size >= 4 && head[0].toInt() == 'P'.code && head[1].toInt() == 'K'.code &&
            head[2].toInt() == 3 && head[3].toInt() == 4
        ) {
            val extracted = OtaPayloadExtractor.extractPartitions(source, workDir, onLog)
            try {
                return deriveImage(
                    extracted.images(), provenanceBase, validator, imageExtractor, workDir, onLog,
                )
            } finally {
                extracted.delete()
            }
        }
        // A raw arm64 Image / Android boot image picked as an "archive".
        return deriveImage(ExtractInput.BootImageFile(input.file),
            provenanceBase, validator, imageExtractor, workDir, onLog)
    }

    private fun deriveImage(
        input: ExtractInput.BootImageFile, provenance: ProfileProvenance,
        validator: ProfileValidator, imageExtractor: KernelImageExtractor?,
        workDir: File, onLog: (String) -> Unit,
    ): ExtractionOutcome {
        if (imageExtractor == null) {
            val boot = readLocalImage(input.boot)
            return derive(boot.first, boot.second, provenance, validator, onLog)
        }
        val document = imageExtractor.extract(input, workDir, onLog)
        val imported = importDocument(input.boot.name, document, false, validator)
        if (imported !is ExtractionOutcome.Generated) {
            throw IOException("extractor output carries no kernel release")
        }
        return ExtractionOutcome.Generated(imported.profiles.map { profile ->
            GeneratedProfile(profile.release, profile.route, profile.document,
                provenance.copy(documentSha256 = sha256(profile.document.toByteArray(Charsets.UTF_8)),
                    sourceSha256 = provenance.sourceSha256 ?: sha256(input.boot),
                    referenceCommit = GhostlockNativeExtractor.REFERENCE_COMMIT),
                profile.validation)
        })
    }

    /** Read and parse one local image with the reference's size bound. */
    private fun readLocalImage(file: File): Pair<BootImage, ByteArray> {
        if (!file.isFile) throw IOException("file not found: ${file.name}")
        if (file.length() > MAX_LOCAL_IMAGE_BYTES) {
            throw IOException("image exceeds the ${MAX_LOCAL_IMAGE_BYTES} byte bound")
        }
        val bytes = file.readBytes()
        return BootImage.load(bytes) to bytes
    }

    private fun derive(
        boot: BootImage,
        rawBytes: ByteArray,
        provenanceBase: ProfileProvenance,
        validator: ProfileValidator,
        onLog: (String) -> Unit,
    ): ExtractionOutcome {
        val btfBlob = boot.embeddedBtfAt()
        val btf = btfBlob?.let { Btf.parse(it.bytes) }
        if (btf == null) {
            onLog("no embedded BTF; struct offsets will be null and the profile cannot be used")
        }
        val kallsyms = KallsymsRecovery.recover(boot.kernel, btfBlob)
        val base = kallsyms.unique("_text") ?: kallsyms.unique("_head")
            ?: throw ExtractionException(
                FailureKind.GENERIC, "_text/_head is not unique in kallsyms")
        val symbols = KernelLayout.resolveSymbols(kallsyms, base).toMutableMap()
        /*
         * The reference's optional symbols (only `security_hook_heads` today)
         * emit 0 when kallsyms has no such symbol: the runtime then falls back
         * to its compiled-in target.h default. A missing *required* symbol stays
         * null and is reported by the validator, never guessed.
         */
        for (key in KernelLayout.OPTIONAL_SYMBOLS) {
            if (symbols[key] == null) {
                symbols[key] = 0L
                onLog("optional symbol $key not found; emitted 0")
            }
        }
        val structs = KernelLayout.resolveStructs(btf)
        val release = boot.release()
            ?: throw ExtractionException(
                FailureKind.GENERIC, "boot image carries no kernel release string")
        if (!WIRE_RELEASE.matches(release)) {
            throw ExtractionException(
                FailureKind.GENERIC, "kernel release is not encodable on the wire: $release")
        }
        val major = release.split('.').firstOrNull()?.toIntOrNull()
        if (major != 5 && major != 6) {
            throw ExtractionException(
                FailureKind.GENERIC, "--format conf needs a 5.x/6.x release, got $release")
        }
        onLog("release=$release base=0x${base.toString(16)} btf=${btfBlob?.bytes?.size ?: 0}")

        val paths = KernelLayout.probePaths(kallsyms)
        val pselectShift = KernelLayout.pselectWaiterShiftFor(release)
        // The reference's `pselect_derived` flag is set only by disassembly; this
        // port does not disassemble, so the family fallback above is used and the
        // route is chosen exactly as the reference chooses it in that case.
        var route = KernelLayout.suggestRoute(false, paths, release)
        if (route != null && KernelLayout.routeDependsOnPselectLayout(route) && pselectShift == null) {
            // No verified family and no disassembly: the select branch's only
            // required field cannot be produced. Keep the route (the reference
            // also writes the recommended branch) and let validation report it.
            onLog("no verified-family pselect_waiter_shift for $release")
        }
        val geometry = route?.let {
            KernelLayout.confRouteGeometry(it, release, pselectShift, structs)
        } ?: emptyList()
        val cred = if (major == 5) {
            // 5.x credential template derivation needs the reference's
            // disassembly-free `init_cred` byte scan; not ported (documented gap).
            emptyList()
        } else {
            KernelLayout.confCred6x()
        }
        val emptyZeroPage = kallsyms.unique("empty_zero_page")?.let { it - base }
        val document = KernelLayout.renderConf(
            KernelLayout.ConfInputs(
                release = release,
                phys = null,
                physOffset = null,
                symbols = symbols,
                structs = structs,
                route = route,
                routeGeometry = geometry,
                cred = cred,
                emptyZeroPage = emptyZeroPage,
            ),
        )
        val validation = validator.validate(document, release)
        val provenance = provenanceBase.copy(
            documentSha256 = sha256(document.toByteArray(Charsets.UTF_8)),
            sourceSha256 = provenanceBase.sourceSha256 ?: sha256(rawBytes),
        )
        onLog("route=${route ?: "none"} invalid=${validation.invalidFields.size}")
        return ExtractionOutcome.Generated(
            listOf(GeneratedProfile(release, route, document, provenance, validation)))
    }

    /**
     * Import an `offsets.conf` (v2) or `offsets.json` (v1) document.
     *
     * v1 JSON is converted in memory exactly like the reference
     * (`LegacyProfileConverter`) and the stored text is the converted HOCON, so
     * every downstream consumer sees one format.
     */
    private fun importDocument(
        name: String,
        text: String,
        legacy: Boolean,
        validator: ProfileValidator,
    ): ExtractionOutcome {
        if (text.isBlank()) throw IOException("empty document")
        val parsed = try {
            com.ghostlock.app.data.HoconSupport.parseValue(text)
        } catch (error: RuntimeException) {
            throw ExtractionException(FailureKind.GENERIC, "invalid HOCON/JSON document")
        }
        val entries = when (parsed) {
            is Map<*, *> -> listOfNotNull(parsed.asValueMap()?.takeIf { it.containsKey("release") })
            is List<*> -> parsed.mapNotNull { item ->
                item.asValueMap()?.takeIf { it.containsKey("release") }
            }
            else -> emptyList()
        }
        if (entries.isEmpty()) return ExtractionOutcome.AlreadyPresent
        val profiles = ArrayList<GeneratedProfile>()
        for (entry in entries) {
            if (legacy || LegacyOffsetsConverter.isLegacy(entry)) {
                LegacyOffsetsConverter.convertValue(entry)
            }
            val release = entry["release"] as? String ?: continue
            if (!WIRE_RELEASE.matches(release)) {
                throw ExtractionException(
                    FailureKind.GENERIC, "release is not encodable on the wire: $release")
            }
            val document = renderHocon(entry)
            val validation = validator.validate(document, release)
            val route = routeOf(entry)
            val provenance = ProfileProvenance(
                kind = if (legacy) "offsets_json" else "offsets_conf",
                input = name,
                generatedAt = Instant.now().toString(),
                documentSha256 = sha256(document.toByteArray(Charsets.UTF_8)),
            )
            profiles.add(GeneratedProfile(release, route, document, provenance, validation))
        }
        if (profiles.isEmpty()) return ExtractionOutcome.AlreadyPresent
        return ExtractionOutcome.Generated(profiles)
    }

    private fun routeOf(entry: Map<*, *>): String? = when (val route = entry["route"]) {
        is String -> route
        is Map<*, *> -> route.keys.filterIsInstance<String>().firstOrNull()
        else -> null
    }

    /** Render one already-parsed value map back to HOCON, in a stable shape. */
    private fun renderHocon(entry: Map<*, *>): String {
        val out = StringBuilder()
        fun walk(prefix: String, node: Map<*, *>, indent: Int) {
            val pad = "  ".repeat(indent)
            for ((rawKey, value) in node) {
                val key = rawKey.toString()
                val path = if (prefix.isEmpty()) key else "$prefix.$key"
                when (value) {
                    is Map<*, *> -> {
                        out.append(pad).append(key).append(" {\n")
                        walk(path, value, indent + 1)
                        out.append(pad).append("}\n")
                    }
                    is List<*> -> {
                        out.append(pad).append(key).append(" = [")
                        out.append(value.joinToString(", ") { literal(it) })
                        out.append("]\n")
                    }
                    else -> out.append(pad).append(key).append(" = ").append(literal(value)).append('\n')
                }
            }
        }
        walk("", entry, 0)
        return out.toString()
    }

    private fun literal(value: Any?): String = when (value) {
        null -> "null"
        is String -> "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
        is Boolean -> value.toString()
        is Number -> value.toString()
        else -> "\"" + value.toString().replace("\"", "\\\"") + "\""
    }

    /** Lowercase hex SHA-256 of [bytes]. */
    fun sha256(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    /** Streaming SHA-256 of [file] (never loads the whole file twice). */
    fun sha256(file: File): String = try {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { stream ->
            val buffer = ByteArray(1 shl 16)
            while (true) {
                val read = stream.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    } catch (error: IOException) {
        ""
    }
}
