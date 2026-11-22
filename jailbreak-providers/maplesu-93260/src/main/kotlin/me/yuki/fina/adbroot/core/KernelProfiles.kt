package me.yuki.fina.adbroot.core

import org.json.JSONObject

/**
 * The link-time addresses one packaged kernel profile needs.
 *
 * These are static symbol addresses from the matching kernel build; the running
 * value is `address + KASLR slide`. A profile is only usable when every address
 * is present: a partial table would make the flow write a guessed location, so
 * it is rejected instead of being completed with defaults.
 */
data class KernelAddresses(
    val imageBase: Long,
    val kprobeTable: Long,
    val loadModule: Long,
    val moduleNotifyList: Long,
    val traceModuleNotify: Long,
    val traceSysExit: Long,
) {
    val complete: Boolean
        get() = imageBase != 0L && kprobeTable != 0L && loadModule != 0L &&
            moduleNotifyList != 0L && traceModuleNotify != 0L && traceSysExit != 0L

    companion object {
        /** Reads one non-zero unsigned 64-bit address; null when absent or malformed. */
        fun parse(json: JSONObject?): KernelAddresses? {
            if (json == null) return null
            fun read(key: String): Long? = runCatching {
                val text = json.optString(key).trim()
                if (text.isEmpty()) return@runCatching null
                java.lang.Long.parseUnsignedLong(text.removePrefix("0x"), 16)
                    .takeIf { it != 0L }
            }.getOrNull()
            val imageBase = read("imageBase") ?: return null
            val kprobeTable = read("kprobeTable") ?: return null
            val loadModule = read("loadModule") ?: return null
            val moduleNotifyList = read("moduleNotifyList") ?: return null
            val traceModuleNotify = read("traceModuleNotify") ?: return null
            val traceSysExit = read("traceSysExit") ?: return null
            return KernelAddresses(imageBase, kprobeTable, loadModule,
                moduleNotifyList, traceModuleNotify, traceSysExit)
        }
    }
}

/**
 * Which acquisition engine a profile runs.
 *
 * The retained engine is the 3.8.10 source (`louise` + `probe` + a per-build
 * kallsyms snapshot). The plant engine is a per-kernel executable this project
 * builds from the retained offset tables (derived from the public Shark
 * implementation): it performs the escalation and hands its fake-cred root
 * context to `PYB110_KSUD`, which this build points at the retained handover
 * batch. Both engines end in the same MapleSU handover, receipt and
 * verification; only the code that obtains the kernel-domain root context
 * differs.
 */
enum class KernelEngine {
    RETAINED,
    PLANT;

    companion object {
        /** A document without the field is the retained engine (schema v1). */
        fun parse(value: String?): KernelEngine? = when (value?.trim()?.lowercase()) {
            null, "" -> RETAINED
            "retained" -> RETAINED
            // "shark" is the historical name of this engine in older documents.
            "plant", "shark" -> PLANT
            else -> null
        }
    }
}

/**
 * One escalation profile: the exact kernel builds it can serve and everything
 * the retained flow needs for them.
 *
 * [releases] is the full `uname -r` identity. A release that is merely in the
 * same KMI family is **not** served by this profile - the flow patches build
 * specific symbols, so a family match would be a guess. [models] is only a
 * human-readable hint recorded with the profile; it never widens or narrows a
 * match.
 *
 * [addresses] is required for [KernelEngine.RETAINED] and null for
 * [KernelEngine.PLANT]; [runner] is the opposite. The parser rejects a profile
 * that lacks what its engine needs instead of completing it with defaults.
 */
data class KernelProfile(
    val id: String,
    val engine: KernelEngine,
    val releases: List<String>,
    val variant: String,
    val kmi: String,
    val kernelUapi: Int,
    val pageSize: String?,
    val models: List<String>,
    val addresses: KernelAddresses?,
    val runner: String?,
    val payloadKey: String,
) {
    fun serves(release: KernelRelease): Boolean =
        release.valid && serves(release.raw)

    fun serves(raw: String): Boolean = releases.any { it == raw }

    companion object {
        private val ID = Regex("""[a-z0-9][a-z0-9._-]{2,63}""")
        private val KMI = Regex("""android\d{2}-\d+\.\d+""")
        private val RUNNER = Regex("""plant-[0-9]{5}""")

        /**
         * Parses one profile document. Every field is required except [models],
         * [pageSize] and the other engine's payload; an entry that fails any
         * check is rejected whole rather than being completed with a default.
         */
        fun parse(json: JSONObject?): KernelProfile? {
            if (json == null) return null
            val id = json.optString("id").trim()
            if (!ID.matches(id)) return null
            val engine = KernelEngine.parse(json.optString("engine")) ?: return null
            val releases = json.optJSONArray("releases")?.let { array ->
                (0 until array.length()).mapNotNull { index ->
                    array.optString(index).trim().takeIf { it.isNotEmpty() }
                }
            }.orEmpty()
            if (releases.isEmpty() || releases.distinct().size != releases.size) return null
            val parsed = releases.map { KernelRelease.parse(it) }
            if (parsed.any { !it.valid }) return null
            val variant = json.optString("variant").trim()
            if (variant.isEmpty()) return null
            val kmi = json.optString("kmi").trim()
            if (!KMI.matches(kmi)) return null
            val kernelUapi = json.optInt("kernelUapi", -1)
            if (kernelUapi <= 0) return null
            val pageSize = json.optString("pageSize").trim().takeIf { it.isNotEmpty() }
            val models = json.optJSONArray("models")?.let { array ->
                (0 until array.length()).mapNotNull { index ->
                    array.optString(index).trim().takeIf { it.isNotEmpty() }
                }
            }.orEmpty()
            val payloadKey = json.optString("payloadKey").trim().ifEmpty { id }
            if (!ID.matches(payloadKey)) return null
            val addresses: KernelAddresses?
            val runner: String?
            when (engine) {
                KernelEngine.RETAINED -> {
                    addresses = KernelAddresses.parse(json.optJSONObject("addresses"))
                        ?: return null
                    if (!addresses.complete) return null
                    runner = null
                }
                KernelEngine.PLANT -> {
                    addresses = null
                    runner = json.optString("runner").trim()
                    if (!RUNNER.matches(runner)) return null
                }
            }
            // The declared identity must agree with every release it serves.
            for (release in parsed) {
                if (release.kmi != null && release.kmi != kmi) return null
                if (release.pageSize != null && pageSize != null && release.pageSize != pageSize) return null
            }
            return KernelProfile(id, engine, releases, variant, kmi, kernelUapi, pageSize,
                models, addresses, runner, payloadKey)
        }
    }
}

/**
 * A kernel build whose escalation variant is known from a public support matrix
 * but whose payload is not packaged in this build.
 *
 * It exists so the App can name the variant it recognised and say what is
 * missing; it is never runnable and never relaxes a profile match.
 */
data class DeclaredKernel(
    val release: String,
    val variant: String,
    val kmi: String?,
    val pageSize: String?,
    val models: List<String>,
    val requires: String,
) {
    companion object {
        fun parse(json: JSONObject?): DeclaredKernel? {
            if (json == null) return null
            val release = json.optString("release").trim()
            val parsed = KernelRelease.parse(release)
            if (!parsed.valid || release.isEmpty()) return null
            val variant = json.optString("variant").trim()
            if (variant.isEmpty()) return null
            val kmi = json.optString("kmi").trim().takeIf { it.isNotEmpty() }
            val pageSize = json.optString("pageSize").trim().takeIf { it.isNotEmpty() }
            val models = json.optJSONArray("models")?.let { array ->
                (0 until array.length()).mapNotNull { index ->
                    array.optString(index).trim().takeIf { it.isNotEmpty() }
                }
            }.orEmpty()
            return DeclaredKernel(release, variant, kmi, pageSize, models,
                json.optString("requires").trim())
        }
    }
}

/**
 * The 98260 kernel profile catalog carried by the APK.
 *
 * The compiled default profile is always present: a missing or unreadable
 * manifest must not turn a working device into an unsupported one. Additional
 * profiles come from the packaged manifest; an entry that fails validation or
 * contradicts the compiled default is recorded in [rejected] and dropped.
 */
data class KernelCatalog(
    val profiles: List<KernelProfile>,
    val declared: List<DeclaredKernel>,
    val source: String = SOURCE_BUILT_IN,
    val rejected: List<String> = emptyList(),
) {
    fun profile(id: String): KernelProfile? = profiles.firstOrNull { it.id == id }

    companion object {
        const val SOURCE_BUILT_IN = "built-in"

        fun builtIn(): KernelCatalog = KernelCatalog(
            profiles = listOf(KernelProfiles.DEFAULT_PROFILE),
            declared = emptyList(),
            source = SOURCE_BUILT_IN,
        )

        /**
         * Parses the `maplesu93260` block of `maplesu-jailbreak-artifacts.json`.
         * Null (or a block without profiles) keeps the compiled default only.
         */
        fun parse(block: JSONObject?): KernelCatalog {
            val default = KernelProfiles.DEFAULT_PROFILE
            if (block == null) return builtIn()
            val profiles = LinkedHashMap<String, KernelProfile>()
            profiles[default.id] = default
            val rejected = mutableListOf<String>()
            block.optJSONArray("profiles")?.let { array ->
                for (index in 0 until array.length()) {
                    val entry = array.optJSONObject(index)
                    if (entry == null) {
                        rejected += "profiles[$index]:not-an-object"
                        continue
                    }
                    val id = entry.optString("id").trim()
                    val parsed = KernelProfile.parse(entry)
                    if (parsed == null) {
                        rejected += "profile:${id.ifEmpty { "profiles[$index]" }}:invalid"
                        continue
                    }
                    if (parsed.id == default.id) {
                        if (!same(parsed, default)) rejected += "profile:${parsed.id}:default-drift"
                        continue
                    }
                    if (profiles.containsKey(parsed.id)) {
                        rejected += "profile:${parsed.id}:duplicate"
                        continue
                    }
                    profiles[parsed.id] = parsed
                }
            }
            val declared = mutableListOf<DeclaredKernel>()
            val seen = mutableSetOf<String>()
            block.optJSONArray("declared")?.let { array ->
                for (index in 0 until array.length()) {
                    val entry = DeclaredKernel.parse(array.optJSONObject(index))
                    if (entry == null) {
                        rejected += "declared[$index]:invalid"
                        continue
                    }
                    // A build that a real profile serves needs no declaration.
                    if (profiles.values.any { it.serves(entry.release) }) continue
                    if (!seen.add(entry.release)) continue
                    declared += entry
                }
            }
            val source = block.optJSONObject("catalog")?.let { catalog ->
                val url = catalog.optString("url").trim()
                val commit = catalog.optString("commit").trim()
                listOf(url, commit).filter { it.isNotEmpty() }.joinToString("@")
            }.orEmpty().ifEmpty { SOURCE_BUILT_IN }
            return KernelCatalog(profiles.values.toList(), declared, source, rejected.toList())
        }

        /**
         * Functional identity of two copies of the same profile. `models` is a
         * display hint and is deliberately excluded: a manifest that lists no
         * model names must not read as a different profile.
         */
        fun same(left: KernelProfile, right: KernelProfile): Boolean =
            left.id == right.id && left.engine == right.engine &&
                left.releases == right.releases &&
                left.variant == right.variant && left.kmi == right.kmi &&
                left.kernelUapi == right.kernelUapi && left.pageSize == right.pageSize &&
                left.addresses == right.addresses && left.runner == right.runner &&
                left.payloadKey == right.payloadKey
    }
}

/**
 * What the catalog can do with one running release.
 *
 * The three outcomes are deliberately different: a [Packaged] profile is the
 * only one allowed to bind [KernelMap]; [Declared] is recognised but has no
 * payload; [Unsupported] is not in the catalog at all. Both non-runnable
 * outcomes carry their own stable failure token.
 */
sealed interface KernelResolution {
    val release: KernelRelease

    val profileId: String? get() = (this as? Packaged)?.profile?.id
    val variant: String? get() = when (this) {
        is Packaged -> profile.variant
        is Declared -> entry.variant
        is Unsupported -> null
    }
    val supported: Boolean get() = this is Packaged

    /** Stable provider failure token, or null when the profile can run. */
    val failureToken: String? get() = when (this) {
        is Packaged -> null
        is Declared -> "MAPLESU_93260_PROFILE_NOT_PACKAGED:" + entry.variant
        is Unsupported -> "MAPLESU_93260_KERNEL_UNSUPPORTED"
    }

    /** One ASCII line for logs; the UI owns human-readable text. */
    fun describe(): String = when (this) {
        is Packaged -> "profile=${profile.id} engine=${profile.engine.name.lowercase()} " +
            "variant=${profile.variant} kmi=${profile.kmi}"
        is Declared -> "declared variant=${entry.variant} kmi=${entry.kmi ?: "unknown"} artifacts=missing"
        is Unsupported -> "unsupported release=${release.raw.ifEmpty { "unreadable" }} kmi=${release.kmi ?: "unknown"}"
    }

    data class Packaged(val profile: KernelProfile, override val release: KernelRelease) : KernelResolution

    data class Declared(override val release: KernelRelease, val entry: DeclaredKernel) : KernelResolution

    data class Unsupported(override val release: KernelRelease) : KernelResolution
}

/**
 * Resolution over a [KernelCatalog]. The only matching rule is the exact
 * `uname -r` string; the KMI and model hints are reported, never used to pick a
 * profile.
 */
object KernelProfiles {
    const val DEFAULT_ID = "maplesu-93260-61258-gdd6fd"
    const val DEFAULT_RELEASE = "6.12.58-android16-6-gdd6fd5c98918-abogki543627742-4k"
    const val DEFAULT_VARIANT = "CVE-2026-98260-6.12.58"
    const val DEFAULT_KMI = "android16-6.12"

    private fun u64(hex: String): Long =
        java.lang.Long.parseUnsignedLong(hex.removePrefix("0x"), 16)

    /**
     * PD2546 (iQOO 15 Ultra) link-time addresses from
     * `data/PD2546-symbols.json`, matching the boot image one to one.
     */
    val DEFAULT_ADDRESSES = KernelAddresses(
        imageBase = u64("ffffffc080000000"),
        kprobeTable = u64("ffffffc08279f6e8"),
        loadModule = u64("ffffffc080502688"),
        moduleNotifyList = u64("ffffffc0825d7d28"),
        traceModuleNotify = u64("ffffffc08057d2a4"),
        traceSysExit = u64("ffffffc0826d93e0"),
    )

    /** The profile this build was developed against; always runnable. */
    val DEFAULT_PROFILE = KernelProfile(
        id = DEFAULT_ID,
        engine = KernelEngine.RETAINED,
        releases = listOf(DEFAULT_RELEASE),
        variant = DEFAULT_VARIANT,
        kmi = DEFAULT_KMI,
        kernelUapi = 6,
        pageSize = "4k",
        models = listOf("PD2546", "iQOO 15 Ultra"),
        addresses = DEFAULT_ADDRESSES,
        runner = null,
        payloadKey = DEFAULT_ID,
    )

    fun resolve(release: String, catalog: KernelCatalog = KernelCatalog.builtIn()): KernelResolution =
        resolve(KernelRelease.parse(release), catalog)

    fun resolve(release: KernelRelease, catalog: KernelCatalog = KernelCatalog.builtIn()): KernelResolution {
        val profile = catalog.profiles.firstOrNull { it.serves(release) }
        if (profile != null) return KernelResolution.Packaged(profile, release)
        val declared = catalog.declared.firstOrNull { release.valid && it.release == release.raw }
        if (declared != null) return KernelResolution.Declared(release, declared)
        return KernelResolution.Unsupported(release)
    }
}
