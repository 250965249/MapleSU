package dev.maplesu.manager.jailbreak

import android.content.Context
import android.os.Build
import android.system.ErrnoException
import android.system.Os
import dev.maplesu.manager.runtime.SuGate
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest

/**
 * The packaged in-kernel root installer (IR) and its per-release specs.
 *
 * The module is release-agnostic on purpose: the loader compares only the vermagic
 * suffix once a module carries a `__versions` section, so one module serves every
 * GKI build with the same configuration. What is release-exact is the spec, and the
 * spec is the thing that can silently do the wrong thing — so a release is only
 * ever "supported" when its spec is packaged AND its digest matches what the
 * packaging edge recorded.
 *
 * Nothing here decides that the kernel will accept the spec; that is the module's
 * own original-byte check, and the bootstrap reports its verdict under a stable
 * `MAPLESU_IR_*` token.
 */
object IrImages {
    const val MANIFEST_ASSET = "maplesu-jailbreak-artifacts.json"
    const val MODULE_FILE = "maplesu_ir.ko"
    const val SPEC_FILE = "ir.spec"
    /** Loader-contract canary, probed by the bootstrap during bring-up only. */
    const val CANARY_FILE = "maplesu_ir_canary.ko"
    /**
     * The step-2 canary helper's staged name. From step-3 no such asset is packaged:
     * the module execs `<CE>/bs` (see [HELPER_PATH]), which
     * `DirtyfragAttempt.stageBootstrap()` writes on every route. The constant is kept
     * only so a copy left behind by an earlier canary build is removed instead of
     * being left at a path the kernel could exec.
     */
    const val HELPER_FILE = "maplesu-bootstrap"

    /**
     * Stage-2 slot the UMH helper loads with init_module (bootstrap.c
     * MAPLESU_STAGE2_NAME). From L3 on this slot carries exactly one thing: the L3
     * su gate (`l3Module` in the packaged manifest). The step-3 hook module is
     * delivered through the IR/canary slot, never here.
     */
    const val STAGE2_FILE = "maplesu_stage2.ko"
    /**
     * Returned by [stageHookModule] when this build packages no L3 module. It is a
     * deliberate non-null value: the hook handover must still run (the kernel module
     * comes from the IR/canary slot), and only the su gate is unavailable. An empty
     * string can never be mistaken for a digest, so it cannot be recorded as one.
     */
    const val L3_ABSENT = ""
    /**
     * The path the packaged hook module execs (design D3-3: the credential-encrypted
     * data directory; `/data/data/<pkg>` is the same inode). Recorded here so the App
     * side has one place that names it; the module constant and the packaging edge's
     * `ROOT_CANARY_HELPER_PATH` must equal it.
     */
    const val HELPER_PATH = "/data/user/0/dev.maplesu.manager/bs"
    const val MARKER_FILE = "use-ir"
    /** W0 only: stage the patches but stay in this boot so ART can be probed. */
    const val NO_REBOOT_MARKER = "ir-no-reboot"
    /** Packaging mode of a step-2 bring-up build (see docs/patching/maplesu-canary-…). */
    const val MODE_ROOT_CANARY = "root-canary"
    /** The exact failure the manual requires for an unadapted release (C10). */
    fun unsupported(release: String): String = "MAPLESU_IR_UNSUPPORTED:" + release

    data class Spec(
        val release: String,
        val asset: String,
        val sha256: String,
        val bytes: Long,
        val imageSha256: String?,
        val blocks: Int,
    )

    data class Module(val asset: String, val sha256: String, val bytes: Long)

    data class Canary(val asset: String, val sha256: String, val bytes: Long)

    /**
     * The canary helper shipped only by a step-2 packaging build. It is staged at
     * [HELPER_FILE] with mode 0700 so the kernel can exec it as kernel-domain root;
     * a build without this block never writes that path (and removes a stale copy).
     */
    data class CanaryHelper(val asset: String, val sha256: String, val bytes: Long,
                            val devicePath: String?)

    data class Inventory(val module: Module?, val specs: Map<String, Spec>,
                         val canary: Canary? = null,
                         val canaryHelper: CanaryHelper? = null,
                         val mode: String? = null,
                         /** Release-independent in-kernel root module (Ultra/hook route). */
                         val rootModule: Module? = null,
                         /**
                          * L3 su gate (ABI v1) the UMH helper loads from the stage-2
                          * slot. Null on a build that packages no L3 module; su is then
                          * UNAVAILABLE by construction, not by a later probe.
                          */
                         val l3Module: Module? = null,
                         val l3Modules: Map<String, Module> = emptyMap()) {
        fun specFor(release: String): Spec? = specs[release]
        fun l3For(release: String): Module? {
            val version = Regex("^(\\d+\\.\\d+)").find(release)?.groupValues?.get(1)
            if (l3Modules.isEmpty()) return if (version == "5.10") null else l3Module
            if (version == null) return null
            val android = Regex("android(\\d+)").find(release)?.groupValues?.get(1)
            // 5.10 has two Android KMIs; only the measured one may be selected.
            if (version == "5.10") return l3Modules["android$android-$version"]
            return l3Modules["android$android-$version"]
                ?: l3Modules.entries.firstOrNull { it.key.substringAfter('-') == version }?.value
        }
        val isUsable: Boolean get() = module != null && specs.isNotEmpty()
        /** A step-2 bring-up build: its canary slot is the module, not a probe image. */
        val isRootCanary: Boolean get() = mode == MODE_ROOT_CANARY
        /** True only when this APK can actually offer the kernel su gate. */
        val hasL3: Boolean get() = l3Module != null || l3Modules.isNotEmpty()
    }

    data class Staged(val release: String, val moduleSha256: String, val specSha256: String)

    @Volatile private var cached: Inventory? = null

    /**
     * Read the packaged inventory. A malformed or absent block yields an empty
     * inventory instead of an exception: the caller turns that into
     * `MAPLESU_IR_UNSUPPORTED`, which is the honest answer for a build that simply
     * did not package the module.
     */
    @JvmStatic
    fun inventory(context: Context): Inventory {
        cached?.let { return it }
        val parsed = runCatching { parse(context) }.getOrNull() ?: Inventory(null, emptyMap())
        cached = parsed
        return parsed
    }

    private fun parse(context: Context): Inventory {
        val text = context.assets.open(MANIFEST_ASSET).use { it.readBytes().toString(Charsets.UTF_8) }
        return parseManifest(text)
    }

    /**
     * Pure parser for the packaged manifest, separated from [parse] so the host
     * tests can assert the decisions (supported release / empty inventory) without
     * an Android Context.
     */
    @JvmStatic
    fun parseManifest(text: String): Inventory {
        val root = org.json.JSONObject(text)
        val ir = root.optJSONObject("ir") ?: return Inventory(null, emptyMap())
        val moduleJson = ir.optJSONObject("module")
        val module = moduleJson?.let {
            Module(
                asset = it.getString("asset"),
                sha256 = it.getString("sha256"),
                bytes = it.getLong("bytes"),
            )
        }
        val specs = LinkedHashMap<String, Spec>()
        val array = ir.optJSONArray("specs") ?: org.json.JSONArray()
        for (index in 0 until array.length()) {
            val entry = array.getJSONObject(index)
            val release = entry.optString("release")
            if (release.isEmpty()) continue
            specs[release] = Spec(
                release = release,
                asset = entry.getString("asset"),
                sha256 = entry.getString("sha256"),
                bytes = entry.getLong("bytes"),
                imageSha256 = entry.optString("imageSha256").takeIf { it.isNotEmpty() },
                blocks = entry.optInt("blocks", 0),
            )
        }
        /*
         * The root module is release-independent on purpose: its symbols are resolved
         * at load time, so this block has no per-kernel key and one packaged file
         * serves every release of a KMI. That is what lets the Ultra target run on a
         * device whose exact kernel release we have never seen.
         */
        val rootJson = ir.optJSONObject("root")
        val rootModule = rootJson?.let {
            Module(asset = it.getString("asset"), sha256 = it.getString("sha256"),
                bytes = it.getLong("bytes"))
        }
        /*
         * L3 su gate (ABI v1). It lives inside the same `ir` block as `root` and has
         * the same shape, so this parser reads both identically. A manifest without
         * the key means the build packaged no L3 module: su is UNAVAILABLE, and that
         * is decided here rather than discovered when a command fails.
         */
        val l3Json = ir.optJSONObject("l3Module") ?: root.optJSONObject("l3Module")
        val l3Module = l3Json?.let {
            Module(asset = it.getString("asset"), sha256 = it.getString("sha256"),
                bytes = it.getLong("bytes"))
        }
        val l3Modules = LinkedHashMap<String, Module>()
        l3Json?.optString("kmi")?.takeIf { it.isNotEmpty() }?.let { kmi ->
            if (l3Module != null) l3Modules[kmi] = l3Module
        }
        val families = ir.optJSONObject("l3Modules")
        families?.keys()?.forEach { kmi ->
            val entry = families.getJSONObject(kmi)
            l3Modules[kmi] = Module(entry.getString("asset"), entry.getString("sha256"), entry.getLong("bytes"))
        }
        val canaryJson = ir.optJSONObject("canary")
        val canary = canaryJson?.let {
            Canary(asset = it.getString("asset"), sha256 = it.getString("sha256"),
                bytes = it.getLong("bytes"))
        }
        val helperJson = ir.optJSONObject("canaryHelper")
        val helper = helperJson?.let {
            CanaryHelper(asset = it.getString("asset"), sha256 = it.getString("sha256"),
                bytes = it.getLong("bytes"),
                devicePath = it.optString("devicePath").takeIf { value -> value.isNotEmpty() })
        }
        return Inventory(module, specs, canary, helper,
            ir.optString("mode").takeIf { value -> value.isNotEmpty() }, rootModule,
            l3Module, l3Modules)
    }

    /**
     * True only when this exact release has a packaged spec whose digest still
     * matches. Anything else must be refused before a provider is started, so a
     * mismatch can never reach a kernel-side attempt.
     */
    @JvmStatic
    fun supports(context: Context, release: String): Boolean =
        inventory(context).specFor(release) != null

    /**
     * Stage the module and this release's spec into the attempt directory and only
     * then publish the `use-ir` marker. The order matters: the bootstrap selects
     * the route by seeing the marker, so a marker that exists before both inputs
     * are complete would dispatch a route with nothing to load.
     */
    @JvmStatic
    @Throws(IOException::class)
    fun stage(context: Context, directory: File, release: String,
              noReboot: Boolean = false): Staged {
        val inventory = inventory(context)
        val spec = inventory.specFor(release)
            ?: throw IOException(unsupported(release))
        val module = inventory.module ?: throw IOException(unsupported(release))
        val moduleBytes = readVerified(context, module.asset, module.sha256, module.bytes)
        val specBytes = readVerified(context, spec.asset, spec.sha256, spec.bytes)
        if (specBytes.isEmpty() || specBytes.size >= 4096) {
            throw IOException("MAPLESU_IR_SPEC_INVALID:size=" + specBytes.size)
        }
        // The spec must declare the release it is being used for; a spec that
        // disagrees with the device is refused here rather than in the kernel.
        val banner = "#kernel=" + release
        val head = specBytes.copyOfRange(0, minOf(specBytes.size, banner.length))
        if (!head.toString(Charsets.UTF_8).startsWith(banner)) {
            throw IOException("MAPLESU_IR_SPEC_INVALID:release-mismatch")
        }
        /*
         * A step-2 canary build carries the real module in the canary slot and the
         * helper beside it. Both are only staged in the explicit probe mode
         * (`softReboot=false` -> `ir-no-reboot`, the marker the bootstrap documents as
         * "never present in a product run"); a product-mode attempt with such an APK
         * gets the stub and nothing else. In a product build the slot keeps its
         * original meaning (loader-contract probe), so this changes nothing there.
         */
        val canaryActive = !inventory.isRootCanary || noReboot
        if (canaryActive) {
            // The canary exists only so a failed bring-up can tell ELF-contract
            // rejections from code rejections; it is staged, never loaded by the product.
            inventory.canary?.let { candidate ->
                runCatching {
                    write(directory, CANARY_FILE,
                        readVerified(context, candidate.asset, candidate.sha256,
                            candidate.bytes))
                }
            }
        } else {
            remove(directory, CANARY_FILE)
        }
        /*
         * The canary helper is the one file the module execs, so its content is
         * verified against the packaged digest and it is written 0700 -- a readable
         * file without an execute bit would make the module's dispatch fail. When
         * this build ships no helper, a copy left behind by an earlier canary build
         * is removed: a stale binary at a path the kernel will exec is exactly the
         * hazard this staging step exists to rule out.
         *
         * Step-3 order is load-bearing: a root-canary build packages no helper, so
         * this branch removes the stale `maplesu-bootstrap`, while the `bs` the module
         * really execs is written by `DirtyfragAttempt.stageBootstrap()` *after* this
         * call. Do not swap those two steps - a reader that "cleans up" after staging
         * would delete the handover target.
         */
        val helper = inventory.canaryHelper
        if (canaryActive && helper != null) {
            // The module has the dispatch path compiled in. Refuse a build whose
            // manifest disagrees instead of staging a file nobody will exec.
            val devicePath = helper.devicePath
            if (devicePath != null && !devicePath.endsWith("/" + HELPER_FILE)) {
                throw IOException("MAPLESU_IR_HELPER_PATH_MISMATCH:" + devicePath)
            }
            write(directory, HELPER_FILE,
                readVerified(context, helper.asset, helper.sha256, helper.bytes), 448)
        } else {
            remove(directory, HELPER_FILE)
        }
        write(directory, MODULE_FILE, moduleBytes)
        write(directory, SPEC_FILE, specBytes)
        // Route markers last: they are what the bootstrap reacts to.
        if (noReboot) write(directory, NO_REBOOT_MARKER, ByteArray(0))
        else File(directory, NO_REBOOT_MARKER).delete()
        write(directory, MARKER_FILE, ByteArray(0))
        return Staged(release, module.sha256, spec.sha256)
    }

    /** Product first-stage modules already dispatch the hook helper; only bring-up
     * builds load it through the legacy IR/canary path with an exact-release spec. */
    @JvmStatic
    @Throws(IOException::class)
    fun stageForHook(context: Context, directory: File, release: String) {
        val inventory = inventory(context)
        if (inventory.isRootCanary) {
            stage(context, directory, release, noReboot = true)
        } else {
            if (inventory.rootModule == null) throw IOException("MAPLESU_HOOK_NOT_PACKAGED")
            clear(directory)
        }
    }

    /**
     * Stage the L3 su gate into the slot the UMH helper loads.
     *
     * <p>From L3 ABI v1 the stage-2 slot carries exactly one thing: `l3Module`
     * (`maplesu_l3.ko`). The step-3 hook module is **not** copied here any more - it
     * is delivered through the IR/canary slot, and a second copy at a path the helper
     * loads would put a second module into the kernel for no reason.
     *
     * <p>Three outcomes, and the caller's `== null` test keeps its old meaning (it is
     * the `MAPLESU_HOOK_NOT_PACKAGED` gate in `DirtyfragAttempt.start`):
     *
     *  - the packaged L3 module staged: its digest is returned;
     *  - no L3 module, but the build does package a hook module: nothing is staged
     *    (a stale copy is removed - fail-closed for su), [L3_ABSENT] is returned and
     *    the handover proceeds. The helper then finds no stage-2 module and the daemon
     *    record says `suGate=UNAVAILABLE`; the App reports that, never an armed gate;
     *  - the build packages no hook module at all: `null`, so the caller refuses as
     *    before. This branch is unchanged on purpose - it is an existing gate.
     */
    @JvmStatic
    @Throws(IOException::class)
    fun stageHookModule(context: Context, directory: File): String? {
        val inventory = inventory(context)
        val release = Os.uname().release
        val l3 = inventory.l3For(release)
        if (l3 == null && inventory.l3Modules.isNotEmpty()) {
            throw IOException("MAPLESU_L3_NOT_PACKAGED:" + release)
        }
        if (l3 != null) {
            val bytes = readVerified(context, l3.asset, l3.sha256, l3.bytes)
            write(directory, STAGE2_FILE, bytes)
            return l3.sha256
        }
        // Fail-closed: never leave the previous attempt's (or a step-3 build's) module
        // in the L3 slot. The helper decides what to report by what it finds here.
        remove(directory, STAGE2_FILE)
        android.util.Log.w(SuGate.TAG, SuGate.ERROR_NOT_ARMED +
            ": this build packages no l3Module (suGate=UNAVAILABLE)")
        if (inventory.rootModule == null && !inventory.isRootCanary) return null
        return L3_ABSENT
    }

    /** Remove the staged inputs so a later attempt cannot reuse them by accident. */
    @JvmStatic
    fun clear(directory: File) {
        listOf(MODULE_FILE, SPEC_FILE, MARKER_FILE, NO_REBOOT_MARKER, CANARY_FILE, HELPER_FILE,
            STAGE2_FILE, "maplesu_root.ko")
            .forEach { name ->
            val file = File(directory, name)
            if (file.exists() && !file.delete()) {
                // Best effort: the bootstrap re-validates everything it reads.
            }
        }
    }

    private fun readVerified(context: Context, asset: String, sha256: String, bytes: Long): ByteArray {
        val content = context.assets.open(asset).use { it.readBytes() }
        if (content.size.toLong() != bytes) {
            throw IOException("MAPLESU_IR_ASSET_SIZE:" + asset)
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(content)
        val hex = digest.joinToString("") { "%02x".format(it) }
        if (!hex.equals(sha256, ignoreCase = true)) {
            throw IOException("MAPLESU_IR_ASSET_DIGEST:" + asset)
        }
        return content
    }

    /**
     * Delete one staged name. A symlink left behind by another process must never be
     * followed here: the bootstrap opens with O_NOFOLLOW and would refuse it anyway,
     * but writing through it would already have changed a file outside the attempt dir.
     */
    private fun remove(directory: File, name: String) {
        val target = File(directory, name)
        if (target.exists() && !target.delete()) {
            throw IOException("MAPLESU_IR_STAGE_UNWRITABLE:" + name)
        }
    }

    private fun write(directory: File, name: String, content: ByteArray, mode: Int = 384) {
        remove(directory, name)
        val target = File(directory, name)
        FileOutputStream(target, false).use { output -> output.write(content) }
        try {
            // 0600 by default (owner read/write only); the canary helper is 0700
            // because the kernel requires an execute bit to exec it. Kotlin has no
            // octal literals, so 384 / 448.
            Os.chmod(target.path, mode)
        } catch (error: ErrnoException) {
            throw IOException("MAPLESU_IR_STAGE_MODE:" + name, error)
        }
    }

    /** Only used to keep the API honest on hosts that run unit tests. */
    @JvmStatic
    fun describe(): String = "ir/" + Build.CPU_ABI
}
