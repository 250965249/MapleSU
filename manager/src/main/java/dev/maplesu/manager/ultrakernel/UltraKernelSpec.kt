package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.KernelIdentity
import java.io.File
import java.security.MessageDigest

/**
 * MapleSU boot-spec: the vendor patch grammar (`offset|original|replacement` hex triples,
 * with `#kernel=` / `#key=` header slots), applied to a **pristine** raw kernel.
 *
 * The rules that make this safe are the vendor's and are kept verbatim:
 *
 *  - every record's `original` is verified against the *input* kernel before any byte is
 *    written, so a record that overlaps an earlier one (k21/k22's cave record #12 versus the
 *    8 B gate records) still validates against pristine bytes;
 *  - replacements are written in file order, so a later record wins inside an earlier range;
 *  - a build is only accepted when the resulting kernel digest equals the digest pinned for
 *    that variant (see [UltraKernelCatalog]); this class never decides that on its own.
 *
 * An empty `#key=` slot means the replacement bytes are used as-is; the Ultra envelope already
 * carries the device init path, so no key substitution is performed here.
 */
internal class UltraKernelSpec private constructor(
    val kernelRelease: String,
    val key: String,
    val patches: List<Patch>,
) {
    class Patch(val index: Int, val offset: Long, val original: ByteArray, val replacement: ByteArray)

    class Result(val kernel: ByteArray, val differingBytes: Int, val outsideSites: Int)

    /** Records whose pristine bytes are absent from [kernel], in declaration order. */
    fun mismatched(kernel: ByteArray): List<Patch> =
        patches.filter { !matches(kernel, it.offset, it.original) }

    /** Recognizes a completed template patch, including later records that overlap earlier ones. */
    fun isApplied(kernel: ByteArray): Boolean {
        if (!KernelSeries.same(releaseOf(kernel), kernelRelease)) return false
        for ((index, patch) in patches.withIndex()) {
            if (patch.offset < 0 || patch.offset + patch.replacement.size > kernel.size) return false
            for (byte in patch.replacement.indices) {
                val offset = patch.offset + byte
                var overwritten = false
                for (later in index + 1 until patches.size) {
                    val next = patches[later]
                    if (offset >= next.offset && offset < next.offset + next.replacement.size) {
                        overwritten = true
                        break
                    }
                }
                if (!overwritten && kernel[offset.toInt()] != patch.replacement[byte]) return false
            }
        }
        return true
    }

    /** Kernel release reported inside [kernel] (`Linux version ...`), or "" when absent. */
    fun observeKernelRelease(kernel: ByteArray): String = releaseOf(kernel)

    /**
     * Verify every record against [kernel] and then apply the replacements in file order.
     * Throws [IllegalStateException] with a stable code when a record does not fit.
     *
     * The version gate is the kernel **series** (`major.minor`): a spec recorded on `6.6.89` may be
     * applied to a `6.6.50` kernel, because that is the product rule ("6.6.89 匹配 6.6"). Everything
     * that actually makes the result safe - every record's pristine bytes, the "no byte outside a
     * record changed" invariant, and the caller's own read-back digest - is unchanged and still
     * fails closed.
     */
    fun apply(kernel: ByteArray): Result {
        require(kernel.isNotEmpty()) { "ULTRA_KERNEL_EMPTY" }
        val release = releaseOf(kernel)
        check(KernelSeries.same(release, kernelRelease)) {
            "ULTRA_KERNEL_RELEASE_MISMATCH:${KernelSeries.detail(release, kernelRelease)}"
        }

        patches.forEach { patch ->
            val end = patch.offset + maxOf(patch.original.size, patch.replacement.size)
            check(patch.offset >= 0 && end <= kernel.size) { "ULTRA_KERNEL_PATCH_RANGE:${patch.index}" }
            check(patch.original.isNotEmpty() && patch.replacement.isNotEmpty()) {
                "ULTRA_KERNEL_PATCH_EMPTY:${patch.index}"
            }
            check(matches(kernel, patch.offset, patch.original)) {
                "ULTRA_KERNEL_PATCH_ORIGINAL_MISMATCH:${patch.index}@${patch.offset}"
            }
        }
        val patched = kernel.copyOf()
        patches.forEach { patch -> patch.replacement.copyInto(patched, patch.offset.toInt()) }
        var differing = 0
        var outside = 0
        for (index in patched.indices) {
            if (patched[index] == kernel[index]) continue
            differing++
            val covered = patches.any { index >= it.offset && index < it.offset + it.replacement.size }
            if (!covered) outside++
        }
        check(outside == 0) { "ULTRA_KERNEL_PATCH_OUTSIDE_SITES:$outside" }
        return Result(patched, differing, outside)
    }

    companion object {
        private val KEY_PATTERN = Regex("[A-Za-z0-9_-]{1,128}")
        const val MAX_PATCHES = 512
        /** Keeps a malformed asset from reserving unbounded memory before parse rejects it. */
        const val MAX_SPEC_BYTES = 1L * 1024 * 1024

        fun parse(text: String, kernel: ByteArray? = null): UltraKernelSpec {
            var release = ""
            var key = ""
            val patches = ArrayList<Patch>()
            val seen = HashSet<Long>()
            for (raw in text.lineSequence()) {
                val line = raw.trim()
                if (line.isEmpty()) continue
                if (line.startsWith("#kernel=")) {
                    check(release.isEmpty()) { "ULTRA_KERNEL_SPEC_DUPLICATE_KERNEL" }
                    release = line.removePrefix("#kernel=").trim()
                    continue
                }
                if (line.startsWith("#key=")) {
                    check(key.isEmpty()) { "ULTRA_KERNEL_SPEC_DUPLICATE_KEY" }
                    key = line.removePrefix("#key=").trim()
                    check(KEY_PATTERN.matches(key)) { "ULTRA_KERNEL_SPEC_KEY_INVALID" }
                    continue
                }
                if (line.startsWith("#")) continue
                val parts = line.split("|")
                check(parts.size == 3) { "ULTRA_KERNEL_SPEC_LINE_INVALID" }
                val offset = parts[0].trim().toLongOrNull()
                check(offset != null && offset >= 0) { "ULTRA_KERNEL_SPEC_OFFSET_INVALID" }
                val original = hex(parts[1])
                val replacement = hex(parts[2])
                check(original.isNotEmpty() && replacement.isNotEmpty()) { "ULTRA_KERNEL_SPEC_BYTES_INVALID" }
                check(seen.add(offset)) { "ULTRA_KERNEL_SPEC_DUPLICATE_RECORD:$offset" }
                check(patches.size < MAX_PATCHES) { "ULTRA_KERNEL_SPEC_TOO_MANY_RECORDS" }
                check(kernel == null || offset + maxOf(original.size, replacement.size).toLong() <= kernel.size.toLong()) {
                    "ULTRA_KERNEL_SPEC_RANGE_INVALID:$offset"
                }
                patches.add(Patch(patches.size, offset, original, replacement))
            }
            check(release.isNotEmpty()) { "ULTRA_KERNEL_SPEC_KERNEL_MISSING" }
            check(patches.isNotEmpty()) { "ULTRA_KERNEL_SPEC_EMPTY" }
            return UltraKernelSpec(release, key, patches)
        }

        fun read(file: File, kernel: ByteArray? = null): UltraKernelSpec {
            check(file.isFile && file.length() in 1..MAX_SPEC_BYTES) { "ULTRA_KERNEL_SPEC_SIZE_INVALID" }
            return parse(file.readText(Charsets.UTF_8), kernel)
        }

        private fun hex(value: String): ByteArray {
            val text = value.trim()
            check(text.length % 2 == 0 && text.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
                "ULTRA_KERNEL_SPEC_HEX_INVALID"
            }
            return ByteArray(text.length / 2) {
                ((Character.digit(text[it * 2], 16) shl 4) or Character.digit(text[it * 2 + 1], 16)).toByte()
            }
        }

        private fun matches(kernel: ByteArray, offset: Long, expected: ByteArray): Boolean {
            if (offset < 0 || offset + expected.size > kernel.size) return false
            for (index in expected.indices) {
                if (kernel[offset.toInt() + index] != expected[index]) return false
            }
            return true
        }

        /**
         * `Linux version <release>` from the raw kernel.
         *
         * Delegates to [KernelIdentity] — the single implementation also used by the
         * roundtrip/inspect path and by `BootKernelVersion` — so one image can no longer report a
         * real release on import and `%s` here. The old local scan stopped at the first marker and
         * had no character whitelist, so OnePlus 5.10/5.15 kernels (whose printk format string
         * `Linux version %s` sits *before* the real banner) returned `"%s"`.
         *
         * `""` = nothing readable, `"AMBIGUOUS"` = two distinct banners. Both keep [apply]
         * fail-closed with a stable `ULTRA_KERNEL_RELEASE_*` code.
         */
        fun releaseOf(raw: ByteArray): String = KernelIdentity.releaseOf(raw)

        fun sha256(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

        fun sha256(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { stream ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }
    }
}
