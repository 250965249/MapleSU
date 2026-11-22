package dev.maplesu.manager.ultrakernel

import java.io.File

/**
 * Fixtures that let the *whole* generator pipeline be exercised without a 36 MB kernel, without a
 * device and without `gradle`.
 *
 * The trick: the shipped `k22-ultra-6.6.89.spec` is an independent artifact that contains, for all 18
 * records, the exact pristine and replacement bytes k22 shipped. Supply those bytes in a synthetic
 * kernel plus a hand-built symbol table - which is the *only* thing `kallsyms` would have supplied,
 * namely where each symbol starts - and the renderer has everything it needs. The historical code
 * blobs remain the oracle; the two SDK AVC descriptors are corrected independently to describe the
 * target's function and return hook. A mismatch identifies the record.
 *
 * The symbol bases below are `shipped offset - recipe delta`, i.e. where kallsyms placed those
 * symbols on 6.6.89. [k22SymbolsMatchTheShippedSites] re-derives that identity so a wrong constant
 * cannot silently make a wrong render look right.
 */
internal object UltraKernelPlanFixtures {

    const val K22_RELEASE = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
    const val K22_CREDENTIAL = "8eORURvE0cAkp3mlIzCuUsEJrr4OfbjKfT6RvkjeIP6aKm6r"
    const val OTHER_CREDENTIAL = "u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzdocJ2isAj"

    /** Current packaged candidates, checked offline against the pristine reference. */
    const val K22_KERNEL_SHA256 = "3a601ef90eab78594ece64767de5cb1176e4ec471729372af08b02c6b04477ab"
    const val K22_BOOT_SHA256 = "3180b35c65bff6f2b6d91437899c9e1e54fff7431347334128d8816a0eff13e6"
    const val CORRECTED_K22_KERNEL_SHA256 = "3a601ef90eab78594ece64767de5cb1176e4ec471729372af08b02c6b04477ab"

    /** Digests of [syntheticKernel] before and after k22 with corrected AVC fields (computed offline). */
    const val SYNTHETIC_BASE_SHA256 = "89c1c373cd9ad69d8e596f4a670d56fad835ebf35f10ec1ce2855cd66960d3ea"
    const val SYNTHETIC_PATCHED_SHA256 = "63198a013e3501b697f12b9e58ebeb9680b1aea78c36f238f4c0402322175772"
    const val SYNTHETIC_CHANGED_BYTES = 866

    /** Symbol starts on 6.6.89: `shipped site offset - recipe delta`. */
    val K22_SYMBOL_BASE = linkedMapOf(
        "die" to 0x212C4,
        "arm64_notify_die" to 0x217B4,
        "free_initmem" to 0x38C20,
        "report_cfi_failure" to 0x2B84FC,
        "free_reserved_area" to 0x36AE88,
        "do_execveat_common" to 0x3DF804,
        "avc_denied" to 0x6385B0,
        "__drm_puts_coredump" to 0x8FCAB0,
        "__drm_printfn_coredump" to 0x8FCB8C,
        "drm_dev_printk" to 0x8FCF7C,
        "__dev_printk" to 0x930FB8,
        "panic" to 0x104F31C,
        "__traceiter_kvm_userspace_exit" to 0x45520,
        // Relocation targets that are not record sites themselves.
        "module_alloc" to 0x2FA64,
        "kallsyms_lookup_name" to 0x1B6560,
        "kern_path" to 0x3E39FC,
        "path_put" to 0x3E2F70,
        "filldir64" to 0x3F052C,
        "module_memfree" to 0x185E68,
        "set_memory_ro" to 0x3D128,
        "set_memory_rw" to 0x3D364,
        "set_memory_x" to 0x3D3B4,
        "set_memory_nx" to 0x3D38C,
        // Not a record site: the two accessor shapes the struct rules scan.
        "prctl_get_seccomp" to 0x100,
        "__arm64_sys_getuid" to 0x180,
        "__arm64_sys_geteuid" to 0x1C0,
        "__get_task_comm" to 0x300,
        "strscpy" to 0x340,
        "__do_sys_getresuid" to 0x380,
        "__do_sys_getresgid" to 0x3C0,
        "_stext" to 0x1000,
        "_etext" to 0x104F31C + 0x1000,
    )

    fun shippedSpec(): UltraKernelSpec =
        UltraKernelSpec.read(File("src/main/assets/ultra-kernels/k22-ultra-6.6.89.spec"))

    fun shippedRecords(): List<UltraKernelSpec.Patch> = shippedSpec().patches

    /** The active template retains PAC and replays the native SUB SP,SP,#0x70. */
    fun correctedReplacement(index: Int): ByteArray = shippedRecords()[index].replacement.copyOf()

    fun credential(): UltraKernelCredential = UltraKernelCredential.of(K22_CREDENTIAL)

    /** Identity in the current oracle, separate from the historic 5.1.8 upgrade fixture. */
    fun activeCredential(): UltraKernelCredential = UltraKernelCredential.of(shippedSpec().key)

    fun freshCredential(): UltraKernelCredential = UltraKernelCredential.of("Aa1".repeat(16))

    fun otherCredential(): UltraKernelCredential = UltraKernelCredential.of(OTHER_CREDENTIAL)

    fun recipe(): UltraKernelRecipe = UltraKernelRecipe.k22()

    /**
     * A kernel-shaped buffer that carries the shipped pristine bytes at every k22 site plus the
     * three things the renderer needs from the image: the release banner and the two accessor
     * shapes the `task_struct` field rules read.
     */
    fun syntheticKernel(): ByteArray {
        // Frozen pre-repair windows provide real instructions at the original function sites.
        val records = UltraKernelSpec.read(File("src/main/assets/ultra-kernels/recovery/k22-ultra-6.6.89.spec")).patches
        val size = records.maxOf {
            it.offset + maxOf(it.original.size, it.replacement.size)
        }.toInt().coerceAtLeast(K22_SYMBOL_BASE.getValue("_etext"))
        val kernel = ByteArray(size)
        UltraKernelA64.writeLe32(kernel, 24, 2) // arm64 Image: native 4K pages.
        val banner = "Linux version $K22_RELEASE\n".toByteArray(Charsets.US_ASCII)
        banner.copyInto(kernel, 0x200)
        // `mrs x8, sp_el0 ; ldrsw x0, [x8, #0x8E8] ; ret` - the shape the seccomp rule reads.
        val seccompOffset = 0x8E8
        val seccomp = intArrayOf(
            0xD5384108.toInt(),
            0xB9800000.toInt() or ((seccompOffset shr 2) shl 10) or (8 shl 5),
            UltraKernelA64.RET,
        )
        seccomp.forEachIndexed { index, word ->
            UltraKernelA64.writeLe32(kernel, 0x100 + index * 4, word.toLong() and 0xFFFFFFFFL)
        }
        // `mrs x8, sp_el0 ; ldr x8, [x8, #0x820] ; ret` - the shape the cred rule reads.
        val credOffset = 0x820
        val cred = intArrayOf(
            0xD5384108.toInt(),
            UltraKernelA64.ldAuto("ldr", 8, 8, credOffset, 8),
            UltraKernelA64.ldAuto("ldr", 0, 8, 8, 4),
            UltraKernelA64.RET,
        )
        cred.forEachIndexed { index, word ->
            UltraKernelA64.writeLe32(kernel, 0x180 + index * 4, word.toLong() and 0xFFFFFFFFL)
        }
        records.forEach { record -> record.original.copyInto(kernel, record.offset.toInt()) }
        UltraKernelA64.writeLe32(kernel, K22_SYMBOL_BASE.getValue("do_execveat_common") + 4, 0xD101C3FFL)
        val euid = intArrayOf(UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
            UltraKernelA64.ldAuto("ldr", 8, 8, credOffset, 8),
            UltraKernelA64.ldAuto("ldr", 0, 8, 24, 4), UltraKernelA64.RET)
        euid.forEachIndexed { index, word ->
            UltraKernelA64.writeLe32(kernel, 0x1C0 + index * 4, word.toLong())
        }
        // Independent comm accessor: __get_task_comm(buf, size, task) copies task->comm.
        val comm = intArrayOf(UltraKernelA64.addImm(1, 2, 0x830),
            UltraKernelA64.encodeB(0x304, 0x340))
        comm.forEachIndexed { index, word ->
            UltraKernelA64.writeLe32(kernel, 0x300 + index * 4, word.toLong())
        }
        // Each saved ID is independently observed at getres*'s third user output.
        for ((at, member) in listOf(0x380 to 16, 0x3C0 to 20)) {
            val saved = intArrayOf(UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
                UltraKernelA64.ldAuto("ldr", 8, 8, credOffset, 8),
                UltraKernelA64.ldAuto("ldr", 8, 8, member, 4),
                UltraKernelA64.ldAuto("str", 8, 2, 0, 4), UltraKernelA64.RET)
            saved.forEachIndexed { index, word ->
                UltraKernelA64.writeLe32(kernel, at + index * 4, word.toLong())
            }
        }
        return kernel
    }

    fun symbols(imageSize: Int = syntheticKernel().size): FakeSymbols =
        FakeSymbols(K22_SYMBOL_BASE, imageSize)

    /** Render the shipped recipe against the synthetic kernel with [credential]. */
    fun rendered(credential: UltraKernelCredential = credential()): List<UltraKernelRecipe.Rendered> {
        val kernel = syntheticKernel()
        return recipe().render(symbols(kernel.size), kernel, credential)
    }

    /**
     * A plan built exactly the way `UltraKernelSpecGenerator` builds one, minus the `kallsyms` decode
     * (which cannot run on a synthetic image).
     */
    fun k22Plan(
        credential: UltraKernelCredential = credential(),
        kernel: ByteArray = syntheticKernel(),
    ): UltraKernelPlan {
        val rendered = recipe().render(symbols(kernel.size), kernel, credential)
        val match = recipe().generatedCoverage(rendered)
        val records = rendered.map { item ->
            UltraKernelPlan.PatchRecord(
                role = item.role,
                offset = item.site.toLong(),
                original = item.original,
                replacement = item.replacement,
            )
        }
        val plan = UltraKernelPlan.fromRecords(
            kernelRelease = K22_RELEASE,
            records = records,
            credential = credential,
            origin = UltraKernelPlan.Origin.GENERATED,
            evidence = UltraKernelPlan.SiteEvidence(
                match.matching, match.total, match.differingRoles, emptyList(),
            ),
            baseKernelSha256 = sha256Hex(kernel),
        )
        return plan.withDerived(plan.apply(kernel).derived)
    }
}

/**
 * A [UltraKernelSymbols] over a literal `name -> offset` map.
 *
 * `isSymbolStart` is membership in the set of known offsets, `nextOffset` is the smallest known
 * offset above the query - both exactly what the kallsyms table answers.
 */
internal class FakeSymbols(
    private val offsets: Map<String, Int>,
    override val imageSize: Int,
) : UltraKernelSymbols {

    override fun offsetOf(name: String): Int? = offsets[name]

    override fun isSymbolStart(value: Int): Boolean = offsets.containsValue(value)

    override fun nextOffset(offset: Int): Int? =
        offsets.values.filter { it > offset }.minOrNull()

    override val summary: String get() = "fake=${offsets.size} image=$imageSize"
}
