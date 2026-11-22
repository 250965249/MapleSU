package dev.maplesu.manager.ultrakernel

import java.io.File
import org.junit.Assert.*
import org.junit.Test

/** The actual case04 entry allocates SP before a static SCS push, without PAC. */
class UltraKernelStaticScsEntryTest {
    @Test fun realNonPacEntryKeepsAllocationAndReplaysShadowPushOnce() {
        val (kernel, plan) = fixture()
        val hook = plan.records.single { it.role == "do_execveat_common+0x0" }
        val frame = plan.records.single { it.role == "arm64_notify_die+0x0" }
        val patched = plan.apply(kernel).kernel
        assertEquals(entry + 4L, hook.offset)
        assertArrayEquals(realEntry.copyOfRange(0, 4), patched.copyOfRange(entry, entry + 4))
        assertArrayEquals(realEntry.copyOfRange(8, 64), patched.copyOfRange(entry + 8, entry + 64))
        assertEquals(shadowPush, UltraKernelA64.le32Bits(frame.replacement, 20))
        assertEquals(frame.offset + 28, branchTarget(hook.offset, hook.replacement, 0))
        assertEquals(entry + 8L, branchTarget(frame.offset, frame.replacement, 24))
        assertEquals(1, (0 until frame.length step 4).count {
            UltraKernelA64.le32Bits(frame.replacement, it) == shadowPush
        })
        assertFalse((0 until frame.length step 4).any {
            UltraKernelA64.le32Bits(frame.replacement, it) == UltraKernelA64.PACIA1716
        })
        for ((role, prefix) in listOf("free_initmem+0x0" to 4,
            "__traceiter_kvm_userspace_exit+0x70" to 0)) {
            val metadata = plan.records.single { it.role == role }
            assertEquals(hook.offset,
                UltraKernelA64.le32Bits(metadata.replacement, prefix + 36).toLong())
        }
        System.getProperty("maplesu.scs.dump")?.let { path ->
            val gate = plan.records.single { it.role == "die+0x0" }
            File(path).writeText("""{"entry":$entry,"original":"${hex(realEntry)}","patchedEntry":"${hex(patched.copyOfRange(entry, entry + 64))}","frame":${frame.offset},"frameBytes":"${hex(frame.replacement)}","gate":${gate.offset},"gateBytes":"${hex(gate.replacement)}"}""")
        }
    }

    @Test fun otherPositiveAlignedSubImmediatesHaveTheSameContract() {
        for (amount in listOf(16, 32, 112, 4080)) {
            val word = 0xD10003FF.toInt() or (amount shl 10)
            val (kernel, plan) = fixture(word, shadowPush)
            assertEquals(word, UltraKernelA64.le32Bits(plan.apply(kernel).kernel, entry))
            assertEquals(shadowPush, UltraKernelA64.le32Bits(
                plan.records.single { it.role == "arm64_notify_die+0x0" }.replacement, 20))
        }
    }

    @Test fun unprovedFirstInstructionsStayRejected() {
        val rejected = listOf(
            0xD10003FFL, // zero allocation
            0xD10023FFL, // unaligned 8-byte allocation
            0xF101C3FFL, // SUBS changes flags
            0x5101C3FFL, // 32-bit SUB
            0xD101C3DFL, // source is X30
            0xD101C3FEL, // destination is X30
            0xD141C3FFL, // shifted immediate is outside this reviewed form
            0x90000000L, // PC-relative ADRP
            0x14000001L, // pre-existing B is not an original prefix
        )
        for (word in rejected) {
            val error = assertThrows(UltraKernelGenerateException::class.java) {
                fixture(word.toInt(), shadowPush)
            }
            assertEquals("first=%08x".format(word),
                "HOOK_ENTRY_UNSUPPORTED:do_execveat_common", error.detail)
        }
    }

    @Test fun nonPacAllocationRequiresTheExactStaticShadowPush() {
        for (word in listOf(0x90000000L, 0xD503201FL, 0xF800867EL, 0xF800825EL)) {
            val error = assertThrows(UltraKernelGenerateException::class.java) {
                fixture(0xD101C3FF.toInt(), word.toInt())
            }
            assertEquals("second=%08x".format(word),
                "HOOK_FRAME_UNSUPPORTED:do_execveat_common", error.detail)
        }
    }

    @Test fun existingPacStackFrameAndStaticScsProloguesRemainSupported() {
        for (word in listOf(0xA9BF7BFD.toInt(), 0xD101C3FF.toInt(), shadowPush)) {
            val (kernel, plan) = fixture(UltraKernelA64.PACIA1716, word)
            assertEquals(UltraKernelA64.PACIA1716, UltraKernelA64.le32Bits(plan.apply(kernel).kernel, entry))
            assertEquals(word, UltraKernelA64.le32Bits(
                plan.records.single { it.role == "arm64_notify_die+0x0" }.replacement, 20))
        }
    }

    @Test fun aDynamicScsSymbolKeepsPacAtItsUnwindAddress() {
        val kernel = base.copyOf()
        UltraKernelA64.writeLe32(kernel, entry, UltraKernelA64.PACIA1716.toLong())
        UltraKernelA64.writeLe32(kernel, entry + 4, 0xD101C3FFL)
        val symbols = FakeSymbols(UltraKernelPlanFixtures.K22_SYMBOL_BASE +
            ("__pi_scs_patch" to 0x450), kernel.size)
        val records = UltraKernelRecipe.k22().render(symbols, kernel, UltraKernelPlanFixtures.credential())
        val hook = records.single { it.role == "do_execveat_common+0x0" }
        val frame = records.single { it.role == "arm64_notify_die+0x0" }
        assertEquals(entry + 4, hook.site)
        assertEquals(frame.site + 28L, branchTarget(hook.site.toLong(), hook.replacement, 0))
        assertEquals(0xD101C3FF.toInt(), UltraKernelA64.le32Bits(frame.replacement, 20))
        assertEquals(entry + 8L, branchTarget(frame.site.toLong(), frame.replacement, 24))
        assertFalse((0 until frame.replacement.size step 4).any {
            UltraKernelA64.le32Bits(frame.replacement, it) == UltraKernelA64.PACIA1716
        })
    }

    private fun fixture(first: Int? = null, second: Int? = null): Pair<ByteArray, UltraKernelPlan> {
        val kernel = base.copyOf()
        realEntry.copyInto(kernel, entry)
        first?.let { UltraKernelA64.writeLe32(kernel, entry, it.toLong()) }
        second?.let { UltraKernelA64.writeLe32(kernel, entry + 4, it.toLong()) }
        return kernel to UltraKernelPlanFixtures.k22Plan(kernel = kernel)
    }

    private fun branchTarget(base: Long, bytes: ByteArray, at: Int): Long {
        val word = UltraKernelA64.le32Bits(bytes, at)
        assertEquals(0x14000000, word and 0xfc000000.toInt())
        return base + at + UltraKernelA64.signExtend((word and 0x03ffffff).toLong(), 26) * 4
    }

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }

    companion object {
        private val entry = UltraKernelPlanFixtures.K22_SYMBOL_BASE.getValue("do_execveat_common")
        private val base by lazy { UltraKernelPlanFixtures.syntheticKernel() }
        private val shadowPush = 0xF800865E.toInt()
        // Boot_Research/boot.img, raw SHA 80e2007352c83cf0..., entry 0x50b09c.
        private val realEntry = ("ffc301d15e8600f8fd7b01a9fc6f02a9fa6703a9f85f04a9f65705a9f44f06a9" +
            "fd430091f30301aa3ffc3fb163000054fb03132aa40000141c4138d5884740b9")
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
