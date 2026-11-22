package dev.maplesu.manager.ultrakernel

import java.io.File
import org.junit.Assert.*
import org.junit.Test

class UltraKernelSavedIdFrameTest {
    private class Symbols(private val names: Map<String, Int>, override val imageSize: Int) : UltraKernelSymbols {
        override val summary = "saved-id-frame-fixture"
        override fun offsetOf(name: String) = names[name]
        override fun isSymbolStart(value: Int) = value in names.values
        override fun nextOffset(offset: Int) = names.values.filter { it > offset }.minOrNull()
    }
    private val names = mapOf("__arm64_sys_getuid" to 0x100, "__arm64_sys_geteuid" to 0x140,
        "__arm64_sys_getgid" to 0x180, "__arm64_sys_getegid" to 0x1c0,
        "__arm64_sys_getresuid" to 0x400, "__arm64_sys_getresgid" to 0x600)
    private fun emit(raw: ByteArray, at: Int, vararg words: Int) {
        words.forEachIndexed { index, word -> UltraKernelA64.writeLe32(raw, at + index * 4, word.toLong()) }
    }
    private fun getter(raw: ByteArray, at: Int, member: Int) = emit(raw, at,
        UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8),
        UltraKernelA64.ldImm("ldr", 0, 8, member, 4), UltraKernelA64.RET)
    private fun pair(first: Int, second: Int, base: Int, offset: Int = 0) =
        0xa9400000.toInt() or (((offset / 8) and 127) shl 15) or (second shl 10) or (base shl 5) or first
    private fun wrapper(raw: ByteArray, at: Int, real: Int, effective: Int, saved: Int) = emit(raw, at,
        UltraKernelA64.mrs(19, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 19, 19, 0x780, 8),
        UltraKernelA64.movReg(20, 0), pair(21, 22, 20), UltraKernelA64.ldImm("ldr", 23, 20, 16, 8),
        UltraKernelA64.ldImm("ldr", 8, 19, real, 4), UltraKernelA64.ldImm("str", 8, 21, 0, 4),
        UltraKernelA64.ldImm("ldr", 8, 19, effective, 4), UltraKernelA64.ldImm("str", 8, 22, 0, 4),
        UltraKernelA64.ldImm("ldr", 8, 19, saved, 4), UltraKernelA64.ldImm("str", 8, 23, 0, 4), UltraKernelA64.RET)
    private fun image() = ByteArray(2048).also {
        getter(it, 0x100, 4); getter(it, 0x140, 20); getter(it, 0x180, 8); getter(it, 0x1c0, 24)
        wrapper(it, 0x400, 4, 20, 12); wrapper(it, 0x600, 8, 24, 16)
    }
    private fun layout(raw: ByteArray, anchors: Map<String, Int> = names) =
        UltraKernelStructOffsets.credentialLayout(Symbols(anchors, raw.size), raw, 0x780, null)
    private fun reject(raw: ByteArray) = assertThrows(UltraKernelGenerateException::class.java) { layout(raw) }

    @Test fun frameLoadsIdentifyThreeIndependentOutputs() {
        val result = layout(image())
        assertEquals(12, result.suid); assertEquals(16, result.sgid); assertEquals(20, result.euid)
    }

    @Test fun eachUserOutputMustReceiveItsIndependentCredentialField() {
        for ((at, member) in listOf(0x414 to 20, 0x41c to 4, 0x424 to 20,
            0x614 to 24, 0x61c to 8, 0x624 to 24)) {
            val raw = image()
            emit(raw, at, UltraKernelA64.ldImm("ldr", 8, 19, member, 4))
            reject(raw)
        }
    }

    @Test fun everyFrameArgumentMustBeAnExact64BitSlot() {
        for (word in listOf(UltraKernelA64.ldImm("ldr", 23, 20, 24, 8),
            UltraKernelA64.ldImm("ldr", 23, 20, 16, 4), UltraKernelA64.ldImm("ldr", 23, 1, 16, 8))) {
            val raw = image(); emit(raw, 0x410, word); reject(raw)
        }
    }

    @Test fun scalarAndStoreWidthsStay32BitForEveryOutput() {
        for (at in listOf(0x414, 0x41c, 0x424, 0x614, 0x61c, 0x624)) {
            val raw = image(); emit(raw, at, UltraKernelA64.ldImm("ldr", 8, 19, 16, 8)); reject(raw)
        }
        for ((at, pointer) in listOf(0x418 to 21, 0x420 to 22, 0x428 to 23,
            0x618 to 21, 0x620 to 22, 0x628 to 23)) {
            val raw = image(); emit(raw, at, UltraKernelA64.ldImm("str", 8, pointer, 0, 8)); reject(raw)
        }
    }

    @Test fun missingOrWrongUserOutputDoesNotBorrowAnotherStore() {
        for (at in listOf(0x418, 0x420, 0x428, 0x618, 0x620, 0x628)) {
            val raw = image(); emit(raw, at, UltraKernelA64.NOP); reject(raw)
        }
        for (at in listOf(0x428, 0x628)) for (pointer in listOf(20, 21, 22)) {
            val raw = image(); emit(raw, at, UltraKernelA64.ldImm("str", 8, pointer, 0, 4)); reject(raw)
        }
    }

    @Test fun pairsMustBeInteger64BitLoadsFromDistinctRegisterFrameSlots() {
        val normal = pair(21, 22, 20)
        for (word in listOf(normal xor (1 shl 31), normal or (1 shl 26), normal xor (3 shl 30),
            pair(21, 21, 20), pair(20, 22, 20) or (1 shl 23), pair(21, 22, 1))) {
            val raw = image(); emit(raw, 0x40c, word); reject(raw)
        }
    }

    @Test fun aProvenDirectAccessorDoesNotRequireItsWrapperToBeInlined() {
        val raw = image()
        emit(raw, 0x300, UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
            UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8), UltraKernelA64.ldImm("ldr", 8, 8, 12, 4),
            UltraKernelA64.ldImm("str", 8, 2, 0, 4), UltraKernelA64.RET)
        emit(raw, 0x400, UltraKernelA64.RET)
        assertEquals(12, layout(raw, names + ("__do_sys_getresuid" to 0x300)).suid)
    }

    @Test fun shiftedFrameAndDirectArgumentABIStayDistinct() {
        val raw = image()
        emit(raw, 0x40c, pair(21, 22, 20, 8))
        reject(raw)
        val direct = names - "__arm64_sys_getresuid" + ("__do_sys_getresuid" to 0x400)
        assertThrows(UltraKernelGenerateException::class.java) { layout(image(), direct) }
    }

    @Test fun observedSavedValuesRemainIndependentOfGetterAndNeighbourOffsets() {
        val raw = image()
        wrapper(raw, 0x400, 4, 20, 92); wrapper(raw, 0x600, 8, 24, 156)
        val result = layout(raw)
        assertEquals(92, result.suid); assertEquals(156, result.sgid)
    }

    private fun realImage(): Pair<ByteArray, Map<String, Int>> {
        val folder = File("src/test/resources/ultrakernel/case04-saved-id-frame")
        val windows = listOf(Triple("__arm64_sys_getuid", 0x144290, 0x1442c0),
            Triple("__arm64_sys_geteuid", 0x145eac, 0x145edc),
            Triple("__arm64_sys_getgid", 0x145e7c, 0x145eac),
            Triple("__arm64_sys_getegid", 0x145edc, 0x145f0c),
            Triple("__arm64_sys_getresuid", 0x144fa0, 0x145160),
            Triple("__arm64_sys_getresgid", 0x145160, 0x145314),
            Triple("from_kuid_munged", 0x2a88dc, 0x2a89ac),
            Triple("from_kgid_munged", 0x2a8b30, 0x2a8c00))
        val raw = ByteArray(0x2a8c04)
        val anchors = linkedMapOf<String, Int>()
        for ((name, start, end) in windows) {
            val data = File(folder, "$name.hex").readText().trim().chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            assertEquals(end - start, data.size)
            data.copyInto(raw, start); anchors[name] = start; anchors["${name}_end"] = end
        }
        return raw to anchors
    }

    @Test fun realCase04FrameWrappersIdentifySavedIDs() {
        val (raw, anchors) = realImage()
        val result = layout(raw, anchors)
        assertEquals(12, result.suid); assertEquals(16, result.sgid); assertEquals(20, result.euid)
    }

    @Test fun everyRealConverterCallMustRemainInItsOwnIdDomain() {
        val (raw, anchors) = realImage()
        for ((name, converter, other) in listOf(
            Triple("__arm64_sys_getresuid", "from_kuid_munged", "from_kgid_munged"),
            Triple("__arm64_sys_getresgid", "from_kgid_munged", "from_kuid_munged"))) {
            var calls = 0
            for (at in anchors.getValue(name) until anchors.getValue("${name}_end") step 4) {
                val word = UltraKernelA64.le32Bits(raw, at)
                if (!UltraKernelA64.isBl(word)) continue
                val target = at + UltraKernelA64.signExtend((word and 0x03ffffff).toLong(), 26).toInt() * 4
                if (target != anchors.getValue(converter)) continue
                calls++
                val changed = raw.copyOf()
                emit(changed, at, UltraKernelA64.encodeBl(at.toLong(), anchors.getValue(other).toLong()))
                assertThrows(UltraKernelGenerateException::class.java) { layout(changed, anchors) }
            }
            assertEquals(name, 3, calls)
        }
    }
}
