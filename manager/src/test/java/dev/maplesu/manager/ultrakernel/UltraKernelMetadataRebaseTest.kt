package dev.maplesu.manager.ultrakernel

import org.junit.Assert.*
import org.junit.Test

class UltraKernelMetadataRebaseTest {
    @Test fun capturedArchiveAndHelperCallbacksMatchTheCompleteCompatibilityAbi() {
        val capturePath = System.getProperty("maplesu.metadata.payloads")
        org.junit.Assume.assumeNotNull(capturePath)
        val files = java.io.File(capturePath!!).listFiles()!!.filter {
            it.name.startsWith("apk518-") && it.extension == "bin"
        }
        assertEquals(30, files.size)
        for (file in files) {
            val delta = Regex("apk518-m(?:024|041|073)-delta(-?\\d+)\\.bin").matchEntire(file.name)!!.groupValues[1].toInt()
            val input = file.readBytes()
            assertArrayEquals(file.name, callback(delta), input)
            val vm = execute(input, delta, 0x123456)
            assertEquals(file.name, RETURN_ADDRESS - 4 + 0x123456,
                evaluate(vm.payload.copyOfRange(116, input.size - 140))[11])
            assertFalse(file.name, vm.writes.isEmpty())
        }
    }

    @Test fun completeSdkCallbacksRebaseAcrossSignedDisplacements() {
        val deltas = listOf(Int.MIN_VALUE, -9139764, -65536, -208, -1, 0, 1, 65536, 0x123456, Int.MAX_VALUE)
        for (legacy in deltas) for (actual in deltas) {
            val input = callback(legacy)
            val vm = execute(input, legacy, actual, credSuid = 20)
            assertEquals("helper budget", true, vm.code.size <= 448)
            assertArrayEquals(input.copyOfRange(0, 116), vm.payload.copyOfRange(0, 116))
            assertArrayEquals(input.copyOfRange(input.size - 140, input.size),
                vm.payload.copyOfRange(input.size - 140, input.size))
            val result = evaluate(vm.payload.copyOfRange(116, input.size - 140))
            assertEquals(RETURN_ADDRESS - 4 + actual, result[11])
            assertEquals(actual.toLong(), result[12])
            assertEquals(RETURN_ADDRESS, result[30])
            assertEquals((116 until input.size - 140 step 4).toList(), vm.writes)
            assertEquals(vm.writes, vm.cleaned)
            assertEquals(1, vm.barriers)
            assertEquals(PAYLOAD, vm.registers[0])
            assertEquals(REQUEST, vm.registers[11])
            assertEquals(CRED + 20, vm.registers[17])
            assertEquals(RETURN_ADDRESS, vm.registers[30])
            assertEquals(STACK, vm.registers[31])
            assertTrue(vm.payloadReads.all { it in 0..input.size - 4 })
        }
    }

    @Test fun everyNearMatchByteAndWrongKeyDeltaRemainUnchanged() {
        val original = callback(-9139764)
        for (offset in original.indices) {
            val input = original.copyOf().also { it[offset] = (it[offset].toInt() xor 1).toByte() }
            val vm = execute(input, -9139764, 0x123456)
            assertArrayEquals("near match byte $offset", input, vm.payload)
            assertTrue(vm.writes.isEmpty())
            assertTrue(vm.cleaned.isEmpty())
        }
        val vm = execute(original, -9139760, 0x123456)
        assertArrayEquals(original, vm.payload)
        assertTrue(vm.writes.isEmpty())
    }

    @Test fun truncatedRangesAndNullPointersNeverReadPayload() {
        val original = callback(-9139764)
        for (size in 0 until original.size) {
            val vm = execute(original.copyOf(size), -9139764, 0x123456)
            assertTrue("truncated size $size", vm.payloadReads.isEmpty())
            assertTrue(vm.writes.isEmpty())
        }
        val vm = execute(original, -9139764, 0x123456, pointer = 0)
        assertTrue(vm.payloadReads.isEmpty())
        assertTrue(vm.writes.isEmpty())
    }

    @Test fun embeddedDataIsIgnoredAndUnreachableTrailingDataIsRetained() {
        val original = callback(-9139764)
        val embedded = words(0xD503201F) + original
        val dataVm = execute(embedded, -9139764, -4)
        assertArrayEquals(embedded, dataVm.payload)
        assertTrue(dataVm.writes.isEmpty())
        val tail = ByteArray(321) { (it * 53).toByte() }
        val vm = execute(original + tail, -9139764, -4)
        assertArrayEquals(tail, vm.payload.copyOfRange(original.size, vm.payload.size))
        assertEquals(RETURN_ADDRESS - 8, evaluate(vm.payload.copyOfRange(116, original.size - 140))[11])
        assertTrue(vm.payloadReads.all { it < original.size })
    }

    @Test fun emittedCodeDeclaresAllTemplatesAsDataAndPassesInstructionValidation() {
        val vm = execute(callback(-9139764), -9139764, 0x123456)
        assertEquals(emptyList<Int>(), UltraKernelA64Verify.invalidWords(vm.code, vm.dataOffsets))
        assertEquals(312 / 4, vm.dataOffsets.size)
    }

    private fun execute(input: ByteArray, legacy: Int, actual: Int, credSuid: Int = 16, pointer: Long = PAYLOAD): Vm {
        val asm = UltraKernelAsm(0x1000)
        val resolver = UltraKernelSymbolResolver(object : UltraKernelSymbols {
            override val imageSize = 0x100000
            override val summary = "metadata rebase fixture"
            override fun offsetOf(name: String): Int? = null
            override fun isSymbolStart(value: Int) = false
            override fun nextOffset(offset: Int): Int? = null
        })
        UltraKernelMetadataRebase.generate(asm, resolver, UltraKernelFields(comm = 0x830, cred = 0x820, credSuid = credSuid,
            legacyMetadataDisplacement = legacy, actualMetadataDisplacement = actual))
        return Vm(asm.finish(), asm.dataOffsets, input.copyOf(), pointer).also { it.run() }
    }

    // Frozen wrapper bytes from the pinned m025 emitter; the body uses its
    // explicit MOVZ/MOVK helper, independently of the product's template builder.
    private fun callback(delta: Int): ByteArray {
        val body = mutableListOf(0xAA1E03EBL, 0xD100116BL)
        var started = false
        for (i in 0..3) {
            val part = (delta.toLong() ushr (i * 16)) and 65535
            if (part != 0L) {
                body += (if (started) 0xF2800000L else 0xD2800000L) or (i.toLong() shl 21) or (part shl 5) or 12
                started = true
            }
        }
        if (!started) body += 0xD280000CL
        body += 0x8B0C016BL
        return hex(PREFIX) + words(*body.toLongArray()) + hex(SUFFIX)
    }

    private fun evaluate(code: ByteArray): LongArray {
        val r = LongArray(32).also { it[30] = RETURN_ADDRESS }
        for (at in code.indices step 4) {
            val w = UltraKernelA64.le32(code, at)
            val rd = (w and 31).toInt()
            val rn = ((w ushr 5) and 31).toInt()
            when {
                w == 0xD503201FL -> Unit
                w and 0xFF800000L == 0xD2800000L -> r[rd] = ((w ushr 5) and 65535) shl (((w ushr 21) and 3).toInt() * 16)
                w and 0xFF800000L == 0x92800000L -> r[rd] = (((w ushr 5) and 65535) shl (((w ushr 21) and 3).toInt() * 16)).inv()
                w and 0xFF800000L == 0xF2800000L -> {
                    val shift = ((w ushr 21) and 3).toInt() * 16
                    r[rd] = (r[rd] and (65535L shl shift).inv()) or (((w ushr 5) and 65535) shl shift)
                }
                w and 0xFFE0FFE0L == 0xAA0003E0L -> r[rd] = r[((w ushr 16) and 31).toInt()]
                w and 0xFFC00000L == 0xD1000000L -> r[rd] = r[rn] - ((w ushr 10) and 4095)
                w and 0xFFE0FC00L == 0x8B000000L -> r[rd] = r[rn] + r[((w ushr 16) and 31).toInt()]
                else -> error("unexpected locator word ${w.toString(16)}")
            }
        }
        return r
    }

    /** Executes the emitted helper, with bounds checked separately for each memory surface. */
    private class Vm(val code: ByteArray, val dataOffsets: Set<Int>, val payload: ByteArray, pointer: Long) {
        val registers = LongArray(32).also {
            it[0] = pointer; it[11] = REQUEST; it[17] = CRED; it[30] = RETURN_ADDRESS; it[31] = STACK
        }
        val payloadReads = mutableListOf<Int>()
        val writes = mutableListOf<Int>()
        val cleaned = mutableListOf<Int>()
        var barriers = 0
        private var equal = false
        private var carry = false

        fun run() {
            var pc = 0
            repeat(2000) {
                val w = UltraKernelA64.le32(code, pc)
                val rd = (w and 31).toInt()
                val rn = ((w ushr 5) and 31).toInt()
                var next = pc + 4
                fun assign(value: Long) { if (rd != 31) registers[rd] = if (w and 0x80000000L != 0L) value else value and 0xffffffffL }
                when {
                    w == 0xD65F03C0L -> return
                    w == 0xD5033B9FL -> barriers++
                    w and 0xFFFFFFE0L == 0xD50B7A20L -> cleaned += (registers[rd] - PAYLOAD).toInt()
                    w and 0x9F000000L == 0x10000000L -> assign(0x1000 + pc + signed(((w ushr 5) and 0x7ffff) * 4 + ((w ushr 29) and 3), 21))
                    w and 0xFF000010L == 0x54000000L -> {
                        val branch = when ((w and 15).toInt()) { 1 -> !equal; 3 -> !carry; else -> error("condition") }
                        if (branch) next = pc + signed((w ushr 5) and 0x7ffff, 19).toInt() * 4
                    }
                    w and 0x7F000000L == 0x34000000L -> if (registers[rd] == 0L) next = pc + signed((w ushr 5) and 0x7ffff, 19).toInt() * 4
                    w and 0x7F800000L == 0x52800000L -> assign(((w ushr 5) and 65535) shl (((w ushr 21) and 3).toInt() * 16))
                    w and 0x7FE0FFE0L == 0x2A0003E0L -> assign(registers[((w ushr 16) and 31).toInt()])
                    w and 0x1F000000L == 0x11000000L -> {
                        val value = registers[rn]; val imm = (w ushr 10) and 4095
                        val result = if (w and 0x40000000L != 0L) value - imm else value + imm
                        if (w and 0x20000000L != 0L) { equal = result == 0L; carry = java.lang.Long.compareUnsigned(value, imm) >= 0 }
                        assign(result)
                    }
                    w and 0x7FE0FC1FL == 0x6B00001FL -> {
                        val left = registers[rn]; val right = registers[((w ushr 16) and 31).toInt()]
                        equal = left == right; carry = java.lang.Long.compareUnsigned(left, right) >= 0
                    }
                    w and 0xFFC00000L == 0xB9400000L -> assign(read(registers[rn] + ((w ushr 10) and 4095) * 4))
                    w and 0xFFE00C00L == 0xB8400400L -> {
                        assign(read(registers[rn])); registers[rn] += signed((w ushr 12) and 511, 9)
                    }
                    w and 0xFFC00000L == 0xB9000000L -> {
                        val address = registers[rn] + ((w ushr 10) and 4095) * 4
                        val offset = (address - PAYLOAD).toInt()
                        require(address >= PAYLOAD && offset in 0..payload.size - 4)
                        writes += offset; UltraKernelA64.writeLe32(payload, offset, registers[rd])
                    }
                    else -> error("unexpected helper word ${w.toString(16)} at $pc")
                }
                pc = next
            }
            error("helper did not return")
        }

        private fun read(address: Long): Long = when {
            address == REQUEST + 76 -> payload.size.toLong()
            address >= 0x1000 && address < 0x1000 + code.size -> UltraKernelA64.le32(code, (address - 0x1000).toInt())
            else -> {
                val offset = (address - PAYLOAD).toInt()
                require(address >= PAYLOAD && offset in 0..payload.size - 4) { "payload read $offset" }
                payloadReads += offset; UltraKernelA64.le32(payload, offset)
            }
        }

        private fun signed(value: Long, bits: Int) = (value shl (64 - bits)) shr (64 - bits)
    }

    private fun words(vararg values: Long): ByteArray = ByteArray(values.size * 4).also { bytes ->
        values.forEachIndexed { index, value -> UltraKernelA64.writeLe32(bytes, index * 4, value) }
    }
    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    companion object {
        private const val PAYLOAD = 0x20000L
        private const val REQUEST = 0x40000L
        private const val CRED = 0x60000L
        private const val STACK = 0x80000L
        private val RETURN_ADDRESS = 0xffff000040000044UL.toLong()
        private const val PREFIX = "5f2403d5f353bfa9f55bbfa9f763bfa9f96bbfa9fb73bfa96a4144f86c4d40b96d5140b9ea33bfa9ed47bfa9fd7bbfa911000014" +
            "30355957746147766443764f383052524b357775596c506950356b686c6c3859634a3450327a474c353346494b39564733454a4742593230766b437a316b4f00"
        private const val SUFFIX = "1100001437436a3447373949596835503947704942544d654c5a734e31594261796c564437374973415067666e456875576e384d477145643865427045636d446f6f3500" +
            "e0030baafd7bc1a8ed47c1a8ea33c1a83f0200f9201200b801fc60d321520078316200913f0200b901fc70d321020079fb73c1a8f96bc1a8f763c1a8f55bc1a8f353c1a8c0035fd6"
    }
}
