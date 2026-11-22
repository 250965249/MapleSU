package dev.maplesu.manager.ultrakernel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic Image coordinates vary independently of member/record locations. */
class UltraKernelTracePidLocationTest {
    private fun fixture(member: Int = 160, comm: Int = 256, wrongName: Boolean = false,
        wrongWidth: Boolean = false, conflict: Boolean = false, wrongClass: Boolean = false,
        wrongCallback: Boolean = false, namespaceDecoy: Boolean = false, executable: Boolean = false, cfi: Boolean = false): Pair<ByteArray, UltraKernelSymbols> {
        val raw = ByteArray(0x4000)
        val base = -0x100000000L
        fun q(at: Int, value: Long) { for (i in 0..7) raw[at + i] = (value ushr (8 * i)).toByte() }
        fun u(at: Int, value: Int) { for (i in 0..3) raw[at + i] = (value ushr (8 * i)).toByte() }
        u(56, 0x644d5241); q(8, 0x80000)
        fun rela(at: Int, slot: Int, target: Long) { q(at, base + slot); q(at + 8, 1027); q(at + 16, target) }
        rela(0x2000, 0x1000, base - 0x80000)
        rela(0x2018, 0x1100, base + if (wrongClass) 0x1500 else 0x1200)
        rela(0x2030, 0x1200, base + if (wrongCallback) 0x950 else if (cfi) 0x600 else 0x500)
        rela(0x2048, 0x1208, base + if (executable) 0x700 else 0x1300)
        var str = 0x1800
        fun text(value: String): Int {
            val result = str; val b = value.toByteArray(Charsets.US_ASCII); b.copyInto(raw, str); str = UltraKernelA64.alignUp(str + b.size + 1, 4)
            return result
        }
        val stringAddresses = arrayListOf<Pair<Int, Int>>()
        val specs = listOf(Triple("parent_comm", "char[16]", 16),
            Triple(if (wrongName) "other_pid" else "parent_pid", "pid_t", if (wrongWidth) 8 else 4),
            Triple("child_comm", "char[16]", 16), Triple("child_pid", "pid_t", 4))
        for ((index, spec) in specs.withIndex()) {
            val at = 0x1300 + index * 32
            val typeText = text(spec.second); val nameText = text(spec.first)
            stringAddresses += typeText to nameText
            q(at, base + typeText); q(at + 8, base + nameText); u(at + 16, spec.third)
            u(at + 20, if (spec.second == "pid_t") 4 else 1); u(at + 24, if (spec.second == "pid_t") 1 else 0)
        }
        val setter = UltraKernelAsm(0x100)
        setter.emit(UltraKernelA64.movReg(19, 0)); setter.emit(UltraKernelA64.movReg(20, 1))
        setter.emit(UltraKernelA64.addImm(0, 19, comm)); setter.emit(UltraKernelA64.movReg(1, 20))
        setter.emit(UltraKernelA64.movz(2, 16)); setter.blAbs(0x900); setter.emit(UltraKernelA64.RET)
        val setterCode = setter.finish(); setterCode.copyInto(raw, 0x100)
        val a = UltraKernelAsm(0x500)
        a.emit(UltraKernelA64.movReg(19, 1)); a.emit(UltraKernelA64.movReg(20, 2))
        a.emit(UltraKernelA64.movReg(21, 0)); a.blr(8)
        a.emit(UltraKernelA64.movReg(1, 21)); a.emit(UltraKernelA64.movz(2, 48)); a.blAbs(0xa00)
        a.cbz(0, "done"); a.emit(UltraKernelA64.movReg(22, 0))
        for ((task, recordComm, recordPid) in listOf(Triple(19, 8, 24), Triple(20, 28, 44))) {
            for (part in 0..1) {
                a.emit(UltraKernelA64.ldImm("ldr", 8, task, comm + part * 8, 8))
                a.emit(UltraKernelA64.ldAuto("str", 8, 22, recordComm + part * 8, 8))
            }
            a.emit(UltraKernelA64.ldImm("ldr", 8, task, member + if (conflict && task == 20) 4 else 0, 4))
            a.emit(UltraKernelA64.ldImm("str", 8, 22, recordPid, 4))
        }
        a.emit(UltraKernelA64.movReg(0, 22)); a.blAbs(0xa40); a.mark("done"); a.emit(UltraKernelA64.RET)
        val code = a.finish(); code.copyInto(raw, 0x500)
        val entries = linkedMapOf("__set_task_comm" to 0x100, "end_setter" to 0x100 + setterCode.size,
            "trace_event_raw_event_sched_process_fork" to 0x500, "end_callback" to 0x500 + code.size,
            "strlcpy" to 0x900, "trace_event_buffer_reserve" to 0xa00, "trace_event_buffer_commit" to 0xa40,
            "kimage_vaddr" to 0x1000, "event_sched_process_fork" to 0x1100,
            "event_class_sched_process_fork" to 0x1200, "trace_event_fields_sched_process_fork" to 0x1300,
            "end_fields" to 0x13a0)
        if (cfi) {
            u(0x600, UltraKernelA64.encodeB(0x600L, 0x500L))
            entries["trace_event_raw_event_sched_process_fork.cfi_jt"] = 0x600
            entries["end_cfi"] = 0x604
        }
        if (executable) {
            val d = UltraKernelAsm(0x700)
            d.emit(UltraKernelA64.movReg(19, 0))
            for ((index, spec) in specs.withIndex()) {
                d.emit(UltraKernelA64.movReg(0, 19))
                for ((reg, at) in listOf(1 to stringAddresses[index].first, 2 to stringAddresses[index].second))
                    d.emit(UltraKernelA64.encodeAdr(d.here().toLong(), at.toLong(), reg))
                d.emit(UltraKernelA64.movz(3, listOf(8, 24, 28, 44)[index]))
                d.emit(UltraKernelA64.movz(4, spec.third))
                d.emit(UltraKernelA64.movz(5, if (spec.second == "pid_t") 1 else 0))
                d.blAbs(0xb80); d.cbnz(0, "done", false)
            }
            d.mark("done"); d.emit(UltraKernelA64.RET)
            val body = d.finish(); body.copyInto(raw, 0x700)
            entries["trace_event_define_fields_sched_process_fork"] = 0x700
            entries["end_definition"] = 0x700 + body.size
            entries["trace_define_field"] = 0xb80
            entries.remove("trace_event_fields_sched_process_fork")
        }
        if (namespaceDecoy) entries["__arm64_sys_gettid"] = 0xb00
        return raw to object : UltraKernelSymbols {
            override val imageSize = raw.size
            override val summary = "trace-pid-image-fixture"
            override fun offsetOf(name: String) = entries[name]
            override fun isSymbolStart(value: Int) = value in entries.values
            override fun nameAt(offset: Int) = entries.entries.firstOrNull { it.value == offset }?.key
            override fun nextOffset(offset: Int) = entries.values.filter { it > offset }.minOrNull()
        }
    }
    private fun field(pair: Pair<ByteArray, UltraKernelSymbols>) =
        UltraKernelStructOffsets.runtimeAccessorField(pair.second, pair.first, "task_struct.pid")
    private fun rejects(pair: Pair<ByteArray, UltraKernelSymbols>, reason: String) {
        val error = assertThrows(UltraKernelGenerateException::class.java) { field(pair) }
        assertTrue(error.message.orEmpty(), reason in error.message.orEmpty())
    }
    @Test fun `named parent child copies follow varying actual task member offsets`() {
        for ((pid, comm) in listOf(160 to 256, 320 to 448)) assertEquals(pid, field(fixture(pid, comm)).offsetBytes)
    }
    @Test fun `actual executable field definition binds named copies`() = assertEquals(160, field(fixture(executable = true)).offsetBytes)
    @Test fun `CFI jump stub binds to the registered callback`() = assertEquals(160, field(fixture(cfi = true)).offsetBytes)
    @Test fun `event registration class pointer is required`() = rejects(fixture(wrongClass = true), "STRUCT_TRACE_EVENT_CLASS")
    @Test fun `callback must be referenced by registered class`() = rejects(fixture(wrongCallback = true), "STRUCT_TRACE_CALLBACK_BINDING")
    @Test fun `wrong field name is not pid provenance`() = rejects(fixture(wrongName = true), "STRUCT_TRACE_FIELD_NAMES")
    @Test fun `wrong pid width is not accepted`() = rejects(fixture(wrongWidth = true), "STRUCT_TRACE_PID_TYPE")
    @Test fun `parent and child disagreement is a real conflict`() = rejects(fixture(conflict = true), "STRUCT_TRACE_PID_CONFLICT")
    @Test fun `namespace gettid decoy is never used for task pid`() = assertEquals(160, field(fixture(namespaceDecoy = true)).offsetBytes)
}


