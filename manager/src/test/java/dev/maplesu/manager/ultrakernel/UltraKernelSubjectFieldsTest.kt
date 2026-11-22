package dev.maplesu.manager.ultrakernel

import java.io.File
import org.junit.Assert.*
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runners.MethodSorters

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class UltraKernelSubjectFieldsTest {
    private class Symbols(val names: Map<String, List<Int>>, override val imageSize: Int,
        private val withoutBtf: Boolean = false) : UltraKernelSymbols {
        override val summary = "subject-target"
        override fun offsetOf(name: String) = offsetsOf(name).minOrNull()
        override fun offsetsOf(name: String) = if (withoutBtf && name in setOf("__start_BTF", "__stop_BTF"))
            emptyList() else names[name].orEmpty()
        override fun isSymbolStart(value: Int) = names.values.any { value in it }
        override fun nextOffset(offset: Int) = names.values.asSequence().flatten().filter { it > offset }.minOrNull()
    }
    private fun target(name: String, withoutBtf: Boolean): Pair<ByteArray, Symbols> {
        val directory = File("native-inputs/kernels/$name")
        val raw = File(directory, "Image").readBytes()
        val names = linkedMapOf<String, MutableList<Int>>()
        File(directory, "symbols.tsv").useLines { lines -> lines.forEach { line ->
            val parts = line.split('\t')
            if (parts.size == 3) parts[0].toIntOrNull()?.let { names.getOrPut(parts[2]) { arrayListOf() }.add(it) }
        } }
        return raw to Symbols(names, raw.size, withoutBtf)
    }
    private val members = setOf("cred.uid", "cred.euid", "cred.group_info", "group_info.usage", "cred.usage")
    private fun describe(raw: ByteArray, symbols: UltraKernelSymbols) = UltraKernelStructOffsets.describe(
        symbols, raw, setOf("task_struct.cred"), emptyMap(), members)
    private fun checked(layout: UltraKernelLayout, cred: Int, uid: Int, euid: Int, groups: Int, usageWidth: Int) {
        assertEquals(members + "task_struct.cred", layout.fields.keys)
        for ((name, offset, width) in listOf(Triple("task_struct.cred", cred, 8), Triple("cred.uid", uid, 4),
            Triple("cred.euid", euid, 4), Triple("cred.group_info", groups, 8), Triple("group_info.usage", 0, 4),
            Triple("cred.usage", 0, usageWidth))) {
            assertEquals(name, offset, layout.fields.getValue(name).offsetBytes)
            assertEquals(name, width, layout.fields.getValue(name).widthBytes)
        }
    }
    @Test fun a_actual_510_without_BTF_produces_subject_fields() {
        val (raw, symbols) = target("android12-5.10-9465fbb7", true)
        checked(describe(raw, symbols), 0x780, 4, 20, 0x90, 4)
    }
    @Test fun b_actual_66_code_without_BTF_produces_subject_fields() {
        val (raw, symbols) = target("android15-6.6-346d51ea", true)
        checked(describe(raw, symbols), 0x820, 8, 24, 0xa0, 8)
    }
    @Test fun z_actual_66_BTF_is_an_independent_final_oracle() {
        val (raw, symbols) = target("android15-6.6-346d51ea", false)
        val oracle = describe(raw, symbols)
        checked(oracle, 0x820, 8, 24, 0xa0, 8)
        assertTrue(oracle.fields.values.all { it.source == "btf" })
    }

    private fun mutated(name: String, mutation: (ByteArray, Symbols) -> Symbols = { _, symbols -> symbols },
        change: (ByteArray) -> Unit, reason: String = "STRUCT_") {
        val (raw, symbols) = target(name, true)
        change(raw)
        val error = assertThrows(UltraKernelGenerateException::class.java) { describe(raw, mutation(raw, symbols)) }
        assertTrue(error.detail, error.detail.contains(reason))
    }
    private fun word(raw: ByteArray, at: Int, value: Int) = UltraKernelA64.writeLe32(raw, at, value.toLong() and 0xffffffffL)
    @Test fun c_group_writeback_wrong_field_is_not_a_layout() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe741c, UltraKernelA64.le32Bits(raw, 0xe741c) + (1 shl 10)) },
        reason = "STRUCT_GROUP_SEQUENCE")
    @Test fun d_group_free_requires_the_same_old_object() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe7408, UltraKernelA64.NOP) }, reason = "STRUCT_GROUP_RELEASE")
    @Test fun e_exclusive_data_width_is_not_status_register_width() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe2784, UltraKernelA64.le32Bits(raw, 0xe2784) xor (1 shl 30)) },
        reason = "STRUCT_EXCLUSIVE_STORE")
    @Test fun f_nonzero_credential_count_guard_is_required() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe2750, UltraKernelA64.NOP) }, reason = "STRUCT_CRED_NONZERO_GUARD")
    @Test fun g_credential_put_requires_zero_assertion() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe2488, UltraKernelA64.NOP) }, reason = "STRUCT_CRED_ZERO_ASSERTION")
    @Test fun h_credential_return_must_be_the_incremented_object() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe279c, 0xaa1403e0.toInt()) }, reason = "STRUCT_CRED_RETURN")
    @Test fun i_LSE_compare_exchange_must_store_incremented_value() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe2760, UltraKernelA64.le32Bits(raw, 0xe2760) - 1) },
        reason = "STRUCT_COMPARE_EXCHANGE")
    @Test fun j_callback_is_proved_from_reachable_code() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0x10578a0, UltraKernelA64.le32Bits(raw, 0x10578a0) xor (1 shl 5)) },
        reason = "STRUCT_ALTERNATIVE_CALLBACK_WRITE")
    @Test fun k_unknown_reachable_instruction_keeps_a_specific_unknown() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe73ec, 0) }, reason = "STRUCT_INSTRUCTION_UNKNOWN")
    @Test fun l_all_same_name_subject_candidates_are_checked() = mutated("android15-6.6-346d51ea",
        mutation = { raw, symbols -> Symbols(symbols.names + ("__put_cred" to
            (symbols.names.getValue("__put_cred") + symbols.names.getValue("groups_alloc"))), raw.size, true) },
        change = {}, reason = "STRUCT_SUBJECT_CALL")
    @Test fun m_allocator_initializer_must_reach_returned_object() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe72e8, UltraKernelA64.NOP) }, reason = "STRUCT_ALLOCATION_INITIALIZER")
    @Test fun n_alternative_load_width_is_checked_independently() = mutated("android12-5.10-9465fbb7",
        change = { raw -> word(raw, 0x184888, UltraKernelA64.le32Bits(raw, 0x184888) xor (1 shl 30)) })

    @Test fun o_count_branch_cannot_test_only_low_word() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe2488, UltraKernelA64.le32Bits(raw, 0xe2488) xor (1 shl 31)) },
        reason = "STRUCT_BRANCH_WIDTH")
    @Test fun p_pointer_null_guard_requires_full_pointer_width() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe72d8, UltraKernelA64.le32Bits(raw, 0xe72d8) xor (1 shl 31)) },
        reason = "STRUCT_BRANCH_WIDTH")
    @Test fun q_ordinary_store_invalidates_a_prior_count_proof() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe24a8, 0xf900001f.toInt()) }, reason = "STRUCT_CRED_ZERO_ASSERTION")
    @Test fun r_unknown_call_does_not_preserve_subject_proofs() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe2798, UltraKernelA64.encodeBl(0xe2798, 0xe729c)) },
        reason = "STRUCT_SUBJECT_CALL")
    @Test fun s_null_only_same_name_allocator_is_not_silently_ignored() {
        val (raw, symbols) = target("android15-6.6-346d51ea", true)
        val other = symbols.names.getValue("__put_cred").single()
        word(raw, other, 0xd2800000.toInt()); word(raw, other + 4, UltraKernelA64.RET)
        val changed = Symbols(symbols.names + ("groups_alloc" to
            (symbols.names.getValue("groups_alloc") + other)), raw.size, true)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.describe(changed, raw, setOf("task_struct.cred"), emptyMap(), setOf("group_info.usage"))
        }
        assertTrue(error.detail, error.detail.contains("STRUCT_ALLOCATION_ANCHOR"))
    }

    @Test fun t_CAS_exclusive_comparison_requires_full_data_width() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe277c, UltraKernelA64.le32Bits(raw, 0xe277c) xor (1 shl 31)) },
        reason = "STRUCT_EXCLUSIVE_STORE")
    @Test fun u_CAS_LSE_comparison_requires_full_data_width() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe2764, UltraKernelA64.le32Bits(raw, 0xe2764) xor (1 shl 31)) },
        reason = "STRUCT_CRED_INCREMENT")

    @Test fun v_missing_STXR_retry_is_not_accepted_from_other_view() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe2788, UltraKernelA64.NOP) }, reason = "STRUCT_EXCLUSIVE_RETRY")
    @Test fun w_group_STXR_retry_must_test_the_written_status() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe7444, UltraKernelA64.le32Bits(raw, 0xe7444) - 1) },
        reason = "STRUCT_EXCLUSIVE_RETRY")
    @Test fun x_flag_clobber_does_not_inherit_prior_equality() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe2768, 0xeb28011f.toInt()) }, reason = "STRUCT_CRED_INCREMENT")
    @Test fun y_conditional_select_word_cannot_return_a_full_credential_pointer() = mutated("android15-6.6-346d51ea",
        change = { raw -> word(raw, 0xe279c, 0x1a930260) }, reason = "STRUCT_CRED_RETURN")
    @Test fun y1_conditional_select_full_width_keeps_the_same_credential_pointer() {
        val (raw, symbols) = target("android15-6.6-346d51ea", true)
        word(raw, 0xe279c, 0x9a930260.toInt())
        checked(describe(raw, symbols), 0x820, 8, 24, 0xa0, 8)
    }

    @Test fun y2_vmalloc_return_still_requires_the_group_initializer() {
        val (raw, symbols) = target("android12-5.10-9465fbb7", true)
        val renamed = Symbols(symbols.names - "__vmalloc_node" +
            ("__vmalloc" to symbols.names.getValue("__vmalloc_node")), raw.size, true)
        checked(describe(raw, renamed), 0x780, 4, 20, 0x90, 4)
        word(raw, 0x18c0d0, UltraKernelA64.NOP)
        val error = assertThrows(UltraKernelGenerateException::class.java) { describe(raw, renamed) }
        assertTrue(error.detail, error.detail.contains("STRUCT_ALLOCATION_INITIALIZER"))
    }

    @Test fun y3_vmalloc_similar_name_is_not_an_allocator() {
        val (raw, symbols) = target("android12-5.10-9465fbb7", true)
        val renamed = Symbols(symbols.names - "__vmalloc_node" +
            ("__vmalloc_unrelated" to symbols.names.getValue("__vmalloc_node")), raw.size, true)
        val error = assertThrows(UltraKernelGenerateException::class.java) { describe(raw, renamed) }
        assertTrue(error.detail, error.detail.contains("STRUCT_SUBJECT_CALL"))
    }

    /** Synthetic private names retain the target's real get_task_cred and release callee bodies. */
    private fun privateRelease(thunk: Boolean = true): Pair<ByteArray, Symbols> {
        val (raw, symbols) = target("android15-6.6-346d51ea", true)
        val start = symbols.names.getValue("__put_cred").single()
        val direct = symbols.names.getValue("put_cred_rcu").single()
        val wrapper = symbols.names.getValue("call_rcu").single()
        val call = wrapper + 20
        val delegate = call + (UltraKernelA64.signExtend(
            (UltraKernelA64.le32Bits(raw, call) and 0x03ffffff).toLong(), 26) * 4).toInt()
        val callback = if (thunk) symbols.names.getValue("groups_alloc").single() else direct
        val headRead = UltraKernelA64.le32Bits(raw, start + 48)
        word(raw, wrapper + 12, UltraKernelA64.NOP)
        word(raw, wrapper + 16, 0x2a1f03e2) // MOV W2,WZR: this delegated form has a third argument.
        val body = listOf(0xf9400008.toInt(),
            UltraKernelA64.encodeCbz(8, start + 4L, start + 48L, true, true), headRead,
            UltraKernelA64.encodeCbz(8, start + 12L, start + 24L, false, false),
            UltraKernelA64.encodeBl(start + 16L, direct.toLong()), UltraKernelA64.encodeB(start + 20L, start + 44L),
            UltraKernelA64.encodeAdrp(start + 24L, callback.toLong(), 1),
            0x91000021.toInt() or ((callback and 0xfff) shl 10), 0x2a1f03e2,
            UltraKernelA64.encodeBl(start + 36L, delegate.toLong()), UltraKernelA64.NOP, UltraKernelA64.RET,
            0xd4210000.toInt())
        body.forEachIndexed { index, instruction -> word(raw, start + index * 4, instruction) }
        if (thunk) word(raw, callback, UltraKernelA64.encodeB(callback.toLong(), direct.toLong()))
        val renamed = symbols.names - "put_cred_rcu" + ("private_release_fixture" to listOf(direct)) +
            if (thunk) mapOf("fixture_rcu_thunk" to listOf(callback), "fixture_rcu_thunk_end" to listOf(callback + 4)) else emptyMap()
        return raw to Symbols(renamed, raw.size, true)
    }
    private fun privateUsage(raw: ByteArray, symbols: Symbols) = UltraKernelStructOffsets.describe(
        symbols, raw, setOf("task_struct.cred"), mapOf("task_struct.cred" to 0x820), setOf("cred.usage"), null)
    private fun privateRejected(change: (ByteArray, Symbols) -> Unit) {
        val (raw, symbols) = privateRelease()
        change(raw, symbols)
        val error = assertThrows(UltraKernelGenerateException::class.java) { privateUsage(raw, symbols) }
        assertTrue(error.detail, error.detail.contains("STRUCT_SUBJECT_CALL") || error.detail.contains("STRUCT_CRED_RELEASE_CALL"))
    }
    @Test fun y4_private_release_is_the_same_rcu_callback_and_head() {
        for (thunk in listOf(false, true)) {
            val (raw, symbols) = privateRelease(thunk)
            val usage = privateUsage(raw, symbols).fields.getValue("cred.usage")
            assertEquals(0, usage.offsetBytes); assertEquals(8, usage.widthBytes)
        }
    }
    @Test fun y5_rcu_wrapper_must_forward_the_full_head_pointer() = privateRejected { raw, symbols ->
        word(raw, symbols.names.getValue("call_rcu").single() + 12, 0x2a0003e0) // MOV W0,W0.
    }
    @Test fun y6_rcu_wrapper_third_argument_is_not_assumed() = privateRejected { raw, symbols ->
        word(raw, symbols.names.getValue("call_rcu").single() + 16, 0x52800022) // MOV W2,#1.
    }
    @Test fun y7_private_direct_release_must_match_the_deferred_head() = privateRejected { raw, symbols ->
        val start = symbols.names.getValue("__put_cred").single()
        val call = start + 36
        val delegate = call + (UltraKernelA64.signExtend(
            (UltraKernelA64.le32Bits(raw, call) and 0x03ffffff).toLong(), 26) * 4).toInt()
        word(raw, call, 0x91002000.toInt()); word(raw, call + 4, UltraKernelA64.encodeBl(call + 4L, delegate.toLong()))
    }
    @Test fun y8_private_release_does_not_allow_other_calls_afterwards() = privateRejected { raw, symbols ->
        val at = symbols.names.getValue("__put_cred").single() + 40
        word(raw, at, UltraKernelA64.encodeBl(at.toLong(), symbols.names.getValue("get_task_cred").single().toLong()))
    }
    @Test fun y9_rcu_wrapper_cannot_have_multiple_delegates() = privateRejected { raw, symbols ->
        val at = symbols.names.getValue("call_rcu").single() + 12
        word(raw, at, UltraKernelA64.encodeBl(at.toLong(), symbols.names.getValue("get_task_cred").single().toLong()))
    }
    @Test fun ya_private_direct_release_must_match_the_callback() = privateRejected { raw, symbols ->
        val at = symbols.names.getValue("fixture_rcu_thunk").single()
        word(raw, at, UltraKernelA64.encodeB(at.toLong(), symbols.names.getValue("get_task_cred").single().toLong()))
    }
    @Test fun yb_rcu_wrapper_must_forward_the_callback_pointer() = privateRejected { raw, symbols ->
        word(raw, symbols.names.getValue("call_rcu").single() + 12, 0xaa0003e1.toInt()) // MOV X1,X0.
    }

    /** Keep the real set_groups proof; replace only the allocator with an unknown-CPU table loop. */
    private fun cpuGroups(): Pair<ByteArray, Symbols> {
        val (raw, symbols) = target("android12-5.10-9465fbb7", true)
        val start = symbols.names.getValue("groups_alloc").single()
        val table = symbols.names.getValue("__put_cred").single()
        val allocator = symbols.names.getValue("__vmalloc_node").single()
        val body = listOf(UltraKernelA64.movz(9, 1, sf = 0), 0xd5380009.toInt(),
            UltraKernelA64.encodeAdr(start + 8L, table.toLong(), 11), UltraKernelA64.ldImm("ldr", 12, 11, 0, 4),
            UltraKernelA64.encodeCbz(12, start + 16L, start + 60L, false, false), 0x6b0c013f,
            UltraKernelA64.encodeBCond(1, start + 24L, start + 32L),
            UltraKernelA64.encodeB(start + 28L, start + 40L), 0x9100316b.toInt(),
            UltraKernelA64.encodeB(start + 36L, start + 12L),
            UltraKernelA64.encodeBl(start + 40L, allocator.toLong()),
            UltraKernelA64.encodeCbz(0, start + 44L, start + 76L, true, false), UltraKernelA64.movz(8, 1, sf = 0),
            UltraKernelA64.ldImm("str", 8, 0, 0, 4), UltraKernelA64.encodeB(start + 56L, start + 76L),
            UltraKernelA64.encodeBl(start + 60L, allocator.toLong()),
            UltraKernelA64.encodeCbz(0, start + 64L, start + 76L, true, false), UltraKernelA64.movz(8, 1, sf = 0),
            UltraKernelA64.ldImm("str", 8, 0, 0, 4), UltraKernelA64.RET)
        body.forEachIndexed { index, instruction -> word(raw, start + index * 4, instruction) }
        listOf(1, 0, 0, 2, 0, 0, 0, 0, 0).forEachIndexed { index, value -> word(raw, table + index * 4, value) }
        return raw to Symbols(symbols.names + mapOf("fixture_cpu_table" to listOf(table),
            "fixture_cpu_table_end" to listOf(table + 36), "__start_rodata" to listOf(table),
            "__end_rodata" to listOf(table + 36)), raw.size, true)
    }
    private fun cpuLayout(raw: ByteArray, symbols: Symbols) = UltraKernelStructOffsets.describe(
        symbols, raw, setOf("task_struct.cred"), mapOf("task_struct.cred" to 0x780), setOf("group_info.usage"), null)
    private fun cpuRejected(reason: String, mutate: (ByteArray, Symbols) -> Symbols) {
        val (raw, symbols) = cpuGroups()
        val changed = mutate(raw, symbols)
        val error = assertThrows(UltraKernelGenerateException::class.java) { cpuLayout(raw, changed) }
        assertTrue(error.detail, error.detail.contains(reason))
    }
    @Test fun yc_runtime_MIDR_walks_every_table_outcome() {
        val (raw, symbols) = cpuGroups()
        val usage = cpuLayout(raw, symbols).fields.getValue("group_info.usage")
        assertEquals(0, usage.offsetBytes); assertEquals(4, usage.widthBytes)
    }
    @Test fun yd_runtime_MIDR_does_not_hide_the_nonmatching_initializer() = cpuRejected("STRUCT_ALLOCATION_INITIALIZER") { raw, s ->
        word(raw, s.names.getValue("groups_alloc").single() + 72, UltraKernelA64.NOP); s
    }
    @Test fun ye_runtime_MIDR_does_not_hide_the_matching_initializer() = cpuRejected("STRUCT_ALLOCATION_INITIALIZER") { raw, s ->
        word(raw, s.names.getValue("groups_alloc").single() + 52, UltraKernelA64.NOP); s
    }
    @Test fun yf_CPU_table_cannot_read_into_the_next_component() = cpuRejected("STRUCT_READONLY_BOUNDS") { _, s ->
        val table = s.names.getValue("fixture_cpu_table").single()
        Symbols(s.names + ("fixture_next_component" to listOf(table + 12)), s.imageSize, true)
    }
    @Test fun yg_CPU_table_without_a_terminator_is_bounded() = cpuRejected("STRUCT_READONLY_BOUNDS") { raw, s ->
        word(raw, s.names.getValue("fixture_cpu_table").single() + 24, 3); s
    }
    @Test fun yh_CPU_table_requires_rodata() = cpuRejected("STRUCT_READONLY_RODATA") { _, s ->
        Symbols(s.names - "__start_rodata", s.imageSize, true)
    }
    @Test fun yi_CPU_table_write_invalidates_immutable_data() = cpuRejected("STRUCT_READONLY_WRITE") { raw, s ->
        word(raw, s.names.getValue("groups_alloc").single() + 12, UltraKernelA64.ldImm("str", 31, 11, 0, 4)); s
    }
    @Test fun yj_other_system_registers_stay_unknown_instructions() = cpuRejected("STRUCT_INSTRUCTION_UNKNOWN") { raw, s ->
        word(raw, s.names.getValue("groups_alloc").single() + 4, 0xd53800a9.toInt()); s
    }
    @Test fun yk_CPU_table_pointer_truncation_stays_unknown() = cpuRejected("STRUCT_READONLY_ADDRESS") { raw, s ->
        word(raw, s.names.getValue("groups_alloc").single() + 8, 0x2a0b03eb); s // MOV W11,W11.
    }
    @Test fun yl_CPU_table_pair_write_invalidates_immutable_data() = cpuRejected("STRUCT_READONLY_WRITE") { raw, s ->
        word(raw, s.names.getValue("groups_alloc").single() + 12, UltraKernelA64.pair("stp", 31, 31, 11, 0, true, 2)); s
    }
    @Test fun ym_CPU_table_path_does_not_skip_unknown_calls() = cpuRejected("STRUCT_SUBJECT_CALL") { raw, s ->
        val at = s.names.getValue("groups_alloc").single() + 60
        word(raw, at, UltraKernelA64.encodeBl(at.toLong(), s.names.getValue("get_task_cred").single().toLong())); s
    }
    @Test fun yn_CPU_table_arithmetic_does_not_wrap_into_the_original_component() = cpuRejected("STRUCT_READONLY_BOUNDS") { raw, s ->
        val start = s.names.getValue("groups_alloc").single()
        val table = s.names.getValue("fixture_cpu_table").single()
        val allocator = s.names.getValue("__vmalloc_node").single()
        // 512 real ADD-immediate executions add 2^32; a truncated pointer would re-enter the table.
        val body = listOf(UltraKernelA64.encodeAdr(start.toLong(), table.toLong(), 11),
            UltraKernelA64.ldImm("ldr", 12, 11, 0, 4), UltraKernelA64.movz(13, 512, sf = 0),
            0x9160016b.toInt(), 0x710005ad, UltraKernelA64.encodeBCond(1, start + 20L, start + 12L),
            UltraKernelA64.ldImm("ldr", 12, 11, 0, 4), UltraKernelA64.encodeBl(start + 28L, allocator.toLong()),
            UltraKernelA64.encodeCbz(0, start + 32L, start + 48L, true, false), UltraKernelA64.movz(8, 1, sf = 0),
            UltraKernelA64.ldImm("str", 8, 0, 0, 4), UltraKernelA64.RET, UltraKernelA64.RET)
        body.forEachIndexed { index, instruction -> word(raw, start + index * 4, instruction) }; s
    }
}
