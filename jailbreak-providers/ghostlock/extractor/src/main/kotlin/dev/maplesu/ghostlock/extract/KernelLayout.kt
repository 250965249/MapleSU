package dev.maplesu.ghostlock.extract

/**
 * Kernel geometry derivation and `--format conf` rendering.
 *
 * Port of GhostLock-App `tools/extract_rs/src/symbols.rs`, `report.rs` and the
 * route-suggestion half of `analysis.rs` (Apache-2.0, commit 437b3b2).
 *
 * Scope note (documented in the handover report): the reference additionally
 * derives two values by disassembling the image (`pselect_waiter_shift` from the
 * pselect/futex stack chain, `off_slide_loggers_0_1` from the nf_logger
 * registration). This port uses the reference's *own* fallbacks for both - the
 * verified-family table and the `loggers + 0x10` symbol heuristic - which the
 * reference also falls back to when disassembly is unavailable. Everything else
 * (symbol offsets from kallsyms, struct offsets from BTF, route selection from
 * probed paths, credential/KernelSnitch constants, field order and `null`
 * rendering) is the reference's logic verbatim.
 */
object KernelLayout {
    /** symbol key -> kallsyms name, exactly as `SYMBOLS`. */
    val SYMBOLS: List<Pair<String, String>> = listOf(
        "off_init_task" to "init_task",
        "off_init_cred" to "init_cred",
        "off_root_task_group" to "root_task_group",
        "off_selinux_enforcing" to "selinux_state",
        "off_selinux_blob_sizes" to "selinux_blob_sizes",
        "off_security_hook_heads" to "security_hook_heads",
        "off_slide_nfulnl_logger" to "nfulnl_logger",
        "off_slide_boot_id" to "sysctl_bootid",
    )

    /** Unresolved optionals emit 0 and the runtime falls back to target.h defaults. */
    val OPTIONAL_SYMBOLS: Set<String> = setOf("off_security_hook_heads")

    /** struct name -> (macro key, BTF field name). */
    val STRUCT_FIELDS: List<Pair<String, List<Pair<String, String>>>> = listOf(
        "task_struct" to listOf(
            "task_prio" to "prio",
            "task_normal_prio" to "normal_prio",
            "task_sched_task_group" to "sched_task_group",
            "task_pi_lock" to "pi_lock",
            "task_pi_waiters" to "pi_waiters",
            "task_pi_top_task" to "pi_top_task",
            "task_pi_blocked_on" to "pi_blocked_on",
            "task_pid" to "pid",
            "task_tgid" to "tgid",
            "task_atomic_flags" to "atomic_flags",
            "task_real_cred" to "real_cred",
            "task_cred" to "cred",
            "task_comm" to "comm",
            "task_tasks" to "tasks",
            "task_seccomp" to "seccomp",
        ),
        "rt_mutex_waiter" to listOf(
            "waiter_tree" to "tree",
            "waiter_pi_tree" to "pi_tree",
            "waiter_task" to "task",
            "waiter_lock" to "lock",
            "waiter_wake_state" to "wake_state",
            "waiter_ww_ctx" to "ww_ctx",
            "waiter_tree" to "tree_entry",
            "waiter_pi_tree" to "pi_tree_entry",
        ),
        "cred" to listOf(
            "cred_uid" to "uid",
            "cred_securebits" to "securebits",
            "cred_caps" to "cap_inheritable",
            "cred_security" to "security",
        ),
        "seccomp" to listOf(
            "seccomp_mode" to "mode",
            "seccomp_filter_count" to "filter_count",
            "seccomp_filter" to "filter",
        ),
    )

    /** Layout template selector for a release series (not proof of verification). */
    fun kernelStructMacro(release: String?): String? {
        if (release == null) return null
        val parts = release.split('.')
        val major = parts.getOrNull(0)?.toIntOrNull() ?: return null
        val minor = parts.getOrNull(1)?.toIntOrNull() ?: return null
        return when (major to minor) {
            // 6.1 android14 builds use the flat compact-waiter layout.
            6 to 1 -> "STRUCT_OFFSETS_6_1"
            6 to 6 -> "STRUCT_OFFSETS_6_6"
            6 to 12 -> "STRUCT_OFFSETS_6_12"
            else -> null
        }
    }

    /**
     * Whether this release belongs to a layout family with retained verification
     * evidence: `android14-6.1`, `android15-6.6`, `android16-6.12`,
     * `android13-5.15`. A mere `major.minor` match is not verified.
     */
    fun kernelLayoutVerified(release: String?): Boolean {
        if (release == null) return false
        val parts = release.split('.')
        val major = parts.getOrNull(0)?.toIntOrNull() ?: return false
        val minor = parts.getOrNull(1)?.toIntOrNull() ?: return false
        return when (major to minor) {
            6 to 1 -> release.contains("-android14-")
            6 to 6 -> release.contains("-android15-")
            6 to 12 -> release.contains("-android16-")
            5 to 15 -> release.contains("-android13-")
            else -> false
        }
    }

    /**
     * The reference's verified-family fallback for `pselect_waiter_shift`
     * (`report::pselect_waiter_shift_for`), used when image-specific
     * disassembly derivation is unavailable.
     */
    fun pselectWaiterShiftFor(release: String?): Int? {
        if (!kernelLayoutVerified(release)) return null
        return when (kernelStructMacro(release)) {
            "STRUCT_OFFSETS_6_12" -> 0
            // android14-6.1 compiles its fd_set words one qword later than 6.6;
            // the committed tables all measure 1.
            "STRUCT_OFFSETS_6_1" -> 1
            "STRUCT_OFFSETS_6_6" -> -2
            else -> null
        }
    }

    /** `symbols` -> resolved image offsets (absolute address minus [base]). */
    fun resolveSymbols(symbols: Kallsyms, base: Long): Map<String, Long?> {
        val result = LinkedHashMap<String, Long?>()
        for ((key, name) in SYMBOLS) result[key] = symbols.unique(name)
        result["off_slide_loggers_0_1"] = symbols.unique("loggers")?.let { it + 0x10 }
        for (key in result.keys.toList()) {
            result[key] = result[key]?.minus(base)
        }
        return result
    }

    /** `struct_fields` -> offsets; alias entries never clobber a resolved value. */
    fun resolveStructs(btf: Btf?): Map<String, Int?> {
        val result = LinkedHashMap<String, Int?>()
        if (btf == null) {
            for ((_, fields) in STRUCT_FIELDS) for ((key, _) in fields) result[key] = null
            result["struct_page_size"] = null
            result["struct_page_compound_head"] = null
            result["struct_page_type"] = null
            result["struct_slab_cache"] = null
            result["struct_mm_struct"] = null
            return result
        }
        for ((structName, fields) in STRUCT_FIELDS) {
            if (btf.namedStruct(structName) == null) {
                for ((key, _) in fields) result[key] = null
                continue
            }
            for ((key, fieldName) in fields) {
                val value = btf.field(structName, fieldName)
                val old = result[key]
                result[key] = if (old != null && value == null) old else value
            }
        }
        result["struct_page_size"] = btf.size("page")
        result["struct_page_compound_head"] = btf.field("page", "compound_head")
        result["struct_page_type"] = btf.field("page", "page_type")
        result["struct_slab_cache"] = btf.field("slab", "slab_cache")
        result["struct_mm_struct"] = btf.size("mm_struct")
        return result
    }

    /** One route path probe, mirroring `analysis::PathCandidate`. */
    class PathCandidate(
        val route: String,
        val probes: List<Pair<String, Long?>>,
        val available: Boolean,
    )

    /**
     * Probes the three route paths like `analysis::probe_paths`.
     *
     * Limitation: the reference also accepts `tcp_zerocopy_receive` inlined into
     * the option handler, which it proves by disassembling `do_tcp_getsockopt`;
     * this port only probes the exact symbol. That difference can only make the
     * probe *more* conservative (no path inferred), never invent one.
     */
    fun probePaths(symbols: Kallsyms): List<PathCandidate> {
        fun probe(exact: String, fragments: List<String> = emptyList()): Long? =
            symbols.findFunction(exact, fragments)

        fun build(route: String, probes: List<Pair<String, Long?>>, requireAll: Boolean): PathCandidate {
            val available = if (requireAll) probes.all { it.second != null } else probes.any { it.second != null }
            return PathCandidate(route, probes, available)
        }
        val paths = listOf(
            build(
                "select_stack",
                listOf(
                    "core_sys_select" to probe("core_sys_select", listOf("core_sys_select")),
                    "futex_wait" to probe("futex_wait", listOf("futex_wait")),
                ),
                true,
            ),
            build(
                "tcp_zerocopy",
                listOf("tcp_zerocopy_receive" to probe("tcp_zerocopy_receive", listOf("zerocopy_receive"))),
                false,
            ),
            build(
                "multicast_waiter",
                listOf(
                    "ip_mc_msfadd" to probe("ip_mc_msfadd", listOf("ip_mc_msfadd")),
                    "ip_mc_source" to probe("ip_mc_source", listOf("ip_mc_source")),
                ),
                false,
            ),
        )
        return paths.sortedBy { it.route }
    }

    /** The route a profile should select from kernel evidence alone. */
    fun suggestRoute(
        pselectDerived: Boolean,
        paths: List<PathCandidate>,
        release: String?,
    ): String? {
        val parts = release?.split('.')
        val major = parts?.getOrNull(0)?.toIntOrNull()
        val minor = parts?.getOrNull(1)?.toIntOrNull()
        val family = kernelStructMacro(release).takeIf { kernelLayoutVerified(release) }
        fun available(route: String): Boolean = paths.any { it.route == route && it.available }
        if (pselectDerived) return "select_stack"
        if (major == 5 && available("multicast_waiter")) return "multicast_waiter"
        if (major == 6 && minor == 1 && available("tcp_zerocopy")) return "tcp_zerocopy"
        return when (family) {
            "STRUCT_OFFSETS_6_6", "STRUCT_OFFSETS_6_12" -> "select_stack"
            "STRUCT_OFFSETS_6_1" -> "tcp_zerocopy"
            else -> null
        }
    }

    /** Routes whose layout is only meaningful when the pselect geometry was derived. */
    fun routeDependsOnPselectLayout(route: String): Boolean = route == "select_stack"

    /** Full route field universe per branch (`CONF_ROUTE_FIELDS`). */
    val CONF_ROUTE_FIELDS: Map<String, List<String>> = linkedMapOf(
        "tcp_zerocopy" to listOf("compact_waiter"),
        "select_stack" to listOf("waiter_shift"),
        "multicast_waiter" to listOf("waiter_off", "buffer_size", "task_offset", "lock_offset", "compact_waiter"),
    )

    /** Full credential field universe (`CONF_CRED_FIELDS`). */
    val CONF_CRED_FIELDS: List<String> = listOf(
        "copy_size", "usage_offset", "usage_value", "caps_offset", "caps_count", "caps_value",
        "ref_count", "ref0_offset", "ref1_offset", "ref2_offset", "ref3_offset",
        "ref0_image", "ref1_image", "ref2_image", "ref3_image",
    )

    /** Full offset field universe (`CONF_OFFSET_FIELDS`). */
    val CONF_OFFSET_FIELDS: List<String> = listOf(
        "init_task", "init_cred", "empty_zero_page", "root_task_group", "selinux_enforcing",
        "selinux_blob_sizes", "security_hook_heads", "slide_nfulnl_logger",
        "slide_loggers_0_1", "slide_boot_id",
    )

    /** `task_struct` keys in the bundled profiles' order. */
    val CONF_TASK_FIELDS: List<Pair<String, String>> = listOf(
        "task_prio" to "prio",
        "task_normal_prio" to "normal_prio",
        "task_sched_task_group" to "sched_task_group",
        "task_pi_lock" to "pi_lock",
        "task_pi_waiters" to "pi_waiters",
        "task_pi_top_task" to "pi_top_task",
        "task_pi_blocked_on" to "pi_blocked_on",
        "task_pid" to "pid",
        "task_tgid" to "tgid",
        "task_atomic_flags" to "atomic_flags",
        "task_real_cred" to "real_cred",
        "task_cred" to "cred",
        "task_comm" to "comm",
        "task_tasks" to "tasks",
        "task_seccomp" to "seccomp",
    )

    /** Shared 6.x credential template, in the bundled order. */
    fun confCred6x(): List<Pair<String, String>> = listOf(
        "caps_offset" to "48",
        "copy_size" to "136",
        "usage_value" to "1",
        "caps_count" to "5",
        "caps_value" to "-1",
    )

    /**
     * The selected route's branch geometry, or an empty list when the extractor
     * cannot derive a layout for it (the missing fields then render as `null`).
     */
    fun confRouteGeometry(
        route: String,
        release: String,
        pselectShift: Int?,
        structs: Map<String, Int?>,
    ): List<Pair<String, String>> {
        val major = release.split('.').firstOrNull()?.toIntOrNull()
        return when (route) {
            "select_stack" -> pselectShift?.let { listOf("waiter_shift" to it.toString()) } ?: emptyList()
            // android14-6.1 is the compact-waiter family; no other family has a
            // measured tcp layout.
            "tcp_zerocopy" -> if (kernelLayoutVerified(release) &&
                kernelStructMacro(release) == "STRUCT_OFFSETS_6_1"
            ) listOf("compact_waiter" to "1") else emptyList()
            // The 5.x multicast branch runs from the train-proven constants
            // (waiter_off/buffer_size) plus BTF-derived rt_mutex_waiter
            // task/lock offsets, which is also the reference's fallback when its
            // static waiter_off derivation fails ("keeping the proven 5.x
            // constant"). The reference's disassembly refinement of waiter_off
            // is the one value this port does not recompute; the constant it
            // falls back to is emitted unchanged.
            "multicast_waiter" -> if (major == 5) {
                buildList {
                    add("waiter_off" to "96")
                    add("buffer_size" to "264")
                    structs["waiter_task"]?.let { add("task_offset" to it.toString()) }
                    structs["waiter_lock"]?.let { add("lock_offset" to it.toString()) }
                    add("compact_waiter" to "1")
                }
            } else emptyList()
            else -> emptyList()
        }
    }

    /** Everything `renderConf` writes, in one bundle. */
    class ConfInputs(
        val release: String,
        val phys: Long?,
        /** DRAM base / linear-map PHYS_OFFSET; normally supplied by hand. */
        val physOffset: Long?,
        val symbols: Map<String, Long?>,
        val structs: Map<String, Int?>,
        val route: String?,
        val routeGeometry: List<Pair<String, String>>,
        val cred: List<Pair<String, String>>,
        val emptyZeroPage: Long?,
    )

    private fun confLookup(entries: List<Pair<String, String>>, key: String): String =
        entries.firstOrNull { it.first == key }?.second ?: "null"

    private fun pushConfBlock(lines: MutableList<String>, name: String, entries: List<Pair<String, String>>) {
        if (entries.isEmpty()) return
        lines.add("$name {")
        for ((key, value) in entries) lines.add("  $key = $value")
        lines.add("}")
    }

    /** `offset` keys in the bundled profiles' order; `empty_zero_page` comes from kallsyms. */
    private fun confOffsets(symbols: Map<String, Long?>, emptyZeroPage: Long?): List<Pair<String, String>> {
        fun symbol(key: String): String? = symbols[key]?.toString()
        return listOfNotNull(
            symbol("off_init_task")?.let { "init_task" to it },
            symbol("off_init_cred")?.let { "init_cred" to it },
            emptyZeroPage?.let { "empty_zero_page" to it.toString() },
            symbol("off_root_task_group")?.let { "root_task_group" to it },
            symbol("off_selinux_enforcing")?.let { "selinux_enforcing" to it },
            symbol("off_selinux_blob_sizes")?.let { "selinux_blob_sizes" to it },
            symbol("off_security_hook_heads")?.let { "security_hook_heads" to it },
            symbol("off_slide_nfulnl_logger")?.let { "slide_nfulnl_logger" to it },
            symbol("off_slide_boot_id")?.let { "slide_boot_id" to it },
            symbol("off_slide_loggers_0_1")?.let { "slide_loggers_0_1" to it },
        )
    }

    /**
     * Renders a flattened, self-contained GLK profile (`--format conf`): no
     * `include` lines, the shared 6.x credential and KernelSnitch constants
     * inlined, keys and nesting matching `app/src/main/assets/kernel_profiles/`.
     * Fields without a derived value are written as `null` so the app reports
     * them as invalid paths before execution.
     */
    fun renderConf(input: ConfInputs): String {
        val release = input.release
        val major = release.split('.').firstOrNull()?.toIntOrNull()
        val lines = ArrayList<String>()
        lines.add("# GhostLock kernel profile: $release (HOCON, self-contained).")
        lines.add("release = \"$release\"")
        lines.add("schema_version = 1")
        lines.add("kernel_major = ${major ?: 0}")
        lines.add("recommend_shizuku = 0")
        lines.add(if (input.phys != null) "kernel_phys_load = ${input.phys}" else "kernel_phys_load = null")
        lines.add(
            if (input.physOffset != null) "kernel_phys_offset = ${input.physOffset}"
            else "kernel_phys_offset = null")
        input.route?.let { route ->
            lines.add("route {")
            lines.add("  $route {")
            val fields = CONF_ROUTE_FIELDS[route]
            if (fields != null) {
                for (field in fields) {
                    val value = input.routeGeometry.firstOrNull { it.first == field }?.second ?: "null"
                    lines.add("    $field = $value")
                }
            } else {
                for ((key, value) in input.routeGeometry) lines.add("    $key = $value")
            }
            lines.add("  }")
            lines.add("}")
        }
        pushConfBlock(lines, "fallback", listOf("to" to "\"none\""))
        // KernelSnitch: full universe. `collisions` is emitted for a verified
        // train (and every 5.x kernel); `mm_struct_sz` only where it applies.
        val snitch = ArrayList<Pair<String, String>>()
        if (kernelLayoutVerified(release) || major == 5) {
            when (major) {
                6 -> {
                    snitch.add("collisions" to "4")
                    if (kernelStructMacro(release) == "STRUCT_OFFSETS_6_1") {
                        snitch.add("mm_struct_sz" to "1024")
                    }
                }
                5 -> {
                    snitch.add("collisions" to "8")
                    snitch.add("mm_struct_sz" to "1024")
                }
            }
        }
        pushConfBlock(
            lines,
            "kernelsnitch",
            listOf(
                "collisions" to confLookup(snitch, "collisions"),
                "mm_struct_sz" to confLookup(snitch, "mm_struct_sz"),
            ),
        )
        val task = CONF_TASK_FIELDS.map { (macroName, key) ->
            key to (input.structs[macroName]?.toString() ?: "null")
        }
        pushConfBlock(lines, "task_struct", task)
        val cred = CONF_CRED_FIELDS.map { key -> key to confLookup(input.cred, key) }
        pushConfBlock(lines, "cred", cred)
        val offsetEntries = confOffsets(input.symbols, input.emptyZeroPage)
        val offset = CONF_OFFSET_FIELDS.map { key -> key to confLookup(offsetEntries, key) }
        pushConfBlock(lines, "offset", offset)
        return lines.joinToString("\n") + "\n"
    }
}
