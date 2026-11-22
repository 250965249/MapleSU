package dev.maplesu.ghostlock.extract

import com.ghostlock.app.data.ValueMap
import com.ghostlock.app.data.asValueMap
import com.ghostlock.app.data.mutableChild
import com.ghostlock.app.data.valueMapOf

/**
 * Converts remote/main-era `offsets.json` (v1) entries into the current v2
 * layout, and normalises the local transition formats.
 *
 * Port of GhostLock-App `app/src/main/kotlin/com/ghostlock/app/data/
 * LegacyProfileConverter.kt` (Apache-2.0, commit 437b3b2). The conversion is
 * idempotent; it never invents geometry other than the two shared 6.x templates
 * the reference also seeds (`credential-6x.conf`, `kernelsnitch-6x.conf`).
 *
 * Multicast (a newer route) is intentionally unsupported here: `remote/main`-era
 * documents never selected it. That matches the reference exactly.
 */
object LegacyOffsetsConverter {
    private val METADATA_KEYS = listOf("kimage_text_base", "btf_size", "kallsyms")

    private val TASK_STRUCT_FIELDS = setOf(
        "prio", "normal_prio", "sched_task_group", "pi_lock", "pi_waiters",
        "pi_top_task", "pi_blocked_on", "pid", "tgid", "atomic_flags",
        "real_cred", "cred", "comm", "tasks", "seccomp",
    )
    private val CRED_FIELDS = setOf(
        "copy_size", "usage_offset", "usage_value", "caps_offset", "caps_count",
        "caps_value", "ref_count", "ref0_offset", "ref1_offset", "ref2_offset",
        "ref3_offset", "ref0_image", "ref1_image", "ref2_image", "ref3_image",
    )
    private val OFFSET_FIELDS = setOf(
        "init_task", "init_cred", "root_task_group", "selinux_enforcing",
        "selinux_blob_sizes", "security_hook_heads", "slide_nfulnl_logger",
        "slide_loggers_0_1", "slide_boot_id",
    )

    private interface LegacyRouteCodec {
        fun fillBranch(entry: ValueMap, branch: ValueMap)
        fun fillFallback(entry: ValueMap, branch: ValueMap)
    }

    private object TcpRouteCodec : LegacyRouteCodec {
        override fun fillBranch(entry: ValueMap, branch: ValueMap) =
            moveKey(entry, branch, "compact_waiter", "compact_waiter")

        override fun fillFallback(entry: ValueMap, branch: ValueMap) =
            moveKey(entry, branch, "compact_waiter", "compact_waiter")
    }

    private object SelectRouteCodec : LegacyRouteCodec {
        override fun fillBranch(entry: ValueMap, branch: ValueMap) =
            moveKey(entry, branch, "pselect_waiter_shift", "waiter_shift")

        override fun fillFallback(entry: ValueMap, branch: ValueMap) =
            moveKey(entry, branch, "pselect_waiter_shift", "waiter_shift")
    }

    private val ROUTE_CODECS: Map<String, LegacyRouteCodec> = mapOf(
        "tcp_zerocopy" to TcpRouteCodec,
        "select_stack" to SelectRouteCodec,
    )

    /** Values `credential-6x.conf` / `kernelsnitch-6x.conf` carry. */
    private val CRED_DEFAULTS_6X = valueMapOf(
        "caps_offset" to 48L,
        "copy_size" to 136L,
        "usage_value" to 1L,
        "caps_count" to 5L,
        "caps_value" to -1L,
    )
    private val KERNELSNITCH_DEFAULTS_6X = valueMapOf("collisions" to 4L)

    private fun moveKey(source: ValueMap, target: ValueMap, from: String, to: String) {
        if (source.containsKey(from) && source[from] != null && !target.containsKey(to)) {
            target[to] = source[from]
        }
        source.remove(from)
    }

    /** True when [entry] is a v1 document (no `schema_version`). */
    fun isLegacy(entry: ValueMap): Boolean = !entry.containsKey("schema_version")

    /** Converts [entry] in place (the same contract as the reference). */
    fun convertValue(entry: ValueMap?): ValueMap? {
        if (entry == null) return null
        val legacy = isLegacy(entry)
        METADATA_KEYS.forEach(entry::remove)
        moveFlatNamespaces(entry)
        moveSymbolGroups(entry)
        moveKernelsnitch(entry)
        if (legacy && entry.containsKey("release")) {
            if (!entry.containsKey("kernel_major")) entry["kernel_major"] = 6L
        }
        moveRouteLayout(entry)
        moveFallback(entry)
        dropEmptyRouteBranches(entry)
        if (legacy) applySharedDefaults(entry)
        return entry
    }

    private fun applySharedDefaults(entry: ValueMap) {
        if (!entry.containsKey("release")) return
        if ((entry["kernel_major"] as? Number)?.toLong() != 6L) return
        fillMissing(entry, "cred", CRED_DEFAULTS_6X)
        fillMissing(entry, "kernelsnitch", KERNELSNITCH_DEFAULTS_6X)
    }

    private fun fillMissing(entry: ValueMap, namespace: String, defaults: Map<String, Any?>) {
        val target = entry.mutableChild(namespace)
        for ((field, value) in defaults) if (!target.containsKey(field)) target[field] = value
    }

    private fun dropEmptyRouteBranches(entry: ValueMap) {
        entry["route"].asValueMap()?.let { route ->
            route.keys.toList()
                .filter { key -> route[key].asValueMap()?.isEmpty() == true }
                .forEach(route::remove)
            if (route.isEmpty()) entry.remove("route")
        }
        entry["fallback"].asValueMap()?.get("route").asValueMap()?.let { route ->
            route.keys.toList()
                .filter { key -> route[key].asValueMap()?.isEmpty() == true }
                .forEach(route::remove)
            if (route.isEmpty()) entry["fallback"].asValueMap()?.remove("route")
        }
    }

    private fun moveSymbolGroups(entry: ValueMap) {
        moveGroup(entry, "symbols", "offset", "off_", OFFSET_FIELDS)
        moveGroup(entry, "struct_fields", "task_struct", "task_", TASK_STRUCT_FIELDS)
        moveGroup(entry, "struct_fields", "cred", "cred_", CRED_FIELDS)
        val structFields = entry["struct_fields"].asValueMap() ?: return
        val snitch = entry.mutableChild("kernelsnitch")
        moveKey(structFields, snitch, "kernelsnitch_collisions", "collisions")
        moveKey(structFields, snitch, "mm_struct_sz", "mm_struct_sz")
        if (snitch.isEmpty()) entry.remove("kernelsnitch")
        if (structFields.isEmpty()) entry.remove("struct_fields")
    }

    private fun moveGroup(
        entry: ValueMap,
        groupName: String,
        namespace: String,
        prefix: String,
        allowed: Set<String>,
    ) {
        val group = entry[groupName].asValueMap() ?: return
        val matching = group.keys.filter { it.startsWith(prefix) && it.removePrefix(prefix) in allowed }
        if (matching.isEmpty()) return
        val target = entry.mutableChild(namespace)
        for (key in matching) {
            val field = key.removePrefix(prefix)
            if (!target.containsKey(field)) target[field] = group[key]
            group.remove(key)
        }
        if (group.isEmpty()) entry.remove(groupName)
    }

    private fun moveFlatNamespaces(entry: ValueMap) {
        val namespaces = listOf(
            Triple("task_struct", "task_", TASK_STRUCT_FIELDS),
            Triple("cred", "cred_", CRED_FIELDS),
            Triple("offset", "off_", OFFSET_FIELDS),
        )
        for ((namespace, flatPrefix, allowed) in namespaces) {
            val keys = entry.keys.filter { it.startsWith(flatPrefix) && it.removePrefix(flatPrefix) in allowed }
            if (keys.isEmpty()) continue
            val nested = entry.mutableChild(namespace)
            for (key in keys) {
                val field = key.removePrefix(flatPrefix)
                if (!nested.containsKey(field)) nested[field] = entry[key]
                entry.remove(key)
            }
        }
        for ((legacy, current) in listOf("task" to "task_struct", "off" to "offset")) {
            val legacyObject = entry[legacy].asValueMap() ?: continue
            val target = entry.mutableChild(current)
            legacyObject.forEach { (field, value) -> if (!target.containsKey(field)) target[field] = value }
            entry.remove(legacy)
        }
    }

    private fun moveKernelsnitch(entry: ValueMap) {
        val hasFlat = entry.containsKey("kernelsnitch_collisions") || entry.containsKey("mm_struct_sz")
        if (!hasFlat) return
        val nested = entry.mutableChild("kernelsnitch")
        moveKey(entry, nested, "kernelsnitch_collisions", "collisions")
        moveKey(entry, nested, "mm_struct_sz", "mm_struct_sz")
        if (nested.isEmpty()) entry.remove("kernelsnitch")
    }

    private fun moveRouteLayout(entry: ValueMap) {
        fun fillBranch(name: String, branch: ValueMap) {
            ROUTE_CODECS[name]?.fillBranch(entry, branch)
        }
        when (val route = entry["route"]) {
            is String -> {
                val branch = valueMapOf()
                fillBranch(route, branch)
                entry["route"] = valueMapOf(route to branch)
            }

            is Map<*, *> -> Unit

            else -> if (entry.containsKey("release")) {
                val inferred = inferRoute(entry)
                val branch = valueMapOf()
                fillBranch(inferred, branch)
                entry["route"] = valueMapOf(inferred to branch)
            }
        }
    }

    private fun moveFallback(entry: ValueMap) {
        val fallbackValue = entry["fallback_to"]
        if (fallbackValue is String) {
            entry.remove("fallback_to")
            val fallback = entry["fallback"].asValueMap() ?: valueMapOf()
            fallback["to"] = fallbackValue
            if (fallbackValue != "none") {
                val branch = fallback["route"].asValueMap()?.get(fallbackValue).asValueMap() ?: valueMapOf()
                ROUTE_CODECS[fallbackValue]?.fillFallback(entry, branch)
                if (branch.isNotEmpty()) fallback["route"] = valueMapOf(fallbackValue to branch)
            }
            entry["fallback"] = fallback
            entry.remove("compact_waiter")
            entry.remove("pselect_waiter_shift")
            return
        }
        if (entry["fallback"].asValueMap() != null || entry["route"].asValueMap() == null) {
            entry.remove("compact_waiter")
            entry.remove("pselect_waiter_shift")
            return
        }
        if (!entry.containsKey("release")) {
            entry.remove("compact_waiter")
            entry.remove("pselect_waiter_shift")
            return
        }
        val routeName = entry["route"].asValueMap()?.keys?.firstOrNull()
        val pselect = entry["pselect_waiter_shift"]
        if (routeName == "tcp_zerocopy" && pselect != null) {
            entry["fallback"] = valueMapOf(
                "to" to "select_stack",
                "route" to valueMapOf("select_stack" to valueMapOf("waiter_shift" to pselect)),
            )
        } else {
            entry["fallback"] = valueMapOf("to" to "none")
        }
        entry.remove("compact_waiter")
        entry.remove("pselect_waiter_shift")
    }

    private fun inferRoute(entry: ValueMap): String {
        if (((entry["compact_waiter"] as? Number)?.toLong() ?: 0L) != 0L) return "tcp_zerocopy"
        return "select_stack"
    }
}
