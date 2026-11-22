package dev.maplesu.manager.ultrakernel

import kotlinx.serialization.json.*

internal object UltraKernelHostDeploymentMetadata {
    private const val ROOT = "runtime/ultra/identity/kernel/"
    private val native = setOf("manager_resident_host.c", "manager_resident_host.h",
        "manager_resident_abi.h", "manager_claim_loader.h", "manager_deployment_namespace.h")
    private val support = setOf("manager_claim_bootstrap.c", "manager_claim_bootstrap.h",
        "manager_resident_abi.h", "manager_claim_loader.h", "manager_deployment_namespace.h")

    fun verify(evolution: JsonObject, manifest: JsonObject, coreInputs: Map<String, JsonObject>,
               coreSelection: JsonObject): Map<String, JsonObject> {
        fun flag(key: String) = evolution.getValue(key).jsonPrimitive.boolean
        fun path(item: JsonObject) = item.getValue("path").jsonPrimitive.content.replace('\\', '/')
        fun identity(value: JsonElement?): JsonObject {
            val item = value?.jsonObject ?: error("ULTRA_KERNEL_DEPLOYMENT_SOURCE_IDENTITY")
            require(path(item).isNotBlank() && (item["bytes"]?.jsonPrimitive?.longOrNull ?: 0) > 0 &&
                item["sha256"]?.jsonPrimitive?.content?.matches(Regex("[0-9a-f]{64}")) == true) {
                "ULTRA_KERNEL_DEPLOYMENT_SOURCE_IDENTITY"
            }
            return item
        }
        fun same(a: JsonObject, b: JsonObject) = a["bytes"] == b["bytes"] && a["sha256"] == b["sha256"]
        val inputs = manifest.getValue("inputs").jsonObject
        fun selected(value: JsonElement?): JsonObject = identity(value).also { item ->
            require(inputs.entries.singleOrNull {
                val input = it.key.replace('\\', '/')
                path(item) == input || path(item).endsWith("/$input")
            }?.value == item["sha256"]) { "ULTRA_KERNEL_DEPLOYMENT_SELECTED_SOURCE" }
        }
        require(evolution["schema"]?.jsonPrimitive?.content == "maplesu-host-deployment-source-evolution/1" &&
            evolution["sourceOwner"]?.jsonPrimitive?.content == "HOST" &&
            evolution["sourceFileCount"]?.jsonPrimitive?.intOrNull == 7 &&
            flag("predecessorIsNotFinalHostSource") && !flag("productionWritten") && !flag("targetQualified")) {
            "ULTRA_KERNEL_DEPLOYMENT_SOURCE_EVOLUTION"
        }
        for (key in listOf("identity", "ownerCandidate", "ownerSelection")) selected(evolution[key])
        require(same(selected(evolution["corePredecessor"]), selected(coreSelection))) {
            "ULTRA_KERNEL_DEPLOYMENT_CORE_PREDECESSOR"
        }
        val names = native + support
        val rows = evolution.getValue("selectedInputs").jsonArray.map { it.jsonObject }
        val byPath = rows.associateBy { it.getValue("logicalPath").jsonPrimitive.content }
        require(byPath.size == rows.size && byPath.keys == names.map { ROOT + it }.toSet()) {
            "ULTRA_KERNEL_DEPLOYMENT_SOURCE_PATHS"
        }
        val hasCoreSupport = coreInputs.containsKey(ROOT + "manager_deployment_namespace.h")
        val after = byPath.mapValues { (logical, row) ->
            selected(row["after"]).also { item ->
                val core = if (hasCoreSupport) coreInputs.getValue(logical) else null
                val exactCoreCopy = core != null &&
                    same(item, selected(core["nativeCopyIdentity"] ?: core["after"])) &&
                    path(item).substringAfterLast('/') == logical.substringAfterLast('/')
                require(path(item).endsWith("/$logical") || exactCoreCopy) {
                    "ULTRA_KERNEL_DEPLOYMENT_SOURCE_AFTER_PATH"
                }
            }
        }
        require(after.values.map(::path).distinct().size == rows.size) { "ULTRA_KERNEL_DEPLOYMENT_SOURCE_ALIAS" }
        val before = byPath.mapValues { (logical, row) ->
            val value = row.getValue("before")
            if (logical == ROOT + "manager_deployment_namespace.h" && !hasCoreSupport) {
                require(value is JsonNull) { "ULTRA_KERNEL_DEPLOYMENT_NEW_SOURCE_PREIMAGE" }
                null
            } else selected(value).also { item ->
                val core = if (hasCoreSupport) coreInputs.getValue(logical) else null
                require(if (core == null) path(item).endsWith("/$logical") else
                    same(item, selected(core["nativeCopyIdentity"] ?: core["after"])) &&
                        path(item).substringAfterLast('/') == logical.substringAfterLast('/')) {
                    "ULTRA_KERNEL_DEPLOYMENT_SOURCE_BEFORE_PATH"
                }
            }
        }
        val previous = evolution.getValue("previousInputs").jsonObject
        require(previous.keys == setOf("native", "support")) { "ULTRA_KERNEL_DEPLOYMENT_SOURCE_ROLES" }
        val coreNativeRows = evolution.getValue("coreNativeInputs").jsonArray.map { it.jsonObject }
        val coreNative = coreNativeRows.associateBy { it.getValue("logicalPath").jsonPrimitive.content }
        require(coreNative.size == coreNativeRows.size &&
            coreNative.keys == (native - "manager_deployment_namespace.h").map { ROOT + it }.toSet()) {
            "ULTRA_KERNEL_DEPLOYMENT_CORE_INPUTS"
        }
        val corePredecessors = coreNative.map { (logical, item) ->
            val name = logical.removePrefix(ROOT)
            name to selected(item["snapshotIdentity"]).also { require(path(it).substringAfterLast('/') == name) {
                "ULTRA_KERNEL_DEPLOYMENT_CORE_INPUT_PATH"
            } }
        }.toMap()
        evolution["sourceCorrections"]?.jsonArray?.forEach { selected(it) }
        for ((role, allowed) in mapOf("native" to native, "support" to support)) {
            val group = previous.getValue(role).jsonObject
            require(group.keys == names) { "ULTRA_KERNEL_DEPLOYMENT_PREVIOUS_INPUTS:$role" }
            for ((name, value) in group) {
                if (name !in allowed || name == "manager_deployment_namespace.h" && !hasCoreSupport) {
                    require(value is JsonNull) { "ULTRA_KERNEL_DEPLOYMENT_PREVIOUS_ABSENT:$role:$name" }
                    continue
                }
                val prior = selected(value)
                require(path(prior).substringAfterLast('/') == name) { "ULTRA_KERNEL_DEPLOYMENT_PREVIOUS_PATH:$role:$name" }
                if (hasCoreSupport) {
                    val core = coreInputs.getValue(ROOT + name)
                    val selectedCore = selected(core["nativeCopyIdentity"] ?: core["after"])
                    require(same(prior, selectedCore) && same(prior, before.getValue(ROOT + name)!!)) {
                        "ULTRA_KERNEL_DEPLOYMENT_SELECTED_CORE_PREDECESSOR:$role:$name"
                    }
                } else if (role == "native") {
                    require(same(prior, corePredecessors.getValue(name)) && same(prior, before.getValue(ROOT + name)!!)) {
                        "ULTRA_KERNEL_DEPLOYMENT_NATIVE_PREDECESSOR:$name"
                    }
                } else if (name in corePredecessors) {
                    require(same(prior, corePredecessors.getValue(name))) {
                        "ULTRA_KERNEL_DEPLOYMENT_SUPPORT_PREDECESSOR:$name"
                    }
                }
            }
        }
        val host = coreInputs.getValue(ROOT + "manager_resident_host.c")
        require(same(selected(host["nativeCopyIdentity"] ?: host["after"]),
            corePredecessors.getValue("manager_resident_host.c"))) { "ULTRA_KERNEL_DEPLOYMENT_CORE_HOST_SOURCE" }
        return after
    }
}