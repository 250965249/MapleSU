package dev.maplesu.manager.ultrakernel

import kotlinx.serialization.json.*
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UltraKernelHostDeploymentMetadataTest {
    @Test fun exactOverlayAndBrokenPredecessors() {
        val root = "runtime/ultra/identity/kernel/"
        val native = setOf("manager_resident_host.c", "manager_resident_host.h", "manager_resident_abi.h", "manager_claim_loader.h")
        val support = setOf("manager_claim_bootstrap.c", "manager_claim_bootstrap.h", "manager_resident_abi.h", "manager_claim_loader.h")
        val names = native + support + "manager_deployment_namespace.h"
        val inputs = linkedMapOf<String, JsonElement>()
        fun identity(path: String, digest: Char = 'a', bytes: Int = 10) = buildJsonObject {
            put("path", path); put("bytes", bytes); put("sha256", digest.toString().repeat(64))
        }.also { inputs[path] = it.getValue("sha256") }
        val coreSelection = identity("fixture/core-selection.json")
        val coreNative = native.associateWith { identity("fixture/core-native/$it") }
        val coreInputs = mapOf(root + "manager_resident_host.c" to buildJsonObject {
            put("after", coreNative.getValue("manager_resident_host.c"))
            put("nativeCopyIdentity", coreNative.getValue("manager_resident_host.c"))
        })
        val rows = names.map { name -> buildJsonObject {
            put("logicalPath", root + name)
            put("before", if (name == "manager_deployment_namespace.h") JsonNull else
                identity("fixture/owner-before/$root$name", bytes = if (name.startsWith("manager_claim_bootstrap")) 12 else 10))
            put("after", identity("fixture/owner-after/$root$name", 'b'))
        } }
        val previous = buildJsonObject {
            put("native", JsonObject(names.associateWith { name -> coreNative[name] ?: JsonNull }))
            put("support", JsonObject(names.associateWith { name ->
                if (name in support) identity("fixture/support-before/$root$name") else JsonNull
            }))
        }
        val evolution = buildJsonObject {
            put("schema", "maplesu-host-deployment-source-evolution/1")
            put("sourceOwner", "HOST"); put("sourceFileCount", 7)
            put("predecessorIsNotFinalHostSource", true); put("productionWritten", false); put("targetQualified", false)
            put("identity", identity("fixture/selection.json"))
            put("ownerCandidate", identity("fixture/contact.md"))
            put("ownerSelection", identity("fixture/owner-selection.json"))
            put("corePredecessor", coreSelection)
            put("selectedInputs", JsonArray(rows)); put("previousInputs", previous)
            put("coreNativeInputs", JsonArray(coreNative.map { (name, item) -> buildJsonObject {
                put("logicalPath", root + name); put("snapshotIdentity", item)
            } }))
        }
        val manifest = buildJsonObject { put("inputs", JsonObject(inputs)) }
        assertEquals(names.map { root + it }.toSet(),
            UltraKernelHostDeploymentMetadata.verify(evolution, manifest, coreInputs, coreSelection).keys)
        fun rejects(value: JsonObject, source: JsonObject = manifest) = assertTrue(runCatching {
            UltraKernelHostDeploymentMetadata.verify(value, source, coreInputs, coreSelection)
        }.isFailure)
        rejects(JsonObject(evolution - "coreNativeInputs"))
        rejects(JsonObject(evolution + ("targetQualified" to JsonPrimitive(true))))
        val badPrevious = JsonObject(previous + ("native" to JsonObject(previous.getValue("native").jsonObject +
            ("manager_resident_host.c" to JsonNull))))
        rejects(JsonObject(evolution + ("previousInputs" to badPrevious)))
        val first = rows.first().getValue("after").jsonObject.getValue("path").jsonPrimitive.content
        rejects(evolution, buildJsonObject { put("inputs", JsonObject(inputs - first)) })

        val selection54 = identity("fixture/core54-selection.json", 'd')
        val before54 = names.associateWith { identity("fixture/core54/$root$it", 'c', 14) }
        val core54 = names.associate { name -> root + name to buildJsonObject { put("after", before54.getValue(name)) } }
        val rows54 = names.map { name -> buildJsonObject {
            put("logicalPath", root + name); put("before", before54.getValue(name))
            put("after", rows.single { it["logicalPath"]?.jsonPrimitive?.content == root + name }.getValue("after"))
        } }
        val previous54 = buildJsonObject {
            put("native", JsonObject(names.associateWith { name ->
                if (name in native || name == "manager_deployment_namespace.h") before54.getValue(name) else JsonNull
            }))
            put("support", JsonObject(names.associateWith { name ->
                if (name in support || name == "manager_deployment_namespace.h") before54.getValue(name) else JsonNull
            }))
        }
        val evolution54 = JsonObject(evolution + mapOf(
            "corePredecessor" to selection54, "selectedInputs" to JsonArray(rows54), "previousInputs" to previous54,
            "coreNativeInputs" to JsonArray(native.map { name -> buildJsonObject {
                put("logicalPath", root + name); put("snapshotIdentity", before54.getValue(name))
            } })))
        val manifest54 = buildJsonObject { put("inputs", JsonObject(inputs)) }
        assertEquals(names.map { root + it }.toSet(),
            UltraKernelHostDeploymentMetadata.verify(evolution54, manifest54, core54, selection54).keys)
        val missingBefore = JsonObject(evolution54 + ("selectedInputs" to JsonArray(rows54.map {
            if (it["logicalPath"]?.jsonPrimitive?.content == root + "manager_deployment_namespace.h")
                JsonObject(it + ("before" to JsonNull)) else it
        })))
        assertTrue(runCatching {
            UltraKernelHostDeploymentMetadata.verify(missingBefore, manifest54, core54, selection54)
        }.isFailure)
    }
}