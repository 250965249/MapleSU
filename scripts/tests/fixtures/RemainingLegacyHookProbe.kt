package dev.maplesu.manager.ultrakernel

import java.io.File
import kotlinx.serialization.json.*
import kotlin.system.exitProcess

/** Read-only symptom probe; nonzero means the two recorded install failures remain. */
fun main(args: Array<String>) {
    val cases = Json.parseToJsonElement(File(args[0]).readText()).jsonArray
    val hypotheticalPac = args.getOrNull(2) == "synthetic-pac-control"
    val results = cases.map { element ->
        val row = element.jsonObject
        val entry = row.getValue("entryOffset").jsonPrimitive.int
        val notify = row.getValue("notifyOffset").jsonPrimitive.int
        val die = row.getValue("dieOffset").jsonPrimitive.int
        val kernel = UltraKernelPlanFixtures.syntheticKernel()
        fun bytes(key: String) = row.getValue(key).jsonPrimitive.content.chunked(2)
            .map { it.toInt(16).toByte() }.toByteArray()
        bytes("entryBytes64").copyInto(kernel, entry)
        bytes("notifyFrameActual52").copyInto(kernel, notify)
        if (hypotheticalPac) UltraKernelA64.writeLe32(kernel, entry, UltraKernelA64.PACIA1716.toLong())
        val before = kernel.copyOf()
        val symbols = FakeSymbols(UltraKernelPlanFixtures.K22_SYMBOL_BASE + mapOf(
            "do_execveat_common" to entry, "arm64_notify_die" to notify, "die" to die), kernel.size)
        val error = try {
            val rendered = UltraKernelRecipe.k22().render(symbols, kernel, UltraKernelPlanFixtures.credential())
            buildJsonObject { put("renderedRecords", rendered.size) }
        } catch (failure: UltraKernelGenerateException) {
            buildJsonObject {
                put("errorCode", failure.code)
                put("errorDetail", failure.detail)
                put("firstSourceFrame", failure.stackTrace.first().toString())
            }
        }
        check(before.contentEquals(kernel))
        buildJsonObject {
            put("case", row.getValue("case"))
            put("mode", if (hypotheticalPac) "synthetic-pac-control" else "actual-recorded-window")
            put("targetPreimageClaimed", false)
            put("inputBufferUnchanged", true)
            put("observation", error)
        }
    }
    val success = results.all { "renderedRecords" in it.getValue("observation").jsonObject }
    File(args[1]).writeText(buildJsonObject {
        put("results", JsonArray(results))
        put("bothRenderSucceeded", success)
        put("largeImageGeneration", false)
        put("deviceTest", false)
        put("partitionWrites", false)
    }.toString())
    println(File(args[1]).readText())
    exitProcess(if (success) 0 else 1)
}
