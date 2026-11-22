package dev.maplesu.manager.litehidden

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.HttpURLConnection
import java.net.URI

/** The only destructive request is fixed to the manager-only authenticated daemon endpoint. */
class HttpHiddenManagerRemoval : HiddenManagerRemoval {
    override fun supported(port: Int, token: String): Boolean = runCatching {
        if (port !in 1..65535 || token.length < 16 || !token.all(Char::isLetterOrDigit)) return false
        val connection = URI(ParasitePaths.webUiUrl(port, token) + "api/manager/capabilities")
            .toURL().openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = 1_000
            connection.readTimeout = 1_000
            connection.instanceFollowRedirects = false
            connection.responseCode == 200 && connection.inputStream.bufferedReader().use {
                it.readText().trim() == """{"ok":true,"managerUninstall":1,"fullRestore":6}"""
            }
        } finally {
            connection.disconnect()
        }
    }.getOrDefault(false)

    override fun uninstall(port: Int, token: String): HiddenManagerRemovalResult = runCatching {
        val unconfirmed = HiddenManagerRemovalResult(false, HiddenFailure.MANAGER_REMOVAL_FAILED.wire)
        if (port !in 1..65535 || token.length < 16 || !token.all(Char::isLetterOrDigit)) return unconfirmed
        val connection = URI(ParasitePaths.webUiUrl(port, token) + "api/manager/uninstall")
            .toURL().openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.connectTimeout = 3_000
            connection.readTimeout = 60_000
            connection.doOutput = true
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("Content-Type", "application/json")
            connection.outputStream.use { it.write("{}".toByteArray(Charsets.UTF_8)) }
            val status = connection.responseCode
            val stream = if (status == 200) connection.inputStream else connection.errorStream
            val body = stream?.bufferedReader()?.use { it.readText() } ?: return unconfirmed
            val receipt = Json.parseToJsonElement(body) as? JsonObject ?: return unconfirmed
            if (status == 200 && receipt["ok"] == JsonPrimitive(true) &&
                receipt["state"] == JsonPrimitive("absent") && receipt["data"] == JsonPrimitive("retained")
            ) {
                HiddenManagerRemovalResult(true)
            } else {
                // Keep only fixed daemon codes; arbitrary response bodies may contain secrets.
                val code = (receipt["code"] as? JsonPrimitive)?.content
                val known = receipt["ok"] == JsonPrimitive(false) && code in FAILURE_CODES
                if (known) HiddenManagerRemovalResult(false, code.orEmpty()) else unconfirmed
            }
        } finally {
            connection.disconnect()
        }
    }.getOrElse { HiddenManagerRemovalResult(false, HiddenFailure.MANAGER_REMOVAL_FAILED.wire) }

    private companion object {
        val FAILURE_CODES = setOf(
            "MANAGER_HIDE_NOT_VERIFIED", "MANAGER_RECOVERY_NOT_VERIFIED",
            "MANAGER_FULL_RESTORE_UNAVAILABLE", "MANAGER_UNINSTALL_FAILED",
            "MANAGER_UNINSTALL_UNVERIFIED", "MANAGER_UNINSTALL_UNAVAILABLE",
        )
    }
}
