package dev.maplesu.manager.compat

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

object StoredInputs {
    const val RECOVERY_MAGIC = "MAPLESU-RK1"
    const val RECOVERY_SALT = "maplesu-\u0070\u0072\u006f-recovery-v1"
    const val CREDENTIAL_FILE = "\u0073\u006b\u0072\u006f\u006f\u0074-credential.bin"
    const val CREDENTIAL_ALIAS_SUFFIX = ".\u0073\u006b\u0072\u006f\u006f\u0074.credential.v1"
    const val BOOT_APK = "pairing.apk"
    const val BOOT_LIBRARY = "libmaplesu_\u0070\u0072\u006f_bridge.so"
    const val ENVIRONMENT_VERSION_FILE = "\u0073\u006b\u0072\u006f\u006f\u0074.sdk.ver"
    const val CREDENTIAL_STEM = "\u0073\u006b\u0072\u006f\u006f\u0074-credential"
    const val ENVIRONMENT_INPUT_TEST = "if [ -d /data/adb/maplesu ] || [ -e /data/adb/\u0073\u006b\u0072\u006f\u006f\u0074_su_auth ] || ls -d /data/adb/*\u0073\u006b\u0072\u006f\u006f\u0074* >/dev/null 2>&1; then echo YES; else echo NO; fi"
    const val IDENTITY_FAILURE_PREFIX = "(?:MAPLESU|\u0053\u004b\u0052\u004f\u004f\u0054)"
    const val MODULE_TYPE = "\u0053\u004b\u0052\u004f\u004f\u0054_\u0050\u0052\u004f"
    const val ENVIRONMENT_GLOB = "/data/adb/*\u0073\u006b\u0072\u006f\u006f\u0074*"
    const val ENVIRONMENT_NAME_PATTERN = "\u0073\u006b\u0072\u006f\u006f\u0074"
    const val FLASH_DIRECTORY = "\u0070\u0072\u006f-flash"
    const val OPERATIONS_FILE = "\u0070\u0072\u006f-operations.jsonl"
    const val MODULE_EVIDENCE_FILE = "\u0070\u0072\u006f-module-evidence.jsonl"
    const val ACTIVATION_PREFIX = "\u0070\u0072\u006f-env-activation-"
    const val ACTIVATION_KIND = "\u0070\u0072\u006f-env-activation-evidence"

    val preferenceNames = mapOf(
        "maplesu-ultra" to "maplesu-\u0070\u0072\u006f",
        "maplesu-ultra-image-exports" to "maplesu-\u0070\u0072\u006f-image-exports",
        "maplesu-ultra-selfheal" to "maplesu-\u0070\u0072\u006f-selfheal",
        "ultra-auto-setup" to "\u0070\u0072\u006f-auto-setup",
        "ultra-env-identity" to "\u0070\u0072\u006f-env-identity",
        "ultra-env-upgrade" to "\u0070\u0072\u006f-env-upgrade",
        "ultra-idle-recovery" to "\u0070\u0072\u006f-idle-recovery",
        "ultra-identity-recovery" to "\u0070\u0072\u006f-identity-recovery",
    )

    private val sourceRoots = mapOf(
        "runtime/\u0070\u0072\u006f/" to "runtime/ultra/",
        "runtime/upstream-\u0070\u0072\u006f/" to "runtime/maplesu-sdk/",
    )

    fun sourcePath(value: String): String {
        val path = value.replace('\\', '/')
        val root = sourceRoots.keys.firstOrNull { path.startsWith(it) } ?: return path
        return sourceRoots.getValue(root) + path.removePrefix(root)
    }

    fun backend(value: String): String = when {
        value == "A_\u0050\u0052\u004f" -> "A_ULTRA"
        value.startsWith("A_\u0050\u0052\u004f:") -> "A_ULTRA:" + value.substringAfter(':')
        else -> value
    }

    fun receiptBackend(value: String): String = when (value) {
        "maplesu_\u0070\u0072\u006f", "\u0073\u006b\u0072\u006f\u006f\u0074_\u0070\u0072\u006f" -> "maplesu_ultra"
        else -> value
    }

    fun error(value: String): String = when (value) {
        "ERR_\u0053\u004b\u0052\u004f\u004f\u0054_ENV_NOT_INSTALL", "ERR_MAPLESU_ENV_NOT_INSTALL" -> "ERR_MAPLESU_ENV_UNPREPARED"
        else -> value
    }

    fun moduleType(value: String): String = if (value == MODULE_TYPE) "MAPLESU" else value

    fun operation(value: String): String = if (value.startsWith("\u0050\u0052\u004f_")) "ULTRA_" + value.removePrefix("\u0050\u0052\u004f_") else value

    fun control(raw: String): String {
        val root = Json.parseToJsonElement(raw) as? JsonObject ?: return raw
        return if (root.containsKey("transports") ||
            root.keys.containsAll(listOf("entries", "tombs", "policy", "revision"))) normalize(root).toString() else raw
    }

    private fun normalize(element: JsonElement): JsonElement = when (element) {
        is JsonArray -> JsonArray(element.map(::normalize))
        is JsonObject -> {
            val transports = element.containsKey("a1") && element.containsKey("jailbreak")
            JsonObject(buildMap {
                for ((key, value) in element) {
                    val name = if (transports && key == "\u0070\u0072\u006f") "ultra" else key
                    if (name != key && element.containsKey(name)) continue
                    put(name, when {
                        key in setOf("backend", "writtenBy", "channel") && value is JsonPrimitive && value.isString ->
                            JsonPrimitive(backend(value.content))
                        key == "degraded" && value is JsonArray -> JsonArray(value.map { item ->
                            if (item is JsonPrimitive && item.isString) JsonPrimitive(backend(item.content)) else normalize(item)
                        })
                        else -> normalize(value)
                    })
                }
            })
        }
        else -> element
    }
}
