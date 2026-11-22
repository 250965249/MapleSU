package dev.maplesu.manager.workmode.control

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * 控制面 JSON 唯一配置。
 *
 * - `encodeDefaults = true`：缺省字段必须落盘，否则升级后语义漂移；
 * - `explicitNulls = true`：显式 null 可区分"未设置"与"缺字段"（wire 层）；
 * - `ignoreUnknownKeys = true`：只影响读，未知字段仍受 schema 版本闸门保护；
 * - `prettyPrint = false`：canonical sha256 必须稳定。
 *
 * 只约束本包的控制文件；`switch.json` 由切换状态机定义，本包只做字节级原子写和只读投影。
 */
@OptIn(ExperimentalSerializationApi::class)
val ControlJson: Json = Json {
    encodeDefaults = true
    explicitNulls = true
    ignoreUnknownKeys = true
    prettyPrint = false
}

object ControlJsonCodec {
    fun <T> encode(value: T, serializer: KSerializer<T>): String =
        ControlJson.encodeToString(serializer, value)

    inline fun <reified T> encode(value: T): String = ControlJson.encodeToString(value)

    inline fun <reified T> decodeOrNull(raw: String): T? =
        runCatching { ControlJson.decodeFromString<T>(dev.maplesu.manager.compat.StoredInputs.control(raw)) }.getOrNull()

    fun <T> decodeOrNull(raw: String, serializer: KSerializer<T>): T? =
        runCatching { ControlJson.decodeFromString(serializer, dev.maplesu.manager.compat.StoredInputs.control(raw)) }.getOrNull()
}
