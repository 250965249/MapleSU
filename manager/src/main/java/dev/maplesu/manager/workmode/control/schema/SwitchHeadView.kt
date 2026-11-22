package dev.maplesu.manager.workmode.control.schema

import dev.maplesu.manager.workmode.switch.SwitchStateNames
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/**
 * App 侧只读投影：字段名与含义来自 `switch.json`，
 * 由 [SwitchHeadViewCodec.parse] 完成 wire → 投影映射（不校验业务迁移合法性）。
 *
 * 用途：启动门控（有没有未完切换）、恢复页标题、WorkMode 页的"切换未完成"卡。
 */
@Serializable
data class SwitchHeadView(
    val schema: Int,
    val switchId: String,
    /** SwitchState 名称。 */
    val state: String,
    val from: String,
    val to: String,
    val bootIdAtBegin: String,
    /** = PENDING_STATES 成员（未知 state 保守为 true）。 */
    val pending: Boolean,
    val attempts: Int,
    val errorCode: String,
    val errorStage: String,
    val updatedAt: Long,
)

/**
 * `switch.json` 原文 → 投影。
 *
 * wire 字段来自 02 §3.2：`fromMode`/`toMode`/`startBootId`/`attempts.rebootRequests`/
 * `error.{code,stage}`/`updatedAtUptimeMs`。解析失败（不是 JSON object、缺 switchId/state）
 * → null（调用方按 Corrupt 处理，保留文件，禁止自动删除）。
 */
object SwitchHeadViewCodec {
    fun parse(rawJson: String): SwitchHeadView? {
        val root = runCatching { Json.parseToJsonElement(rawJson).jsonObject }.getOrNull() ?: return null
        val switchId = root.stringOrNull("switchId") ?: return null
        val state = root.stringOrNull("state") ?: return null
        val attemptsObject = root.objectOrNull("attempts")
        val errorObject = root.objectOrNull("error")
        val attempts = attemptsObject?.intOrNull("rebootRequests")
            ?: attemptsObject?.intOrNull("bootVerifyFailures")
            ?: 0
        return SwitchHeadView(
            schema = root.intOrNull("schema") ?: 1,
            switchId = switchId,
            state = state,
            from = root.stringOrNull("fromMode").orEmpty(),
            to = root.stringOrNull("toMode").orEmpty(),
            bootIdAtBegin = root.stringOrNull("startBootId").orEmpty(),
            pending = SwitchStateNames.isPending(state),
            attempts = attempts,
            errorCode = errorObject?.stringOrNull("code").orEmpty(),
            errorStage = errorObject?.stringOrNull("stage").orEmpty(),
            updatedAt = root.longOrNull("updatedAtUptimeMs") ?: 0L,
        )
    }

    private fun JsonObject.stringOrNull(key: String): String? =
        (this[key] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content

    private fun JsonObject.objectOrNull(key: String): JsonObject? =
        this[key] as? JsonObject

    private fun JsonObject.intOrNull(key: String): Int? =
        (this[key] as? kotlinx.serialization.json.JsonPrimitive)?.intOrNull

    private fun JsonObject.longOrNull(key: String): Long? =
        (this[key] as? kotlinx.serialization.json.JsonPrimitive)?.longOrNull

    @Suppress("unused")
    private fun JsonObject.booleanOrNull(key: String): Boolean? =
        (this[key] as? kotlinx.serialization.json.JsonPrimitive)?.booleanOrNull
}
