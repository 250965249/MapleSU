package dev.maplesu.manager.workmode.service

import android.os.Bundle
import dev.maplesu.manager.workmode.switch.ExportedImage
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.SwitchPartitionStatus

/**
 * W08 服务端 → AIDL 的 Bundle 编解码（02 §5.2 键集合）。
 *
 * 与 `InstallerServiceClient` 的解码保持一一对应：`state/error/errorDetail/partitions` 等
 * 键名不得改动；未知键由客户端忽略。
 */
internal object ModeSwitchAidlCodec {

    private val requiredPlanFields = listOf("fromMode", "toMode", "baselineId")
    private val partitionPlanFields = listOf("targetPartition", "sourcePartition")

    fun planBundle(switchId: String, planFields: Map<String, String>): Bundle = Bundle().apply {
        putString("schema", "MAPLESU_SWITCH_PLAN_V1")
        putString("switchId", switchId)
        for (key in requiredPlanFields) putString(key, planFields[key].orEmpty())
        for (key in partitionPlanFields) {
            planFields[key]?.let { putString(key, it) }
        }
    }

    fun decodePlanFields(plan: Bundle): Map<String, String> {
        val fields = LinkedHashMap<String, String>()
        for (key in requiredPlanFields + partitionPlanFields) {
            plan.getString(key)?.let { fields[key] = it }
        }
        // 平铺的 SwitchPlan 字段（begin 时可携带；服务端只在 submit 后使用）。
        plan.keySet().sorted().forEach { key ->
            if (key in fields) return@forEach
            if (key.startsWith("step.") || key in setOf("schema", "switchId", "planSha256", "startBootId")) {
                plan.getString(key)?.let { fields[key] = it }
            }
        }
        return fields
    }

    fun statusBundle(status: DeviceSwitchStatus?): Bundle = Bundle().apply {
        putString("switchId", status?.switchId.orEmpty())
        putString("state", status?.state.orEmpty())
        putString("stage", status?.stage.orEmpty())
        putString("step", status?.step.orEmpty())
        putString("fromMode", status?.fromMode.orEmpty())
        putString("toMode", status?.toMode.orEmpty())
        putString("error", status?.error.orEmpty())
        putString("errorDetail", status?.errorDetail.orEmpty())
        putString("planSha256", status?.planSha256.orEmpty())
        putBoolean("rebootRequired", status?.rebootRequired ?: false)
        putBoolean("bootObserved", status?.bootObserved ?: false)
        putBoolean("operationActive", status?.operationActive ?: false)
        putBoolean("canRollback", status?.canRollback ?: false)
        putBoolean("canResumeReboot", status?.canResumeReboot ?: false)
        putInt("verifyFailures", status?.verifyFailures ?: 0)
        val names = status?.partitions?.map { it.name }.orEmpty()
        putStringArrayList("partitions", ArrayList(names))
        status?.partitions?.forEach { row -> putBundle(row.name, partitionBundle(row)) }
        status?.device?.forEach { (key, value) -> putString(key, value) }
    }

    fun preflightBundle(result: DevicePreflightResult, switchId: String): Bundle = Bundle().apply {
        result.status?.takeIf { it.switchId == switchId }?.let { putAll(statusBundle(it)) }
        putBoolean("ok", result.ok)
        putString("error", if (result.ok) "" else result.code.ifEmpty { "SWITCH_SERVICE_FAILED" })
        putString("errorDetail", result.detail)
        putString("switchId", switchId)
        if (!result.ok) putString("state", "")
    }

    fun resultBundle(result: DeviceSwitchResult, switchId: String): Bundle = Bundle().apply {
        val status = result.status?.takeIf { it.switchId == switchId }
        if (status != null) putAll(statusBundle(status)) else putString("state", "")
        putBoolean("ok", result.ok)
        putString("error", if (result.ok) "" else result.code.ifEmpty { "SWITCH_SERVICE_FAILED" })
        putString("errorDetail", result.detail)
        putString("switchId", switchId)
        if (!result.ok) putString("state", status?.state.orEmpty())
    }

    fun errorBundle(code: String, detail: String, switchId: String): Bundle = statusBundle(null).apply {
        putBoolean("ok", false)
        putString("switchId", switchId)
        putString("error", code.ifEmpty { "SWITCH_SERVICE_FAILED" })
        putString("errorDetail", detail)
        putString("state", "")
    }

    fun imageMeta(image: ExportedImage): Bundle = Bundle().apply {
        putLong("size", image.size)
        putString("sha256", image.sha256)
        putString("path", image.file.absolutePath)
    }

    fun partitionBundle(row: SwitchPartitionStatus): Bundle = Bundle().apply {
        putString("name", row.name)
        putString("role", row.role)
        putLong("size", row.size)
        putString("preSha256", row.preSha256)
        putString("targetSha256", row.targetSha256)
        putString("tailSha256", row.tailSha256)
        putString("observedSha256", row.observedSha256)
        putString("state", row.state)
    }

    /** AIDL PFD 方法失败时唯一可用的错误通道（客户端以 RemoteException 呈现）。 */
    fun throwForPfd(error: DeviceSwitchError): Nothing =
        throw IllegalStateException(error.code + if (error.detail.isBlank()) "" else ":${error.detail}")

    fun unknownFailure(error: Throwable): Bundle =
        errorBundle(ModeSwitchCodes.ROOT_UNAVAILABLE, error.message.orEmpty(), "")
}
