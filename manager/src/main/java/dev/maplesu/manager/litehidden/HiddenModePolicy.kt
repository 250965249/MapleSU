package dev.maplesu.manager.litehidden

import dev.maplesu.manager.workmode.WorkMode

/**
 * Lite 隐藏模式终态：**一个按钮**（用户选择寄生宿主 + 启用 WebUI + 状态写入；
 * 恢复经 WebUI，App 内不再自我卸载）。
 *
 * 本文件是纯策略（JVM 可测）：可见性、端口校验、恢复通道、单按钮状态机、失败码文案。
 * Android 执行由 `ui/security/LiteHiddenController` 与 `workmode/ui/LiteHidden*` 负责；
 * 后端未就绪时 fail-closed。
 */
enum class HiddenCardPhase {
    /** 未隐藏：显示卡片（含按钮/端口）。 */
    UNHIDDEN,

    /** 已点击，等待二次确认。 */
    CONFIRMING,

    /** 已确认，正在执行（按钮禁用）。 */
    ENABLING,

    /** 执行失败：卡片恢复可见并显示原因（保持未隐藏）。 */
    FAILED,
}

/** 端口校验结果。 */
data class PortInput(
    val raw: String,
    val value: Int? = null,
    val valid: Boolean = false,
    val errorKey: String? = null,
) {
    companion object {
        const val DEFAULT = 18427
        const val MIN = 1024
        const val MAX = 65535
    }
}

/** 恢复通道（开启隐藏前必须至少有一条，否则阻断并提示）。 */
data class RecoveryChannels(
    /** 拨号密令可用（默认 70707 也算可用；用户自定义同样可用）。 */
    val dialCodeAvailable: Boolean,
    /** 已拿到的 WebUI 恢复链接（含 token）；开启后 WebUI 才会真正启动。 */
    val webUiRecoveryLink: String?,
    /** 当前是否有 root 通道（Ultra 环境 Running / Lite 内核）。 */
    val rootAvailable: Boolean,
) {
    val hasRecovery: Boolean
        get() = dialCodeAvailable || !webUiRecoveryLink.isNullOrBlank()
}

/** 开启/解除失败码 → 文案资源键（纯映射，UI 直接查）。 */
enum class HiddenFailure(val wire: String, val messageKey: String) {
    BACKEND_UNAVAILABLE("LITE_HIDDEN_BACKEND_UNAVAILABLE", "lite_hidden_reason_backend_unavailable"),
    ROOT_UNAVAILABLE("LITE_HIDDEN_ROOT_UNAVAILABLE", "lite_hidden_reason_root_unavailable"),
    WEBUI_NOT_STARTED("LITEWEB_NOT_RUNNING", "lite_hidden_reason_webui"),
    PORT_IN_USE("LITEWEB_PORT_IN_USE", "lite_hidden_reason_port"),
    NO_RECOVERY_CHANNEL("LITE_HIDDEN_NO_RECOVERY", "lite_hidden_reason_recovery"),
    INVALID_PORT("LITE_HIDDEN_INVALID_PORT", "lite_hidden_reason_port_invalid"),
    VERIFY_FAILED("LITE_HIDDEN_VERIFY_FAILED", "lite_hidden_reason_verify"),
    RECOVERY_NOT_READY("MANAGER_FULL_RESTORE_UNAVAILABLE", "lite_hidden_reason_recovery_not_ready"),
    MANAGER_REMOVAL_FAILED("MANAGER_UNINSTALL_UNVERIFIED", "lite_hidden_reason_manager_removal"),

    /** 未选择宿主就确认激活。 */
    HOST_NOT_SELECTED("HOST_NOT_SELECTED", "lite_hidden_reason_host"),

    /** 选中的宿主不满足过滤规则（列表过期/包名伪造）。 */
    HOST_REJECTED("HOST_REJECTED", "lite_hidden_reason_host_invalid"),

    /** 宿主候选扫描失败（PackageManager 异常等）。 */
    HOST_SCAN_FAILED("HOST_SCAN_FAILED", "lite_hidden_reason_host_scan"),

    /** 宿主 native 库**备份**失败（原库没被动过；用户可见文案与「改写失败」分开）。 */
    HOST_BACKUP_FAILED("HOST_BACKUP_FAILED", "lite_hidden_reason_host_backup"),

    /** 宿主 native 库改写失败（后端已回滚或明确未写入）。 */
    HOST_SO_PATCH_FAILED("HOST_SO_PATCH_FAILED", "lite_hidden_reason_host_so"),

    /** 解除寄生失败（宿主 so/授权/daemon 任一步未完成）。 */
    DEACTIVATE_FAILED("HIDDEN_DEACTIVATE_FAILED", "lite_hidden_reason_deactivate"),

    UNKNOWN("LITE_HIDDEN_UNKNOWN", "lite_hidden_reason_unknown"),
    ;

    companion object {
        fun fromWire(code: String?): HiddenFailure =
            entries.firstOrNull { it.wire == code } ?: UNKNOWN
    }
}

/** 单按钮状态机的唯一入口。 */
object HiddenModePolicy {

    /** 卡片可见性：**A/B 都显示**，仅在隐藏生效后消失（UNKNOWN 保守按 ON）。 */
    fun cardVisible(mode: WorkMode?, state: LiteHiddenState): Boolean = !state.isEffectivelyOn

    /** 隐藏后所有隐藏相关入口/文字必须不可见（A/B 一致）。 */
    fun anyHiddenEntriesVisible(mode: WorkMode?, state: LiteHiddenState): Boolean = !state.isEffectivelyOn

    /**
     * 隐藏后将使用的 WebUI 链接（只读预览；token 缺失显示 "—"，不伪造）。
     * 端口变化时链接随之更新；token 只来自内存缓存（不启动 daemon/不写盘）。
     */
    fun webUiLinkPreview(portText: String, token: String?): String {
        val input = validatePort(portText)
        val port = if (input.valid) input.value ?: PortInput.DEFAULT else PortInput.DEFAULT
        val t = token?.trim()?.takeIf { it.isNotEmpty() } ?: return "—"
        return "http://127.0.0.1:$port/x7k9f/$t/"
    }

    /** 端口输入校验（默认 18427；范围 1024–65535；不合法返回错误键）。 */
    fun validatePort(raw: String?): PortInput {
        val text = raw?.trim().orEmpty()
        if (text.isEmpty()) return PortInput(text, null, false, "lite_hidden_reason_port_invalid")
        val value = text.toIntOrNull()
            ?: return PortInput(text, null, false, "lite_hidden_reason_port_invalid")
        if (value !in PortInput.MIN..PortInput.MAX) {
            return PortInput(text, value, false, "lite_hidden_reason_port_invalid")
        }
        return PortInput(text, value, true, null)
    }

    /** 端口默认展示值（设置页初始 18427）。 */
    fun defaultPort(): Int = PortInput.DEFAULT

    /** 开启前裁决：模式/隐藏态/端口/恢复通道/root 通道全部满足才 ready（fail-closed）。 */
    fun canEnable(
        mode: WorkMode?,
        state: LiteHiddenState,
        port: PortInput,
        channels: RecoveryChannels,
    ): HiddenFailure? {
        if (mode != WorkMode.LITE) return HiddenFailure.BACKEND_UNAVAILABLE
        if (state.isEffectivelyOn) return HiddenFailure.VERIFY_FAILED
        if (!port.valid) return HiddenFailure.INVALID_PORT
        if (!channels.rootAvailable) return HiddenFailure.ROOT_UNAVAILABLE
        if (!channels.hasRecovery) return HiddenFailure.NO_RECOVERY_CHANNEL
        return null
    }

    /** 纯状态机：返回下一阶段；未知事件保持当前阶段（fail-safe）。 */
    fun nextPhase(current: HiddenCardPhase, event: HiddenEvent): HiddenCardPhase = when (event) {
        HiddenEvent.ClickEnable -> when (current) {
            HiddenCardPhase.UNHIDDEN, HiddenCardPhase.FAILED -> HiddenCardPhase.CONFIRMING
            else -> current
        }

        HiddenEvent.CancelConfirm -> HiddenCardPhase.UNHIDDEN
        HiddenEvent.Confirm -> if (current == HiddenCardPhase.CONFIRMING) {
            HiddenCardPhase.ENABLING
        } else {
            current
        }

        HiddenEvent.EnableFailed -> if (current == HiddenCardPhase.ENABLING) {
            HiddenCardPhase.FAILED
        } else {
            current
        }

        HiddenEvent.EnableSucceeded -> current
    }

    /** 失败码 → 文案资源名（未知码回退 UNKNOWN，不伪造成功原因）。 */
    fun failureMessageKey(code: String?): String = HiddenFailure.fromWire(code).messageKey

    /** 按钮下方小字（≤15 字红线）。 */
    const val HINT = "开启后所有管理将寄生至 WebUI"

    /** 设置项/按钮/弹窗文案（与 res 保持一致；测试锁定）。 */
    const val GROUP_TITLE = "隐藏"
    const val BUTTON = "开启隐藏模式"
    const val PORT_LABEL = "WebUI 端口"
    const val DIALOG_TITLE = "开启隐藏？"
    const val DIALOG_BODY = "将寄生至所选应用，请保存 WebUI 链接"
    const val DIALOG_HOST_LABEL = "宿主应用"
    const val DIALOG_CANCEL = "取消"
    const val DIALOG_CONFIRM = "开启"
    const val COPY_LINK = "复制恢复链接"

    /** 解除寄生（隐藏设置页入口 + 步骤标题）。 */
    const val DEACTIVATE = "解除寄生"
    const val DEACTIVATE_TITLE = "解除寄生？"
    const val DEACTIVATE_BODY = "将恢复宿主原生库并撤销授权"
    const val DEACTIVATE_CONFIRM = "解除"

    /** 小字长度红线（中文按字符数，不含换行/首尾空白）。 */
    fun hintWithinLimit(text: String = HINT): Boolean =
        text.trim().count { it.code in 0x4E00..0x9FFF } <= 15
}

enum class HiddenEvent {
    ClickEnable,
    CancelConfirm,
    Confirm,
    EnableFailed,
    EnableSucceeded,
}
