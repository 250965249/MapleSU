package dev.maplesu.manager.jailbreak

/** Keep diagnostic tokens useful without displaying arbitrary exception details. */
internal fun jailbreakFailureCode(code: String): String {
    val token = code.substringBefore('\n').substringBefore('\r').substringBefore(':')
    if (!Regex("[A-Z][A-Z0-9_]{2,95}").matches(token)) return "JAILBREAK_ATTEMPT_FAILED"
    val sanitized = code.takeIf { Regex("[A-Z][A-Z0-9_]{2,95}(?::[a-zA-Z0-9_]{1,64})?").matches(it) }
        ?: token
    return sanitized
}

/**
 * User-facing explanation; the dialog shows the sanitized diagnostic identifier
 * separately so an exported log can be matched to the reported failure.
 */
internal fun jailbreakFailureText(rawCode: String): String {
    val code = rawCode.removePrefix("MAPLESU_")
    return when {
    code.startsWith("DIRTYFRAG_GUARD_PRESENT_REBOOT_REQUIRED") ||
        code.startsWith("DIRTYFRAG_REBOOT_REQUIRED_AFTER_ATTEMPT") ->
        "本次开机已运行过提权，请重启设备后重试"
    code.startsWith("HOOK_PREPARE_TIMEOUT") ||
        code.startsWith("HOOK_BACKEND_NOT_READY:prepare_timeout") ->
        "等待提权服务响应超时，详细原因请查看导出日志"
    code.startsWith("HOOK_EVIDENCE_MISSING") ->
        "提权辅助程序未返回本次运行记录，详细原因请查看导出日志"
    code.startsWith("HOOK_EVIDENCE_UNREADABLE") ->
        "提权运行记录读取失败，请查看导出日志"
    code.startsWith("HOOK_BACKEND_NOT_READY:worker_unreachable") ->
        "提权辅助程序未响应，请查看导出日志"
    code.startsWith("HOOK_BACKEND_NOT_READY:restore_not_enforcing") ->
        "系统状态恢复校验未通过，请查看导出日志"
    code.startsWith("SU_GATE_NOT_ARMED") ||
        code.startsWith("HOOK_BACKEND_NOT_READY:su_gate_not_armed") -> "Root 会话尚未就绪，请查看导出日志"
    code.startsWith("L3_NOT_PACKAGED") -> "安装包缺少当前内核的 Ultra 模块，请更新应用并导出日志"
    code.startsWith("93260_PROFILE_NOT_PACKAGED") ->
        "已识别当前内核的 98260 提权方案，但本版本未内置对应载荷，请更新应用"
    code.startsWith("93260_KERNEL_UNSUPPORTED") ->
        "当前内核构建不在本版本内置的 98260 方案中"
    code.startsWith("93260_PROFILE_BIND_FAILED") ->
        "内核方案与运行版本不匹配，已拒绝执行"
    code.startsWith("93260_PLANT_") ->
        "内核 plant 引擎未能完成提权或接管，详细原因请查看导出日志"
    // A previous session expiring is distinct from the current operation failing.
    code.startsWith("JAILBREAK_SUPERSEDED") ||
        code.startsWith("JAILBREAK_STATUS_BOOT_CHANGED") ->
        "上次提权会话已失效（设备已重启或内核载体已消失），请重新尝试"
    code.startsWith("JAILBREAK_SESSION_ACTIVE") ->
        "本次开机已有 Root 会话在运行，请先结束当前会话或重启设备"
    code.startsWith("TARGET_KMI_MISMATCH") -> {
        val detail = code.substringAfter(':', "")
        val parts = detail.split('/')
        if (parts.size == 2 && parts[0].isNotBlank() && parts[1].isNotBlank()) {
            "设备内核版本 ${parts[0]} 与内置模块 ${parts[1]} 不一致，已拒绝加载"
        } else {
            "设备内核版本与内置模块不一致，已拒绝加载"
        }
    }
    code.startsWith("HANDOVER_LOAD_FAILED") ->
        "内核模块加载失败，详细原因请查看导出日志"
    code.startsWith("HANDOVER_KSU_LATE_LOAD_FAILED") ->
        "KernelSU 延迟加载失败，详细原因请查看导出日志"
    code.startsWith("HANDOVER_RESTORE_UNVERIFIED") ->
        "系统状态恢复校验未通过，详细原因请查看导出日志"
    code.startsWith("HANDOVER_EVIDENCE_UNREADABLE") ->
        "Root 启动记录读取失败，请查看导出日志"
    // v1 transport tokens are still readable from a legacy file, but they no longer
    // decide anything: liveness is derived, never presented as this attempt's failure.
    code.startsWith("JAILBREAK_LEASE_EXITED") ||
        code.startsWith("JAILBREAK_HOOK_WORKER_EXITED") -> "Root 会话已断开，请查看导出日志"
    code.startsWith("IR_UNSUPPORTED") ->
        "当前内核版本尚未适配"
    code.startsWith("IR_NOT_READY") -> "系统环境未就绪，请确认 Root 环境后重试"
    code.startsWith("IR_SPEC_INVALID") -> "内核镜像格式不受支持"
    code.startsWith("IR_MODULE_INVALID") -> "内核模块校验未通过"
    code.startsWith("IR_HELPER_PATH_MISMATCH") -> "辅助程序路径不一致"
    code.startsWith("IR_ASSET_SIZE") || code.startsWith("IR_ASSET_DIGEST") ->
        "内置文件校验失败"
    code.startsWith("IR_STAGE_UNWRITABLE") -> "暂存目录写入失败，请检查可用空间与文件权限"
    code.startsWith("IR_STAGE_MODE") -> "暂存文件权限异常"
    code.startsWith("IR_STAGE_MISSING") -> "暂存文件缺失，请重新准备安装文件"
    code.startsWith("HOOK_NOT_PACKAGED") -> "当前版本未内置该模块"
    code.startsWith("JAILBREAK_CANCELLED") -> "已取消"
    code.startsWith("JAILBREAK_METHOD_UNKNOWN") -> "未知的运行方式"
    code.startsWith("SECONDARY_USER_UNSUPPORTED") -> "不支持子用户"
    code.startsWith("PROVIDER_STALE_PAGE_CACHE") -> "分页缓存已过期"
    else -> "操作未完成，请重试或导出日志查看原因"
    }
}

/**
 * Facts observed by the reader (owner gone, boot changed, carrier gone) are
 * hints for the UI. They never become a failure reason and never change the stage.
 */
internal fun jailbreakDerivedHint(status: JailbreakStatus): String? {
    val derived = status.derived ?: return null
    return when {
        derived.bootChanged -> "记录属于上一次开机，本次开机需要重新提权"
        derived.ownerAlive == false -> "提权进程已退出；若内核载体仍在服务则无需重新提权"
        derived.carrierLive == false -> "未检测到存活的提权载体"
        else -> null
    }
}

/**
 * A carrier proof only counts for the attempt and boot it was written for.
 * A record without a proof is the legacy path and keeps the existing probes until
 * T6 starts writing proofs.
 */
internal fun carrierBindsAttempt(status: JailbreakStatus): Boolean {
    val carrier = status.carrier ?: return true
    return carrier.attemptId == status.attemptId && carrier.bootId == status.bootId
}
