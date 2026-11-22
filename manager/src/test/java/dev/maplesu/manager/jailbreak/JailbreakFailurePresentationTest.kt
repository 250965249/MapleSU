package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Test

class JailbreakFailurePresentationTest {
    @Test fun dirtyfragOneShotGuardExplainsTheRequiredNextStep() {
        assertEquals("本次开机已运行过提权，请重启设备后重试",
            jailbreakFailureText("DIRTYFRAG_GUARD_PRESENT_REBOOT_REQUIRED"))
        assertEquals("本次开机已运行过提权，请重启设备后重试",
            jailbreakFailureText("DIRTYFRAG_REBOOT_REQUIRED_AFTER_ATTEMPT"))
    }

    @Test fun hookTimeoutAndEvidenceFailureAreNotHiddenBehindAGenericFailure() {
        assertEquals("等待提权服务响应超时，详细原因请查看导出日志",
            jailbreakFailureText("HOOK_PREPARE_TIMEOUT"))
        assertEquals("提权辅助程序未返回本次运行记录，详细原因请查看导出日志",
            jailbreakFailureText("MAPLESU_HOOK_EVIDENCE_MISSING"))
        assertEquals("提权辅助程序未响应，请查看导出日志",
            jailbreakFailureText("HOOK_BACKEND_NOT_READY:worker_unreachable"))
    }

    @Test fun uiShowsOnlyASanitizedDiagnosticIdentifier() {
        assertEquals("DIRTYFRAG_KERNEL_CHANGED_SINCE_ADMISSION",
            jailbreakFailureCode("DIRTYFRAG_KERNEL_CHANGED_SINCE_ADMISSION"))
        assertEquals("HOOK_BACKEND_NOT_READY:worker_unreachable",
            jailbreakFailureCode("HOOK_BACKEND_NOT_READY:worker_unreachable"))
        assertEquals("HOOK_BACKEND_NOT_READY",
            jailbreakFailureCode("HOOK_BACKEND_NOT_READY:worker_unreachable\nsecret=123"))
        assertEquals("JAILBREAK_ATTEMPT_FAILED", jailbreakFailureCode("private details here"))
    }

    @Test fun mapleSuCodesKeepTheirIdentifierAndExplanation() {
        assertEquals("MAPLESU_IR_NOT_READY", jailbreakFailureCode("MAPLESU_IR_NOT_READY"))
        assertEquals("MAPLESU_IR_NOT_READY", jailbreakFailureCode("MAPLESU_IR_NOT_READY\nprivate=details"))
        assertEquals("MAPLESU_IR_NOT_READY", jailbreakFailureCode("MAPLESU_IR_NOT_READY\r\nprivate=details"))
        assertEquals("系统环境未就绪，请确认 Root 环境后重试",
            jailbreakFailureText("MAPLESU_IR_NOT_READY"))
        assertEquals("设备内核版本 6.1 与内置模块 6.6 不一致，已拒绝加载",
            jailbreakFailureText("MAPLESU_TARGET_KMI_MISMATCH:6.1/6.6"))
    }
}
