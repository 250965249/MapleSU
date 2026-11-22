package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.workmode.service.SwitchBlocker as BackendBlocker
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * Ultra 环境互操作 blocker 的 UI 映射：必须给出**具体原因**（而不是笼统的“前置检查未通过”），
 * 否则用户无法判断是"需要先暂停 Ultra 环境"还是"状态读不到"。
 */
class SwitchFlowUltraEnvBlockerTest {

    private fun map(code: String): String =
        mapBackendBlockers(listOf(BackendBlocker(code = code, detail = "detail"))).single().code

    @Test
    fun ultraEnvironmentBlockersMapToSpecificUiReasons() {
        assertEquals(SwitchBlockerCodes.ULTRA_ENV_MUST_SUSPEND, map("ULTRA_ENV_MUST_SUSPEND"))
        assertEquals(SwitchBlockerCodes.ULTRA_ENV_MUST_RESTORE, map("ULTRA_ENV_MUST_PREPARE_RESTORE"))
        assertEquals(SwitchBlockerCodes.ULTRA_ENV_STATE_UNKNOWN, map("ULTRA_ENV_STATE_UNKNOWN"))
        assertEquals(SwitchBlockerCodes.ULTRA_ENV_STATE_UNKNOWN, map("ULTRA_ENV_NO_KEY"))
        assertEquals(SwitchBlockerCodes.ULTRA_ENV_STATE_UNKNOWN, map("ULTRA_ENV_FAULT"))
    }

    @Test
    fun unknownBackendCodesStayGeneric() {
        assertEquals(SwitchBlockerCodes.BACKEND_BLOCKED, map("SWITCH_SOMETHING_ELSE"))
    }

    @Test
    fun exportFailureDoesNotClaimRestoreFilesAreMissing() {
        assertEquals(SwitchBlockerCodes.EXPORT_FAILED, map("SWITCH_EXPORT_REQUIRED"))
        assertEquals(SwitchBlockerCodes.W19_IMPLANT_MISSING, map("SWITCH_IMPLANT_RESTORE_MISSING"))
        assertNotEquals(SwitchBlockerCodes.W19_IMPLANT_MISSING, map("SWITCH_EXPORT_REQUIRED"))
        assertNotEquals(
            WorkModeStrings.blockerRes(SwitchBlockerCodes.W19_IMPLANT_MISSING),
            WorkModeStrings.failureRes("SWITCH_EXPORT_REQUIRED"),
        )
    }

    @Test
    fun blockerCodesHaveDedicatedStrings() {
        // 三个 Ultra 环境 code 都必须有专属文案，不能落到 generic。
        val generic = WorkModeStrings.blockerRes(SwitchBlockerCodes.BACKEND_BLOCKED)
        val suspend = WorkModeStrings.blockerRes(SwitchBlockerCodes.ULTRA_ENV_MUST_SUSPEND)
        val restore = WorkModeStrings.blockerRes(SwitchBlockerCodes.ULTRA_ENV_MUST_RESTORE)
        val unknown = WorkModeStrings.blockerRes(SwitchBlockerCodes.ULTRA_ENV_STATE_UNKNOWN)
        assertEquals("三个文案必须互不相同", 3, setOf(suspend, restore, unknown).size)
        assertEquals("不能复用 generic", 3, setOf(suspend, restore, unknown).minus(generic).size)
    }
}
