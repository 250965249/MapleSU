package com.maplesu.core.ui.screen.module

import com.maplesu.core.R
import com.maplesu.core.data.model.Module
import dev.maplesu.manager.modules.ModuleWaitReason
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * T10：`ModuleUiState` 的"启动中"（pending）与终态（loadError/hasLoaded）必须互斥，
 * 并用源码契约锁住 ViewModel/MainActivity 的实际接线（纯状态机测试覆盖不到的那一段）。
 */
class ModuleEnvironmentStateTest {

    private val module = Module(
        id = "fixture", name = "Fixture", author = "MapleSU", version = "1", versionCode = 1,
        description = "", enabled = true, update = false, remove = false, updateJson = "",
        hasWebUi = false, hasActionScript = false, metamodule = false,
        actionIconPath = null, webUiIconPath = null,
    )

    private fun source(relativePath: String): String {
        val file = listOf(File(relativePath), File("manager/$relativePath"))
            .firstOrNull { it.isFile }
        assumeTrue(relativePath, file != null)
        return file!!.readText()
    }

    @Test
    fun pendingShowsTheEnvironmentMessageAndNeverTheLoadFailure() {
        val state = ModuleUiState().withModulePending(ModuleWaitReason.MODE_UNRESOLVED)

        assertTrue(state.pending)
        assertEquals("MODE_UNRESOLVED", state.pendingReason)
        assertFalse("hasLoaded 只在终态为 true", state.hasLoaded)
        assertNull("等待接线不是失败", state.loadError)
        assertEquals(R.string.module_environment_pending, state.emptyStateMessage)
        assertNotEquals(R.string.module_load_failed, state.emptyStateMessage)
        assertNotEquals("不得用空列表现成成功空态", R.string.module_empty, state.emptyStateMessage)
    }

    @Test
    fun pendingDoesNotHideAnAlreadyLoadedList() {
        val loaded = ModuleUiState(hasLoaded = true, modules = listOf(module), moduleList = listOf(module))
        val pending = loaded.withModulePending(ModuleWaitReason.KSU_BACKEND_UNWIRED)

        assertNull("已有列表时继续显示列表，不显示任何空态文案", pending.emptyStateMessage)
        assertEquals(listOf(module), pending.modules)
        assertEquals("KSU_BACKEND_UNWIRED", pending.pendingReason)
    }

    @Test
    fun terminalOutcomesClearPendingExactlyOnce() {
        val pending = ModuleUiState().withModulePending(ModuleWaitReason.MODE_UNRESOLVED)

        val success = pending.withModuleLoadResult(Result.success(listOf(module)))
        assertFalse(success.pending)
        assertNull(success.pendingReason)
        assertTrue(success.hasLoaded)
        assertEquals(listOf(module), success.modules)

        val failed = pending.withModuleLoadResult(Result.failure(IllegalStateException("BACKEND_UNAVAILABLE: x")))
        assertFalse(failed.pending)
        assertNull(failed.pendingReason)
        assertTrue("失败是终态，必须可见（重试按钮的判据）", failed.hasLoaded)
        assertEquals(R.string.module_load_failed, failed.emptyStateMessage)
    }

    @Test
    fun theViewModelNeverFetchesBeforeTheEnvironmentGateAndWaitsOnlyOnce() {
        val viewModel = source("src/main/java/com/maplesu/core/ui/viewmodel/ModuleViewModel.kt")

        val fetch = viewModel.substringAfter("fun fetchModuleList(")
            .substringBefore("private fun awaitEnvironmentWiring(")
        assertTrue("没有环境门就不是 T10", fetch.contains("startupGate.onLoadRequested()"))
        assertTrue(fetch.contains("withModulePending"))
        assertTrue(
            "环境未接线时必须先退出，不能先 bump 请求代次再取列表",
            fetch.indexOf("startupGate.onLoadRequested()") < fetch.indexOf("refreshRequests.next()"),
        )
        assertTrue(fetch.indexOf("awaitEnvironmentWiring") < fetch.indexOf("refreshRequests.next()"))

        val wiring = viewModel.substringAfter("private fun awaitEnvironmentWiring(")
            .substringBefore("private fun Module.toSignature")
        assertTrue("单飞：等待期间重复请求不重复订阅", wiring.contains("environmentWaitJob?.isActive == true"))
        assertTrue(
            wiring.indexOf("environmentWaitJob?.isActive == true") < wiring.indexOf("viewModelScope.launch"),
        )
        assertTrue("只挂起在一次性事件上", wiring.contains("ModuleEnvironmentWatch.awaitReady"))
        assertTrue(wiring.contains("ENVIRONMENT_WAIT_TIMEOUT_MS"))
        assertTrue("就绪 → 自动重取一次", wiring.contains("startupGate.onEnvironmentReady()"))
        assertTrue("超时 → 允许一次如实失败，不能无限启动中", wiring.contains("startupGate.onWaitTimedOut()"))
        assertFalse("禁止轮询", wiring.contains("delay("))
        assertEquals("自动重取只有一处", 1, Regex("fetchModuleList\\(").findAll(wiring).count())

        val load = viewModel.substringAfter("private suspend fun loadModuleList(")
            .substringBefore("fun fetchModuleList(")
        assertTrue(
            "终态发布后才允许 onTerminal",
            load.indexOf("withModuleLoadResult(result)") < load.indexOf("startupGate.onTerminal()"),
        )
    }

    @Test
    fun theStartupPreloadWaitsForEitherOutcomeInsteadOfHangingOnHasLoaded() {
        val activity = source("src/main/java/com/maplesu/core/ui/MainActivity.kt")
        assertTrue(
            "未判定时死等 hasLoaded 会把后续预取一起挂住",
            activity.contains("moduleViewModel.uiState.first { it.hasLoaded || it.pending }"),
        )
        // 模块列表：不得再出现"只等 hasLoaded"的旧写法（超管列表的写法与 T10 无关，不动）。
        assertFalse(
            "模块列表不得再死等 hasLoaded",
            activity.contains("moduleViewModel.uiState.first { it.hasLoaded }"),
        )
    }
}
