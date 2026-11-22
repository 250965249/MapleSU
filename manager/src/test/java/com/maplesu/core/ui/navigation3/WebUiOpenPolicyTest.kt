package com.maplesu.core.ui.navigation3

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * 「不要自动跳进模块 WebUI」的纯 JVM 契约。
 *
 * 真机取证（`evidence/webui-repro/logcat-after-start.txt:707` → `:1537`）显示：
 * 进程启动后 `SoterLane` 为了读一个开关调用 `start_module_web_ui_server_async`，
 * 该宿主调用会以 uid 0 执行 `am start -a android.view.ACTION_VIEW
 * http://127.0.0.1:<port>/`，于是每次进入 MapleSU 都自动弹出模块 WebUI。
 * 这里锁定修复后的三条不变量：
 *
 * 1. 只有「用户此刻的显式动作」能通过导航闸门；冷启动/恢复/安装回执/未知状态一律拒绝；
 * 2. pending 请求只在进程内存在、消费即清空，进程重建不会重放；
 * 3. 后台路径（SoterLane）不再持有启动模块 WebUI 的调用，显式入口必须带 USER_CLICK。
 */
class WebUiOpenPolicyTest {

    private val moduleId = "teesimulator601skpro202607210000"

    // ── 1. 冷启动 / 非用户状态永不导航 ─────────────────────────────────────

    @Test
    fun coldStartDefaultNeverNavigatesToWebUi() {
        // 冷启动没有「此刻的用户动作」：即使设备上装着带 WebUI 的模块，也不能导航。
        assertFalse(
            WebUiOpenPolicy.mayNavigate(
                WebUiOpenRequest(moduleId, WebUiOpenOrigin.PROCESS_START)
            )
        )
        // 没有任何请求时同样停在首页。
        assertFalse(WebUiOpenPolicy.mayNavigate(null))
    }

    @Test
    fun installedModuleWithWebUiIsNotAnOpenRequest() {
        // 模块状态（hasWebUi / 已安装 / 已启用）不是请求；只有点击才会构造请求。
        // 这里用 null 表示「列表里有个带 WebUI 的模块，但没人点它」。
        assertFalse(WebUiOpenPolicy.mayNavigate(null))
        assertFalse(
            WebUiOpenPolicy.mayNavigate(
                WebUiOpenRequest(moduleId, WebUiOpenOrigin.PROCESS_START)
            )
        )
    }

    @Test
    fun restoredTaskOrSavedIntentDoesNotNavigate() {
        assertFalse(
            WebUiOpenPolicy.mayNavigate(
                WebUiOpenRequest(moduleId, WebUiOpenOrigin.RESTORED_STATE)
            )
        )
    }

    @Test
    fun installReceiptDoesNotNavigate() {
        // 安装完成回执（needsReboot / 默认打开）绝不能变成一次自动跳转。
        assertFalse(
            WebUiOpenPolicy.mayNavigate(
                WebUiOpenRequest(moduleId, WebUiOpenOrigin.INSTALL_RECEIPT)
            )
        )
    }

    @Test
    fun unknownOrMissingOriginFailsClosed() {
        assertFalse(
            WebUiOpenPolicy.mayNavigate(
                WebUiOpenRequest(moduleId, WebUiOpenOrigin.UNKNOWN)
            )
        )
        assertFalse(WebUiOpenPolicy.mayNavigate(WebUiOpenRequest(moduleId, null)))
    }

    // ── 2. 显式动作仍然可用 ───────────────────────────────────────────────

    @Test
    fun explicitUserClickStillOpens() {
        assertTrue(
            WebUiOpenPolicy.mayNavigate(
                WebUiOpenRequest(moduleId, WebUiOpenOrigin.USER_CLICK)
            )
        )
    }

    @Test
    fun validatedDeepLinkStillOpens() {
        // IntentDispatcher 只在 ksu:// + id + token 全部通过后才构造这个请求。
        assertTrue(
            WebUiOpenPolicy.mayNavigate(
                WebUiOpenRequest(moduleId, WebUiOpenOrigin.DEEP_LINK, tokenValid = true)
            )
        )
    }

    @Test
    fun explicitOpenWithInvalidTokenIsRejected() {
        assertFalse(
            WebUiOpenPolicy.mayNavigate(
                WebUiOpenRequest(moduleId, WebUiOpenOrigin.USER_CLICK, tokenValid = false)
            )
        )
        assertFalse(
            WebUiOpenPolicy.mayNavigate(
                WebUiOpenRequest(moduleId, WebUiOpenOrigin.DEEP_LINK, tokenValid = false)
            )
        )
    }

    @Test
    fun explicitOpenWithoutModuleIdIsRejected() {
        assertFalse(
            WebUiOpenPolicy.mayNavigate(
                WebUiOpenRequest(null, WebUiOpenOrigin.USER_CLICK)
            )
        )
        assertFalse(
            WebUiOpenPolicy.mayNavigate(
                WebUiOpenRequest("   ", WebUiOpenOrigin.USER_CLICK)
            )
        )
    }

    // ── 3. pending：一次性、消费即清、不跨进程 ────────────────────────────

    @Test
    fun pendingIsConsumedExactlyOnceThenCleared() {
        val pending = PendingWebUiOpen()
        val request = WebUiOpenRequest(moduleId, WebUiOpenOrigin.USER_CLICK)
        assertTrue(pending.offer(request))
        assertTrue(pending.isPending())
        assertSame(request, pending.consume())
        assertNull(pending.consume())
        assertFalse(pending.isPending())
    }

    @Test
    fun secondRequestCannotOverwriteAPendingOne() {
        val pending = PendingWebUiOpen()
        assertTrue(pending.offer(WebUiOpenRequest(moduleId, WebUiOpenOrigin.USER_CLICK)))
        assertFalse(pending.offer(WebUiOpenRequest(moduleId, WebUiOpenOrigin.DEEP_LINK)))
        assertTrue(pending.isPending())
        assertTrue(pending.consume() != null)
    }

    @Test
    fun rejectedRequestNeverBecomesPending() {
        val pending = PendingWebUiOpen()
        assertFalse(pending.offer(WebUiOpenRequest(moduleId, WebUiOpenOrigin.PROCESS_START)))
        assertFalse(pending.offer(WebUiOpenRequest(moduleId, WebUiOpenOrigin.INSTALL_RECEIPT)))
        assertFalse(pending.offer(null))
        assertNull(pending.consume())
    }

    @Test
    fun processRecreationStartsWithNoPendingRequest() {
        // 进程内对象，不落盘：模拟「上次进程留下的请求」在重建后根本不存在。
        val previousProcess = PendingWebUiOpen()
        assertTrue(previousProcess.offer(WebUiOpenRequest(moduleId, WebUiOpenOrigin.USER_CLICK)))

        val recreatedProcess = PendingWebUiOpen()
        assertFalse(recreatedProcess.isPending())
        assertNull(recreatedProcess.consume())
    }

    // ── 4. 源码契约：后台路径不再启动模块 WebUI ───────────────────────────

    private fun source(path: String): String? = File(path).takeIf { it.isFile }?.readText()

    @Test
    fun soterLaneNeverStartsTheModuleWebUiOnItsOwn() {
        val text = source("src/main/java/dev/maplesu/manager/soter/SoterLane.kt")
        assumeTrue("SoterLane source unavailable", text != null)
        // 真机取证里 uid-0 的 am start 就是由这个宿主调用触发的；后台 lane 里必须没有它。
        assertFalse(
            "SoterLane must not call start_module_web_ui_server_async / openModuleWebUi",
            text!!.contains("openModuleWebUi")
        )
        // 唯一允许的入口是用户显式打开 WebUI 后的端口回传，且必须校验模块身份。
        assertTrue(text.contains("fun onExplicitWebUiOpened("))
        assertTrue(text.contains("moduleId != MODULE_ID32"))
    }

    @Test
    fun moduleWebUiLauncherOnlyAcceptsExplicitUserClick() {
        val launcher = source("src/main/java/dev/maplesu/manager/modules/ModuleWebUiLauncher.kt")
        assumeTrue("launcher source unavailable", launcher != null)
        assertTrue(launcher!!.contains("WebUiOpenPolicy.mayNavigate"))
        assertTrue(launcher.contains("origin: WebUiOpenOrigin"))

        val callSite = source("src/main/java/com/maplesu/core/ui/screen/module/ModuleScreen.kt")
        assumeTrue("call site unavailable", callSite != null)
        assertTrue(
            "the only launcher call site must be a user click",
            callSite!!.contains("WebUiOpenOrigin.USER_CLICK")
        )
    }

    @Test
    fun mainActivityStillStartsOnThePlainMainRoute() {
        val main = source("src/main/java/com/maplesu/core/ui/MainActivity.kt")
        assumeTrue("MainActivity source unavailable", main != null)
        assertTrue(main!!.contains("rememberNavigator(Route.Main)"))
        // 启动路由不接受模块状态或 Intent 决定：没有第二个启动路由来源。
        assertFalse(main.contains("rememberNavigator(Route.WebUi"))
        assertFalse(main.contains("rememberNavigator(Route.ModuleWebUi"))
    }
}
