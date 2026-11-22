package dev.maplesu.manager.modules.compat

import com.maplesu.core.ui.screen.flash.FlashIt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume
import org.junit.Test
import java.io.File

/**
 * W3-K：安装入口 → 兼容门动作的传递口径（开发方案 §4.1）。
 *
 * 这里只锁**在 JVM 上可断言**的那部分：`FlashIt.FlashModules.action` 的缺省值必须是
 * [UltraModuleAction.INSTALL]，且显式传入的 UPDATE / MARKET_QUICK_ACTION 不能被构造或 `copy`
 * 改写。普通安装、外部 Intent 安装这两类入口没有显式传 action，它们能正确归因为「安装」，
 * 靠的就是这个缺省值；市场更新 / 市场快捷动作只要在 Route 构造点传一次，就必须一路保住。
 *
 * 不能在这里断言的（见 `.analysis/ultra-module-crash-remediation-20261031/w3-k/EVIDENCE.md` §4）：
 * `Route.Flash` 的 Parcel 往返、`KsuCli.flashModule` 把 action 交给 `backend.install` 的端到端、
 * 被门拦下时的回执文案——它们需要 Android 运行时（`ksuApp`/`Uri`/`Parcel`），仓库没有
 * Robolectric，按约束也不新增依赖。
 */
class FlashEntryActionTest {

    @Test
    fun flashModulesDefaultsToInstall() {
        // 缺省动作就是普通安装：本地文件安装与 Intent 安装都不显式传 action。
        val flash = FlashIt.FlashModules(emptyList())
        assertEquals(UltraModuleAction.INSTALL, flash.action)
    }

    @Test
    fun explicitEntryActionsArePreserved() {
        // 更新与市场快捷动作在各自的 Route 构造点显式传入，不能在中间被默认值吃掉。
        val update = FlashIt.FlashModules(emptyList(), UltraModuleAction.UPDATE)
        val market = FlashIt.FlashModules(emptyList(), UltraModuleAction.MARKET_QUICK_ACTION)
        assertEquals(UltraModuleAction.UPDATE, update.action)
        assertEquals(UltraModuleAction.MARKET_QUICK_ACTION, market.action)
        // 动作参与相等性：同 uri 的更新请求与安装请求不是同一个路由键。
        assertNotEquals(update, FlashIt.FlashModules(emptyList()))
    }

    @Test
    fun copyKeepsTheEntryAction() {
        // 防御未来有人用 copy()/解构重建路由时把动作丢掉。
        val update = FlashIt.FlashModules(emptyList(), UltraModuleAction.UPDATE)
        assertEquals(UltraModuleAction.UPDATE, update.copy(uris = emptyList()).action)
        assertEquals(UltraModuleAction.UPDATE, update.component2())
    }

    @Test
    fun installAndUpdateAreDistinctActions() {
        // 命中条件与动作无关（W2-0 §1.5），但回执与证据按动作归因，所以不能退化成同一个值。
        assertNotEquals(UltraModuleAction.INSTALL, UltraModuleAction.UPDATE)
        assertNotEquals(UltraModuleAction.INSTALL, UltraModuleAction.MARKET_QUICK_ACTION)
        assertNotEquals(UltraModuleAction.UPDATE, UltraModuleAction.MARKET_QUICK_ACTION)
    }

    /**
     * W4-PATCH：两个市场入口调用的**源码契约**断言（ModuleScreen 更新 / ModuleRepoScreen 市场快捷动作）。
     *
     * 这两处都在 `@Composable` 函数体里，唯一行为就是一句 `navigator.push(...)`；没有可在 JVM 上直接
     * 调用的纯函数，仓库也不带 Robolectric（按约束不新增依赖），所以这里按文本定位调用点，只锁住
     * 「动作实参没有被丢掉 / 没有退回缺省」这一件事。它**不能**证明运行期 `data.action`、`Parcel`
     * 往返或被拦回执文案——那些见 w4-patch/EVIDENCE.md 的 `not_run`/`unknown` 清单。
     *
     * 工作目录不在仓库内时（外部 runner）用 [Assume] 跳过，避免环境差异造成假失败；Gradle 的
     * `:manager:testDebugUnitTest` 工作目录是 `manager/`，向上找仓库根可以命中。
     */
    @Test
    fun marketEntryCallSitesPassTheirAction() {
        val here = File(System.getProperty("user.dir")).absoluteFile
        val root = generateSequence(here) { it.parentFile }.firstOrNull { dir ->
            File(dir, UPDATE_SITE).isFile && File(dir, MARKET_SITE).isFile
        }
        if (root == null) {
            Assume.assumeTrue("工作目录 $here 不在 MapleSU 仓库内，跳过源码契约断言", false)
            return
        }
        val updateSite = File(root, UPDATE_SITE).readText()
        val marketSite = File(root, MARKET_SITE).readText()

        assertTrue(
            "市场/Registry 更新（ModuleScreen: onConfirmUpdate → onDownloaded）必须显式传 UPDATE",
            updateSite.contains("FlashModules(listOf(uri), $ACTION_PREFIX.UPDATE)"),
        )
        assertTrue(
            "市场快捷动作（ModuleRepoScreen 详情页一键安装）必须显式传 MARKET_QUICK_ACTION",
            marketSite.contains("FlashModules(listOf(uri), $ACTION_PREFIX.MARKET_QUICK_ACTION)"),
        )
        // 反向断言：两处都不能再退回「不传动作」的写法，否则归因又变回 INSTALL。
        assertFalse(UPDATE_SITE, updateSite.contains("FlashModules(listOf(uri))"))
        assertFalse(MARKET_SITE, marketSite.contains("FlashModules(listOf(uri))"))
        // 普通安装（模块页选本地 zip / 外部 Intent）仍走缺省值，不能被顺手改成别的入口动作。
        assertTrue(
            "普通安装入口应继续使用 FlashModules(uris) 的缺省动作",
            updateSite.contains("FlashModules(uris)"),
        )
    }

    private companion object {
        const val UPDATE_SITE = "manager/src/main/java/com/maplesu/core/ui/screen/module/ModuleScreen.kt"
        const val MARKET_SITE = "manager/src/main/java/com/maplesu/core/ui/screen/modulerepo/ModuleRepoScreen.kt"
        const val ACTION_PREFIX = "dev.maplesu.manager.modules.compat.UltraModuleAction"
    }
}
