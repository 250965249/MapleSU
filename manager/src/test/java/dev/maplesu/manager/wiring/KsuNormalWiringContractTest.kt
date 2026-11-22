// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.wiring

import dev.maplesu.manager.ksu.KsuTestPaths
import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Normal（KSU）"最后一公里"接线的**源码契约**（2026-11-01 收尾）。
 *
 * 这些行为大多在 Android 边界上（`Context`/libsu/Compose），主机单测无法端到端执行；
 * 本仓库既有的做法是「纯逻辑抽出来单测 + 接线点做源码断言」
 * （见 `com/maplesu/core/ui/security/StealthAndDaemonPolicyTest`）。
 * 纯逻辑部分另有覆盖：
 * - 后端装配/端口注入 → `KsuBackendRegistryTest`
 * - root shell 提权/探针/部署状态 → `KsuRootWiringTest`
 * - 模块根隔离 → `ModeModuleRootIsolationTest`
 * - sulog 路径与 transport → `SulogModePathTest`
 * - AppProfile 状态 → `KsuAppProfileStateTest`
 */
class KsuNormalWiringContractTest {

    private fun mainSource(relative: String): String {
        val file = File(KsuTestPaths.managerDir(), "src/main/java/$relative")
        assertTrue("missing source: ${file.path}", file.isFile)
        return file.readText()
    }

    // ── 1. ksud 用户态部署：只有 KSU 模式接线时才做 ─────────────────────

    @Test
    fun modeBootstrapWiresKsuBackendsOnActivation() {
        val text = mainSource("dev/maplesu/manager/workmode/boot/ModeBootstrap.kt")
        assertTrue(
            "KSU 激活后必须装配后端（ksuFactory/root executor/ksud 部署）",
            text.contains("dev.maplesu.manager.workmode.backend.KsuBackendRegistry"),
        )
        assertTrue(text.contains("installProduction("))
        // 恢复路径（清数据 restore / 重启收敛）也要补一次接线。
        assertTrue(text.contains("ModeRuntime.active"))
    }

    @Test
    fun applicationInstallsKsuLogging() {
        val text = mainSource("com/maplesu/core/KernelSUApplication.kt")
        assertTrue(text.contains("KsuBackendRegistry.installLogging()"))
    }

    // ── 2. RootExec：KSU executor 由接线层注入 ──────────────────────────

    @Test
    fun rootExecCarriesKsuExecutor() {
        val router = mainSource("dev/maplesu/manager/runtime/RootExecutionRouter.kt")
        assertTrue(router.contains("KSU,"))
        assertTrue(router.contains("fun installKsu("))
        assertTrue(router.contains("fun ksuExecutor("))
        assertTrue("KSU 模式必须先试 KSU executor", router.contains("WorkMode.KSU -> listOfNotNull(ksuProvider(), ultraEnv)"))
        assertFalse(
            "RootExecutionRouter 不得直接 import KSU 后端（保持门面边界）",
            router.contains("import dev.maplesu.manager.ksu"),
        )
    }

    @Test
    fun ksuRootExecutorIsExplicitlyFailClosed() {
        val text = KsuTestPaths.managerDir()
            .resolve("src/ksu/java/dev/maplesu/manager/ksu/KsuRootExecutor.kt").readText()
        assertTrue(text.contains("WorkMode.KSU"))
        assertTrue(text.contains("KSU_ROOT_CHANNEL_UNAVAILABLE") || text.contains("KsuRootChannel.UNAVAILABLE"))
        assertTrue(text.contains("RootBackend.KSU"))
    }

    // ── 3. 模块后端注入 + 命令走 root shell ─────────────────────────────

    @Test
    fun registryInjectsKsuModuleFactory() {
        val text = mainSource("dev/maplesu/manager/workmode/backend/KsuBackendRegistry.kt")
        assertTrue(text.contains("ModuleBackendPorts.ksuFactory ="))
        assertTrue(text.contains("KsuBackends.wireDeployed("))
        assertTrue(text.contains("KsuCommands.DEPLOYED_DAEMON"))
        assertTrue(text.contains("ensureDeployed("))
        assertTrue("部署失败必须是显式状态", text.contains("KsuBootstrapResult"))
    }

    @Test
    fun commandBackendRunsInRootShellInsteadOfAppUid() {
        val text = KsuTestPaths.managerDir()
            .resolve("src/ksu/java/dev/maplesu/manager/ksu/KsuCommandBackend.kt").readText()
        assertFalse(
            "生产装配不得再用 app uid 的 libsu runner（审计 §8）",
            text.contains("runner = LibsuShellRunner()"),
        )
        assertTrue(text.contains("KsuRootShell.runner()"))
        assertTrue(text.contains("forDeployedDaemon"))
        assertTrue(text.contains("DEPLOYED_DAEMON"))
    }

    @Test
    fun productionRootExecutorForwardsBothCommandTimeouts() {
        val registry = mainSource("dev/maplesu/manager/workmode/backend/KsuBackendRegistry.kt")
        assertTrue(registry.contains("override fun exec(commandLine: String, timeoutMs: Long)"))
        assertTrue(registry.contains("override fun execInGlobalMount(commandLine: String, timeoutMs: Long)"))
        assertTrue(registry.contains("exec(application, commandLine, globalMnt = false, timeoutMs = timeoutMs)"))
        assertTrue(registry.contains("exec(application, commandLine, globalMnt = true, timeoutMs = timeoutMs)"))
        val channel = mainSource("dev/maplesu/manager/ksu/KsuRootChannel.kt")
        assertTrue(channel.contains("fun exec(context: Context, command: String, globalMnt: Boolean, timeoutMs: Long)"))
        assertTrue(channel.contains("execOn(shell, command, timeoutMs)"))
    }

    // ── 4. 模块操作分派：KSU 走 ksud，不走 Lite 脚本后端 ────────────────

    @Test
    fun moduleOperationsDispatchToKsudInKsuMode() {
        val text = mainSource("com/maplesu/core/ui/util/KsuCli.kt")
        assertTrue("flashModule 在 KSU 下必须走 ksud 安装器", text.contains("installModuleResult(file, onStdout, onStderr)"))
        assertTrue("Normal 安装等待须响应调用方取消", text.contains("val installed = runInterruptible {"))
        assertTrue("Normal 安装取消须原样传播", text.contains("exception is CancellationException"))
        assertTrue("runModuleAction 在 KSU 下必须走 ksud action", text.contains("runModuleAction(moduleId"))
        assertTrue("listModules 在 KSU 下不得回落 Lite", text.contains("moduleListJson()"))
        val listing = text.substringAfter("fun listModules(): String {").substringBefore("// Hook owns")
        assertTrue(listing.contains("?: error(\"KSU_MODULE_BACKEND_UNAVAILABLE\")"))
        assertFalse(listing.contains("?: \"[]\""))
        val count = text.substringAfter("fun getModuleCount(): Int =").substringBefore("fun getSuperuserCount()")
        assertTrue(count.contains("JSONArray(listModules()).length()"))
        assertFalse(count.contains("getOrDefault(0)"))
        // Ultra 运行时部署不能在 Normal 下跑（跨模式污染）
        assertTrue(text.contains("ultra runtime deployment skipped"))
        val manifest = KsuTestPaths.managerDir().resolve("src/main/AndroidManifest.xml").readText()
        val dispatcher = mainSource("com/maplesu/core/ui/navigation3/IntentDispatcher.kt")
        val zipTypes = dispatcher.substringAfter("private val ZIP_MIME_TYPES = setOf(").substringBefore(')')
        for (mime in listOf("application/zip", "application/x-zip-compressed", "application/x-zip")) {
            assertTrue("manifest ZIP entry missing: $mime", manifest.contains("android:mimeType=\"$mime\""))
            assertTrue("intent ZIP entry missing: $mime", zipTypes.contains("\"$mime\""))
        }
        assertTrue(dispatcher.contains("viewUri.scheme == \"content\" && intent.type in ZIP_MIME_TYPES"))
    }

    // ── 5. 设置：KSU 分派到 feature + save ──────────────────────────────

    @Test
    fun settingsDispatchToKsuFeatureWithSave() {
        val text = mainSource("com/maplesu/core/data/repository/SettingsRepositoryImpl.kt")
        assertTrue(text.contains("KsuBackendRegistry.featurePort()"))
        assertTrue("feature 写入必须带持久化", text.contains("ksuFeature?.set("))
        assertTrue(text.contains("ksuFeature?.save()"))
        assertTrue(text.contains("workmode.backend.KsuBackendRegistry"))
    }

    @Test
    fun daemonPathPolicyPointsAtDeployedKsudForKsu() {
        val cli = mainSource("com/maplesu/core/ui/util/KsuCli.kt")
        val start = cli.indexOf("internal fun getKsuDaemonPath()")
        assertTrue("getKsuDaemonPath 必须存在", start >= 0)
        val body = cli.substring(start, minOf(cli.length, start + 1200))
        val ksuBranch = body.indexOf("WorkMode.KSU")
        val liteDaemon = body.indexOf("libksud.so")
        assertTrue("KSU 分支必须在 libksud.so 兜底之前", ksuBranch in 0 until liteDaemon)
        assertTrue(body.contains("KsuDaemonPolicy.ksuDaemonPath()"))

        val policy = mainSource("com/maplesu/core/ui/util/KsuDaemonPolicy.kt")
        assertTrue(policy.contains("const val DEPLOYED_KSUD = \"/data/adb/ksud\""))
        assertTrue(policy.contains("const val WORKDIR_KSUD = \"/data/adb/ksu/bin/ksud\""))
    }

    // ── 6. AppProfile：KSU 不碰 Lite 探测；模板入口不再空实现 ────────────

    @Test
    fun appProfileSkipsLiteProbeInKsuMode() {
        val text = mainSource("com/maplesu/core/ui/screen/appprofile/AppProfileScreen.kt")
        val ksuBranch = text.indexOf("ksuSuState(")
        val liteProbe = text.indexOf("DirectPolicy.grantedUids(")
        assertTrue("KSU 分支必须使用 KSU 语义", ksuBranch >= 0)
        assertTrue("Lite 投递探测只能出现在非 KSU 分支", liteProbe > ksuBranch)
        assertTrue(text.contains("WorkMode.KSU"))
    }

    @Test
    fun appProfileTemplateEntriesAreWired() {
        val text = mainSource("com/maplesu/core/ui/screen/appprofile/AppProfileScreen.kt")
        assertFalse("模板入口不能是空实现", text.contains("onViewTemplate = {}"))
        assertFalse("模板入口不能是空实现", text.contains("onManageTemplate = {}"))
        assertTrue(text.contains("Route.AppProfileTemplate"))
        assertTrue(text.contains("Route.TemplateEditor"))
        val cli = mainSource("com/maplesu/core/ui/util/KsuCli.kt")
        val quoting = cli.substringAfter("private fun String.shellQuote(): String = ").substringBefore('\n').trim()
        assertTrue(quoting.startsWith("\"'\" + replace("))
        assertTrue(quoting.contains("\"'\\\\''\""))
        assertTrue(quoting.endsWith(" + \"'\""))
        for (command in listOf("sepolicy check \${rules.shellQuote()}",
            "profile get-sepolicy \${pkg.shellQuote()}",
            "profile set-sepolicy \${pkg.shellQuote()} \${rules.shellQuote()}",
            "profile get-template \${id.shellQuote()}",
            "profile set-template \${id.shellQuote()} \${template.shellQuote()}",
            "profile delete-template \${id.shellQuote()}")) {
            assertTrue("profile argument must use the shared token quoting: $command", cli.contains(command))
        }
    }

    // ── 7. 模式隔离：Lite boot 只在 LITE；模块树发布只在 LITE ───────────

    @Test
    fun liteModuleBootServiceAndReceiverAreModeGated() {
        val service = mainSource("dev/maplesu/manager/modules/LiteModuleBootService.kt")
        assertTrue(service.contains("LiteModuleModePolicy.allowsRun"))
        assertTrue("onStartCommand 必须先过模式门", service.contains("if (!isLiteMode())"))
        val receiver = mainSource("dev/maplesu/manager/modules/LiteModuleBootReceiver.kt")
        assertTrue(receiver.contains("LiteModuleModePolicy.allowsRun") || receiver.contains("allowsRun("))
    }

    @Test
    fun moduleTreePublishIsModeGated() {
        val text = mainSource("dev/maplesu/manager/modules/ModuleTree.kt")
        assertTrue(text.contains("MODULE_TREE_MODE_REJECTED"))
        assertTrue(text.contains("allowsPublish(ModeRuntime.active)"))
    }

    // ── 8. WebUI：后端不可用要显式报错，不折叠成 "no such module" ────────

    @Test
    fun webViewHelperSurfacesBackendErrors() {
        val text = mainSource("com/maplesu/core/ui/webui/WebViewHelper.kt")
        assertFalse(
            "getOrDefault(emptyList()) 会把'后端不可用'伪装成'模块不存在'",
            text.contains("getOrDefault(emptyList())"),
        )
        assertTrue(text.contains("getOrElse"))
    }

    // ── 9. sulog 路径按模式 ────────────────────────────────────────────

    @Test
    fun sulogDirectoryIsModeScoped() {
        val text = mainSource("com/maplesu/core/ui/util/SulogHelper.kt")
        assertTrue(text.contains("\"/data/adb/ksu/log\""))
        assertTrue(text.contains("sulogDirectory("))
        assertTrue(text.contains("KsuRootShellSulogTransport"))
    }
}
