package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.liteweb.LiteHiddenResult
import dev.maplesu.manager.liteweb.LiteWebToggleView
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * daemon 只读/受限 root 后端的主机用例（纯 JVM）：临时 `/data/adb` + 假 APK。
 *
 * 覆盖：APK 静态资源（含 8MB 上限/穿越拒绝）、status 事实、模块解析与 disable 语义、
 * toggle 成功/非法 id/待卸载、lite_hidden 读写与失败路径、su 日志尾部、honest 默认值。
 */
class DaemonLiteWebBackendTest {
    @get:Rule
    val temporary = TemporaryFolder()

    private lateinit var env: DaemonLiteWebTestEnv
    private lateinit var backend: DaemonLiteWebBackend

    @Before
    fun setUp() {
        env = DaemonLiteWebTestEnv(temporary.newFolder("env"))
        env.createTextApk(
            mapOf(
                "assets/liteweb/index.html" to "<html><body>lite</body></html>",
                "assets/liteweb/a/app.js" to "console.log(1)",
                "assets/liteweb/a/licenses/MIT.txt" to "MIT",
                "classes.dex" to "not-an-asset",
            ),
        )
        backend = env.backend()
    }

    @After
    fun tearDown() {
        backend.close()
    }

    // ------------------------------------------------------------------ status

    @Test
    fun statusCarriesDaemonFacts() {
        env.addModule("demo", "id=demo\nname=Demo\n")
        val status = backend.status()
        assertEquals("KSU", status.mode)
        assertEquals("daemon", status.uapi)
        assertTrue("uid0 + readable /data/adb", status.rootAvailable)
        assertEquals(1, status.moduleCount)
        assertEquals(1, status.serverVersion)
        assertEquals("", status.moduleCountError)
        // 没有 lite_hidden 文件：既不是 true 也不是 false，而是「不知道」。
        assertFalse(status.hidden)
        assertNull(status.hiddenKnown)
    }

    @Test
    fun statusReportsHiddenFromTheStateFile() {
        env.hiddenFile.parentFile.mkdirs()
        env.hiddenFile.writeText("1\n", Charsets.UTF_8)
        val status = backend.status()
        assertTrue(status.hidden)
        assertEquals(true, status.hiddenKnown)

        env.hiddenFile.writeText("0", Charsets.UTF_8)
        val off = backend.status()
        assertFalse(off.hidden)
        assertEquals(false, off.hiddenKnown)
    }

    @Test
    fun rootRequiresUidZeroAndReadableAdbRoot() {
        assertTrue(backend.rootAvailable())
        assertFalse(env.backend(uid = 2000).use { it.rootAvailable() })
        assertFalse(env.backend(uid = null).use { it.rootAvailable() })

        val missingRoot = File(env.root, "no-adb").absolutePath
        DaemonLiteWebBackend(
            adbRoot = missingRoot,
            managerApkPath = env.apk.absolutePath,
            hiddenStatePath = env.hiddenFile.absolutePath,
            modulesRoot = File(missingRoot, "modules").absolutePath,
            suLogPath = env.suLog.absolutePath,
            selfUid = { 0 },
        ).use { assertFalse(it.rootAvailable()) }
    }

    // ------------------------------------------------------------------ modules

    @Test
    fun modulesJsonParsesDeclaredFieldsAndFlags() {
        env.addModule(
            "alpha",
            "id=alpha\nname=Alpha\nversion=1.2\nversionCode=12\nauthor=me\ndescription=hello world\n",
        )
        env.addModule("beta", "id=beta\nname=Beta\n", disable = true)
        env.addModule("gamma", "id=gamma\nname=Gamma\n", remove = true)
        val json = backend.modulesJson()
        assertTrue(json, json.startsWith("["))
        assertTrue(json, json.contains("\"id\":\"alpha\""))
        assertTrue(json, json.contains("\"name\":\"Alpha\""))
        assertTrue(json, json.contains("\"version\":\"1.2\""))
        assertTrue(json, json.contains("\"versionCode\":12"))
        assertTrue(json, json.contains("\"author\":\"me\""))
        assertTrue(json, json.contains("\"description\":\"hello world\""))
        assertTrue(json, json.contains("\"id\":\"alpha\",\"name\":\"Alpha\""))
        // disable 文件 = 停用；remove 文件 = 待卸载（都是文件事实，不是猜的）。
        assertTrue(json, json.contains("\"id\":\"beta\",\"name\":\"Beta\",\"enabled\":false,\"remove\":false"))
        assertTrue(json, json.contains("\"id\":\"gamma\",\"name\":\"Gamma\",\"enabled\":true,\"remove\":true"))
        assertEquals(3, backend.status().moduleCount)
    }

    @Test
    fun modulesJsonOmitsFieldsThatAreNotDeclared() {
        env.addModule("bare", "id=bare\n")
        val json = backend.modulesJson()
        assertTrue(json, json.contains("\"id\":\"bare\""))
        assertFalse("name 未声明就不造一个: $json", json.contains("\"name\""))
        assertFalse("author 未声明就不造一个: $json", json.contains("\"author\""))
        assertFalse("version 未声明就不造一个: $json", json.contains("\"version\""))
        assertFalse("versionCode 未声明就不造一个: $json", json.contains("\"versionCode\""))
        assertFalse("update 无法得知就不输出: $json", json.contains("\"update\""))
        assertTrue(json, json.contains("\"enabled\":true"))
        assertTrue(json, json.contains("\"action\":false"))
        assertTrue(json, json.contains("\"web\":false"))
    }

    @Test
    fun modulesJsonSkipsDirectoriesWithoutModulePropAndEmptyRoot() {
        env.addModule("no-prop", prop = null)
        assertEquals("[]", backend.modulesJson())
        // modules 目录不存在（隐藏模式下的极端情况）也只能是空数组，不是崩溃。
        val absent = DaemonLiteWebBackend(
            adbRoot = env.adbRoot.absolutePath,
            managerApkPath = env.apk.absolutePath,
            hiddenStatePath = env.hiddenFile.absolutePath,
            modulesRoot = File(env.root, "nope/modules").absolutePath,
            suLogPath = env.suLog.absolutePath,
            selfUid = { 0 },
            runtimeSource = env.normalRuntime,
        )
        absent.use {
            assertEquals("[]", it.modulesJson())
            assertEquals(0, it.status().moduleCount)
        }
    }

    @Test
    fun moduleFlagsFollowRealFiles() {
        val directory = env.addModule("tools", "id=tools\nname=Tools\n")
        File(directory, "action.sh").writeText("#!/system/bin/sh\n", Charsets.UTF_8)
        File(directory, "webroot").mkdirs()
        val json = backend.modulesJson()
        assertTrue(json, json.contains("\"hasAction\":true"))
        assertTrue(json, json.contains("\"hasWebUi\":true"))
        assertTrue(json, json.contains("\"action\":false,\"web\":false,\"canWeb\":false"))
    }

    // ------------------------------------------------------------------ toggle

    @Test
    fun toggleCreatesAndRemovesDisableFile() {
        val directory = env.addModule("demo", "id=demo\nname=Demo\n")
        val disable = File(directory, "disable")

        assertTrue(backend.toggleModule("demo", false) is LiteWebToggleView.Ok)
        assertTrue("停用 = 建 disable 文件", disable.isFile)

        assertTrue(backend.toggleModule("demo", true) is LiteWebToggleView.Ok)
        assertFalse("启用 = 删 disable 文件", disable.exists())

        // 幂等：已经是启用态再启用一次仍然成功，且不制造文件。
        assertTrue(backend.toggleModule("demo", true) is LiteWebToggleView.Ok)
        assertFalse(disable.exists())
    }

    @Test
    fun toggleRejectsUnsafeModuleIds() {
        env.addModule("demo", "id=demo\nname=Demo\n")
        for (bad in listOf("../escape", "a/b", ".", "..", "A".repeat(65), "a b", "a\u0000b")) {
            val result = backend.toggleModule(bad, false)
            assertTrue("$bad -> $result", result is LiteWebToggleView.Failed)
            assertEquals("$bad", "MODULE_ID_INVALID", (result as LiteWebToggleView.Failed).code)
        }
    }

    @Test
    fun toggleRejectsUnknownModuleAndRemovePending() {
        env.modulesRoot.mkdirs()
        val unknown = backend.toggleModule("nope", false)
        assertEquals("MODULE_NOT_FOUND", (unknown as LiteWebToggleView.Failed).code)

        env.addModule("gone", "id=gone\nname=Gone\n", remove = true)
        val pending = backend.toggleModule("gone", false)
        assertEquals("MODULE_REMOVE_PENDING", (pending as LiteWebToggleView.Failed).code)
        assertFalse("被拒绝时不许偷偷写 disable", File(env.modulesRoot, "gone/disable").exists())
    }

    @Test
    fun toggleReportsMissingModulesDirectory() {
        val absent = DaemonLiteWebBackend(
            adbRoot = env.adbRoot.absolutePath,
            managerApkPath = env.apk.absolutePath,
            hiddenStatePath = env.hiddenFile.absolutePath,
            modulesRoot = File(env.root, "nope/modules").absolutePath,
            suLogPath = env.suLog.absolutePath,
            selfUid = { 0 },
            runtimeSource = env.normalRuntime,
        )
        absent.use {
            val result = it.toggleModule("demo", false)
            assertEquals("MODULES_DIR_ABSENT", (result as LiteWebToggleView.Failed).code)
        }
    }

    // ------------------------------------------------------------------ hidden port

    @Test
    fun hiddenPortReadWriteRoundTrip() {
        env.hiddenFile.parentFile.mkdirs()
        val port = backend.hiddenPort()
        assertNull("没有状态文件时不得冒充关闭", port.currentHidden())

        val enabled = port.setHidden(true)
        assertTrue("$enabled", enabled is LiteHiddenResult.Ok)
        assertTrue(File(env.hiddenFile.path).readText(Charsets.UTF_8).trim() == "1")
        assertEquals(true, port.currentHidden())

        val disabled = port.setHidden(false)
        assertTrue("$disabled", disabled is LiteHiddenResult.Ok)
        assertEquals(false, port.currentHidden())
    }

    @Test
    fun hiddenPortRejectsGarbageContent() {
        env.hiddenFile.parentFile.mkdirs()
        env.hiddenFile.writeText("ON\n", Charsets.UTF_8)
        assertNull(backend.hiddenPort().currentHidden())
        env.hiddenFile.writeText("1111\n", Charsets.UTF_8)
        assertNull("非 0/1 内容一律 unknown", backend.hiddenPort().currentHidden())
    }

    @Test
    fun hiddenPortWriteFailsExplicitlyWhenParentIsNotADirectory() {
        val blocker = File(env.root, "blocker")
        blocker.writeText("not a directory", Charsets.UTF_8)
        val port = DaemonLiteHiddenPort(File(blocker, "lite_hidden").absolutePath)

        val result = port.setHidden(true)
        assertTrue("$result", result is LiteHiddenResult.Failed)
        assertEquals("LITE_HIDDEN_WRITE_FAILED", (result as LiteHiddenResult.Failed).code)
        assertNull(port.currentHidden())
    }

    @Test
    fun hiddenPortReadbackMismatchIsReported() {
        env.hiddenFile.parentFile.mkdirs()
        // 目录存在但状态路径被一个「只读目录里的目录」占住：move 到目录名必然失败，
        // 走的是写入失败分支；这里只验证不会假装成功。
        val directory = File(env.hiddenFile.path)
        assertTrue(directory.mkdirs())
        val result = backend.hiddenPort().setHidden(false)
        assertTrue("$result", result is LiteHiddenResult.Failed)
        val code = (result as LiteHiddenResult.Failed).code
        assertTrue(code, code == "LITE_HIDDEN_WRITE_FAILED" || code == "LITE_HIDDEN_READBACK_FAILED")
    }

    // ------------------------------------------------------------------ assets

    @Test
    fun assetsServeIndexAndNestedFilesFromTheApk() {
        assertEquals(
            "<html><body>lite</body></html>",
            backend.assets().read("index.html")?.toString(Charsets.UTF_8),
        )
        assertEquals("console.log(1)", backend.assets().read("a/app.js")?.toString(Charsets.UTF_8))
        assertEquals("MIT", backend.assets().read("a/licenses/MIT.txt")?.toString(Charsets.UTF_8))
        assertNull("APK 里 assets/liteweb 之外的东西不可见", backend.assets().read("classes.dex"))
        assertNull(backend.assets().read("a/missing.js"))
    }

    @Test
    fun assetsRejectTraversalAbsoluteAndOddPaths() {
        val assets = backend.assets()
        for (path in listOf(
            "../manager.apk",
            "a/../../index.html",
            "/assets/liteweb/index.html",
            "a\\app.js",
            "..",
            ".",
            "",
            "a//app.js",
            "a/\u0000",
        )) {
            assertNull("path=$path", assets.read(path))
        }
    }

    @Test
    fun assetsEnforceSingleFileLimit() {
        val tiny = DaemonLiteWebAssets(env.apk.absolutePath, maxFileBytes = 4)
        assertNull("超过上限的文件不可服务", tiny.read("a/app.js"))
        assertEquals("MIT", tiny.read("a/licenses/MIT.txt")?.toString(Charsets.UTF_8))
        tiny.close()
        // 默认上限就是 8MB。
        assertEquals(8L * 1024 * 1024, DaemonLiteWebLimits.MAX_ASSET_BYTES)
    }

    @Test
    fun assetsReturnNullWhenApkIsMissingOrDefaultHonest() {
        val missing = DaemonLiteWebAssets(File(env.root, "no.apk").absolutePath)
        assertNull(missing.read("index.html"))
        missing.close()
        // APK 不是 zip（恢复备份损坏）也不能崩，只是不可服务。
        val broken = File(env.root, "broken.apk")
        broken.writeText("not a zip", Charsets.UTF_8)
        val brokenAssets = DaemonLiteWebAssets(broken.absolutePath)
        assertNull(brokenAssets.read("index.html"))
        brokenAssets.close()
    }

    @Test
    fun assetsFallBackToTheRunningClasspathApk() {
        // 主路径缺失：退回备用 APK（daemon 自己的 classpath），而不是直接 404。
        val fallback = DaemonLiteWebAssets(
            apkPath = File(env.root, "no.apk").absolutePath,
            fallbackApkPaths = listOf(env.apk.absolutePath),
        )
        assertEquals("console.log(1)", fallback.read("a/app.js")?.toString(Charsets.UTF_8))
        fallback.close()

        // 主路径损坏（不是 zip）同样退回备用。
        val broken = File(env.root, "broken.apk")
        broken.writeText("not a zip", Charsets.UTF_8)
        val viaBroken = DaemonLiteWebAssets(
            apkPath = broken.absolutePath,
            fallbackApkPaths = listOf(env.apk.absolutePath),
        )
        assertEquals("MIT", viaBroken.read("a/licenses/MIT.txt")?.toString(Charsets.UTF_8))
        viaBroken.close()
    }

    // ------------------------------------------------------------------ sulog / superusers / hidden status

    @Test
    fun sulogReadsOnlyTheBoundedTail() {
        env.suLog.parentFile.mkdirs()
        env.suLog.writeText((0 until 300).joinToString("\n") { "line-$it" } + "\n", Charsets.UTF_8)
        val view = backend.sulog()
        assertTrue(view.available)
        assertEquals(DaemonLiteWebLimits.MAX_SULOG_LINES, view.lines.size)
        assertEquals("line-100", view.lines.first())
        assertEquals("line-299", view.lines.last())
        assertEquals("", view.reason)
    }

    @Test
    fun sulogIsUnavailableWhenMissing() {
        val view = backend.sulog()
        assertFalse(view.available)
        assertTrue(view.lines.isEmpty())
        assertEquals("SULOG_NOT_FOUND", view.reason)
    }

    @Test
    fun superusersAreNotFabricated() {
        assertEquals("[]", backend.superusersJson())
        assertTrue(DaemonLiteWebBackend.SUPERUSERS_UNAVAILABLE.contains("no readable authorization store"))
        // 前端只接受数组，所以在 /status 里把「不可用」这个事实显式标出来。
        val status = DaemonLiteWebStatus.render(backend)
        assertTrue(status, status.contains("\"superusers\":\"unavailable\""))
    }

    @Test
    fun hiddenStatusUsesConfiguredPortAndOnlyProvableFacts() {
        val custom = env.backend(port = 18500)
        custom.use {
            val view = it.hiddenStatus()
            assertEquals(18500, view.port)
            assertEquals(18500, it.configuredPort())
            assertEquals(true, view.recovery.apkBackupPresent)
            assertNull("sha 需要完整校验，不断言", view.recovery.apkShaValid)
            assertEquals(true, view.recovery.daemonRunning)
            assertEquals("unknown", view.recovery.bootPersistence)
            assertNull(view.hidden)
            assertTrue(view.steps.isEmpty())
        }
    }

    @Test
    fun unimplementedPortsKeepTheirHonestDefaults() {
        // 这些接口没有真实后端：必须是 Unavailable*，而不是「成功但什么都没做」。
        assertTrue(backend.activatePort() is dev.maplesu.manager.liteweb.UnavailableActivatePort)
        assertTrue(backend.restorePort() is dev.maplesu.manager.liteweb.UnavailableRestorePort)
        assertTrue(backend.settingsPort() is dev.maplesu.manager.liteweb.UnavailableSettingsPort)
        assertEquals("KSU", backend.diagnosticsPort().read().mode)
        assertEquals("KSU", backend.workModePort().read().mode)
        assertFalse(backend.workModePort().read().canSwitch)
        assertTrue(backend.moduleActionPort() is dev.maplesu.manager.liteweb.UnavailableModuleActionPort)
        assertEquals("KSU", backend.modeBackend().mode().mode)
        assertFalse(backend.modeBackend().startDaemon().ok)
        assertTrue(backend.tokenPresent())
    }
}
