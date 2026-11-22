package dev.maplesu.manager.liteweb

/** 主机测试共用 fixture：固定 token + 可注入事实的后端替身（含 activate/restore/settings 端口）。 */
internal object LiteWebTestFixtures {
    val TOKEN: String = "a".repeat(LiteWebConstants.TOKEN_HEX_LENGTH)
    val OTHER_TOKEN: String = "b".repeat(LiteWebConstants.TOKEN_HEX_LENGTH)
    const val HOST = "127.0.0.1:18427"
    const val PREFIX = LiteWebConstants.PATH_PREFIX

    fun target(pathAfterToken: String = ""): String = "/$PREFIX/$TOKEN$pathAfterToken"

    fun request(
        method: String = "GET",
        target: String = target(),
        host: String? = HOST,
        body: ByteArray = ByteArray(0),
        remoteLoopback: Boolean = true,
    ): LiteWebHttpRequest {
        val headers = LinkedHashMap<String, String>()
        if (host != null) headers["Host"] = host
        return LiteWebHttpRequest(method, target, headers, body, remoteLoopback)
    }

    fun handler(backend: FakeBackend, token: String? = TOKEN): LiteWebRequestHandler =
        LiteWebRequestHandler(tokenProvider = { token }, backend = backend)

    fun ok(name: String = "step") = LiteWebRestoreStep(name, true)
}

internal class FakeAssets(
    private val contents: Map<String, ByteArray> = mapOf(
        "index.html" to "<html><body>lite</body></html>".toByteArray(),
        "app.css" to "body{color:#fff}".toByteArray(),
    ),
) : LiteWebAssets {
    val requested = mutableListOf<String>()
    override fun read(relativePath: String): ByteArray? {
        requested.add(relativePath)
        return contents[relativePath]
    }
}

internal class FakeActivatePort : LiteWebActivatePort {
    var recoveryStatus = LiteWebRecoveryStatus(
        apkBackupPresent = true, apkShaValid = true, daemonRunning = false,
        bootPersistence = LiteWebBootPersistence.PROVEN,
    )
    var prepareStep = LiteWebTestFixtures.ok("prepareBackup")
    var startStep = LiteWebTestFixtures.ok("startDaemon")
    var pingStep = LiteWebTestFixtures.ok("pingDaemon")
    var applyStep = LiteWebTestFixtures.ok("applyPort")
    var revertStep = LiteWebTestFixtures.ok("revertPort")
    var stopStep = LiteWebTestFixtures.ok("stopDaemon")
    var hiddenWriteStep = LiteWebTestFixtures.ok("writeHidden")
    var portValue = LiteWebPortPolicy.DEFAULT_PORT
    val calls = mutableListOf<String>()
    val hiddenWrites = mutableListOf<Boolean>()
    val appliedPorts = mutableListOf<Int?>()
    private var steps = mutableListOf<LiteWebRestoreStep>()

    override fun recovery(): LiteWebRecoveryStatus = recoveryStatus
    override fun writeHidden(enabled: Boolean): LiteWebRestoreStep {
        calls.add("writeHidden:$enabled"); hiddenWrites.add(enabled)
        if (enabled && hiddenWriteStep.ok) recoveryStatus = recoveryStatus.copy(daemonRunning = true)
        return hiddenWriteStep
    }
    override fun currentPort(): Int = portValue
    override fun prepareBackup(): LiteWebRestoreStep { calls.add("prepareBackup"); return prepareStep }
    override fun startDaemon(): LiteWebRestoreStep { calls.add("startDaemon"); return startStep }
    override fun pingDaemon(port: Int): LiteWebRestoreStep { calls.add("pingDaemon:$port"); return pingStep }
    override fun applyPort(port: Int?): LiteWebRestoreStep {
        calls.add("applyPort:${port ?: "keep"}"); appliedPorts.add(port)
        if (applyStep.ok && port != null) portValue = port
        return applyStep
    }
    override fun revertPort(): LiteWebRestoreStep { calls.add("revertPort"); return revertStep }
    override fun stopDaemon(): LiteWebRestoreStep { calls.add("stopDaemon"); return stopStep }
    override fun recordedSteps(): List<LiteWebRestoreStep> = steps
    override fun recordSteps(steps: List<LiteWebRestoreStep>) { this.steps = steps.toMutableList() }
}

internal class FakeRestorePort : LiteWebRestorePort {
    var verifyBackupStep = LiteWebTestFixtures.ok("verifyBackupSha")
    var installStep = LiteWebTestFixtures.ok("installApk")
    var packageStep = LiteWebTestFixtures.ok("verifyPackageInstalled")
    var hiddenWriteStep = LiteWebTestFixtures.ok("writeHidden")
    var componentsStep = LiteWebTestFixtures.ok("restoreComponents")
    var verifyStep = LiteWebTestFixtures.ok("verify")
    var needRebootValue = false
    var portValue = LiteWebPortPolicy.DEFAULT_PORT
    var recoveryStatus = LiteWebRecoveryStatus(
        apkBackupPresent = true, apkShaValid = true, daemonRunning = true,
        bootPersistence = LiteWebBootPersistence.PROVEN,
    )
    val calls = mutableListOf<String>()
    val hiddenWrites = mutableListOf<Boolean>()
    private var steps = mutableListOf<LiteWebRestoreStep>()

    override fun recovery(): LiteWebRecoveryStatus = recoveryStatus
    override fun writeHidden(enabled: Boolean): LiteWebRestoreStep {
        calls.add("writeHidden:$enabled"); hiddenWrites.add(enabled)
        return hiddenWriteStep
    }
    override fun currentPort(): Int = portValue
    override fun verifyBackupSha(): LiteWebRestoreStep { calls.add("verifyBackupSha"); return verifyBackupStep }
    override fun installApk(): LiteWebRestoreStep { calls.add("installApk"); return installStep }
    override fun verifyPackageInstalled(): LiteWebRestoreStep { calls.add("verifyPackageInstalled"); return packageStep }
    override fun restoreComponents(): LiteWebRestoreStep { calls.add("restoreComponents"); return componentsStep }
    override fun verify(): LiteWebRestoreStep { calls.add("verify"); return verifyStep }
    override fun needReboot(): Boolean = needRebootValue
    override fun recordedSteps(): List<LiteWebRestoreStep> = steps
    override fun recordSteps(steps: List<LiteWebRestoreStep>) { this.steps = steps.toMutableList() }
}

internal class FakeSettingsPort(
    val values: MutableMap<String, String> = linkedMapOf("ui_style" to "default"),
) : LiteWebSettingsPort {
    var unavailable = false
    val writes = mutableListOf<Pair<String, String>>()
    override fun read(): Map<String, String> = values.toMap()
    override fun write(key: String, value: String): LiteWebSettingsWriteResult {
        if (unavailable) return LiteWebSettingsWriteResult.Unavailable("SETTINGS_BACKEND_UNAVAILABLE")
        writes.add(key to value)
        values[key] = value
        return LiteWebSettingsWriteResult.Ok(key, value)
    }
}

internal class FakeBackend(
    var statusValue: LiteWebStatusView = LiteWebStatusView(rootAvailable = true, moduleCount = 3),
    var modules: String = "[{\"id\":\"m1\",\"enabled\":true}]",
    var superusers: String = "[{\"uid\":10200,\"allowed\":true}]",
    var sulogValue: LiteWebSulogView = LiteWebSulogView(false, reason = "lite has no su log"),
    var toggleResult: LiteWebToggleView = LiteWebToggleView.Ok("m1", true),
    var hiddenValue: Boolean? = null,
    var hiddenResult: LiteHiddenResult = LiteHiddenResult.Unavailable("hidden controller not wired"),
    val assets: FakeAssets = FakeAssets(),
) : LiteWebBackend {
    val toggles = mutableListOf<Pair<String, Boolean>>()
    val hiddenRequests = mutableListOf<Pair<Boolean, String?>>()
    val activatePort = FakeActivatePort()
    val restore = FakeRestorePort()
    var settings = FakeSettingsPort()
    var diagnostics = LiteWebDiagnosticsView(
        probe = "root", rootBackend = "lite", port = 18427, version = "test", mode = "LITE",
        apkBackupPresent = true, apkShaValid = true, daemonUptimeSeconds = 12,
        bootPersistence = LiteWebBootPersistence.PROVEN,
    )
    var workMode = LiteWebWorkModeView(mode = "LITE", canSwitch = false, blocker = "MODE_SWITCH_READ_ONLY")
    var moduleActionResult: LiteWebModuleActionResult = LiteWebModuleActionResult.Unavailable("unwired")
    var tokenValue = true
    var resetTokenStep = LiteWebRestoreStep("resetToken", false, "TOKEN_RESET_BACKEND_UNAVAILABLE")
    var configuredPort = LiteWebPortPolicy.DEFAULT_PORT
    var activatePortOverride: LiteWebActivatePort? = null
    /** 解除寄生端口（`POST /api/hidden {enable:false}`）；默认未接线 → 501。 */
    var unhide: LiteWebUnhidePort = UnavailableUnhidePort
    var modeBackendValue: LiteWebHiddenModeBackend = FakeModeBackend()
    /** `/modweb/<id>/<rel>` 的假 webroot：`"<id>/<rel>" -> 字节`。 */
    var moduleWeb: Map<String, ByteArray> = emptyMap()
    var moduleWebUnavailable: String? = null
    val moduleWebRequests = mutableListOf<Pair<String, String>>()

    override fun moduleWebFile(moduleId: String, relativePath: String): LiteWebModuleWeb {
        moduleWebRequests.add(moduleId to relativePath)
        moduleWebUnavailable?.let { return LiteWebModuleWeb.Unavailable(it) }
        val bytes = moduleWeb["$moduleId/$relativePath"] ?: return LiteWebModuleWeb.NotFound
        return LiteWebModuleWeb.Found(LiteWebModWeb.contentType(relativePath), bytes)
    }

    override fun status(): LiteWebStatusView = statusValue
    override fun modulesJson(): String = modules
    override fun superusersJson(): String = superusers
    override fun sulog(): LiteWebSulogView = sulogValue
    override fun toggleModule(moduleId: String, enabled: Boolean): LiteWebToggleView {
        toggles.add(moduleId to enabled)
        return toggleResult
    }
    override fun assets(): LiteWebAssets = assets
    override fun hiddenPort(): LiteHiddenPort = object : LiteHiddenPort {
        override fun currentHidden(): Boolean? = hiddenValue
        override fun setHidden(hidden: Boolean, level: String?): LiteHiddenResult {
            hiddenRequests.add(hidden to level)
            return hiddenResult
        }
    }
    override fun activatePort(): LiteWebActivatePort = activatePortOverride ?: activatePort
    override fun restorePort(): LiteWebRestorePort = restore
    override fun unhidePort(): LiteWebUnhidePort = unhide
    override fun settingsPort(): LiteWebSettingsPort = settings
    override fun diagnosticsPort(): LiteWebDiagnosticsPort = object : LiteWebDiagnosticsPort {
        override fun read(): LiteWebDiagnosticsView = diagnostics
    }
    override fun workModePort(): LiteWebWorkModePort = object : LiteWebWorkModePort {
        override fun read(): LiteWebWorkModeView = workMode
    }
    override fun moduleActionPort(): LiteWebModuleActionPort = object : LiteWebModuleActionPort {
        override fun run(moduleId: String, action: String): LiteWebModuleActionResult = moduleActionResult
    }
    override fun tokenPresent(): Boolean = tokenValue
    override fun resetToken(): LiteWebRestoreStep = resetTokenStep
    override fun configuredPort(): Int = configuredPort
    override fun modeBackend(): LiteWebHiddenModeBackend = modeBackendValue
}

/** 两模式（A=Ultra / B=KSU）共用的模式后端 fake；默认 LITE 且所有前置满足。 */
internal class FakeModeBackend(
    var modeInfo: LiteWebModeInfo = LiteWebModeInfo(
        mode = "LITE", rootBackend = "lite", bootHook = LiteWebBootHooks.ULTRA_MODULE,
        daemonRunning = true, daemonPort = LiteWebPortPolicy.DEFAULT_PORT,
    ),
    var backupInfo: LiteWebBackupInfo = LiteWebBackupInfo(
        present = true, shaValid = true, apkPath = "/data/adb/maplesu/recovery/manager.apk",
    ),
    var boot: LiteWebBootEvidence = LiteWebBootEvidence(
        bootIdObserved = true, persistent = true,
        bootPersistence = LiteWebBootPersistence.PROVEN,
    ),
    var startStep: LiteWebRestoreStep = LiteWebTestFixtures.ok("startDaemon"),
    var stopStep: LiteWebRestoreStep = LiteWebTestFixtures.ok("stopDaemon"),
    var unhideStep: LiteWebRestoreStep = LiteWebTestFixtures.ok("restoreUnhide"),
    var installStep: LiteWebRestoreStep = LiteWebTestFixtures.ok("installApk"),
    var packageStep: LiteWebRestoreStep = LiteWebTestFixtures.ok("verifyPackage"),
    var componentsStep: LiteWebRestoreStep = LiteWebTestFixtures.ok("restoreComponents"),
) : LiteWebHiddenModeBackend {
    val calls = mutableListOf<String>()
    override fun mode(): LiteWebModeInfo = modeInfo
    override fun startDaemon(): LiteWebRestoreStep { calls.add("startDaemon"); return startStep }
    override fun stopDaemon(): LiteWebRestoreStep { calls.add("stopDaemon"); return stopStep }
    override fun backup(): LiteWebBackupInfo = backupInfo
    override fun bootEvidence(): LiteWebBootEvidence = boot
    override fun restorePlan(): List<LiteWebRestoreStep> = listOf(
        LiteWebRestoreStep("verifyBackupSha", backupInfo.shaValid == true),
        LiteWebRestoreStep("unhide", true),
        LiteWebRestoreStep("installApk", true),
        LiteWebRestoreStep("verifyPackageInstalled", true),
        LiteWebRestoreStep("restoreComponents", true),
    )
    override fun restoreUnhide(): LiteWebRestoreStep { calls.add("restoreUnhide"); return unhideStep }
    override fun installApk(): LiteWebRestoreStep { calls.add("installApk"); return installStep }
    override fun verifyPackage(): LiteWebRestoreStep { calls.add("verifyPackage"); return packageStep }
    override fun restoreComponents(): LiteWebRestoreStep { calls.add("restoreComponents"); return componentsStep }
}
