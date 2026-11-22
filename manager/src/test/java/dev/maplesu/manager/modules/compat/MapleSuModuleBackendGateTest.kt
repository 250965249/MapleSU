package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.ultra.model.MapleSuModInstalledItem
import dev.maplesu.manager.ultra.model.MapleSuModRunState
import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.UltraOutcome
import dev.maplesu.manager.runtime.ultra.UltraPhase
import dev.maplesu.manager.runtime.ultra.UltraReceipt
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * H1 的**真实入口**测试：直接驱动 [UltraModuleInstallTransaction]（W6-F1）。
 *
 * ## 这个测试与 W2-0 版本的区别（W5 复核 S1-1）
 *
 * 旧版本用 `runBackendGateSequence` **复刻** `MapleSuModuleBackend.install` 的门相关步骤
 * （旧文件自述见 `.analysis/.../w2-0`），从不调用产品代码——把 stage/descriptor 挪到门之前它仍然
 * 全绿，因此它证明不了产品行为。现在：
 *
 *  * 被测对象是**产品类** [UltraModuleInstallTransaction]，`MapleSuModuleBackend.install` 只是把
 *    `Report` 翻成 [UltraModulePackageIdentity] 后转调它（一行委托，见 backend 的 `install`）；
 *  * 断言的是**真实事务**的调用序列：`host.callOrder`、`catalog` 的 stage/commit/discard 计数、
 *    操作日志条数与 token、§4.3 事件条数与内容、回执字段；
 *  * 因此「门在 stage 之前」是可失败的断言（反向对照实验见
 *    `.analysis/ultra-module-crash-remediation-20261031/w6-f1/EVIDENCE.md`：把门挪到 descriptor 之后，
 *    本文件的 `knownIncompatibleNeverReachesTheHost` 立即变红）。
 *
 * ## 为什么这里仍然不 `new` 一个 `MapleSuModuleBackend`
 *
 * 那个类要 `Context`（`filesDir` / `SharedPreferences` / `assets` / `PackageManager`）。仓库的
 * `testImplementation` 只有 junit，按任务约束不引入 Robolectric。所以「`Context` 解析」留在
 * backend（薄壳），「事务行为」全部移进可注入的 [UltraModuleInstallTransaction]——这不是绕开产品
 * 代码，而是把产品代码里真正需要断言的那一段做成可测的。
 *
 * ## 回执 `data` 段为什么是注入的
 *
 * `org.json` 在 JVM 单测里是 `android.jar` 的 stub（`new JSONObject()` 直接抛）。所以 `data`
 * 的生产者 [UltraModuleReceiptData] 被注入：本文件用记录型替身，断言的是
 * [UltraModuleReceiptPayload]（`data` 的语义内容），生产实现 `OrgJsonReceiptData` 的序列化逐字段
 * 与改前相同（见该类注释）。回执的 phase/outcome/unknowns/cleanupOutcome 都是 `UltraReceipt` 的
 * 普通字段，不经过 JSON，断言的是真值。
 */
class MapleSuModuleBackendGateTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private companion object {
        // ---- 本机已确认身份（与 UltraModuleCompatibilityRegistry / 冻结排查一致）----
        const val ID32 = "cd08ae9eef7bb885c06f80ef3aea1d5c"
        const val VERSION = "1.9.3"
        const val ARCHIVE_SHA256 = "2fdc08482075a9865d49e2595a2487f07a37ab499aab744d8d9bb09a098d4a31"
        const val PAYLOAD_SHA256 = "a0835b667db5ed33a12b7fa2d2f8ba9ee58b8f7fd538250b62111cffd2a647dc"
        const val NATIVE_ENTRY = "libmodule_app_auto_hider.so"
        const val KERNEL_RELEASE = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
        const val SDK_VERSION = "5.1.0"
        const val OPERATION_ID = "5b1c9a70-2d3e-4f56-8a9b-0c1d2e3f4a5b"
        const val STAGED_TOKEN = "0123456789abcdef0123456789abcdef"
        const val BOOT_ID = "1f2e3d4c-5b6a-4978-8c9d-0e1f2a3b4c5d"
        const val PROCESS_PID = 4242

        /** 固定的注入时钟。`Instant.ofEpochMilli` 的结果见 [FIXED_ISO]。 */
        const val FIXED_MILLIS = 1_700_000_000_123L
        const val FIXED_ISO = "2023-11-14T22:13:20.123Z"

        /** 构建摘要（管理器 APK 的 SHA-256 形态：64 位小写十六进制）。 */
        val APK_SHA256 = "9f".repeat(32)
    }

    // ------------------------------------------------------------------ 计数型宿主

    /** 计数型宿主：每次调用都记下来，用来断言「被拦请求一次都没到宿主」。 */
    private class CountingHost : UltraModuleHost {

        val callOrder = ArrayList<String>()
        var environmentStateCalls = 0
        var parseModuleDescriptorCalls = 0
        var installModuleCalls = 0
        var uninstallModuleCalls = 0
        var modulesCalls = 0
        var openModuleWebUiCalls = 0

        var lastDescriptorPath: String? = null
        var lastInstallPath: String? = null
        var lastDevRunOnce: Boolean? = null
        var lastOpenWebUiId: String? = null

        /** 环境探针的返回状态：默认「已就绪」。 */
        var environmentStateValue = "Running"
        var environmentOk = true
        var environmentFailure: Exception? = null

        /** 宿主的安装回执：默认接受；置 false 模拟「宿主拒绝」。 */
        var installAccepted = true
        var installFailure: NativeReceipt? = null
        var modulesFailure: Exception? = null

        /** 安装后 `get_all_modules_list` 的内容。默认没有模块（安装未被证明）。 */
        var listedAfterInstall: List<MapleSuModInstalledItem> = emptyList()

        override fun environmentState(): NativeReceipt {
            environmentStateCalls++
            callOrder += "environment"
            environmentFailure?.let { throw it }
            return receipt("get_maplesu_environment_state").copy(
                ok = environmentOk,
                sdkError = if (environmentOk) "OK" else "ENV_FAULT",
                sdkErrorCode = if (environmentOk) 0 else -7,
            )
        }

        override fun parseModuleDescriptor(zipPath: String): NativeReceipt {
            parseModuleDescriptorCalls++
            callOrder += "descriptor"
            lastDescriptorPath = zipPath
            return receipt("parse_module_desc_from_zip_file")
        }

        override fun installModule(zipPath: String, devRunOnce: Boolean): NativeReceipt {
            installModuleCalls++
            callOrder += "install"
            lastInstallPath = zipPath
            lastDevRunOnce = devRunOnce
            val operation = if (devRunOnce) "install_module_dev_run_once" else "install_module"
            return installFailure ?: if (installAccepted) {
                receipt(operation)
            } else {
                receipt(operation).copy(ok = false, sdkError = "MODULE_REFUSED_BY_HOST", sdkErrorCode = -3)
            }
        }

        override fun uninstallModule(id32: String): NativeReceipt {
            uninstallModuleCalls++
            callOrder += "uninstall"
            return receipt("uninstall_module")
        }

        override fun modules(): List<MapleSuModInstalledItem> {
            modulesCalls++
            callOrder += "modules"
            modulesFailure?.let { throw it }
            return listedAfterInstall
        }

        override fun openModuleWebUI(id32: String): NativeReceipt {
            openModuleWebUiCalls++
            callOrder += "open_webui"
            lastOpenWebUiId = id32
            return receipt("start_module_web_ui_server_async")
        }

        /** 会执行模块原生代码的三个入口的总次数（H1 断言的对象）。 */
        fun moduleExecutionCalls(): Int =
            parseModuleDescriptorCalls + installModuleCalls + openModuleWebUiCalls
    }

    // ------------------------------------------------------------------ 计数型 catalog / journal / 回执 data

    /** 计数型包存储：被拦时**必须**一次都没碰（只数宿主调用会漏掉「先复制字节再拦」）。 */
    private class CountingCatalog(private val stagedFile: File) : UltraModuleCatalogPort {

        val callOrder = ArrayList<String>()
        var stageCalls = 0
        var stagedArchiveCalls = 0
        var commitCalls = 0
        var discardCalls = 0

        var stageFailure: Exception? = null
        var discardFailure: Exception? = null
        var commitFailure: Exception? = null

        override fun stage(source: File, confirmedArchiveSha256: String): String {
            stageCalls++
            callOrder += "stage"
            stageFailure?.let { throw it }
            return STAGED_TOKEN
        }

        override fun stagedArchive(token: String): File {
            stagedArchiveCalls++
            callOrder += "stagedArchive"
            return stagedFile
        }

        override fun commit(token: String) {
            commitCalls++
            callOrder += "commit"
            commitFailure?.let { throw it }
        }

        override fun discard(token: String) {
            discardCalls++
            callOrder += "discard"
            discardFailure?.let { throw it }
        }
    }

    /** 操作日志替身：记下每一条 `(operationId, receipt, token)`。 */
    private class RecordingJournal : UltraModuleJournal {
        val entries = ArrayList<Entry>()

        data class Entry(val operationId: String, val receipt: UltraReceipt, val token: String?)

        override fun append(operationId: String, receipt: UltraReceipt, token: String?) {
            entries += Entry(operationId, receipt, token)
        }
    }

    /** 回执 `data` 替身：不构造 JSON（JVM 上 `org.json` 是 stub），只记录语义内容。 */
    private class RecordingReceiptData : UltraModuleReceiptData {
        val payloads = ArrayList<UltraModuleReceiptPayload>()

        override fun create(payload: UltraModuleReceiptPayload): org.json.JSONObject? {
            payloads += payload
            return null
        }
    }

    // ------------------------------------------------------------------ 夹具

    /** 真实证据写入器：走 W1-C 的脱敏器，落盘内容与设备上同一条路径。 */
    private class EvidenceLines {
        val lines = ArrayList<String>()
        val log = UltraModuleGateEvidenceLog(appendLine = { lines += it })

        fun events(): List<UltraModuleEvent> = lines.map {
            UltraModuleEvidenceJson.decode(it)?.event
                ?: throw AssertionError("证据行不是合法 JSONL: $it")
        }
    }

    private val stagedFile: File by lazy { tmp.newFile("staged.zip") }

    private fun confirmedIdentity() = UltraModulePackageIdentity(
        id32 = ID32,
        version = VERSION,
        archiveSha256 = ARCHIVE_SHA256,
        nativePayloadSha256 = PAYLOAD_SHA256,
        nativeEntryName = NATIVE_ENTRY,
    )

    private fun unknownIdentity() = UltraModulePackageIdentity(
        id32 = "0123456789abcdef0123456789abcdef",
        version = "2.0.0",
        archiveSha256 = "e".repeat(64),
        nativePayloadSha256 = "d".repeat(64),
        nativeEntryName = "libunknown.so",
    )

    /** 本机设备事实（内核 release 可读；变体读不到，与 `UltraModuleDeviceFacts.read` 实际产出一致）。 */
    private fun deviceFacts() = UltraModuleDeviceFacts.of(
        sdkVersion = SDK_VERSION,
        kernelRelease = KERNEL_RELEASE,
        sdkManifestVerified = false,
        kernelVariantId = null,
        bootImageSha256 = null,
    )

    private fun request(
        identity: UltraModulePackageIdentity = confirmedIdentity(),
        devRunOnce: Boolean = false,
        action: UltraModuleAction =
            if (devRunOnce) UltraModuleAction.DEV_RUN_ONCE else UltraModuleAction.INSTALL,
        manifestVersion: String? = identity.version,
    ) = UltraModuleInstallRequest(
        source = tmp.newFile("source-${System.nanoTime()}.zip"),
        identity = identity,
        manifestVersion = manifestVersion,
        devRunOnce = devRunOnce,
        action = action,
    )

    /** 被测对象：**产品类**，全部依赖注入，没有 `Context`。 */
    private fun transaction(
        host: CountingHost,
        catalog: CountingCatalog,
        journal: RecordingJournal,
        evidence: EvidenceLines,
        payloads: RecordingReceiptData,
        clockMillis: () -> Long = { FIXED_MILLIS },
        build: () -> UltraModuleBuildDigest = { UltraModuleBuildDigest.of(APK_SHA256) },
        facts: () -> UltraModuleDeviceFacts = { deviceFacts() },
    ) = UltraModuleInstallTransaction(
        host = host,
        // 前置条件观测点：真实实现读 `host.environmentState()` 的 `data.state`，而 `org.json`
        // 在 JVM 上是 stub，所以测试注入观测值（判据仍在事务里，见 UltraModuleEnvironmentObservation）。
        environmentProbe = {
            UltraModuleEnvironmentObservation(host.environmentState(), host.environmentStateValue)
        },
        catalog = catalog,
        journal = journal,
        evidence = evidence.log::record,
        facts = facts,
        clockMillis = clockMillis,
        buildDigest = build,
        bootId = { BOOT_ID },
        processPid = { PROCESS_PID },
        newOperationId = { OPERATION_ID },
        receiptData = payloads,
    )

    private class Harness(
        val host: CountingHost,
        val catalog: CountingCatalog,
        val journal: RecordingJournal,
        val evidence: EvidenceLines,
        val payloads: RecordingReceiptData,
        val transaction: UltraModuleInstallTransaction,
        val stdout: MutableList<String> = ArrayList(),
        val stderr: MutableList<String> = ArrayList(),
    )

    private fun harness(
        clockMillis: () -> Long = { FIXED_MILLIS },
        build: () -> UltraModuleBuildDigest = { UltraModuleBuildDigest.of(APK_SHA256) },
    ): Harness {
        val host = CountingHost()
        val catalog = CountingCatalog(stagedFile)
        val journal = RecordingJournal()
        val evidence = EvidenceLines()
        val payloads = RecordingReceiptData()
        return Harness(
            host = host,
            catalog = catalog,
            journal = journal,
            evidence = evidence,
            payloads = payloads,
            transaction = transaction(host, catalog, journal, evidence, payloads, clockMillis, build),
        )
    }

    // ------------------------------------------------------------------ (a) 被拦 = 0 次宿主调用，0 次 stage

    @Test
    fun selectedModuleReachesHostDespiteCompatibilityDiagnostics() {
        val h = harness()
        h.host.listedAfterInstall = listOf(installedItem(ID32, VERSION, MapleSuModRunState.RUNNING))
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
        assertEquals(listOf("environment", "descriptor", "install", "modules"), h.host.callOrder)
        assertEquals(listOf("stage", "stagedArchive", "commit"), h.catalog.callOrder)
        assertEquals(stagedFile.absolutePath, h.host.lastInstallPath)
        assertTrue(h.stderr.isEmpty())
        assertEquals(UltraModuleOutcome.UNKNOWN, h.evidence.events().first().outcome)
        assertTrue(h.evidence.events().first().detail.contains("gate=KNOWN_INCOMPATIBLE"))
    }

    @Test
    fun compatibilityDiagnosticsDoNotMisreportASelectedInstallAsBlocked() {
        val h = harness()
        h.transaction.install(request(), h.stdout::add, h.stderr::add)
        val events = h.evidence.events()
        assertEquals(2, events.size)
        assertEquals(UltraModulePhase.PRE_EXEC_CHECK, events[0].phase)
        assertEquals(UltraModuleOutcome.UNKNOWN, events[0].outcome)
        assertTrue(events[0].detail.contains("gate=KNOWN_INCOMPATIBLE"))
        assertEquals(UltraModulePhase.NATIVE_ENTRY, events[1].phase)
        assertEquals(UltraModuleOutcome.SUCCESS, events[1].outcome)
        assertEquals(1, h.host.installModuleCalls)
        assertFalse(h.evidence.lines.any { it.contains(ARCHIVE_SHA256) || it.contains(PAYLOAD_SHA256) })
    }

    @Test
    fun eventsCarryTheBuildDigestAndTheDeviceTimeFromTheInjectedClock() {
        val h = harness()
        h.transaction.install(request(), h.stdout::add, h.stderr::add)

        val event = h.evidence.events().first()
        // 构建摘要：来自注入的生产者，落进字段（不是 null，也不是占位串）。
        assertEquals(APK_SHA256, event.buildDigest)
        assertTrue(h.evidence.lines.first().contains("\"buildDigest\":\"$APK_SHA256\""))
        // detail 里只放来源标记，不放摘要本身（32 位以上十六进制会被脱敏器吃掉）。
        assertTrue(event.detail.contains("build=verified:${UltraModuleBuildDigest.SOURCE_MANAGER_BASE_APK}"))
        // 设备时间：事件发生那一刻取自注入时钟，转成 ISO-8601 UTC。
        assertEquals(FIXED_ISO, event.deviceTimeIso)
        assertEquals(FIXED_ISO, event.hostUtcIso)
        // 脱敏器必须原样接受这条事件（否则「有字段」只是内存里的事，落盘时会被丢掉）。
        assertEquals(event.detail, UltraModuleEvidenceSanitizer().redact(event.detail))
    }

    @Test
    fun deviceTimeFollowsTheInjectedClockInsteadOfAConstant() {
        val first = harness(clockMillis = { FIXED_MILLIS })
        first.transaction.install(request(), first.stdout::add, first.stderr::add)

        val second = harness(clockMillis = { FIXED_MILLIS + 86_400_000L })
        second.transaction.install(request(), second.stdout::add, second.stderr::add)

        assertEquals(FIXED_ISO, first.evidence.events().first().deviceTimeIso)
        assertEquals(
            "时钟被真正读取：换一个注入值，事件时间必须跟着变",
            "2023-11-15T22:13:20.123Z",
            second.evidence.events().first().deviceTimeIso,
        )
    }

    @Test
    fun unavailableBuildDigestIsARecordedReasonAndNotSilentNull() {
        val h = harness(build = {
            UltraModuleBuildDigest.Unavailable(UltraModuleBuildDigest.REASON_APK_UNREADABLE)
        })
        h.transaction.install(request(), h.stdout::add, h.stderr::add)

        val line = h.evidence.lines.first()
        val event = h.evidence.events().first()
        // 字段本身只能是真实摘要或 null —— 占位串会被脱敏器置空，所以「拿不到」写在 detail 里。
        assertNull(event.buildDigest)
        assertTrue(line.contains("\"buildDigest\":null"))
        assertTrue(event.detail.contains("build=unknown:${UltraModuleBuildDigest.REASON_APK_UNREADABLE}"))
        // 「拿不到」与「没写」必须是两个不同的状态码。
        assertFalse(event.detail.contains(UltraModuleBuildDigest.REASON_NOT_PROVIDED))
    }

    // ------------------------------------------------------------------ (b) 未验证包 = 放行并调用宿主

    @Test
    fun unverifiedPackageIsJudgedAndThenExecuted() {
        val h = harness()
        val identity = unknownIdentity()
        h.host.listedAfterInstall = listOf(
            installedItem(identity.id32, identity.version, MapleSuModRunState.RUNNING),
        )
        val receipt = h.transaction.install(
            request(identity = identity),
            h.stdout::add,
            h.stderr::add,
        )

        // 顺序固定：descriptor -> install -> 回读 -> commit。
        assertEquals(
            listOf("environment", "descriptor", "install", "modules"),
            h.host.callOrder,
        )
        assertEquals(1, h.host.parseModuleDescriptorCalls)
        assertEquals(1, h.host.installModuleCalls)
        assertEquals(listOf("stage", "stagedArchive", "commit"), h.catalog.callOrder)
        assertEquals(0, h.catalog.discardCalls)
        assertEquals(stagedFile.absolutePath, h.host.lastDescriptorPath)
        assertEquals(stagedFile.absolutePath, h.host.lastInstallPath)
        assertEquals(false, h.host.lastDevRunOnce)

        // 回执与改前一致：宿主接受 + 列表可见 + catalog 已提交。
        assertEquals(UltraPhase.CATALOG_COMMITTED, receipt.phase)
        assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
        assertEquals("catalog_committed", receipt.cleanupOutcome)
        assertEquals(identity.id32, receipt.moduleId)
        assertEquals(identity.version, receipt.installedVersion)
        assertTrue(receipt.unknowns.isEmpty())
        assertEquals(2, h.stdout.size)
        assertTrue(h.stdout[0].startsWith("Staged $STAGED_TOKEN"))
        assertTrue(h.stdout[1].startsWith("Installed "))
        assertEquals(2, h.journal.entries.size)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, h.journal.entries[0].receipt.outcome)
        assertEquals(STAGED_TOKEN, h.journal.entries[0].token)
        assertNull(h.journal.entries[1].token)

        // §4.3：两次事件 —— 门放行（UNKNOWN）+ 宿主已调用（SUCCESS）。
        val events = h.evidence.events()
        assertEquals(2, events.size)
        assertEquals(UltraModulePhase.PRE_EXEC_CHECK, events[0].phase)
        assertEquals(UltraModuleOutcome.UNKNOWN, events[0].outcome)
        assertTrue(events[0].detail.contains("gate=UNVERIFIED"))
        assertEquals(UltraModulePhase.NATIVE_ENTRY, events[1].phase)
        assertEquals(UltraModuleOutcome.SUCCESS, events[1].outcome)
        assertEquals(0, events[1].returnCode)
        assertTrue(events[1].detail.contains("state=HOST_CALLED"))
        assertEquals(APK_SHA256, events[1].buildDigest)

        // data 的语义内容：runState / minSdk / webUi / crossCheck。
        val installed = h.payloads.payloads.single() as UltraModuleReceiptPayload.Installed
        assertEquals(MapleSuModRunState.RUNNING, installed.runState)
        assertTrue("descriptor 没有 min_sdk_ver 时保持 null", installed.minSdk == null)
        assertEquals(false, installed.webUi)
        assertTrue(installed.crossCheck.isEmpty())
    }

    @Test
    fun aDifferentListedModuleIsNotReadAsTheInstalledOne() {
        // 宿主接受但没有把它列出来：不能凭 install 返回值当成功（回读是唯一证据）。
        val h = harness()
        h.host.listedAfterInstall = listOf(
            installedItem("ffffffffffffffffffffffffffffffff", "9.9.9", MapleSuModRunState.RUNNING),
        )
        val receipt = h.transaction.install(
            request(identity = unknownIdentity()),
            h.stdout::add,
            h.stderr::add,
        )

        assertEquals(UltraPhase.HOST_ACCEPTED, receipt.phase)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
        assertEquals("staged_kept_for_reconciliation", receipt.cleanupOutcome)
        assertEquals(0, h.catalog.commitCalls)
        assertEquals(0, h.catalog.discardCalls)
        assertEquals(
            mapOf("listedAfterInstall" to "module absent from get_all_modules_list"),
            receipt.unknowns,
        )
        assertTrue(h.stderr.single().contains("does not show it yet"))
        // 待对账时 staged token 必须留在日志里（否则没人能找回那份字节）。
        assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
    }

    // ------------------------------------------------------------------ (c) 宿主拒绝

    @Test
    fun hostRefusalIsRecordedAsHostRefusedAndDiscardsTheStagedCopy() {
        val h = harness()
        h.host.installAccepted = false
        val receipt = h.transaction.install(
            request(identity = unknownIdentity()),
            h.stdout::add,
            h.stderr::add,
        )

        assertEquals(UltraPhase.HOST_CALLED, receipt.phase)
        assertEquals(UltraOutcome.FAILED, receipt.outcome)
        assertEquals("MODULE_REFUSED_BY_HOST", receipt.sdkError)
        assertEquals("staged_discarded", receipt.cleanupOutcome)
        // 宿主拒绝之后不读列表、不提交 catalog：只丢掉 staged 副本。
        assertEquals(listOf("stage", "stagedArchive", "discard"), h.catalog.callOrder)
        assertEquals(1, h.catalog.discardCalls)
        assertEquals(0, h.catalog.commitCalls)
        assertEquals(0, h.host.modulesCalls)

        // §4.3：HOST_REFUSED 事件必须带真实 SDK 返回码。
        val events = h.evidence.events()
        assertEquals(2, events.size)
        assertEquals(UltraModulePhase.NATIVE_ENTRY, events[1].phase)
        assertEquals(UltraModuleOutcome.FAILURE, events[1].outcome)
        assertEquals(-3, events[1].returnCode)
        assertTrue(events[1].detail.contains("state=HOST_REFUSED"))
    }

    @Test
    fun callbackDeclineNeverCommitsEvenWhenAnOlderModuleIsStillListed() {
        for (devOnce in listOf(false, true)) {
            val h = harness()
            h.host.installFailure = requireNotNull(NativeReceipt.parse(
                """{"backend":"maplesu_ultra","operation":"install_module","ok":false,
                    "sdkError":"MAPLESU_MODULE_INSTALL_CALLBACK_DECLINED","sdkErrorCode":-1007,
                    "reason":"module requires a different kernel",
                    "data":{"installCallbackAccepted":false}}""",
            ))
            h.host.listedAfterInstall = listOf(
                installedItem(unknownIdentity().id32, "1.0", MapleSuModRunState.RUNNING),
            )
            val receipt = h.transaction.install(
                request(identity = unknownIdentity(), devRunOnce = devOnce), h.stdout::add, h.stderr::add,
            )
            assertEquals(UltraOutcome.FAILED, receipt.outcome)
            assertEquals("MAPLESU_MODULE_INSTALL_CALLBACK_DECLINED", receipt.sdkError)
            assertEquals(1, h.host.installModuleCalls)
            assertEquals(0, h.host.modulesCalls)
            assertEquals(0, h.catalog.commitCalls)
            assertEquals(1, h.catalog.discardCalls)
            assertEquals("module requires a different kernel", h.stderr.single())
        }
    }

    @Test
    fun lostInstallWorkerReceiptKeepsThePackageAndNeverReplaysEitherMode() {
        for (devOnce in listOf(false, true)) {
            val h = harness()
            h.host.installFailure = requireNotNull(NativeReceipt.parse(
                """{"backend":"maplesu_ultra","operation":"install_module","ok":false,
                    "sdkError":"MAPLESU_MODULE_INSTALL_INTERRUPTED","sdkErrorCode":-1005,
                    "data":{"reconciliationRequired":true}}""",
            ))
            val receipt = h.transaction.install(
                request(identity = unknownIdentity(), devRunOnce = devOnce), h.stdout::add, h.stderr::add,
            )
            assertEquals(UltraPhase.HOST_CALLED, receipt.phase)
            assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
            assertEquals("staged_kept_for_reconciliation", receipt.cleanupOutcome)
            assertEquals("host_result_unverified", receipt.unknowns["installation"])
            assertEquals(1, h.host.installModuleCalls)
            assertEquals(devOnce, h.host.lastDevRunOnce)
            assertEquals(0, h.host.modulesCalls)
            assertEquals(0, h.catalog.discardCalls)
            assertEquals(0, h.catalog.commitCalls)
            assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
        }
    }

    @Test
    fun legacyAndUnparseableInstallRepliesAlsoRetainReconciliationMaterial() {
        for (error in listOf("ERR_READ_CHILD_ERRCODE", "MAPLESU_BRIDGE_EXCEPTION", "MAPLESU_BRIDGE_UNPARSEABLE")) {
            val h = harness()
            h.host.installFailure = NativeReceipt.bridgeFailure("install_module", error, "reply lost")
            val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
            assertEquals(error, UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
            assertEquals(1, h.host.installModuleCalls)
            assertEquals(0, h.catalog.discardCalls)
            assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
        }
    }

    @Test
    fun failedStagedCleanupIsReportedAndKeepsItsJournalToken() {
        val h = harness()
        h.host.installAccepted = false
        h.catalog.discardFailure = java.io.IOException("disk error")
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
        assertEquals("staged_discard_failed", receipt.cleanupOutcome)
        assertEquals(1, h.catalog.discardCalls)
        assertEquals(0, h.catalog.commitCalls)
        assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
    }

    @Test
    fun abnormalReadbackNeverReportsInstallOrRunOnceSuccess() {
        for (devOnce in listOf(false, true)) {
            val h = harness()
            h.host.listedAfterInstall = listOf(installedItem(ID32, VERSION, MapleSuModRunState.ABNORMAL))
            val receipt = h.transaction.install(request(devRunOnce = devOnce), h.stdout::add, h.stderr::add)
            assertEquals(UltraOutcome.FAILED, receipt.outcome)
            assertEquals(UltraPhase.CATALOG_COMMITTED, receipt.phase)
            assertEquals(VERSION, receipt.installedVersion)
            assertNull(receipt.activeVersion)
            assertFalse(receipt.needsReboot)
            assertEquals("MODULE_ABNORMAL", receipt.unknowns["runtime"])
            assertEquals(1, h.host.installModuleCalls)
            assertEquals(1, h.catalog.commitCalls) // Keep the installed bytes available for repair/uninstall.
            assertEquals(0, h.catalog.discardCalls)
            assertNull(h.journal.entries.last().token)
            assertFalse(h.stdout.any { it.startsWith("Installed ") })
            assertTrue(h.stderr.single().contains("ABNORMAL"))
        }
    }

    @Test
    fun abnormalInstallWithCatalogFailureKeepsReconciliationToken() {
        val h = harness()
        h.host.listedAfterInstall = listOf(installedItem(ID32, VERSION, MapleSuModRunState.ABNORMAL))
        h.catalog.commitFailure = java.io.IOException("commit failed")
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
        assertEquals(UltraPhase.HOST_COMMITTED_CATALOG_PENDING, receipt.phase)
        assertEquals("MODULE_ABNORMAL", receipt.unknowns["runtime"])
        assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
        assertEquals(0, h.catalog.discardCalls)
        assertFalse(receipt.needsReboot)
    }

    @Test
    fun previousInstalledVersionDoesNotConfirmAnUpgrade() {
        val h = harness()
        h.host.listedAfterInstall = listOf(installedItem(ID32, "older-version", MapleSuModRunState.RUNNING))
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
        assertEquals("listed module version differs from requested version", receipt.unknowns["listedAfterInstall"])
        assertEquals(0, h.catalog.commitCalls)
        assertEquals(0, h.catalog.discardCalls)
        assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
    }

    @Test
    fun duplicateTargetRowsDoNotConfirmAnInstall() {
        val h = harness()
        h.host.listedAfterInstall = listOf(
            installedItem(ID32, VERSION, MapleSuModRunState.RUNNING),
            installedItem(ID32, VERSION, MapleSuModRunState.NOT_RUNNING),
        )
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
        assertEquals("module list contains duplicate target rows", receipt.unknowns["listedAfterInstall"])
        assertEquals(0, h.catalog.commitCalls)
        assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
    }

    @Test
    fun aNullListedIdDoesNotMatchAnAbsentDescriptorId() {
        val h = harness()
        h.host.listedAfterInstall = listOf(
            installedItem(ID32, VERSION, MapleSuModRunState.RUNNING).apply { id32 = null },
        )
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
        assertEquals(0, h.catalog.commitCalls)
        assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
    }

    @Test
    fun readbackExceptionProducesAReconciliationReceiptWithoutRetryingTheInstall() {
        val h = harness()
        h.host.modulesFailure = java.io.IOException("read failed")
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
        assertEquals("module list read failed", receipt.unknowns["listedAfterInstall"])
        assertEquals(1, h.host.installModuleCalls)
        assertEquals(1, h.host.modulesCalls)
        assertEquals(0, h.catalog.commitCalls)
        assertEquals(0, h.catalog.discardCalls)
        assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
    }

    // ------------------------------------------------------------------ (d) stage 失败

    @Test
    fun stageFailureHappensAfterTheGateAndTouchesNoHostModuleEntry() {
        val h = harness()
        h.catalog.stageFailure = java.io.IOException("MODULE_CATALOG_BUSY")
        val receipt = h.transaction.install(
            request(identity = unknownIdentity()),
            h.stdout::add,
            h.stderr::add,
        )

        assertEquals(UltraPhase.PREPARED, receipt.phase)
        assertEquals(UltraOutcome.FAILED, receipt.outcome)
        assertEquals(mapOf("stageError" to "MODULE_CATALOG_BUSY"), receipt.unknowns)
        // 门放过之后才 stage：门的事件已经写过，宿主模块入口仍然 0 次。
        assertEquals(1, h.catalog.stageCalls)
        assertEquals(0, h.host.moduleExecutionCalls())
        assertEquals(listOf("environment"), h.host.callOrder)
        assertEquals(1, h.evidence.events().size)
        assertTrue(h.stderr.single().contains("Staging failed: MODULE_CATALOG_BUSY"))
    }

    // ------------------------------------------------------------------ (e) 前置条件不满足

    @Test
    fun failedEnvironmentObservationDoesNotBlockTheSelectedInstall() {
        val h = harness()
        h.host.environmentStateValue = "Fault"
        h.host.environmentOk = false
        h.host.listedAfterInstall = listOf(installedItem(ID32, VERSION, MapleSuModRunState.RUNNING))
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)

        assertEquals(UltraPhase.CATALOG_COMMITTED, receipt.phase)
        assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
        assertTrue(h.stderr.isEmpty())
        val event = h.evidence.events().first()
        assertEquals(UltraModulePhase.PRE_EXEC_CHECK, event.phase)
        assertEquals(UltraModuleOutcome.UNKNOWN, event.outcome)
        assertTrue(event.detail.contains("environment=Fault"))
        assertNull(event.returnCode)

        assertEquals(1, h.catalog.stageCalls)
        assertEquals(1, h.catalog.commitCalls)
        assertEquals(listOf("environment", "descriptor", "install", "modules"), h.host.callOrder)
    }

    @Test
    fun throwingEnvironmentProbeStillUsesTheActualHostResult() {
        val h = harness()
        h.host.environmentFailure = java.io.IOException("ENVIRONMENT_PROBE_LOST")
        h.host.installAccepted = false
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)

        assertEquals(UltraPhase.HOST_CALLED, receipt.phase)
        assertEquals(UltraOutcome.FAILED, receipt.outcome)
        assertEquals("MODULE_REFUSED_BY_HOST", receipt.sdkError)
        assertEquals(listOf("environment", "descriptor", "install"), h.host.callOrder)
        assertEquals(1, h.catalog.discardCalls)
        assertEquals(listOf("MODULE_REFUSED_BY_HOST"), h.stderr)
    }

    @Test
    fun interruptedEnvironmentProbeStopsTheCancelledOperation() {
        val h = harness()
        h.host.environmentFailure = InterruptedException("cancelled")
        org.junit.Assert.assertThrows(InterruptedException::class.java) {
            h.transaction.install(request(), h.stdout::add, h.stderr::add)
        }
        assertEquals(0, h.host.moduleExecutionCalls())
        assertEquals(0, h.catalog.stageCalls)
    }

    // ------------------------------------------------------------------ (f) dev-run-once 与 WebUI

    @Test
    fun devRunOnceUsesTheUserSelectedInstallTransaction() {
        val h = harness()
        val receipt = h.transaction.install(request(devRunOnce = true, action = UltraModuleAction.DEV_RUN_ONCE), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
        assertEquals(1, h.catalog.stageCalls)
        assertEquals(1, h.host.installModuleCalls)
        assertEquals(true, h.host.lastDevRunOnce)
        assertEquals(UltraModuleOutcome.UNKNOWN, h.evidence.events().first().outcome)
    }

    @Test
    fun selectedInstallUsesHostWhileWebUiRetainsItsOwnDecision() {
        val host = CountingHost()
        val gate = UltraModuleExecutionGate(host)
        val decision = gate.evaluate(confirmedIdentity(), deviceFacts(), UltraModuleAction.INSTALL)
        val execution = gate.executeInstall(decision, "/tmp/staged.zip", devRunOnce = false)
        assertTrue(execution is UltraModuleInstallExecution.Ran)
        assertEquals(1, host.parseModuleDescriptorCalls)
        assertEquals(1, host.installModuleCalls)
        val webUi = gate.evaluate(confirmedIdentity(), deviceFacts(), UltraModuleAction.OPEN_WEBUI)
        assertNull(gate.openWebUiIfAllowed(webUi, ID32))
        assertEquals(0, host.openModuleWebUiCalls)
    }

    @Test
    fun openWebUiIsGatedTheSameWay() {
        val host = CountingHost()
        val gate = UltraModuleExecutionGate(host)

        val blocked = gate.evaluate(confirmedIdentity(), deviceFacts(), UltraModuleAction.OPEN_WEBUI)
        assertTrue(blocked.blocked)
        assertNull(gate.openWebUiIfAllowed(blocked, ID32))
        assertEquals(0, host.openModuleWebUiCalls)

        val allowed = gate.evaluate(unknownIdentity(), deviceFacts(), UltraModuleAction.OPEN_WEBUI)
        assertFalse(allowed.blocked)
        val receipt = gate.openWebUiIfAllowed(allowed, ID32)
        assertEquals(1, host.openModuleWebUiCalls)
        assertEquals(ID32, host.lastOpenWebUiId)
        assertTrue(receipt!!.succeeded)
    }

    // ------------------------------------------------------------------ (g) 重复请求无隐藏状态

    @Test
    fun repeatedRequestsRetainDiagnosticsAndExecuteEachSelectedInstall() {
        val h = harness()
        h.transaction.install(request(identity = unknownIdentity()), h.stdout::add, h.stderr::add)
        repeat(2) {
            h.transaction.install(request(), h.stdout::add, h.stderr::add)
        }
        assertEquals(3, h.host.installModuleCalls)
        assertEquals(3, h.host.parseModuleDescriptorCalls)
        assertEquals(3, h.catalog.stageCalls)
        assertEquals(6, h.evidence.events().size)
        assertTrue(h.evidence.events().none { it.outcome == UltraModuleOutcome.BLOCKED })
    }

    // ------------------------------------------------------------------ helpers

    private fun installedItem(id32: String, ver: String, state: MapleSuModRunState) =
        MapleSuModInstalledItem("枫栖示例", "demo", ver, id32, "Maple", "", "", false, state)

    /**
     * 被拦回执的两个稳定码：**与 backend 的公开常量必须逐字相同**。
     *
     * 引用 `MapleSuModuleBackend.KNOWN_INCOMPATIBLE_*`（`const val`，编译期内联）来钉住两处：
     * 任何一侧被改名/改值，这个对照就会失败。不实例化 backend（那需要 `Context`）。
     */
    private object UltraInstallTransactionCodes {
        const val SDK_ERROR = dev.maplesu.manager.modules.MapleSuModuleBackend.KNOWN_INCOMPATIBLE_SDK_ERROR
        const val SDK_ERROR_CODE =
            dev.maplesu.manager.modules.MapleSuModuleBackend.KNOWN_INCOMPATIBLE_SDK_ERROR_CODE
    }
}

/** 一个「成功」的宿主回执。`data` 默认 null：JVM 单测里不碰 `org.json`。 */
private fun receipt(operation: String): NativeReceipt = NativeReceipt(
    schemaVersion = 1,
    backend = UltraRuntimeClient.BACKEND,
    bridgeVersion = 1,
    operation = operation,
    ok = true,
    sdkError = "OK",
    sdkErrorCode = 0,
    reason = null,
    data = null,
    raw = "{}",
)
