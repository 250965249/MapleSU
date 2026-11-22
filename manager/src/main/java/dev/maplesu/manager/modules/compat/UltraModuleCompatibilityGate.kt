package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.runtime.ultra.NativeReceipt
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.util.Locale

/**
 * 「执行前静态兼容门」的接入层：把 `ModuleArchiveInspector.Report` 与设备事实送进 W1-A 的判定，
 * 并给出展示文案与可落盘的证据事件。
 *
 * 这个文件**不做判定**：判定规则与固定记录在 [UltraModuleCompatibility] /
 * [UltraModuleCompatibilityRegistry]（W1-A）。这里只做三件事：
 *
 *  1. [identityFrom]：把静态检查的产物翻译成判定需要的包身份；
 *  2. [evaluate]：转发到 W1-A，不重解释结论；
 *  3. [blockingText] / [evidenceEvent]：给用户看的文案、给交付包看的事件。
 *
 * 纯逻辑、JVM 可测：没有 Android import、没有时钟、没有网络。时间与落盘由调用方
 * （`MapleSuModuleBackend` / `UltraModuleInstallTransaction`）传入 —— 见 [UltraModuleGateEvidenceLog]
 * 只在注入的 sink 上写一行。
 *
 * ## 设备时间与构建摘要
 *
 * 每条事件保留「设备时间」与「构建摘要」。两个字段的生产者
 * 都保持「纯输入 → 纯输出」：
 *
 *  - [deviceTimeIso]：调用方在**事件发生时**用 `System.currentTimeMillis()` 取值，转成 ISO-8601 UTC。
 *    函数本身不取时钟（时钟注入点在被调用方，测试因此能传固定时钟）。
 *  - [UltraModuleBuildDigest]：**要么真实摘要，要么具名「拿不到」原因** —— 不允许静默 null。
 *    唯一带 IO 的是 [UltraModuleBuildDigest.fromApkFile]（读 APK 字节算 SHA-256），JVM 可测。
 */
object UltraModuleCompatibilityGate {

    /**
     * 被拦请求的补充说明：**「结束执行」不等于「模块已停止」**。
     *
     * 开发方案 §4.1/§6.3 明确要求区分「本次请求被拦下」与「内核影响已撤销」。拦截发生在进入原生
     * 执行之前，所以它对**本次**请求有效；已经加载过的旧安装属于 §4.2 的恢复交付，不能被这句话
     * 覆盖。
     */
    private const val BLOCK_EXECUTION_SUFFIX =
        "本次请求没有向 Ultra 宿主发起模块执行调用（安装、宿主描述解析、WebUI 启动次数均为 0）；" +
            "结束执行不等于模块已停止或内核侧影响已撤销。"

    /** UNVERIFIED 的补充说明：不拦，但也不能显示成已兼容。 */
    private const val UNVERIFIED_SUFFIX =
        "本次请求没有被拦下，但上面这个「未验证」状态必须原样展示：不是已兼容，也不是已确认不兼容。"

    /**
     * 把 [ModuleArchiveInspector.Report] 映射成判定用的包身份。
     *
     * 字段来源逐项对应（任何一个字段都不许由调用方「顺手补」）：
     *  - [UltraModulePackageIdentity.id32] ← `Report.id`（Ultra 宿主认识的模块 id）；
     *  - [UltraModulePackageIdentity.version] ← `properties["version"]`（只用于报告与「同版本内容变化」
     *    的诊断，**不参与命中**）；
     *  - [UltraModulePackageIdentity.archiveSha256] ← `Report.sha256`（整个 ZIP 的字节）；
     *  - [UltraModulePackageIdentity.nativePayloadSha256] ← `Report.nativePayloadSha256`
     *    （真正会被加载的那个顶层 `.so` 成员的字节；W1-B 添加，非 MAPLESU 或认不出入口时为 null）；
     *  - [UltraModulePackageIdentity.nativeEntryName] ← `Report.nativeEntry`（仅报告用，不参与命中）。
     *
     * `properties` 是只读 Map，缺少 `version` 时得到空串 —— 判定会把它当成「版本字段缺失」的
     * 诊断项，而不是猜一个版本号出来。
     */
    fun identityFrom(report: ModuleArchiveInspector.Report): UltraModulePackageIdentity =
        UltraModulePackageIdentity(
            id32 = report.id,
            version = report.properties["version"].orEmpty(),
            archiveSha256 = report.sha256,
            nativePayloadSha256 = report.nativePayloadSha256,
            nativeEntryName = report.nativeEntry,
        )

    /**
     * 转发到 W1-A 的判定。存在的意义只有一个：调用方不必自己拼 `UltraSdkIdentity` /
     * `UltraKernelIdentity`，也不会漏掉 `records` 的默认值。
     */
    fun evaluate(
        identity: UltraModulePackageIdentity,
        facts: UltraModuleDeviceFacts,
        action: UltraModuleAction,
        records: List<UltraModuleCompatibilityRecord> = UltraModuleCompatibilityRegistry.records,
    ): UltraModuleCompatibilityVerdict = UltraModuleCompatibility.evaluate(
        pkg = identity,
        sdk = facts.sdkIdentity,
        kernel = facts.kernelIdentity,
        action = action,
        records = records,
    )

    /**
     * 展示文案（中文，可直接进对话框或 stderr）。
     *
     * 三态各自带上「下一步该怎么办」：
     *  - `KNOWN_INCOMPATIBLE`：保留 W1-A 的完整理由，并补一句「本次没有发起模块执行调用」，
     *    避免被读成「模块已停止」；
     *  - `UNVERIFIED`：明确「没拦，但不能显示成已兼容」；
     *  - `VERIFIED`：原样返回 W1-A 的文案（那里已经写明只覆盖记录里的能力）。
     */
    fun blockingText(verdict: UltraModuleCompatibilityVerdict): String = when (verdict.decision) {
        UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE ->
            verdict.displayReason + BLOCK_EXECUTION_SUFFIX

        UltraModuleCompatibilityDecision.UNVERIFIED ->
            verdict.displayReason + UNVERIFIED_SUFFIX

        UltraModuleCompatibilityDecision.VERIFIED -> verdict.displayReason
    }

    /**
     * 设备时间：**事件发生时**由调用方用 `System.currentTimeMillis()` 转换成 ISO-8601 UTC。
     *
     * 为什么不在本类里取时钟：§4.3 的「设备时间」是**事件发生那一刻**的时间戳，取晚了就会把
     * 一次几分钟前的原生调用记成现在。所以时钟由调用方（`UltraModuleInstallTransaction`）在构造
     * 时注入，`System.currentTimeMillis()` 是生产默认值，测试传固定值 —— 这样「事件时间来自
     * 调用方的时钟」这件事才可以被断言，而不是靠读代码相信。
     *
     * `Instant.ofEpochMilli(...).toString()` 的输出一定是带 `Z` 的 ISO-8601（UTC），
     * 与 [UltraModuleEvidenceSanitizer] 的 `ISO_8601` 白名单一致：无毫秒时 `...:20Z`，
     * 有毫秒时 `...:20.123Z`，两种都在白名单内。
     */
    fun deviceTimeIso(epochMillis: Long): String = Instant.ofEpochMilli(epochMillis).toString()

    /**
     * 构造一条「门根本没跑」的事件（安装前置条件不满足时用）。
     *
     * 为什么需要它：§4.3 要求每次安装至少留下一条记录；环境未就绪时安装在第一道检查就返回了，
     * 门（[evidenceEvent]）不会发生。若这里不写，那次安装就成了「零证据」，事后与「根本没尝试」
     * 无法区分。
     *
     * 语义边界（不许含糊）：
     *  - `gate=NOT_EVALUATED`：**明确写「没有做过兼容判定」**，不能借用 `gate=UNVERIFIED`
     *    （那是「判定过但证据不足」）或 `gate=KNOWN_INCOMPATIBLE`（那是「拦下了」）；
     *  - `outcome = FAILURE`：这一步确实没有成功（前置条件不满足），不是 `BLOCKED`
     *    （门没跑，谈不上被门拦住），也不是 `UNKNOWN`（我们知道原因）；
     *  - `returnCode = null`：没有宿主返回码，不写 0。
     */
    fun preconditionEvent(
        action: UltraModuleAction,
        operationId: String,
        bootId: String,
        hostUtcIso: String,
        deviceTimeIso: String?,
        processPid: Int?,
        buildDigest: UltraModuleBuildDigest,
        environmentState: String?,
    ): UltraModuleEvent = UltraModuleEvent(
        operationId = operationId,
        action = action,
        bootId = bootId,
        deviceTimeIso = deviceTimeIso,
        hostUtcIso = hostUtcIso,
        processRole = UltraModuleProcessRole.MANAGER,
        processPid = processPid,
        phase = UltraModulePhase.PRE_EXEC_CHECK,
        returnCode = null,
        buildDigest = buildDigest.digest,
        outcome = UltraModuleOutcome.FAILURE,
        detail = "state=ENVIRONMENT_NOT_READY gate=NOT_EVALUATED action=" + action.name +
            " environment=" + machineToken(environmentState) +
            " build=" + buildDigest.detailToken,
    )

    /**
     * 构造一条「宿主已被调用」的事件（§4.3 的 HOST_CALLED / HOST_REFUSED）。
     *
     * 为什么在 `install` 里只有一条：`parse_module_desc_from_zip_file` 与 `install_module`
     * 是同一次事务里的相邻两步，真正的分界是「宿主有没有收下」。[UltraModulePhase] 没有
     * `HOST_CALLED` 这一档（schema 发布后不改），所以阶段取最贴近的 `NATIVE_ENTRY`
     * （模块原生入口已被调用），**状态码写进 detail 的 `state=`**：
     *
     *  - `state=HOST_CALLED` + `outcome=SUCCESS`：宿主回执成功（只表示这一步成功）；
     *  - `state=HOST_REFUSED` + `outcome=FAILURE`：宿主拒绝（本次没有安装成功）。
     *
     * `returnCode` 取 `NativeReceipt.sdkErrorCode`：那是 SDK 自己的数值返回码，是这里唯一
     * 可核对的东西；桥不存在时它是 `Int.MIN_VALUE`（`MAPLESU_BRIDGE_ABSENT` 的既有码），
     * 照写，不改成 0 也不吞掉。
     */
    fun hostEvent(
        action: UltraModuleAction,
        operationId: String,
        bootId: String,
        hostUtcIso: String,
        deviceTimeIso: String?,
        processPid: Int?,
        buildDigest: UltraModuleBuildDigest,
        install: NativeReceipt,
    ): UltraModuleEvent {
        val accepted = install.succeeded
        return UltraModuleEvent(
            operationId = operationId,
            action = action,
            bootId = bootId,
            deviceTimeIso = deviceTimeIso,
            hostUtcIso = hostUtcIso,
            processRole = UltraModuleProcessRole.MANAGER,
            processPid = processPid,
            phase = UltraModulePhase.NATIVE_ENTRY,
            returnCode = install.sdkErrorCode,
            buildDigest = buildDigest.digest,
            outcome = if (accepted) UltraModuleOutcome.SUCCESS else UltraModuleOutcome.FAILURE,
            detail = "state=" + (if (accepted) "HOST_CALLED" else "HOST_REFUSED") +
                " action=" + action.name +
                " build=" + buildDigest.detailToken,
        )
    }

    /**
     * detail 里允许出现的外部字符串（环境状态之类的 SDK 词表值）先归一成机器 token。
     *
     * 为什么不能直接拼：`UltraModuleEvidenceSanitizer.unsafeReason` 要求 `redact(detail) == detail`，
     * 一条 detail 里只要出现设备给的可疑文本（路径、32 位十六进制），整条事件会被丢弃 ——
     * 那正是「静默少一条」。所以这里只放行 `[A-Za-z0-9._:-]`，其它一律写成 `unreadable`。
     */
    private fun machineToken(value: String?): String {
        val trimmed = value?.trim().orEmpty()
        if (trimmed.isEmpty()) return "unreadable"
        return if (MACHINE_TOKEN.matches(trimmed)) trimmed else "unreadable"
    }

    /** 与 [UltraModuleEvidenceSanitizer] 的 `MACHINE_TOKEN` 同形（那里是 private）。 */
    private val MACHINE_TOKEN = Regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")

    /**
     * 构造一条 §4.3 的故障证据事件（**不落盘**：落盘见 [UltraModuleGateEvidenceLog]）。
     *
     * 字段取舍：
     *  - `processRole = MANAGER`：门发生在管理器进程里，不是模块守护，也不是 WebUI 加载器；
     *  - `phase = PRE_EXEC_CHECK`：此时任何原生代码都还没加载（§4.1 的时序）；
     *  - `returnCode = null`：门这里**没有**宿主返回码。W1-C 的约定是「没有返回码就 null，
     *    不写成 0」——写 0 会让统计把「没调用」误读成「调用返回成功」；
     *  - `outcome`：被拦 = [UltraModuleOutcome.BLOCKED]；未拦（UNVERIFIED / VERIFIED）= 
     *    [UltraModuleOutcome.UNKNOWN] —— 门只说明「这一步可以继续」，不表示动作已经成功；
     *  - `detail` 只写机器码（gate / action / record / codes），不写包哈希、路径与用户数据：
     *    包身份已经由同一 `operationId` 的操作日志（`moduleId` / `packageSha256`）承载，
     *    在证据里再抄一遍只会多一个泄露面（W1-C 的脱敏规则会把 32 位以上十六进制换成 `<hex>`，
     *    抄了也留不住）。
     *
     * @param operationId 与操作日志同一个 id（同一次操作的多条事件靠它对齐）。
     * @param bootId  `/proc/sys/kernel/random/boot_id`；读不到传空串（W1-C：空串 = unknown）。
     * @param hostUtcIso 主机 UTC 时间（调用方取），必须是带时区的 ISO-8601，否则会被脱敏器丢弃。
     * @param deviceTimeIso 设备时间：调用方用 [deviceTimeIso] 把**事件发生那一刻**的
     *   `System.currentTimeMillis()` 转成 ISO-8601 UTC 传进来。默认 null = 调用方没提供
     *   （W1-C：不伪造），生产调用点必须传。
     * @param buildDigest 构建摘要生产者（见 [UltraModuleBuildDigest]）。默认
     *   [UltraModuleBuildDigest.Unavailable] + 原因码 `not-provided`：**「没写」也必须是一个
     *   具名状态**，不能和「写了但拿不到」（`unknown:apk-unreadable` 之类）混成同一个 null。
     */
    fun evidenceEvent(
        verdict: UltraModuleCompatibilityVerdict,
        operationId: String,
        bootId: String,
        hostUtcIso: String,
        processPid: Int? = null,
        deviceTimeIso: String? = null,
        buildDigest: UltraModuleBuildDigest =
            UltraModuleBuildDigest.Unavailable(UltraModuleBuildDigest.REASON_NOT_PROVIDED),
    ): UltraModuleEvent = UltraModuleEvent(
        operationId = operationId,
        action = verdict.action,
        bootId = bootId,
        deviceTimeIso = deviceTimeIso,
        hostUtcIso = hostUtcIso,
        processRole = UltraModuleProcessRole.MANAGER,
        processPid = processPid,
        phase = UltraModulePhase.PRE_EXEC_CHECK,
        returnCode = null,
        buildDigest = buildDigest.digest,
        outcome = when (verdict.decision) {
            UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE -> UltraModuleOutcome.BLOCKED
            UltraModuleCompatibilityDecision.UNVERIFIED,
            UltraModuleCompatibilityDecision.VERIFIED -> UltraModuleOutcome.UNKNOWN
        },
        detail = evidenceDetail(verdict) + " build=" + buildDigest.detailToken,
    )

    /**
     * 证据 detail 的稳定格式：`gate=<决策> action=<动作> record=<记录|none> codes=<逗号分隔的原因码>`。
     *
     * 只放机器可读的稳定值：中文文案会变，原因码不会；包哈希/路径/模块 id 不进来（见
     * [evidenceEvent]）。这样同一条 detail 在设备上、主机侧脚本里都能按 `codes=` 检索。
     */
    fun evidenceDetail(verdict: UltraModuleCompatibilityVerdict): String = buildString {
        append("gate=").append(verdict.decision.name)
        append(" action=").append(verdict.action.name)
        append(" record=").append(verdict.matchedRecordId ?: "none")
        append(" codes=").append(verdict.reasonCodes.joinToString(","))
    }
}

/**
 * §4.3 的 `buildDigest` 生产者：**要么是真实构建摘要，要么是一个具名「拿不到」原因**。
 *
 * ## 为什么不是一个可空 `String`
 *
 * 1. `null` 在 JSONL 里只有一种写法。字段是 null 时，事后无法区分「构建摘要拿不到」与
 *    「代码根本没有产出它」——这正是 W5 复核 S1-2 点名的「系统性缺失」。
 * 2. W1-C 的脱敏器只接受 32/40/64 位十六进制（`UltraModuleEvidenceSanitizer.normalizeBuildDigest`），
 *    把 `unknown` 这类占位串塞进**字段**会被静默置空，又变回 null。
 *
 * 所以：「拿不到」的稳定原因码写进**同一条事件的 detail**（`build=unknown:<原因码>`），
 * 与「没写」（`build=unknown:not-provided`）区分；字段本身仍然是真实摘要或 null。
 * 三种状态因此都可以从一行 JSONL 里读出来：
 *
 * | 场景 | `buildDigest` 字段 | `detail` 里的标记 |
 * |---|---|---|
 * | 拿到摘要 | 64 位小写十六进制 | `build=verified:manager-base-apk` |
 * | 拿不到 | `null` | `build=unknown:apk-unreadable`（或其它原因码） |
 * | 没写 | `null` | `build=unknown:not-provided` |
 *
 * ## 摘要是什么
 *
 * [SOURCE_MANAGER_BASE_APK] 是**管理器自己已安装的那个 APK**（`ApplicationInfo.sourceDir`）的
 * SHA-256：它就是产生这条事件的构建产物，可以拿 `sha256sum` 对着拉下来的 APK 复算。
 * 不用 `BuildConfig.VERSION_NAME` 当摘要：版本号不是字节身份，改一行代码就能保持同版本号。
 */
sealed interface UltraModuleBuildDigest {

    /** 写进 [UltraModuleEvent.buildDigest] 的值：真实摘要，或 null（原因见 [detailToken]）。 */
    val digest: String?

    /** 写进 `detail` 的稳定标记：`verified:<来源>` 或 `unknown:<原因码>`。不含摘要本身。 */
    val detailToken: String

    /** 已算好的摘要。构造时校验格式（见 [of]）。 */
    data class Known(
        override val digest: String,
        val source: String = SOURCE_MANAGER_BASE_APK,
    ) : UltraModuleBuildDigest {
        init {
            // 手写构造也不能把自由文本塞进摘要字段：不合格就当场失败，不留给脱敏器静默置空。
            require(UltraModuleBuildDigest.isValidDigest(digest)) {
                "buildDigest must be 32/40/64 lowercase hex"
            }
        }

        override val detailToken: String get() = "verified:$source"
    }

    /** 拿不到摘要。[reason] 是稳定原因码（本接口的 `REASON_*` 常量），不是自由文本。 */
    data class Unavailable(val reason: String) : UltraModuleBuildDigest {
        override val digest: String? get() = null
        override val detailToken: String get() = "unknown:$reason"
    }

    companion object {

        /** 摘要来源：管理器自身的已安装 APK。 */
        const val SOURCE_MANAGER_BASE_APK = "manager-base-apk"

        /** 「调用方没有提供」（= 没写）。与下面几个「拿不到」的原因码**故意不同**。 */
        const val REASON_NOT_PROVIDED = "not-provided"

        /** 包管理器拿不到自己的 `PackageInfo`（权限、竞态、被替换中）。 */
        const val REASON_PACKAGE_INFO_UNAVAILABLE = "package-info-unavailable"

        /** `PackageInfo.applicationInfo.sourceDir` 为空：没有可读的 APK 路径。 */
        const val REASON_APK_PATH_UNAVAILABLE = "apk-path-unavailable"

        /** 路径存在但不是普通文件（目录、符号链接失效、被删）。 */
        const val REASON_APK_NOT_A_FILE = "apk-not-a-file"

        /** 文件长度为 0：空文件算不出有意义的摘要。 */
        const val REASON_APK_EMPTY = "apk-empty"

        /** 读 APK 字节失败（IO 异常、权限、正在被替换）。 */
        const val REASON_APK_UNREADABLE = "apk-unreadable"

        /** 传进来的摘要不是 32/40/64 位十六进制：不把自由文本混进摘要字段。 */
        const val REASON_DIGEST_INVALID = "digest-invalid"

        /**
         * 与 `UltraModuleEvidenceSanitizer` 的 `BUILD_DIGEST` 同形（那里是 private）。
         * 在这里提前校验，是为了让「不合格摘要」变成一个**具名原因**，而不是等落盘时被
         * 脱敏器静默置空（那时只剩一个 null，看不出为什么）。
         */
        private val BUILD_DIGEST = Regex("^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")

        /** 摘要格式检查（`Known` 的 `init` 也用它，所以是公开的纯函数）。 */
        fun isValidDigest(value: String?): Boolean = value != null && BUILD_DIGEST.matches(value)

        /** 已算好的摘要：大小写归一，格式不合格 → [Unavailable] 的 [REASON_DIGEST_INVALID]。 */
        fun of(digest: String?, source: String = SOURCE_MANAGER_BASE_APK): UltraModuleBuildDigest {
            val normalized = digest?.trim()?.lowercase(Locale.ROOT).orEmpty()
            if (normalized.isEmpty()) return Unavailable(REASON_NOT_PROVIDED)
            if (!isValidDigest(normalized)) return Unavailable(REASON_DIGEST_INVALID)
            return Known(normalized, source)
        }

        /**
         * 从 APK 文件算 SHA-256。**纯 IO，无 Android 依赖**，所以 JVM 单测能用真文件跑。
         *
         * 返回 [Unavailable] 的四种情况都点名了原因（路径为空 / 不是普通文件 / 空文件 / 读失败），
         * 不抛异常：写证据的路径不能因为摘要拿不到而打断安装事务。
         *
         * 成本：读一遍 APK 字节（管理器 APK 约 130 MB）。调用方负责缓存（每进程一次即可），
         * 本函数不做缓存 —— 缓存策略不该藏在一个纯函数里。
         */
        fun fromApkFile(file: File?, source: String = SOURCE_MANAGER_BASE_APK): UltraModuleBuildDigest {
            if (file == null) return Unavailable(REASON_APK_PATH_UNAVAILABLE)
            if (!file.isFile) return Unavailable(REASON_APK_NOT_A_FILE)
            if (file.length() <= 0L) return Unavailable(REASON_APK_EMPTY)
            return try {
                val digest = MessageDigest.getInstance("SHA-256")
                file.inputStream().use { input ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        if (read > 0) digest.update(buffer, 0, read)
                    }
                }
                val hex = digest.digest().joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 255) }
                of(hex, source)
            } catch (_: Exception) {
                Unavailable(REASON_APK_UNREADABLE)
            }
        }
    }
}

/** [UltraModuleGateEvidenceLog.record] 的结果：写了什么，或者为什么没写（原因码）。 */
sealed interface UltraModuleEvidenceRecordResult {

    /** 已把 [line]（单行 JSONL）交给 sink，且没有抛异常。[notes] 是脱敏/降级记录。 */
    data class Appended(val line: String, val notes: List<String>) : UltraModuleEvidenceRecordResult

    /** 没写。 [reason] 是稳定原因码（W1-C 的脱敏原因，或 `append-failed`）。 */
    data class Dropped(val reason: String) : UltraModuleEvidenceRecordResult
}

/**
 * 把门的结论写成一行 JSONL。
 *
 * 为什么落盘放到这个类、而不是塞进 `compat` 的纯逻辑类：W1-C 的 `UltraModuleEvidence` 是纯逻辑
 * （不 import `java.io`），而**写文件**是 Android 侧的约定（`filesDir`）。这里用注入的
 * [appendLine] 把两者接起来：
 *
 *  - 生产实现：`UltraModuleGateEvidenceLog { line -> file.appendText(line) }`；
 *  - 测试实现：把行收进 `MutableList<String>`，直接断言内容（不需要 Context、不需要 Robolectric）。
 *
 * 失败语义：**写证据不能打断安装事务**。sink 抛异常不向外传播（返回
 * [UltraModuleEvidenceRecordResult.Dropped] `append-failed`），否则一个只读文件系统就会让「拦截」
 * 变成「崩溃」。脱敏失败同样只丢这一条，不写半脱敏的行（W1-C 的默认策略 `DROP_WHOLE_EVENT`）。
 *
 * @param appendLine 单行写入（生产传 `File::appendText` 之类的实现）。
 * @param sanitizer 脱敏器；默认策略是「无法安全脱敏就整条丢弃」。
 */
class UltraModuleGateEvidenceLog(
    private val appendLine: (String) -> Unit,
    private val sanitizer: UltraModuleEvidenceSanitizer = UltraModuleEvidenceSanitizer(),
) {

    fun record(event: UltraModuleEvent): UltraModuleEvidenceRecordResult =
        when (val write = sanitizer.sanitizeEvidence(event)) {
            is UltraModuleEvidenceWrite.Dropped -> UltraModuleEvidenceRecordResult.Dropped(write.reason)
            is UltraModuleEvidenceWrite.Recorded -> {
                val line = UltraModuleEvidenceJson.encodeLine(write.event)
                if (runCatching { appendLine(line) }.isSuccess) {
                    UltraModuleEvidenceRecordResult.Appended(line, write.notes)
                } else {
                    UltraModuleEvidenceRecordResult.Dropped("append-failed")
                }
            }
        }
}
