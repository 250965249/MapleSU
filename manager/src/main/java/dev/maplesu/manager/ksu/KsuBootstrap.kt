// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.File
import java.util.concurrent.ConcurrentHashMap

/** Stage next boot's daemon through the current installer's root channel. */
fun ensureNormalBootUserland(
    nativeLibraryDir: File,
    runner: KsuRootCommandRunner,
    onStdout: (String) -> Unit = {},
    onStderr: (String) -> Unit = {},
    dataAdbRoot: File = File("/data/adb"),
): KsuBootstrapResult {
    val daemon = File(nativeLibraryDir, KsuCommands.DAEMON_LIB_NAME)
    val library = File(nativeLibraryDir, KsuBootstrap.LIBADBROOT_NAME)
    if (!library.isFile) return KsuBootstrapResult.failed(KsuBootstrap.CODE_INSTALL_FAILED, "libadbroot.so missing")
    val shell = KsuRootShellExecutor { command ->
        onStdout("- $command")
        val result = try {
            runner.run(command, KsuBootstrap.INSTALL_TIMEOUT_MS)
        } catch (error: Exception) {
            onStderr("${error.javaClass.simpleName}: ${error.message}")
            throw error
        }
        result.out.forEach(onStdout)
        result.err.forEach(onStderr)
        if (result.code != 0) onStderr("- command exitCode=${result.code}")
        result
    }
    val paths = rootShellPathProbe(shell)
    val digest = KsuBootstrap.rootShellDigest(shell)
    val librarySha = KsuInstallProducer.sha256(library)
    val deployed = File(dataAdbRoot, "ksud").absolutePath
    val workDaemon = File(dataAdbRoot, "ksu/bin/ksud").absolutePath
    val deployedLibrary = File(dataAdbRoot, "ksu/lib/libadbroot.so").absolutePath
    val probe = object : KsuPathProbe {
        override fun exists(path: String): Boolean = paths.exists(path) &&
            (path !in setOf(deployed, workDaemon) || paths.canExecute(path)) &&
            (path != deployedLibrary || digest(path) == librarySha)
    }
    val bootstrap = KsuBootstrap(
        daemonPath = daemon.absolutePath,
        runner = KsuRootCommandRunner { command, timeout ->
            // A first switch can lack ksu_file and its working directory. The
            // existing staged installer records its deferred label in this dir.
            val createCommand = KsuInstallProducer.shellJoin(listOf("/system/bin/mkdir", "-p",
                File(dataAdbRoot, "ksu").absolutePath))
            onStdout("- $createCommand")
            val created = runner.run(createCommand, timeout)
            if (created.code != 0) {
                created.copy(err = listOf("bootstrap directory command failed: $createCommand") + created.err)
            } else {
                created.out.forEach(onStdout)
                created.err.forEach(onStderr)
                runner.run(command, timeout)
            }
        },
        dataAdbRoot = dataAdbRoot,
        probe = probe,
        digest = digest,
        expectedKsudSha256 = KsuBootstrap.bundledKsudSha256(daemon),
        versionProbe = { path ->
            val result = shell.exec(KsuInstallProducer.shellJoin(listOf(path, "debug", "build-info")))
            val fields = result.takeIf { it.code == 0 }?.out?.singleOrNull()?.trim()
                ?.let { Regex("MAPLESU_KSUD_BUILD_V1 version=([0-9]+) uapi=([0-9]+)").matchEntire(it) }
            fields?.groupValues?.let { values ->
                val version = values[1].toIntOrNull()
                val uapi = values[2].toIntOrNull()
                if (version == null || uapi == null) null else KsuVersionInfo(version, uapi, false, 0)
            }
        },
        busyboxProbe = KsuBootstrap.rootShellBusyboxProbe(shell),
    )
    return bootstrap.ensureDeployed(library, stageForSwitch = true, onStdout, onStderr)
}

/**
 * 首次 userland bootstrap+ T1「部署内容寻址」。
 *
 * 场景：A→B 首次切换的 S4f（重启前、root 服务内），以及 **Normal 首次启动**
 * （`ModeBootstrap` 激活为 KSU 后，2026-11-01 收尾）。此时 KSU 内核尚未启动，
 * Lite 策略里可能没有 `ksu_file` 类型；因此安装命令必须带 **staging 标签**路径
 * （分支补丁 `0009-install-staging-label.patch` 的 `--stage-for-switch`），
 * 由切换事务记录"待目标内核加载策略后再 restorecon"。
 *
 * 本类只负责：
 * 1. 构造并执行 `libksud_ksu.so install --libadbroot <path> --data-path /data/adb
 *    --stage-for-switch`；
 * 2. 校验安装的**硬事实**：`/data/adb/ksud`、`/data/adb/ksu/bin/ksud`、
 *    `/data/adb/ksu/lib/libadbroot.so` 存在且摘要一致；
 * 3. **T1 内容寻址**：部署的 `/data/adb/ksud` 摘要必须等于 APK 内
 *    `libksud_ksu.so` 的摘要（G6）、`ksud debug info` 的版本必须能与本构建对齐
 *    （`version > 0 && uapi == 7`）、`/data/adb/ksu/bin/busybox true` 退出码必须为 0（A11）；
 * 4. 失败 → 具名 code（[CODE_DIGEST_MISMATCH] / [CODE_VERSION_MISMATCH] /
 *    [CODE_BUSYBOX_UNUSABLE] / [CODE_INSTALL_FAILED] / [CODE_PROBE_FAILED]），
 *    调用方阻断并回滚（不重启）。
 *
 * ⚠️ `/data/adb` 是 **0700 root**：Manager 进程（app uid）连 `stat` 都不行。
 * 因此存在性/摘要/版本/busybox 校验都走可注入的 [probe] / [digest] / [versionProbe] /
 * [busyboxProbe]，生产实现由 root shell 回答（`rootShellPathProbe` / [rootShellDigest] /
 * [rootShellVersionProbe] / [rootShellBusyboxProbe]）。默认值是"主机可算"或"未证明"
 * —— 主机单测用，且**未装配的探针一律按失败处理**（禁止"摘要算不出来就当通过"，C7）。
 *
 * SELinux 标签是否已真正生效是**设备项**：本类只暴露 [Result.Completed.labelVerified]
 * （null = 未验证 → 切换服务必须按"未闭环"处理，禁止首次切换）。主机测试覆盖命令
 * 构造与文件级校验，覆盖不到 label/A`VC`。
 */
class KsuBootstrap(
    private val daemonPath: String,
    private val runner: KsuRootCommandRunner,
    private val dataAdbRoot: File = File("/data/adb"),
    /** 已部署路径的存在性探针（生产 = root shell；主机 = 本地 File）。 */
    private val probe: KsuPathProbe = KsuPathProbe.LOCAL,
    /** 已部署文件的摘要（生产 = root shell `sha256sum`；读不到 → null）。 */
    private val digest: (String) -> String? = { path ->
        runCatching { KsuInstallProducer.sha256(File(path)) }.getOrNull()
    },
    /**
     * APK 内 `libksud_ksu.so` 的期望摘要 —— 内容寻址的**唯一权威**（T1）。
     *
     * `null` = 算不出来（APK 缺库/构建缺陷）。此时 [ensureDeployed] **必须失败**
     * （[CODE_DIGEST_MISMATCH]）：没有权威摘要就没有"对"可言，绝不静默放行（C7）。
     * 生产由装配层用 [bundledKsudSha256] 在后台线程只算一次。
     */
    private val expectedKsudSha256: String? = null,
    /**
     * `ksud debug info` 版本探针（参数 = 已部署 ksud 的绝对路径）。
     *
     * 默认 `{ null }` = 未装配 → 版本无法证明 → [CODE_PROBE_FAILED]（fail-closed）。
     * 生产见 [rootShellVersionProbe]。
     */
    private val versionProbe: (String) -> KsuVersionInfo? = { null },
    /**
     * busybox 可用性探针（参数 = `<dataAdbRoot>/ksu/bin/busybox` 的绝对路径）。
     *
     * 判据是**真跑一次** `busybox true` 的退出码 == 0（A11：文件在但执行崩的坏 busybox
     * 只有真跑才能发现）。默认 `{ false }` = 未装配 → 不可用 → 强制重装 binaries。
     * 生产见 [rootShellBusyboxProbe]。
     */
    private val busyboxProbe: (String) -> Boolean = { false },
    /** 部署回执落点（`filesDir/ksu_deploy.json`）；`null` = 不写（主机测试/未装配）。 */
    private val receiptFile: File? = null,
    /** 回执里的内核版本；默认 `os.version`（Android 上即 `uname -r` 的版本串）。 */
    private val kernelVersion: () -> String = { System.getProperty("os.version") ?: "" },
    // ⚠️ `clock` 必须保持在**最后一个**参数：既有测试用尾随 lambda 传它
    // （`KsuBootstrap(daemon, runner, dataRoot) { 42L }`），插到中间会改变绑定目标。
    private val clock: () -> Long = { System.currentTimeMillis() },
) {

    /** bootstrap 计划（命令 argv 已被 [KsuCommands.install] 参数级校验）。 */
    data class Plan(
        val tokens: List<String>,
        val commandLine: String,
        val libadbroot: File,
        val libadbrootSha256: String,
        val stagedForSwitch: Boolean,
        val createdAt: Long,
    )

    sealed class Result {
        data class Completed(
            val ksudInstalled: File,
            val workDirKsud: File,
            val libadbrootInstalled: File,
            val libadbrootSha256: String,
            /** null = 未验证（设备侧 restorecon 后由 S6 复核）；false = 明确失败。 */
            val labelVerified: Boolean?,
            /**
             * 安装后**同一轮**实证的校验事实（T1）。
             *
             * 让 [ensureDeployed] 不必再跑一遍 6.6 MB 摘要与两次 root 探针；
             * `null` = 旧调用方未提供（[ensureDeployed] 会自己重新 [verify]）。
             */
            val verification: Verification? = null,
        ) : Result()

        data class Failed(val code: String, val detail: String) : Result()
    }

    data class Verification(
        val ksudPresent: Boolean,
        val workDirKsudPresent: Boolean,
        val libadbrootPresent: Boolean,
        val libadbrootDigestMatches: Boolean?,
        /** T1：已部署 `/data/adb/ksud` 的实测摘要；读不到 = null（**不等于**"通过"）。 */
        val ksudSha256: String? = null,
        /** T1：`ksud debug info` 解析结果；探针失败/输出不可解析 = null。 */
        val ksudVersion: KsuVersionInfo? = null,
        /** T1：`/data/adb/ksu/bin/busybox true` 退出码 == 0（A11）。 */
        val busyboxOk: Boolean = false,
    ) {
        val complete: Boolean
            get() = ksudPresent && workDirKsudPresent && libadbrootPresent &&
                libadbrootDigestMatches != false

        /** T1 内容寻址：期望摘要缺失 / 实际读不到 / 不相等 → 一律不匹配（C7）。 */
        fun digestMatches(expectedKsudSha256: String?): Boolean {
            val expected = expectedKsudSha256?.trim() ?: return false
            val actual = ksudSha256 ?: return false
            return actual.equals(expected, ignoreCase = true)
        }

        /** T1 版本：探针必须成功，且 `version > 0 && uapi == 7`。 */
        val versionMatches: Boolean get() = ksudVersion?.matchesBuild == true

        /**
         * 四态短路的**唯一**判据（T1）：`complete && 摘要 && 版本 && busybox` 全对。
         *
         * 「文件存在但内容旧/版本旧/busybox 坏」必须走重装，**不得**返回
         * `ALREADY_PRESENT`（开发文档 §6-T1 实现要求 2）。
         */
        fun deployable(expectedKsudSha256: String?): Boolean =
            complete && digestMatches(expectedKsudSha256) && versionMatches && busyboxOk

        /** 不满足时的可读原因（只进 detail/日志，不参与判定）。 */
        fun mismatchDetail(expectedKsudSha256: String?): String = when {
            !ksudPresent -> "ksud missing: $KSUD_NAME"
            !workDirKsudPresent -> "work-dir ksud missing: ksu/bin/$KSUD_NAME"
            !libadbrootPresent -> "$LIBADBROOT_NAME missing"
            libadbrootDigestMatches == false -> "$LIBADBROOT_NAME digest mismatch"
            !digestMatches(expectedKsudSha256) ->
                "ksud digest not proven: actual=$ksudSha256 " +
                    "expected=${expectedKsudSha256 ?: "unavailable"}"
            !versionMatches ->
                "ksud version not proven: ${ksudVersion ?: "`debug info` unavailable"} " +
                    "(required version>0, uapi=${KsuVersionInfo.REQUIRED_UAPI_VERSION})"
            !busyboxOk -> "busybox unusable: $BUSYBOX_RELATIVE_PATH `true` rc != 0"
            else -> "ok"
        }
    }

    fun plan(libadbroot: File?, stageForSwitch: Boolean = true): Plan {
        requireNotNull(libadbroot) { "libadbroot is required for mode B bootstrap" }
        require(libadbroot.isFile) { "libadbroot missing: ${libadbroot.absolutePath}" }
        require(libadbroot.name == LIBADBROOT_NAME) {
            "expected $LIBADBROOT_NAME, got ${libadbroot.name}"
        }
        val tokens = KsuCommands.install(
            daemon = daemonPath,
            libadbroot = libadbroot,
            dataPath = dataAdbRoot,
            stageForSwitch = stageForSwitch,
        )
        return Plan(
            tokens = tokens,
            commandLine = KsuInstallProducer.shellJoin(tokens),
            libadbroot = libadbroot,
            libadbrootSha256 = KsuInstallProducer.sha256(libadbroot),
            stagedForSwitch = stageForSwitch,
            createdAt = clock(),
        )
    }

    /** 执行 bootstrap；失败返回 [FAILURE_CODE]，调用方不得继续写分区。 */
    fun run(
        libadbroot: File?,
        stageForSwitch: Boolean = true,
        onStdout: (String) -> Unit = {},
        onStderr: (String) -> Unit = {},
    ): Result {
        val plan = try {
            plan(libadbroot, stageForSwitch)
        } catch (t: Throwable) {
            return Result.Failed(FAILURE_CODE, "${t.javaClass.simpleName}: ${t.message}")
        }
        onStdout("- ${plan.commandLine}")
        val result = try {
            runner.run(plan.commandLine, INSTALL_TIMEOUT_MS)
        } catch (error: Exception) {
            val detail = "command=${plan.commandLine}\n${error.javaClass.simpleName}: ${error.message}"
            onStderr(detail)
            return Result.Failed(FAILURE_CODE, detail)
        }
        result.out.forEach { onStdout(it) }
        result.err.forEach { onStderr(it) }
        onStdout("- ksud install exitCode=${result.code}")
        if (result.code != 0) {
            return Result.Failed(
                FAILURE_CODE,
                "command=${plan.commandLine}\nksud install code=${result.code}\n" +
                    "stdout:\n${result.outText}\nstderr:\n${result.errText}",
            )
        }
        val verification = verify(plan.libadbrootSha256)
        if (!verification.complete) {
            return Result.Failed(
                FAILURE_CODE,
                "post-install verification failed: ksud=${verification.ksudPresent} " +
                    "workDir=${verification.workDirKsudPresent} " +
                    "libadbroot=${verification.libadbrootPresent} " +
                    "digest=${verification.libadbrootDigestMatches}",
            )
        }
        return Result.Completed(
            ksudInstalled = File(dataAdbRoot, KSUD_NAME),
            workDirKsud = File(dataAdbRoot, "ksu/bin/ksud"),
            libadbrootInstalled = File(dataAdbRoot, "ksu/lib/$LIBADBROOT_NAME"),
            libadbrootSha256 = plan.libadbrootSha256,
            // 标签是设备事实；主机/切换服务无法在此证明，必须留给 S6 的 restorecon 复核。
            labelVerified = null,
            // T1：同一轮的摘要/版本/busybox 实证随结果返回（ensureDeployed 直接消费）。
            verification = verification,
        )
    }

    fun verify(expectedLibadbrootSha256: String? = null): Verification {
        val ksud = File(dataAdbRoot, KSUD_NAME)
        val workDirKsud = File(dataAdbRoot, "ksu/bin/ksud")
        val libadbroot = File(dataAdbRoot, "ksu/lib/$LIBADBROOT_NAME")
        val ksudPresent = probe.exists(ksud.absolutePath)
        val workDirPresent = probe.exists(workDirKsud.absolutePath)
        val libPresent = probe.exists(libadbroot.absolutePath)
        val matches = if (expectedLibadbrootSha256 != null && libPresent) {
            // 读不到摘要 = "未验证"（null），不是"不一致"（false）。
            digest(libadbroot.absolutePath)?.let { it == expectedLibadbrootSha256 }
        } else if (expectedLibadbrootSha256 != null) {
            false
        } else {
            null
        }
        // T1：内容寻址 + 版本 + busybox。ksud 不存在时没有可问的对象，三项一律"未证明"
        // （由 ensureDeployed 决定重装/失败，绝不当成通过）。
        val ksudSha = if (ksudPresent) digest(ksud.absolutePath) else null
        val ksudVersion = if (ksudPresent) probeVersion(ksud.absolutePath) else null
        val busyboxOk = if (ksudPresent) probeBusybox(busyboxPath()) else false
        return Verification(
            ksudPresent = ksudPresent,
            workDirKsudPresent = workDirPresent,
            libadbrootPresent = libPresent,
            libadbrootDigestMatches = matches,
            ksudSha256 = ksudSha,
            ksudVersion = ksudVersion,
            busyboxOk = busyboxOk,
        )
    }

    private fun probeVersion(ksudPath: String): KsuVersionInfo? =
        runCatching { versionProbe(ksudPath) }.getOrNull()

    private fun probeBusybox(path: String): Boolean =
        runCatching { busyboxProbe(path) }.getOrDefault(false)

    /** `<dataAdbRoot>/ksu/bin/busybox`（生产即 `/data/adb/ksu/bin/busybox`）。 */
    private fun busyboxPath(): String = File(dataAdbRoot, BUSYBOX_RELATIVE_PATH).absolutePath

    /**
     * 首次启动/切换前的**显式状态**（给接线层与诊断用；不要在失败时静默）。
     *
     * 与 [run] 的区别：多一条"已经部署好了"的短路，避免每次重启都重跑 `ksud install`
     * （幂等安装本身也会改写 `/data/adb`，没有理由每次开机做一次）。
     *
     * **T1 短路判据**（唯一）：`complete && digestMatches && versionMatches && busyboxOk`。
     * 任何一项不满足（内容旧 / 版本旧 / busybox 坏 / 摘要读不到）都必须重装；
     * 重装后仍不满足 → `FAILED` + 具名 code。**不存在**"旧文件还能用就算 ALREADY_PRESENT"。
     *
     * [KsuDeployReceipt] 不参与短路：回执是上一次部署的事实记录，不能替代本轮对
     * 已部署字节的实证（C7）。
     */
    fun ensureDeployed(
        libadbroot: File?,
        stageForSwitch: Boolean = true,
        onStdout: (String) -> Unit = {},
        onStderr: (String) -> Unit = {},
    ): KsuBootstrapResult {
        val expected = expectedKsudSha256
        if (expected == null) {
            // C7：APK 侧摘要算不出来 ⇒ 没有"对"的基准。宁可失败，也不能"看起来部署好了"。
            return KsuBootstrapResult.failed(
                CODE_DIGEST_MISMATCH,
                "expected ksud sha256 unavailable (bundled ${KsuCommands.DAEMON_LIB_NAME} " +
                    "missing or unreadable); content addressing cannot be proven",
            )
        }
        val before = verify()
        if (before.deployable(expected)) {
            return KsuBootstrapResult(
                status = KsuBootstrapResult.Status.ALREADY_PRESENT,
                ksudPath = File(dataAdbRoot, KSUD_NAME).absolutePath,
                workDirKsudPath = File(dataAdbRoot, "ksu/bin/ksud").absolutePath,
                libadbrootPath = File(dataAdbRoot, "ksu/lib/$LIBADBROOT_NAME").absolutePath,
                detail = "content verified ${verifiedDetail(before)}",
            )
        }
        // 先解释"为什么不短路"，再重装：这条日志是设备排障的第一手材料。
        onStdout("- pre-check: ${before.mismatchDetail(expected)} → reinstalling binaries")
        return when (val result = run(libadbroot, stageForSwitch, onStdout, onStderr)) {
            is Result.Completed -> {
                val after = result.verification ?: verify()
                val failure = t1Failure(expected, after)
                if (failure != null) {
                    KsuBootstrapResult.failed(failure.first, failure.second)
                } else {
                    val receipt = writeReceipt(after)
                    KsuBootstrapResult(
                        status = KsuBootstrapResult.Status.DEPLOYED,
                        ksudPath = result.ksudInstalled.absolutePath,
                        workDirKsudPath = result.workDirKsud.absolutePath,
                        libadbrootPath = result.libadbrootInstalled.absolutePath,
                        detail = "labelVerified=${result.labelVerified} " +
                            "content verified ${verifiedDetail(after)} receipt=$receipt",
                    )
                }
            }
            is Result.Failed -> KsuBootstrapResult.failed(
                // 任何"没能装上/装上但不完整"都归 install 失败；原始 code 保留在 detail 里。
                CODE_INSTALL_FAILED,
                "${result.code}: ${result.detail}",
            )
        }
    }

    /**
     * 安装后 T1 的具名失败（按"能定位到的最早一项"报）：
     * 摘要读不到/版本探不到 → [CODE_PROBE_FAILED]；摘要不等 → [CODE_DIGEST_MISMATCH]；
     * 版本不等 → [CODE_VERSION_MISMATCH]；busybox 不可用 → [CODE_BUSYBOX_UNUSABLE]。
     */
    private fun t1Failure(expected: String, verification: Verification): Pair<String, String>? =
        when {
            verification.ksudSha256 == null -> CODE_PROBE_FAILED to
                "post-install probe failed: deployed ksud digest unreadable"
            !verification.digestMatches(expected) -> CODE_DIGEST_MISMATCH to
                "post-install digest mismatch: actual=${verification.ksudSha256} expected=$expected"
            verification.ksudVersion == null -> CODE_PROBE_FAILED to
                "post-install probe failed: `ksud debug info` unavailable/unparsable at " +
                File(dataAdbRoot, KSUD_NAME).absolutePath
            !verification.versionMatches -> CODE_VERSION_MISMATCH to
                "post-install version mismatch: ${verification.ksudVersion} " +
                "(required version>0, uapi=${KsuVersionInfo.REQUIRED_UAPI_VERSION})"
            !verification.busyboxOk -> CODE_BUSYBOX_UNUSABLE to
                "post-install busybox unusable: ${busyboxPath()} `true` rc != 0 (A11)"
            else -> null
        }

    /** 部署成功后的回执写入；返回只进 detail/日志，**不**改变部署结论。 */
    private fun writeReceipt(verification: Verification): String {
        val target = receiptFile ?: return "skipped"
        val sha = verification.ksudSha256 ?: return "skipped"
        val version = verification.ksudVersion ?: return "skipped"
        val written = KsuDeployReceipt.write(
            target,
            KsuDeployReceipt(
                sha256 = sha,
                version = version.version,
                uapiVersion = version.uapiVersion,
                busyboxOk = verification.busyboxOk,
                deployedAt = clock(),
                kernelVersionAtDeploy = kernelVersion(),
            ),
        )
        KsuLog.record(
            "deploy-receipt",
            if (written) "written ${target.absolutePath}" else "write failed ${target.absolutePath}",
        )
        return if (written) "written" else "failed"
    }

    private fun verifiedDetail(verification: Verification): String {
        val version = verification.ksudVersion
        return "sha256=${verification.ksudSha256} version=${version?.version} " +
            "uapi=${version?.uapiVersion} " +
            "busybox=${if (verification.busyboxOk) "ok" else "unusable"}"
    }

    companion object {
        const val FAILURE_CODE = "SWITCH_BOOTSTRAP_FAILED"
        const val LIBADBROOT_NAME = "libadbroot.so"
        const val KSUD_NAME = "ksud"

        /** install 会解包/复制二进制，按 boot-patch 同量级窗口（180s）给足时间。 */
        const val INSTALL_TIMEOUT_MS = 180_000L

        // ── T1：部署自校验的具名失败码（禁止静默成功；UI 只映射，不做字符串匹配）──

        /** APK 侧摘要缺失，或已部署 `/data/adb/ksud` 的摘要与 APK 内 `libksud_ksu.so` 不等。 */
        const val CODE_DIGEST_MISMATCH = "KSUD_DIGEST_MISMATCH"

        /** `ksud debug info` 的 `version`/`uapi_version` 与本构建（`uapi == 7`）不一致。 */
        const val CODE_VERSION_MISMATCH = "KSUD_VERSION_MISMATCH"

        /** `/data/adb/ksu/bin/busybox true` 退出码非 0（A11：坏 busybox 会让所有模块脚本 spawn 失败）。 */
        const val CODE_BUSYBOX_UNUSABLE = "KSUD_BUSYBOX_UNUSABLE"

        /** `ksud install` 非 0 退出，或装完后的硬校验（文件/摘要）不完整。 */
        const val CODE_INSTALL_FAILED = "KSUD_INSTALL_FAILED"

        /** 探针本身失败（摘要读不到 / `debug info` 跑不起来或输出不可解析）。 */
        const val CODE_PROBE_FAILED = "KSUD_PROBE_FAILED"

        /** busybox 相对 [KsuBootstrap.dataAdbRoot] 的路径（生产 = `/data/adb/ksu/bin/busybox`）。 */
        const val BUSYBOX_RELATIVE_PATH = "ksu/bin/busybox"

        /**
         * 生产存在性探针见 `KsuRootShell.rootShellPathProbe`（`-e` / `-x` 两问分开答）；
         * 这里只保留摘要读取：`/data/adb` 是 0700 root，必须由 root shell 算。
         */
        fun rootShellDigest(exec: KsuRootShellExecutor): (String) -> String? = { path ->
            val quoted = "'" + path.replace("'", "'\\''") + "'"
            val result = runCatching { exec.exec("/system/bin/sha256sum $quoted") }.getOrNull()
            if (result == null || result.code != 0) {
                null
            } else {
                result.outText.trim().split(Regex("\\s+")).firstOrNull()
                    ?.takeIf { it.length == 64 && it.all { ch -> ch.isDigit() || ch in 'a'..'f' } }
            }
        }

        /**
         * 生产版本探针（T1）：root shell 执行 `<ksud> debug info`，[KsuVersionInfo.parse] 解析。
         *
         * 命令跑不起来 / 非 0 退出 / 输出不可解析 → `null`（由 [ensureDeployed] 报
         * [CODE_PROBE_FAILED]，**不猜**版本）。
         */
        fun rootShellVersionProbe(exec: KsuRootShellExecutor): (String) -> KsuVersionInfo? = { daemon ->
            val line = KsuInstallProducer.shellJoin(listOf(daemon, "debug", "info"))
            val result = runCatching { exec.exec(line) }.getOrNull()
            if (result == null || result.code != 0) null else KsuVersionInfo.parse(result.outText)
        }

        /**
         * 生产 busybox 探针（T1 / A11）：root shell 执行 `<busybox> true`，**退出码必须为 0**。
         *
         * 不能用 `test -x` 代替：A11 的坏 busybox 是"文件在、一执行就崩"（旧版/缺链接器），
         * 只有真跑一次才能区分。
         */
        fun rootShellBusyboxProbe(exec: KsuRootShellExecutor): (String) -> Boolean = { busybox ->
            val line = KsuInstallProducer.shellJoin(listOf(busybox, "true"))
            val result = runCatching { exec.exec(line) }.getOrNull()
            result != null && result.code == 0
        }

        /** APK 内 `libksud_ksu.so` 摘要的进程级缓存（按 path+length+mtime 命中）。 */
        private val bundledDigestCache = ConcurrentHashMap<String, String>()

        /**
         * APK 内 `libksud_ksu.so` 的期望摘要 —— 内容寻址的权威来源（T1）。
         *
         * 6.6 MB：按 `(path, length, mtime)` 做**进程级**缓存，同一 APK 只算一次；
         * `ConcurrentHashMap` 保证装配线程与诊断线程并发读安全。
         * 文件不存在/读失败 → `null` ⇒ 调用方必须按"不可验证"失败（C7）。
         */
        fun bundledKsudSha256(file: File): String? {
            if (!runCatching { file.isFile }.getOrDefault(false)) return null
            val key = "${file.absolutePath}|${file.length()}|${file.lastModified()}"
            bundledDigestCache[key]?.let { return it }
            val sha = runCatching { KsuInstallProducer.sha256(file) }.getOrNull() ?: return null
            bundledDigestCache[key] = sha
            return sha
        }
    }
}

class KsuBootstrapFailure(val result: KsuBootstrapResult) : IllegalStateException(
    result.failureCode ?: KsuBootstrap.CODE_INSTALL_FAILED,
)

/** 首次 userland 部署的显式结果（接线层/诊断唯一状态来源；失败不得静默）。 */
data class KsuBootstrapResult(
    val status: Status,
    val ksudPath: String?,
    val workDirKsudPath: String?,
    val libadbrootPath: String?,
    val failureCode: String? = null,
    val detail: String = "",
) {
    enum class Status {
        /** 本次执行 `ksud install` 并校验通过。 */
        DEPLOYED,

        /** 开机前就已部署（跳过重装）。 */
        ALREADY_PRESENT,

        /** 当前模式不是 KSU：什么都不做（显式，不静默）。 */
        SKIPPED_NOT_KSU,

        /** 部署/校验失败；[failureCode] 必填。 */
        FAILED,
    }

    val ok: Boolean get() = status == Status.DEPLOYED || status == Status.ALREADY_PRESENT

    companion object {
        fun skipped(): KsuBootstrapResult = KsuBootstrapResult(
            status = Status.SKIPPED_NOT_KSU,
            ksudPath = null,
            workDirKsudPath = null,
            libadbrootPath = null,
            detail = "mode is not KSU",
        )

        fun failed(code: String, detail: String): KsuBootstrapResult = KsuBootstrapResult(
            status = Status.FAILED,
            ksudPath = null,
            workDirKsudPath = null,
            libadbrootPath = null,
            failureCode = code,
            detail = detail,
        )
    }
}
