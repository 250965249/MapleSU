// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.File

/**
 * ksud 命令面的**唯一构造入口** + 参数级硬拒绝。
 *
 * 三条不可谈判的规则：
 * 1. `boot-patch` **只产候选文件**（`-o <outDir>`），绝不 flash；`--flash`/`-f` 等
 *    任何会写分区的 flag 在构造层被拒绝，而不是靠调用方自觉。
 * 2. 所有分区写入走 `InstallerPartitionService`（D10）；7K 的 `flash_partition`
 *    即使写后校验，也不在我方 journal 内，失败无法与切换事务联动 → 禁。
 * 3. `--partition` 只在 `boot-patch` 允许，且值必须在 [ALLOWED_BOOT_PARTITIONS] 内
 *    （B 模式首版只支持 `init_boot`/`boot`）；出现在其它子命令里一律拒绝。
 *
 * 禁用参数包括 --flash/--backup/--ota/--partition/--restore、
 * --force-foreign/--no-install/--kernel，并在测试里逐项覆盖。
 */
object KsuCommands {
    const val DAEMON_LIB_NAME = "libksud_ksu.so"

    /**
     * **部署后**的 ksud 路径（`KsuBootstrap`/`ksud install --data-path /data/adb` 的产物）。
     *
     * 内核侧 rc 固定 `exec /data/adb/ksud`（`third_party/kernelsu/applied/kernel/runtime/
     * ksud_integration.c:40-49`、`sucompat.c:198`），所以这是**主路径**；
     * [WORKDIR_DAEMON] 是同一份二进制的 work-dir 形态（`ksud install` 的副产品），
     * 只在主路径不可执行时使用。
     *
     * KSU 模式下 `getKsuDaemonPath()`/`execKsud` 必须指向这里 —— APK 里**没有**
     * `libksud.so`（那是 Ultra 的运行时），指向它只会让每条命令都失败。
     */
    const val DEPLOYED_DAEMON = "/data/adb/ksud"

    const val WORKDIR_DAEMON = "/data/adb/ksu/bin/ksud"

    /** 任何情况下都不允许出现在我们构造/透传的命令里的 flag。 */
    val FORBIDDEN_TOKENS: Set<String> = setOf(
        "--flash", "-f",
        "--backup",
        "--ota", "-u",
        "--force-foreign",
        "--no-install",
        "--kernel",
        "--restore",
        "--partition", // 仅 boot-patch 的受控构造允许；raw 透传一律拒绝
    )

    /** `boot-patch --partition` 的允许值（首版单分区）。 */
    val ALLOWED_BOOT_PARTITIONS: Set<String> = setOf("boot", "init_boot")

    private val KMI_PATTERN = Regex("^[A-Za-z0-9._-]{1,64}$")
    private val FILE_NAME_PATTERN = Regex("^[A-Za-z0-9._-]{1,128}$")
    private val FEATURE_KEY_PATTERN = Regex("^[a-z][a-z0-9_]{1,63}$")
    private val MODULE_ID_PATTERN = Regex("^[a-zA-Z][a-zA-Z0-9._-]+$")
    private val BOOT_BLOCK_MODULE_PATTERN = Regex("^[A-Za-z0-9._-]{1,128}$")
    private val PACKAGE_PATTERN = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")

    fun daemonPath(nativeLibraryDir: File): String =
        File(nativeLibraryDir, DAEMON_LIB_NAME).absolutePath

    fun assertDaemon(daemon: String): String {
        val name = File(daemon).name
        if (name != DAEMON_LIB_NAME && name != "ksud") {
            throw KsuCommandRejectedException(daemon, "unexpected ksud executable: $daemon")
        }
        return daemon
    }

    /**
     * 参数级硬拒绝。`allowPartition` 仅供 [bootPatch] 内部受控构造调用；
     * 任何外部透传（模块 action、feature 值、用户输入）都必须 `allowPartition=false`。
     */
    fun rejectForbidden(tokens: List<String>, allowPartition: Boolean = false) {
        for (token in tokens) {
            val flag = token.substringBefore('=')
            val forbidden = flag in FORBIDDEN_TOKENS &&
                !(allowPartition && flag == "--partition")
            if (forbidden) {
                KsuLog.rejected("KsuCommands", flag)
                throw KsuCommandRejectedException(
                    flag, "refusing git/flash-class ksud argument: $flag (D10: writes go " +
                        "through InstallerPartitionService)")
            }
        }
    }

    // ── boot-patch：候选生产者（绝不写分区）──────────────────────────────
    /**
     * 构造 `ksud boot-patch -b <src> --partition <p> -o <outDir> --out-name <name>
     * --kmi <kmi> [--allow-shell] [--enable-adbd] [--force-feature k:v]...
     * [--block-module a,b]`。
     *
     * produceCandidate 命令形态；`--flash` 等在这里
     * 根本不会被拼出来，且构造结果会再过一遍 [rejectForbidden]（纵深防御）。
     */
    fun bootPatch(
        daemon: String,
        sourceImage: File,
        outDir: File,
        outName: String,
        options: KsuBootPatchOptions,
    ): List<String> {
        assertDaemon(daemon)
        require(sourceImage.isFile) { "source image missing: ${sourceImage.absolutePath}" }
        require(outDir.isDirectory || outDir.mkdirs()) { "outDir unavailable: $outDir" }
        if (!FILE_NAME_PATTERN.matches(outName)) {
            throw KsuCommandRejectedException(outName, "illegal out-name: $outName")
        }
        val partition = options.partition
        if (partition !in ALLOWED_BOOT_PARTITIONS) {
            throw KsuCommandRejectedException(
                "--partition=$partition", "partition not allowed: $partition " +
                    "(allowed=${ALLOWED_BOOT_PARTITIONS.sorted()})")
        }
        options.kmi?.let {
            if (!KMI_PATTERN.matches(it)) {
                throw KsuCommandRejectedException("--kmi=$it", "illegal kmi: $it")
            }
        }
        options.forceFeatures.keys.forEach {
            if (!FEATURE_KEY_PATTERN.matches(it)) {
                throw KsuCommandRejectedException("--force-feature=$it", "illegal feature key: $it")
            }
        }
        options.blockModules.forEach {
            if (!BOOT_BLOCK_MODULE_PATTERN.matches(it)) {
                throw KsuCommandRejectedException("--block-module=$it", "illegal module id: $it")
            }
        }

        val cmd = mutableListOf(
            daemon, "boot-patch",
            "-b", sourceImage.absolutePath,
            "--partition", partition,
            "-o", outDir.absolutePath,
            "--out-name", outName,
        )
        options.kmi?.let { cmd += listOf("--kmi", it) }
        if (options.allowShell) cmd += "--allow-shell"
        if (options.enableAdb) cmd += "--enable-adbd"
        options.forceFeatures.toSortedMap().forEach { (k, v) ->
            cmd += listOf("--force-feature", "$k:$v")
        }
        if (options.blockModules.isNotEmpty()) {
            cmd += listOf("--block-module", options.blockModules.joinToString(","))
        }
        rejectForbidden(cmd, allowPartition = true)
        return cmd
    }

    /**
     * 构造「从当前分区做出可还原镜像」的非 flash 形态：
     * `ksud boot-restore -o <outDir> --out-name <name>`（**无** `-f`/`--flash`）。
     */
    fun bootRestoreImage(
        daemon: String,
        outDir: File,
        outName: String,
    ): List<String> {
        assertDaemon(daemon)
        require(outDir.isDirectory || outDir.mkdirs()) { "outDir unavailable: $outDir" }
        if (!FILE_NAME_PATTERN.matches(outName)) {
            throw KsuCommandRejectedException(outName, "illegal out-name: $outName")
        }
        val cmd = mutableListOf(
            daemon, "boot-restore",
            "-o", outDir.absolutePath,
            "--out-name", outName,
        )
        rejectForbidden(cmd, allowPartition = false)
        return cmd
    }

    /** Rebuild only the supplied file; ksud does not consult or clean global backups. */
    fun bootRebuildCopy(daemon: String, input: File, outDir: File, outName: String): List<String> {
        assertDaemon(daemon)
        require(java.nio.file.Files.isRegularFile(input.toPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            "input copy missing: $input"
        }
        require(outDir.isDirectory || outDir.mkdirs()) { "outDir unavailable: $outDir" }
        if (!FILE_NAME_PATTERN.matches(outName) || outName in setOf(".", "..")) {
            throw KsuCommandRejectedException(outName, "illegal out-name: $outName")
        }
        require(!File(outDir, outName).exists() &&
            !java.nio.file.Files.isSymbolicLink(File(outDir, outName).toPath())) { "output already exists" }
        val cmd = listOf(daemon, "boot-restore", "--file-only", "--boot", input.absolutePath,
            "-o", outDir.absolutePath, "--out-name", outName)
        rejectForbidden(cmd)
        return cmd
    }

    // ── boot-info / debug / module / feature / profile ───────────────────
    fun bootInfo(daemon: String, subcommand: String, image: File? = null): List<String> {
        assertDaemon(daemon)
        require(subcommand in KsuBootInfoSubcommand.ALL_NAMES) { "unknown boot-info: $subcommand" }
        val cmd = mutableListOf(daemon, "boot-info", subcommand)
        if (image != null) {
            require(image.isFile) { "image missing: ${image.absolutePath}" }
            if (subcommand == KsuBootInfoSubcommand.RAMDISK_STATE) {
                cmd += listOf("--boot", image.absolutePath)
            } else {
                throw KsuCommandRejectedException(
                    "--boot", "boot-info ${subcommand} does not accept an image")
            }
        }
        rejectForbidden(cmd)
        return cmd
    }

    fun debugInfo(daemon: String): List<String> = assertDaemon(daemon).let { listOf(it, "debug", "info") }

    fun module(daemon: String, subcommand: String, id: String? = null): List<String> {
        assertDaemon(daemon)
        val cmd = mutableListOf(daemon, "module", subcommand)
        if (id != null) {
            if (!MODULE_ID_PATTERN.matches(id)) {
                throw KsuCommandRejectedException("module=$id", "illegal module id: $id")
            }
            cmd += id
        }
        rejectForbidden(cmd)
        return cmd
    }

    /**
     * `ksud module action <id>` —— **不带任何 flag**。
     *
     * 上游 KernelSU 的形态是 `withNewRootShell(true) { "${ksud} module action $id" }`
     * （`upstream/manager/app/src/main/java/me/weishu/kernelsu/ui/util/KsuCli.kt:282-285`）：
     * 全局挂载命名空间由 **root shell** 提供，命令本身没有 `-g`。
     *
     * `Module::Action` 只声明了 `id`（`third_party/kernelsu/applied/userspace/ksud/src/cli.rs`
     * 的 `Action` 分支），`-g` 只存在于 `debug su`；拼上去会被 clap 直接拒绝，
     * 于是动作 100% 失败（开发文档 §2.3 A1 / §10.3 D3）。
     */
    fun moduleAction(daemon: String, id: String): List<String> =
        module(daemon, "action", id)

    fun feature(daemon: String, action: String, feature: String, value: Long? = null): List<String> {
        assertDaemon(daemon)
        // feature name 是**固定表**（uapi/feature.h），不是自由字符串；
        // 5 号已废弃且不得复用，未知名字一律拒绝，避免任意 token 被送进 ksud。
        if (!FEATURE_KEY_PATTERN.matches(feature) || !KsuFeature.isValid(feature)) {
            throw KsuCommandRejectedException(
                "feature=$feature", "unknown feature: $feature (known=${KsuFeature.idByName.keys})")
        }
        if (action !in setOf("check", "get", "set", "save", "status", "persist")) {
            throw KsuCommandRejectedException("feature-action=$action", "illegal feature action: $action")
        }
        val cmd = mutableListOf(daemon, "feature", action, feature)
        if (action == "set") {
            cmd += (value ?: 0L).toString()
        } else if (value != null) {
            throw KsuCommandRejectedException("feature-value=$value",
                "feature $action does not take a value")
        }
        rejectForbidden(cmd)
        return cmd
    }

    fun profile(daemon: String, subcommand: String, args: List<String>): List<String> {
        assertDaemon(daemon)
        if (subcommand !in setOf("get-sepolicy", "set-sepolicy", "templates", "template",
                "get", "set", "delete")) {
            throw KsuCommandRejectedException("profile=$subcommand", "illegal profile subcommand")
        }
        args.forEach {
            if (it.startsWith("-")) {
                rejectForbidden(listOf(it))
            }
        }
        return listOf(daemon, "profile", subcommand) + args
    }

    fun install(daemon: String, libadbroot: File?, dataPath: File?, stageForSwitch: Boolean): List<String> {
        assertDaemon(daemon)
        val cmd = mutableListOf(daemon, "install")
        libadbroot?.let {
            require(it.isFile) { "libadbroot missing: $it" }
            cmd += listOf("--libadbroot", it.absolutePath)
        }
        dataPath?.let { cmd += listOf("--data-path", it.absolutePath) }
        if (stageForSwitch) cmd += "--stage-for-switch"
        rejectForbidden(cmd)
        return cmd
    }

    fun webadmin(daemon: String, action: String): List<String> {
        assertDaemon(daemon)
        if (action !in setOf("on", "off", "status", "url", "reset-token", "sync", "restart")) {
            throw KsuCommandRejectedException("webadmin=$action", "illegal webadmin action: $action")
        }
        return listOf(daemon, "webadmin", action)
    }

    fun su(daemon: String, globalMount: Boolean): List<String> {
        assertDaemon(daemon)
        return if (globalMount) listOf(daemon, "debug", "su", "-g") else listOf(daemon, "debug", "su")
    }

    fun requirePackageName(packageName: String): String {
        if (!PACKAGE_PATTERN.matches(packageName)) {
            throw KsuCommandRejectedException(packageName, "illegal package name: $packageName")
        }
        return packageName
    }
}

/** `boot-patch` 的选项。 */
data class KsuBootPatchOptions(
    val kmi: String? = null,
    val allowShell: Boolean = false,
    val enableAdb: Boolean = false,
    val forceFeatures: Map<String, Long> = emptyMap(),
    val blockModules: List<String> = emptyList(),
    val partition: String = "init_boot",
)

/** `ksud boot-info` 的机器接口子命令（7K `cli.rs:248-262`）。 */
object KsuBootInfoSubcommand {
    const val CURRENT_KMI = "current-kmi"
    const val SUPPORTED_KMIS = "supported-kmis"
    const val IS_AB_DEVICE = "is-ab-device"
    const val DEFAULT_PARTITION = "default-partition"
    const val AVAILABLE_PARTITIONS = "available-partitions"
    const val SLOT_SUFFIX = "slot-suffix"
    const val RAMDISK_STATE = "ramdisk-state"
    val ALL_NAMES: Set<String> = setOf(
        CURRENT_KMI, SUPPORTED_KMIS, IS_AB_DEVICE, DEFAULT_PARTITION,
        AVAILABLE_PARTITIONS, SLOT_SUFFIX, RAMDISK_STATE,
    )
}

/** 一次 shell 执行的结果（与 libsu `Shell.Result` 解耦，便于主机单测）。 */
data class KsuShellResult(
    val code: Int,
    val out: List<String>,
    val err: List<String>,
) {
    val outText: String get() = out.joinToString("\n")
    val errText: String get() = err.joinToString("\n")
}

/** shell 执行器抽象：默认实现走 libsu；测试注入替身（不起进程）。 */
fun interface KsuShellRunner {
    fun run(command: List<String>, timeoutMs: Long): KsuShellResult

    fun runStreaming(
        command: List<String>, timeoutMs: Long,
        onStdout: (String) -> Unit, onStderr: (String) -> Unit,
    ): KsuShellResult = run(command, timeoutMs).also {
        it.out.forEach(onStdout)
        it.err.forEach(onStderr)
    }

    fun readFeatureBatch(commands: List<List<String>>, timeoutMs: Long): List<KsuShellResult> {
        val deadline = System.nanoTime() + timeoutMs.coerceAtLeast(1L) * 1_000_000L
        return commands.map { command ->
            val remaining = (deadline - System.nanoTime()) / 1_000_000L
            if (remaining <= 0L) KsuShellResult(-1, emptyList(), listOf("FEATURE_READ_TIMEOUT"))
            else run(command, remaining)
        }
    }
}

/**
 * ksud 命令后端：负责 daemon 路径、shell 选择、一次调用一次进程、超时与错误语义。
 *
 * 实现约定（03 §3.9）：
 * - 不存在/不可执行 → `false`/空输出，**不抛**、不重试；
 * - 退出码非 0 → 返回 false/空输出；
 * - `globalMnt` 时优先 `ksud debug su -g`，退化到系统 `su -mm`/`su`（7K KsuCli:301-350）。
 */
class KsuCommandBackend(
    private val daemonPathProvider: () -> String,
    private val runner: KsuShellRunner,
    /**
     * 全局挂载命名空间（global-mnt）里的执行器。
     *
     * `ksud module action` 与 one-shot 脚本必须跑在全局命名空间（上游
     * `withNewRootShell(true)`），否则模块脚本看不到其它模块/`/system` 的挂载。
     * `null` = 复用 [runner]（主机测试与未装配时的安全默认，绝不静默降级成 app uid）。
     */
    private val globalMountRunner: KsuShellRunner? = null,
    private val shellCandidatesProvider: (Boolean) -> List<List<String>> = { globalMnt ->
        val daemon = daemonPathProvider()
        if (globalMnt) {
            listOf(KsuCommands.su(daemon, true), listOf("su", "-mm"), listOf("su"))
        } else {
            listOf(KsuCommands.su(daemon, false), listOf("su"))
        }
    },
    /**
     * daemon 可执行性探针。
     *
     * 默认 [KsuPathProbe.LOCAL]（APK 自带路径 app 可读，行为与改动前一致）；
     * **部署路径**（`/data/adb/ksud`、`/data/adb/ksu/bin/ksud`）必须注入 root shell 探针，
     * 否则 0700 的 `/data/adb` 会让已部署的 ksud 被判成"不存在"。
     */
    private val probe: KsuPathProbe = KsuPathProbe.LOCAL,
) {

    fun daemonPath(): String = daemonPathProvider()

    fun daemonExists(): Boolean =
        runCatching { probe.canExecute(daemonPath()) }.getOrDefault(false)

    /** 等价于现有 `execKsud(args, newShell, globalMnt)`：一次命令一次进程。 */
    fun exec(args: String, newShell: Boolean, globalMnt: Boolean): Boolean {
        // 纵深防御：**先**做参数级拒绝，再判 daemon 存在性 —— 否则 daemon 缺失时
        // 恶意 flag 会被静默吞掉（安全审阅与单测都不接受）。
        val tokens = mutableListOf(daemonPath())
        // args 为调用方给的子命令串（不含 daemon）；先做参数级拒绝再拆分
        val argTokens = args.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        KsuCommands.rejectForbidden(argTokens)
        tokens += argTokens
        if (!daemonExists()) {
            KsuLog.unavailable("KsuCommandBackend", "ksud missing: ${daemonPath()}")
            return false
        }
        val target = if (globalMnt) globalMountRunner ?: runner else runner
        val result = target.run(tokens, KsuTimeouts.COMMAND_MS)
        if (result.code != 0) {
            KsuLog.record("exec-failed", "code=${result.code} args=$args err=${result.errText}")
            return false
        }
        return true
    }

    /** 捕获 stdout（供 boot-info / debug info 解析）。失败 → 空串。 */
    fun capture(args: String, timeoutMs: Long = KsuTimeouts.COMMAND_MS): String {
        val argTokens = args.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        KsuCommands.rejectForbidden(argTokens)
        if (!daemonExists()) {
            KsuLog.unavailable("KsuCommandBackend", "ksud missing: ${daemonPath()}")
            return ""
        }
        val result = runner.run(listOf(daemonPath()) + argTokens, timeoutMs)
        return if (result.code == 0) result.outText else ""
    }

    fun runCommand(tokens: List<String>, timeoutMs: Long): KsuShellResult {
        // 参数拒绝先于 daemon 存在性判断（见 exec 的注释）
        val args = tokens.drop(1)
        KsuCommands.rejectForbidden(args)
        if (!daemonExists()) {
            KsuLog.unavailable("KsuCommandBackend", "ksud missing: ${daemonPath()}")
            return KsuShellResult(-1, emptyList(), listOf("$CODE_KSUD_UNAVAILABLE:${daemonPath()}"))
        }
        return runner.run(tokens, timeoutMs)
    }

    fun readFeatureBatch(commands: List<List<String>>, timeoutMs: Long): List<KsuShellResult> {
        val daemon = daemonPath()
        commands.forEach { command ->
            require(command.size == 4 && command[1] == "feature" && command[2] in setOf("check", "get"))
            require(command == KsuCommands.feature(daemon, command[2], command[3]))
        }
        if (!daemonExists()) {
            KsuLog.unavailable("KsuCommandBackend", "ksud missing: $daemon")
            return commands.map { KsuShellResult(-1, emptyList(), listOf(CODE_KSUD_UNAVAILABLE)) }
        }
        val results = runner.readFeatureBatch(commands, timeoutMs)
        return commands.indices.map { index ->
            results.getOrNull(index) ?: KsuShellResult(-1, emptyList(), listOf("FEATURE_READ_MISSING_RESULT"))
        }
    }

    /**
     * 在**全局挂载命名空间**里执行一条 ksud 命令（模块 Action 的唯一入口）。
     *
     * 与 [runCommand] 的差别只有两点，两点都是开发文档 §10.3 D3 的上游形态：
     * 1. 用 [globalMountRunner]（`KsuRootChannel.openShell(globalMnt = true)`）；
     * 2. daemon 不可用时返回**具名错误**（C3：禁止静默成功/静默降级）。
     */
    fun runCommandInGlobalMount(tokens: List<String>, timeoutMs: Long): KsuShellResult {
        val args = tokens.drop(1)
        KsuCommands.rejectForbidden(args)
        if (!daemonExists()) {
            KsuLog.unavailable("KsuCommandBackend", "ksud missing (global-mnt): ${daemonPath()}")
            return KsuShellResult(-1, emptyList(), listOf("$CODE_KSUD_UNAVAILABLE:${daemonPath()}"))
        }
        return (globalMountRunner ?: runner).run(tokens, timeoutMs)
    }

    fun runCommandStreaming(
        tokens: List<String>, timeoutMs: Long, globalMnt: Boolean = false,
        onStdout: (String) -> Unit, onStderr: (String) -> Unit,
    ): KsuShellResult {
        KsuCommands.rejectForbidden(tokens.drop(1))
        if (!daemonExists()) {
            val message = "$CODE_KSUD_UNAVAILABLE:${daemonPath()}"
            KsuLog.unavailable("KsuCommandBackend", message)
            onStderr(message)
            return KsuShellResult(-1, emptyList(), listOf(message))
        }
        val target = if (globalMnt) globalMountRunner ?: runner else runner
        return target.runStreaming(tokens, timeoutMs, onStdout, onStderr)
    }

    /** 供 `KsuBootInfo` 使用：按候选顺序尝试 root shell，返回首个成功结果。 */
    fun rootShellCandidates(globalMnt: Boolean): List<List<String>> =
        shellCandidatesProvider(globalMnt)

    companion object {
        /** 部署的 ksud 不存在/不可执行时的具名错误码（C3：静默成功一律禁止）。 */
        const val CODE_KSUD_UNAVAILABLE = "KSUD_UNAVAILABLE"

        /**
         * 生产装配（**部署路径**）：`/data/adb/ksud` 或 `/data/adb/ksu/bin/ksud`。
         *
         * 命令一律在**已认证 root shell** 里执行（[KsuRootShell] 装配的 executor）：
         * app uid 读 `/data/adb` 会被拒，那正是审计里"模块列表为空 / 设置读不到"的根因。
         * daemon 存在性同样由 root shell 探针回答。
         */
        fun forDeployedDaemon(
            daemonPath: String = KsuCommands.DEPLOYED_DAEMON,
            probe: KsuPathProbe = KsuRootShell.pathProbe(),
        ): KsuCommandBackend = KsuCommandBackend(
            daemonPathProvider = { daemonPath },
            runner = KsuRootShell.runner(),
            globalMountRunner = KsuRootShell.runner(globalMnt = true),
            probe = probe,
        )

        /**
         * APK 自带 ksud（`<nativeLibraryDir>/libksud_ksu.so`）的装配。
         *
         * 仍然走 root shell（这个二进制本来就是拿来起 root 进程的），只是路径在 APK 内、
         * app 可探测。**不再**以 app uid 起进程。
         */
        fun forApp(nativeLibraryDir: File): KsuCommandBackend = KsuCommandBackend(
            daemonPathProvider = { KsuCommands.daemonPath(nativeLibraryDir) },
            runner = KsuRootShell.runner(),
            globalMountRunner = KsuRootShell.runner(globalMnt = true),
            probe = KsuPathProbe.LOCAL,
        )

        /** 未接线/不可用替身：所有命令返回 false/空，且记录一条日志。 */
        fun unavailable(reason: String): KsuCommandBackend {
            KsuLog.unavailable("KsuCommandBackend", reason)
            return KsuCommandBackend(
                daemonPathProvider = { "/nonexistent/libksud_ksu.so" },
                runner = KsuShellRunner { _, _ -> KsuShellResult(-1, emptyList(), emptyList()) },
                probe = object : KsuPathProbe {
                    override fun exists(path: String): Boolean = false
                },
            )
        }
    }
}
