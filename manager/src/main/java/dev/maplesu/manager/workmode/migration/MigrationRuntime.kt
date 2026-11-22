package dev.maplesu.manager.workmode.migration

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import android.os.StatFs
import dev.maplesu.manager.workmode.control.ControlPaths
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * 迁移生产运行时（W20–W22，05 §1.2）——**唯一组装点**。
 *
 * 设备侧：[initialize] 用 Android 只读探针 + 设备端口组装 [HostMigrationFacade]。
 * 当前里程碑的分区写入/备份端口由共用事务实现方后续注入；未接线时 start 在写入前
 * 返回结构化错误（`MIGRATION_DEVICE_WRITE_UNAVAILABLE`），**绝不假装成功**。
 *
 * App 启动点调用 [initialize]；[MigrationViewModel] 默认取 [current]。
 */
object MigrationRuntime {

    @Volatile
    private var facade: MigrationFacade? = null

    /** 设备启动点调用；任何异常都不影响 App 启动（保持 Unavailable 诚实降级）。 */
    fun initialize(context: Context): Boolean {
        val appContext = context.applicationContext ?: context
        return runCatching {
            facade = HostMigrationFacade(
                root = File(ControlPaths.ROOT),
                probes = AndroidMigrationProbePort(appContext),
                backup = UnavailableMigrationBackupPort,
                writer = UnavailableMigrationWritePort,
            )
            true
        }.getOrElse {
            facade = null
            false
        }
    }

    /** host 测试 / 集成注入（不依赖 Android）。 */
    fun initialize(facade: MigrationFacade) {
        this.facade = facade
    }

    fun current(): MigrationFacade? = facade

    fun reset() {
        facade = null
    }
}

/**
 * Android 只读探针（设备侧，fail-closed）。
 *
 * 实现约束（05 §1.1/§1.2）：
 * - 无 root 会话（`id -u != 0`）或 `/data/adb` 不可读 → `Unavailable`，**绝不猜家族**；
 * - 只读 `lstat` 白名单路径 + PackageManager 包名；不执行任何外部管理器命令、不写文件；
 * - 镜像 marker / stock 备份内容解析需要 root 服务提供的镜像副本，本实现未接线时
 *   返回空证据（→ 检测为 UNKNOWN best-effort 或 CleanImageUnavailable 阻断），不做猜测。
 */
class AndroidMigrationProbePort(private val context: Context) : MigrationProbePort {

    override suspend fun read(): MigrationProbeResult {
        val uid = rootUid() ?: return MigrationProbeResult.Unavailable(PROBE_UNAVAILABLE)
        if (uid != 0) {
            return MigrationProbeResult.Unavailable(MigrationCodes.NO_ROOT)
        }
        val dataAdb = File("/data/adb")
        if (!dataAdb.isDirectory || !dataAdb.canRead()) {
            // 无 root 通道/控制面不可读：返回不可用，不猜测为"未安装外部 root"。
            return MigrationProbeResult.Unavailable(PROBE_UNAVAILABLE)
        }

        val files = MigrationPaths.PROBE_PATHS.associateWith { path -> fileFact(path) }
        val tools = mapOf(
            "ksud" to toolFact(MigrationPaths.KSUD),
            "magisk" to toolFact("${MigrationPaths.MAGISK_DIR}/magisk"),
            "magiskboot" to toolFact("${MigrationPaths.MAGISK_DIR}/magiskboot"),
        )
        val partitions = listOf("boot", "init_boot").associateWith { name ->
            PartitionFacts(name = name, present = false)
        }
        val inventory = PackageInventory()
        return MigrationProbeResult.Ready(
            probe = ExternalRootProbe(
                suUid = uid,
                suVersion = null,
                suPath = null,
                files = files,
                tools = tools,
                partitions = partitions,
                stockBackups = emptyMap(),
                device = deviceFacts(uid),
                ownControlPlanePresent = File(ControlPaths.CONTROL, "modes.json").isFile,
            ),
            inventory = inventory,
        )
    }

    private fun fileFact(path: String): FileFact {
        val file = File(path)
        if (!file.exists()) return FileFact(path, exists = false)
        val symlink = runCatching { java.nio.file.Files.isSymbolicLink(file.toPath()) }.getOrDefault(false)
        val target = if (symlink) runCatching { java.nio.file.Files.readSymbolicLink(file.toPath()).toString() }.getOrNull() else null
        return FileFact(
            path = path,
            exists = true,
            isSymlink = symlink,
            linkTarget = target,
            isDirectory = file.isDirectory,
            size = if (file.isFile) file.length() else 0,
        )
    }

    private fun toolFact(path: String): ToolFact {
        val file = File(path)
        return ToolFact(path = path, executable = file.isFile && file.canExecute())
    }

    private fun deviceFacts(uid: Int): DeviceFacts {
        val data = Environment.getDataDirectory()
        val freeBytes = runCatching {
            val stat = StatFs(data.absolutePath)
            stat.availableBytes
        }.getOrDefault(0L)
        return DeviceFacts(
            kernelRelease = System.getProperty("os.version").orEmpty(),
            firmware = Build.DISPLAY.orEmpty(),
            slotSuffix = runCatching { System.getProperty("ro.boot.slot_suffix").orEmpty() }.getOrDefault(""),
            selinux = runCatching {
                File("/sys/fs/selinux/enforce").readText().trim().let { if (it == "1") "Enforcing" else "Permissive" }
            }.getOrDefault("Unknown"),
            bootId = runCatching { File("/proc/sys/kernel/random/boot_id").readText().trim() }.getOrDefault(""),
            freeBytesOnData = freeBytes,
            externalRootAvailable = uid == 0,
            layoutSupported = true,
            pendingTransaction = false,
            batteryOk = true,
        )
    }

    /**
     * 当前进程 uid：root 服务内为 0；普通 App 进程为应用 uid。
     * 不做 `su` 尝试（避免弹授权/阻塞）；拿不到就视为无 root 通道。
     */
    private fun rootUid(): Int? = runCatching {
        val process = ProcessBuilder("/system/bin/id", "-u")
            .redirectErrorStream(true)
            .start()
        process.waitFor(2, TimeUnit.SECONDS)
        process.inputStream.bufferedReader().readText().trim().toIntOrNull()
    }.getOrNull()

    companion object {
        const val PROBE_UNAVAILABLE = "MIGRATION_PROBE_UNAVAILABLE"
    }
}
