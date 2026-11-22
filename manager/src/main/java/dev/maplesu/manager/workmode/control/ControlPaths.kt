package dev.maplesu.manager.workmode.control

import dev.maplesu.manager.workmode.WorkMode
import java.io.File
import java.io.IOException
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

/**
 * 控制面路径常量唯一来源。
 *
 * 设备上的权限/所有者断言统一走本文件；主机单测用临时目录时 POSIX 不可用 → 权限断言降级为
 * "存在性 + 类型"（见 [requirePrivateDir]）。
 */
object ControlPaths {
    const val ROOT = "/data/adb/maplesu-workmode"
    const val CONTROL = "$ROOT/control"
    const val SHARED = "$ROOT/shared"
    const val MODES = "$ROOT/modes"
    const val BOOT = "$ROOT/boot"
    const val BASELINE = "$BOOT/baseline"
    const val TAKEOVER = "$BOOT/takeover"

    /**
     * 用户可见的「恢复目录」：**刷写前纯净镜像**（`PRE_FIRST_WRITE_CAPTURE`）的落点。
     *
     * 它与 [BASELINE] 是**同一个物理目录**（别名，不是第二份拷贝），理由：
     * 1. `/data/adb/maplesu-workmode` 整棵子树在 `MoveSet.NEVER_MOVE` 里 ⇒ 切模式永远搬不走它
     *    （用户要求的 `/data/adb/maplesu/recovery` 位于 `MoveSet.LITE_MOVE_SET` 的第一项之内，
     *    整树 rename 会把恢复镜像一起搬进 `modes/LITE/...`，回滚时正好找不到）；
     * 2. 一份 8–200 MiB 的镜像只存一次：再开一个 `recovery/` 目录就是同一份字节的第二次落盘，
     *    `/data` 峰值翻倍（低端机 `SWITCH_SPACE_INSUFFICIENT`）；
     * 3. 消费方（`UltraRootModeSwitchClient` 的 BASE 镜像、`FileBaselineStore`、`LocalInstallerGateway`）
     *    读的都是 `boot/baseline/<id>`；别名保证「恢复」与「切换」用的是同一份字节，
     *    不会出现两份镜像互相漂移（漂移 = 回滚刷回的不是基线）。
     *
     * 「改回 `/data/adb/maplesu/recovery`」的代价（不选它的理由）：`MoveSet.preservedPathsUnder`
     * 会把 `/data/adb/maplesu` 这一项降级成"逐子项搬移 + 保留子树"的合并搬移，
     * 与 `INSTALLER_ROOT` 锁目录（M5）同一类脆弱点，却只为省一个路径常量。
     */
    const val RECOVERY_BOOT = BASELINE

    /** 单份恢复镜像目录（= 一份基线目录：`boot.img` / `init_boot.img` / `manifest.json`）。 */
    fun recovery(id: String) = "$RECOVERY_BOOT/$id"

    const val WORK = "$BOOT/work"
    const val SNAPSHOTS = "$ROOT/snapshots"
    const val TMP = "$ROOT/tmp"

    fun modes(mode: WorkMode) = "$MODES/${mode.suffix}"
    fun store(mode: WorkMode) = "$MODES/${mode.suffix}/data"
    fun appStore(mode: WorkMode) = "$MODES/${mode.suffix}/app"
    fun externalStore(mode: WorkMode) = "$MODES/${mode.suffix}/external"
    fun secretsStore(mode: WorkMode) = "$MODES/${mode.suffix}/secrets"
    fun modeSettings(mode: WorkMode) = "$MODES/${mode.suffix}/settings.json"
    fun modeModules(mode: WorkMode) = "$MODES/${mode.suffix}/modules.json"
    fun modeRuntime(mode: WorkMode) = "$MODES/${mode.suffix}/runtime.json"
    fun modeBoot(mode: WorkMode) = "$MODES/${mode.suffix}/boot.json"
    fun modeManifest(mode: WorkMode) = "$MODES/${mode.suffix}/manifest.json"

    fun baseline(id: String) = "$BASELINE/$id"
    fun takeover(id: String) = "$TAKEOVER/$id"
    fun work(switchId: String) = "$WORK/$switchId"

    fun switchFile() = "$CONTROL/switch.json"
    fun switchLock() = "$CONTROL/switch.lock"

    /** WAL 在 boot/work/<switchId>/journal.jsonl（不在 control/）。 */
    fun switchJournal(switchId: String) = "$WORK/$switchId/journal.jsonl"

    fun modesFile() = "$CONTROL/modes.json"
    fun installedFile() = "$CONTROL/installed.json"
    fun publishFile() = "$CONTROL/publish.json"
    fun selinuxFile() = "$CONTROL/selinux.json"
    fun evidence() = "$CONTROL/evidence.jsonl"
    fun evidenceRotated() = "$CONTROL/evidence.jsonl.1"
    fun sharedSuperuser() = "$SHARED/superuser.json"
    fun sharedSuperuserPrev() = "$SHARED/superuser.json.prev"

    val ROOT_FILE get() = File(ROOT)
    val CONTROL_DIR get() = File(CONTROL)
}

/** 目录/文件权限断言（与 `installer/InstallerBootTransaction.kt:443-448` 同语义）。 */
object ControlPermissions {
    private val posix: Boolean by lazy {
        FileSystems.getDefault().supportedFileAttributeViews().contains("posix")
    }

    fun requireDir(path: File) {
        if (!path.exists() || !path.isDirectory) throw IOException("CONTROL_DIR_INVALID")
    }

    /** 0700 语义：目录存在、是目录、group/other 无权限（POSIX 可用时）。 */
    fun requirePrivateDir(path: File) {
        requireDir(path)
        if (!posix) return
        val permissions = runCatching { Files.getPosixFilePermissions(path.toPath()) }.getOrNull()
            ?: return
        if (permissions.any { it in GROUP_OTHER }) throw IOException("CONTROL_DIR_INVALID")
    }

    /** 0600 语义：普通文件、group/other 无权限（POSIX 可用时）。 */
    fun requirePrivateFile(path: File) {
        if (!path.isFile) throw IOException("CONTROL_DIR_INVALID")
        if (!posix) return
        val permissions = runCatching { Files.getPosixFilePermissions(path.toPath()) }.getOrNull()
            ?: return
        if (permissions.any { it in GROUP_OTHER }) throw IOException("CONTROL_DIR_INVALID")
    }

    /** 建目录并尽力设置 0700；返回是否新建。 */
    fun ensureDir(path: File): Boolean {
        if (path.exists()) {
            requireDir(path)
            return false
        }
        if (!path.mkdirs() && !path.isDirectory) throw IOException("CONTROL_DIR_INVALID")
        setPermissions(path, 0x1c0) // 0700
        return true
    }

    /** 建文件并尽力设置 0600。 */
    fun ensureFile(path: File): Boolean {
        if (path.exists()) {
            if (!path.isFile) throw IOException("CONTROL_DIR_INVALID")
            return false
        }
        if (!path.createNewFile()) throw IOException("CONTROL_DIR_INVALID")
        setPermissions(path, 0x180) // 0600
        return true
    }

    fun setPermissions(path: File, mode: Int) {
        if (!posix) return
        val permissions = PosixFilePermission.values().filter { permission ->
            val bit = when (permission) {
                PosixFilePermission.OWNER_READ -> 0x100
                PosixFilePermission.OWNER_WRITE -> 0x80
                PosixFilePermission.OWNER_EXECUTE -> 0x40
                PosixFilePermission.GROUP_READ -> 0x20
                PosixFilePermission.GROUP_WRITE -> 0x10
                PosixFilePermission.GROUP_EXECUTE -> 0x8
                PosixFilePermission.OTHERS_READ -> 0x4
                PosixFilePermission.OTHERS_WRITE -> 0x2
                PosixFilePermission.OTHERS_EXECUTE -> 0x1
            }
            mode and bit != 0
        }.toSet()
        runCatching { Files.setPosixFilePermissions(path.toPath(), permissions) }
    }

    /** 建立完整控制面目录树（幂等）。 */
    fun ensureTree(root: File = ControlPaths.ROOT_FILE) {
        ensureDir(root)
        listOf(
            "control", "shared", "boot", "boot/baseline", "boot/takeover", "boot/work",
            "modes", "modes/A", "modes/A/data", "modes/A/app", "modes/A/external",
            "modes/A/secrets", "modes/B", "modes/B/data", "modes/B/app", "modes/B/external",
            "modes/B/secrets", "snapshots", "tmp",
        ).forEach { ensureDir(File(root, it)) }
    }

    private val GROUP_OTHER = setOf(
        PosixFilePermission.GROUP_READ,
        PosixFilePermission.GROUP_WRITE,
        PosixFilePermission.GROUP_EXECUTE,
        PosixFilePermission.OTHERS_READ,
        PosixFilePermission.OTHERS_WRITE,
        PosixFilePermission.OTHERS_EXECUTE,
    )
}
