package dev.maplesu.manager.workmode.migration

import java.io.File
import java.util.UUID

/**
 * 迁移控制面路径与外部管理器路径白名单（05 §1.4 / §2.1）。
 *
 * 只定义路径；设备侧 root 适配器把 [MIGRATIONS] 放到 `/data/adb/maplesu-workmode/migrations`。
 * 这里不 import `ControlPaths` 的目的是让本包可在临时目录里完整跑 JVM 测试。
 */
object MigrationPaths {
    const val ROOT = "/data/adb/maplesu-workmode"
    const val MIGRATIONS = "$ROOT/migrations"
    const val WORKMODE_CONTROL = "$ROOT/control"

    /** 本产品包名（禁止传给外部卸载接口；判定"会话自身就是 MapleSu"）。 */
    const val SELF_PACKAGE = "dev.maplesu.manager"

    /** 已知 KSU 家族管理器包名（WEAK 证据，仅用于 managerPackages/APK 备份）。 */
    val KSU_MANAGER_PACKAGES: Set<String> = setOf(
        "me.weishu.kernelsu",
        "me.weishu.kernelsu.debug",
        "com.rifsxd.ksunext",
        "com.sukisu.ultra",
        "com.sukisu.ultra.debug",
    )

    /** 已知 7K 管理器包名族。 */
    val SEVENK_MANAGER_PACKAGES: Set<String> = setOf(
        "com.sevenk.manager",
        "com.sevenk.manager.debug",
    )

    /** 已知 Magisk 家族管理器包名（含 Kitsune/Debug 变体）。 */
    val MAGISK_MANAGER_PACKAGES: Set<String> = setOf(
        "com.topjohnwu.magisk",
        "com.topjohnwu.magisk.debug",
        "io.github.huskydg.magisk",
        "io.github.huskydg.magisk.debug",
        "io.github.vvb2060.magisk",
    )

    val ALL_MANAGER_PACKAGES: Set<String> =
        KSU_MANAGER_PACKAGES + SEVENK_MANAGER_PACKAGES + MAGISK_MANAGER_PACKAGES

    // ---- /data/adb 外部路径白名单（探测项矩阵；只读） ----

    const val KSU_DIR = "/data/adb/ksu"
    const val SEVENK_DIR = "/data/adb/sevenk"
    const val KSUD = "/data/adb/ksud"
    const val KSU_ALLOWLIST = "/data/adb/ksu/.allowlist"
    const val SEVENK_ALLOWLIST = "/data/adb/sevenk/.allowlist"
    const val MAGISK_DIR = "/data/adb/magisk"
    const val MAGISK_DB = "/data/adb/magisk.db"
    const val MODULES_DIR = "/data/adb/modules"
    const val MODULES_UPDATE_DIR = "/data/adb/modules_update"
    const val METAMODULE = "/data/adb/metamodule"
    const val POST_FS_DATA_DIR = "/data/adb/post-fs-data.d"
    const val SERVICE_D_DIR = "/data/adb/service.d"
    const val ADDON_D_DIR = "/data/adb/addon.d"
    const val PREINIT_VOLD = "/metadata/vold/ksu"
    const val PREINIT_WATCHDOG = "/metadata/watchdog/ksu"
    const val PREINIT_ROOT = "/metadata/ksu"
    const val MAGISK_PREINIT = "/metadata/magisk"

    /** 探测白名单：服务侧只允许 `lstat` 这些路径（05 §1.4）。 */
    val PROBE_PATHS: List<String> = listOf(
        KSU_DIR, SEVENK_DIR, KSUD, KSU_ALLOWLIST, SEVENK_ALLOWLIST,
        MAGISK_DIR, MAGISK_DB, MODULES_DIR, MODULES_UPDATE_DIR, METAMODULE,
        POST_FS_DATA_DIR, SERVICE_D_DIR, ADDON_D_DIR,
        PREINIT_VOLD, PREINIT_WATCHDOG, PREINIT_ROOT, MAGISK_PREINIT,
        "/cache", "/data/local/tmp",
    )

    /** 外部 owner 清理候选（M6/RESIDUE 扫描；按目标状态过滤，05 §7.1）。 */
    val RESIDUE_SCAN_PATHS: List<String> = listOf(
        "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/ksu", "/data/adb/sevenk",
        "/data/adb/ksud", "/data/adb/post-fs-data.d", "/data/adb/service.d",
        "/data/adb/modules_update", "/data/adb/metamodule",
        "/metadata/magisk", "/metadata/vold/ksu", "/metadata/watchdog/ksu", "/metadata/ksu",
    )

    // ---- 迁移工作目录（注入 root，主机测试用临时目录） ----

    fun migrationsDir(root: File): File = File(root, "migrations")

    fun migrationDir(root: File, migrationId: String): File {
        requireCanonicalId(migrationId)
        return File(migrationsDir(root), migrationId)
    }

    fun backupDir(root: File, migrationId: String): File = File(migrationDir(root, migrationId), "backup")

    fun manifest(root: File, migrationId: String): File = File(backupDir(root, migrationId), "manifest.json")

    fun journal(root: File, migrationId: String): File = File(migrationDir(root, migrationId), "journal.json")

    fun detect(root: File, migrationId: String): File = File(migrationDir(root, migrationId), "detect.json")

    fun retention(root: File, migrationId: String): File = File(migrationDir(root, migrationId), "retention.json")

    fun report(root: File, migrationId: String): File = File(migrationDir(root, migrationId), "report.json")

    fun secretsDir(root: File, migrationId: String): File = File(migrationDir(root, migrationId), "secrets")

    /** backup/ 子目录（05 §2.1）。 */
    val BACKUP_SUBDIRS: List<String> = listOf(
        "images",
        "external-stock/ksu",
        "external-stock/magisk",
        "external-data",
        "auth/ksu",
        "auth/magisk",
        "modules",
        "manager-apk",
        "our",
    )

    /** KSU `ksu_backup_<sha1>` 文件名前缀（KSU/userspace/ksud/src/defs.rs:72-73）。 */
    const val KSU_BACKUP_PREFIX = "ksu_backup_"

    /** Magisk 备份目录格式（Magisk/scripts/util_functions.sh:547-575）。 */
    const val MAGISK_BACKUP_PREFIX = "/data/magisk_backup_"
    const val MAGISK_OLD_BACKUP_PREFIX = "/data/stock_boot_"

    /** 严格 UUIDv4 规范形态（对齐 InstallerBootTransaction 的 taskId 校验）。 */
    fun isCanonicalId(migrationId: String): Boolean {
        if (migrationId.isBlank()) return false
        return runCatching { UUID.fromString(migrationId).toString() == migrationId }.getOrDefault(false)
    }

    fun requireCanonicalId(migrationId: String) {
        MigrationFailure.require(isCanonicalId(migrationId), MigrationCodes.PLAN_INVALID, "migrationId")
    }

    /** 拒绝路径穿越 / 绝对路径 / 控制字符（backup 内相对路径唯一入口）。 */
    fun requireSafeRelativePath(relative: String): String {
        MigrationFailure.require(relative.isNotEmpty(), MigrationCodes.MODULE_PATH_INVALID, "empty")
        MigrationFailure.require(!relative.startsWith("/") && !relative.contains('\\'), MigrationCodes.MODULE_PATH_INVALID, relative)
        MigrationFailure.require(!relative.contains("//"), MigrationCodes.MODULE_PATH_INVALID, relative)
        MigrationFailure.require(relative.split('/').none { it == "." || it == ".." }, MigrationCodes.MODULE_PATH_INVALID, relative)
        MigrationFailure.require(relative.none { it.code < 0x20 || it == ':' }, MigrationCodes.MODULE_PATH_INVALID, relative)
        return relative
    }
}
