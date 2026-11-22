package dev.maplesu.manager.workmode.migration

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** 05 §3.3/§3.7：外部还原只处理副本、禁止 flash、备份未验证不执行（T-23）。 */
class ExternalRestoreStrategyTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test
    fun restoreLevelMapping() {
        assertEquals(RestoreLevel.P0_STOCK_COPY, ExternalRootRestoreStrategy.level(RestoreStrategy.KSU_STOCK_COPY))
        assertEquals(RestoreLevel.P0_STOCK_COPY, ExternalRootRestoreStrategy.level(RestoreStrategy.MAGISK_STOCK_GZ))
        assertEquals(
            RestoreLevel.P2_EXTERNAL_TOOL,
            ExternalRootRestoreStrategy.level(RestoreStrategy.KSU_EXTERNAL_TOOL_ON_COPY),
        )
        assertEquals(RestoreLevel.P3_UNAVAILABLE, ExternalRootRestoreStrategy.level(RestoreStrategy.GENERIC_STOCK_SCAN))
        assertEquals(RestoreLevel.P3_UNAVAILABLE, ExternalRootRestoreStrategy.level(RestoreStrategy.NONE))
    }

    @Test
    fun p0StockCopyNeedsNoTool() {
        val backupRoot = tmp.newFolder("backup")
        val input = Fixtures.write(backupRoot, "external-stock/ksu/ksu_backup_" + "ab".repeat(20), "image")
        val request = ExternalRootRestoreStrategy.request(
            strategy = RestoreStrategy.KSU_STOCK_COPY,
            partition = "init_boot",
            inputImage = input,
            outputDirectory = tmp.newFolder("work"),
            backupRoot = backupRoot,
            toolPath = null,
            argv = emptyList(),
            allExternalBackupsVerified = false,
        )
        assertEquals(RestoreStrategy.KSU_STOCK_COPY, request.strategy)
    }

    @Test
    fun externalToolRejectsFlashFlag() {
        val backupRoot = tmp.newFolder("backup")
        val input = Fixtures.write(backupRoot, "images/pre-init_boot.img", "image")
        val failure = assertThrows(MigrationFailure::class.java) {
            ExternalRootRestoreStrategy.request(
                strategy = RestoreStrategy.KSU_EXTERNAL_TOOL_ON_COPY,
                partition = "init_boot",
                inputImage = input,
                outputDirectory = tmp.newFolder("work"),
                backupRoot = backupRoot,
                toolPath = "/data/adb/ksud",
                argv = ExternalRootRestoreStrategy.ksuRestoreArgv(input, tmp.newFolder("out")) + "-f",
                allExternalBackupsVerified = true,
            )
        }
        assertEquals(MigrationCodes.RESTORE_EXTERNAL_TOOL_FORBIDDEN, failure.code)
    }

    @Test
    fun externalToolRejectsUninstallerToken() {
        val backupRoot = tmp.newFolder("backup")
        val input = Fixtures.write(backupRoot, "images/pre-init_boot.img", "image")
        val failure = assertThrows(MigrationFailure::class.java) {
            ExternalRootRestoreStrategy.request(
                strategy = RestoreStrategy.KSU_EXTERNAL_TOOL_ON_COPY,
                partition = "init_boot",
                inputImage = input,
                outputDirectory = tmp.newFolder("work"),
                backupRoot = backupRoot,
                toolPath = "/data/adb/ksud",
                argv = listOf("uninstall", "com.example"),
                allExternalBackupsVerified = true,
            )
        }
        assertEquals(MigrationCodes.RESTORE_EXTERNAL_TOOL_FORBIDDEN, failure.code)
    }

    @Test
    fun externalToolRejectsDeviceInputOutsideBackupRoot() {
        val backupRoot = tmp.newFolder("backup")
        val outside = Fixtures.write(tmp.root, "outside/copy.img", "image")
        val failure = assertThrows(MigrationFailure::class.java) {
            ExternalRootRestoreStrategy.request(
                strategy = RestoreStrategy.KSU_EXTERNAL_TOOL_ON_COPY,
                partition = "init_boot",
                inputImage = outside,
                outputDirectory = tmp.newFolder("work"),
                backupRoot = backupRoot,
                toolPath = "/data/adb/ksud",
                argv = listOf("boot-restore", "--boot", outside.path, "--out", "/tmp/out"),
                allExternalBackupsVerified = true,
            )
        }
        assertEquals(MigrationCodes.RESTORE_INPUT_NOT_COPY, failure.code)
    }

    @Test
    fun externalToolRequiresVerifiedBackups() {
        val backupRoot = tmp.newFolder("backup")
        val input = Fixtures.write(backupRoot, "images/pre-init_boot.img", "image")
        val failure = assertThrows(MigrationFailure::class.java) {
            ExternalRootRestoreStrategy.request(
                strategy = RestoreStrategy.KSU_EXTERNAL_TOOL_ON_COPY,
                partition = "init_boot",
                inputImage = input,
                outputDirectory = tmp.newFolder("work"),
                backupRoot = backupRoot,
                toolPath = "/data/adb/ksud",
                argv = ExternalRootRestoreStrategy.ksuRestoreArgv(input, tmp.newFolder("out")),
                allExternalBackupsVerified = false,
            )
        }
        assertEquals(MigrationCodes.RESTORE_BACKUP_UNVERIFIED, failure.code)
        // 已验证时通过
        ExternalRootRestoreStrategy.request(
            strategy = RestoreStrategy.KSU_EXTERNAL_TOOL_ON_COPY,
            partition = "init_boot",
            inputImage = input,
            outputDirectory = tmp.newFolder("work2"),
            backupRoot = backupRoot,
            toolPath = "/data/adb/ksud",
            argv = ExternalRootRestoreStrategy.ksuRestoreArgv(input, tmp.newFolder("out2")),
            allExternalBackupsVerified = true,
        )
    }

    @Test
    fun magiskInternalRebuildIsFileOnlyAndNeedsNoBackupPin() {
        val backupRoot = tmp.newFolder("backup")
        val input = Fixtures.write(backupRoot, "images/pre-init_boot.img", "image")
        val request = ExternalRootRestoreStrategy.request(
            strategy = RestoreStrategy.MAGISK_INTERNAL_REBUILD,
            partition = "init_boot",
            inputImage = input,
            outputDirectory = tmp.newFolder("work"),
            backupRoot = backupRoot,
            toolPath = "/data/adb/magisk/magiskboot",
            argv = ExternalRootRestoreStrategy.magiskRepackArgv(
                "cpio", input, File(tmp.newFolder("out"), "restored.img"), listOf("restore"),
            ),
            allExternalBackupsVerified = false,
        )
        assertFalse(request.argv.contains("-f"))
    }

    @Test
    fun availableLevelPrefersStockCopyThenTool() {
        assertEquals(
            RestoreLevel.P0_STOCK_COPY,
            ExternalRootRestoreStrategy.availableLevel(
                Family.KSU_UPSTREAM, RestoreStrategy.KSU_STOCK_COPY, "init_boot",
                usableBackupPartitions = setOf("init_boot"), toolExecutable = false,
            ),
        )
        assertEquals(
            RestoreLevel.P2_EXTERNAL_TOOL,
            ExternalRootRestoreStrategy.availableLevel(
                Family.KSU_UPSTREAM, RestoreStrategy.KSU_EXTERNAL_TOOL_ON_COPY, "init_boot",
                usableBackupPartitions = emptySet(), toolExecutable = true,
            ),
        )
        assertEquals(
            RestoreLevel.P3_UNAVAILABLE,
            ExternalRootRestoreStrategy.availableLevel(
                Family.UNKNOWN, RestoreStrategy.GENERIC_STOCK_SCAN, "init_boot",
                usableBackupPartitions = emptySet(), toolExecutable = true,
            ),
        )
    }

    @Test
    fun p3StrategyIsRejectedByRequest() {
        val failure = assertThrows(MigrationFailure::class.java) {
            ExternalRootRestoreStrategy.request(
                strategy = RestoreStrategy.NONE,
                partition = "init_boot",
                inputImage = File(tmp.root, "x"),
                outputDirectory = tmp.newFolder("work"),
                backupRoot = tmp.newFolder("backup"),
                toolPath = null,
                argv = emptyList(),
                allExternalBackupsVerified = false,
            )
        }
        assertEquals(MigrationCodes.CLEAN_IMAGE_UNAVAILABLE, failure.code)
    }
}
