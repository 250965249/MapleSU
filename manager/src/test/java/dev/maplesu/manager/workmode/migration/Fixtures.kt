package dev.maplesu.manager.workmode.migration

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.WorkMode
import java.io.File

/** 迁移后端的共享测试夹具（只构造纯数据，不接触 Android）。 */
object Fixtures {
    fun sha(label: String): String = Hashes.sha256Hex(label)

    fun fileFact(
        path: String,
        exists: Boolean = true,
        isDirectory: Boolean = false,
        isSymlink: Boolean = false,
        linkTarget: String? = null,
    ) = FileFact(path, exists, isSymlink, linkTarget, isDirectory, size = 4096)

    /** 已存在的目录事实。 */
    fun dir(path: String) = FileFact(path, exists = true, isDirectory = true, size = 4096)

    fun partition(
        name: String,
        markers: Set<ImageMarker> = emptySet(),
        present: Boolean = true,
        size: Long = 100 * 1024 * 1024,
    ) = PartitionFacts(name, present, size, sha(name), "/dev/block/by-name/$name", markers)

    fun image(
        path: String,
        size: Long = 100 * 1024 * 1024,
        label: String = path,
        source: ImageSource = ImageSource.EXTERNAL_STOCK,
    ) = ImageRef(path, size, sha(label), source)

    fun backup(
        partitionHint: String?,
        state: BackupState = BackupState.USABLE,
        path: String = "/data/adb/ksu/ksu_backup_${"ab".repeat(20)}",
    ) = StockBackupRef(
        partitionHint = partitionHint,
        recordedId = "ab".repeat(20),
        path = path,
        size = 100 * 1024 * 1024,
        sha256 = sha(path),
        state = state,
    )

    fun packageFacts(
        uid: Int,
        vararg packages: String,
        signer: String = "a".repeat(64),
        firstInstallTime: Long = 1_700_000_000_000,
        lastUpdateTime: Long = 1_700_000_100_000,
        apkPath: String = "/data/app/~~abc/com.example/base.apk",
    ) = PackageFacts(
        uid = uid,
        packages = packages.toList(),
        signerSha256 = setOf(signer),
        firstInstallTime = firstInstallTime,
        lastUpdateTime = lastUpdateTime,
        apkPath = apkPath,
    )

    fun device(
        externalRootAvailable: Boolean = true,
        layoutSupported: Boolean = true,
        pendingTransaction: Boolean = false,
        freeBytesOnData: Long = 100L * 1024 * 1024 * 1024,
    ) = DeviceFacts(
        kernelRelease = "6.1.75-android14",
        firmware = "PLQ110_TEST",
        slotSuffix = "",
        externalRootAvailable = externalRootAvailable,
        layoutSupported = layoutSupported,
        pendingTransaction = pendingTransaction,
        freeBytesOnData = freeBytesOnData,
    )

    fun probe(
        files: Map<String, FileFact> = emptyMap(),
        tools: Map<String, ToolFact> = emptyMap(),
        partitions: Map<String, PartitionFacts> = emptyMap(),
        stockBackups: Map<String, StockBackupRef> = emptyMap(),
        suUid: Int = 0,
        suVersion: String? = null,
        device: DeviceFacts = device(),
        ownControlPlanePresent: Boolean = false,
    ) = ExternalRootProbe(
        suUid = suUid,
        suVersion = suVersion,
        suPath = "/debug_ramdisk/su",
        files = files,
        tools = tools,
        partitions = partitions,
        stockBackups = stockBackups,
        device = device,
        ownControlPlanePresent = ownControlPlanePresent,
    )

    fun tool(path: String, executable: Boolean = true, version: String? = null) =
        ToolFact(path, executable, version)

    /** 写一个测试文件并返回；父目录自动创建。 */
    fun write(dir: File, relative: String, content: String = "x"): File {
        val file = File(dir, relative)
        file.parentFile?.mkdirs()
        file.writeText(content)
        return file
    }

    fun partitionSizes(vararg entries: Pair<String, Long>): Map<String, Long> = entries.toMap()

    fun planInput(
        pre: Map<String, ImageRef>,
        clean: Map<String, ImageRef> = emptyMap(),
        baseline: Map<String, ImageRef> = emptyMap(),
        candidates: Map<String, ImageRef> = emptyMap(),
        patched: Set<String>,
        family: Family = Family.KSU_UPSTREAM,
        target: WorkMode = WorkMode.LITE,
        partitionSize: Map<String, Long> = emptyMap(),
        migrationId: String = MIGRATION_ID,
    ): PlanInput {
        val info = ExternalRootInfo(
            family = family,
            patchedPartitions = patched,
            supported = family.isKnown,
            bestEffort = !family.isKnown,
        )
        return PlanInput(
            migrationId = migrationId,
            target = target,
            info = info,
            pre = pre,
            clean = clean,
            partitionSize = partitionSize,
            baseline = baseline,
            candidates = candidates,
        )
    }

    const val MIGRATION_ID = "3f2b0c9e-6a1d-4c47-9c2e-1b7d5a0f8e33"
}
