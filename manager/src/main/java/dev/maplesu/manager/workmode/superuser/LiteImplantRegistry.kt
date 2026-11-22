package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.schema.SharedSuperuserFile
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.WallClock
import kotlinx.serialization.Serializable
import java.io.File

/**
 * Lite 植入登记（01 §6.7）：`SuDelivery`/`SuPathWiring` 对目标 App 做过的每一处修改，
 * 用于切出 A 时撤回。**修改前必须先登记原件证据**（W19）：
 * - 目标文件原本存在 → 原件已备份（[ImplantIntent.originalBackupPath] + sha/uid/gid/mode）；
 * - 目标文件原本不存在 → [ImplantIntent.originalAbsent] = true（撤回 = 删除我们新增的文件）。
 *
 * 未登记/原件缺失禁止“完全隔离”切换（主文档:373）。
 * “Lite 撤销”= 撤回投递入口 + 重写授权列表，**不是内核级按 uid 撤销**；UI 必须继承该限制。
 */
@Serializable
data class ImplantIntent(
    val packageName: String,
    val uid: Int,
    /** nativeLibraryDir/su */
    val deliverPath: String,
    val deliverSha256: String,
    /** 被加 DT_NEEDED 的库。 */
    val wiringTargetLib: String? = null,
    /** 原件 sha（原件另存于 originals 目录）。 */
    val wiringOriginalSha256: String? = null,
    val sideLibraryPath: String? = null,
    /** 例如 nativeLibraryDir/arm64。 */
    val createdDirs: List<String> = emptyList(),
    val pathInjection: Boolean = false,
    val recordedAt: Long,
    /** 植入种类（"DELIVERY" | "WIRING" | "PATH_INJECTION"）；同一 App 可各有一条。 */
    val kind: String = ImplantKinds.WIRING,
    /** 修改前目标不存在（撤回 = 删除，而非恢复）。 */
    val originalAbsent: Boolean = false,
    /** 原件备份文件的绝对路径（root 0600）；存在即“可恢复”的硬证据。 */
    val originalBackupPath: String? = null,
    /** 原件内容 sha256（备份读回校验用）。 */
    val originalSha256: String? = null,
    /** 原件权限/属主（恢复时原样写回；null = 读不到，按默认值恢复并记 degraded）。 */
    val originalMode: Int? = null,
    val originalUid: Int? = null,
    val originalGid: Int? = null,
    /**
     * 完成标记：false = 已登记但投递/植入未确认（崩溃窗口）。撤回对两者一视同仁，
     * 因此崩溃后仍可恢复到“修改前”状态。
     */
    val active: Boolean = true,
) {
    fun key(): String = "$packageName#$kind"
}

/** 植入种类常量。 */
object ImplantKinds {
    const val DELIVERY = "DELIVERY"
    const val WIRING = "WIRING"
    const val PATH_INJECTION = "PATH_INJECTION"
}

/** W19 错误码（跨 runtime/switch 复用的稳定字符串）。 */
object LiteImplantCodes {
    const val ORIGINAL_MISSING = "LITE_IMPLANT_ORIGINAL_MISSING"
    const val REVERT_FAILED = "LITE_IMPLANT_REVERT_FAILED"
    const val REGISTRY_CORRUPT = "LITE_IMPLANT_REGISTRY_CORRUPT"
    const val REGISTRY_WRITE_FAILED = "LITE_IMPLANT_REGISTRY_WRITE_FAILED"
    const val BACKUP_FAILED = "LITE_IMPLANT_BACKUP_FAILED"
    /** 静默期内拒绝新的植入（切换进行中）。 */
    const val QUIESCING = "LITE_IMPLANT_QUIESCING"

    /** 真实写者停止失败（切换必须 fail-closed）。 */
    const val QUIESCE_FAILED = "LITE_IMPLANT_QUIESCE_FAILED"

    /** 写者恢复失败（切换已放弃；返回结构化失败供调用方告警）。 */
    const val RESTORE_WRITERS_FAILED = "LITE_IMPLANT_RESTORE_WRITERS_FAILED"

    /** S0-15 的 switch 层结构化码（hooks 把 registry 码映射到它）。 */
    const val IMPLANT_RESTORE_MISSING = "IMPLANT_RESTORE_MISSING"
}

data class RevertReport(
    val ok: Boolean,
    val code: String = "",
    val reverted: List<String> = emptyList(),
    val failed: List<String> = emptyList(),
    val detail: String = "",
)

/** 原件存放探测（设备侧由 W19 的备份实现；主机测试可注入）。 */
interface OriginalBackupStore {
    fun hasOriginal(intent: ImplantIntent): Boolean
}

/** 实际撤回动作（SuDelivery.withdraw / SuPathWiring 还原）；失败必须返回 false。 */
interface ImplantReverter {
    fun revert(intent: ImplantIntent): Boolean
}

interface LiteImplantRegistry {
    /** 首次修改**之前**调用。 */
    fun record(intent: ImplantIntent)

    fun pending(): List<ImplantIntent>

    fun revert(packageName: String): RevertReport

    /** false → 切换前阻断（S0-15 → `IMPLANT_RESTORE_MISSING`）。 */
    fun hasOriginals(): Boolean
}

@Serializable
data class LiteImplantFile(
    val schema: Int = 1,
    val entries: List<ImplantIntent> = emptyList(),
)

/**
 * 文件实现：`shared/lite-implants.json`（0600，原子写）。损坏时 `hasOriginals()=false`、
 * `revert()` 返回 `LITE_IMPLANT_REGISTRY_CORRUPT`——**不静默当作“无植入”**。
 */
class FileLiteImplantRegistry(
    private val directory: File,
    private val originals: OriginalBackupStore = FileOriginalBackupStore(directory),
    private val reverter: ImplantReverter = UnavailableImplantReverter,
    private val clock: Clock = WallClock,
) : LiteImplantRegistry {
    private val file = File(directory, "lite-implants.json")

    @Volatile
    private var corrupted = false

    override fun record(intent: ImplantIntent) {
        val entries = load()
        val merged = intent.copy(createdDirs = intent.createdDirs.distinct().sorted())
        // 同一 (package, kind) 覆盖；同一 App 的 DELIVERY/WIRING/PATH_INJECTION 必须共存。
        save(entries.filterNot { it.packageName == merged.packageName && it.kind == merged.kind } + merged)
    }

    override fun pending(): List<ImplantIntent> = load()

    override fun hasOriginals(): Boolean {
        val entries = load()
        if (corrupted) return false
        return entries.all { originals.hasOriginal(it) }
    }

    override fun revert(packageName: String): RevertReport {
        if (corrupted) {
            return RevertReport(false, LiteImplantCodes.REGISTRY_CORRUPT, failed = listOf(packageName))
        }
        val entries = load()
        val targets = entries.filter { it.packageName == packageName }
        if (targets.isEmpty()) return RevertReport(true)
        val missing = targets.filterNot { originals.hasOriginal(it) }
        if (missing.isNotEmpty()) {
            return RevertReport(
                false, LiteImplantCodes.ORIGINAL_MISSING,
                failed = missing.map { it.packageName }.distinct(),
            )
        }
        val reverted = ArrayList<String>()
        val failed = ArrayList<String>()
        for (intent in targets) {
            if (runCatching { reverter.revert(intent) }.getOrDefault(false)) reverted.add(intent.key())
            else failed.add(intent.key())
        }
        if (reverted.isNotEmpty()) {
            save(entries.filterNot { it.key() in reverted })
        }
        return if (failed.isEmpty()) {
            RevertReport(true, reverted = reverted)
        } else {
            RevertReport(false, LiteImplantCodes.REVERT_FAILED, reverted = reverted, failed = failed)
        }
    }

    private fun load(): List<ImplantIntent> {
        if (!file.isFile) {
            corrupted = false
            return emptyList()
        }
        val raw = AtomicControlFile.readUtf8(file)
        if (raw == null) {
            corrupted = true
            return emptyList()
        }
        val decoded = ControlJsonCodec.decodeOrNull(raw, LiteImplantFile.serializer())
        if (decoded == null || decoded.schema > 1) {
            corrupted = true
            return emptyList()
        }
        corrupted = false
        return decoded.entries.sortedWith(compareBy({ it.packageName }, { it.kind }))
    }

    private fun save(entries: List<ImplantIntent>) {
        check(directory.isDirectory || directory.mkdirs()) { "LITE_IMPLANT_STORE_INVALID" }
        val canonical = LiteImplantFile(entries = entries.sortedWith(compareBy({ it.packageName }, { it.kind })))
        AtomicControlFile.writeJson(file, ControlJsonCodec.encode(canonical, LiteImplantFile.serializer()))
        corrupted = false
    }
}

/**
 * 原件目录探测：
 * 1) [ImplantIntent.originalAbsent] → 无需恢复（删除新增文件即可）→ true；
 * 2) [ImplantIntent.originalBackupPath] → 备份文件必须真实存在；
 * 3) 旧格式（只有 `wiringOriginalSha256`）→ `originals/<package>/<sha>` 必须存在；
 * 4) 无恢复需求的旧记录（仅授权）→ true。
 */
class FileOriginalBackupStore(private val directory: File) : OriginalBackupStore {
    override fun hasOriginal(intent: ImplantIntent): Boolean {
        if (intent.originalAbsent) return true
        intent.originalBackupPath?.let { return File(it).isFile }
        val needsRestore = intent.wiringTargetLib != null || intent.pathInjection
        if (!needsRestore) return true
        val sha = intent.originalSha256 ?: intent.wiringOriginalSha256
            ?: intent.deliverSha256.takeIf { it.isNotBlank() }
            ?: return false
        return File(File(directory, "originals/${intent.packageName}"), sha).isFile
    }
}

/** W19 实现前：不伪造成功，撤回请求安全失败并进 LITE_IMPLANT_REVERT_FAILED。 */
object UnavailableImplantReverter : ImplantReverter {
    override fun revert(intent: ImplantIntent): Boolean = false
}

/** 空登记（无植入记录）时 `hasOriginals()=true`，不误阻断切换。 */
object EmptyLiteImplantRegistry : LiteImplantRegistry {
    override fun record(intent: ImplantIntent) = Unit
    override fun pending(): List<ImplantIntent> = emptyList()
    override fun revert(packageName: String): RevertReport = RevertReport(true)
    override fun hasOriginals(): Boolean = true
}

/** 供 runtime 记录时构造：投递路径/摘要 + 指定修改项。 */
fun implantIntent(
    packageName: String,
    uid: Int,
    deliverPath: String,
    deliverSha256: String,
    now: Long,
    wiringTargetLib: String? = null,
    wiringOriginalSha256: String? = null,
    sideLibraryPath: String? = null,
    createdDirs: List<String> = emptyList(),
    pathInjection: Boolean = false,
): ImplantIntent = ImplantIntent(
    packageName = packageName,
    uid = uid,
    deliverPath = deliverPath,
    deliverSha256 = deliverSha256,
    wiringTargetLib = wiringTargetLib,
    wiringOriginalSha256 = wiringOriginalSha256,
    sideLibraryPath = sideLibraryPath,
    createdDirs = createdDirs,
    pathInjection = pathInjection,
    recordedAt = now,
)

/** 只读空文件时的默认构造（供 W08 在未接登记表前安全使用）。 */
fun defaultLiteImplantRegistry(): LiteImplantRegistry = EmptyLiteImplantRegistry

/** 设备侧文件位置：`<root>/shared/lite-implants.json`。 */
fun fileLiteImplantRegistry(
    sharedDirectory: File,
    originals: OriginalBackupStore,
    reverter: ImplantReverter,
    clock: Clock = WallClock,
): LiteImplantRegistry = FileLiteImplantRegistry(sharedDirectory, originals, reverter, clock)

/** 便于测试/诊断：从一个已存在的 shared/superuser.json 值确认 schema 兼容。 */
fun sharedSuperuserSchemaOf(file: SharedSuperuserFile): Int = file.schema
