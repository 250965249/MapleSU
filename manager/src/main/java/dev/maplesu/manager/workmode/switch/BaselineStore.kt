package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.ShaCheck
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.WallClock
import kotlinx.serialization.Serializable
import java.io.File
import java.io.FileDescriptor
import java.io.IOException

/**
 * BaselineStore：基线 = 匹配当前槽、来源可追溯、已验证无 A/B 补丁的
 * 完整 boot/init_boot 镜像 + manifest。
 *
 * 硬约束：**takeover 不得当 baseline**（发布红线 3）；baseline 一旦建立不得被覆盖；
 * STALE 是硬阻断而不是警告（主文档:602、:967）。
 *
 * 边界：分区读写/镜像采样由切换事务（02/W05）负责；本类只消费其结论并持久化 manifest。
 */
enum class BaselineState { PRESENT_OK, MISSING_NEVER_CAPTURED, IMPORT_REQUIRED, STALE, CORRUPT }

object BaselineErrors {
    const val BASELINE_MISSING = "BASELINE_MISSING"
    const val BASELINE_STALE = "BASELINE_STALE"
    const val BASELINE_CORRUPT = "BASELINE_CORRUPT"
    const val BASELINE_UNCLEAN = "BASELINE_UNCLEAN"
    const val BASELINE_PROVENANCE_UNKNOWN = "BASELINE_PROVENANCE_UNKNOWN"
    const val BASELINE_PROMOTION_FORBIDDEN = "BASELINE_PROMOTION_FORBIDDEN"
    const val BASELINE_CAPTURE_UNSUPPORTED = "BASELINE_CAPTURE_UNSUPPORTED"
}

object BaselineProvenance {
    const val OEM_PACKAGE = "OEM_PACKAGE"
    const val PRE_FIRST_WRITE_CAPTURE = "PRE_FIRST_WRITE_CAPTURE"
    /** Explicit input for one switch; never an automatically reusable factory backup. */
    const val USER_SELECTED = "USER_SELECTED"
    val ALL: Set<String> = setOf(OEM_PACKAGE, PRE_FIRST_WRITE_CAPTURE)
}

@Serializable
data class BaselineManifest(
    val schema: Int = SCHEMA,
    val id: String,
    val createdAt: Long,
    /** Factory provenance, or USER_SELECTED for explicitly supplied switch input. */
    val provenance: String,
    /** = patchMarkers 全 absent 且 ramdisk 扫描通过。 */
    val clean: Boolean,
    val verifiedAt: Long,
    val slot: String,
    val firmware: String,
    val kernelRelease: String,
    val partitions: List<BaselinePartition>,
    val avb: AvbFacts,
    /** 必须全 absent 才允许当 baseline。 */
    val patchMarkers: PatchMarkers,
    /** 恒 true：baseline 一旦建立不得被覆盖。 */
    val immutable: Boolean = true,
) {
    companion object { const val SCHEMA = 1 }
}

@Serializable
data class BaselinePartition(
    val name: String,
    val size: Long,
    val sha256: String,
    val avbTailPreserved: Boolean,
)

@Serializable
data class AvbFacts(
    val vbmetaPresent: Boolean,
    val vbmetaSha256: String? = null,
    val verificationDisabled: Boolean,
)

@Serializable
data class PatchMarkers(
    val liteMarker: Boolean = false,
    val ksuInitReal: Boolean = false,
    val ksuKo: Boolean = false,
) {
    val allAbsent: Boolean get() = !liteMarker && !ksuInitReal && !ksuKo
}

/** 与 `baseline` 字段对齐：{"id","provenance","bootSha256","initBootSha256","clean"}。 */
data class BaselineCheck(
    val id: String,
    val provenance: String,
    val bootSha256: String,
    val initBootSha256: String,
    val clean: Boolean,
)

data class BaselineVerification(
    val state: BaselineState,
    val id: String?,
    /** 供 02 的 SwitchPlan 直接取用。 */
    val check: BaselineCheck?,
    /** ["slot:_a!=_b","avb_tail:boot","sha:boot"]。 */
    val mismatch: List<String>,
    /** 非空即禁止切换；取值域使用切换服务的稳定错误码。 */
    val blocker: String?,
)

/** 设备当前事实（由切换事务/只读探测提供；纯数据便于主机测试）。 */
data class DeviceBootFacts(
    val slot: String,
    val firmware: String,
    val kernelRelease: String,
)

/** 01 §7.3 未给出请求/结果类型，这里按最小需要补齐（见交付报告的规格缺口清单）。 */
sealed interface BaselineResult {
    data class Ok(val manifest: BaselineManifest) : BaselineResult
    data class Failed(val code: String, val detail: String) : BaselineResult
}

data class BaselineCaptureRequest(val id: String, val manifest: BaselineManifest)

data class BaselineImportRequest(val sourcePath: String, val manifest: BaselineManifest)

data class TakeoverRequest(val id: String, val manifest: BaselineManifest)

/** 纯规则：baseline 校验清单（import/capture 共用）与 STALE 判定。 */
object BaselineRules {

    /** 拒绝把 `Ace6/`、`.analysis/` 下的研究镜像自动当 baseline（主文档:821）。 */
    fun isStudyImage(sourcePath: String): Boolean {
        val normalized = sourcePath.replace('\\', '/')
        return normalized.contains("Ace6/") || normalized.contains(".analysis/")
    }

    /**
     * @param requireCleanProof 请求 manifest 自己是否必须声明 `clean`。
     *
     *   - `true`（默认）= manifest-only 路径（没有 materializer，例如受限环境/单测）：
     *     请求里的 `clean` 就是**唯一**证明，必须为 true，否则拒绝。
     *   - `false` = 有 materializer：`clean` / `patchMarkers` 由它用**真实字节**跑
     *     `BaselineCleanlinessPort` 之后重写（`FileBaselineStore` 在 `materializer != null` 时传 false）。
     *     这样"请求 manifest 里的 clean"不再是结论，**不再需要任何地方硬写 `clean = true`**。
     *
     * 判据仍然 fail-closed：materializer 说不干净就返回 `Failed`，落盘的 manifest 也只写它给出的结论。
     */
    fun validateImport(
        sourcePath: String,
        manifest: BaselineManifest,
        requireCleanProof: Boolean = true,
    ): String? = when {
        isStudyImage(sourcePath) -> BaselineErrors.BASELINE_PROVENANCE_UNKNOWN
        requireCleanProof && manifest.provenance != BaselineProvenance.USER_SELECTED &&
            (!manifest.patchMarkers.allAbsent || !manifest.clean) -> BaselineErrors.BASELINE_UNCLEAN
        manifest.provenance !in BaselineProvenance.ALL &&
            manifest.provenance != BaselineProvenance.USER_SELECTED -> BaselineErrors.BASELINE_PROVENANCE_UNKNOWN
        manifest.partitions.isEmpty() -> BaselineErrors.BASELINE_CORRUPT
        manifest.partitions.any { !it.avbTailPreserved } -> BaselineErrors.BASELINE_CORRUPT
        else -> null
    }

    /** 见 [validateImport] 的 [requireCleanProof] 说明（capture 与 import 同一口径）。 */
    fun validateCapture(manifest: BaselineManifest, requireCleanProof: Boolean = true): String? = when {
        requireCleanProof && !manifest.patchMarkers.allAbsent -> BaselineErrors.BASELINE_UNCLEAN
        requireCleanProof && !manifest.clean -> BaselineErrors.BASELINE_UNCLEAN
        manifest.provenance !in BaselineProvenance.ALL -> BaselineErrors.BASELINE_PROVENANCE_UNKNOWN
        manifest.partitions.isEmpty() -> BaselineErrors.BASELINE_CORRUPT
        else -> null
    }

    /**
     * 判定 baseline 状态。
     *
     * [shaForPartition] 返回实际读到（或从 manifest 目录算得）的镜像 sha；null = 该分区
     * 未读取（UNKNOWN，不据此判定）。
     */
    fun evaluate(
        manifest: BaselineManifest?,
        device: DeviceBootFacts,
        corruptManifest: Boolean = false,
        shaForPartition: (String) -> String? = { null },
        allowUserSelected: Boolean = false,
    ): BaselineVerification {
        if (corruptManifest) return corrupt()
        if (manifest == null) {
            return BaselineVerification(
                BaselineState.MISSING_NEVER_CAPTURED, null, null, emptyList(), BaselineErrors.BASELINE_MISSING,
            )
        }
        if (!manifest.immutable || manifest.partitions.isEmpty()) return corrupt(manifest.id)
        val selected = allowUserSelected && manifest.provenance == BaselineProvenance.USER_SELECTED
        if (!selected && (manifest.provenance !in BaselineProvenance.ALL || !manifest.clean || !manifest.patchMarkers.allAbsent)) {
            return BaselineVerification(
                BaselineState.IMPORT_REQUIRED, manifest.id, null, emptyList(),
                if (manifest.provenance !in BaselineProvenance.ALL) {
                    BaselineErrors.BASELINE_PROVENANCE_UNKNOWN
                } else {
                    BaselineErrors.BASELINE_UNCLEAN
                },
            )
        }
        val mismatch = mutableListOf<String>()
        if (manifest.slot != device.slot) mismatch += "slot:${manifest.slot}!=${device.slot}"
        // 两种工作模式可运行不同内核；运行时版本文字不代表已保存原厂镜像发生变化。
        // firmware/kernelRelease 保留为来源记录，实际可用性仍由槽位、镜像摘要与干净证明判定。
        manifest.partitions.filter { !it.avbTailPreserved }.forEach { mismatch += "avb_tail:${it.name}" }
        manifest.partitions.forEach { partition ->
            val actual = shaForPartition(partition.name) ?: return@forEach
            if (!actual.equals(partition.sha256, ignoreCase = true)) mismatch += "sha:${partition.name}"
        }
        if (mismatch.isNotEmpty()) {
            return BaselineVerification(
                BaselineState.STALE, manifest.id, null, mismatch, BaselineErrors.BASELINE_STALE,
            )
        }
        return BaselineVerification(BaselineState.PRESENT_OK, manifest.id, check(manifest), emptyList(), null)
    }

    fun check(manifest: BaselineManifest): BaselineCheck {
        val boot = manifest.partitions.firstOrNull { it.name == "boot" }
        val initBoot = manifest.partitions.firstOrNull { it.name == "init_boot" }
        return BaselineCheck(
            id = manifest.id,
            provenance = manifest.provenance,
            bootSha256 = boot?.sha256.orEmpty(),
            initBootSha256 = initBoot?.sha256.orEmpty(),
            clean = manifest.clean && manifest.patchMarkers.allAbsent,
        )
    }

    /** 硬约束：takeover 不得当 baseline。 */
    fun promoteTakeover(id: String): Nothing =
        throw IllegalStateException(BaselineErrors.BASELINE_PROMOTION_FORBIDDEN)

    private fun corrupt(id: String? = null): BaselineVerification = BaselineVerification(
        BaselineState.CORRUPT, id, null, emptyList(), BaselineErrors.BASELINE_CORRUPT,
    )
}

/** 基线持久化门面（接口与 01 §7.3 对齐）。 */
interface BaselineStore {
    fun state(): BaselineState
    fun verify(id: String? = null): BaselineVerification
    fun capture(request: BaselineCaptureRequest): BaselineResult
    fun import(request: BaselineImportRequest): BaselineResult
    fun open(id: String, partition: String): FileDescriptor?

    /**
     * 读出一份基线 manifest（`id == null` = latest）。
     *
     * 「已存在即复用」需要把**已存在**那份 manifest 原样交回调用方（不能凭空造一条新 manifest，
     * 那会变成"覆盖"或"假成功"）。默认 `null` = 该实现不提供 manifest ⇒ 调用方必须 fail-closed
     * （绝不降级成"重新抓一次并覆盖"）。
     */
    fun manifest(id: String? = null): BaselineManifest? = null

    /** 与 baseline 分目录，永不可晋升。 */
    fun captureTakeover(request: TakeoverRequest): BaselineResult
    fun markStale(reason: String)
    fun history(): List<BaselineManifest>

    /** 供切换前置检查消费的投影。 */
    fun check(id: String? = null): BaselineCheck
}

/**
 * P0：真实镜像字节的 materializer（installer 侧实现：只读分区 → 校验 → 写
 * `baseline/<id>/<partition>.img` → 原子回读）。`FileBaselineStore` 只负责 manifest、
 * 覆盖保护与失败清理；未注入时保持旧的 manifest-only 行为（单元测试/受限环境）。
 */
interface BaselineImageMaterializer {
    fun capture(request: BaselineCaptureRequest, directory: File): BaselineResult

    fun import(request: BaselineImportRequest, directory: File): BaselineResult
}

/**
 * 文件实现：baseline manifest 持久化在 `boot/baseline/<id>/manifest.json`，
 * takeover 在 `boot/takeover/<id>/manifest.json`（分目录，永不可晋升）。
 *
 * 分区镜像本体由切换事务写入同目录；本类只读取其 sha（若存在 `*.img`）做校验。
 */
class FileBaselineStore(
    private val root: File,
    private val deviceFacts: () -> DeviceBootFacts,
    private val clock: Clock = WallClock,
    /** P0：真实镜像 materializer；null = manifest-only（仅测试/受限环境）。 */
    private val materializer: BaselineImageMaterializer? = null,
) : BaselineStore {

    private val openStreams = LinkedHashMap<String, java.io.FileInputStream>()

    private fun baselineDir(id: String) = File(root, "boot/baseline/$id")
    private fun takeoverDir(id: String) = File(root, "boot/takeover/$id")
    private fun staleMarker() = File(root, "boot/baseline/.stale")

    override fun state(): BaselineState = verify().state

    override fun verify(id: String?): BaselineVerification {
        val device = deviceFacts()
        if (staleMarker().isFile &&
            (id.isNullOrBlank() || manifest(id)?.provenance != BaselineProvenance.USER_SELECTED)) {
            val manifest = id?.let { readManifest(File(baselineDir(it), "manifest.json")) }
                ?: latestManifest()
            return BaselineVerification(
                BaselineState.STALE, manifest?.id, null, listOf("marked_stale"), BaselineErrors.BASELINE_STALE,
            )
        }
        val manifestFile = id?.let { File(baselineDir(it), "manifest.json") }
            ?: latestManifestFile()
            ?: return BaselineRules.evaluate(null, device)
        val manifest = readManifest(manifestFile)
            ?: return BaselineRules.evaluate(null, device, corruptManifest = true)
        val shaCheck = AtomicControlFile.verifySha(manifestFile)
        return BaselineRules.evaluate(
            manifest = manifest,
            device = device,
            corruptManifest = shaCheck == ShaCheck.MISMATCH,
            allowUserSelected = !id.isNullOrBlank(),
            shaForPartition = { name ->
                val image = File(manifestFile.parentFile, "$name.img")
                // 流式 sha：boot/init_boot 镜像 96 MiB 起，绝不整块进堆（设备 OOM）。
                // 异常语义不变：不可读 → IOException 向上抛（与 readBytes 一致）。
                image.takeIf { it.isFile }?.let { dev.maplesu.manager.workmode.Hashes.sha256(it) }
            },
        )
    }

    override fun capture(request: BaselineCaptureRequest): BaselineResult {
        // 有 materializer 时 clean/patchMarkers 由它用真实字节证明并重写 ⇒ 请求里的声明不是结论。
        BaselineRules.validateCapture(request.manifest, requireCleanProof = materializer == null)
            ?.let { return BaselineResult.Failed(it, "capture") }
        val directory = baselineDir(request.id)
        if (File(directory, "manifest.json").exists()) {
            return BaselineResult.Failed(
                BaselineErrors.BASELINE_PROMOTION_FORBIDDEN, "baseline 已存在，禁止覆盖",
            )
        }
        val materialized = materializer?.capture(request, directory) ?: BaselineResult.Ok(request.manifest)
        if (materialized is BaselineResult.Failed) return materialized
        val written = writeManifest(
            directory, (materialized as BaselineResult.Ok).manifest, requireAbsent = true,
        )
        if (written is BaselineResult.Failed && materializer != null) {
            // 半成品不留在控制面：manifest 失败时删除本次 materialize 出来的镜像目录。
            directory.deleteRecursively()
        }
        return written
    }

    override fun import(request: BaselineImportRequest): BaselineResult {
        BaselineRules.validateImport(
            request.sourcePath, request.manifest, requireCleanProof = materializer == null,
        )?.let { return BaselineResult.Failed(it, "import") }
        val directory = baselineDir(request.manifest.id)
        if (File(directory, "manifest.json").exists()) {
            return BaselineResult.Failed(
                BaselineErrors.BASELINE_PROMOTION_FORBIDDEN, "baseline 已存在，禁止覆盖",
            )
        }
        val materialized = materializer?.import(request, directory)
            ?: BaselineResult.Ok(request.manifest)
        if (materialized is BaselineResult.Failed) return materialized
        val written = writeManifest(
            directory, (materialized as BaselineResult.Ok).manifest, requireAbsent = true,
        )
        if (written is BaselineResult.Failed && materializer != null) {
            directory.deleteRecursively()
        }
        return written
    }

    /**
     * P0：返回真实镜像的只读 FD（不再是恒 null）。流对象由本 store 持有（防止 GC 提前关闭），
     * 调用方读完由 [closeOpenImages] 统一释放；baseline 生命周期内文件不可变。
     */
    @Synchronized
    override fun open(id: String, partition: String): FileDescriptor? {
        val image = File(baselineDir(id), "$partition.img")
        if (!image.isFile) return null
        val key = "$id/$partition"
        openStreams.remove(key)?.let { runCatching { it.close() } }
        val stream = java.io.FileInputStream(image)
        openStreams[key] = stream
        return stream.fd
    }

    /** 释放 [open] 持有的只读流（恢复向导/导入完成后调用）。 */
    @Synchronized
    fun closeOpenImages() {
        openStreams.values.forEach { runCatching { it.close() } }
        openStreams.clear()
    }

    override fun captureTakeover(request: TakeoverRequest): BaselineResult {
        val manifest = request.manifest.copy(provenance = BaselineProvenance.PRE_FIRST_WRITE_CAPTURE)
        return writeManifest(takeoverDir(request.id), manifest, requireAbsent = false)
    }

    override fun markStale(reason: String) {
        staleMarker().parentFile?.mkdirs()
        AtomicControlFile.writeUtf8(staleMarker(), "${clock.nowMillis()} $reason".toByteArray(Charsets.UTF_8))
    }

    override fun history(): List<BaselineManifest> {
        val rootDir = File(root, "boot/baseline")
        val dirs = rootDir.listFiles { file -> file.isDirectory }?.toList() ?: return emptyList()
        return dirs.mapNotNull { readManifest(File(it, "manifest.json")) }
            .sortedWith(compareBy({ it.createdAt }, { it.id }))
    }

    override fun check(id: String?): BaselineCheck {
        val manifest = id?.let { readManifest(File(baselineDir(it), "manifest.json")) } ?: latestManifest()
        return manifest?.let { BaselineRules.check(it) }
            ?: BaselineCheck("", "", "", "", false)
    }

    private fun latestManifestFile(): File? {
        val dirs = File(root, "boot/baseline").listFiles { file -> file.isDirectory }?.toList()
            ?: return null
        return dirs
            .mapNotNull { dir -> readManifest(File(dir, "manifest.json"))
                ?.takeUnless { it.provenance == BaselineProvenance.USER_SELECTED }
                ?.let { it.createdAt to File(dir, "manifest.json") } }
            .maxByOrNull { it.first }
            ?.second
    }

    private fun latestManifest(): BaselineManifest? =
        latestManifestFile()?.let { readManifest(it) }

    override fun manifest(id: String?): BaselineManifest? =
        id?.let { readManifest(File(baselineDir(it), "manifest.json")) } ?: latestManifest()

    private fun readManifest(file: File): BaselineManifest? {
        val raw = AtomicControlFile.readUtf8(file) ?: return null
        return ControlJsonCodec.decodeOrNull(raw, BaselineManifest.serializer())
    }

    private fun writeManifest(directory: File, manifest: BaselineManifest, requireAbsent: Boolean): BaselineResult {
        val target = File(directory, "manifest.json")
        if (requireAbsent && target.exists()) {
            return BaselineResult.Failed(BaselineErrors.BASELINE_PROMOTION_FORBIDDEN, "baseline 已存在，禁止覆盖")
        }
        return try {
            if (!directory.exists() && !directory.mkdirs() && !directory.isDirectory) {
                return BaselineResult.Failed(BaselineErrors.BASELINE_CORRUPT, "dir")
            }
            val normalized = manifest.copy(
                id = manifest.id,
                immutable = true,
                verifiedAt = if (manifest.verifiedAt == 0L) clock.nowMillis() else manifest.verifiedAt,
            )
            AtomicControlFile.writeJson(target, ControlJsonCodec.encode(normalized, BaselineManifest.serializer()))
            BaselineResult.Ok(normalized)
        } catch (error: IOException) {
            BaselineResult.Failed(BaselineErrors.BASELINE_CORRUPT, error.message.orEmpty())
        }
    }
}
