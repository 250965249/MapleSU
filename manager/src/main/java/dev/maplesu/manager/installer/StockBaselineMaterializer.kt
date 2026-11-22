package dev.maplesu.manager.installer

import android.content.Context
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.ControlPaths
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.WallClock
import dev.maplesu.manager.workmode.switch.AvbFacts
import dev.maplesu.manager.workmode.switch.BaselineCaptureRequest
import dev.maplesu.manager.workmode.switch.BaselineErrors
import dev.maplesu.manager.workmode.switch.BaselineImageMaterializer
import dev.maplesu.manager.workmode.switch.BaselineImportRequest
import dev.maplesu.manager.workmode.switch.BaselineManifest
import dev.maplesu.manager.workmode.switch.BaselinePartition
import dev.maplesu.manager.workmode.switch.BaselineProvenance
import dev.maplesu.manager.workmode.switch.BaselineResult
import dev.maplesu.manager.workmode.switch.BaselineRules
import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import dev.maplesu.manager.workmode.switch.PatchMarkers
import kotlinx.serialization.Serializable
import org.tukaani.xz.XZInputStream
import org.tukaani.xz.XZIOException
import java.io.BufferedInputStream
import java.io.EOFException
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.UUID

/**
 * 随包 stock 资产的字节来源（生产 = `AssetManager`；主机单测 = 临时目录）。
 *
 * 只暴露"打开一个 entry 的流"，因此实现方不需要 Context 也能被测试；
 * 任何打开失败必须以 `IOException`（`FileNotFoundException` 是其子类）抛出，
 * materializer 会把它翻成既有的 `BASELINE_IMPORT_SOURCE_MISSING`。
 */
fun interface StockAssetSource {
    fun open(path: String): InputStream
}

/**
 * stock 资产的位置与 Context 解析（唯一来源，别处不要硬编码路径）。
 *
 * ⚠️ **本构建不再随包这份资产**（2026-11-01 `55-asset-slim.md`）：基线改由
 * 「首次写盘前现场抓取」获得（`CaptureFirstBaselineProvisioner`），随包 12.3 MB 的
 * `boot-stock/` 被删除——它既把产品钉死在一台机型上，又让 APK 超出体积闸门。
 * 保留本对象是为了两条**将来**的路径：①用户导入 OEM 镜像（`BaselineImportWizard`）；
 * ②若某构建确实要重新随包资产，仍从这里取根目录（`fromContext` 走真实 `AssetManager`）。
 * 在生产装配里不要再假设这些 entry 存在——见 [NoStockBaselineMaterializer]。
 */
object StockAssets {
    /**
     * `assets/` 下的固定根目录。目录名刻意不带括号/点
     * （见 15-stock-asset-feasibility.md §8.2①），firmware 原文写在 `pins.json` 的
     * `deviceFirmware` 里用于逐字比对。
     *
     * 2026-11-01 起该目录**不存在**于本仓库（`manager/src/main/assets/boot-stock/` 已删除）。
     */
    const val ROOT = "boot-stock/PLQ110_16.0.7.201_CN01"

    fun pinsAsset(root: String = ROOT): String = "$root/pins.json"

    fun fromContext(context: Context): StockAssetSource {
        val application = context.applicationContext ?: context
        val assets = application.assets
        return StockAssetSource { path -> assets.open(path) }
    }
}

/**
 * 「本构建不随包 stock 资产」时的 **fail-closed** materializer（`55-asset-slim.md`）。
 *
 * 为什么不是 `materializer = null`：`FileBaselineStore` 在 `materializer == null` 时走
 * manifest-only 分支（`BaselineStore.kt:327-328`）——只写 manifest、不落 `.img`，
 * 而写下的 manifest 带 `immutable`，等于在设备上永久占位一份「声称干净但没有镜像」的基线。
 * 这里显式失败：既不写 manifest，也不写镜像，用户看到的是一个既有错误码。
 *
 * `BASELINE_CAPTURE_UNSUPPORTED` 的选择：它在 `SwitchFlow`/`BaselinePreflightRepair` 里
 * 已是「基线类可修复码」（= CTA 可点一次自动获取），不会被当成设备/权限硬阻断。
 */
object NoStockBaselineMaterializer : BaselineImageMaterializer {
    /** detail 里必须能让现场一眼看懂「不是坏盘，是这个构建本来就没有资产」。 */
    const val DETAIL: String =
        "this build ships no stock baseline assets; " +
            "a baseline must come from a live capture or a user-imported OEM image"

    override fun capture(request: BaselineCaptureRequest, directory: File): BaselineResult =
        BaselineResult.Failed(BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED, DETAIL)

    override fun import(request: BaselineImportRequest, directory: File): BaselineResult =
        BaselineResult.Failed(BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED, DETAIL)
}

/** `pins.json` 顶层（字段与 15 §8.2② 逐字一致）。 */
@Serializable
internal data class StockPins(
    val schema: Int = 1,
    val deviceFirmware: String,
    val kernelRelease: String,
    val slotAgnostic: Boolean = true,
    val partitions: Map<String, StockPartitionPin> = emptyMap(),
)

@Serializable
internal data class StockPartitionPin(
    val asset: String,
    val size: Long,
    val sha256: String,
    /** 只作记录：整镜像 sha256 已经覆盖内核字节，不再单独校验。 */
    val kernelSha256: String? = null,
    val ramdiskSize: Long? = null,
    val ramdiskSha256: String? = null,
    val osPatch: String? = null,
)

/**
 * P7（P0-1 第 3 条）：把**调用方注入的** stock 资产（`<assetRoot>/` 下的 `*.img.xz` 与
 * `pins.json`）变成真实基线镜像字节。
 *
 * 2026-11-01 `55-asset-slim.md` 之后：本构建**不再随包** `assets/boot-stock/`，生产装配
 * 也不再构造本类（`productionBaselineProvisioner` 改为 `stockFallback = null`，
 * `ModeSwitchBindings`/`ServiceModeSwitchWiring` 改用 [NoStockBaselineMaterializer]）。
 * 本类保留是因为它仍是「用户导入 OEM 镜像」那条路的唯一实现；host 测试仍用临时目录夹具
 * 驱动它，xz 解压 / pin 校验 / cleanliness / 原子落位全部照旧被覆盖。
 *
 * 语义固定为 **`import()`**，绝不用 `capture()`：`capture()` 要求"镜像字节 == 当前 live 分区"，
 * 而本机 live 分区已被第三方改过（09 §1.6），stock 资产与它**必然不等**；`import()` 只要求
 * "解压出的字节 == manifest/pin 声明的 sha256"（`BaselineCaptureService.kt:206-212` 同口径）。
 *
 * **entry 路径契约（真机 2026-10-31 报障后固化）**：`pins.json` 的 `asset` 只写**裸文件名**
 * （`boot.img.xz`，可移植），真实 `AssetManager` entry 一律由 [assetPath] 拼成
 * `<assetRoot>/<asset>`。任何 `assets.open(...)` 都必须走 [assetPath]：漏拼根只会得到
 * `FileNotFoundException`，而 `AssetManager` 的 message 恰好就是裸名，于是 detail 退化成
 * `boot.img.xz: boot.img.xz` 这种自证不了的文案。
 *
 * 失败一律显式（复用既有码，不新增），**绝不**写"没有镜像的 manifest"，也**绝不**硬写
 * `clean = true` 掩盖证据缺失：
 *
 * | 情形 | 码 |
 * |---|---|
 * | 该固件没有随包资产 / `pins.json` 不可读 / pins 与设备事实不符 | `BASELINE_CAPTURE_UNSUPPORTED` |
 * | `pins.asset` 不是裸文件名（带了目录） | `BASELINE_CAPTURE_UNSUPPORTED` |
 * | 设备事实不全（slot/firmware/kernelRelease 有空） | `BASELINE_PROVENANCE_UNKNOWN` |
 * | 请求 manifest 与 pin/设备事实不一致（换固件后沿用旧 manifest） | `BASELINE_STALE` |
 * | 资产 entry 打不开（拼根后的 entry 不存在） | `BASELINE_IMPORT_SOURCE_MISSING` |
 * | xz 解码失败 / 解压后超过 pin.size / 落盘失败 | `BASELINE_CAPTURE_READ_FAILED` / `BASELINE_PARTITION_SIZE_MISMATCH` / `BASELINE_CAPTURE_WRITE_FAILED` |
 * | 解压后 sha256 与 pin 不符 | `BASELINE_PARTITION_SHA_MISMATCH` |
 * | 落位后回读 sha 不符 | `BASELINE_CAPTURE_READBACK_FAILED` |
 * | ramdisk 有 KSU/MapleSU 残留 / AVB 尾部越界 / 结构损坏 | `BASELINE_UNCLEAN` / `BASELINE_AVB_TAIL_INVALID` / `BASELINE_CORRUPT` |
 * | 目标目录已有镜像 | `BASELINE_PROMOTION_FORBIDDEN` |
 * | 被要求走 `capture()` | `BASELINE_CAPTURE_UNSUPPORTED` |
 *
 * 内存：`XZInputStream` 按块头声明的字典分配（`-6e` = 8 MiB），加 64 KiB 缓冲；
 * 与镜像大小（96 MiB / 8 MiB）无关。字典上限 32 MiB ⇒ 若有人把资产换成 `-9e`（64 MiB
 * 字典）会在解码阶段显式失败，而不是把 App 拖进 OOM。
 */
class StockBaselineMaterializer(
    private val assets: StockAssetSource,
    private val deviceFacts: () -> DeviceBootFacts,
    private val clock: Clock = WallClock,
    /** assets 内的根目录（测试注入不同根，生产用 [StockAssets.ROOT]）。 */
    private val assetRoot: String = StockAssets.ROOT,
    /** 暂存根：生产 = `ControlPaths.TMP`（`/data/adb/maplesu-workmode/tmp`），与基线目录同一文件系统。 */
    private val stagingRoot: File = File(ControlPaths.TMP),
    private val cleanliness: BaselineCleanlinessPort = RamdiskBaselineCleanliness(),
) : BaselineImageMaterializer {

    /**
     * [assetRoot] 的规范化形态（去前导/尾随斜杠、合并连续斜杠、`\` → `/`）。
     *
     * 生产值 = [StockAssets.ROOT]（本来就干净），此处的意义是**兜住注入**：若调用方传
     * `"boot-stock/x/"`，不 normalize 就会拼出 `boot-stock/x//boot.img.xz`，
     * `AssetManager` 同样只回 `FileNotFoundException`（与 2026-10-31 真机报障同一条失败路径）。
     */
    private val root: String = normalizeAssetRoot(assetRoot)

    /**
     * `pins.json` 里的 `asset` 只有**裸文件名**（可移植：换固件只改根目录），真实 entry 必须拼上
     * [root]。**所有**打开资产的调用点都必须走这里 —— 直接 `assets.open(pin.asset)` 会去找
     * `assets/boot.img.xz`，真机抛 `FileNotFoundException("boot.img.xz")`，被包成
     * `IMPORT_SOURCE_MISSING` 且 detail = `boot.img.xz: boot.img.xz`（用户看到的
     * “切换失败：boot.img.xz:boot.img.xz”）。
     */
    private fun assetPath(name: String): String = if (root.isEmpty()) name else "$root/$name"

    /**
     * 交给 [BaselineImportRequest.sourcePath] 的 provenance 标签。
     * 不含 `Ace6/`、`.analysis/`（`BaselineRules.isStudyImage` 会拒绝研究镜像）。
     */
    val sourcePath: String get() = assetPath(PINS_NAME)

    /**
     * 从 pin 造出"可交给 `FileBaselineStore.import()`"的请求 manifest。
     *
     * 这里 `clean = true` 与 `avbTailPreserved = true` 只是**请求声明**（`validateImport` 的
     * 前置形状要求，`BaselineStore.kt:135-143`）；真正的证明在 [import] 里由
     * [BaselineCleanlinessPort] 完成，不通过就直接 `Failed` 且不落任何 manifest。
     */
    fun prepareImport(id: String, device: DeviceBootFacts = deviceFacts()): BaselineResult {
        val pins = readPins()
            ?: return BaselineResult.Failed(
                BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED,
                "stock pins unavailable: ${assetPath(PINS_NAME)}",
            )
        problemOf(pins)?.let { return BaselineResult.Failed(BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED, it) }
        deviceProblem(device)?.let {
            return BaselineResult.Failed(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, it)
        }
        pinMismatch(pins, device)?.let {
            return BaselineResult.Failed(BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED, it)
        }
        return BaselineResult.Ok(
            BaselineManifest(
                id = id,
                createdAt = clock.nowMillis(),
                provenance = BaselineProvenance.OEM_PACKAGE,
                // 请求声明；import() 会用 cleanliness 结论重写这两个字段。
                clean = true,
                verifiedAt = 0L,
                slot = device.slot,
                firmware = device.firmware,
                kernelRelease = device.kernelRelease,
                partitions = pinnedPartitions(pins),
                avb = AvbFacts(vbmetaPresent = false, vbmetaSha256 = null, verificationDisabled = false),
                patchMarkers = PatchMarkers(),
                immutable = true,
            ),
        )
    }

    /** stock 资产不能当 `capture()` 源：live 分区与 stock 镜像必然不等（09 §1.6）。 */
    override fun capture(request: BaselineCaptureRequest, directory: File): BaselineResult =
        BaselineResult.Failed(
            BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED,
            "stock asset materializer supports import() only (no live partition bytes)",
        )

    override fun import(request: BaselineImportRequest, directory: File): BaselineResult {
        val manifest = request.manifest
        if (manifest.provenance != BaselineProvenance.OEM_PACKAGE) {
            return BaselineResult.Failed(
                BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
                "stock import requires provenance=${BaselineProvenance.OEM_PACKAGE}, was ${manifest.provenance}",
            )
        }
        if (BaselineRules.isStudyImage(request.sourcePath)) {
            return BaselineResult.Failed(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, request.sourcePath)
        }
        val device = deviceFacts()
        val pins = readPins()
            ?: return BaselineResult.Failed(
                BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED,
                "stock pins unavailable: ${assetPath(PINS_NAME)}",
            )
        problemOf(pins)?.let { return BaselineResult.Failed(BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED, it) }
        deviceProblem(device)?.let {
            return BaselineResult.Failed(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, it)
        }
        pinMismatch(pins, device)?.let {
            return BaselineResult.Failed(BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED, it)
        }
        requestMismatch(manifest, pins, device)?.let { (code, detail) ->
            return BaselineResult.Failed(code, detail)
        }

        val staging = File(stagingRoot, "stock-${directory.name}-${UUID.randomUUID()}")
        if (!staging.mkdirs() && !staging.isDirectory) {
            return BaselineResult.Failed(BaselineCaptureCodes.CAPTURE_WRITE_FAILED, staging.absolutePath)
        }
        try {
            val staged = LinkedHashMap<String, File>()
            val sizes = LinkedHashMap<String, Long>()
            for (partition in manifest.partitions) {
                val pin = pins.partitions[partition.name] ?: continue
                val target = File(staging, BaselineImageNames.imageName(partition.name))
                val failure = extract(pin, target)
                if (failure != null) return failure
                staged[partition.name] = target
                sizes[partition.name] = pin.size
            }
            if (staged.keys.toSet() != PINNED_PARTITIONS.toSet()) {
                return BaselineResult.Failed(
                    BaselineErrors.BASELINE_CORRUPT,
                    "staged=${staged.keys} manifest=${manifest.partitions.map { it.name }}",
                )
            }
            // 真实证明：结构（boot 容器 / ramdisk 可解析）+ 无 KSU/MapleSU 残留 + AVB 尾部。
            // 导入外部 OEM 镜像时控制面 patch 证据不适用（`BaselineCaptureService.kt:218-219` 同口径）。
            val report = cleanliness.verify(
                staged, sizes, BaselinePatchEvidence(true, false, null, "stock:pin-only"),
            )
            if (!report.clean) {
                return BaselineResult.Failed(
                    report.code.ifEmpty { BaselineErrors.BASELINE_UNCLEAN }, report.detail,
                )
            }
            if (!manifest.clean || !manifest.patchMarkers.allAbsent) {
                return BaselineResult.Failed(
                    BaselineErrors.BASELINE_UNCLEAN, "request claims an unclean baseline",
                )
            }
            if (!directory.isDirectory && !directory.mkdirs() && !directory.isDirectory) {
                return BaselineResult.Failed(BaselineErrors.BASELINE_CORRUPT, "baseline dir")
            }
            for ((name, stagedImage) in staged) {
                val target = File(directory, BaselineImageNames.imageName(name))
                if (target.exists()) {
                    return BaselineResult.Failed(
                        BaselineErrors.BASELINE_PROMOTION_FORBIDDEN, "$name image already exists",
                    )
                }
                val expected = pins.partitions.getValue(name).sha256
                if (!promote(stagedImage, target, expected)) {
                    target.delete()
                    return BaselineResult.Failed(
                        BaselineCaptureCodes.CAPTURE_READBACK_FAILED, "$name readback mismatch",
                    )
                }
            }
            return BaselineResult.Ok(
                manifest.copy(
                    provenance = BaselineProvenance.OEM_PACKAGE,
                    clean = true,
                    patchMarkers = report.patchMarkers,
                    // 缺失即 false（fail-closed）：avbTailPreserved=true 不能靠默认值猜。
                    partitions = manifest.partitions.map { part ->
                        part.copy(avbTailPreserved = report.avbTailPreserved[part.name] == true)
                    },
                    verifiedAt = clock.nowMillis(),
                ),
            )
        } catch (error: IOException) {
            return BaselineResult.Failed(BaselineCaptureCodes.CAPTURE_WRITE_FAILED, error.message.orEmpty())
        } finally {
            staging.deleteRecursively()
        }
    }

    // ------------------------------------------------------------------ 解压 + 校验

    /** 流式解压一个 entry 到 [destination]，同时算 sha256；返回 null = 成功。 */
    private fun extract(pin: StockPartitionPin, destination: File): BaselineResult.Failed? {
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L
        // ★ 必须拼根：pin.asset 只是 `boot.img.xz`（见 assetPath 的 KDoc）。
        val path = assetPath(pin.asset)
        val raw = try {
            assets.open(path)
        } catch (error: IOException) {
            // detail 里同时给出“想打开的 entry 全路径”和 AssetManager 的原话，
            // 避免旧版本的 `boot.img.xz: boot.img.xz` 那种自证不了的重复。
            return BaselineResult.Failed(
                BaselineCaptureCodes.IMPORT_SOURCE_MISSING, "$path: ${error.message.orEmpty()}",
            )
        }
        try {
            BufferedInputStream(raw).use { buffered ->
                // 32 MiB 字典上限：-6e 的 8 MiB 字典够用，-9e 的 64 MiB 会显式失败而不是 OOM。
                XZInputStream(buffered, XZ_MEMORY_LIMIT_KIB).use { xz ->
                    FileOutputStream(destination).use { output ->
                        val buffer = ByteArray(BUFFER_BYTES)
                        while (true) {
                            val read = xz.read(buffer)
                            if (read < 0) break
                            if (read == 0) continue
                            total += read
                            if (total > pin.size) {
                                return BaselineResult.Failed(
                                    BaselineCaptureCodes.CAPTURE_SIZE_MISMATCH,
                                    "${pin.asset}: decompressed more than ${pin.size}",
                                )
                            }
                            digest.update(buffer, 0, read)
                            output.write(buffer, 0, read)
                        }
                        output.flush()
                        output.fd.sync()
                    }
                }
            }
        } catch (error: XZIOException) {
            return BaselineResult.Failed(
                BaselineCaptureCodes.CAPTURE_READ_FAILED, "${pin.asset}: ${error.message.orEmpty()}",
            )
        } catch (error: EOFException) {
            return BaselineResult.Failed(
                BaselineCaptureCodes.CAPTURE_READ_FAILED, "${pin.asset}: truncated xz stream",
            )
        } catch (error: IOException) {
            return BaselineResult.Failed(
                BaselineCaptureCodes.CAPTURE_WRITE_FAILED, "${pin.asset}: ${error.message.orEmpty()}",
            )
        }
        if (total != pin.size) {
            return BaselineResult.Failed(
                BaselineCaptureCodes.CAPTURE_SIZE_MISMATCH, "${pin.asset}: $total != ${pin.size}",
            )
        }
        val actual = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        if (!actual.equals(pin.sha256, ignoreCase = true)) {
            return BaselineResult.Failed(
                BaselineCaptureCodes.CAPTURE_SHA_MISMATCH, "${pin.asset}: $actual != ${pin.sha256}",
            )
        }
        return null
    }

    /**
     * 暂存文件 → 基线目录：优先同文件系统原子 rename（`ControlPaths.TMP` 与
     * `boot/baseline` 同在 `/data/adb/maplesu-workmode` 下），跨文件系统才退化成
     * 流式 copy + 原子替换（`BaselineAtomicFiles.copyVerified`）。最后再读回验一次 sha。
     */
    private fun promote(staged: File, target: File, expectedSha256: String): Boolean {
        val parent = target.parentFile ?: return false
        if (!parent.isDirectory && !parent.mkdirs() && !parent.isDirectory) return false
        val renamed = runCatching {
            Files.move(staged.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE)
        }.isSuccess
        if (!renamed && !BaselineAtomicFiles.copyVerified(staged, target, expectedSha256)) return false
        AtomicControlFile.syncDirectory(parent)
        return BaselineAtomicFiles.sha256(target).equals(expectedSha256, ignoreCase = true)
    }

    // ------------------------------------------------------------------ pins

    /**
     * 只负责“读得到 + 解得开”；结构问题交给调用方的 [problemOf] 报，这样 detail 能指出
     * 具体哪一条 pin 坏了（例：`boot: asset must be a bare file name ...`），
     * 而不是一律缩成 “stock pins unavailable”。两个调用点都在拿到的下一步就调 [problemOf]。
     */
    private fun readPins(): StockPins? {
        val path = assetPath(PINS_NAME)
        val raw = runCatching {
            assets.open(path).use { stream -> stream.readBytes() }
        }.getOrNull() ?: return null
        if (raw.size > MAX_PINS_BYTES) return null
        return ControlJsonCodec.decodeOrNull<StockPins>(raw.toString(Charsets.UTF_8))
    }

    /** pins 自身的结构问题（缺分区 / 尺寸非正 / sha 形状不对 / asset 不是裸文件名）。 */
    private fun problemOf(pins: StockPins): String? {
        if (pins.schema < 1) return "pins.schema=${pins.schema}"
        if (pins.deviceFirmware.isBlank() || pins.kernelRelease.isBlank()) return "pins firmware/kernelRelease blank"
        if (pins.partitions.isEmpty()) return "pins.partitions empty"
        for (name in PINNED_PARTITIONS) {
            val pin = pins.partitions[name] ?: return "pins missing partition: $name"
            assetProblem(pin.asset)?.let { return "$name: $it" }
            if (pin.size <= 0L) return "$name: size=${pin.size}"
            if (!pin.sha256.matches(SHA256_PATTERN)) return "$name: sha256=${pin.sha256}"
        }
        return null
    }

    /**
     * `pins.json` 的 `asset` 契约：**裸文件名**（不含目录、不是 `.`/`..`）。
     *
     * 带目录的 asset 与 [assetPath] 会二次嵌套（`root/<path>/boot.img.xz`），真机只会得到
     * `IMPORT_SOURCE_MISSING`；而且 asset 是随包常量、没有“运行时才知道”的理由 ⇒ 宁可在这里
     * 就显式拒绝，也不要让它在解压阶段变成一个看不懂的 FileNotFoundException。
     */
    private fun assetProblem(asset: String): String? {
        if (asset.isBlank()) return "asset blank"
        if (asset.contains('/') || asset.contains('\\') || asset == "." || asset == "..") {
            return "asset must be a bare file name (joined with assetRoot), was \"$asset\""
        }
        return null
    }

    private fun deviceProblem(device: DeviceBootFacts): String? {
        if (device.slot.isBlank() || device.firmware.isBlank() || device.kernelRelease.isBlank()) {
            return "device facts incomplete: slot=${device.slot} firmware=${device.firmware} " +
                "kernelRelease=${device.kernelRelease}"
        }
        return null
    }

    /**
     * pin ↔ 设备事实。校验维度**只用**整镜像 sha256 + size + kernelRelease
     * （15 §8.2②；boot header 的 `osVersion` 是 0、init_boot 的 `build.prop` 是通用
     * oplus 体，两者都没有区分力，因此不参与判定）。
     */
    private fun pinMismatch(pins: StockPins, device: DeviceBootFacts): String? {
        if (device.firmware != pins.deviceFirmware) {
            return "firmware device=${device.firmware} pins=${pins.deviceFirmware}"
        }
        if (device.kernelRelease != pins.kernelRelease) {
            return "kernelRelease device=${device.kernelRelease} pins=${pins.kernelRelease}"
        }
        if (!pins.slotAgnostic) {
            // pin 里没有 slot 字段 ⇒ 无法证明"该 slot 适用" ⇒ 不许猜
            return "pins not slot-agnostic but carry no slot"
        }
        return null
    }

    /** 请求 manifest ↔ pin/设备事实（防"换了固件却沿用旧 manifest"）。 */
    private fun requestMismatch(
        manifest: BaselineManifest,
        pins: StockPins,
        device: DeviceBootFacts,
    ): Pair<String, String>? {
        if (manifest.slot != device.slot) {
            return BaselineErrors.BASELINE_STALE to "slot ${manifest.slot} != ${device.slot}"
        }
        if (manifest.firmware != device.firmware) {
            return BaselineErrors.BASELINE_STALE to "firmware ${manifest.firmware} != ${device.firmware}"
        }
        if (manifest.kernelRelease != device.kernelRelease) {
            return BaselineErrors.BASELINE_STALE to
                "kernelRelease ${manifest.kernelRelease} != ${device.kernelRelease}"
        }
        if (manifest.partitions.isEmpty()) {
            return BaselineErrors.BASELINE_CORRUPT to "manifest has no partitions"
        }
        for (part in manifest.partitions) {
            val pin = pins.partitions[part.name]
                ?: return BaselineErrors.BASELINE_CORRUPT to "${part.name}: not pinned"
            if (part.size != pin.size) {
                return BaselineErrors.BASELINE_STALE to "${part.name}: size ${part.size} != ${pin.size}"
            }
            if (!part.sha256.equals(pin.sha256, ignoreCase = true)) {
                return BaselineErrors.BASELINE_STALE to "${part.name}: sha ${part.sha256} != ${pin.sha256}"
            }
        }
        for (name in PINNED_PARTITIONS) {
            if (manifest.partitions.none { it.name == name }) {
                return BaselineErrors.BASELINE_STALE to "$name: pinned but missing from manifest"
            }
        }
        return null
    }

    private fun pinnedPartitions(pins: StockPins): List<BaselinePartition> =
        PINNED_PARTITIONS.mapNotNull { name ->
            pins.partitions[name]?.let { pin ->
                // avbTailPreserved=true 是请求形状（validateImport 要求）；真实值由 import() 覆盖。
                BaselinePartition(name, pin.size, pin.sha256, avbTailPreserved = true)
            }
        }

    private companion object {
        /** `pins.json` 的裸文件名；真实 entry = `assetPath(PINS_NAME)`。 */
        const val PINS_NAME = "pins.json"

        /**
         * `assetRoot` 规范化：去前导/尾随斜杠、合并连续斜杠、`\` → `/`。
         *
         * 返回空串表示“assets 根就是根”（此时 `assetPath` 不加前缀），
         * 无论哪种情况都不会产生 `//x` 或 `/x` 这种 `AssetManager` 不认的 entry。
         */
        fun normalizeAssetRoot(raw: String): String =
            raw.trim().replace('\\', '/').split('/').filter { it.isNotEmpty() }.joinToString("/")

        /**
         * 双向切换两边都要求有非目标分区的基线（`ModeSwitchPreflight.kt:248-255`：
         * A→B 的非目标 = boot，B→A 的非目标 = init_boot）⇒ 一份基线必须同时含两者，
         * 缺任何一个就显式 `BASELINE_CAPTURE_UNSUPPORTED`，不允许产出"半份基线"。
         */
        val PINNED_PARTITIONS = listOf("boot", "init_boot")

        const val BUFFER_BYTES = 64 * 1024
        const val XZ_MEMORY_LIMIT_KIB = 32 * 1024
        const val MAX_PINS_BYTES = 64 * 1024
        val SHA256_PATTERN = Regex("[0-9a-fA-F]{64}")
    }
}
