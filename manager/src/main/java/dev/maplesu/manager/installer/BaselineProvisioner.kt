package dev.maplesu.manager.installer

import android.content.Context
import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.ControlPaths
import dev.maplesu.manager.workmode.control.ShaCheck
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.WallClock
import dev.maplesu.manager.workmode.superuser.LiteImplantScripts
import dev.maplesu.manager.workmode.superuser.RootScriptRunner
import dev.maplesu.manager.workmode.switch.BaselineErrors
import dev.maplesu.manager.workmode.switch.BaselineImportRequest
import dev.maplesu.manager.workmode.switch.BaselineManifest
import dev.maplesu.manager.workmode.switch.BaselineProvenance
import dev.maplesu.manager.workmode.switch.BaselineResult
import dev.maplesu.manager.workmode.switch.BaselineRules
import dev.maplesu.manager.workmode.switch.BaselineState
import dev.maplesu.manager.workmode.switch.BaselineStore
import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import dev.maplesu.manager.workmode.switch.FileBaselineStore
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.ModeSwitchHashes
import java.io.File

/**
 * P0-1 第 3 项（第二步：接线层）：**用户点一次切换**时的基线自动获取（2026-11-01 W4a 改为抓取优先）。
 *
 * 位置约定（唯一入口）：`ModeSwitchFacade.startSwitch` 在 SELinux 自动恢复**之后**、
 * 第一次 `client.preflight` / `client.snapshot`（第一个 dd）**之前**调用 [ensureBaseline]；
 * `ModeSwitchFacade.installCommit` 在 `InstallCommitCoordinator.commit`（第一次分区写）之前
 * 走同一条路径。因此失败一定是"零写入"的显式错误，而不是点了没反应、或先 dd 100 MB 再报
 * `SWITCH_PRE_IMAGE_INVALID`（`11-baseline-construction-plan.md` §1.2 / §11.2）。
 *
 * **源顺序（抓取优先，2026-11-01 用户指令）**：
 * 1. ① 控制面里**已存在且校验通过**的基线 → `Ready(id, reused = true)`，**零 dd**；
 * 2. ② 首次写盘前**现场抓取**（root 只读 dd 当前槽 `boot`/`init_boot` 整分区 → App 侧满长/sha
 *    复核 → cleanliness 真实字节判定 → 发布到控制面）→ `Ready(id, reused = false)`；
 * 3. ③ 随包 stock 资产（[StockBaselineMaterializer] / `pins.json`）**仅兜底**
 *    （2026-11-01 `55-asset-slim.md`：本构建已删除该 12.3 MB 资产 ⇒ 生产装配
 *    `stockFallback = null`，即没有③；①/② 完全不受影响）。
 *
 * 于是「没有该机型的 pin」不再是切换的前置条件：任意机型只要能在首次写盘前读到当前槽，
 * 就能得到一份可证明纯净、可还原的基线（见 [CaptureFirstBaselineProvisioner]）。
 *
 * 边界（红线，违反就等于没做成）：
 * 1. **只写基线目录**（`/data/adb/maplesu-workmode/boot/baseline/<id>/`，= `ControlPaths.RECOVERY_BOOT`）；
 *    **绝不写任何分区**。本文件只出现 `dd if=<分区> of=<App 暂存>` 的**只读**方向。
 * 2. **绝不硬写 `clean = true`**：干净性由 [BaselineCleanlinessPort] 对真实字节判定，
 *    本文件只消费它的结论（抓取证据不足 → 显式 `BASELINE_PROVENANCE_UNKNOWN`，不猜）。
 * 3. **绝不覆盖**已有基线（`BaselineStore` 的 `BASELINE_PROMOTION_FORBIDDEN` 原样透出）：
 *    已有可复用基线走"复用"，不是"重抓覆盖"。
 * 4. **两个分区都抓**（有 `init_boot` 的机型）：只备一个会让另一个方向永远撞
 *    `SWITCH_BASELINE_REQUIRED`（施工图 §11.2-2）。没有 `init_boot` 节点的机型只抓 `boot`。
 * 5. 复用判定**不重复解压、不重复写盘**：已有基线且 manifest 自校验通过 → 直接 `Ready(reused=true)`。
 */
fun interface BaselineProvisioner {
    /**
     * 幂等：已有可证明纯净的基线 → `Ready(id, reused = true)`（零写盘）；
     * 否则从随包 stock 资产建立；任何建立不了的情形 → `Failed(code, detail)`（绝不返回假成功）。
     *
     * 调用方必须已切到后台线程（IO）；实现内部会做 100 MB 级 IO。
     */
    fun ensureBaseline(): BaselineProvisionOutcome
}

/** 一次基线获取的结果（`reused = true` ⇒ 这一次**一个字节都没写**）。 */
sealed interface BaselineProvisionOutcome {
    /** [id] 必须接进 `ModeSwitchRequest.baselineId` 与 planFields（否则 Normal 侧 BASE 导出必失败）。 */
    data class Ready(
        val id: String,
        val reused: Boolean,
        val provenance: String,
    ) : BaselineProvisionOutcome

    /** 显式失败码（全部来自既有 [BaselineErrors] / [BaselineCaptureCodes] / [ModeSwitchCodes]）。 */
    data class Failed(val code: String, val detail: String) : BaselineProvisionOutcome
}

/**
 * 「本构建是否已接线基线自动获取」的**构建期**事实（服务端 CTA 放宽的唯一依据）。
 *
 * 为什么是常量而不是构造参数：`ModeSwitchDeviceDelegate` 活在 **root 服务进程**
 * （`InstallerPartitionService` → `ServiceModeSwitchWiring.create()`），而 provisioner 活在
 * **App 进程**（只有 App 有 `AssetManager` 与控制面写入的 root 通道）。跨进程序言无法
 * "问一句 App 有没有接线"，而本波不允许改 AIDL/`ModeSwitchClient`、也不允许改两处 wiring，
 * 所以用**同一个 APK 同一个常量**表达"两端同构建"这个真实不变量：
 * - 生产 App 侧必然有 [productionBaselineProvisioner]（`AndroidSwitchEnvironment.provisioner()`），
 *   服务端若不同步放宽，`KSU→LITE` 的 CTA 会恒灰 ⇒ 自动获取永远跑不到；
 * - 常量只影响 **CTA**：真正的基线硬闸门是 `begin`（第一个 dd 之前）、`snapshot`、`commit`，
 *   它们不看这个常量。所以常量判断错的最坏后果是"点一次得到显式失败码"，不是假成功。
 *
 * ⚠️ 若将来移除 App 侧 provisioner 接线，必须把这里改回 `false`（否则只是白点一次，
 * 不会写坏任何东西，但会把错误推迟到 `begin`）。
 */
object BaselineProvisioning {
    const val APP_WIRED: Boolean = true
}

/** 基线 id 与分区集合的唯一来源（不读 pin，纯设备事实 → 确定性 id）。 */
object BaselineIdentity {
    /**
     * 一份**随包 stock 基线**必须同时含两个分区（A↔B 双向的非目标分区分别是 boot / init_boot，
     * 见 `ModeSwitchPreflight.kt` 的 `targetPartition`/`writeOrder`）。
     *
     * 注意：这是"随包资产/导入 OEM 镜像"的要求，**不是**所有机型的要求 —— 没有独立
     * `init_boot` 分区的机型（A-only / 早期 GKI）只能抓到 `boot`，抓取路径允许只含 `boot`
     * （见 [reusableBaselineEntry] 的 `requireInitBoot`）。
     */
    val PARTITIONS: List<String> = listOf("boot", "init_boot")

    /** `_a` → `a`、`_b` → `b`、其它/空 → `na`（id 只允许 `[A-Za-z0-9._-]`）。 */
    fun slotToken(slot: String): String = when (slot.trim()) {
        "_a", "a", "A" -> "a"
        "_b", "b", "B" -> "b"
        else -> "na"
    }

    /** `^[A-Za-z0-9._-]{1,64}$`：与 `UltraRootModeSwitchClient` 的 `BASELINE_ID` 逐字一致。 */
    fun isValidId(id: String): Boolean = BASELINE_ID.matches(id)

    /**
     * 内容派生 id：`bl-<slot>-<fw8>-<boot12>`（28~32 字符）。
     *
     * 与 [fromDevice] 的差别：**只有抓取路径能用这个**（它必须手里已经有 boot 的真实摘要）。
     * 抓取时先用 `source.snapshot()` 拿到整分区摘要再派生 id ⇒ 不需要为了算 id 先 dd 一次，
     * 也不会出现"同一个 boot 字节每次得到不同 id"（时间戳 id 的后果：每次切换重新 dd 96–200 MiB）。
     *
     * 合法性：`^[A-Za-z0-9._-]{1,64}$` ✔
     */
    fun fromSnapshot(snapshot: BaselineDeviceSnapshot): String {
        val firmware = Hashes.sha256Hex(snapshot.firmware).take(8)
        val boot = snapshot.partitions["boot"]?.sha256?.trim()?.lowercase().orEmpty()
        val bootToken = if (SHA256.matches(boot)) {
            boot.take(12)
        } else {
            // 没有 boot 摘要时不能靠时间戳兜底（不可复用），退化成对空串摘要 ⇒ 仍然确定性。
            Hashes.sha256Hex(boot).take(12)
        }
        return "bl-${slotToken(snapshot.slot)}-$firmware-$bootToken"
    }

    /**
     * 设备事实派生 id（stock 资产路径用：**先有 id 才能造 import 请求 manifest**，
     * 那时还没有任何镜像字节）。
     *
     * 与施工图 §3.2 的差别（已在交付报告说明）：那里的 `bootSha256` 只有 `pins.json` 里才有，
     * 而 `prepareImport()` 需要**先**有 id 才能造 manifest。本机随包资产是"固件 + 内核版本 →
     * 唯一 pinned 镜像集"（`pins.json` 逐字比对 `deviceFirmware` 与 `kernelRelease`），
     * 所以用这两者派生 id **同样确定**，且不引入"算 id 要先解 pin"的顺序陷阱（施工图 §12-②）。
     */
    fun fromDevice(device: DeviceBootFacts): String {
        val firmware = Hashes.sha256Hex(device.firmware).take(8)
        val kernel = Hashes.sha256Hex(device.kernelRelease).take(12)
        return "bl-${slotToken(device.slot)}-$firmware-$kernel"
    }

    private val BASELINE_ID = Regex("^[A-Za-z0-9._-]{1,64}$")
    private val SHA256 = Regex("[0-9a-f]{64}")
}

// ---------------------------------------------------------------------------
// 第一层：在**本进程可写**的基线上做「复用 → 导入」
// ---------------------------------------------------------------------------

/**
 * 基线获取的纯编排（不碰 root、不碰 Android API，主机可直接测）。
 *
 * 复用判定**不复用** `FileBaselineStore.verify()` 的 sha 计算（那边是
 * `Hashes.sha256(image.readBytes())`，96 MiB 一次进堆 —— 见 `16-baseline-base-layer.md` U-5），
 * 而是走 [BaselineRules.evaluate] + [ModeSwitchHashes.sha256]（64 KiB 流式）。
 * 判定口径仍然只有一套：`BaselineRules` 是唯一权威。
 */
class StockBaselineProvisioner(
    private val store: BaselineStore,
    private val materializer: StockBaselineMaterializer,
    /** 控制面根（生产 = [ControlPaths.ROOT]；standalone 测试 = 临时目录）。 */
    private val controlRoot: File,
    private val deviceFacts: () -> DeviceBootFacts,
    private val idOf: (DeviceBootFacts) -> String = BaselineIdentity::fromDevice,
) : BaselineProvisioner {

    private val baselineRoot: File get() = File(controlRoot, "boot/baseline")

    override fun ensureBaseline(): BaselineProvisionOutcome {
        val device = runCatching { deviceFacts() }.getOrNull()
            ?: return fail(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, "device facts unavailable")
        if (device.slot.isBlank() || device.firmware.isBlank() || device.kernelRelease.isBlank()) {
            return fail(
                BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
                "device facts incomplete: slot=${device.slot} firmware=${device.firmware} " +
                    "kernelRelease=${device.kernelRelease}",
            )
        }
        // ① 零 dd 复用：枚举 + 逐个自校验（不是"算 id 只看一个目录"，施工图 §3.3/§12-②）。
        reusable(device)?.let { manifest ->
            return BaselineProvisionOutcome.Ready(
                id = manifest.id,
                reused = true,
                provenance = manifest.provenance,
            )
        }
        // ② 建立：prepareImport 造请求 manifest（pin/设备事实双重比对在 materializer 里），
        //    store.import 只写 `boot/baseline/<id>/`（镜像 + manifest + .sha256）。
        val id = idOf(device)
        val prepared = materializer.prepareImport(id, device)
        if (prepared is BaselineResult.Failed) return fail(prepared.code, prepared.detail)
        val manifest = (prepared as BaselineResult.Ok).manifest
        val imported = store.import(BaselineImportRequest(materializer.sourcePath, manifest))
        if (imported is BaselineResult.Failed) return fail(imported.code, imported.detail)
        // ③ 回读复核：不信 import() 的返回值，用**同一套**复用判定再证明一次落盘产物可用。
        val written = reusable(device)
            ?: return fail(
                BaselineCaptureCodes.CAPTURE_READBACK_FAILED,
                "baseline not readable after import: $id",
            )
        return BaselineProvisionOutcome.Ready(
            id = written.id,
            reused = false,
            provenance = written.provenance,
        )
    }

    /**
     * 找出本机上**可证明纯净且匹配当前设备**的已有基线；没有 → null。
     *
     * 只读：`manifest.json` + `manifest.json.sha256` + 两个 `*.img` 的流式 sha。
     */
    internal fun reusable(device: DeviceBootFacts): BaselineManifest? {
        val directories = baselineRoot.listFiles { file -> file.isDirectory } ?: return null
        // 期待 id 优先，其次按 createdAt 从新到旧（多份基线时取最新可用的）。
        val ordered = directories.sortedWith(
            compareByDescending<File> { it.name == idOf(device) }
                .thenByDescending { it.name },
        )
        for (directory in ordered) {
            val manifestFile = File(directory, "manifest.json")
            val raw = AtomicControlFile.readUtf8(manifestFile) ?: continue
            val manifest = ControlJsonCodec.decodeOrNull(raw, BaselineManifest.serializer()) ?: continue
            // manifest.id 必须 == 目录名（Ultra 侧用 manifest.id 拼 BASE 路径）。
            if (manifest.id != directory.name) continue
            // 两个分区的镜像必须存在且长度与 manifest 声明一致（size 也是判据，施工图 §7 #8）。
            if (!imagesMatchDeclaredSizes(directory, manifest)) continue
            val verification = BaselineRules.evaluate(
                manifest = manifest,
                device = device,
                corruptManifest = AtomicControlFile.verifySha(manifestFile) == ShaCheck.MISMATCH,
                shaForPartition = { name ->
                    ModeSwitchHashes.sha256(File(directory, "$name.img"))
                },
            )
            if (verification.state != BaselineState.PRESENT_OK) continue
            if (BaselineIdentity.PARTITIONS.any { name -> manifest.partitions.none { it.name == name } }) {
                continue
            }
            return manifest
        }
        return null
    }

    private fun imagesMatchDeclaredSizes(directory: File, manifest: BaselineManifest): Boolean =
        BaselineIdentity.PARTITIONS.all { name ->
            val partition = manifest.partitions.firstOrNull { it.name == name } ?: return@all false
            val image = File(directory, "$name.img")
            image.isFile && image.length() == partition.size
        }

    private fun fail(code: String, detail: String): BaselineProvisionOutcome.Failed =
        BaselineProvisionOutcome.Failed(code, detail)
}

// ---------------------------------------------------------------------------
// 第一层 b：**首次写盘前的现场抓取**（W4a，源②）—— root 只读 dd → App 暂存 → 真码判定
// ---------------------------------------------------------------------------

/**
 * 当前槽的只读探测结果（由 root 脚本产出；`getprop` / `blockdev --getsize64` 同一份事实）。
 *
 * [devices] 里的节点必须是白名单前缀 `/dev/block/by-name/` + 分区名 + 槽位拼出来的，
 * 不接受任何外部传入路径（与 `UltraRootModeSwitchClient` 的设备白名单同一条红线）。
 */
data class BaselineCaptureProbe(
    val slot: String,
    val firmware: String,
    val kernelRelease: String,
    val selinux: String,
    /** 分区 → 真实块设备节点（只含探测到的分区）。 */
    val devices: Map<String, String>,
    /** 分区 → `blockdev --getsize64`（>0；缺失/0 = 不能抓）。 */
    val sizes: Map<String, Long>,
) {
    fun partitions(): List<String> = devices.keys.filter { (sizes[it] ?: 0L) > 0L }
}

/**
 * 「本产品是否写过盘」的 root 侧证据 —— 抓取路径的**前置证明**。
 *
 * `PRE_FIRST_WRITE_CAPTURE` 的定义就是"本产品还没写过任何分区"，所以要抓取就必须先能证明
 * 这一点；证明不了就不猜（返回 `BASELINE_PROVENANCE_UNKNOWN`，让用户走导入/随包资产）。
 *
 * | 证据 | 含义 |
 * |---|---|
 * | `control/installed.json` 存在 | 本产品记过安装事实（写过盘） |
 * | `boot/takeover/<id>` 存在 | 本产品做过 boot 接管（必然写过） |
 * | `boot/work/<id>/journal.jsonl` 存在 | 本产品执行过切换事务（必然写过） |
 *
 * [modulePresent] 只作诊断：模块目录存在 ≠ "这个 boot 被本产品改过"（很多机型带着模块却是
 * 官方刷回来的），所以它**不参与** [neverWritten]。
 */
data class BaselineWriteMarkers(
    val installedJson: Boolean,
    val takeoverEntries: Int,
    val switchJournals: Int,
    val modulePresent: Boolean = false,
    val installerTransactions: Int = 0,
    val ultraEnvironmentPresent: Boolean = false,
) {
    val neverWritten: Boolean
        get() = !installedJson && takeoverEntries == 0 && switchJournals == 0 &&
            installerTransactions == 0 && !ultraEnvironmentPresent
}

/** 一次分区抓取的产物（**App 侧**重新算出的 size/sha，不信任 root 的输出）。 */
data class BaselineCapturedImage(
    val name: String,
    val file: File,
    val size: Long,
    val sha256: String,
)

/**
 * 分区抓取通道（root 只读 dd → App 可读暂存）。
 *
 * 三条实现约束：
 * 1. **只读方向**：`dd if=<分区> of=<App 暂存>`；本接口没有任何"写分区"的方法。
 * 2. **必须落到 App 能读的位置**：cleanliness 是纯 JVM 判定（`BootImageInspector` +
 *    `RamdiskInspector`），必须读到真实字节；8–200 MiB 的镜像**禁止**走 root 文本通道。
 * 3. **失败抛 [BaselineCaptureFault]**（带既有错误码），让 size/sha 不符保持可行动。
 */
interface BaselineLiveCapturePort {
    /** 只读探测；`null` = 探测失败（没有 root / 脚本失败）—— 不是"没有分区"。 */
    fun probe(): BaselineCaptureProbe?

    /** 把 [name] 分区完整只读复制到 [destination]，返回 App 侧重算的 size/sha。 */
    fun copy(name: String, destination: File): BaselineCapturedImage

    /** 写盘证据；`null` = 读不到（不知道 ⇒ 不许抓）。 */
    fun writeMarkers(): BaselineWriteMarkers?
}

/**
 * 生产实现：一次性 root 脚本（与 `RootScriptBaselineBridge` 同一个 [RootScriptRunner]，
 * 不新建 AIDL、不碰 `NativeBridge`）。
 *
 * 铁律（`HANDOFF-2026-11-01.md:255`）：dd **不向 stdout 写任何东西**（重定向到 `/dev/null`），
 * 只回显两行小结果（长度 / sha）；`dd` 的失败单独一条 `FAIL:<rc>`。
 * 抓取产物 `chown` 回 App uid + `restorecon`，否则 App 读不到（读不到 = 显式失败）。
 */
class RootScriptBaselineCapture(
    private val runner: RootScriptRunner,
    /** App uid：root 在 App 私有目录里创建的文件必须 chown 回来才可读。 */
    private val appUid: Int,
    private val controlRoot: String = ControlPaths.ROOT,
    private val moduleRoot: String = "/data/adb/maplesu",
) : BaselineLiveCapturePort {

    private fun quote(value: String): String = LiteImplantScripts.quote(value)

    override fun probe(): BaselineCaptureProbe? = runCatching {
        val result = runner.run(probeScript())
        if (result.code != 0) return null
        parseProbe(result.out)
    }.getOrNull()

    override fun copy(name: String, destination: File): BaselineCapturedImage {
        if (!PARTITION_NAMES.contains(name)) {
            throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_READ_FAILED, "$name: not a captureable partition",
            )
        }
        val probed = probe()
            ?: throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_READ_FAILED, "partition probe failed",
            )
        val device = probed.devices[name]
            ?: throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_READ_FAILED, "$name: device node not found",
            )
        if (!device.startsWith(DEVICE_PREFIX) || !DEVICE.matches(device)) {
            throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_READ_FAILED, "$name: invalid device node $device",
            )
        }
        val expected = probed.sizes[name] ?: 0L
        val parent = destination.parentFile
        if (parent != null && !parent.isDirectory && !parent.mkdirs() && !parent.isDirectory) {
            throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_WRITE_FAILED, parent.absolutePath,
            )
        }
        val result = runner.run(copyScript(device, destination))
        val parsed = parseCopy(result.out)
        if (result.code != 0 || parsed == null) {
            throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_READ_FAILED,
                "$name: dd rc=${result.code} ${result.out.take(160).replace('\n', ' ')}",
            )
        }
        if (!destination.isFile) {
            throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_READ_FAILED, "$name: image not readable by app",
            )
        }
        if (expected > 0L && destination.length() != expected) {
            throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_SIZE_MISMATCH,
                "$name: dd=${destination.length()} partition=$expected",
            )
        }
        if (parsed.size != destination.length()) {
            throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_SIZE_MISMATCH,
                "$name: root len=${parsed.size} app len=${destination.length()}",
            )
        }
        // ★ App 自己重算摘要（root 的输出只是交叉验证，不是信任源）。
        val actual = BaselineAtomicFiles.sha256(destination)
        if (!actual.equals(parsed.sha256, ignoreCase = true)) {
            throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_SHA_MISMATCH,
                "$name: root=${parsed.sha256} app=$actual",
            )
        }
        return BaselineCapturedImage(name, destination, destination.length(), actual)
    }

    override fun writeMarkers(): BaselineWriteMarkers? = runCatching {
        val result = runner.run(markersScript())
        if (result.code != 0) return null
        parseMarkers(result.out)
    }.getOrNull()

    internal fun probeScript(): String {
        val bin = "/system/bin"
        return buildString {
            appendLine("set -u")
            appendLine("SLOT=\$($bin/getprop ro.boot.slot_suffix 2>/dev/null)")
            appendLine("[ -n \"\$SLOT\" ] || SLOT=\$($bin/getprop ro.boot.slot 2>/dev/null)")
            appendLine("FW=\$($bin/getprop ro.build.display.id 2>/dev/null)")
            appendLine("KR=\$($bin/uname -r 2>/dev/null)")
            appendLine("echo \"SLOT:\$SLOT\"")
            appendLine("echo \"FW:\$FW\"")
            appendLine("echo \"KR:\$KR\"")
            appendLine("for n in boot init_boot; do")
            appendLine(
                "if [ -n \"\$SLOT\" ]; then d=\"$DEVICE_PREFIX\$n\$SLOT\"; " +
                    "else d=\"$DEVICE_PREFIX\$n\"; fi",
            )
            appendLine("if [ -e \"\$d\" ]; then")
            appendLine("z=\$($bin/blockdev --getsize64 \"\$d\" 2>/dev/null)")
            appendLine("[ -n \"\$z\" ] || z=\$($bin/stat -c %s \"\$d\" 2>/dev/null)")
            appendLine("echo \"PART:\$n:\$d:\$z\"")
            appendLine("fi")
            appendLine("done")
            appendLine("echo \"SELINUX:\$($bin/getenforce 2>/dev/null)\"")
            appendLine("echo '$MARK_PROBED'")
        }
    }

    internal fun copyScript(device: String, destination: File): String {
        val bin = "/system/bin"
        val target = destination.absolutePath
        return buildString {
            appendLine("set -u")
            appendLine("umask 077")
            appendLine("T=${quote("$target.part")}")
            appendLine("D=${quote(target)}")
            appendLine("$bin/rm -f \"\$T\"")
            appendLine("$bin/dd if=${quote(device)} of=\"\$T\" bs=1M 2>/dev/null")
            appendLine("rc=\$?")
            appendLine("if [ \"\$rc\" -ne 0 ]; then $bin/rm -f \"\$T\"; echo \"FAIL:\$rc\"; exit 3; fi")
            appendLine("$bin/sync")
            appendLine("$bin/mv -f \"\$T\" \"\$D\" || exit 4")
            appendLine("$bin/chmod 0600 \"\$D\" 2>/dev/null")
            appendLine("$bin/chown $appUid:$appUid \"\$D\" 2>/dev/null")
            appendLine("$bin/restorecon \"\$D\" 2>/dev/null")
            appendLine("echo \"LEN:\$($bin/wc -c < \"\$D\")\"")
            appendLine("echo \"SHA:\$($bin/sha256sum \"\$D\" 2>/dev/null | $bin/cut -d' ' -f1)\"")
            appendLine("echo '$MARK_COPIED'")
        }
    }

    internal fun markersScript(): String {
        val bin = "/system/bin"
        return buildString {
            appendLine("set -u")
            appendLine("C=${quote(controlRoot)}")
            appendLine("M=${quote(moduleRoot)}")
            appendLine("[ \"\$($bin/id -u)\" = 0 ] || exit 2")
            appendLine("for d in \"\$C\" \"\$C/control\" \"\$C/boot/takeover\" \"\$C/boot/work\" \"\$M\" \"\$M/installer\"; do")
            appendLine("[ ! -e \"\$d\" ] || { [ -d \"\$d\" ] && [ -r \"\$d\" ] && [ -x \"\$d\" ]; } || exit 3")
            appendLine("done")
            appendLine("n=0")
            appendLine("for d in \"\$C\"/boot/takeover/*; do [ -d \"\$d\" ] && n=\$((n + 1)); done")
            appendLine("echo \"TAKEOVER:\$n\"")
            appendLine("w=0")
            appendLine("for f in \"\$C\"/boot/work/*/journal.jsonl; do [ -f \"\$f\" ] && w=\$((w + 1)); done")
            appendLine("echo \"WORK:\$w\"")
            appendLine("if [ -e \"\$C/control/installed.json\" ]; then echo 'INSTALLED:1'; else echo 'INSTALLED:0'; fi")
            appendLine("if [ -d \"\$M\" ]; then echo 'MODULE:1'; else echo 'MODULE:0'; fi")
            appendLine("i=0")
            appendLine("for d in \"\$M\"/installer/*; do [ -e \"\$d\" ] && i=\$((i + 1)); done")
            appendLine("echo \"INSTALLER:\$i\"")
            appendLine("if [ -e /data/adb/maplesu_su_auth ]; then echo 'ULTRA:1'; else echo 'ULTRA:0'; fi")
            appendLine("echo '$MARK_MARKERS'")
        }
    }

    internal fun parseProbe(output: String): BaselineCaptureProbe? {
        if (output.lineSequence().none { it.trim() == MARK_PROBED }) return null
        var slot = ""
        var firmware = ""
        var kernelRelease = ""
        var selinux = ""
        val devices = LinkedHashMap<String, String>()
        val sizes = LinkedHashMap<String, Long>()
        for (line in output.lineSequence()) {
            when {
                line.startsWith("SLOT:") -> slot = line.removePrefix("SLOT:").trim()
                line.startsWith("FW:") -> firmware = line.removePrefix("FW:").trim()
                line.startsWith("KR:") -> kernelRelease = line.removePrefix("KR:").trim()
                line.startsWith("SELINUX:") -> selinux = line.removePrefix("SELINUX:").trim()
                line.startsWith("PART:") -> {
                    val parts = line.removePrefix("PART:").split(':')
                    if (parts.size == 3) {
                        val name = parts[0].trim()
                        val node = parts[1].trim()
                        val size = parts[2].trim().toLongOrNull() ?: 0L
                        if (name !in PARTITION_NAMES || name in devices || !node.startsWith(DEVICE_PREFIX) ||
                            !DEVICE.matches(node) || size <= 0L
                        ) return null
                        devices[name] = node
                        sizes[name] = size
                    } else return null
                }
            }
        }
        return BaselineCaptureProbe(slot, firmware, kernelRelease, selinux, devices, sizes)
    }

    internal fun parseCopy(output: String): BaselineCapturedImage? {
        if (output.lineSequence().none { it.trim() == MARK_COPIED }) return null
        var size = -1L
        var sha = ""
        for (line in output.lineSequence()) {
            when {
                line.startsWith("LEN:") -> size = line.removePrefix("LEN:").trim().toLongOrNull() ?: -1L
                line.startsWith("SHA:") -> {
                    val value = line.removePrefix("SHA:").trim()
                    if (SHA256_PATTERN.matches(value)) sha = value
                }
            }
        }
        if (size < 0L || sha.isEmpty()) return null
        // `file` 由调用方补（解析层不依赖真实路径，主机可测）。
        return BaselineCapturedImage("", File(""), size, sha)
    }

    internal fun parseMarkers(output: String): BaselineWriteMarkers? {
        if (output.lineSequence().none { it.trim() == MARK_MARKERS }) return null
        val fields = LinkedHashMap<String, Int>()
        val keys = setOf("INSTALLED", "TAKEOVER", "WORK", "MODULE", "INSTALLER", "ULTRA")
        for (line in output.lineSequence()) {
            val key = line.substringBefore(':')
            if (key !in keys) continue
            if (key in fields || ':' !in line) return null
            val value = line.substringAfter(':').trim().toIntOrNull() ?: return null
            if (value < 0 || (key in setOf("INSTALLED", "MODULE", "ULTRA") && value !in 0..1)) return null
            fields[key] = value
        }
        if (fields.keys != keys) return null
        return BaselineWriteMarkers(
            installedJson = fields.getValue("INSTALLED") == 1,
            takeoverEntries = fields.getValue("TAKEOVER"),
            switchJournals = fields.getValue("WORK"),
            modulePresent = fields.getValue("MODULE") == 1,
            installerTransactions = fields.getValue("INSTALLER"),
            ultraEnvironmentPresent = fields.getValue("ULTRA") == 1,
        )
    }

    private companion object {
        val PARTITION_NAMES: Set<String> = setOf("boot", "init_boot")
        const val DEVICE_PREFIX = "/dev/block/by-name/"
        val DEVICE = Regex("^/dev/block/by-name/[A-Za-z0-9_.-]{1,64}$")
        val SHA256_PATTERN = Regex("[0-9a-f]{64}")
        const val MARK_PROBED = "PROBED"
        const val MARK_COPIED = "COPIED"
        const val MARK_MARKERS = "MARKERS"
    }
}

/**
 * [BaselinePartitionSourcePort] 的抓取实现：`snapshot()` 就是"读一次当前槽"，
 * `readPartition()` 只是把已抓到的暂存文件搬给 materializer。
 *
 * 关键设计（为什么不是"先哈希一遍、再 dd 一遍"）：
 * - **只 dd 一次**：`snapshot()` 里把整分区 dd 到 App 暂存并**在 App 侧重算 sha**，
 *   这次读就是"live 事实"本身；`readPartition(name, dest)` 只做一次同盘 `rename`
 *   （失败退化为 copy），因此峰值空间 = 一份镜像（而不是两份）。
 * - **独立性靠三重交叉**：root 侧 `wc -c`/`sha256sum` ↔ App 侧重算 ↔ 写入基线目录后
 *   `BaselineAtomicFiles.copyVerified` 的流式回读。任何一环不符都是显式 `Failed`。
 * - **快照缓存**：`BaselineCaptureService.capture()` 与 materializer 各调一次 `snapshot()`，
 *   缓存保证第二次不会再 dd 一遍（否则每次切换 2×96–200 MiB）。
 */
class RootCapturedPartitionSource(
    private val capture: BaselineLiveCapturePort,
    private val deviceFacts: () -> DeviceBootFacts,
    /** App 私有暂存目录（每次抓取前清空重建）。 */
    private val stagingRoot: File,
    /** 只抓这些分区（默认 boot，探测到 init_boot 才抓它）。 */
    private val candidates: List<String> = listOf("boot", "init_boot"),
) : BaselinePartitionSourcePort {

    private var snapshotCache: BaselineDeviceSnapshot? = null
    private val staged = LinkedHashMap<String, BaselineCapturedImage>()

    @Synchronized
    override fun snapshot(): BaselineDeviceSnapshot {
        snapshotCache?.let { return it }
        val device = deviceFacts()
        if (device.slot.isBlank() || device.firmware.isBlank() || device.kernelRelease.isBlank()) {
            throw BaselineCaptureFault(
                BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
                "device facts incomplete: slot=${device.slot} firmware=${device.firmware} " +
                    "kernelRelease=${device.kernelRelease}",
            )
        }
        val probed = capture.probe() ?: throw BaselineCaptureFault(
            BaselineCaptureCodes.CAPTURE_READ_FAILED, "partition probe failed",
        )
        // root 侧与 App 侧的设备事实必须一致：不一致就说明"读的是另一个槽/另一个固件"，
        // 抓到的东西不能当本机基线（宁可显式 STALE，也不写一条永远对不上的基线）。
        if (probed.firmware.isNotEmpty() && probed.firmware != device.firmware) {
            throw BaselineCaptureFault(
                BaselineErrors.BASELINE_STALE,
                "firmware: root=${probed.firmware} app=${device.firmware}",
            )
        }
        if (probed.kernelRelease.isNotEmpty() && probed.kernelRelease != device.kernelRelease) {
            throw BaselineCaptureFault(
                BaselineErrors.BASELINE_STALE,
                "kernelRelease: root=${probed.kernelRelease} app=${device.kernelRelease}",
            )
        }
        if (probed.slot.isNotEmpty() && probed.slot != device.slot) {
            throw BaselineCaptureFault(
                BaselineErrors.BASELINE_STALE, "slot: root=${probed.slot} app=${device.slot}",
            )
        }
        stagingRoot.deleteRecursively()
        if (!stagingRoot.mkdirs() && !stagingRoot.isDirectory) {
            throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_WRITE_FAILED, stagingRoot.absolutePath,
            )
        }
        val partitions = LinkedHashMap<String, BaselinePartitionFacts>()
        for (name in candidates) {
            if (probed.devices[name] == null) {
                if (name == "boot") {
                    throw BaselineCaptureFault(
                        BaselineCaptureCodes.CAPTURE_READ_FAILED, "boot: device node not found",
                    )
                }
                continue
            }
            val image = capture.copy(name, File(stagingRoot, "$name.img"))
            if (image.size != (probed.sizes[name] ?: image.size)) {
                throw BaselineCaptureFault(
                    BaselineCaptureCodes.CAPTURE_SIZE_MISMATCH,
                    "$name: captured=${image.size} partition=${probed.sizes[name]}",
                )
            }
            staged[name] = image
            partitions[name] = BaselinePartitionFacts(name, image.size, image.sha256)
        }
        if (partitions.isEmpty()) {
            throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_READ_FAILED, "no partition captured",
            )
        }
        val snapshot = BaselineDeviceSnapshot(
            slot = device.slot,
            firmware = device.firmware,
            kernelRelease = device.kernelRelease,
            selinux = probed.selinux,
            partitions = partitions,
            // vbmeta 只作记录：本路径不做 vbmeta 读取（不猜 present，也不编造摘要）。
            vbmeta = null,
        )
        snapshotCache = snapshot
        return snapshot
    }

    @Synchronized
    override fun readPartition(name: String, destination: File): BaselinePartitionRead {
        val image = staged[name] ?: throw BaselineCaptureFault(
            BaselineCaptureCodes.CAPTURE_READ_FAILED, "$name: not captured",
        )
        val parent = destination.parentFile
        if (parent != null && !parent.isDirectory && !parent.mkdirs() && !parent.isDirectory) {
            throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_WRITE_FAILED, parent.absolutePath,
            )
        }
        if (!moveInto(image.file, destination)) {
            // 跨文件系统/权限异常时的退路：整份复制（仍要重新算摘要）。
            runCatching { image.file.copyTo(destination, overwrite = true) }.getOrElse {
                throw BaselineCaptureFault(
                    BaselineCaptureCodes.CAPTURE_WRITE_FAILED, "$name: ${it.message.orEmpty()}",
                )
            }
        }
        val actual = BaselineAtomicFiles.sha256(destination)
        if (!actual.equals(image.sha256, ignoreCase = true)) {
            throw BaselineCaptureFault(
                BaselineCaptureCodes.CAPTURE_SHA_MISMATCH,
                "$name: staged=${image.sha256} dest=$actual",
            )
        }
        return BaselinePartitionRead(name, destination.length(), actual)
    }

    private fun moveInto(source: File, destination: File): Boolean = runCatching {
        try {
            java.nio.file.Files.move(
                source.toPath(), destination.toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
            java.nio.file.Files.move(
                source.toPath(), destination.toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
            )
        }
        destination.isFile
    }.getOrDefault(false)
}

/**
 * 抓取路径的 patch 证据：**只认「本产品从未写过盘」这一个正面证明**，其余一律"未知"（不猜）。
 *
 * 与 `ControlPlaneBaselinePatchEvidence`（只读 `installed.json`，缺失即 `readable=false`）的差别：
 * 后者的数据源当前没有生产者（`installed.json` 全仓无写入方），`Missing` 一律阻断 ⇒ 抓取路径
 * 永远停在 `BASELINE_PROVENANCE_UNKNOWN`。这里把 `Missing` 拆成两种：
 * - **没有任何写盘证据**（`installed.json` / takeover / 切换日志全无）→ 正面证据 `readable=true`；
 * - 有写盘证据 → `readable=false`（真的不知道这个 boot 是否已被本产品改过），绝不猜"干净"。
 *
 * 残余风险（已写入交付报告）：内核级 patch 若没有控制面记录，ramdisk 扫描看不到 —— 这类机型
 * 仍应使用随包 stock 资产（源③）或用户导入的原厂镜像。
 */
fun capturePatchEvidence(markers: BaselineWriteMarkers?): BaselinePatchEvidence {
    if (markers == null) {
        return BaselinePatchEvidence(false, null, null, "write markers unreadable")
    }
    if (!markers.neverWritten) {
        return BaselinePatchEvidence(
            false, null, null,
            "control plane records an earlier write: installed=${markers.installedJson} " +
                "takeover=${markers.takeoverEntries} journals=${markers.switchJournals} " +
                "installer=${markers.installerTransactions} ultra=${markers.ultraEnvironmentPresent}",
            ultraKernelMarker = markers.ultraEnvironmentPresent,
            priorWriteRecorded = true,
        )
    }
    return BaselinePatchEvidence(
        readable = true,
        liteKernelMarker = false,
        ksuUapi = null,
        detail = "never-written:" + if (markers.modulePresent) "module-present" else "module-absent",
    )
}

// ---------------------------------------------------------------------------
// 第二层（生产）：App 进程 → 控制面的 root 发布桥
// ---------------------------------------------------------------------------

/**
 * 控制面基线目录的只读视图（每条 = 一个基线目录的 manifest + 两个镜像的 size/sha）。
 * 由 root 脚本产出，主机测试可直接构造。
 */
data class BaselineControlPlaneEntry(
    val id: String,
    /** `manifest.json` 原文（canonical JSON 是单行）。 */
    val manifestJson: String,
    /** root 侧算出的 `manifest.json` 自身 sha256（空 = 没算出来）。 */
    val manifestSha256: String = "",
    /** `manifest.json.sha256` 兄弟文件的裸 hex（空 = 文件缺失/为空）。 */
    val shaFile: String = "",
    /** 分区 → 实际镜像 sha256（缺失 = 该分区镜像不存在）。 */
    val imageSha256: Map<String, String> = emptyMap(),
    /** 分区 → 实际镜像字节数。 */
    val imageSize: Map<String, Long> = emptyMap(),
)

/**
 * 「把一份本地基线发布进控制面」的通道。
 *
 * 只有 root 侧实现能写 0700 的 `/data/adb/maplesu-workmode`；主机测试注入
 * 本地目录 fake（复制即可），从而端到端验证"staging → 发布 → 从控制面复核"整条编排。
 */
interface BaselineControlPlaneBridge {
    /** 控制面现有基线（只读）；`null` = 读不到（无 root/无权限/脚本失败），不是"没有基线"。 */
    fun probe(): List<BaselineControlPlaneEntry>?

    /**
     * 把 [localDirectory] 发布成 `boot/baseline/<id>`。
     *
     * 实现必须在 root 侧**自己复核**两个镜像的 sha256（等于 [expectedSha256]）后才 `mv` 到位；
     * 任一步失败返回 false（不得留下半成品目录）。
     */
    fun publish(id: String, localDirectory: File, expectedSha256: Map<String, String>): Boolean
}

/**
 * 生产实现：root 脚本（`cp -a` → `chown 0:0` → `chmod 0700/0600` → sha 复核 → `mv`）。
 *
 * 暂存目录放在 `ControlPaths.TMP`（与 `boot/baseline` 同一文件系统 ⇒ `mv` 是原子 rename），
 * **刻意不**放 `boot/baseline/.tmp-*`：那些名字也匹配 `BASELINE_ID`，会挤掉
 * `UltraRootModeSwitchClient` 的 16 个候选（施工图 §3.4-4）。
 */
class RootScriptBaselineBridge(
    private val runner: RootScriptRunner,
    private val controlRoot: String = ControlPaths.ROOT,
    private val temporaryRoot: String = ControlPaths.TMP,
    private val originalsRoot: String = "${InstallerPending.MODE_SWITCH_RECOVERY_ROOT}/originals",
    private val deviceSlot: (() -> String)? = null,
) : BaselineControlPlaneBridge {

    private val baselineRoot: String get() = "$controlRoot/boot/baseline"

    private fun quote(value: String): String = LiteImplantScripts.quote(value)

    override fun probe(): List<BaselineControlPlaneEntry>? = runCatching {
        val result = runner.run(probeScript())
        if (result.code != 0) return null
        val existing = parseProbe(result.out) ?: return null
        val slot = deviceSlot?.invoke() ?: return existing
        if (slot !in setOf("", "_a", "_b")) return null
        val saved = runner.run(probeScript(originalsRoot))
        if (saved.code != 0) return null
        val mirrors = parseProbe(saved.out) ?: return null
        var restored = false
        for (entry in mirrors) {
            if (existing.any { it.id == entry.id }) continue
            val manifest = decodeBaselineManifest(entry.manifestJson) ?: continue
            if (reusableBaselineEntry(listOf(entry), DeviceBootFacts(slot, manifest.firmware, manifest.kernelRelease),
                    entry.id, requireInitBoot = false) == null) continue
            val recovered = runner.run(restoreMirrorScript(entry, manifest))
            if (recovered.code != 0 || recovered.out.lineSequence().none { it == "RECOVERED:${entry.id}" }) return null
            restored = true
        }
        if (!restored) return existing
        val recovered = runner.run(probeScript())
        if (recovered.code == 0) parseProbe(recovered.out) else null
    }.getOrNull()

    override fun publish(
        id: String,
        localDirectory: File,
        expectedSha256: Map<String, String>,
    ): Boolean = runCatching {
        if (!localDirectory.isDirectory) return false
        if (!BaselineIdentity.isValidId(id) || id == "." || id == "..") return false
        // 只要求 boot（抓取路径可能没有独立 init_boot：A-only / 早期 GKI 机型只有 boot）。
        val boot = expectedSha256["boot"] ?: return false
        if (!SHA256_PATTERN.matches(boot)) return false
        if (expectedSha256.any { (name, sha) -> name !in BaselineIdentity.PARTITIONS || !SHA256_PATTERN.matches(sha) }) return false
        val destination = "$baselineRoot/$id"
        val temporary = "$temporaryRoot/baseline-$id-${System.nanoTime()}"
        val result = runner.run(
            publishScript(localDirectory, temporary, destination, expectedSha256, id),
        )
        result.code == 0 && result.out.contains("PUBLISHED:$id")
    }.getOrDefault(false)

    internal fun probeScript(root: String = baselineRoot): String {
        val bin = "/system/bin"
        return buildString {
            appendLine("set -u")
            appendLine("B=${quote(root)}")
            appendLine(noLinksFunction())
            appendLine("no_links \"\$B\" || exit 3")
            appendLine("if [ -d \"\$B\" ]; then")
            appendLine("for d in \"\$B\"/*; do")
            appendLine("[ -d \"\$d\" ] && [ ! -L \"\$d\" ] || continue")
            appendLine("n=\${d##*/}")
            appendLine("printf 'ID:%s\\n' \"\$n\"")
            appendLine("for p in boot init_boot; do")
            appendLine("f=\"\$d/\$p.img\"")
            appendLine("if [ -f \"\$f\" ] && [ ! -L \"\$f\" ]; then")
            appendLine("s=\$($bin/sha256sum \"\$f\" 2>/dev/null | $bin/cut -d' ' -f1)")
            appendLine("z=\$($bin/stat -c %s \"\$f\" 2>/dev/null || $bin/wc -c < \"\$f\")")
            appendLine("printf 'IMG:%s:%s:%s\\n' \"\$p\" \"\$s\" \"\$z\"")
            appendLine("fi")
            appendLine("done")
            appendLine("if [ -f \"\$d/manifest.json\" ] && [ ! -L \"\$d/manifest.json\" ] && [ ! -L \"\$d/manifest.json.sha256\" ]; then")
            appendLine("s=\$($bin/sha256sum \"\$d/manifest.json\" 2>/dev/null | $bin/cut -d' ' -f1)")
            appendLine("printf 'MSHA:%s\\n' \"\$s\"")
            appendLine(
                "printf 'SHAFILE:'; $bin/head -c 80 \"\$d/manifest.json.sha256\" 2>/dev/null " +
                    "| $bin/tr -d '\\r\\n'; printf '\\n'",
            )
            appendLine(
                "printf 'MAN:'; $bin/cat \"\$d/manifest.json\" 2>/dev/null | $bin/head -c 65536; printf '\\n'",
            )
            appendLine("printf 'END:%s\\n' \"\$n\"")
            appendLine("fi")
            appendLine("done")
            appendLine("fi")
            appendLine("printf '$MARK_LISTED\\n'")
        }
    }

    private fun restoreMirrorScript(entry: BaselineControlPlaneEntry, manifest: BaselineManifest): String = buildString {
        val bin = "/system/bin"
        appendLine("set -eu; umask 077")
        appendLine("SRC=${quote("$originalsRoot/${entry.id}")}")
        appendLine("DST=${quote("$baselineRoot/${entry.id}")}")
        appendLine("TMP=${quote("$temporaryRoot/recover-${entry.id}-${System.nanoTime()}")}")
        appendLine(noLinksFunction())
        appendLine("no_links \"\$SRC\" && no_links \"\$DST\" && no_links \"\$TMP\" || exit 3")
        appendLine("[ ! -e \"\$DST\" ] && [ ! -L \"\$DST\" ] || exit 7")
        appendLine("trap '$bin/rm -rf \"\$TMP\"' EXIT")
        appendLine("verify_saved() {")
        appendLine("d=\$1; [ -d \"\$d\" ] && [ ! -L \"\$d\" ] || return 1")
        appendLine("[ -f \"\$d/manifest.json\" ] && [ ! -L \"\$d/manifest.json\" ] && [ -f \"\$d/manifest.json.sha256\" ] && [ ! -L \"\$d/manifest.json.sha256\" ] || return 1")
        appendLine("[ \"\$($bin/sha256sum \"\$d/manifest.json\" | $bin/cut -d' ' -f1)\" = ${quote(entry.manifestSha256)} ] || return 1")
        appendLine("[ \"\$($bin/cat \"\$d/manifest.json.sha256\" | $bin/tr -d '\\r\\n ')\" = ${quote(entry.manifestSha256)} ] || return 1")
        manifest.partitions.forEach { part ->
            appendLine("[ -f \"\$d/${part.name}.img\" ] && [ ! -L \"\$d/${part.name}.img\" ] || return 1")
            appendLine("[ \"\$($bin/stat -c %s \"\$d/${part.name}.img\")\" = ${quote(part.size.toString())} ] || return 1")
            appendLine("[ \"\$($bin/sha256sum \"\$d/${part.name}.img\" | $bin/cut -d' ' -f1)\" = ${quote(part.sha256)} ] || return 1")
        }
        appendLine("}")
        appendLine("verify_saved \"\$SRC\" || exit 8")
        appendLine("$bin/mkdir -p ${quote(baselineRoot)} ${quote(temporaryRoot)}")
        appendLine("$bin/mkdir \"\$TMP\"")
        (listOf("manifest.json", "manifest.json.sha256") + manifest.partitions.map { "${it.name}.img" }).forEach { name ->
            appendLine("$bin/cp -p \"\$SRC/$name\" \"\$TMP/$name\"")
            appendLine("$bin/chmod 0600 \"\$TMP/$name\"")
        }
        appendLine("$bin/chmod 0700 \"\$TMP\"")
        appendLine("$bin/chown -R 0:0 \"\$TMP\" 2>/dev/null || true")
        appendLine("$bin/restorecon -R \"\$TMP\" 2>/dev/null || true")
        appendLine("verify_saved \"\$TMP\" || exit 8")
        appendLine("[ ! -e \"\$DST\" ] && [ ! -L \"\$DST\" ] || exit 7")
        appendLine("$bin/sync; $bin/mv \"\$TMP\" \"\$DST\"; $bin/sync")
        appendLine("printf 'RECOVERED:${entry.id}\\n'")
    }

    private fun noLinksFunction(): String = """
        no_links() (
          p=${'$'}1
          while [ "${'$'}p" != / ]; do
            [ ! -L "${'$'}p" ] || return 1
            n=${'$'}{p%/*}; [ "${'$'}n" != "${'$'}p" ] || break
            p=${'$'}n; [ -n "${'$'}p" ] || p=/
          done
        )
    """.trimIndent()

    /**
     * 发布脚本：`cp -a` → `chown 0:0` → `chmod 0700/0600` → **逐分区** sha 复核 → `mv` 原子落位。
     *
     * 分区集合由 [expectedSha256] 决定（不是硬编码 boot+init_boot）：只有 `boot` 的机型
     * （A-only / 早期 GKI）抓出来的基线也必须能发布，否则"适配所有机型"在最后一步失败。
     */
    internal fun publishScript(
        localDirectory: File,
        temporary: String,
        destination: String,
        expectedSha256: Map<String, String>,
        id: String,
    ): String {
        val bin = "/system/bin"
        return buildString {
            appendLine("set -eu")
            appendLine("umask 077")
            appendLine("SRC=${quote(localDirectory.absolutePath)}")
            appendLine("TMP=${quote(temporary)}")
            appendLine("DST=${quote(destination)}")
            appendLine("ORIGINALS=${quote(originalsRoot)}")
            appendLine("MIRROR=\"\$ORIGINALS/$id\"")
            appendLine("MTMP=\"\$ORIGINALS/.$id.${System.nanoTime()}.tmp\"")
            appendLine("if [ -e \"\$DST\" ]; then $bin/printf 'EXISTS\\n'; exit 7; fi")
            appendLine("trap '$bin/rm -rf \"\$TMP\" \"\$MTMP\"' EXIT")
            appendLine("private_root() (")
            appendLine("p=\$1")
            appendLine("while [ \"\$p\" != / ]; do")
            appendLine("[ ! -L \"\$p\" ] && { [ ! -e \"\$p\" ] || [ -d \"\$p\" ]; } || return 1")
            appendLine("n=\${p%/*}; [ \"\$n\" != \"\$p\" ] || break; p=\$n; [ -n \"\$p\" ] || p=/")
            appendLine("done")
            appendLine("$bin/mkdir -p \"\$1\" && $bin/chmod 0700 \"\$1\"")
            appendLine(")")
            appendLine("private_root ${quote(originalsRoot.substringBeforeLast('/'))} && private_root \"\$ORIGINALS\" || exit 10")
            appendLine("verify_saved() {")
            appendLine("d=\$1; [ -d \"\$d\" ] && [ ! -L \"\$d\" ] || return 1")
            appendLine("[ -f \"\$d/manifest.json\" ] && [ ! -L \"\$d/manifest.json\" ] && [ -f \"\$d/manifest.json.sha256\" ] || return 1")
            appendLine("m=\$($bin/sha256sum \"\$d/manifest.json\" | $bin/cut -d' ' -f1)")
            appendLine("[ \"\$m\" = \"\$($bin/cat \"\$d/manifest.json.sha256\" | $bin/tr -d '\\r\\n ')\" ] || return 1")
            for ((name, sha) in expectedSha256.toSortedMap()) {
                appendLine("[ -f \"\$d/$name.img\" ] && [ ! -L \"\$d/$name.img\" ] || return 1")
                appendLine("[ \"\$($bin/stat -c %s \"\$d/$name.img\")\" = ${quote(File(localDirectory, "$name.img").length().toString())} ] || return 1")
                appendLine("[ \"\$($bin/sha256sum \"\$d/$name.img\" | $bin/cut -d' ' -f1)\" = ${quote(sha)} ] || return 1")
            }
            appendLine("}")
            appendLine("$bin/rm -rf \"\$TMP\"")
            appendLine("$bin/mkdir -p \"\$TMP\" ${quote(baselineRoot)}")
            appendLine("$bin/cp -a \"\$SRC\"/. \"\$TMP\"/")
            appendLine("$bin/chown -R 0:0 \"\$TMP\" 2>/dev/null || true")
            appendLine("$bin/find \"\$TMP\" -type d -exec $bin/chmod 0700 {} + 2>/dev/null || true")
            appendLine("$bin/find \"\$TMP\" -type f -exec $bin/chmod 0600 {} + 2>/dev/null || true")
            // 标签按控制面策略重打（P7 §4.2 的 root 侧清单）；失败不阻断（多数设备无自定义策略）。
            appendLine("$bin/restorecon -R \"\$TMP\" 2>/dev/null || true")
            for ((name, sha) in expectedSha256.toSortedMap()) {
                if (!SHA256_PATTERN.matches(sha)) continue
                appendLine(
                    "if [ \"\$($bin/sha256sum \"\$TMP/$name.img\" 2>/dev/null | $bin/cut -d' ' -f1)\"" +
                        " != ${quote(sha)} ]; then $bin/rm -rf \"\$TMP\"; " +
                        "$bin/printf 'SHA_MISMATCH\\n'; exit 8; fi",
                )
            }
            appendLine("if [ ! -f \"\$TMP/manifest.json\" ]; then $bin/rm -rf \"\$TMP\"; exit 9; fi")
            appendLine("verify_saved \"\$TMP\" || exit 11")
            appendLine("if [ -e \"\$MIRROR\" ] || [ -L \"\$MIRROR\" ]; then")
            appendLine("verify_saved \"\$MIRROR\" || exit 12")
            // Reuse its exact immutable manifest when republishing after control-tree cleanup.
            appendLine("$bin/rm -rf \"\$TMP\"; $bin/mkdir -p \"\$TMP\"")
            appendLine("$bin/cp -a \"\$MIRROR\"/. \"\$TMP\"/")
            appendLine("else")
            appendLine("$bin/mkdir \"\$MTMP\"")
            appendLine("$bin/cp -a \"\$TMP\"/. \"\$MTMP\"/")
            appendLine("verify_saved \"\$MTMP\" || exit 12")
            appendLine("$bin/sync; $bin/mv \"\$MTMP\" \"\$MIRROR\"")
            appendLine("fi")
            appendLine("verify_saved \"\$TMP\" && verify_saved \"\$MIRROR\" || exit 12")
            appendLine("$bin/sync")
            appendLine("$bin/mv \"\$TMP\" \"\$DST\"")
            appendLine("$bin/sync")
            appendLine("$bin/printf 'PUBLISHED:$id\\n'")
        }
    }

    internal fun parseProbe(output: String): List<BaselineControlPlaneEntry>? {
        if (output.lineSequence().none { it.trim() == MARK_LISTED }) return null
        val entries = mutableListOf<BaselineControlPlaneEntry>()
        var id = ""
        var manifestJson: String? = null
        var manifestSha = ""
        var shaFile = ""
        val shas = LinkedHashMap<String, String>()
        val sizes = LinkedHashMap<String, Long>()

        fun flush() {
            val json = manifestJson
            if (id.isNotEmpty() && json != null) {
                entries += BaselineControlPlaneEntry(id, json, manifestSha, shaFile, shas.toMap(), sizes.toMap())
            }
            id = ""
            manifestJson = null
            manifestSha = ""
            shaFile = ""
            shas.clear()
            sizes.clear()
        }

        for (line in output.lineSequence()) {
            when {
                line.startsWith("ID:") -> {
                    flush()
                    id = line.removePrefix("ID:").trim()
                }
                line.startsWith("IMG:") -> {
                    val parts = line.removePrefix("IMG:").split(':')
                    if (parts.size >= 3) {
                        val name = parts[0].trim()
                        val sha = parts[1].trim()
                        val size = parts[2].trim().toLongOrNull() ?: -1L
                        if (name.isNotEmpty() && SHA256_PATTERN.matches(sha) && size >= 0L) {
                            shas[name] = sha
                            sizes[name] = size
                        }
                    }
                }
                line.startsWith("MSHA:") -> {
                    val value = line.removePrefix("MSHA:").trim()
                    manifestSha = if (SHA256_PATTERN.matches(value)) value else ""
                }
                line.startsWith("SHAFILE:") -> shaFile = line.removePrefix("SHAFILE:").trim()
                line.startsWith("MAN:") -> manifestJson = line.removePrefix("MAN:")
                line.startsWith("END:") -> flush()
            }
        }
        flush()
        return entries
    }

    private companion object {
        const val MARK_LISTED = "LISTED"
        val SHA256_PATTERN = Regex("[0-9a-f]{64}")
    }
}

/**
 * 生产编排：**App 进程**里建基线（有 `AssetManager` + 可写 App 私有暂存），再用 root 脚本发布到
 * 控制面，最后**从控制面**再复核一次（不复用 App 侧结论）。
 *
 * ⚠️ 2026-11-01 `55-asset-slim.md`：本类**已不在生产装配里**（随包资产被删除，
 * [productionBaselineProvisioner] 传 `stockFallback = null`）。它保留给两条将来路径：
 * ①重新随包某个固件的资产；②用户导入 OEM 镜像后的「解压 → 校验 → 发布」。
 * 主机测试仍直接构造它，所以这段编排（发布 + 控制面复核 + 空间前置）没有被弃测。
 *
 * 为什么必须走发布而不是直接写控制面：`/data/adb/maplesu-workmode` 是 0700 root，App 进程
 * 一个字节都写不进去；而基线必须落在控制面——Normal（SERVICE）侧的 `LocalInstallerGateway`
 * 与 Ultra（ULTRA_ROOT）侧的 `UltraRootModeSwitchClient` 都只从
 * `File(ControlPaths.ROOT, "boot/baseline")` 读。本波不允许改 AIDL/`ModeSwitchClient`，
 * 所以复用仓内既有做法（`RootScriptSnapshotBridge`：App 暂存 → root `cp -a` + `chown/chmod`
 * + sha 复核 + `mv`）。
 *
 * 空间：暂存（104 MiB）+ 控制面落位（104 MiB）⇒ 峰值约 +208 MiB（< 施工图 §4.4 的 312 MiB）。
 * 空间不足 → `SWITCH_SPACE_INSUFFICIENT`（既有码，UI 已有映射），**不在写盘途中失败**。
 */
class RootPublishingBaselineProvisioner(
    private val bridge: BaselineControlPlaneBridge,
    /** App 私有暂存根（建议 = `cacheDir/baseline-provision`）。 */
    private val stagingRoot: File,
    private val assets: StockAssetSource,
    private val deviceFacts: () -> DeviceBootFacts,
    private val freeBytes: () -> Long = { Long.MAX_VALUE },
    private val clock: Clock = WallClock,
    private val assetRoot: String = StockAssets.ROOT,
    private val minFreeBytes: Long = MIN_FREE_BYTES,
    private val idOf: (DeviceBootFacts) -> String = BaselineIdentity::fromDevice,
) : BaselineProvisioner {

    override fun ensureBaseline(): BaselineProvisionOutcome {
        val device = runCatching { deviceFacts() }.getOrNull()
            ?: return fail(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, "device facts unavailable")
        if (device.slot.isBlank() || device.firmware.isBlank() || device.kernelRelease.isBlank()) {
            return fail(
                BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
                "device facts incomplete: slot=${device.slot} firmware=${device.firmware} " +
                    "kernelRelease=${device.kernelRelease}",
            )
        }
        // ① 零 dd / 零写盘复用：**从控制面**读（消费者读的就是这里）。
        val existing = bridge.probe()
            ?: return fail(ModeSwitchCodes.ROOT_UNAVAILABLE, "baseline control plane unreadable")
        reusable(existing, device)?.let { (entry, manifest) ->
            return BaselineProvisionOutcome.Ready(entry.id, reused = true, provenance = manifest.provenance)
        }
        // ② 空间前置（在写任何字节之前）。
        val free = runCatching { freeBytes() }.getOrDefault(0L)
        if (free < minFreeBytes) {
            return fail(ModeSwitchCodes.SPACE_INSUFFICIENT, "free=$free required>=$minFreeBytes")
        }
        // ③ App 私有暂存里建一份完整基线（xz 解压 + cleanliness + manifest），不写分区。
        val staging = File(stagingRoot, "baseline-import")
        try {
            staging.deleteRecursively()
            if (!staging.mkdirs() && !staging.isDirectory) {
                return fail(BaselineCaptureCodes.CAPTURE_WRITE_FAILED, staging.absolutePath)
            }
            val facts: () -> DeviceBootFacts = { device }
            val materializer = StockBaselineMaterializer(
                assets = assets,
                deviceFacts = facts,
                clock = clock,
                assetRoot = assetRoot,
                stagingRoot = File(staging, "tmp"),
            )
            val store = FileBaselineStore(
                root = staging,
                deviceFacts = facts,
                clock = clock,
                materializer = materializer,
            )
            val staged = StockBaselineProvisioner(
                store = store,
                materializer = materializer,
                controlRoot = staging,
                deviceFacts = facts,
                idOf = idOf,
            ).ensureBaseline()
            if (staged is BaselineProvisionOutcome.Failed) return staged
            val ready = staged as BaselineProvisionOutcome.Ready
            val id = ready.id
            val localDirectory = File(staging, "boot/baseline/$id")
            val manifest = readManifest(File(localDirectory, "manifest.json"))
                ?: return fail(BaselineCaptureCodes.CAPTURE_READBACK_FAILED, "staged manifest unreadable")
            val expected = manifest.partitions
                .filter { it.name in BaselineIdentity.PARTITIONS }
                .associate { it.name to it.sha256 }
            if (expected.keys != BaselineIdentity.PARTITIONS.toSet()) {
                return fail(BaselineErrors.BASELINE_CORRUPT, "staged partitions=${expected.keys}")
            }
            // ④ 发布（root 侧自己再核一次镜像 sha）。
            if (!runCatching { bridge.publish(id, localDirectory, expected) }.getOrDefault(false)) {
                return fail(BaselineCaptureCodes.CAPTURE_WRITE_FAILED, "publish failed: $id")
            }
            // ⑤ 从控制面复核（不信 App 侧结论、也不信 publish 的返回值）。
            val after = bridge.probe()
                ?: return fail(BaselineCaptureCodes.CAPTURE_READBACK_FAILED, "control plane unreadable after publish")
            val (_, published) = reusable(after, device)?.takeIf { it.first.id == id }
                ?: return fail(BaselineCaptureCodes.CAPTURE_READBACK_FAILED, "published baseline not verified: $id")
            return BaselineProvisionOutcome.Ready(
                id = id,
                reused = false,
                provenance = published.provenance,
            )
        } catch (error: Throwable) {
            return fail(BaselineCaptureCodes.CAPTURE_WRITE_FAILED, error.javaClass.simpleName)
        } finally {
            runCatching { staging.deleteRecursively() }
        }
    }

    /** 控制面条目 → 可复用基线（判定口径与 [StockBaselineProvisioner.reusable] 完全一致）。 */
    internal fun reusable(
        entries: List<BaselineControlPlaneEntry>,
        device: DeviceBootFacts,
    ): Pair<BaselineControlPlaneEntry, BaselineManifest>? =
        reusableBaselineEntry(entries, device, idOf(device), requireInitBoot = true)

    private fun readManifest(file: File): BaselineManifest? {
        val raw = AtomicControlFile.readUtf8(file) ?: return null
        return ControlJsonCodec.decodeOrNull(raw, BaselineManifest.serializer())
    }

    private fun fail(code: String, detail: String): BaselineProvisionOutcome.Failed =
        BaselineProvisionOutcome.Failed(code, detail)

    companion object {
        /** 暂存 + 控制面落位（各 104 MiB）留 2 倍余量；不足 → `SWITCH_SPACE_INSUFFICIENT`。 */
        const val MIN_FREE_BYTES: Long = 256L * 1024 * 1024
    }
}

// ---------------------------------------------------------------------------
// 第一层 c：**抓取优先的编排**（W4a 的生产入口）
// ---------------------------------------------------------------------------

/**
 * 抓取优先的 provisioner：`① 复用 → ② 现场抓取 → ③ 随包资产（仅兜底）`。
 *
 * ③ 是**可选**的：[stockFallback] 默认 `null`。2026-11-01 `55-asset-slim.md` 之后生产装配
 * 就传 `null`（随包资产已删除），因此本构建的实际顺序是 ① → ②，②失败即显式失败。
 *
 * 与旧的 [RootPublishingBaselineProvisioner] 的关系：那个类只剩"③ 随包资产 + 发布"这一段职责，
 * 这里把它当作 [stockFallback] 组合进来（不再复制粘贴股票资产逻辑）。
 *
 * 为什么**不再要求机型 pin**：①/② 的输入只有"当前槽的真实字节"与设备事实，
 * 与 `assets/boot-stock/<firmware>/pins.json` 是否存在无关；随包资产只在
 * "抓不到 / 抓到的不能证明干净"时兜底（③）。
 *
 * 失败语义：任何一步失败都返回既有错误码，**且此时一个分区字节都还没写**（本类不写分区）；
 * 抓取专用码（`BASELINE_CAPTURE_*` / `BASELINE_UNCLEAN` / `BASELINE_PROVENANCE_UNKNOWN`）
 * 属于 [CAPTURE_FALLBACK_CODES] 时才会尝试③，空间不足不兜底（两条路都需要空间，早失败更诚实）。
 */
class CaptureFirstBaselineProvisioner(
    private val bridge: BaselineControlPlaneBridge,
    private val capture: BaselineLiveCapturePort,
    /** App 私有暂存根（`cacheDir/baseline-provision/capture`）。 */
    private val stagingRoot: File,
    private val deviceFacts: () -> DeviceBootFacts,
    /** 抓取证据（默认 = [capturePatchEvidence]；主机测试可注入固定证据）。 */
    private val evidenceOf: (BaselineWriteMarkers?) -> BaselinePatchEvidence = ::capturePatchEvidence,
    private val cleanliness: BaselineCleanlinessPort = RamdiskBaselineCleanliness(),
    /** ③ 随包 stock 资产；`null` = 本构建没有随包资产（抓取失败就真的失败）。 */
    private val stockFallback: BaselineProvisioner? = null,
    private val freeBytes: () -> Long = { Long.MAX_VALUE },
    private val clock: Clock = WallClock,
    private val minFreeBytes: Long = RootPublishingBaselineProvisioner.MIN_FREE_BYTES,
    private val idOf: (DeviceBootFacts) -> String = BaselineIdentity::fromDevice,
    private val notes: (String) -> Unit = {},
    /** Installer observations can supply topology without another root probe. */
    private val requiredPartitions: Set<String>? = null,
    private val installerRecovery: BaselineProvisioner? = null,
) : BaselineProvisioner {

    override fun ensureBaseline(): BaselineProvisionOutcome {
        val device = runCatching { deviceFacts() }.getOrNull()
            ?: return fail(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, "device facts unavailable")
        if (device.slot.isBlank() || device.firmware.isBlank() || device.kernelRelease.isBlank()) {
            return fail(
                BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
                "device facts incomplete: slot=${device.slot} firmware=${device.firmware} " +
                    "kernelRelease=${device.kernelRelease}",
            )
        }
        // ① 零 dd 复用：控制面里已存在且**校验通过**的基线（任意 provenance）直接交回。
        val existing = bridge.probe()
            ?: return fail(ModeSwitchCodes.ROOT_UNAVAILABLE, "baseline control plane unreadable")
        val partitions = requiredPartitions ?: capture.probe()?.devices?.keys
            ?: return fail(BaselineCaptureCodes.CAPTURE_READ_FAILED, "partition topology unavailable")
        if ("boot" !in partitions || partitions.any { it !in BaselineIdentity.PARTITIONS }) {
            return fail(BaselineCaptureCodes.CAPTURE_READ_FAILED, "invalid partition topology: $partitions")
        }
        reusable(existing, device, partitions)?.let { (entry, manifest) ->
            return BaselineProvisionOutcome.Ready(entry.id, reused = true, provenance = manifest.provenance)
        }
        // ② 首次写盘前现场抓取。
        val captured = captureNow(device, partitions)
        if (captured is BaselineProvisionOutcome.Ready) return captured
        var captureFailure = captured as BaselineProvisionOutcome.Failed
        if (captureFailure.code !in CAPTURE_FALLBACK_CODES) return captureFailure
        installerRecovery?.let { recovery ->
            val imported = runCatching { recovery.ensureBaseline() }.getOrElse {
                BaselineProvisionOutcome.Failed(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, it.javaClass.simpleName)
            }
            when (imported) {
                is BaselineProvisionOutcome.Ready -> return imported
                is BaselineProvisionOutcome.Failed -> captureFailure = captureFailure.copy(
                    detail = "${captureFailure.detail}; installer recovery: ${imported.detail}",
                )
            }
        }
        // ③ 随包 stock 资产（仅兜底）。
        val fallback = stockFallback ?: return captureFailure
        val stock = runCatching { fallback.ensureBaseline() }.getOrElse { error ->
            BaselineProvisionOutcome.Failed(
                BaselineCaptureCodes.CAPTURE_WRITE_FAILED, error.javaClass.simpleName,
            )
        }
        return when (stock) {
            is BaselineProvisionOutcome.Ready -> stock
            is BaselineProvisionOutcome.Failed -> BaselineProvisionOutcome.Failed(
                captureFailure.code,
                "capture: ${captureFailure.detail}; stock: ${stock.code} ${stock.detail}",
            )
        }
    }

    /** ②：root 只读抓取 → App 侧真码判定 → 发布到控制面 → 从控制面复核。 */
    private fun captureNow(device: DeviceBootFacts, partitions: Set<String>): BaselineProvisionOutcome {
        val free = runCatching { freeBytes() }.getOrDefault(0L)
        if (free < minFreeBytes) {
            return fail(ModeSwitchCodes.SPACE_INSUFFICIENT, "free=$free required>=$minFreeBytes")
        }
        val markers = runCatching { capture.writeMarkers() }.getOrNull()
        val proof = evidenceOf(markers)
        if (!proof.readable || proof.liteKernelMarker != false ||
            proof.ultraKernelMarker || proof.priorWriteRecorded
        ) {
            // 不猜：证据不足/有写盘迹象时不把当前 boot 当"刷写前纯净镜像"。
            return fail(
                BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
                "capture evidence: ${proof.detail}",
            )
        }
        val staging = File(stagingRoot, "baseline-capture")
        try {
            staging.deleteRecursively()
            if (!staging.mkdirs() && !staging.isDirectory) {
                return fail(BaselineCaptureCodes.CAPTURE_WRITE_FAILED, staging.absolutePath)
            }
            val facts: () -> DeviceBootFacts = { device }
            val source = RootCapturedPartitionSource(
                capture = capture,
                deviceFacts = facts,
                stagingRoot = File(staging, "images"),
            )
            val store = FileBaselineStore(
                root = staging,
                deviceFacts = facts,
                clock = clock,
                materializer = InstallerBaselineMaterializer(
                    source = source,
                    cleanliness = cleanliness,
                    evidence = BaselinePatchEvidencePort { proof },
                    clock = clock,
                    notes = notes,
                ),
            )
            val service = BaselineCaptureService(
                store = store,
                source = source,
                clock = clock,
                newBaselineId = BaselineIdentity::fromSnapshot,
                notes = notes,
            )
            when (val result = service.capture()) {
                is BaselineResult.Failed -> return fail(result.code, result.detail)
                is BaselineResult.Ok -> {
                    val id = result.manifest.id
                    val local = File(staging, "boot/baseline/$id")
                    val expected = result.manifest.partitions.associate { it.name to it.sha256 }
                    if (!expected.keys.containsAll(partitions)) {
                        return fail(BaselineErrors.BASELINE_CORRUPT, "partitions=${expected.keys}")
                    }
                    if (!runCatching { bridge.publish(id, local, expected) }.getOrDefault(false)) {
                        return fail(BaselineCaptureCodes.CAPTURE_WRITE_FAILED, "publish failed: $id")
                    }
                    val after = bridge.probe()
                        ?: return fail(
                            BaselineCaptureCodes.CAPTURE_READBACK_FAILED,
                            "control plane unreadable after publish",
                        )
                    val verified = reusable(after, device, partitions)?.takeIf { it.first.id == id }
                        ?: return fail(
                            BaselineCaptureCodes.CAPTURE_READBACK_FAILED,
                            "published capture not verified: $id",
                        )
                    return BaselineProvisionOutcome.Ready(
                        id = id, reused = false, provenance = verified.second.provenance,
                    )
                }
            }
        } catch (error: Throwable) {
            return fail(
                BaselineCaptureCodes.CAPTURE_WRITE_FAILED,
                error.javaClass.simpleName + ": " + error.message.orEmpty(),
            )
        } finally {
            runCatching { staging.deleteRecursively() }
        }
    }

    /** 与 [RootPublishingBaselineProvisioner.reusable] 同一口径；抓取基线允许只含 `boot`。 */
    internal fun reusable(
        entries: List<BaselineControlPlaneEntry>,
        device: DeviceBootFacts,
        partitions: Set<String> = setOf("boot"),
    ): Pair<BaselineControlPlaneEntry, BaselineManifest>? =
        reusableBaselineEntry(entries, device, idOf(device), requireInitBoot = "init_boot" in partitions)

    private fun fail(code: String, detail: String): BaselineProvisionOutcome.Failed =
        BaselineProvisionOutcome.Failed(code, detail)

    private companion object {
        /**
         * 这些抓取失败才值得试③（随包资产）。
         *
         * 不含 `SWITCH_SPACE_INSUFFICIENT`：两条路都要空间，早失败更诚实；
         * 不含 `SWITCH_ROOT_UNAVAILABLE`：没有 root 时连发布都做不到。
         */
        val CAPTURE_FALLBACK_CODES: Set<String> = setOf(
            BaselineErrors.BASELINE_CAPTURE_UNSUPPORTED,
            BaselineErrors.BASELINE_UNCLEAN,
            BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
            BaselineErrors.BASELINE_CORRUPT,
            BaselineCaptureCodes.CAPTURE_READ_FAILED,
            BaselineCaptureCodes.CAPTURE_SIZE_MISMATCH,
            BaselineCaptureCodes.CAPTURE_SHA_MISMATCH,
            BaselineCaptureCodes.CAPTURE_WRITE_FAILED,
            BaselineCaptureCodes.CAPTURE_READBACK_FAILED,
            BaselineCaptureCodes.AVB_TAIL_INVALID,
        )
    }
}

/**
 * 控制面条目 → 可复用基线（`StockBaselineProvisioner.reusable` 的控制面版本，唯一口径）。
 *
 * [requireInitBoot] 由本机分区拓扑决定，与基线来源无关；没有 init_boot 的机型允许只含 boot。
 * 槽位、manifest 与逐分区大小/摘要仍需匹配，运行时的内核和固件描述仅作记录。
 */
internal fun reusableBaselineEntry(
    entries: List<BaselineControlPlaneEntry>,
    device: DeviceBootFacts,
    expectedId: String,
    requireInitBoot: Boolean,
    allowUserSelected: Boolean = false,
): Pair<BaselineControlPlaneEntry, BaselineManifest>? {
    val ordered = entries.sortedWith(
        compareByDescending<BaselineControlPlaneEntry> { it.id == expectedId }.thenByDescending { it.id },
    )
    for (entry in ordered) {
        val manifest = decodeBaselineManifest(entry.manifestJson) ?: continue
        // manifest.id 必须 == 目录名（Ultra 侧用 manifest.id 拼 BASE 路径）。
        if (manifest.id != entry.id || !BaselineIdentity.isValidId(entry.id) || entry.id in setOf(".", "..") ||
            manifest.schema != BaselineManifest.SCHEMA) continue
        val shaPattern = Regex("[0-9a-fA-F]{64}")
        val actualManifestSha = Hashes.sha256Hex(entry.manifestJson)
        if (!shaPattern.matches(entry.shaFile) || !shaPattern.matches(entry.manifestSha256) ||
            !entry.shaFile.equals(entry.manifestSha256, ignoreCase = true) ||
            !actualManifestSha.equals(entry.manifestSha256, ignoreCase = true)
        ) continue
        if (manifest.partitions.map { it.name }.distinct().size != manifest.partitions.size) continue
        if (manifest.partitions.any { declared ->
                declared.name !in BaselineIdentity.PARTITIONS || declared.size <= 0L ||
                    !shaPattern.matches(declared.sha256) ||
                    entry.imageSize[declared.name] != declared.size ||
                    entry.imageSha256[declared.name]?.equals(declared.sha256, ignoreCase = true) != true
            }
        ) continue
        val needed = if (requireInitBoot) {
            BaselineIdentity.PARTITIONS
        } else {
            listOf("boot")
        }
        if (needed.any { name ->
                val declared = manifest.partitions.firstOrNull { it.name == name } ?: return@any true
                val size = entry.imageSize[name] ?: return@any true
                val sha = entry.imageSha256[name] ?: return@any true
                size != declared.size || !sha.equals(declared.sha256, ignoreCase = true)
            }
        ) {
            continue
        }
        val verification = BaselineRules.evaluate(
            manifest = manifest,
            device = device,
            corruptManifest = false,
            allowUserSelected = allowUserSelected,
            shaForPartition = { entry.imageSha256[it] },
        )
        if (verification.state != BaselineState.PRESENT_OK) continue
        if (needed.any { name -> manifest.partitions.none { it.name == name } }) continue
        return entry to manifest
    }
    return null
}

/** 控制面 manifest 解码（唯一入口：容忍多余字段、不容忍缺字段/类型错）。 */
internal fun decodeBaselineManifest(json: String): BaselineManifest? =
    ControlJsonCodec.decodeOrNull(json, BaselineManifest.serializer())

// ---------------------------------------------------------------------------
// 生产装配
// ---------------------------------------------------------------------------

/**
 * 生产 provisioner（只在 App 进程构造）：已有基线复用 → 首次写盘前现场抓取 →
 * 私有安装记录中的独立 pin 原件 → 与当前候选完整绑定的原件恢复。
 *
 * 原件恢复只接受匹配完整 base/candidate SHA、随包 spec 和正向重建结果的留存原件；
 * 缺少原件时，仅在原字节完整覆盖且完整镜像 SHA 和正向重建均吻合时逆向恢复。
 * 两条恢复路径仍经真实镜像 cleanliness 与发布回读校验，不写任何设备分区。
 *
 * 本构建已移除随包 stock 镜像（`55-asset-slim.md`），所以 `stockFallback = null`。
 * 可恢复的抓取失败会依次尝试上述恢复路径；全部失败后保留抓取失败码并附加恢复详情。
 *
 * 拿不到 `Context`/`AssetManager` 时也不返回 null（那会让 CTA 又变灰）：`cacheDir`
 * 只在真正执行（IO 线程）时才被访问，构造期不碰磁盘。
 *
 * 线程：本函数只构造对象，不做任何 IO；真正执行在 `ModeSwitchFacade.startSwitch` /
 * `installCommit` 的 IO 线程里（`Dispatchers.IO`）。
 */
fun productionBaselineProvisioner(
    context: Context,
    runner: RootScriptRunner,
    deviceFacts: () -> DeviceBootFacts,
    freeBytes: () -> Long,
    requiredPartitions: Set<String>? = null,
): BaselineProvisioner {
    val app = context.applicationContext ?: context
    val stagingRoot = File(app.cacheDir, "baseline-provision")
    val bridge = RootScriptBaselineBridge(runner, deviceSlot = { deviceFacts().slot })
    val capture = RootScriptBaselineCapture(runner, android.os.Process.myUid())
    val installerRecovery = InstallerRecoveryBaselineProvisioner(
        bridge = bridge,
        recovery = RootInstallerRecoverySource(runner, android.os.Process.myUid()),
        capture = capture,
        stagingRoot = File(stagingRoot, "installer-recovery"),
        deviceFacts = deviceFacts,
        trustedOriginalBoot = { image, release ->
            val flow = dev.maplesu.manager.ultrakernel.UltraKernelFlow(app)
            val selection = flow.selectForRelease(release)
            selection?.usable?.any { asset ->
                runCatching {
                    val inspected = flow.inspect(image, asset)
                    inspected.pristine && inspected.baseKernelPinned && inspected.kernelRelease == release
                }.getOrDefault(false)
            } == true
        },
        freeBytes = freeBytes,
        requiredPartitions = requiredPartitions,
    )
    val reconstructedRecovery = RecoveredOriginalBaselineProvisioner(
        bridge = bridge,
        capture = capture,
        stagingRoot = File(stagingRoot, "original-recovery"),
        deviceFacts = deviceFacts,
        recoverOriginal = { currentBoot, output ->
            dev.maplesu.manager.ultrakernel.UltraKernelOriginalRecovery(
                dev.maplesu.manager.ultrakernel.UltraKernelContextAssets(app),
            ).recover(
                currentBoot = currentBoot,
                receiptsDirectory = dev.maplesu.manager.compat.UltraStateStorage.flash(app.filesDir),
                originals = listOf(
                    File(app.filesDir, "images/imported.img"),
                    File(dev.maplesu.manager.compat.UltraStateStorage.flash(app.filesDir), "boot-current.img"),
                ),
                output = output,
            )?.image
        },
        freeBytes = freeBytes,
        requiredPartitions = requiredPartitions,
    )
    val recovery = BaselineProvisioner {
        when (val recovered = installerRecovery.ensureBaseline()) {
            is BaselineProvisionOutcome.Ready -> recovered
            is BaselineProvisionOutcome.Failed -> when (val reconstructed = reconstructedRecovery.ensureBaseline()) {
                is BaselineProvisionOutcome.Ready -> reconstructed
                is BaselineProvisionOutcome.Failed -> runCatching {
                    // The native resolver also checks an opposite-slot source. It publishes only
                    // verified originals; the app independently reads the resulting baseline back.
                    val result = InstallerServiceClient.withService(app) { it.inspectStockInstall("") }
                    val device = deviceFacts()
                    val entries = bridge.probe().orEmpty()
                    val publishedId = result.getString("baselineDirectory").orEmpty()
                        .takeIf { it.isNotBlank() }?.let { File(it).name }
                    val partitions = requiredPartitions ?: capture.probe()?.devices?.keys
                        ?: error("partition topology unavailable")
                    val verified = reusableBaselineEntry(entries, device, publishedId ?: BaselineIdentity.fromDevice(device),
                        requireInitBoot = "init_boot" in partitions)
                    if (verified != null) BaselineProvisionOutcome.Ready(verified.first.id, false, verified.second.provenance)
                    else BaselineProvisionOutcome.Failed(reconstructed.code,
                        reconstructed.detail + "; native original source: " + result.getString("error").orEmpty())
                }.getOrElse { reconstructed }
            }
        }
    }
    return CaptureFirstBaselineProvisioner(
        bridge = bridge,
        capture = capture,
        stagingRoot = File(stagingRoot, "capture"),
        deviceFacts = deviceFacts,
        // 随包 stock 镜像已移除；只保留上面有完整证明的原件恢复兜底。
        // 抓取与恢复都失败时返回明确失败，不发布缺少真实镜像的基线。
        stockFallback = null,
        freeBytes = freeBytes,
        requiredPartitions = requiredPartitions,
        installerRecovery = recovery,
    )
}
