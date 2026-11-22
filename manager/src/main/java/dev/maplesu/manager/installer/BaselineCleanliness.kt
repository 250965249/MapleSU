package dev.maplesu.manager.installer

import dev.maplesu.image.AvbFooter
import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.RamdiskInspector
import dev.maplesu.manager.workmode.control.ControlPlane
import dev.maplesu.manager.workmode.control.ControlRead
import dev.maplesu.manager.workmode.control.schema.InstalledFile
import dev.maplesu.manager.workmode.switch.BaselineErrors
import dev.maplesu.manager.workmode.switch.PatchMarkers
import java.io.File
import java.io.IOException

/**
 * clean 证明（P0 第 2 条）：A/B 补丁指纹不存在才允许当 baseline。
 *
 * 证据面（缺一即阻断，禁止猜）：
 * 1. 镜像结构：boot 容器可解析（header/compression/ramdisk 区段），init_boot ramdisk 可解析；
 * 2. ramdisk 无 KSU/MapleSU/7K 残留（`RamdiskInspector` 的 `hasInitReal/hasKernelsuKo/
 *    hasMaplesuId/hasSevenkKo/hasKsud/hasKsuConfig/hasDataAdbKsuPath`）；
 * 3. Lite 内核补丁 marker 与控制面 KSU UAPI 证据（[BaselinePatchEvidencePort]，读不到 = 未知 → 阻断）；
 * 4. AVB 尾部：若分区尾部 64B 是 `AVBf` footer，则 `original_image_size/vbmeta` 区间必须落在分区内，
 *    否则视为尾部被破坏（基线必须整分区保留尾部）。
 *
 * 例外（C1，2026-11-01）：`RamdiskInspector` 对 `ramdisk_size == 0` 报 `EMPTY_RAMDISK` 并置
 * `malformed=true`。stock GKI `boot.img` 就是这种情况 ⇒ **「无 ramdisk」既不算 corrupt 也不算
 * unclean**，只在 notes 里留 `no-ramdisk`。理由见该分支注释：不存在 ≠ 损坏，且没有可植入面。
 */
class RamdiskBaselineCleanliness : BaselineCleanlinessPort {
    override fun verify(
        images: Map<String, File>,
        expectedSizes: Map<String, Long>,
        evidence: BaselinePatchEvidence,
    ): BaselineCleanReport {
        val notes = ArrayList<String>()
        val avb = LinkedHashMap<String, Boolean>()
        var ksuInitReal = false
        var ksuKo = false
        var structuralFailure = ""
        var failureDetail = ""
        for ((name, file) in images.entries.sortedBy { it.key }) {
            val expected = expectedSizes[name]
            if (expected == null || expected <= 0 || !file.isFile || file.length() != expected) {
                return report(
                    BaselineErrors.BASELINE_CORRUPT,
                    "$name: image missing or not full length",
                    PatchMarkers(), avb, notes,
                )
            }
            try {
                BootImageInspector.inspect(file)
            } catch (error: IOException) {
                return report(
                    BaselineErrors.BASELINE_CORRUPT,
                    "$name: boot container malformed: ${error.message.orEmpty()}",
                    PatchMarkers(), avb, notes,
                )
            } catch (error: RuntimeException) {
                return report(
                    BaselineErrors.BASELINE_CORRUPT,
                    "$name: boot container malformed: ${error.message.orEmpty()}",
                    PatchMarkers(), avb, notes,
                )
            }
            val ramdisk = try {
                RamdiskInspector.inspect(file)
            } catch (error: IOException) {
                return report(
                    BaselineErrors.BASELINE_CORRUPT,
                    "$name: ramdisk unreadable: ${error.message.orEmpty()}",
                    PatchMarkers(), avb, notes,
                )
            } catch (error: RuntimeException) {
                return report(
                    BaselineErrors.BASELINE_CORRUPT,
                    "$name: ramdisk unreadable: ${error.message.orEmpty()}",
                    PatchMarkers(), avb, notes,
                )
            }
            if (ramdisk.malformed && !isEmptyRamdisk(ramdisk)) {
                return report(
                    BaselineErrors.BASELINE_CORRUPT,
                    "$name: ramdisk malformed: ${ramdisk.errorCode}",
                    PatchMarkers(), avb, notes,
                )
            }
            if (ramdisk.malformed) {
                // C1：`EMPTY_RAMDISK` 的语义是「该分区没有 ramdisk」，不是「ramdisk 损坏」。
                // stock GKI `boot.img` 的 `ramdisk_size` 可以为 0；
                // 把「不存在」当「损坏」是误判。把「不存在」当「干净」是正确的：没有 ramdisk
                // 就没有可被植入 KSU/MapleSU 残留的字节面（本分区比有 ramdisk 的分区更无可扫面）。
                // 真正的内核改动风险由整镜像 sha256 + 随包 pin 承担（`partitions[].sha256` /
                // `assets/boot-stock/**/pins.json`），不依赖 ramdisk 扫描；因此这里只记一条
                // 「无可扫描面」证据，继续走后续（AVB 尾部 / patch 证据 / 其它分区）判定。
                notes += "$name:no-ramdisk"
            }
            if (ramdisk.hasInitReal) ksuInitReal = true
            if (ramdisk.hasKernelsuKo || ramdisk.hasSevenkKo || ramdisk.hasMaplesuId ||
                ramdisk.hasKsud || ramdisk.hasKsuConfig || ramdisk.hasDataAdbKsuPath ||
                ramdisk.hasMagiskMarker || ramdisk.ksuRelatedPaths.isNotEmpty()
            ) {
                ksuKo = true
            }
            notes += "$name:form=${ramdisk.form().name}:compression=${ramdisk.compression}"
            val tailOk = avbTailPreserved(file)
            avb[name] = tailOk
            if (!tailOk && structuralFailure.isEmpty()) {
                structuralFailure = BaselineCaptureCodes.AVB_TAIL_INVALID
                failureDetail = "$name: AVB footer out of range"
            }
        }
        val liteMarker = evidence.liteKernelMarker == true
        val ksuKernel = (evidence.ksuUapi ?: 0) > 0
        val unknownEvidence = !evidence.readable || evidence.liteKernelMarker == null
        if (evidence.ultraKernelMarker || evidence.priorWriteRecorded) {
            return report(
                BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
                "prior installation evidence: ${evidence.detail}",
                PatchMarkers(liteMarker, ksuInitReal, ksuKo), avb, notes,
            )
        }
        if (structuralFailure.isNotEmpty()) {
            return report(structuralFailure, failureDetail,
                PatchMarkers(liteMarker, ksuInitReal, ksuKo), avb, notes)
        }
        if (unknownEvidence) {
            return report(
                BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
                "control-plane patch evidence unavailable: ${evidence.detail}",
                PatchMarkers(liteMarker, ksuInitReal, ksuKo), avb, notes,
            )
        }
        val markers = PatchMarkers(
            liteMarker = liteMarker,
            ksuInitReal = ksuInitReal,
            ksuKo = ksuKo || ksuKernel,
        )
        if (!markers.allAbsent) {
            return report(BaselineErrors.BASELINE_UNCLEAN, "patch fingerprints present: $markers",
                markers, avb, notes)
        }
        return BaselineCleanReport(
            clean = true,
            patchMarkers = markers,
            avbTailPreserved = avb,
            evidence = notes,
        )
    }

    /**
     * 该分区「没有 ramdisk」（结构合法、只是长度为 0），因此没有可扫描的植入面。
     * 只有 `EMPTY_RAMDISK` 享受这个分流；其它 `malformed` 仍是 `BASELINE_CORRUPT`。
     */
    private fun isEmptyRamdisk(ramdisk: RamdiskInspector.Report): Boolean =
        ramdisk.errorCode == EMPTY_RAMDISK_CODE

    private fun report(
        code: String,
        detail: String,
        markers: PatchMarkers,
        avb: Map<String, Boolean>,
        notes: List<String>,
    ) = BaselineCleanReport(
        clean = false,
        patchMarkers = markers,
        avbTailPreserved = avb,
        evidence = notes,
        code = code,
        detail = detail,
    )

    /**
     * AVB footer（最后 64B）区间自洽；无 `AVBf` → 没有需要保留的尾部（true）。
     *
     * 统一走 [AvbFooter]：avbtool 写的是**大端**，字段位于 `+0 magic / +4 major / +8 minor /
     * +12 original_image_size / +20 vbmeta_offset / +28 vbmeta_size`。旧实现按 `LE @ +8/+16/+24`
     * 读 —— 端序与偏移都错（`+8` 是 `version_minor`，`+16` 是 `original_image_size` 的高半字）。
     * 参考镜像上这些位置恰好都是 0，于是这段判断恒为 true，等于这道门从未真正生效；换一种
     * footer 布局（非零 version_minor / >4GiB 分区）就会把合法镜像误判成 `AVB_TAIL_INVALID`。
     */
    private fun avbTailPreserved(image: File): Boolean {
        val footer = try {
            AvbFooter.parse(image)
        } catch (error: IOException) {
            return false
        }
        return footer.invalidReason(image.length()).isEmpty()
    }

    private companion object {

        /** `RamdiskInspector` 对 `ramdisk_size <= 0` 返回的结构码（`RamdiskInspector.java:526`/`:597`）。 */
        const val EMPTY_RAMDISK_CODE = "EMPTY_RAMDISK"
    }
}

/**
 * 控制面 patch 证据的生产实现：只读 `installed.json`。
 * 读不到/损坏/缺失 → `readable=false`（未知 → cleanliness 阻断）。
 */
class ControlPlaneBaselinePatchEvidence(
    private val control: ControlPlane,
) : BaselinePatchEvidencePort {
    override fun read(): BaselinePatchEvidence {
        return when (val installed = control.readInstalled()) {
            is ControlRead.Ok -> evidenceOf(installed.value)
            is ControlRead.Missing ->
                BaselinePatchEvidence(false, null, null, "installed.json missing")
            is ControlRead.Corrupt ->
                BaselinePatchEvidence(false, null, null, installed.code)
            is ControlRead.Unreadable ->
                BaselinePatchEvidence(false, null, null, installed.code)
        }
    }

    private fun evidenceOf(installed: InstalledFile): BaselinePatchEvidence {
        val kernel = installed.kernel
        return BaselinePatchEvidence(
            readable = true,
            liteKernelMarker = kernel.liteMarker != null || kernel.liteCredentialSha256 != null,
            ksuUapi = kernel.ksuUapi,
            detail = "installed.json",
            ultraKernelMarker = installed.transports.ultra || installed.writtenBy == "A_ULTRA",
        )
    }
}
