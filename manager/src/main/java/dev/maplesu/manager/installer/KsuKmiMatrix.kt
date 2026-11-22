package dev.maplesu.manager.installer

import dev.maplesu.manager.ultrakernel.KernelSeries

/**
 * Normal（KSU / LKM）模式的 **KMI 矩阵 + 设备 KMI 检测 + 产物选择**（纯函数，无 Android 依赖）。
 *
 * 背景（本次多内核扩展）：`kernelsu.ko` 不再是单一 `android15-6.6`，而是每 KMI 一份
 * `lkm/<kmi>_kernelsu.ko`（payload 里一个 KMI 一条条目）。安装时必须：
 *
 * 1. 从设备事实（`uname -r` 的主/次版本 + `androidN` 标记，辅以 `ro.board.platform`
 *    交叉校验）**推导** KMI —— [KsuKmiDetector]；系统 SDK 仅记录为证据；
 * 2. 确认该 KMI 的 `.ko` 真的被打进了本次 APK（`ksud boot-info supported-kmis` 列出
 *    内嵌资产）—— [KsuKmiSelector]；
 * 3. 任一步不成立就**显式失败**（稳定机器码），绝不静默降级到别的 KMI 的 `.ko`。
 *
 * 边界：`android12-5.10` 在矩阵里（要构建产物），但**不走**独立 `init_boot` 直装
 * （android12 设备没有独立 init_boot），因此 `directInstall=false`；这点与
 * [KmiRule.supported] 的历史语义一致。`android13-5.10` / `android14-5.15`
 * 与其余 Normal KMI 一同构建；实际打包目录仍逐项确认对应产物，
 * 不使用相邻系列的 `.ko` 替代。
 *
 * **匹配口径 = 内核系列，不是 release 串**（用户口径 2026-11-01）：「6.6.50 与 6.6.89 都归 6.6」。
 * 所以 [KsuKmiDetector] 只做两件事：用 [KernelSeries.of] 取 `major.minor` 前缀、
 * 再取 `uname -r` 里的 `androidN` 标记；**从不**比较完整 release，也从不做子串匹配。
 * `androidN` 与内核系列是同一个 KMI 的两个坐标，两者都在才会得出 `androidN-<series>`。
 */
data class KsuKmiSpec(
    val kmi: String,
    val androidMajor: Int,
    val kernelSeries: String,
    val minSdk: Int,
    val maxSdk: Int,
    /** 是否有独立 `init_boot` 可直装（Normal 模式 v1 的唯一写入目标）。 */
    val directInstall: Boolean,
    val ddkImage: String,
) {
    val artifactName: String get() = KsuKmiMatrix.artifactName(kmi)
}

object KsuKmiMatrix {
    const val DDK_RELEASE = "20260828"

    /**
     * 唯一顺序权威（与 `third_party/kernelsu/scripts/ksu_common.py:KMI_MATRIX` 一致，
     * 也与 Normal CI matrix 的 8 个 leg 一致）。
     */
    val ENTRIES: List<KsuKmiSpec> = listOf(
        spec("android12-5.10", 12, "5.10", 31, 32, directInstall = false),
        spec("android13-5.10", 13, "5.10", 33, 33, directInstall = true),
        spec("android13-5.15", 13, "5.15", 33, 33, directInstall = true),
        spec("android14-5.15", 14, "5.15", 34, 34, directInstall = true),
        spec("android14-6.1", 14, "6.1", 34, 34, directInstall = true),
        spec("android15-6.6", 15, "6.6", 35, 35, directInstall = true),
        spec("android16-6.12", 16, "6.12", 36, 36, directInstall = true),
        spec("android17-6.18", 17, "6.18", 37, 37, directInstall = true),
    )

    val KMIS: List<String> = ENTRIES.map { it.kmi }

    private fun spec(
        kmi: String,
        androidMajor: Int,
        kernelSeries: String,
        minSdk: Int,
        maxSdk: Int,
        directInstall: Boolean,
    ) = KsuKmiSpec(
        kmi = kmi,
        androidMajor = androidMajor,
        kernelSeries = kernelSeries,
        minSdk = minSdk,
        maxSdk = maxSdk,
        directInstall = directInstall,
        ddkImage = "ghcr.io/ylarod/ddk-min:$kmi-$DDK_RELEASE",
    )

    fun spec(kmi: String?): KsuKmiSpec? {
        val value = kmi?.trim().orEmpty()
        if (value.isEmpty()) return null
        return ENTRIES.firstOrNull { it.kmi == value }
    }

    fun contains(kmi: String?): Boolean = spec(kmi) != null

    /** 内嵌资产名：`ksud boot-info supported-kmis` 输出的就是去掉该后缀的 KMI。 */
    fun artifactName(kmi: String): String = "${kmi}_kernelsu.ko"

    /** 同一内核序列可能对应多个 Android 大版本（如 5.10 → android12/android13）。 */
    fun forKernelSeries(series: String): List<KsuKmiSpec> =
        ENTRIES.filter { it.kernelSeries == series.trim() }

    /** 系统 SDK 对应多个 KMI 时返回 null，不以系统版本选择内核产物。 */
    fun forSdk(sdkInt: Int): KsuKmiSpec? =
        ENTRIES.singleOrNull { sdkInt in it.minSdk..it.maxSdk }

    /**
     * 一个真实存在的 KMI 形状：`uname -r` 的 `major.minor` + `androidN` → `androidN-<series>`，
     * 以及它在系统 SDK 上的位置 + 本分支是否构建了它的 `.ko`。
     */
    private data class SeriesExpectation(
        val series: String,
        val androidMajor: Int,
        val sdk: IntRange,
        val built: Boolean,
    )

    /**
     * 六个内核系列的**外部期望表**（用户口径 + DDK KMI 表）。
     *
     * 刻意不"从 [ENTRIES] 反推"：反推永远自洽，测不出任何东西。期望值必须来自矩阵**外部**
     * （这份表 / DDK / 用户口径），[audit] 的比对才有意义。
     *
     * 同一系列对应多个 Android 大版本时分别列出各自构建产物，
     * 不把它们映射到相邻系列。
     */
    private val SERIES_EXPECTATIONS: List<SeriesExpectation> = listOf(
        // 5.10 → android12 / android13，分别构建。
        SeriesExpectation("5.10", 12, 31..32, built = true),
        SeriesExpectation("5.10", 13, 33..33, built = true),
        // 5.15 → android13 / android14，分别构建。
        SeriesExpectation("5.15", 13, 33..33, built = true),
        SeriesExpectation("5.15", 14, 34..34, built = true),
        SeriesExpectation("6.1", 14, 34..34, built = true),
        SeriesExpectation("6.6", 15, 35..35, built = true),
        SeriesExpectation("6.12", 16, 36..36, built = true),
        // 6.18 → android17；使用独立的 6.18 模块。
        SeriesExpectation("6.18", 17, 37..37, built = true),
    )

    /**
     * 矩阵自证：`ENTRIES` × 期望表 × 检测/选择逐项比对。
     *
     * 返回违规列表（空 = 一致）。只在测试 / CI / 诊断里调用，**不在安装路径上跑**：
     * 装了 APK 的设备不需要为这份一致性检查付任何运行时成本。
     *
     * 检查的三类事实：
     * 1. 每一行 [ENTRIES] 自洽（`kmi == android<major>-<series>`、系列可被 [KernelSeries] 解析、
     *    SDK band 不倒挂、产物名 = `<kmi>_kernelsu.ko`）；
     * 2. 期望表每一行与矩阵一致（构建过的必须在矩阵里且 SDK band 相同、未构建的必须不在矩阵里）；
     * 3. **检测层**对同一个 uname 形状给出同一个结论（`built` ⇔ `detection.ok`，
     *    未构建时必须是 [KsuKmiDetection.CODE_NOT_IN_MATRIX] 且 KMI 名完整）。
     */
    fun audit(): List<String> {
        val violations = mutableListOf<String>()

        // 1) 每行 ENTRIES 自洽。
        ENTRIES.forEach { spec ->
            if (spec.kmi != "android${spec.androidMajor}-${spec.kernelSeries}") {
                violations += "kmi '${spec.kmi}' != android${spec.androidMajor}-${spec.kernelSeries}"
            }
            if (KernelSeries.of("${spec.kernelSeries}.0") != spec.kernelSeries) {
                violations += "series '${spec.kernelSeries}' does not parse as 'major.minor'"
            }
            if (spec.kernelSeries !in KernelSeries.TIERS) {
                violations += "series '${spec.kernelSeries}' is not one of ${KernelSeries.TIERS}"
            }
            if (spec.minSdk > spec.maxSdk) {
                violations += "sdk band ${spec.minSdk}..${spec.maxSdk} is inverted for ${spec.kmi}"
            }
            if (artifactName(spec.kmi) != "${spec.kmi}_kernelsu.ko") {
                violations += "artifact name drift for ${spec.kmi}"
            }
        }
        if (KMIS.size != KMIS.toSet().size) violations += "duplicate KMI in matrix: $KMIS"

        // 2) 期望表 ↔ 矩阵；3) 期望表 ↔ 检测。
        SERIES_EXPECTATIONS.forEach { row ->
            val kmi = "android${row.androidMajor}-${row.series}"
            val spec = spec(kmi)
            if (row.built) {
                if (spec == null) {
                    violations += "expected ${artifactName(kmi)} to be built, but '$kmi' is not in the matrix"
                } else {
                    if (spec.minSdk != row.sdk.first || spec.maxSdk != row.sdk.last) {
                        violations += "sdk band for $kmi is ${spec.minSdk}..${spec.maxSdk}, " +
                            "expected ${row.sdk}"
                    }
                }
            } else if (spec != null) {
                violations += "'$kmi' must not be built by this branch (no .ko may exist for it)"
            }

            val release = "${row.series}.77-android${row.androidMajor}-8-gdeadbeef"
            val detection = KsuKmiDetector.detect(release)
            if (detection.kmi != kmi) {
                violations += "detect('$release') KMI='${detection.kmi}', expected '$kmi'"
            }
            if (row.built != detection.ok) {
                violations += "detect('$release') ok=${detection.ok}, expected built=${row.built} " +
                    "(code='${detection.code}')"
            }
            if (!row.built && detection.code != KsuKmiDetection.CODE_NOT_IN_MATRIX) {
                violations += "detect('$release') code='${detection.code}', expected " +
                    KsuKmiDetection.CODE_NOT_IN_MATRIX
            }
        }

        // 4) 无孤儿：矩阵里每一行都必须能由一条 built 期望行解释（新增 KMI 必须同步期望表）。
        ENTRIES.forEach { spec ->
            val explained = SERIES_EXPECTATIONS.any {
                it.built && it.series == spec.kernelSeries && it.androidMajor == spec.androidMajor
            }
            if (!explained) violations += "'${spec.kmi}' has no built expectation row"
        }
        return violations
    }
}

/**
 * `ro.board.platform` 的已知取值 → 该平台出现过的 Android 大版本。
 *
 * **只做交叉校验，不做选择依据**：同一 SoC 会随 OEM 升级跨多个 Android 大版本
 * （例如 `taro` 见过 12/13），单独用平台选 KMI 必然选错。未知平台不阻塞检测
 * （只作为证据记录），已知平台与内核代际冲突则报错。
 */
object KsuKmiPlatforms {
    private val KNOWN: Map<String, Set<Int>> = mapOf(
        "gs101" to setOf(12),
        "gs201" to setOf(13),
        "zuma" to setOf(14),
        "zumapro" to setOf(14, 15),
        "taro" to setOf(12, 13),
        "kalama" to setOf(13, 14),
        "pineapple" to setOf(14, 15),
        "sun" to setOf(15, 16),
        "mt6895" to setOf(12, 13),
        "mt6985" to setOf(13, 14),
        "mt6989" to setOf(14, 15),
    )

    fun normalize(platform: String): String = platform.trim().lowercase().replace('-', '_')

    /** null = 未知平台（不参与判定）。 */
    fun androidMajors(platform: String): Set<Int>? = KNOWN[normalize(platform)]
}

/**
 * KMI 检测结果。
 *
 * 成功：`code=""` 且 [kmi] 非空；失败：稳定机器码（UI 只做本地化映射，不做字符串匹配）。
 */
data class KsuKmiDetection(
    val kmi: String?,
    val kernelSeries: String,
    val androidMajor: Int,
    val evidence: String,
    val code: String = "",
    val detail: String = "",
) {
    val ok: Boolean get() = code.isEmpty() && kmi != null

    companion object {
        /** `uname -r` 里既没有版本号也没有 `androidN` 标记。 */
        const val CODE_UNPARSEABLE = "KMI_UNPARSEABLE"

        /** 解析出来了，但不在本次构建的 Normal 矩阵里。 */
        const val CODE_NOT_IN_MATRIX = "KMI_NOT_IN_MATRIX"

        /** 内核代际与 `ro.board.platform` 互相矛盾。 */
        const val CODE_MISMATCH = "KMI_KERNEL_PLATFORM_MISMATCH"
    }
}

object KsuKmiDetector {
    /**
     * `uname -r` 里的 Android 大版本标记（`-android15-…`）。
     *
     * 只匹配字面 `android<digits>`：`gki_android16`/`android_r` 这类变体不参与判定，
     * 宁可判成"解析不出"也不猜。
     */
    private val ANDROID = Regex("android(\\d+)")

    /**
     * `5.10.198-android13-8-test` → (`5.10`, 13)；`6.1.166` （无 android 标记）→ null。
     *
     * 内核侧**只取系列前缀**，实现来自 [KernelSeries.of]（唯一一份解析：
     * 前缀 `major.minor`、不做子串搜索、不可解析返回 `null`）。因此
     * `6.6.50-android15-…` 与 `6.6.89-android15-…` 得到同一个 KMI；patch 段与
     * 构建号（`-g7e1f3c0`）完全不影响结果。
     */
    fun parseKernelRelease(kernelRelease: String): Pair<String, Int>? {
        val value = kernelRelease.trim()
        if (value.isEmpty()) return null
        val series = KernelSeries.of(value) ?: return null
        val major = ANDROID.find(value)?.groupValues?.get(1)?.toIntOrNull() ?: return null
        return series to major
    }

    /**
     * 检测设备 KMI。
     *
     * @param kernelRelease `uname -r`（或 `ro.kernel.version` 等价的完整 release 串）
     * @param boardPlatform `ro.board.platform`（可空；只做交叉校验）
     * @param sdkInt `ro.build.version.sdk`（0 = 未知；仅记录证据，系统升级允许保留原内核）
     */
    fun detect(
        kernelRelease: String,
        boardPlatform: String = "",
        sdkInt: Int = 0,
    ): KsuKmiDetection {
        val evidence = buildString {
            append("uname=").append(kernelRelease.trim().ifEmpty { "<empty>" })
            if (boardPlatform.isNotBlank()) append(" platform=").append(boardPlatform.trim())
            if (sdkInt > 0) append(" sdk=").append(sdkInt)
        }
        val parsed = parseKernelRelease(kernelRelease)
            ?: return KsuKmiDetection(
                kmi = null, kernelSeries = "", androidMajor = 0, evidence = evidence,
                code = KsuKmiDetection.CODE_UNPARSEABLE,
                detail = "cannot parse kernel release '$kernelRelease' (need '<major>.<minor>...-android<N>-...')",
            )
        val (series, major) = parsed
        val kmi = "android$major-$series"
        if (!KsuKmiMatrix.contains(kmi)) {
            return KsuKmiDetection(
                kmi = kmi, kernelSeries = series, androidMajor = major, evidence = evidence,
                code = KsuKmiDetection.CODE_NOT_IN_MATRIX,
                // 明确说"没有这一份产物"：拿别的 KMI 的 .ko 顶替是禁止行为，所以错误文案
                // 直接点名缺失的资产，而不是只报一个"矩阵外"。
                detail = "no ${KsuKmiMatrix.artifactName(kmi)} is built by this branch " +
                    "(matrix=${KsuKmiMatrix.KMIS}); refusing to substitute another KMI's .ko",
            )
        }
        if (boardPlatform.isNotBlank()) {
            val majors = KsuKmiPlatforms.androidMajors(boardPlatform)
            if (majors != null && major !in majors) {
                return KsuKmiDetection(
                    kmi = kmi, kernelSeries = series, androidMajor = major, evidence = evidence,
                    code = KsuKmiDetection.CODE_MISMATCH,
                    detail = "platform '${boardPlatform.trim()}' is known for " +
                        "android${majors.sorted()} but kernel says android$major",
                )
            }
        }
        return KsuKmiDetection(
            kmi = kmi, kernelSeries = series, androidMajor = major, evidence = evidence,
        )
    }
}

/** 选择结果：能选就给出 [KsuKmiSpec]；不能选就给出稳定错误码。 */
sealed interface KsuKmiSelection {
    data class Ready(val spec: KsuKmiSpec) : KsuKmiSelection {
        val kmi: String get() = spec.kmi
        val artifactName: String get() = spec.artifactName
    }

    /** 明确失败（矩阵外 / 本次 APK 没打进该 KMI 的 .ko）。 */
    data class Missing(val code: String, val detail: String) : KsuKmiSelection

    /**
     * 设备事实没有上报"本次打包了哪些 KMI"（旧适配器）。调用方按策略决定：
     * 兼容模式继续（最终由 ksud 的嵌入资产查找硬失败），严格模式拒绝。
     */
    data class Unknown(val kmi: String, val artifactName: String) : KsuKmiSelection
}

object KsuKmiSelector {
    const val CODE_NOT_IN_MATRIX = "KSU_KMI_NOT_IN_MATRIX"
    const val CODE_ARTIFACT_MISSING = "KSU_KMI_ARTIFACT_MISSING"
    const val CODE_CATALOG_UNKNOWN = "KSU_KMI_CATALOG_UNKNOWN"

    /**
     * 按 KMI 选 `.ko`。
     *
     * @param availableKmis `ksud boot-info supported-kmis` 的结果（本次 APK 内嵌的 KMI）；
     *   null = 未上报 → [KsuKmiSelection.Unknown]（**绝不**当作"全都有"）。
     */
    fun select(kmi: String?, availableKmis: Collection<String>?): KsuKmiSelection {
        val value = kmi?.trim().orEmpty()
        if (value.isEmpty()) {
            return KsuKmiSelection.Missing(
                CODE_NOT_IN_MATRIX, "kmi is empty; refusing to pick any kernelsu.ko")
        }
        if (availableKmis == null) {
            return KsuKmiSelection.Unknown(value, KsuKmiMatrix.artifactName(value))
        }
        val catalog = availableKmis.map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        val spec = KsuKmiMatrix.spec(value)
            ?: return KsuKmiSelection.Missing(
                CODE_NOT_IN_MATRIX,
                "kmi '$value' is outside the built matrix ${KsuKmiMatrix.KMIS} " +
                    "(packaged=${catalog.sorted()})",
            )
        if (spec.kmi !in catalog) {
            return KsuKmiSelection.Missing(
                CODE_ARTIFACT_MISSING,
                "no packaged ${spec.artifactName} for KMI '${spec.kmi}'; " +
                    "packaged=${catalog.sorted()}",
            )
        }
        return KsuKmiSelection.Ready(spec)
    }
}
