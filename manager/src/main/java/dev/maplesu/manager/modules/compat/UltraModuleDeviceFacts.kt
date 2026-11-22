package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import java.io.File

/**
 * 判定需要的**设备事实**：SDK 版本、SDK 清单核对状态、内核 release、内核变体、boot 镜像摘要。
 *
 * 这个类的唯一职责是「把本机能读到的证据如实读出来」。它不做判定
 * （判定在 [UltraModuleCompatibility]），也不做任何「读不到就当默认值」的补偿：
 * **读不到就是 null / false，等于证据不足，不等于兼容，也不等于不兼容。**
 *
 * ## 为什么读不到的字段不能否决、也不能放行
 *
 * 开发方案 §4.1 要求「其它内核/组合记录为未验证，不凭版本号推断全部正常或全部异常」。
 * 因此：
 *  - 某个字段拿不到时**不得伪判**：不能把它当成「这个包已确认不兼容」（`KNOWN_INCOMPATIBLE`
 *    必须绑住 release + 包字节），也不能把它当成「已兼容」（`VERIFIED` 需要实测范围）。
 *  - 某个字段拿不到时**也不得放行成已核实**：结论会停在 `UNVERIFIED`，原因码点名缺哪一项，
 *    上层必须把这个状态原样展示（`UNVERIFIED` 不是授权，见 [UltraModuleCompatibilityVerdict]）。
 *  - 「内核变体读不到」这一项是**可选强化**：它不改变命中结论，但会以
 *    [UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN] 注意码出现（见
 *    `UltraDeviceScope.mismatchCodes` 里 k21/k22 共用 base 内核的说明）。
 *
 * ## 每一项的真实来源
 *
 * | 字段 | 来源 | 读不到时 |
 * |---|---|---|
 * | [kernelRelease] | `/proc/sys/kernel/osrelease`（应用可直接读，**不需要 root**） | null |
 * | [sdkVersion] | 传入的 [UltraRuntimeClient] 的 `sdkVersion()`（= `get_sdk_version`，只读探针） | null |
 * | [sdkManifestVerified] | 「155 文件来源清单核对」的结果；本类拿不到，默认 false | false |
 * | [kernelVariantId] | 当前内核清单里的变体 id（k22/k21）。**应用无法可靠读到自己装的是哪一个**：两个变体同 release、同 base 内核，只有补丁集不同 | null |
 * | [bootImageSha256] | 安装/恢复记录里的 boot 镜像摘要 | null |
 *
 * `sdkManifestVerified` / `kernelVariantId` / `bootImageSha256` 现在没有可靠来源，所以默认值是
 * false / null。这不是「实现没写完就先填个值」，而是**如实记录证据不足**：判定会把它们当成
 * 注意项（SDK 清单 → `SDK_MANIFEST_UNVERIFIED`，变体 → `KERNEL_VARIANT_UNKNOWN`），
 * 并在文案里写清楚缺口。
 *
 * ## 只读、可测
 *
 * 类本身没有 Android import：内核 release 通过注入的读取器取得（默认读 procfs），SDK 版本通过
 * 可空的 [UltraRuntimeClient] 取得。测试可以传 null / 假读取器，不需要设备。
 */
class UltraModuleDeviceFacts private constructor(
    val sdkVersion: String?,
    val sdkManifestVerified: Boolean,
    val kernelRelease: String?,
    val kernelVariantId: String?,
    val bootImageSha256: String?,
) {

    /** 判定用的 SDK 身份。版本读不到时是空串 → `SDK_VERSION_MISSING`（未验证，不猜）。 */
    val sdkIdentity: UltraSdkIdentity
        get() = UltraSdkIdentity(version = sdkVersion.orEmpty(), manifestVerified = sdkManifestVerified)

    /** 判定用的内核身份。release 读不到时是空串 → `KERNEL_RELEASE_MISSING`（未验证，不猜）。 */
    val kernelIdentity: UltraKernelIdentity
        get() = UltraKernelIdentity(
            release = kernelRelease.orEmpty(),
            variantId = kernelVariantId,
            bootImageSha256 = bootImageSha256,
        )

    /** 给回执/日志用的一句话摘要，**只写已知事实**；null 显示成 unknown，不伪造值。 */
    fun summary(): String = buildString {
        append("sdk=")
        append(sdkVersion ?: "unknown")
        append(" manifest=")
        append(if (sdkManifestVerified) "verified" else "unverified")
        append(" kernel=")
        append(kernelRelease ?: "unknown")
        append(" variant=")
        append(kernelVariantId ?: "unknown")
        append(" boot=")
        append(bootImageSha256 ?: "unknown")
    }

    companion object {

        /** 内核 release 的 procfs 路径。`uname -r` 的值就是它（不含换行）。 */
        const val KERNEL_RELEASE_FILE = "/proc/sys/kernel/osrelease"

        /**
         * 读取本机设备事实。
         *
         * @param client 可空的 Ultra 运行时客户端：为 null 时 SDK 版本记为未知（证据不足），
         *   不会因此判定兼容或不兼容。**注意**：这里只调用只读的 `sdkVersion()`
         *   （`get_sdk_version`），不调用任何会执行模块的入口。
         */
        fun read(client: UltraRuntimeClient? = null): UltraModuleDeviceFacts =
            readWith(client) { kernelReleaseFromProc() }

        /**
         * 可注入读取器的版本（测试用；生产走 [read]）。
         *
         * @param kernelReleaseReader 返回内核 release，读不到返回 null。
         */
        fun readWith(
            client: UltraRuntimeClient?,
            kernelReleaseReader: () -> String?,
        ): UltraModuleDeviceFacts {
            val receipt = client?.sdkVersion()
            val version = if (receipt != null && receipt.succeeded) {
                receipt.string("version")?.trim()?.takeIf { it.isNotEmpty() }
            } else {
                null
            }
            return UltraModuleDeviceFacts(
                sdkVersion = version,
                // 没有可靠的「155 文件来源清单」核对入口可调用：默认 false，并把结论里的
                // SDK_MANIFEST_UNVERIFIED 当成注意项展示（它不削弱已知不兼容的拦截）。
                sdkManifestVerified = false,
                kernelRelease = kernelReleaseReader()?.trim()?.takeIf { it.isNotEmpty() },
                // 应用无法可靠区分 k21/k22（同 release、同 base 内核、仅补丁集不同），
                // 所以这里如实写 null，让判定按「可选强化项缺失」处理。
                kernelVariantId = null,
                // boot 镜像摘要来自安装/恢复记录，本类没有读取入口；null = 未固定。
                bootImageSha256 = null,
            )
        }

        /** 显式构造（测试与将来的注入点用）。所有字符串会被 trim，空串归一为 null。 */
        fun of(
            sdkVersion: String? = null,
            kernelRelease: String? = null,
            sdkManifestVerified: Boolean = false,
            kernelVariantId: String? = null,
            bootImageSha256: String? = null,
        ): UltraModuleDeviceFacts = UltraModuleDeviceFacts(
            sdkVersion = sdkVersion?.trim()?.takeIf { it.isNotEmpty() },
            sdkManifestVerified = sdkManifestVerified,
            kernelRelease = kernelRelease?.trim()?.takeIf { it.isNotEmpty() },
            kernelVariantId = kernelVariantId?.trim()?.takeIf { it.isNotEmpty() },
            bootImageSha256 = bootImageSha256?.trim()?.takeIf { it.isNotEmpty() },
        )

        /**
         * procfs 读取。读不到（权限、不存在、非 Linux 宿主）返回 null——不抛异常、不猜值。
         *
         * 为什么用 `/proc/sys/kernel/osrelease` 而不是 `uname`：应用进程不需要 root 就能读它，
         * 也不必起 shell（起 shell 会引出一个与本任务无关的、需要 root 通道的依赖）。
         */
        private fun kernelReleaseFromProc(): String? = runCatching {
            File(KERNEL_RELEASE_FILE).readText()
        }.getOrNull()
    }
}
