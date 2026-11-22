package dev.maplesu.manager.modules.compat

/**
 * 一台设备的「组合范围」：Ultra SDK 版本集 + 内核 release + 内核变体集 + 同 base 变体集 +
 * （可选）boot 镜像哈希集。
 *
 * 为什么要把设备组合写成范围而不是写成一个字符串：判定要回答的是「包 × SDK × 内核」这个三元组
 * 有没有被核对过。把它写成数据，加一个设备组合只要加一条记录，不用改判定逻辑。
 *
 * ## 内核门的构成（2026-10-31 W6-F2 修订）
 *
 * - **必需**：`sdkVersions` 精确匹配、`kernelRelease` 精确匹配。不同 release 就是另一个内核，
 *   一律 UNVERIFIED——「其它内核未验证」这条结论不因为变体规则而改变。
 * - **变体**：只分四态，不再当命中的必要条件（见 `UltraModuleCompatibility` 文件头）：
 *   记录变体 → 精确命中；`sameBaseKernelVariants` 里已核对同 base 内核的补丁集 → 仍拦
 *   （同类推断 + 注意码）；读不到 → 仍拦（无法排除记录变体 + 注意码）；其它不认识的变体 id
 *   → 与「另一个内核」同类，按 UNVERIFIED 处理，**不**冒充同类推断。
 * - **boot**：可选强化。给了且变体=记录变体时，必须在 `bootImageSha256s` 里。
 *
 * ## 「共用同一个 base 内核」这条事实：能推出什么、不能推出什么
 *
 * 可核对的事实（`manager/src/main/assets/ultra-kernels/manifest.json`）：
 *
 *  - 第 18 行（k22）与第 36 行（k21）的 `baseKernelSha256` 都是
 *    `346d51ea1f63413ffa5d99c5c426806291af3573f0a1d66a7621c388e835880e`；
 *  - 两份产物内核的摘要不同：k22 `287fbdd0…`、k21 `34463151…`；boot 也不同：
 *    k22 `47aa147a…`、k21 `6c7a451d…`。**变体不同是真的不同**。
 *
 * **能推出**：两个变体都从同一份 base 内核镜像出发，只应用各自的字节补丁记录；模块看到的
 * 回调类型合同（`filldir64` / `compat_filldir` / `proc_pid_instantiate` 的原型）来自 base 内核
 * 的 BTF，而 BTF 在两份产物里是同一段字节。
 * 实测核对（W6-F2，见 `.analysis/ultra-module-crash-remediation-20261031/w6-f2/EVIDENCE.md`）：
 * 两份内核镜像逐字节比较只差 `0x8FCFB0` 处的 4 字节（k22 多的那条「euid==0 gate」记录），
 * 内嵌 BTF 段（`0x16F3980` 起、6,099,729 B）的 SHA256 与设备 `device-vmlinux.btf` 相同
 * （`8801d0c1…`），因此 k21 上的 BTF 类型表与 k22 逐字节相同。
 *
 * **不能推出**：补丁集的**语义**相同。k21 的 spec 自述 NOP 掉 ssid 门会放宽 SELinux，
 * k22 又多了 `0x8FCFB0` 的 euid 门分支——root/AVC 行为确实可能不同。所以「合同相同」
 * 只覆盖回调**类型**，不覆盖「这个模块在 k21 上运行时内核会怎么处理权限」，更没有设备实测。
 * 因此 k21 的拦截结论带 `KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE`，标明是推断。
 *
 * @param sdkVersions 已核对的 SDK 版本号集合（精确匹配，必需）。
 * @param kernelRelease 已核对的内核 release（`uname -r` 全串，精确匹配，必需）。
 * @param kernelVariants 实测时所在的内核变体 id 集合（当前只有 k22）。它表示「记录实测的那一个」，
 *   不是「允许放行的白名单」：`sameBaseKernelVariants` 里的变体会被拦（推断注意码），读不到时
 *   也会被拦（缺口注意码），只有完全不认识的变体 id 才按未验证处理。
 * @param bootImageSha256s 已核对的 boot 镜像 SHA256 集合。允许为空列表表示「未固定镜像哈希」；
 *   非空时，调用方给出的 boot 哈希必须在集合里（只在变体=记录变体时作为精确组合的强化项）。
 * @param sameBaseKernelVariants 与记录变体**共用同一个 base 内核**、只差补丁集的其它变体 id
 *   （当前只有 k21）。为什么单独成字段、而不是「凡是不等于 k22 的变体都算同类」：那会把
 *   「k21 与 k22 共用 base 内核」这条已核对的事实，外推成「所有变体都共用」——正是 W5 复核
 *   点名的「未经核对就下结论」。这里只列真正核对过 base 内核的变体；不在列表里的变体 id
 *   与「另一个 release」同类，按 UNVERIFIED 处理（既不拦，也不宣称兼容）。
 */
data class UltraDeviceScope(
    val sdkVersions: Set<String>,
    val kernelRelease: String,
    val kernelVariants: Set<String>,
    val bootImageSha256s: Set<String> = emptySet(),
    val sameBaseKernelVariants: Set<String> = emptySet(),
)

/**
 * 一条「已实测通过」的验收范围。
 *
 * 必须绑定具体动作：开发方案 §8.2 要求每条功能路径单独验收，缺一项就「不记为支持」。
 * 所以即使设备组合命中，也只有列在 [actions] 里的入口才算 VERIFIED，其余保持 UNVERIFIED。
 *
 * 匹配是**精确**的：SDK 版本、内核 release、内核变体、boot 摘要（给了就）都必须命中，
 * 缺一项就不算（变体读不到也不给 VERIFIED，见 `UltraModuleCompatibility.matchesVerifiedScope`）。
 *
 * @param id 验收批号/记录标识（写进回执，便于追溯）。
 * @param device 实测时的设备组合范围。
 * @param actions 该记录真正验收通过的入口；空集合表示这条记录什么都不能放行。
 * @param evidence 证据文件路径（repo 相对路径）。
 */
data class UltraVerifiedScope(
    val id: String,
    val device: UltraDeviceScope,
    val actions: Set<UltraModuleAction>,
    val evidence: List<String> = emptyList(),
)

/**
 * 一条固定兼容记录。
 *
 * [archiveSha256] + [nativePayloadSha256] + [id32] 是命中条件（三者同时相等）；
 * [version] 不参与命中，只用于报告和「同版本内容变化」的诊断。
 *
 * @param recordId 稳定记录 id，回执与报告入口按它索引。
 * @param nativeEntryName 被核对的原生成员名，仅用于报告与人工核对。
 * @param incompatibleScope 已确认不兼容的设备组合范围。变体写的是实测时所在的那一个（k22），
 *   不是「白名单」：同一 release 的其它补丁集仍会被拦，只是带推断注意码。
 * @param verifiedScopes 已实测通过的设备组合范围。**首版全部为空**：没有真实设备验收结果就不填，
 *   不能为了让某条路径「看起来通过」而伪造 VERIFIED。
 * @param summary 一句话原因（给对话框与回执用）。
 * @param evidence 证据文件路径（repo 相对路径）。
 */
data class UltraModuleCompatibilityRecord(
    val recordId: String,
    val id32: String,
    val version: String,
    val archiveSha256: String,
    val nativePayloadSha256: String,
    val nativeEntryName: String?,
    val incompatibleScope: UltraDeviceScope,
    val verifiedScopes: List<UltraVerifiedScope>,
    val summary: String,
    val evidence: List<String>,
)

/**
 * 仓库内固定兼容记录（首版唯一权威，不需要远程服务）。
 *
 * 为什么是固定记录：只把「已经被离线核对过的那一组身份」写进代码，判定就不依赖任何服务端可用性，
 * 也不会因为「清单拉不到」而把已确认不兼容的包放过去。远程清单是以后的事；在它之前，这里就是
 * 唯一结论来源。
 *
 * 加记录的门槛（缺一不可）：
 *  1. 三个哈希都来自可复算的证据（归档 SHA256、原生成员 SHA256、模块 id32），不能只抄版本号；
 *  2. 设备组合（SDK 版本、内核 release、**实测时所在的内核变体**、boot 哈希）有对应证据；
 *     变体记录的是「当时实测的那一个」，不是「允许放行的白名单」；
 *  3. 结论只能是「已确认不兼容」或「有实测通过的动作」。同一条记录里，
 *     `verifiedScopes` 只写真正跑过并通过的入口，没有跑过就是空。
 */
object UltraModuleCompatibilityRegistry {

    /** 「应用自动隐藏」1.9.3 市场包在本机组合上确认为不兼容。 */
    const val AAH_MARKET_1_9_3 = "aah-market-1.9.3-20261031"

    /** 设备与内核身份的固定值（来源见 .analysis/app-auto-hider-boot-failure-20261031/）。 */
    // SDK 5.1 retains this module ABI and the kernel BTF callback contract. The pinned bad
    // payload remains blocked; this inherited negative rule is not a new device acceptance.
    // Original device observations stay in the referenced historical evidence.
    private const val DEVICE_SDK_VERSION = "5.1.0"
    private const val DEVICE_KERNEL_RELEASE = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
    private const val DEVICE_KERNEL_VARIANT = "k22"

    /** 与 k22 共用同一个 base 内核、只差补丁集的另一个变体（已按字节核对，见 W6-F2 EVIDENCE §3）。 */
    private const val DEVICE_SAME_BASE_KERNEL_VARIANT = "k21"
    private const val DEVICE_BOOT_SHA256 = "47aa147acbe3edf8e58ce60d334ad4c4b26cad26b5cb93aa6acb59a67fdd5f59"

    val records: List<UltraModuleCompatibilityRecord> = listOf(
        UltraModuleCompatibilityRecord(
            recordId = AAH_MARKET_1_9_3,
            // 模块 id32：cd08ae9eef7bb885c06f80ef3aea1d5c，版本 1.9.3。
            id32 = "cd08ae9eef7bb885c06f80ef3aea1d5c",
            version = "1.9.3",
            // 市场 ZIP SHA256。
            archiveSha256 = "2fdc08482075a9865d49e2595a2487f07a37ab499aab744d8d9bb09a098d4a31",
            // 归档成员 libmodule_app_auto_hider.so 的 SHA256（1,767,272 B，与实装本体一致）。
            nativePayloadSha256 = "a0835b667db5ed33a12b7fa2d2f8ba9ee58b8f7fd538250b62111cffd2a647dc",
            nativeEntryName = "libmodule_app_auto_hider.so",
            incompatibleScope = UltraDeviceScope(
                sdkVersions = setOf(DEVICE_SDK_VERSION),
                kernelRelease = DEVICE_KERNEL_RELEASE,
                kernelVariants = setOf(DEVICE_KERNEL_VARIANT),
                bootImageSha256s = setOf(DEVICE_BOOT_SHA256),
                // 只列真正核对过「同 base 内核」的变体：manifest 两变体 baseKernelSha256 相同 +
                // 两份内核镜像只差 0x8FCFB0 的 4 字节 + 内嵌 BTF 摘要相同（W6-F2 EVIDENCE §3）。
                // 不在这个集合里的变体 id 不按同类推断处理（见 UltraDeviceScope）。
                sameBaseKernelVariants = setOf(DEVICE_SAME_BASE_KERNEL_VARIANT),
            ),
            // 首版没有 VERIFIED：这台设备上该模块没有通过任何功能路径的验收，
            // 只完成了「已确认不兼容」的静态核对。别为了 UI 好看填一条空的通过记录。
            verifiedScopes = emptyList(),
            summary = "模块 ELF 的目录回调返回约定、进程回调参数/返回类型与本机内核 BTF 合同不一致（BR2/BR3），" +
                "且 Hook 句柄缺少统一回收、卸载回执被丢弃（BR4）；入口返回 0 不能证明内核状态安全",
            evidence = listOf(
                "docs/MODULE_COMPATIBILITY.md",
            ),
        ),
    )
}
