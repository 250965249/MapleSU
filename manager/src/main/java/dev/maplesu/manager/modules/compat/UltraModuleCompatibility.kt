package dev.maplesu.manager.modules.compat

/**
 * Ultra 模块兼容性判定：纯逻辑，无 Android import、无 IO、无时钟。
 *
 * 静态兼容检查先于「宿主描述交叉检查」，同一输入应产生相同结论。因此这里只收四个入参
 * （包身份、SDK 身份、内核身份、动作）：不读文件、不读系统属性、不取当前时间、不联网。
 * 同一组输入永远得到同一个结果。读 ZIP、算成员哈希属于调用方（ModuleArchiveInspector）的事，
 * 判定本身不做 IO。
 *
 * ## 首版是仓库内固定记录，不需要远程服务
 * 目前只有一组身份被真正核对过（见 [UltraModuleCompatibilityRegistry]）。把结论写进代码、随 APK
 * 一起发布，判定不会因为「服务端不可用」而把已确认不兼容的包放过去；远程清单以后再补，在它之前
 * 固定记录就是唯一权威。记录是数据（`UltraModuleCompatibilityRecord`），加一条记录不需要改判定逻辑。
 *
 * ## 为什么必须绑哈希，而不是绑模块名或版本号
 * 模块 id32 与版本号都是包自己声明的字段，同一个 id32 + 同一个版本号完全可以对应另一份 ELF。
 * 只有「整个 ZIP 归档字节的 SHA256」加「真正会被加载的那个原生成员的 SHA256」才能证明要执行的
 * 代码就是被核对过的那份字节。所以命中固定记录的条件是三者同时相等：
 * id32 + archiveSha256 + nativePayloadSha256。只对上名字或只对上版本号都不算命中，也绝不据此
 * 推断「兼容」或「不兼容」。
 *
 * ## 拦住是安全方向，放行是危险方向（W6-F2 的口径）
 *
 * 两种错误的代价不对称：
 *  - 把已知坏包**拦住**：代价是功能暂时不可用，可解释、可恢复；
 *  - 把已确认不兼容的包**放行**：模块原生代码按错误合同进内核执行，代价是 panic / 重启。
 *
 * 所以本文件不对「证据不足」做对称处理，而是明确选方向：**拿不准就拦**。
 *
 * 包字节（id32 + 归档 SHA256 + 原生载荷 SHA256）三项命中固定记录之后，
 * 「这个包已确认不兼容」这个结论来自**包自身的实现**与**设备内核 BTF 合同**的冲突；
 * 它不来自「设备组合是否和实测时一模一样」。内核对回调类型的要求写在 base 内核的 BTF 里，
 * 与补丁集无关（可复算的核对写在 [UltraDeviceScope] 的注释里）。因此变体关系分四态：
 *
 *  - 记录变体（k22）：精确命中 → 拦；
 *  - 记录里已核对过**共用 base 内核**的另一个补丁集（k21）：不在已验证范围，但回调类型合同
 *    相同 → **也拦**，明确标注这是推断、未经逐补丁语义审阅，附
 *    [UltraModuleReasonCode.KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE]；
 *  - 读不到（null/空）：无法排除「就是实测的 k22」→ **仍然拦**，缺口记成
 *    [UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN]；
 *  - 读到了、但记录里**没有**它与记录变体共用 base 内核的证据（例如未来的 k23）：与「另一个
 *    release」同类，没有该 build 的证据 → UNVERIFIED（不拦，也不宣称兼容），
 *    原因码 [UltraModuleReasonCode.KERNEL_VARIANT_NOT_IN_RECORD]。
 *
 * 最后一条是刻意保留的边界：不把「k21 与 k22 共用 base 内核」这条已核对的事实外推成
 * 「所有变体都共用」——那正是 W5 复核点名的「未经核对就下结论」。
 *
 * 「已验证」（放行并宣称兼容）则相反：只有**精确**命中实测组合（包括变体）才允许，
 * 读不到变体时不宣称已验证。同一个「读不到」在两个方向上都不被当成「已核实」。
 *
 * ## 判定不产生授权
 * 本文件只回答「这条入口现在能不能作为已验证路径执行」。首版只有
 * [UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE] 会拦下原生执行
 * （见 [UltraModuleCompatibilityVerdict.blocksNativeExecution]）；
 * [UltraModuleCompatibilityDecision.UNVERIFIED] 的含义是「证据不足，不要显示成已兼容」，
 * 既不是「已证明不兼容」，也不是「可以当兼容用」。
 */
object UltraModuleCompatibility {

    private val SHA256_HEX = Regex("^[0-9a-fA-F]{64}$")

    /**
     * 判定一次「这条动作现在能不能作为已验证路径执行」。
     *
     * 顺序（短路）：
     *  1. 包身份字段不全 → UNVERIFIED（证据不足，不按名字/版本猜）；
     *  2. `id32 + archiveSha256 + nativePayloadSha256` 三者同时命中固定记录；
     *  3. 命中后先看有没有**精确**命中的已验证设备范围（变体也必须确认，见
     *     `UltraDeviceScope.matchesVerifiedScope`）；否则要求 SDK 版本在内、内核 release 相等，
     *     再按变体四态决定结论（见文件头）：记录变体/同 base 补丁集/读不到 → 拦（后两者带注意码）；
     *     不认识的变体 id → 未验证；
     *  4. 未命中但同 id32：区分「同版本内容变了」与「换了版本」，一律 UNVERIFIED；
     *  5. 完全未知 → UNVERIFIED（未知不等于兼容，也不等于已确认不兼容）。
     *
     * `records` 默认取仓库内固定记录；只有测试会注入别的列表来验证扩展点。
     * 本函数不抛异常：所有失败都变成带稳定原因码的 UNVERIFIED。
     */
    fun evaluate(
        pkg: UltraModulePackageIdentity,
        sdk: UltraSdkIdentity,
        kernel: UltraKernelIdentity,
        action: UltraModuleAction,
        records: List<UltraModuleCompatibilityRecord> = UltraModuleCompatibilityRegistry.records,
    ): UltraModuleCompatibilityVerdict {
        val id32 = pkg.id32.trim()
        val version = pkg.version.trim()
        val archiveSha256 = pkg.archiveSha256.trim()
        val nativePayloadSha256 = pkg.nativePayloadSha256.orEmpty().trim()

        // 1) 证据够不够用。缺字段就到此为止：不按模块名/版本号推断，也不把「读到空值」
        //    当成「这个包没有原生载荷」。两份 sha256 是无 IO 证据里最强的两项，必须都有。
        val incomplete = ArrayList<UltraModuleReasonCode>(4)
        if (id32.isEmpty()) incomplete += UltraModuleReasonCode.PACKAGE_ID32_MISSING
        if (archiveSha256.isEmpty()) {
            incomplete += UltraModuleReasonCode.PACKAGE_ARCHIVE_SHA256_MISSING
        } else if (!SHA256_HEX.matches(archiveSha256)) {
            incomplete += UltraModuleReasonCode.PACKAGE_ARCHIVE_SHA256_MALFORMED
        }
        if (nativePayloadSha256.isEmpty()) {
            incomplete += UltraModuleReasonCode.PACKAGE_NATIVE_PAYLOAD_SHA256_MISSING
        } else if (!SHA256_HEX.matches(nativePayloadSha256)) {
            incomplete += UltraModuleReasonCode.PACKAGE_NATIVE_PAYLOAD_SHA256_MALFORMED
        }
        if (incomplete.isNotEmpty()) {
            return verdict(
                decision = UltraModuleCompatibilityDecision.UNVERIFIED,
                codes = incomplete,
                action = action,
                matchedRecordId = null,
                displayReason = "未验证：缺少可用于核验的身份字段（${incomplete.joinToString("、") { it.code }}）。" +
                    "无法确认这个模块包就是被核对过的那份字节，因此不按已兼容处理，也不据此判定不兼容。",
            )
        }

        // SHA256 是十六进制串，大小写不影响同一性；统一小写后比较。
        val archiveHash = archiveSha256.lowercase()
        val payloadHash = nativePayloadSha256.lowercase()

        // 2) 固定记录命中：三者同时相等才算「这就是那个包」。
        val matched = records.firstOrNull { record ->
            record.id32.equals(id32, ignoreCase = true) &&
                record.archiveSha256.equals(archiveHash, ignoreCase = true) &&
                record.nativePayloadSha256.equals(payloadHash, ignoreCase = true)
        }
        if (matched != null) return verdictForRecordMatched(matched, sdk, kernel, action)

        // 3) 没命中：是「同 id32 但字节变了」还是完全不同，结论都是 UNVERIFIED，但原因码要分开。
        return verdictForRecordMissed(records, id32, version, archiveHash, payloadHash, action)
    }

    // ------------------------------------------------------------------ 命中记录

    private fun verdictForRecordMatched(
        record: UltraModuleCompatibilityRecord,
        sdk: UltraSdkIdentity,
        kernel: UltraKernelIdentity,
        action: UltraModuleAction,
    ): UltraModuleCompatibilityVerdict {
        // 变体四态（记录变体 / 同 base 补丁集 / 不认识 / 读不到）与随结论返回的注意码。
        // 注意码不改变「拦不拦」，但必须展示：它记录的是「精确到什么程度」。
        val variantRelation = record.incompatibleScope.variantRelation(kernel)
        val advisories = record.incompatibleScope.advisoryCodes(kernel)

        // 扩展点：包已命中，且这台设备的组合**精确**落在某条「已实测通过」的范围内。
        // 变体也必须确认（见 matchesVerifiedScope）：「读不到变体」不能同时被当成
        // 「拦住」和「已验证」的依据——放行宣称兼容是不安全方向（文件头）。
        // 首版所有记录的 verifiedScopes 都是空的，所以这条分支现在不会命中——
        // 不会凭空造出 VERIFIED（见 UltraModuleCompatibilityRegistry 的说明）。
        val verified = record.verifiedScopes.firstOrNull { it.device.matchesVerifiedScope(sdk, kernel) }
        if (verified != null) {
            // 「已验证」是拿到证据才能说的结论：宿主栈本身没核对通过时，只能停在未验证，
            // 既不能宣称已验证，也不能因为这条验收记录改判成不兼容。
            if (!sdk.manifestVerified) {
                return verdict(
                    decision = UltraModuleCompatibilityDecision.UNVERIFIED,
                    codes = listOf(
                        UltraModuleReasonCode.PACKAGE_HASH_MATCHED,
                        UltraModuleReasonCode.DEVICE_COMBINATION_IN_VERIFIED_SCOPE,
                        UltraModuleReasonCode.SDK_MANIFEST_UNVERIFIED,
                    ) + advisories,
                    action = action,
                    matchedRecordId = record.recordId,
                    displayReason = "未验证：模块包 ${record.id32}（版本 ${record.version}）落在验收记录 ${verified.id} " +
                        "的实测范围内，但 Ultra SDK 清单尚未核对通过，无法确认宿主栈就是被记录过的那一套，" +
                        "因此不宣称已验证，按未验证处理。",
                )
            }
            if (action in verified.actions) {
                return verdict(
                    decision = UltraModuleCompatibilityDecision.VERIFIED,
                    codes = listOf(
                        UltraModuleReasonCode.PACKAGE_HASH_MATCHED,
                        UltraModuleReasonCode.DEVICE_COMBINATION_IN_VERIFIED_SCOPE,
                    ) + advisories,
                    action = action,
                    matchedRecordId = record.recordId,
                    displayReason = "已验证：模块包 ${record.id32}（版本 ${record.version}）命中验收记录 " +
                        "${verified.id}，本机 SDK/内核组合在该记录的实测范围内，「${action.label}」按已验证能力放行。" +
                        "该结论只覆盖这条记录列出的能力，不代表模块其它路径也通过。",
                )
            }
            return verdict(
                decision = UltraModuleCompatibilityDecision.UNVERIFIED,
                codes = listOf(
                    UltraModuleReasonCode.PACKAGE_HASH_MATCHED,
                    UltraModuleReasonCode.DEVICE_COMBINATION_IN_VERIFIED_SCOPE,
                    UltraModuleReasonCode.ACTION_NOT_IN_VERIFIED_SCOPE,
                ) + advisories,
                action = action,
                matchedRecordId = record.recordId,
                displayReason = "未验证：模块包 ${record.id32}（版本 ${record.version}）在本机组合上有部分路径通过实测，" +
                    "但「${action.label}」不在验收记录 ${verified.id} 的能力清单里，因此按未验证处理，不显示为已兼容。",
            )
        }

        val scopeMismatch = record.incompatibleScope.confirmedScopeMismatchCodes(sdk, kernel)
        if (scopeMismatch.isEmpty()) {
            // 「已确认不兼容」的证据是包字节 + 设备内核合同，与 SDK 清单是否核对通过无关；
            // 但「清单没核对」「变体读不到 / 不是记录变体」必须记进原因码，不能悄悄消失——
            // 它们是证据缺口或推断，不是已核实项。
            val manifestCaveat = !sdk.manifestVerified
            val codes = ArrayList<UltraModuleReasonCode>(5)
            codes += UltraModuleReasonCode.PACKAGE_HASH_MATCHED
            // 「在记录范围内」只声明**必需项**（SDK 版本 + 内核 release）。变体读不到是缺口（注意码）；
            // 变体是同 base 的另一个补丁集时不声明「在记录内」——那会把推断写成核实（复核 S2-4）；
            // 不认识的变体根本到不了这里（已在 confirmedScopeMismatchCodes 里降级）。
            when (variantRelation) {
                VariantRelation.RECORDED, VariantRelation.UNKNOWN ->
                    codes += UltraModuleReasonCode.DEVICE_COMBINATION_IN_RECORD
                VariantRelation.SAME_BASE_KERNEL, VariantRelation.OTHER_UNRECOGNIZED -> Unit
            }
            codes += advisories
            if (manifestCaveat) codes += UltraModuleReasonCode.SDK_MANIFEST_UNVERIFIED
            val caveat = buildString {
                if (manifestCaveat) {
                    append(
                        "注意：Ultra SDK 清单尚未核对通过，宿主身份只能按版本号认定；这不改变本包已确认不兼容的" +
                            "结论（拦截照旧），但需要补齐 SDK 核对。",
                    )
                }
                when (variantRelation) {
                    VariantRelation.RECORDED -> Unit
                    VariantRelation.UNKNOWN -> append(
                        "注意：本机读不到内核补丁集（变体 id），因此**无法排除**「装的就是实测不兼容的 k22」；" +
                            "判定按内核 release + 包字节命中，变体缺口属于证据不足，" +
                            "未核实不等于已核实（回执保留 ${UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN.code}）。",
                    )
                    VariantRelation.SAME_BASE_KERNEL -> append(
                        "注意：本机读到内核补丁集 ${kernel.variantId.orEmpty().trim()}，它不是记录实测时的 k22；" +
                            "但记录核对过它与 k22 共用同一个 base 内核（manifest 的 baseKernelSha256 相同，两份内核镜像" +
                            "除 4 字节外逐字节相同，内嵌 BTF 类型表相同），模块看到的回调类型合同来自那份 base 内核，" +
                            "所以按同一类合同冲突拦截。这是推断：没有在该变体设备上实测，也没有逐补丁做语义审阅，" +
                            "补丁集仍可能改变 root/AVC 行为（回执保留 " +
                            "${UltraModuleReasonCode.KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE.code}）。",
                    )
                    // 不认识的变体不会走到这里（confirmedScopeMismatchCodes 已把它降级）。
                    VariantRelation.OTHER_UNRECOGNIZED -> Unit
                }
            }
            return verdict(
                decision = UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE,
                codes = codes,
                action = action,
                matchedRecordId = record.recordId,
                displayReason = "已拦截：模块 ${record.id32}（版本 ${record.version}）已确认与本机组合不兼容，" +
                    "本次「${action.label}」不会执行模块原生代码。依据：归档 SHA256 与模块原生载荷 SHA256 共同命中" +
                    "固定记录 ${record.recordId}，结论来自包自身的回调约定与设备内核 BTF 合同的冲突。" +
                    "原因：${record.summary}。可查看报告入口了解已定位的冲突。${actionNote(action)}$caveat",
            )
        }

        // 包 hash 命中、但设备组合不在记录范围内：这是「未验证」，不是「已确认不兼容」。
        return verdict(
            decision = UltraModuleCompatibilityDecision.UNVERIFIED,
            codes = listOf(
                UltraModuleReasonCode.PACKAGE_HASH_MATCHED,
                UltraModuleReasonCode.DEVICE_COMBINATION_NOT_IN_RECORD,
            ) + scopeMismatch,
            action = action,
            matchedRecordId = record.recordId,
            displayReason = "未验证：模块包 ${record.id32}（版本 ${record.version}）与固定记录 ${record.recordId} " +
                "的包哈希一致，但这台设备的组合不在该记录已核对的范围内" +
                "（${scopeMismatch.joinToString("、") { it.code }}）。结论是未验证：既没有证明它兼容，" +
                "也没有证明它不兼容；本次「${action.label}」不按已验证路径处理。",
        )
    }

    // ------------------------------------------------------------------ 未命中记录

    private fun verdictForRecordMissed(
        records: List<UltraModuleCompatibilityRecord>,
        id32: String,
        version: String,
        archiveHash: String,
        payloadHash: String,
        action: UltraModuleAction,
    ): UltraModuleCompatibilityVerdict {
        val sameId = records.firstOrNull { it.id32.equals(id32, ignoreCase = true) }
            ?: return verdict(
                decision = UltraModuleCompatibilityDecision.UNVERIFIED,
                codes = listOf(UltraModuleReasonCode.PACKAGE_NOT_IN_RECORD),
                action = action,
                matchedRecordId = null,
                displayReason = "未验证：没有这个模块包的核对记录（id32 $id32 不在固定记录里）。" +
                    "未知不等于兼容：在取得实测证据之前不会把它显示为已兼容；它也没有被判定为已确认不兼容。",
            )

        val mismatch = ArrayList<UltraModuleReasonCode>(2)
        if (!sameId.archiveSha256.equals(archiveHash, ignoreCase = true)) {
            mismatch += UltraModuleReasonCode.PACKAGE_ARCHIVE_SHA256_MISMATCH
        }
        if (!sameId.nativePayloadSha256.equals(payloadHash, ignoreCase = true)) {
            mismatch += UltraModuleReasonCode.PACKAGE_NATIVE_PAYLOAD_SHA256_MISMATCH
        }

        if (version.isEmpty()) {
            return verdict(
                decision = UltraModuleCompatibilityDecision.UNVERIFIED,
                codes = listOf(UltraModuleReasonCode.PACKAGE_VERSION_MISSING) + mismatch,
                action = action,
                matchedRecordId = null,
                displayReason = "未验证：id32 $id32 有核对记录，但这个包的版本字段缺失，且包哈希与记录不一致，" +
                    "无法确认它是不是同一份内容。需要补齐版本与成员哈希后重新核验。",
            )
        }
        if (version == sameId.version) {
            return verdict(
                decision = UltraModuleCompatibilityDecision.UNVERIFIED,
                codes = listOf(UltraModuleReasonCode.PACKAGE_CONTENT_CHANGED) + mismatch,
                action = action,
                matchedRecordId = null,
                displayReason = "未验证：id32 与版本（$id32 / $version）与核对记录 ${sameId.recordId} 相同，" +
                    "但包内容哈希不同（${mismatch.joinToString("、") { it.code }}）。" +
                    "同样的名字和版本号可能是另一份字节，旧结论不能沿用，需要重新核验。",
            )
        }
        return verdict(
            decision = UltraModuleCompatibilityDecision.UNVERIFIED,
            codes = listOf(UltraModuleReasonCode.PACKAGE_VERSION_NOT_IN_RECORD),
            action = action,
            matchedRecordId = null,
            displayReason = "未验证：id32 $id32 有核对记录（版本 ${sameId.version}），但本次版本 $version " +
                "与包哈希都不在记录中。新版本需要单独核验，不按旧版本的结论推断。",
        )
    }

    // ------------------------------------------------------------------ 设备组合

    /**
     * 读到的内核变体相对记录的关系。四种状态必须显式区分，不能合并成「是否匹配」：
     *  - [RECORDED]：读到了，而且就是记录实测时所在的那个补丁集（k22）；
     *  - [SAME_BASE_KERNEL]：读到了，是**记录里已核对过同 base 内核**的另一个补丁集（k21）——
     *    「不在已验证范围」，但仍属于同一 base 内核上的同一类合同问题（见 [UltraDeviceScope]）；
     *  - [OTHER_UNRECOGNIZED]：读到了，但记录里**没有**它与记录变体共用 base 内核的证据
     *    （例如未来的 k23）。与「另一个 release」同类：不能伪判不兼容，按 UNVERIFIED 处理；
     *  - [UNKNOWN]：读不到（null/空）——不知道装的是哪一个，因此**既不能**排除 k22
     *    （所以不能放行），**也不能**确认就是 k22（所以不能宣称已验证）。
     */
    private enum class VariantRelation {
        RECORDED,
        SAME_BASE_KERNEL,
        OTHER_UNRECOGNIZED,
        UNKNOWN,
    }

    private fun UltraDeviceScope.variantRelation(kernel: UltraKernelIdentity): VariantRelation {
        val variant = kernel.variantId.orEmpty().trim()
        return when {
            variant.isEmpty() -> VariantRelation.UNKNOWN
            variant in kernelVariants -> VariantRelation.RECORDED
            variant in sameBaseKernelVariants -> VariantRelation.SAME_BASE_KERNEL
            else -> VariantRelation.OTHER_UNRECOGNIZED
        }
    }

    /**
     * 设备是否**精确**落在一条「已实测通过」的范围里。
     *
     * 已验证是**放行并宣称兼容**（不安全方向），所以要求最严：SDK 版本、内核 release 精确相等，
     * boot 摘要（给了就）匹配，**并且**变体必须读得到且正是记录变体。
     * 变体读不到时不能宣称已验证：否则「读不到」会在拦截一侧被当成「无法排除」、
     * 在放行一侧被当成「已核实」，同一个缺口得到两种相反待遇。
     *
     * 注意这里**不**判 SDK 清单是否核对（[UltraSdkIdentity.manifestVerified]）：
     * 那个条件决定的是「能不能宣称已验证」，由调用方在同一处显式处理，
     * 免得「清单没核对」被悄悄降级成「设备不在实测范围」。
     */
    private fun UltraDeviceScope.matchesVerifiedScope(
        sdk: UltraSdkIdentity,
        kernel: UltraKernelIdentity,
    ): Boolean = requiredMismatchCodes(sdk, kernel).isEmpty() &&
        bootMismatchCode(kernel) == null &&
        variantRelation(kernel) == VariantRelation.RECORDED

    /**
     * 必需项的不符项：SDK 版本与内核 release。空列表 = 这两项都落在记录里。
     *
     * 「其它内核未验证」这条结论由它保证：不同 release、不同 SDK 版本一律不命中，
     * 不会因为变体规则放宽就变成「所有内核都确认不兼容」。
     */
    private fun UltraDeviceScope.requiredMismatchCodes(
        sdk: UltraSdkIdentity,
        kernel: UltraKernelIdentity,
    ): List<UltraModuleReasonCode> {
        val codes = ArrayList<UltraModuleReasonCode>(2)
        val sdkVersion = sdk.version.trim()
        if (sdkVersion.isEmpty()) {
            codes += UltraModuleReasonCode.SDK_VERSION_MISSING
        } else if (sdkVersion !in sdkVersions) {
            codes += UltraModuleReasonCode.SDK_VERSION_NOT_IN_RECORD
        }
        val release = kernel.release.trim()
        if (release.isEmpty()) {
            codes += UltraModuleReasonCode.KERNEL_RELEASE_MISSING
        } else if (release != kernelRelease) {
            codes += UltraModuleReasonCode.KERNEL_RELEASE_NOT_IN_RECORD
        }
        return codes
    }

    /**
     * boot 镜像摘要的不符项：记录没固定 boot、或调用方没给 boot 时都不判（返回 null）。
     * 给了就必须落在集合里。
     *
     * boot 摘要识别的是「哪一个 boot 产物」，不是「哪一个内核补丁集」：它不能用来分辨
     * k21/k22，所以只在「变体已经确认是记录变体」时作为精确组合的强化项。
     */
    private fun UltraDeviceScope.bootMismatchCode(kernel: UltraKernelIdentity): UltraModuleReasonCode? {
        if (bootImageSha256s.isEmpty()) return null
        val boot = kernel.bootImageSha256.orEmpty().trim()
        if (boot.isEmpty()) return null
        return if (bootImageSha256s.none { it.equals(boot, ignoreCase = true) }) {
            UltraModuleReasonCode.KERNEL_BOOT_SHA256_NOT_IN_RECORD
        } else {
            null
        }
    }

    /**
     * 「已确认不兼容」范围的不符项。空列表 = 这台设备落在记录声明的**必需**范围内，
     * 结论是 KNOWN_INCOMPATIBLE（拦）。否则降级为 UNVERIFIED（不拦，也不宣称兼容）。
     *
     * ## 变体分四态，不再当必要条件（2026-10-31 W6-F2 口径）
     *
     * 旧规则把变体当「命中必要条件」，于是出现两个方向相反的处理：显式 k21 → 不拦；
     * 读不到变体 → 拦。那等于「证据越明确越不设防」，也与本文件「拿不准就拦」的原则冲突。
     * 现在以「包字节 + base 内核合同」这条结论为准，四种关系各有明确去向：
     *
     *  1. [VariantRelation.RECORDED]：精确命中，正常拦截；
     *  2. [VariantRelation.SAME_BASE_KERNEL]：记录里已核对过与记录变体**共用 base 内核**的
     *     另一个补丁集（k21）。回调类型合同来自 base 内核的 BTF（可复算：
     *     `ultra-kernels/manifest.json` 里两变体的 `baseKernelSha256` 相同；两份内核镜像除
     *     `0x8FCFB0` 的 4 字节外逐字节相同，内嵌 BTF 摘要也相同），所以同一类合同冲突仍然
     *     成立 → 拦，并附 [UltraModuleReasonCode.KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE] 标明是推断；
     *  3. [VariantRelation.OTHER_UNRECOGNIZED]：读到了，但记录里**没有**它与记录变体共用
     *     base 内核的证据（例如未来的 k23）。与「另一个 release」同类：不能伪判不兼容 →
     *     降级为 UNVERIFIED，原因码 [UltraModuleReasonCode.KERNEL_VARIANT_NOT_IN_RECORD]；
     *  4. [VariantRelation.UNKNOWN]：读不到 → 无法排除记录变体（k22）→ 拦，附
     *     [UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN]。
     *
     * 「共用 base 内核」能推出什么、不能推出什么，写在 [UltraDeviceScope]（Registry）里：
     * 能推出**回调类型合同相同**；不能推出**补丁语义/root/AVC 行为相同**，也不能替代设备实测。
     *
     * boot 摘要只在变体 = 记录变体时参与否决（见 [bootMismatchCode]）：变体明确同 base 或读不到时，
     * 结论已经是拦，boot 不能把它降级成放行；不认识的变体已经在第 3 条降级了。
     * 必需项（SDK 版本、release）不满足时仍然降级——那是「另一个组合」，不是同一 release 的补丁集。
     */
    private fun UltraDeviceScope.confirmedScopeMismatchCodes(
        sdk: UltraSdkIdentity,
        kernel: UltraKernelIdentity,
    ): List<UltraModuleReasonCode> {
        val codes = ArrayList<UltraModuleReasonCode>(requiredMismatchCodes(sdk, kernel))
        when (variantRelation(kernel)) {
            VariantRelation.RECORDED -> bootMismatchCode(kernel)?.let { codes += it }
            // 不认识的变体 id：没有该 build 的 base 内核/合同证据，和「另一个 release」同类。
            VariantRelation.OTHER_UNRECOGNIZED ->
                codes += UltraModuleReasonCode.KERNEL_VARIANT_NOT_IN_RECORD
            // 已核对同 base 内核的补丁集 / 读不到：结论都是拦（见上）。
            VariantRelation.SAME_BASE_KERNEL, VariantRelation.UNKNOWN -> Unit
        }
        return codes
    }

    /**
     * 变体证据的**注意码**：不改变「拦不拦」，但必须随回执一起展示。
     *
     * 每一项都对一个稳定原因码：
     *  - 记录变体 → 无注意码（精确命中）；
     *  - 已核对同 base 内核的补丁集 → [UltraModuleReasonCode.KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE]；
     *  - 读不到 → [UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN]；
     *  - 不认识的变体 → 无注意码（它在 [confirmedScopeMismatchCodes] 里已经降级为未验证，
     *    原因码是 [UltraModuleReasonCode.KERNEL_VARIANT_NOT_IN_RECORD]）。
     *
     * 为什么注意码不能进 [confirmedScopeMismatchCodes]：那会把它降级成「不在范围内 → 不拦」，
     * 正好把本文件要修的那个方向反过来；也不能什么都不说，那会把「没核实」当成「已核实」。
     */
    private fun UltraDeviceScope.advisoryCodes(
        kernel: UltraKernelIdentity,
    ): List<UltraModuleReasonCode> = when (variantRelation(kernel)) {
        VariantRelation.RECORDED, VariantRelation.OTHER_UNRECOGNIZED -> emptyList()
        VariantRelation.SAME_BASE_KERNEL -> listOf(UltraModuleReasonCode.KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE)
        VariantRelation.UNKNOWN -> listOf(UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN)
    }

    /** 每个入口为什么必须和安装一样被拦：这几个入口最容易被当成「只是看看而已」。 */
    private fun actionNote(action: UltraModuleAction): String = when (action) {
        UltraModuleAction.OPEN_WEBUI -> "打开页面同样会启动模块自己的原生实现，因此和安装一样被拦下。"
        UltraModuleAction.DEV_RUN_ONCE -> "单次运行会执行模块原生代码；进程退出不代表内核侧影响已经撤销，因此同样被拦下。"
        UltraModuleAction.MARKET_QUICK_ACTION -> "市场快捷任务走的是同一批原生入口，不能成为绕过检查的旁路。"
        UltraModuleAction.INSTALL, UltraModuleAction.UPDATE -> ""
    }

    private fun verdict(
        decision: UltraModuleCompatibilityDecision,
        codes: List<UltraModuleReasonCode>,
        action: UltraModuleAction,
        matchedRecordId: String?,
        displayReason: String,
    ): UltraModuleCompatibilityVerdict = UltraModuleCompatibilityVerdict(
        decision = decision,
        reasonCodes = codes.distinct().map { it.code },
        displayReason = displayReason,
        matchedRecordId = matchedRecordId,
        action = action,
    )
}

/**
 * 五个会真正让模块原生代码跑起来的入口。任何一个都不能因为「不是安装」而跳过兼容检查：
 * 开发单次运行、打开页面、市场快捷动作执行的仍是同一份 ELF。
 */
enum class UltraModuleAction(val label: String) {
    /**
     * 普通安装。安装动作本身只写文件，但安装完成后的首次加载会执行模块入口
     * （Ultra 宿主按 SDK 默认流程加载），所以检查必须在安装开始之前完成。
     */
    INSTALL("安装"),

    /**
     * 开发单次运行。进程退出不代表内核侧影响已经撤销（开发方案 §4.1），
     * 它和普通安装执行的是同一份原生代码，不能因为「只跑一次」就放行。
     */
    DEV_RUN_ONCE("开发单次运行"),

    /** 更新。换掉包等于换掉要执行的字节，旧版本的结论不能沿用到新包。 */
    UPDATE("更新"),

    /**
     * 打开页面。SDK 的 `start_module_web_ui_server_async` 拉起的是模块自己的 WebUI 实现
     * （冻结排查 §5），不是读静态 HTML，因此它同样执行模块原生代码，必须同样拦。
     */
    OPEN_WEBUI("打开页面"),

    /** 市场快捷动作（一键安装/运行）：走的是同一批原生入口，不能成为绕过检查的旁路。 */
    MARKET_QUICK_ACTION("市场快捷操作"),
}

/**
 * 一个模块包的身份，全部来自静态读取，不来自模块自己的口头声明。
 *
 * @param id32 Ultra 宿主的模块 id（32 位十六进制串）。
 * @param version 模块自己声明的版本号（module.prop 的 version）。只用于报告与「同版本内容变化」的
 *   诊断，**不参与**命中判定：版本号可以随便写，代表字节的是哈希。
 * @param archiveSha256 整个模块 ZIP 的 SHA256（十六进制，大小写不敏感）。
 * @param nativePayloadSha256 真正会被加载的那个原生成员（ELF）的 SHA256。读不到就传 null：
 *   null 表示证据不足，不表示「没有原生代码」，判定按 UNVERIFIED 处理。
 * @param nativeEntryName 原生成员在归档里的名字（如 `libmodule_app_auto_hider.so`）。只用于报告与
 *   人工核对：字节相同就是同一份代码，成员名的差异不改变判定。
 */
data class UltraModulePackageIdentity(
    val id32: String,
    val version: String,
    val archiveSha256: String,
    val nativePayloadSha256: String? = null,
    val nativeEntryName: String? = null,
)

/**
 * Ultra SDK / 宿主身份。
 *
 * @param version SDK 版本号（如 5.1.0）。
 * @param manifestVerified SDK 清单是否已按来源清单核对通过。它不改变「这个包已确认不兼容」的结论
 *   （那是包字节 + 设备组合的事实），但未核对时：不允许宣称已验证，且拦截结论会带上
 *   [UltraModuleReasonCode.SDK_MANIFEST_UNVERIFIED] 这条注意项。
 */
data class UltraSdkIdentity(
    val version: String,
    val manifestVerified: Boolean,
)

/**
 * 内核身份。
 *
 * @param release `uname -r` 的完整 release，例如
 *   `6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k`。这是**必需**项：不同 release
 *   就是另一个内核，一律判未验证。
 * @param variantId MapleSU 内核变体 id（k22 / k21 …），**只描述这台设备装的是哪个补丁集**，
 *   不参与包命中。四种取值对应四种结论（见 `UltraDeviceScope.variantRelation`）：
 *   记录变体（k22）→ 精确命中；记录里已核对同 base 内核的补丁集（k21）→ 仍拦 +
 *   `KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE`；null/空（应用读不到；当前生产路径就是这种情况）
 *   → 仍拦 + `KERNEL_VARIANT_UNKNOWN`；其它不认识的变体 id → 未验证 +
 *   `KERNEL_VARIANT_NOT_IN_RECORD`（没有该 build 的 base 内核/合同证据，不冒充同类推断）。
 *   回调类型合同在两份已核对的内核镜像上来自同一段 base 内核 BTF（可复算的核对见
 *   `UltraDeviceScope`），所以「读不到」不能被当成放行理由；但它也不能被当成「已验证」的理由。
 * @param bootImageSha256 当前 boot 镜像的 SHA256；可选。给了就必须与记录一致，没给不单独否决；
 *   它只在变体=记录变体时作为精确组合的强化项（boot 摘要分辨的是 boot 产物，不是补丁集）。
 */
data class UltraKernelIdentity(
    val release: String,
    val variantId: String? = null,
    val bootImageSha256: String? = null,
)

/** 判定结论。首版只会出现前两种；VERIFIED 需要真实验收记录才会出现。 */
enum class UltraModuleCompatibilityDecision {
    /**
     * 命中固定记录，且本机组合属于该记录已确认的不兼容类别：必须在进入原生执行之前拦下。
     *
     * 「类别」包括两种：精确命中实测组合；记录里**已核对过同 base 内核**的另一个补丁集
     * （后者带推断标记，见 `KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE`）。
     */
    KNOWN_INCOMPATIBLE,

    /**
     * 证据不足或不在记录范围：不显示为已兼容，也不宣称已确认不兼容。
     *
     * 注意它是**不拦**的：所以任何「本可以拦但证据不全」的情况都不应该落到这里，
     * 而应该由 `KNOWN_INCOMPATIBLE` + 注意码表达（见文件头「拿不准就拦」）。
     */
    UNVERIFIED,

    /** 命中一条带已验证范围的记录：只对记录里列出的动作成立。首版没有任何记录会走到这里。 */
    VERIFIED,
}

/**
 * 稳定机器码。UI、回执与测试只按这些字符串判断，中文只用于展示。
 * 名字一旦发布就不要改：日志与回执都按它对齐。
 */
enum class UltraModuleReasonCode(val code: String) {
    // ---- 包身份：证据够不够用
    PACKAGE_ID32_MISSING("PACKAGE_ID32_MISSING"),
    PACKAGE_ARCHIVE_SHA256_MISSING("PACKAGE_ARCHIVE_SHA256_MISSING"),
    PACKAGE_ARCHIVE_SHA256_MALFORMED("PACKAGE_ARCHIVE_SHA256_MALFORMED"),
    PACKAGE_NATIVE_PAYLOAD_SHA256_MISSING("PACKAGE_NATIVE_PAYLOAD_SHA256_MISSING"),
    PACKAGE_NATIVE_PAYLOAD_SHA256_MALFORMED("PACKAGE_NATIVE_PAYLOAD_SHA256_MALFORMED"),

    // ---- 命中固定记录之后的细分
    PACKAGE_HASH_MATCHED("PACKAGE_HASH_MATCHED"),
    DEVICE_COMBINATION_IN_RECORD("DEVICE_COMBINATION_IN_RECORD"),
    DEVICE_COMBINATION_NOT_IN_RECORD("DEVICE_COMBINATION_NOT_IN_RECORD"),
    DEVICE_COMBINATION_IN_VERIFIED_SCOPE("DEVICE_COMBINATION_IN_VERIFIED_SCOPE"),
    ACTION_NOT_IN_VERIFIED_SCOPE("ACTION_NOT_IN_VERIFIED_SCOPE"),

    // ---- 未命中：同 id32 但内容或版本不同
    PACKAGE_CONTENT_CHANGED("PACKAGE_CONTENT_CHANGED"),
    PACKAGE_ARCHIVE_SHA256_MISMATCH("PACKAGE_ARCHIVE_SHA256_MISMATCH"),
    PACKAGE_NATIVE_PAYLOAD_SHA256_MISMATCH("PACKAGE_NATIVE_PAYLOAD_SHA256_MISMATCH"),
    PACKAGE_VERSION_MISSING("PACKAGE_VERSION_MISSING"),
    PACKAGE_VERSION_NOT_IN_RECORD("PACKAGE_VERSION_NOT_IN_RECORD"),
    PACKAGE_NOT_IN_RECORD("PACKAGE_NOT_IN_RECORD"),

    // ---- SDK 身份
    SDK_VERSION_MISSING("SDK_VERSION_MISSING"),
    SDK_VERSION_NOT_IN_RECORD("SDK_VERSION_NOT_IN_RECORD"),

    /**
     * SDK 清单没核对通过。它不影响「已确认不兼容」的判定（那是包字节的事实），
     * 但会阻止宣称「已验证」，并作为注意项记进拦截结果。
     */
    SDK_MANIFEST_UNVERIFIED("SDK_MANIFEST_UNVERIFIED"),

    // ---- 内核身份
    KERNEL_RELEASE_MISSING("KERNEL_RELEASE_MISSING"),
    KERNEL_RELEASE_NOT_IN_RECORD("KERNEL_RELEASE_NOT_IN_RECORD"),

    /**
     * 内核补丁集（变体 id，如 k21/k22）读不到。
     *
     * **这是注意码，不是不符项**：读不到时不否决拦截（因为无法排除「就是实测不兼容的 k22」），
     * 也不允许宣称已验证（因为无法确认「就是实测通过的 k22」）。它随结论一起返回，
     * 回执与 UI 必须原样展示——「没核实」不能被当成「已核实」。
     */
    KERNEL_VARIANT_UNKNOWN("KERNEL_VARIANT_UNKNOWN"),

    /**
     * 读到了内核补丁集，而且记录里已核对过它与记录变体**共用同一个 base 内核**（本机 k21、
     * 记录 k22）。
     *
     * **这是注意码，不是不符项**：记录已核对过同 base 内核的另一个补丁集仍属于同一类回调
     * 类型冲突，因此仍判 KNOWN_INCOMPATIBLE；本码标明「不在已验证范围、结论含推断成分」。
     * 见 `UltraDeviceScope.confirmedScopeMismatchCodes` 与文件头。
     */
    KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE("KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE"),

    /**
     * 读到了内核补丁集，但记录里**没有**它与记录变体共用 base 内核的证据（例如未来的 k23）。
     *
     * 与「另一个 release」同类：没有该 build 的合同证据，不能伪判不兼容，所以它出现在
     * UNVERIFIED 的分支里（不拦，也不宣称兼容）。它与 [KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE]
     * 的区别是**有没有 base 内核核对**：有 → 同类推断仍拦；没有 → 未验证。
     */
    KERNEL_VARIANT_NOT_IN_RECORD("KERNEL_VARIANT_NOT_IN_RECORD"),
    KERNEL_BOOT_SHA256_NOT_IN_RECORD("KERNEL_BOOT_SHA256_NOT_IN_RECORD"),
}

/**
 * 一次判定的结果。
 *
 * `matchedRecordId` 只在包的三项哈希真正命中固定记录时才有值：这样报告入口知道该展开哪条记录，
 * 也避免把「只是同一个 id32」误读成「已核对过这个包」。
 */
data class UltraModuleCompatibilityVerdict(
    val decision: UltraModuleCompatibilityDecision,
    val reasonCodes: List<String>,
    val displayReason: String,
    val matchedRecordId: String?,
    val action: UltraModuleAction,
) {
    /**
     * 是否必须在进入原生执行之前结束这一步。首版只有「已确认不兼容」为 true。
     *
     * UNVERIFIED **不是**授权：它同样不能显示成「已兼容」；是否允许继续由产品入口决定，
     * 但任何继续都必须保留「未验证」这个事实。
     *
     * 方向不对称是故意的：拦住是安全方向（功能不可用，可解释、可恢复），放行宣称兼容是
     * 不安全方向（模块原生代码按错误合同进内核，代价是 panic/重启）。所以「证据不全」的
     * 内核变体问题走 KNOWN_INCOMPATIBLE + 注意码，而不是走这个 false。
     */
    val blocksNativeExecution: Boolean
        get() = decision == UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE

    fun hasCode(code: String): Boolean = code in reasonCodes

    fun hasCode(reason: UltraModuleReasonCode): Boolean = reason.code in reasonCodes
}
