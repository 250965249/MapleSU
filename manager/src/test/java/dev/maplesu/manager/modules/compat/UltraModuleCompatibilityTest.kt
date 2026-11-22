package dev.maplesu.manager.modules.compat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Ultra 模块兼容判定的可执行规格。
 *
 * 这些用例本身就是开发方案 §8.1 H1 的「静态判定本次已知组合」：同一组身份必须得到
 * KNOWN_INCOMPATIBLE，而任何证据不足的情况都必须停在 UNVERIFIED，不能靠模块名或版本号
 * 推断兼容。固定身份全部来自冻结排查结论，测试里重复写一遍是为了让「改动这些值」必然失败。
 */
class UltraModuleCompatibilityTest {

    // ------------------------------------------------------------------ 固定身份

    private companion object {
        const val ID32 = "cd08ae9eef7bb885c06f80ef3aea1d5c"
        const val VERSION = "1.9.3"
        const val ARCHIVE_SHA256 = "2fdc08482075a9865d49e2595a2487f07a37ab499aab744d8d9bb09a098d4a31"
        const val PAYLOAD_SHA256 = "a0835b667db5ed33a12b7fa2d2f8ba9ee58b8f7fd538250b62111cffd2a647dc"
        const val NATIVE_ENTRY = "libmodule_app_auto_hider.so"
        const val KERNEL_RELEASE = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
        const val BOOT_SHA256 = "47aa147acbe3edf8e58ce60d334ad4c4b26cad26b5cb93aa6acb59a67fdd5f59"
        const val SDK_VERSION = "5.1.0"
        const val KERNEL_VARIANT = "k22"
    }

    /** 与任何固定记录都不相等的合法哈希。 */
    private val otherSha256 = "f".repeat(64)

    /** 变体三态矩阵的一行（测试辅助，不是产品逻辑）。 */
    private data class VariantCase(
        val label: String,
        val kernel: UltraKernelIdentity,
        val advisory: UltraModuleReasonCode?,
        val claimsExactCombination: Boolean,
    )

    // ------------------------------------------------------------------ 夹具

    private fun pkg(
        id32: String = ID32,
        version: String = VERSION,
        archiveSha256: String = ARCHIVE_SHA256,
        nativePayloadSha256: String? = PAYLOAD_SHA256,
        nativeEntryName: String? = NATIVE_ENTRY,
    ) = UltraModulePackageIdentity(id32, version, archiveSha256, nativePayloadSha256, nativeEntryName)

    private fun sdk(
        version: String = SDK_VERSION,
        manifestVerified: Boolean = true,
    ) = UltraSdkIdentity(version, manifestVerified)

    private fun kernel(
        release: String = KERNEL_RELEASE,
        variantId: String? = KERNEL_VARIANT,
        bootImageSha256: String? = BOOT_SHA256,
    ) = UltraKernelIdentity(release, variantId, bootImageSha256)

    private fun evaluate(
        packageIdentity: UltraModulePackageIdentity = pkg(),
        sdkIdentity: UltraSdkIdentity = sdk(),
        kernelIdentity: UltraKernelIdentity = kernel(),
        action: UltraModuleAction = UltraModuleAction.INSTALL,
        records: List<UltraModuleCompatibilityRecord> = UltraModuleCompatibilityRegistry.records,
    ) = UltraModuleCompatibility.evaluate(packageIdentity, sdkIdentity, kernelIdentity, action, records)

    // ------------------------------------------------------------------ 命中

    @Test
    fun exactPackageIdentityIsKnownIncompatible() {
        val verdict = evaluate(pkg())
        assertEquals(UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE, verdict.decision)
        assertEquals(UltraModuleCompatibilityRegistry.AAH_MARKET_1_9_3, verdict.matchedRecordId)
        assertTrue(verdict.hasCode(UltraModuleReasonCode.PACKAGE_HASH_MATCHED))
        assertTrue(verdict.hasCode(UltraModuleReasonCode.DEVICE_COMBINATION_IN_RECORD))
        assertTrue(verdict.blocksNativeExecution)
        assertTrue(verdict.displayReason.contains(ID32))
        assertTrue(verdict.displayReason.contains(VERSION))
    }

    @Test
    fun hashComparisonIsCaseInsensitive() {
        val verdict = evaluate(
            pkg(archiveSha256 = ARCHIVE_SHA256.uppercase(), nativePayloadSha256 = PAYLOAD_SHA256.uppercase()),
        )
        assertEquals(UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE, verdict.decision)
    }

    // ------------------------------------------------------------------ 包内容变化

    @Test
    fun changedNativePayloadHashIsContentChangedNotIncompatible() {
        val verdict = evaluate(pkg(nativePayloadSha256 = otherSha256))
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, verdict.decision)
        assertFalse(verdict.blocksNativeExecution)
        assertTrue(verdict.hasCode(UltraModuleReasonCode.PACKAGE_CONTENT_CHANGED))
        assertTrue(verdict.hasCode(UltraModuleReasonCode.PACKAGE_NATIVE_PAYLOAD_SHA256_MISMATCH))
        // 归档没变，就不该报归档不匹配
        assertFalse(verdict.hasCode(UltraModuleReasonCode.PACKAGE_ARCHIVE_SHA256_MISMATCH))
        // 三项哈希没有同时命中，就不算「核对过这个包」
        assertNull(verdict.matchedRecordId)
    }

    @Test
    fun changedArchiveHashOnSameVersionIsContentChanged() {
        val verdict = evaluate(pkg(archiveSha256 = otherSha256))
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, verdict.decision)
        assertTrue(verdict.hasCode(UltraModuleReasonCode.PACKAGE_CONTENT_CHANGED))
        assertTrue(verdict.hasCode(UltraModuleReasonCode.PACKAGE_ARCHIVE_SHA256_MISMATCH))
        assertFalse(verdict.hasCode(UltraModuleReasonCode.PACKAGE_NATIVE_PAYLOAD_SHA256_MISMATCH))
        assertNull(verdict.matchedRecordId)
    }

    @Test
    fun newerVersionOfRecordedPackageIsUnverified() {
        val verdict = evaluate(
            pkg(version = "1.9.4", archiveSha256 = otherSha256, nativePayloadSha256 = otherSha256),
        )
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, verdict.decision)
        assertTrue(verdict.hasCode(UltraModuleReasonCode.PACKAGE_VERSION_NOT_IN_RECORD))
        assertNull(verdict.matchedRecordId)
    }

    // ------------------------------------------------------------------ 证据不足

    @Test
    fun missingHashesAreUnverifiedInsteadOfGuessed() {
        val noPayload = evaluate(pkg(nativePayloadSha256 = null))
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, noPayload.decision)
        assertTrue(noPayload.hasCode(UltraModuleReasonCode.PACKAGE_NATIVE_PAYLOAD_SHA256_MISSING))
        assertFalse(noPayload.blocksNativeExecution)
        assertNull(noPayload.matchedRecordId)

        val noArchive = evaluate(pkg(archiveSha256 = ""))
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, noArchive.decision)
        assertTrue(noArchive.hasCode(UltraModuleReasonCode.PACKAGE_ARCHIVE_SHA256_MISSING))

        val bothMissing = evaluate(pkg(archiveSha256 = "  ", nativePayloadSha256 = " "))
        assertTrue(bothMissing.hasCode(UltraModuleReasonCode.PACKAGE_ARCHIVE_SHA256_MISSING))
        assertTrue(bothMissing.hasCode(UltraModuleReasonCode.PACKAGE_NATIVE_PAYLOAD_SHA256_MISSING))

        val malformed = evaluate(pkg(archiveSha256 = "not-a-sha256"))
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, malformed.decision)
        assertTrue(malformed.hasCode(UltraModuleReasonCode.PACKAGE_ARCHIVE_SHA256_MALFORMED))

        val noId = evaluate(pkg(id32 = "   "))
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, noId.decision)
        assertTrue(noId.hasCode(UltraModuleReasonCode.PACKAGE_ID32_MISSING))
    }

    @Test
    fun completelyUnknownPackageIsUnverifiedNotIncompatible() {
        val verdict = evaluate(
            pkg(id32 = "0123456789abcdef0123456789abcdef", archiveSha256 = otherSha256, nativePayloadSha256 = otherSha256),
        )
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, verdict.decision)
        assertTrue(verdict.hasCode(UltraModuleReasonCode.PACKAGE_NOT_IN_RECORD))
        assertNull(verdict.matchedRecordId)
        assertFalse(verdict.blocksNativeExecution)
        assertFalse("未知包不能被写成已拦截", verdict.displayReason.contains("已拦截"))
        assertTrue("未知包必须说明未验证", verdict.displayReason.contains("未验证"))
    }

    // ------------------------------------------------------------------ 设备组合

    @Test
    fun differentKernelReleaseIsUnverified() {
        val verdict = evaluate(kernelIdentity = kernel(release = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-NOTK22"))
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, verdict.decision)
        assertTrue(verdict.hasCode(UltraModuleReasonCode.PACKAGE_HASH_MATCHED))
        assertTrue(verdict.hasCode(UltraModuleReasonCode.DEVICE_COMBINATION_NOT_IN_RECORD))
        assertTrue(verdict.hasCode(UltraModuleReasonCode.KERNEL_RELEASE_NOT_IN_RECORD))
        assertFalse(verdict.blocksNativeExecution)
        // 包 hash 命中过，所以仍然能指向那条记录（报告入口用）
        assertEquals(UltraModuleCompatibilityRegistry.AAH_MARKET_1_9_3, verdict.matchedRecordId)
    }

    @Test
    fun everyKernelVariantStateKeepsBlockingWithItsOwnReasonCode() {
        // 三种输入 × 同一结论：都拦。这是 W6-F2 修的方向——旧规则是「显式 k21 放行、读不到变体拦」，
        // 等于「证据越明确越不设防」。现在三种状态都以「包字节 + base 内核合同」这条结论为准：
        //  - k22：精确命中实测组合；
        //  - 未知：无法排除「就是 k22」，所以不能放行；
        //  - k21：同一 release、同一 base 内核上的另一个补丁集，回调类型合同相同（推断），同样拦。
        // 每条都断言对应注意码：结论对了但理由丢了，等于下次又会被改回去。
        val cases = listOf(
            VariantCase("记录变体 k22", kernel(variantId = "k22"), null, true),
            VariantCase("未知变体", kernel(variantId = null), UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN, true),
            VariantCase(
                "同一 release 的另一个补丁集 k21",
                kernel(variantId = "k21", bootImageSha256 = null),
                UltraModuleReasonCode.KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE,
                false,
            ),
        )

        cases.forEach { case ->
            val verdict = evaluate(kernelIdentity = case.kernel)
            assertEquals(
                "「${case.label}」必须拦：包字节命中后结论来自包实现与设备 BTF 合同的冲突，与补丁集无关",
                UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE,
                verdict.decision,
            )
            assertTrue("「${case.label}」必须拦下原生执行", verdict.blocksNativeExecution)
            assertEquals(
                "包哈希命中必须仍然指向那条记录（报告入口要用）",
                UltraModuleCompatibilityRegistry.AAH_MARKET_1_9_3,
                verdict.matchedRecordId,
            )
            if (case.advisory == null) {
                assertFalse(
                    "精确命中时不该有变体注意码",
                    verdict.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN) ||
                        verdict.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE),
                )
            } else {
                assertTrue(
                    "「${case.label}」必须带注意码 ${case.advisory.code}（为什么拦要能机器读出）",
                    verdict.hasCode(case.advisory),
                )
            }
            assertEquals(
                "「${case.label}」是否声明「在记录内」必须与它是否精确命中一致（推断不能写成核实）",
                case.claimsExactCombination,
                verdict.hasCode(UltraModuleReasonCode.DEVICE_COMBINATION_IN_RECORD),
            )
            assertFalse(
                "变体三态都不该再产出旧降级码 KERNEL_VARIANT_NOT_IN_RECORD",
                verdict.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_NOT_IN_RECORD),
            )
        }
    }

    @Test
    fun explicitOtherPatchSetIsBlockedWithAnInferenceCaveat() {
        // 选 (i)：显式 k21 也判 KNOWN_INCOMPATIBLE。
        // 理由：回调类型合同来自 base 内核的 BTF，与补丁集无关——manifest 两变体的
        // baseKernelSha256 相同；两份内核镜像逐字节比较只差 0x8FCFB0 的 4 字节，
        // 内嵌 BTF 摘要也相同。所以同一类合同冲突在 k21 上仍然成立。
        // 但这是推断：没有在 k21 设备上实测，也没有逐补丁做语义审阅——所以必须带注意码，
        // 不能静默等同于 k22。
        val k21 = evaluate(kernelIdentity = kernel(variantId = "k21", bootImageSha256 = null))
        assertEquals(UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE, k21.decision)
        assertTrue(k21.blocksNativeExecution)
        assertTrue(k21.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE))
        assertFalse(k21.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN))
        assertFalse(
            "k21 不是实测组合，不能声明「在记录内」（复核 S2-4 的原因码过度声称）",
            k21.hasCode(UltraModuleReasonCode.DEVICE_COMBINATION_IN_RECORD),
        )
        assertTrue("拦截文案必须仍然说已拦截", k21.displayReason.contains("已拦截"))
        assertTrue(
            "推断必须写进文案，并按稳定码可检索",
            k21.displayReason.contains(UltraModuleReasonCode.KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE.code),
        )

        // k21 自己真实的 boot 摘要（manifest 的 knownBaseImageBootSha256）也不能把拦截降级成放行：
        // boot 摘要分辨的是 boot 产物、不是补丁集；变体明确不是记录变体时，结论已经是拦，
        // 拿 boot 否决会重新制造「证据越明确越不设防」。
        val k21WithItsOwnBoot = evaluate(
            kernelIdentity = kernel(
                variantId = "k21",
                bootImageSha256 = "6c7a451d0f6675d358ac0bcca7979a83fb30051d30d301a22ecec8d6da9ff5c2",
            ),
        )
        assertEquals(
            "显式 k21 + k21 自己的 boot 摘要仍必须拦",
            UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE,
            k21WithItsOwnBoot.decision,
        )
        assertTrue(
            k21WithItsOwnBoot.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE),
        )
    }

    @Test
    fun unreadableKernelVariantStillHitsTheConfirmedCombination() {
        // 读不到变体 → **无法排除**「装的就是实测不兼容的 k22」，所以不能放行。
        // 这与 k21 的方向一致（都拦），区别只在注意码：这里不是「推断同类」，而是「证据缺口」。
        // 反过来，「读不到」也不能被当成「已验证」的理由（见 matchesVerifiedScope）。
        val unknown = evaluate(kernelIdentity = kernel(variantId = null))
        assertEquals(UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE, unknown.decision)
        assertTrue(unknown.blocksNativeExecution)
        assertTrue(unknown.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN))
        assertFalse(unknown.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE))
        assertTrue("必需项（SDK/release）仍在记录内", unknown.hasCode(UltraModuleReasonCode.DEVICE_COMBINATION_IN_RECORD))
        assertFalse("读不到变体不是「不匹配」，不该报旧降级码", unknown.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_NOT_IN_RECORD))
        assertTrue("拦截文案必须仍然说已拦截", unknown.displayReason.contains("已拦截"))
        assertTrue(
            "证据缺口必须写进文案（注意码）",
            unknown.displayReason.contains(UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN.code),
        )
        // 相邻分支也不能被带偏：release 相同但变体读不到，仍然指向那条记录。
        assertEquals(UltraModuleCompatibilityRegistry.AAH_MARKET_1_9_3, unknown.matchedRecordId)
    }

    @Test
    fun unrecognizedKernelVariantIsUnverifiedNotBlocked() {
        // 读到了一个本记录**不认识**的变体 id（例如未来的 k23）：记录里没有它与 k22 共用 base
        // 内核的证据，所以不能像 k21 那样断言「同类合同冲突仍然成立」。与「另一个 release」
        // 同类：没有该 build 的证据 → UNVERIFIED（不拦，也不宣称兼容），原因码点名变体不在记录。
        // 这条用例防止把「k21 与 k22 共用 base 内核」外推成「所有变体都共用」。
        val k23 = evaluate(kernelIdentity = kernel(variantId = "k23", bootImageSha256 = null))
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, k23.decision)
        assertFalse(k23.blocksNativeExecution)
        assertTrue(k23.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_NOT_IN_RECORD))
        assertFalse(k23.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_OUT_OF_VERIFIED_SCOPE))
        assertFalse(k23.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN))
        // 包 hash 命中过，报告入口仍能指向那条记录。
        assertEquals(UltraModuleCompatibilityRegistry.AAH_MARKET_1_9_3, k23.matchedRecordId)
    }

    @Test
    fun unreadableVariantDoesNotWidenTheKernelGateToOtherCombinations() {
        // 放宽变体不等于放宽「其它内核/其它 SDK 未验证」：不同 release 一律 UNVERIFIED。
        val otherRelease = evaluate(
            kernelIdentity = kernel(
                release = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-NOTK22",
                variantId = null,
            ),
        )
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, otherRelease.decision)
        assertTrue(otherRelease.hasCode(UltraModuleReasonCode.KERNEL_RELEASE_NOT_IN_RECORD))
        assertFalse(otherRelease.blocksNativeExecution)
        assertEquals(UltraModuleCompatibilityRegistry.AAH_MARKET_1_9_3, otherRelease.matchedRecordId)

        // 不同 SDK 版本同理。
        val otherSdk = evaluate(
            sdkIdentity = sdk(version = "4.6.4"),
            kernelIdentity = kernel(variantId = null),
        )
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, otherSdk.decision)
        assertTrue(otherSdk.hasCode(UltraModuleReasonCode.SDK_VERSION_NOT_IN_RECORD))
        assertFalse(otherSdk.blocksNativeExecution)
    }

    @Test
    fun untestedBootImageIsUnverifiedButAbsentBootHashIsNotFatal() {
        val otherBoot = evaluate(kernelIdentity = kernel(bootImageSha256 = otherSha256))
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, otherBoot.decision)
        assertTrue(otherBoot.hasCode(UltraModuleReasonCode.KERNEL_BOOT_SHA256_NOT_IN_RECORD))
        assertTrue(otherBoot.hasCode(UltraModuleReasonCode.DEVICE_COMBINATION_NOT_IN_RECORD))

        // boot 哈希可选：release + 变体已经钉住那个 build，没读到时不影响已确认结论。
        val noBoot = evaluate(kernelIdentity = kernel(bootImageSha256 = null))
        assertEquals(UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE, noBoot.decision)
        assertTrue(noBoot.blocksNativeExecution)
    }

    @Test
    fun differentSdkVersionIsUnverified() {
        val olderSdk = evaluate(sdkIdentity = sdk(version = "4.6.4"))
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, olderSdk.decision)
        assertTrue(olderSdk.hasCode(UltraModuleReasonCode.SDK_VERSION_NOT_IN_RECORD))
        assertFalse(olderSdk.blocksNativeExecution)

        val missingSdk = evaluate(sdkIdentity = sdk(version = ""))
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, missingSdk.decision)
        assertTrue(missingSdk.hasCode(UltraModuleReasonCode.SDK_VERSION_MISSING))
    }

    @Test
    fun unverifiedSdkManifestKeepsBlockingWithACaveat() {
        // 「这个包已确认不兼容」是包字节 + 设备组合的事实，不因为 SDK 清单没核对就变成未验证：
        // 那会让已知不兼容的包从拦截路径漏过去。清单状态作为注意项记下来。
        val verdict = evaluate(sdkIdentity = sdk(manifestVerified = false))
        assertEquals(UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE, verdict.decision)
        assertTrue(verdict.blocksNativeExecution)
        assertTrue(verdict.hasCode(UltraModuleReasonCode.SDK_MANIFEST_UNVERIFIED))
        assertTrue(verdict.hasCode(UltraModuleReasonCode.DEVICE_COMBINATION_IN_RECORD))
        assertTrue(verdict.displayReason.contains("SDK"))
    }

    // ------------------------------------------------------------------ 五个动作

    @Test
    fun everyActionIsJudgedAndAllFiveAreBlocked() {
        assertEquals(5, UltraModuleAction.entries.size)
        UltraModuleAction.entries.forEach { action ->
            val verdict = evaluate(action = action)
            assertEquals(
                "动作 $action 必须能判定：精确命中就是已确认不兼容",
                UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE,
                verdict.decision,
            )
            assertTrue("动作 $action 必须拦下原生执行", verdict.blocksNativeExecution)
            assertEquals(action, verdict.action)
            assertTrue("展示文案必须提到动作标签", verdict.displayReason.contains(action.label))
        }

        // OPEN_WEBUI 不是只读操作：SDK 拉起的是模块自己的原生 WebUI 实现。
        val webUi = evaluate(action = UltraModuleAction.OPEN_WEBUI)
        assertEquals(UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE, webUi.decision)
        assertTrue(webUi.displayReason.contains("原生"))
    }

    @Test
    fun unknownPackageIsUnverifiedForEveryActionToo() {
        UltraModuleAction.entries.forEach { action ->
            val verdict = evaluate(pkg(id32 = "ffffffffffffffffffffffffffffffff"), action = action)
            assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, verdict.decision)
            assertEquals(action, verdict.action)
            assertFalse(verdict.blocksNativeExecution)
        }
    }

    // ------------------------------------------------------------------ 可复现

    @Test
    fun sameInputProducesEqualVerdictAndNoHiddenState() {
        val first = evaluate()
        val second = evaluate()
        assertEquals(first, second)
        assertEquals(first.reasonCodes, second.reasonCodes)
        assertEquals(first.displayReason, second.displayReason)

        // 中间夹几次别的输入，再算一次：判定不能留下任何跨调用状态。
        evaluate(pkg(nativePayloadSha256 = null))
        evaluate(pkg(id32 = "ffffffffffffffffffffffffffffffff"))
        evaluate(kernelIdentity = kernel(variantId = "k21"))
        assertEquals(first, evaluate())
    }

    // ------------------------------------------------------------------ 扩展点

    @Test
    fun verifiedExtensionPointOnlyCoversRecordedActions() {
        // 合成记录：只用来证明「有实测证据才可能 VERIFIED」这条扩展点是活的，
        // 不是产品数据，也不会进入 UltraModuleCompatibilityRegistry。
        val device = UltraDeviceScope(
            sdkVersions = setOf(SDK_VERSION),
            kernelRelease = KERNEL_RELEASE,
            kernelVariants = setOf(KERNEL_VARIANT),
            bootImageSha256s = setOf(BOOT_SHA256),
        )
        val synthetic = UltraModuleCompatibilityRecord(
            recordId = "synthetic-verified-record",
            id32 = ID32,
            version = VERSION,
            archiveSha256 = ARCHIVE_SHA256,
            nativePayloadSha256 = PAYLOAD_SHA256,
            nativeEntryName = NATIVE_ENTRY,
            incompatibleScope = device,
            verifiedScopes = listOf(
                UltraVerifiedScope(
                    id = "synthetic-verified-scope",
                    device = device,
                    actions = setOf(UltraModuleAction.OPEN_WEBUI),
                    evidence = emptyList(),
                ),
            ),
            summary = "synthetic",
            evidence = emptyList(),
        )
        val records = listOf(synthetic)

        val verified = evaluate(action = UltraModuleAction.OPEN_WEBUI, records = records)
        assertEquals(UltraModuleCompatibilityDecision.VERIFIED, verified.decision)
        assertTrue(verified.hasCode(UltraModuleReasonCode.DEVICE_COMBINATION_IN_VERIFIED_SCOPE))
        assertFalse(verified.blocksNativeExecution)
        assertEquals("synthetic-verified-record", verified.matchedRecordId)

        // 只有列进 actions 的入口才算通过，其余保持 UNVERIFIED（逐路径验收）。
        val install = evaluate(action = UltraModuleAction.INSTALL, records = records)
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, install.decision)
        assertTrue(install.hasCode(UltraModuleReasonCode.ACTION_NOT_IN_VERIFIED_SCOPE))

        // 已验证范围必须**精确**：变体读不到时不能宣称 VERIFIED（放行宣称兼容是不安全方向）。
        // 同一条记录、同一个动作，只把变体改成「读不到」：不能拿到 VERIFIED。
        val unknownVariant = evaluate(
            kernelIdentity = kernel(variantId = null),
            action = UltraModuleAction.OPEN_WEBUI,
            records = records,
        )
        assertFalse(
            "读不到变体时不允许宣称已验证：那是放行并宣称兼容的方向",
            unknownVariant.decision == UltraModuleCompatibilityDecision.VERIFIED,
        )
        assertFalse(unknownVariant.hasCode(UltraModuleReasonCode.DEVICE_COMBINATION_IN_VERIFIED_SCOPE))
        assertTrue(unknownVariant.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN))
    }

    // ------------------------------------------------------------------ 记录本身

    @Test
    fun registryPinsTheConfirmedIdentity() {
        assertEquals(1, UltraModuleCompatibilityRegistry.records.size)
        val record = UltraModuleCompatibilityRegistry.records.single()
        assertEquals(UltraModuleCompatibilityRegistry.AAH_MARKET_1_9_3, record.recordId)
        assertEquals(ID32, record.id32)
        assertEquals(VERSION, record.version)
        assertEquals(ARCHIVE_SHA256, record.archiveSha256)
        assertEquals(PAYLOAD_SHA256, record.nativePayloadSha256)
        assertEquals(NATIVE_ENTRY, record.nativeEntryName)
        assertEquals(setOf(SDK_VERSION), record.incompatibleScope.sdkVersions)
        assertEquals(KERNEL_RELEASE, record.incompatibleScope.kernelRelease)
        assertEquals(setOf(KERNEL_VARIANT), record.incompatibleScope.kernelVariants)
        assertEquals(setOf(BOOT_SHA256), record.incompatibleScope.bootImageSha256s)
        // 只有 k21 被核对过与 k22 共用 base 内核；这个集合不能随手加（加了就等于把
        // 「共用 base 内核」外推到没核对过的变体）。见 W6-F2 EVIDENCE §3。
        assertEquals(setOf("k21"), record.incompatibleScope.sameBaseKernelVariants)
        // 首版没有通过任何功能路径的验收，不允许出现 VERIFIED 数据。
        assertTrue(record.verifiedScopes.isEmpty())
        assertTrue(record.evidence.isNotEmpty())
        assertTrue(record.summary.isNotBlank())
    }

    @Test
    fun reasonCodesAreStableMachineReadableAndUnique() {
        val codes = UltraModuleReasonCode.entries.map { it.code }
        assertEquals(codes.size, codes.toSet().size)
        codes.forEach { code ->
            assertTrue("原因码必须是大写机器码：$code", Regex("^[A-Z][A-Z0-9_]*$").matches(code))
        }
        // 记录里没有任何一项是空字符串，避免 UI 拿到空原因。
        codes.forEach { assertTrue(it.isNotBlank()) }
    }

    @Test
    fun everyVerdictCarriesADisplayableReason() {
        val verdicts = listOf(
            evaluate(),
            evaluate(pkg(nativePayloadSha256 = null)),
            evaluate(kernelIdentity = kernel(release = "6.6.89-other")),
            evaluate(kernelIdentity = kernel(variantId = "k21")),
            evaluate(sdkIdentity = sdk(manifestVerified = false)),
            evaluate(pkg(id32 = "ffffffffffffffffffffffffffffffff")),
        )
        verdicts.forEach { verdict ->
            assertTrue(verdict.displayReason.isNotBlank())
            assertTrue(verdict.reasonCodes.isNotEmpty())
            verdict.reasonCodes.forEach { assertTrue(it.isNotBlank()) }
        }
    }
}
