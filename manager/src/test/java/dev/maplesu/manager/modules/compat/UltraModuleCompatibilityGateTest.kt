package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.ModuleArchiveInspector
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.CRC32
import java.util.zip.ZipEntry

/**
 * `UltraModuleCompatibilityGate` 的可执行规格（W2-0，H1 的判定面）。
 *
 * 覆盖两件事：
 *  1. **映射**：`ModuleArchiveInspector.Report` → `UltraModulePackageIdentity` 逐字段正确
 *     （用真实合成 MAPLESU 归档跑 `inspect()`，不是拿字符串硬拼）；
 *  2. **判定/文案/事件**：本机已确认组合在五个动作下都是 `KNOWN_INCOMPATIBLE`，读不到内核变体
 *     仍然命中但带注意码，未知包停在 `UNVERIFIED` 且文案不写「已拦截」，证据事件可编码可复读。
 *
 * 夹具说明：合成 MAPLESU ELF 与 W1-B 的 `ModuleArchiveInspectorTest.mapleSuElf()` 同构
 * （一个可执行 `PT_LOAD`、一个 `SHT_DYNSYM`、一个已定义导出入口、五段 metadata 标记）。
 * 本轮只允许改自己名下的文件，所以这里复制一份并在注释里标注来源；构造的是**真的**能被
 * `MapleSuModuleMetadata.inspect` 命中的入口，断言因此是精确的，不是「等价替代」。
 */
class UltraModuleCompatibilityGateTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private companion object {
        // ---- 本机已确认身份（与 UltraModuleCompatibilityRegistry / 冻结排查一致）----
        const val ID32 = "cd08ae9eef7bb885c06f80ef3aea1d5c"
        const val VERSION = "1.9.3"
        const val ARCHIVE_SHA256 = "2fdc08482075a9865d49e2595a2487f07a37ab499aab744d8d9bb09a098d4a31"
        const val PAYLOAD_SHA256 = "a0835b667db5ed33a12b7fa2d2f8ba9ee58b8f7fd538250b62111cffd2a647dc"
        const val NATIVE_ENTRY = "libmodule_app_auto_hider.so"
        const val KERNEL_RELEASE = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
        const val SDK_VERSION = "5.1.0"
        const val OPERATION_ID = "0f3f2e1d-4c5b-4a69-8d7e-102030405060"
        const val BOOT_ID = "1f2e3d4c-5b6a-4978-8c9d-0e1f2a3b4c5d"
        const val HOST_UTC = "2026-10-31T09:00:00Z"
    }

    // ------------------------------------------------------------------ 夹具

    private val otherSha256 = "f".repeat(64)

    /** 判定用的本机设备事实：内核 release 可读、变体读不到（应用的真实处境）。 */
    private fun deviceFacts(
        sdkVersion: String? = SDK_VERSION,
        kernelRelease: String? = KERNEL_RELEASE,
        kernelVariantId: String? = null,
    ) = UltraModuleDeviceFacts.of(
        sdkVersion = sdkVersion,
        kernelRelease = kernelRelease,
        sdkManifestVerified = false,
        kernelVariantId = kernelVariantId,
        bootImageSha256 = null,
    )

    private fun confirmedIdentity() = UltraModulePackageIdentity(
        id32 = ID32,
        version = VERSION,
        archiveSha256 = ARCHIVE_SHA256,
        nativePayloadSha256 = PAYLOAD_SHA256,
        nativeEntryName = NATIVE_ENTRY,
    )

    private fun unknownIdentity() = UltraModulePackageIdentity(
        id32 = "ffffffffffffffffffffffffffffffff",
        version = "0.0.1",
        archiveSha256 = otherSha256,
        nativePayloadSha256 = otherSha256,
        nativeEntryName = "libother.so",
    )

    // 合成 MAPLESU 归档（与 W1-B ModuleArchiveInspectorTest 的夹具同构）。
    private val mapleSuEntry = dev.maplesu.manager.compat.NativeModuleAbi.ENTRY
    private val mapleSuTags = listOf(
        Triple("de1f663bcae792d7c9ed1a21cdaeff00331fe11b074f0303e018f43998f8db3e", "枫栖测试", "04429c3f7172e4cce7ac7a5d44b75631ce91777b5f2a5eec076a3a508a76fb17"),
        Triple("7dc74a2b86805f2cd0f45c6a82d384fd568e341c6f05af17c7229c9ba6d4318b", "1.2", "8dbc019a6e51fe8d4a3db9feaf05535d70879f35626050cd4131bfe323ecefc2"),
        Triple("05c62cd446c811e772c94d97fd546738328f7c6b9967ed135190ef37ff06d866", "静态检查", "ed02c95e091c66100d6f2f4554f96392b2951b394ba042278eed8f236f43e1a3"),
        Triple("1f39b220291a2fb6e4fec95f179d0faf833ca534ef8ab2ffc4bd893768694451", "Maple", "d409c886fd6cedd694c1b126fd19eccd90e2463e04154c193effc7103ce63f1c"),
        Triple("b33dcddd88c07d079a8e0e9ec6ab976f15f2edba46cab91a61234cfbb982111c", "0123456789abcdef0123456789abcdef", "3020d9a6c07a30e2649dd29a72d7e57121f0c0ca457b6d21dca5a69acbe6c2c4"),
    )

    private fun mapleSuElf(): ByteArray {
        val metadata = mapleSuTags.joinToString("\u0000") { it.first + it.second + it.third }.toByteArray()
        val strings = ("\u0000" + mapleSuEntry + "\u0000").toByteArray()
        val strOffset = 512 + metadata.size
        val symOffset = (strOffset + strings.size + 7) and -8
        val shOffset = symOffset + 48
        val b = ByteBuffer.allocate(shOffset + 192).order(ByteOrder.LITTLE_ENDIAN)
        b.put(byteArrayOf(0x7f, 69, 76, 70, 2, 1, 1))
        b.putShort(16, 3); b.putShort(18, 183); b.putInt(20, 1)
        b.putLong(32, 64); b.putLong(40, shOffset.toLong())
        b.putShort(52, 64); b.putShort(54, 56); b.putShort(56, 1)
        b.putShort(58, 64); b.putShort(60, 3)
        b.putInt(64, 1); b.putInt(68, 5); b.putLong(80, 0x400000)
        b.putLong(96, b.capacity().toLong()); b.putLong(104, b.capacity().toLong()); b.putLong(112, 4096)
        b.putInt(256, 0xd65f03c0.toInt()) // RET，不会被加载执行。
        b.position(512); b.put(metadata); b.position(strOffset); b.put(strings)
        b.putInt(symOffset + 24, 1); b.putInt(symOffset + 28, 0x12)
        b.putShort(symOffset + 30, 1)
        b.putLong(symOffset + 32, 0x400100); b.putLong(symOffset + 40, 4)
        b.putInt(shOffset + 68, 3); b.putLong(shOffset + 88, strOffset.toLong())
        b.putLong(shOffset + 96, strings.size.toLong())
        b.putInt(shOffset + 132, 11); b.putLong(shOffset + 152, symOffset.toLong())
        b.putLong(shOffset + 160, 48); b.putInt(shOffset + 168, 1); b.putLong(shOffset + 184, 24)
        return b.array()
    }

    private fun zip(vararg entries: Pair<String, ByteArray>): File {
        val file = tmp.newFile()
        ZipArchiveOutputStream(file).use { archive ->
            for ((name, bytes) in entries) {
                val entry = ZipArchiveEntry(name)
                entry.method = ZipEntry.STORED
                entry.size = bytes.size.toLong()
                entry.crc = CRC32().apply { update(bytes) }.value
                archive.putArchiveEntry(entry)
                archive.write(bytes)
                archive.closeArchiveEntry()
            }
        }
        return file
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private val kernelSuProp =
        "id=maple_demo\nname=枫栖示例\nversion=1.2\nversionCode=12\nauthor=Maple\ndescription=demo\n"

    // ------------------------------------------------------------------ identityFrom

    @Test
    fun identityFromReadsEveryFieldOutOfTheRealReport() {
        val elf = mapleSuElf()
        val report = ModuleArchiveInspector.inspect(zip("libdemo.so" to elf))

        // 前置：确认这确实是 MAPLESU 报告，否则下面的断言就没有意义。
        assertEquals(ModuleArchiveInspector.ModuleType.MAPLESU, report.type)
        assertEquals("libdemo.so", report.nativeEntry)
        assertNotNull(report.nativePayloadSha256)

        val identity = UltraModuleCompatibilityGate.identityFrom(report)
        assertEquals(report.id, identity.id32)
        assertEquals("0123456789abcdef0123456789abcdef", identity.id32)
        assertEquals(report.properties["version"], identity.version)
        assertEquals("1.2", identity.version)
        assertEquals(report.sha256, identity.archiveSha256)
        assertEquals(report.nativePayloadSha256, identity.nativePayloadSha256)
        // 载荷哈希是成员字节自己的摘要，不是整包摘要。
        assertEquals(sha256(elf), identity.nativePayloadSha256)
        assertFalse(identity.archiveSha256 == identity.nativePayloadSha256)
        assertEquals("libdemo.so", identity.nativeEntryName)
    }

    @Test
    fun identityFromKeepsAMissingNativePayloadAsAnEvidenceGap() {
        // 非 MAPLESU 归档没有可核对的原生载荷：Report 给 null，映射必须保持 null。
        // 判定随后会把「缺载荷哈希」当成证据不足，而不是「没有原生代码所以兼容」。
        val report = ModuleArchiveInspector.inspect(zip("module.prop" to kernelSuProp.toByteArray()))
        assertEquals(ModuleArchiveInspector.ModuleType.KERNEL_SU, report.type)
        assertNull(report.nativePayloadSha256)

        val identity = UltraModuleCompatibilityGate.identityFrom(report)
        assertNull(identity.nativePayloadSha256)
        assertNull(identity.nativeEntryName)
        assertEquals("maple_demo", identity.id32)

        val verdict = UltraModuleCompatibilityGate.evaluate(identity, deviceFacts(), UltraModuleAction.INSTALL)
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, verdict.decision)
        assertTrue(verdict.hasCode(UltraModuleReasonCode.PACKAGE_NATIVE_PAYLOAD_SHA256_MISSING))
        assertFalse(verdict.blocksNativeExecution)
    }

    // ------------------------------------------------------------------ 判定

    @Test
    fun everyActionIsKnownIncompatibleForTheConfirmedPackage() {
        assertEquals(5, UltraModuleAction.entries.size)
        UltraModuleAction.entries.forEach { action ->
            val verdict = UltraModuleCompatibilityGate.evaluate(confirmedIdentity(), deviceFacts(), action)
            assertEquals(
                "动作 $action 必须得到已确认不兼容",
                UltraModuleCompatibilityDecision.KNOWN_INCOMPATIBLE,
                verdict.decision,
            )
            assertTrue(verdict.blocksNativeExecution)
            assertEquals(action, verdict.action)
            assertEquals(UltraModuleCompatibilityRegistry.AAH_MARKET_1_9_3, verdict.matchedRecordId)
            // 本机读不到内核变体：命中不变，但必须留下注意码（W2-0 调和）。
            assertTrue(verdict.hasCode(UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN))
            assertTrue(verdict.hasCode(UltraModuleReasonCode.DEVICE_COMBINATION_IN_RECORD))
        }
    }

    @Test
    fun gateEvaluateForwardsToTheCompatibilityCore() {
        // 不重解释结论：同一个输入，门与 W1-A 的判定必须逐字段相等。
        val facts = deviceFacts()
        val identity = confirmedIdentity()
        UltraModuleAction.entries.forEach { action ->
            assertEquals(
                UltraModuleCompatibility.evaluate(
                    identity,
                    facts.sdkIdentity,
                    facts.kernelIdentity,
                    action,
                ),
                UltraModuleCompatibilityGate.evaluate(identity, facts, action),
            )
        }
    }

    @Test
    fun unknownPackageStaysUnverifiedAndIsNotBlocked() {
        val verdict = UltraModuleCompatibilityGate.evaluate(
            unknownIdentity(),
            deviceFacts(),
            UltraModuleAction.INSTALL,
        )
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, verdict.decision)
        assertFalse(verdict.blocksNativeExecution)
        assertTrue(verdict.hasCode(UltraModuleReasonCode.PACKAGE_NOT_IN_RECORD))
        assertNull(verdict.matchedRecordId)
    }

    @Test
    fun unreadableDeviceFactsDoNotBecomeAVerdict() {
        // 内核 release / SDK 版本都读不到：证据不足 → UNVERIFIED，不拦，也不伪判。
        val blind = UltraModuleCompatibilityGate.evaluate(
            confirmedIdentity(),
            deviceFacts(sdkVersion = null, kernelRelease = null),
            UltraModuleAction.INSTALL,
        )
        assertEquals(UltraModuleCompatibilityDecision.UNVERIFIED, blind.decision)
        assertFalse(blind.blocksNativeExecution)
        assertTrue(blind.hasCode(UltraModuleReasonCode.KERNEL_RELEASE_MISSING))
        assertTrue(blind.hasCode(UltraModuleReasonCode.SDK_VERSION_MISSING))
        // 包字节仍然命中：报告入口还能指向那条记录，只是设备组合未验证。
        assertEquals(UltraModuleCompatibilityRegistry.AAH_MARKET_1_9_3, blind.matchedRecordId)
    }

    // ------------------------------------------------------------------ 设备事实

    @Test
    fun deviceFactsKeepUnknownsAsUnknowns() {
        // 注入读取器：JVM 上不读真实 /proc，也不碰 UltraRuntimeClient（client 传 null）。
        val facts = UltraModuleDeviceFacts.readWith(null) { " 6.6.89-test-release " }
        assertEquals("6.6.89-test-release", facts.kernelRelease)
        assertNull("没有客户端时 SDK 版本就是未知，不是空字符串伪造", facts.sdkVersion)
        assertFalse(facts.sdkManifestVerified)
        assertNull(facts.kernelVariantId)
        assertNull(facts.bootImageSha256)
        assertEquals("", facts.sdkIdentity.version)
        assertEquals("6.6.89-test-release", facts.kernelIdentity.release)
        assertNull(facts.kernelIdentity.variantId)
        assertTrue("摘要必须把未知写成 unknown", facts.summary().contains("sdk=unknown"))

        // 读不到内核 release：null 而不是空串/伪造值。
        val blind = UltraModuleDeviceFacts.readWith(null) { null }
        assertNull(blind.kernelRelease)
        assertEquals("", blind.kernelIdentity.release)
    }

    // ------------------------------------------------------------------ 文案

    @Test
    fun blockingTextSaysTheRequestWasStoppedAndNothingWasExecuted() {
        val verdict = UltraModuleCompatibilityGate.evaluate(
            confirmedIdentity(),
            deviceFacts(),
            UltraModuleAction.OPEN_WEBUI,
        )
        val text = UltraModuleCompatibilityGate.blockingText(verdict)
        assertTrue("必须明确写已拦截", text.contains("已拦截"))
        assertTrue("必须写明本次没有发起模块执行调用", text.contains("次数均为 0"))
        assertTrue("必须区分「结束执行」与「模块已停止」", text.contains("不等于模块已停止"))
        assertTrue("必须提到动作", text.contains(UltraModuleAction.OPEN_WEBUI.label))
        // W1-A 的原文案（含记录 id）仍然在：门只追加说明，不替换依据。
        assertTrue(text.contains(UltraModuleCompatibilityRegistry.AAH_MARKET_1_9_3))
    }

    @Test
    fun blockingTextForUnverifiedSaysItWasNotBlocked() {
        val verdict = UltraModuleCompatibilityGate.evaluate(
            unknownIdentity(),
            deviceFacts(),
            UltraModuleAction.INSTALL,
        )
        val text = UltraModuleCompatibilityGate.blockingText(verdict)
        assertTrue(text.contains("未验证"))
        assertTrue("未验证必须明确没被拦下", text.contains("没有被拦下"))
        assertFalse("未知包不能写已拦截", text.contains("已拦截"))
    }

    // ------------------------------------------------------------------ 证据事件

    @Test
    fun evidenceEventCarriesTheBlockedOutcomeAndStableCodes() {
        val verdict = UltraModuleCompatibilityGate.evaluate(
            confirmedIdentity(),
            deviceFacts(),
            UltraModuleAction.INSTALL,
        )
        val event = UltraModuleCompatibilityGate.evidenceEvent(
            verdict = verdict,
            operationId = OPERATION_ID,
            bootId = BOOT_ID,
            hostUtcIso = HOST_UTC,
            processPid = 4242,
        )
        assertEquals(OPERATION_ID, event.operationId)
        assertEquals(UltraModuleAction.INSTALL, event.action)
        assertEquals(UltraModuleProcessRole.MANAGER, event.processRole)
        assertEquals(UltraModulePhase.PRE_EXEC_CHECK, event.phase)
        assertEquals(UltraModuleOutcome.BLOCKED, event.outcome)
        // 门这里没有宿主返回码：null，不是 0（W1-C：没有返回码就 null）。
        assertNull(event.returnCode)
        assertEquals(BOOT_ID, event.bootId)
        assertEquals(HOST_UTC, event.hostUtcIso)
        assertEquals(4242, event.processPid)

        // detail 只放机器码：可检索、不含包哈希/路径/用户数据。
        assertTrue(event.detail.contains("gate=KNOWN_INCOMPATIBLE"))
        assertTrue(event.detail.contains("action=INSTALL"))
        assertTrue(event.detail.contains("record=${UltraModuleCompatibilityRegistry.AAH_MARKET_1_9_3}"))
        assertTrue(event.detail.contains(UltraModuleReasonCode.PACKAGE_HASH_MATCHED.code))
        assertTrue(event.detail.contains(UltraModuleReasonCode.KERNEL_VARIANT_UNKNOWN.code))
        assertFalse("detail 不能带包哈希", event.detail.contains(ARCHIVE_SHA256))
        assertFalse("detail 不能带包哈希", event.detail.contains(PAYLOAD_SHA256))

        // 事件必须能被 W1-C 的脱敏器接受并原样往返（字段顺序、可复读）。
        assertEquals(event.detail, UltraModuleEvidenceSanitizer().redact(event.detail))
        val decoded = UltraModuleEvidenceJson.decode(UltraModuleEvidenceJson.encode(event))
        assertNotNull(decoded)
        assertEquals(event, decoded!!.event)
        assertTrue("结构化字段必须都合格", decoded.missingFields.isEmpty())
    }

    @Test
    fun evidenceEventForUnverifiedIsUnknownNotSuccess() {
        val verdict = UltraModuleCompatibilityGate.evaluate(
            unknownIdentity(),
            deviceFacts(),
            UltraModuleAction.DEV_RUN_ONCE,
        )
        val event = UltraModuleCompatibilityGate.evidenceEvent(
            verdict = verdict,
            operationId = OPERATION_ID,
            bootId = BOOT_ID,
            hostUtcIso = HOST_UTC,
        )
        // 「门没有拦」不等于「这一步成功了」：结果仍然是 UNKNOWN。
        assertEquals(UltraModuleOutcome.UNKNOWN, event.outcome)
        assertEquals(UltraModuleAction.DEV_RUN_ONCE, event.action)
        assertTrue(event.detail.contains("gate=UNVERIFIED"))
        assertTrue(event.detail.contains("record=none"))
        assertNull(event.processPid)
    }

    // ------------------------------------------------------------------ 证据落盘（注入 sink）

    @Test
    fun evidenceLogAppendsExactlyOneJsonLine() {
        val lines = ArrayList<String>()
        val log = UltraModuleGateEvidenceLog(appendLine = { lines += it })
        val verdict = UltraModuleCompatibilityGate.evaluate(
            confirmedIdentity(),
            deviceFacts(),
            UltraModuleAction.UPDATE,
        )
        val result = log.record(
            UltraModuleCompatibilityGate.evidenceEvent(
                verdict = verdict,
                operationId = OPERATION_ID,
                bootId = BOOT_ID,
                hostUtcIso = HOST_UTC,
            ),
        )
        assertTrue(result is UltraModuleEvidenceRecordResult.Appended)
        assertEquals(1, lines.size)
        val line = lines.single()
        assertFalse("JSONL 必须是单行", line.contains("\n"))
        val decoded = UltraModuleEvidenceJson.decode(line)
        assertNotNull(decoded)
        assertEquals(UltraModuleOutcome.BLOCKED, decoded!!.event.outcome)
        assertEquals(UltraModuleAction.UPDATE, decoded.event.action)
        assertTrue(decoded.event.detail.contains(UltraModuleReasonCode.PACKAGE_HASH_MATCHED.code))
        assertEquals(line, (result as UltraModuleEvidenceRecordResult.Appended).line)
    }

    @Test
    fun evidenceLogDropsUnsafeEventsInsteadOfWritingHalfRedactedLines() {
        val lines = ArrayList<String>()
        val log = UltraModuleGateEvidenceLog(appendLine = { lines += it })
        val unsafe = UltraModuleCompatibilityGate.evidenceEvent(
            verdict = UltraModuleCompatibilityGate.evaluate(
                confirmedIdentity(),
                deviceFacts(),
                UltraModuleAction.INSTALL,
            ),
            operationId = OPERATION_ID,
            bootId = BOOT_ID,
            hostUtcIso = HOST_UTC,
        ).copy(detail = "gate=BAD\u0000CONTROL")
        val result = log.record(unsafe)
        assertTrue(result is UltraModuleEvidenceRecordResult.Dropped)
        assertTrue(lines.isEmpty())
        assertEquals(
            "detail:detail-has-control-characters",
            (result as UltraModuleEvidenceRecordResult.Dropped).reason,
        )
    }

    @Test
    fun evidenceLogNeverBreaksTheCallerWhenTheSinkFails() {
        // 证据写不进去是「少一条记录」，不能让安装事务变成崩溃。
        val log = UltraModuleGateEvidenceLog(appendLine = { throw java.io.IOException("disk full") })
        val result = log.record(
            UltraModuleCompatibilityGate.evidenceEvent(
                verdict = UltraModuleCompatibilityGate.evaluate(
                    confirmedIdentity(),
                    deviceFacts(),
                    UltraModuleAction.INSTALL,
                ),
                operationId = OPERATION_ID,
                bootId = BOOT_ID,
                hostUtcIso = HOST_UTC,
            ),
        )
        assertEquals("append-failed", (result as UltraModuleEvidenceRecordResult.Dropped).reason)
    }

    // ------------------------------------------------------------------ §4.3 字段生产者（W6-F1）

    @Test
    fun deviceTimeIsIso8601UtcConvertedFromTheCallersClock() {
        // 调用方在事件发生那一刻取 System.currentTimeMillis()，本函数只做换算（不取时钟）。
        assertEquals("2023-11-14T22:13:20Z", UltraModuleCompatibilityGate.deviceTimeIso(1_700_000_000_000L))
        assertEquals(
            "2023-11-14T22:13:20.123Z",
            UltraModuleCompatibilityGate.deviceTimeIso(1_700_000_000_123L),
        )
        // 两种形态都必须落在脱敏器的 ISO-8601 白名单里，否则整条事件会被丢弃。
        UltraModuleEvidenceSanitizer().unsafeReason(
            event(deviceTimeIso = UltraModuleCompatibilityGate.deviceTimeIso(1_700_000_000L)),
        )?.let { fail("deviceTimeIso 必须是 ISO-8601，实际被拒：$it") }
        UltraModuleEvidenceSanitizer().unsafeReason(
            event(deviceTimeIso = UltraModuleCompatibilityGate.deviceTimeIso(1_700_000_000_123L)),
        )?.let { fail("带毫秒的 deviceTimeIso 必须是 ISO-8601，实际被拒：$it") }
    }

    @Test
    fun buildDigestFromApkFileIsTheFileBytesDigest() {
        val apk = tmp.newFile("manager.apk")
        apk.writeBytes(ByteArray(4096) { (it % 251).toByte() })
        val digest = UltraModuleBuildDigest.fromApkFile(apk)
        assertTrue("可读的 APK 必须给出真实摘要，实际：$digest", digest is UltraModuleBuildDigest.Known)
        val known = digest as UltraModuleBuildDigest.Known
        assertEquals(sha256(apk.readBytes()), known.digest)
        assertEquals(UltraModuleBuildDigest.SOURCE_MANAGER_BASE_APK, known.source)
        assertEquals("verified:manager-base-apk", known.detailToken)
        // 摘要必须能被脱敏器接受（否则字段会在落盘时被置空）。
        assertTrue(UltraModuleBuildDigest.isValidDigest(known.digest))
    }

    @Test
    fun everyWayOfNotGettingTheBuildDigestHasItsOwnReason() {
        // 路径拿不到 / 不是普通文件 / 空文件：三种「拿不到」各有具名原因码，不是同一个 null。
        assertEquals(
            UltraModuleBuildDigest.Unavailable(UltraModuleBuildDigest.REASON_APK_PATH_UNAVAILABLE),
            UltraModuleBuildDigest.fromApkFile(null),
        )
        assertEquals(
            UltraModuleBuildDigest.Unavailable(UltraModuleBuildDigest.REASON_APK_NOT_A_FILE),
            UltraModuleBuildDigest.fromApkFile(tmp.newFolder("no-apk-here")),
        )
        val empty = tmp.newFile("empty.apk")
        assertEquals(0L, empty.length())
        assertEquals(
            UltraModuleBuildDigest.Unavailable(UltraModuleBuildDigest.REASON_APK_EMPTY),
            UltraModuleBuildDigest.fromApkFile(empty),
        )

        // 已算好的摘要：大小写归一；非十六进制/长度不对 -> 具名原因（不把自由文本混进字段）。
        val hex = "a".repeat(64)
        assertEquals(UltraModuleBuildDigest.Known(hex), UltraModuleBuildDigest.of(hex.uppercase()))
        assertEquals(
            UltraModuleBuildDigest.Unavailable(UltraModuleBuildDigest.REASON_DIGEST_INVALID),
            UltraModuleBuildDigest.of("not-a-digest"),
        )
        assertEquals(
            UltraModuleBuildDigest.Unavailable(UltraModuleBuildDigest.REASON_DIGEST_INVALID),
            UltraModuleBuildDigest.of("a".repeat(63)),
        )
        assertEquals(
            UltraModuleBuildDigest.Unavailable(UltraModuleBuildDigest.REASON_NOT_PROVIDED),
            UltraModuleBuildDigest.of(null),
        )
        assertEquals(
            UltraModuleBuildDigest.Unavailable(UltraModuleBuildDigest.REASON_NOT_PROVIDED),
            UltraModuleBuildDigest.of("   "),
        )
    }

    @Test
    fun evidenceEventCarriesTheInjectedBuildDigestAndDeviceTime() {
        val digest = UltraModuleBuildDigest.of("ab".repeat(32))
        val deviceTime = UltraModuleCompatibilityGate.deviceTimeIso(1_700_000_000_123L)
        val event = UltraModuleCompatibilityGate.evidenceEvent(
            verdict = UltraModuleCompatibilityGate.evaluate(
                confirmedIdentity(),
                deviceFacts(),
                UltraModuleAction.INSTALL,
            ),
            operationId = OPERATION_ID,
            bootId = BOOT_ID,
            hostUtcIso = HOST_UTC,
            processPid = 4242,
            deviceTimeIso = deviceTime,
            buildDigest = digest,
        )

        assertEquals("ab".repeat(32), event.buildDigest)
        assertEquals(deviceTime, event.deviceTimeIso)
        assertEquals("2023-11-14T22:13:20.123Z", event.deviceTimeIso)
        // detail 里只留来源标记，不放摘要本身（32 位以上十六进制会被脱敏成 <hex>）。
        assertTrue(event.detail.contains("build=verified:manager-base-apk"))
        assertFalse(event.detail.contains("ab".repeat(32)))

        // 走一遍真实落盘路径：字段必须留在 JSONL 里，且解码后逐字段相等。
        val lines = ArrayList<String>()
        val result = UltraModuleGateEvidenceLog(appendLine = { lines += it }).record(event)
        assertTrue(result is UltraModuleEvidenceRecordResult.Appended)
        val line = lines.single()
        assertTrue(line.contains("\"buildDigest\":\"" + "ab".repeat(32) + "\""))
        assertTrue(line.contains("\"deviceTimeIso\":\"2023-11-14T22:13:20.123Z\""))
        assertEquals(event, UltraModuleEvidenceJson.decode(line)!!.event)
        assertEquals(UltraModuleOutcome.BLOCKED, UltraModuleEvidenceJson.decode(line)!!.event.outcome)
    }

    @Test
    fun aMissingBuildDigestIsAReasonInTheLineNotSilentSilence() {
        // 「拿不到」与「没写」必须能区分：两者字段都是 null，但 detail 的原因码不同。
        val unreadable = UltraModuleCompatibilityGate.evidenceEvent(
            verdict = UltraModuleCompatibilityGate.evaluate(
                confirmedIdentity(),
                deviceFacts(),
                UltraModuleAction.INSTALL,
            ),
            operationId = OPERATION_ID,
            bootId = BOOT_ID,
            hostUtcIso = HOST_UTC,
            buildDigest = UltraModuleBuildDigest.Unavailable(UltraModuleBuildDigest.REASON_APK_UNREADABLE),
        )
        val notProvided = UltraModuleCompatibilityGate.evidenceEvent(
            verdict = UltraModuleCompatibilityGate.evaluate(
                confirmedIdentity(),
                deviceFacts(),
                UltraModuleAction.INSTALL,
            ),
            operationId = OPERATION_ID,
            bootId = BOOT_ID,
            hostUtcIso = HOST_UTC,
        )

        assertNull(unreadable.buildDigest)
        assertTrue(unreadable.detail.contains("build=unknown:apk-unreadable"))
        assertNull(notProvided.buildDigest)
        assertTrue(notProvided.detail.contains("build=unknown:not-provided"))
        assertFalse(unreadable.detail == notProvided.detail)

        // 脱敏器不能把这条事件丢掉（那会让「拿不到」重新变成「没有记录」）。
        val lines = ArrayList<String>()
        val result = UltraModuleGateEvidenceLog(appendLine = { lines += it }).record(unreadable)
        assertTrue(result is UltraModuleEvidenceRecordResult.Appended)
        assertTrue(lines.single().contains("\"buildDigest\":null"))
        assertTrue(lines.single().contains("build=unknown:apk-unreadable"))
    }

    @Test
    fun hostEventDistinguishesCalledFromRefusedWithTheRealReturnCode() {
        val accepted = UltraModuleCompatibilityGate.hostEvent(
            action = UltraModuleAction.INSTALL,
            operationId = OPERATION_ID,
            bootId = BOOT_ID,
            hostUtcIso = HOST_UTC,
            deviceTimeIso = null,
            processPid = 4242,
            buildDigest = UltraModuleBuildDigest.of("cd".repeat(32)),
            install = nativeReceipt(ok = true, sdkError = "OK", sdkErrorCode = 0),
        )
        assertEquals(UltraModulePhase.NATIVE_ENTRY, accepted.phase)
        assertEquals(UltraModuleOutcome.SUCCESS, accepted.outcome)
        assertEquals(0, accepted.returnCode)
        assertTrue(accepted.detail.contains("state=HOST_CALLED"))
        assertEquals("cd".repeat(32), accepted.buildDigest)

        val refused = UltraModuleCompatibilityGate.hostEvent(
            action = UltraModuleAction.INSTALL,
            operationId = OPERATION_ID,
            bootId = BOOT_ID,
            hostUtcIso = HOST_UTC,
            deviceTimeIso = null,
            processPid = 4242,
            buildDigest = UltraModuleBuildDigest.of("cd".repeat(32)),
            install = nativeReceipt(ok = false, sdkError = "MODULE_REFUSED", sdkErrorCode = -3),
        )
        assertEquals(UltraModulePhase.NATIVE_ENTRY, refused.phase)
        assertEquals(UltraModuleOutcome.FAILURE, refused.outcome)
        assertEquals("宿主返回码必须原样进事件", -3, refused.returnCode)
        assertTrue(refused.detail.contains("state=HOST_REFUSED"))
        // 两条事件都必须能被脱敏器接受并原样往返。
        listOf(accepted, refused).forEach { event ->
            assertNull(UltraModuleEvidenceSanitizer().unsafeReason(event))
            assertEquals(event.detail, UltraModuleEvidenceSanitizer().redact(event.detail))
            assertEquals(event, UltraModuleEvidenceJson.decode(UltraModuleEvidenceJson.encode(event))!!.event)
        }
    }

    @Test
    fun preconditionEventSaysTheGateWasNotEvaluated() {
        val event = UltraModuleCompatibilityGate.preconditionEvent(
            action = UltraModuleAction.INSTALL,
            operationId = OPERATION_ID,
            bootId = BOOT_ID,
            hostUtcIso = HOST_UTC,
            deviceTimeIso = null,
            processPid = 4242,
            buildDigest = UltraModuleBuildDigest.of("ef".repeat(32)),
            environmentState = "Fault",
        )
        assertEquals(UltraModulePhase.PRE_EXEC_CHECK, event.phase)
        assertEquals(UltraModuleOutcome.FAILURE, event.outcome)
        assertNull("门没跑，就没有宿主返回码", event.returnCode)
        assertTrue(event.detail.contains("gate=NOT_EVALUATED"))
        assertTrue(event.detail.contains("environment=Fault"))
        assertTrue(event.detail.contains("build=verified:manager-base-apk"))
        // 设备给的可疑状态值会被归一成 unreadable（否则整条事件会被脱敏器丢弃）。
        val suspicious = UltraModuleCompatibilityGate.preconditionEvent(
            action = UltraModuleAction.INSTALL,
            operationId = OPERATION_ID,
            bootId = BOOT_ID,
            hostUtcIso = HOST_UTC,
            deviceTimeIso = null,
            processPid = null,
            buildDigest = UltraModuleBuildDigest.of("ef".repeat(32)),
            environmentState = "/data/local/tmp/state",
        )
        assertTrue(suspicious.detail.contains("environment=unreadable"))
        assertNull(UltraModuleEvidenceSanitizer().unsafeReason(suspicious))
    }

    // ------------------------------------------------------------------ 事件夹具

    private fun event(
        deviceTimeIso: String? = null,
        buildDigest: String? = null,
    ) = UltraModuleEvent(
        operationId = OPERATION_ID,
        action = UltraModuleAction.INSTALL,
        bootId = BOOT_ID,
        deviceTimeIso = deviceTimeIso,
        hostUtcIso = HOST_UTC,
        processRole = UltraModuleProcessRole.MANAGER,
        processPid = 4242,
        phase = UltraModulePhase.PRE_EXEC_CHECK,
        returnCode = null,
        buildDigest = buildDigest,
        outcome = UltraModuleOutcome.BLOCKED,
        detail = "gate=KNOWN_INCOMPATIBLE",
    )

    private fun nativeReceipt(ok: Boolean, sdkError: String, sdkErrorCode: Int) =
        dev.maplesu.manager.runtime.ultra.NativeReceipt(
            schemaVersion = 1,
            backend = dev.maplesu.manager.runtime.ultra.UltraRuntimeClient.BACKEND,
            bridgeVersion = 1,
            operation = "install_module",
            ok = ok,
            sdkError = sdkError,
            sdkErrorCode = sdkErrorCode,
            reason = null,
            data = null,
            raw = "{}",
        )
}
