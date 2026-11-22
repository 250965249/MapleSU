package dev.maplesu.manager.modules.compat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * §4.3 故障证据的可执行规格：事件格式稳定、脱敏不外泄、字段缺失可解析、FORCE STOP 不是崩溃。
 *
 * 这些用例只跑 JVM，不需要设备、`android.jar` 或 gradle：被测文件没有任何 Android import。
 * 断言里刻意写死具体字符串（占位符、字段顺序、原因码），这样任何“顺手改一下格式”都会让测试
 * 失败——证据格式一旦发布就不能漂移，否则旧 JSONL 会读不回来。
 */
class UltraModuleEvidenceTest {

    private val sanitizer = UltraModuleEvidenceSanitizer()

    private val moduleId = "cd08ae9eef7bb885c06f80ef3aea1d5c"
    private val moduleElfSha256 =
        "a0835b667db5ed33a12b7fa2d2f8ba9ee58b8f7fd538250b62111cffd2a647dc"
    private val bootId = "6f1c0b7e-2c4a-4a5f-9a0e-2b8d7c6a5f41"

    private fun event(
        operationId: String = "op-20261031-0001",
        action: UltraModuleAction = UltraModuleAction.OPEN_WEBUI,
        bootId: String = this.bootId,
        deviceTimeIso: String? = "2026-10-31T14:43:01.123+08:00",
        hostUtcIso: String = "2026-10-31T06:43:01.123Z",
        processRole: UltraModuleProcessRole = UltraModuleProcessRole.MANAGER,
        processPid: Int? = 15394,
        phase: UltraModulePhase = UltraModulePhase.WEBUI_START,
        returnCode: Int? = 0,
        buildDigest: String? = moduleElfSha256,
        outcome: UltraModuleOutcome = UltraModuleOutcome.FAILURE,
        detail: String = "webui start returned",
    ): UltraModuleEvent = UltraModuleEvent(
        operationId = operationId,
        action = action,
        bootId = bootId,
        deviceTimeIso = deviceTimeIso,
        hostUtcIso = hostUtcIso,
        processRole = processRole,
        processPid = processPid,
        phase = phase,
        returnCode = returnCode,
        buildDigest = buildDigest,
        outcome = outcome,
        detail = detail,
    )

    private fun recorded(write: UltraModuleEvidenceWrite): UltraModuleEvidenceWrite.Recorded =
        write as? UltraModuleEvidenceWrite.Recorded
            ?: throw AssertionError("expected Recorded, got $write")

    private fun dropped(write: UltraModuleEvidenceWrite): String =
        (write as? UltraModuleEvidenceWrite.Dropped)?.reason
            ?: throw AssertionError("expected Dropped, got $write")

    // ------------------------------------------------------------------ JSONL

    @Test
    fun singleLineJsonKeepsTheDocumentedFieldOrderAndOneLine() {
        val line = UltraModuleEvidenceJson.encode(event())
        assertFalse("JSONL 一行里不能有换行", line.contains('\n'))
        assertFalse(line.contains('\r'))
        val positions = UltraModuleEvidenceSchema.FIELDS.map { name -> line.indexOf("\"$name\":") }
        positions.forEachIndexed { index, position ->
            assertTrue("字段 ${UltraModuleEvidenceSchema.FIELDS[index]} 必须在行内", position >= 0)
        }
        assertEquals("字段顺序必须与 FIELDS 一致", positions.sorted(), positions)
        assertEquals(12, UltraModuleEvidenceSchema.FIELDS.size)
    }

    @Test
    fun eventRoundTripsThroughItsJsonLine() {
        val original = event()
        val line = UltraModuleEvidenceJson.encode(original)
        val decoded = UltraModuleEvidenceJson.decode(line)
        assertNotNull(decoded)
        val envelope = decoded!!
        assertEquals(original, envelope.event)
        assertTrue(envelope.missingFields.isEmpty())
        assertTrue(envelope.ignoredFields.isEmpty())
        assertEquals(line, UltraModuleEvidenceJson.encode(envelope.event))
    }

    @Test
    fun nullableFieldsRoundTripAsExplicitNull() {
        val original = event(
            deviceTimeIso = null,
            processPid = null,
            returnCode = null,
            buildDigest = null,
        )
        val line = UltraModuleEvidenceJson.encode(original)
        assertTrue(line.contains("\"deviceTimeIso\":null"))
        assertTrue(line.contains("\"processPid\":null"))
        assertTrue(line.contains("\"returnCode\":null"))
        assertTrue(line.contains("\"buildDigest\":null"))
        val decoded = UltraModuleEvidenceJson.decode(line)!!
        assertEquals(original, decoded.event)
        assertTrue(decoded.missingFields.isEmpty())
    }

    @Test
    fun missingFieldsStillParseAndAreNamedNotGuessed() {
        val decoded = UltraModuleEvidenceJson.decode("""{"detail":"only detail"}""")
        assertNotNull(decoded)
        val envelope = decoded!!
        assertEquals("only detail", envelope.event.detail)
        // 缺失字段落到默认值，但默认值不是事实：必须被点名。
        assertEquals(UltraModuleAction.INSTALL, envelope.event.action)
        assertEquals(UltraModuleProcessRole.UNKNOWN, envelope.event.processRole)
        assertEquals(UltraModulePhase.UNKNOWN, envelope.event.phase)
        assertEquals(UltraModuleOutcome.UNKNOWN, envelope.event.outcome)
        assertEquals(
            listOf("operationId", "action", "bootId", "hostUtcIso", "processRole", "phase", "outcome"),
            envelope.missingFields,
        )
    }

    @Test
    fun unrecognizedEnumValueIsReportedInsteadOfThrowing() {
        val line = UltraModuleEvidenceJson.encode(event())
            .replace("\"action\":\"OPEN_WEBUI\"", "\"action\":\"TELEPORT\"")
            .replace("\"outcome\":\"FAILURE\"", "\"outcome\":\"MAYBE\"")
        val envelope = UltraModuleEvidenceJson.decode(line)!!
        assertEquals(UltraModuleAction.INSTALL, envelope.event.action)
        assertEquals(UltraModuleOutcome.UNKNOWN, envelope.event.outcome)
        assertTrue(envelope.missingFields.contains("action"))
        assertTrue(envelope.missingFields.contains("outcome"))
    }

    @Test
    fun unknownFieldsAreIgnoredButReported() {
        val line = UltraModuleEvidenceJson.encode(event()).dropLast(1) + ""","futureField":{"nested":1}}"""
        val envelope = UltraModuleEvidenceJson.decode(line)
        assertNotNull(envelope)
        assertEquals(listOf("futureField"), envelope!!.ignoredFields)
        assertEquals(event(), envelope.event)
    }

    @Test
    fun malformedLinesAreRejectedInsteadOfRepaired() {
        assertNull(UltraModuleEvidenceJson.decode(""))
        assertNull(UltraModuleEvidenceJson.decode("   "))
        assertNull(UltraModuleEvidenceJson.decode("{"))
        assertNull(UltraModuleEvidenceJson.decode("""{"detail":}"""))
        assertNull(UltraModuleEvidenceJson.decode("""[1,2]"""))
        assertNull(UltraModuleEvidenceJson.decode("""{"detail":"x"} trailing"""))
        assertNull(UltraModuleEvidenceJson.decode("""{"detail":"unterminated}"""))
        assertNull(UltraModuleEvidenceJson.decode("""plain text"""))
    }

    @Test
    fun decodeLinesReportsRejectedLineNumbersAndKeepsTheRest() {
        val first = UltraModuleEvidenceJson.encode(event(operationId = "op-a"))
        val second = UltraModuleEvidenceJson.encode(event(operationId = "op-b"))
        val content = first + "\n\nnot json\n" + second + "\n"
        val decoded = UltraModuleEvidenceJson.decodeLines(content)
        assertEquals(listOf("op-a", "op-b"), decoded.events.map { it.event.operationId })
        assertEquals(listOf(3), decoded.rejectedLines)
    }

    @Test
    fun escapingRoundTripsQuotesBackslashesNewlinesAndNonAscii() {
        val detail = "quote:\" backslash:\\ newline:\n tab:\t unit:模块"
        val line = UltraModuleEvidenceJson.encode(event(detail = detail))
        assertFalse(line.contains('\n'))
        assertEquals(detail, UltraModuleEvidenceJson.decode(line)!!.event.detail)
    }

    // ------------------------------------------------------------------ 脱敏

    @Test
    fun hexRootKeysAreRedacted() {
        val key32 = "0123456789abcdef0123456789abcdef"
        val key64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        assertEquals("root-key=<hex>", sanitizer.redact("root-key=$key32"))
        assertEquals("root-key=<hex>", sanitizer.redact("root-key=$key64"))
        // 大小写混合的十六进制同样处理
        assertEquals("key=<hex>", sanitizer.redact("key=0123456789ABCDEF0123456789abcdef"))
    }

    @Test
    fun moduleIdInsideItsModuleDirectoryIsKeptAndRedactedElsewhere() {
        assertEquals(
            "/data/adb/modules/$moduleId/<seg>",
            sanitizer.redactPath("/data/adb/modules/$moduleId/aah.log"),
        )
        // 同一串出现在自由文本里就不是“模块目录身份”，按 root key 形态处理。
        assertEquals("module=<hex>", sanitizer.redact("module=$moduleId"))
    }

    @Test
    fun privatePathsKeepStructureAndLoseInstanceSegments() {
        assertEquals("/data", sanitizer.redactPath("/data"))
        assertEquals("/data/adb", sanitizer.redactPath("/data/adb"))
        assertEquals(
            "/data/data/<package>/<seg>/<seg>",
            sanitizer.redactPath("/data/data/dev.maplesu.manager/files/x.json"),
        )
        assertEquals(
            "/data/user/<user>/<package>/<seg>/<seg>",
            sanitizer.redactPath("/data/user/0/dev.maplesu.manager/databases/x.db"),
        )
        assertEquals(
            "/data/local/<data-item>/<seg>",
            sanitizer.redactPath("/data/local/tmp/pull.bin"),
        )
        assertEquals(
            "/data/misc/<data-item>/<seg>",
            sanitizer.redactPath("/data/misc/keystore/user_0"),
        )
        // Ultra 宿主的模块目录不在 /data/adb 下时，环境段被替换、modules/模块身份保留。
        assertEquals(
            "/data/<env>/modules/$moduleId/<seg>",
            sanitizer.redactPath("/data/tricky_store/modules/$moduleId/cfg.json"),
        )
        // 非 /data 路径不是本类定义的私有目录：保留原样。
        assertEquals("/system/bin/su", sanitizer.redactPath("/system/bin/su"))
        // 相对写法补上 / 后走同一套规则。
        assertEquals(
            "/data/data/<package>/<seg>",
            sanitizer.redactPath("data/data/dev.maplesu.manager/files"),
        )
    }

    @Test
    fun pathsInsideFreeTextAreRedactedToo() {
        val text = "log=/data/adb/modules/$moduleId/aah.log"
        assertEquals("log=/data/adb/modules/$moduleId/<seg>", sanitizer.redact(text))
    }

    @Test
    fun fortyEightCharacterCredentialsAreRedactedButShorterRunsAreNot() {
        val token48 = "Zq9X".repeat(12)
        assertEquals(48, token48.length)
        assertEquals("token=<token>", sanitizer.redact("token=$token48"))
        val run47 = "Zq9X".repeat(11) + "Zq9"
        assertEquals(47, run47.length)
        assertEquals("value=$run47", sanitizer.redact("value=$run47"))
    }

    @Test
    fun redactionIsIdempotentSoAlreadySanitizedDetailCanBeRechecked() {
        val token = "Zq9X".repeat(12)
        val key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        val text = "path=/data/data/dev.maplesu.manager/files/a.json token=$token key=$key id=$moduleId"
        val once = sanitizer.redact(text)
        assertEquals(once, sanitizer.redact(once))
        assertNull(sanitizer.unsafeReason(event(detail = once)))
    }

    @Test
    fun sanitizeDetailReportsWhichRulesFired() {
        val token = "Zq9X".repeat(12)
        val result = sanitizer.sanitizeDetail(
            "path=/data/user/0/dev.maplesu.manager/files/x token=$token",
        )
        val redacted = result as UltraModuleSanitizedDetail.Redacted
        assertEquals(
            "path=/data/user/<user>/<package>/<seg>/<seg> token=<token>",
            redacted.text,
        )
        assertTrue(redacted.hits.contains("private-path"))
        assertTrue(redacted.hits.contains("token-secret"))
    }

    @Test
    fun controlCharactersDropTheWholeEventByDefault() {
        val write = sanitizer.sanitizeEvidence(event(detail = "line\u0000end"))
        assertEquals("detail:detail-has-control-characters", dropped(write))
    }

    @Test
    fun keepWithMarkerPolicyKeepsTheEventWithoutTheOriginalText() {
        val keeping = UltraModuleEvidenceSanitizer(UltraModuleUnsafeRedactionPolicy.KEEP_WITH_MARKER)
        val write = keeping.sanitizeEvidence(event(detail = "line\u0000end"))
        val envelope = recorded(write)
        assertEquals("<detail-dropped:detail-has-control-characters>", envelope.event.detail)
        assertTrue(envelope.notes.contains("detail-dropped:detail-has-control-characters"))
        assertNull(keeping.unsafeReason(envelope.event))
    }

    @Test
    fun privateKeyBlocksAndOverlongDetailAreDropped() {
        val pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        assertEquals(
            "detail:detail-has-private-key-block",
            dropped(sanitizer.sanitizeEvidence(event(detail = pem))),
        )
        val long = "a".repeat(UltraModuleEvidenceSanitizer.MAX_DETAIL_CHARS + 1)
        assertEquals(
            "detail:detail-too-long",
            dropped(sanitizer.sanitizeEvidence(event(detail = long))),
        )
    }

    @Test
    fun structuredFieldsMustBeMachineSafeOrTheEventIsDropped() {
        assertEquals(
            "fields:operation-id-not-machine-safe",
            dropped(sanitizer.sanitizeEvidence(event(operationId = "op 1 /data/x"))),
        )
        assertEquals(
            "fields:host-utc-not-iso8601",
            dropped(sanitizer.sanitizeEvidence(event(hostUtcIso = "2026-10-31 06:43:01"))),
        )
        assertEquals(
            "fields:device-time-not-iso8601",
            dropped(sanitizer.sanitizeEvidence(event(deviceTimeIso = "14:43"))),
        )
        assertEquals(
            "fields:boot-id-not-machine-safe",
            dropped(sanitizer.sanitizeEvidence(event(bootId = "boot id/../../etc"))),
        )
        assertEquals(
            "fields:process-pid-out-of-range",
            dropped(sanitizer.sanitizeEvidence(event(processPid = 0))),
        )
    }

    @Test
    fun sanitizeEvidenceRedactsDetailAndOnlyKeepsHexBuildDigests() {
        val envelope = recorded(
            sanitizer.sanitizeEvidence(
                event(detail = "path=/data/data/pkg/files/x", buildDigest = "not-a-digest"),
            ),
        )
        assertEquals("path=/data/data/<package>/<seg>/<seg>", envelope.event.detail)
        assertNull(envelope.event.buildDigest)
        assertTrue(envelope.notes.contains("build-digest-dropped"))
        // 记录下来的事件必须自己通过结构化校验，才能写进 JSONL。
        assertNull(sanitizer.unsafeReason(envelope.event))
        assertEquals(envelope.event, UltraModuleEvidenceJson.decode(
            UltraModuleEvidenceJson.encode(envelope.event),
        )!!.event)
    }

    @Test
    fun buildDigestIsNormalizedWithoutBeingTreatedAsASecret() {
        val upper = moduleElfSha256.uppercase()
        val envelope = recorded(
            sanitizer.sanitizeEvidence(event(buildDigest = upper, detail = "ok")),
        )
        assertEquals(moduleElfSha256, envelope.event.buildDigest)
        // 摘要字段是结构化值，不受自由文本的“32 位十六进制 → <hex>”规则影响。
        assertEquals(moduleElfSha256, UltraModuleEvidenceJson.decode(
            UltraModuleEvidenceJson.encode(envelope.event),
        )!!.event.buildDigest)
    }

    // ------------------------------------------------------------------ 退出原因分类

    @Test
    fun debugAppForceStopIsNotACrash() {
        val classification = UltraModuleExitClassifier.classify(
            UltraModuleExitClassifier.Reason.USER_REQUESTED,
            UltraModuleExitClassifier.Subreason.FORCE_STOP,
            "stop dev.maplesu.manager due to set debug app state",
        )
        assertEquals(UltraModuleExitCategory.MANAGER_FORCE_STOP, classification.category)
        assertEquals(UltraModuleExitCode.FORCE_STOP_DEBUG_APP, classification.code)
        assertEquals(UltraModuleExitMarker.DEBUG_APP, classification.marker)
        assertTrue(classification.countsAsForceStop)
        assertFalse(classification.countsAsNativeOrCrash)
        assertEquals(
            "reason=10 subreason=21 category=MANAGER_FORCE_STOP code=FORCE_STOP_DEBUG_APP marker=DEBUG_APP",
            classification.summary(),
        )
    }

    @Test
    fun nativeCrashIsClassifiedAsNativeOrCrash() {
        val native = UltraModuleExitClassifier.classify(
            UltraModuleExitClassifier.Reason.CRASH_NATIVE,
            0,
            "native crash",
        )
        assertEquals(UltraModuleExitCategory.NATIVE_OR_CRASH, native.category)
        assertEquals(UltraModuleExitCode.CRASH_NATIVE, native.code)
        assertTrue(native.countsAsNativeOrCrash)
        assertFalse(native.countsAsForceStop)

        assertEquals(
            UltraModuleExitCode.CRASH_JAVA,
            UltraModuleExitClassifier.classify(UltraModuleExitClassifier.Reason.CRASH, 0, null).code,
        )
        assertEquals(
            UltraModuleExitCode.CRASH_SIGNALED,
            UltraModuleExitClassifier.classify(UltraModuleExitClassifier.Reason.SIGNALED, 0, null).code,
        )
    }

    @Test
    fun aForceStopDescriptionCannotReclassifyACrash() {
        val classification = UltraModuleExitClassifier.classify(
            UltraModuleExitClassifier.Reason.CRASH_NATIVE,
            UltraModuleExitClassifier.Subreason.FORCE_STOP,
            "stop dev.maplesu.manager due to set debug app state",
        )
        assertEquals(UltraModuleExitCategory.NATIVE_OR_CRASH, classification.category)
        assertEquals(UltraModuleExitCode.CRASH_NATIVE, classification.code)
        assertFalse(classification.countsAsForceStop)
    }

    @Test
    fun unknownReasonsNeverLandInTheCrashBucket() {
        val unrecognized = UltraModuleExitClassifier.classify(99, 0, null)
        assertEquals(UltraModuleExitCategory.UNKNOWN, unrecognized.category)
        assertEquals(UltraModuleExitCode.UNKNOWN_UNRECOGNIZED_REASON, unrecognized.code)
        assertFalse(unrecognized.countsAsNativeOrCrash)

        val unset = UltraModuleExitClassifier.classify(UltraModuleExitClassifier.Reason.UNKNOWN, 0, null)
        assertEquals(UltraModuleExitCategory.UNKNOWN, unset.category)
        assertEquals(UltraModuleExitCode.UNKNOWN_MISSING_REASON, unset.code)
        assertFalse(unset.countsAsNativeOrCrash)

        val negative = UltraModuleExitClassifier.classify(-1, 0, "")
        assertEquals(UltraModuleExitCategory.UNKNOWN, negative.category)
        assertFalse(negative.countsAsNativeOrCrash)
    }

    @Test
    fun anrIsNeitherACrashNorAnExternalForceStop() {
        val classification = UltraModuleExitClassifier.classify(
            UltraModuleExitClassifier.Reason.ANR,
            0,
            "ANR in dev.maplesu.manager",
        )
        assertEquals(UltraModuleExitCategory.OTHER, classification.category)
        assertEquals(UltraModuleExitCode.OTHER_ANR, classification.code)
        assertFalse(classification.countsAsNativeOrCrash)
        assertFalse(classification.countsAsForceStop)
    }

    @Test
    fun packageAndPermissionStopsAreExternalStops() {
        assertEquals(
            UltraModuleExitCode.FORCE_STOP_PACKAGE_UPDATED,
            UltraModuleExitClassifier.classify(UltraModuleExitClassifier.Reason.PACKAGE_UPDATED, 0, null).code,
        )
        assertEquals(
            UltraModuleExitCode.FORCE_STOP_PACKAGE_STATE_CHANGE,
            UltraModuleExitClassifier.classify(UltraModuleExitClassifier.Reason.PACKAGE_STATE_CHANGE, 0, null).code,
        )
        assertEquals(
            UltraModuleExitCode.FORCE_STOP_PERMISSION_CHANGE,
            UltraModuleExitClassifier.classify(UltraModuleExitClassifier.Reason.PERMISSION_CHANGE, 0, null).code,
        )
        assertEquals(
            UltraModuleExitCategory.MANAGER_FORCE_STOP,
            UltraModuleExitClassifier.classify(UltraModuleExitClassifier.Reason.PACKAGE_UPDATED, 0, null).category,
        )
    }

    @Test
    fun explicitForceStopSubreasonWinsAndStillPrefersTheDescription() {
        val fromSubreason = UltraModuleExitClassifier.classify(
            UltraModuleExitClassifier.Reason.UNKNOWN,
            UltraModuleExitClassifier.Subreason.FORCE_STOP,
            null,
        )
        assertEquals(UltraModuleExitCategory.MANAGER_FORCE_STOP, fromSubreason.category)
        assertEquals(UltraModuleExitCode.FORCE_STOP_EXPLICIT_SUBREASON, fromSubreason.code)

        val withDescription = UltraModuleExitClassifier.classify(
            UltraModuleExitClassifier.Reason.UNKNOWN,
            UltraModuleExitClassifier.Subreason.FORCE_STOP,
            "stop dev.maplesu.manager due to set debug app state",
        )
        assertEquals(UltraModuleExitCode.FORCE_STOP_DEBUG_APP, withDescription.code)
    }

    @Test
    fun descriptionMarkersRescueOnlyUninformativeReasons() {
        val instrumentation = UltraModuleExitClassifier.classify(
            UltraModuleExitClassifier.Reason.OTHER,
            0,
            "stop dev.maplesu.manager due to finished inst state",
        )
        assertEquals(UltraModuleExitCategory.MANAGER_FORCE_STOP, instrumentation.category)
        assertEquals(UltraModuleExitCode.FORCE_STOP_INSTRUMENTATION_FINISHED, instrumentation.code)

        val install = UltraModuleExitClassifier.classify(
            UltraModuleExitClassifier.Reason.UNKNOWN,
            0,
            "stop dev.maplesu.manager due to installPackageLI state",
        )
        assertEquals(UltraModuleExitCategory.MANAGER_FORCE_STOP, install.category)
        assertEquals(UltraModuleExitCode.FORCE_STOP_PACKAGE_INSTALL, install.code)

        // EXIT_SELF 等“有含义”的原因不被描述改写。
        val selfExit = UltraModuleExitClassifier.classify(
            UltraModuleExitClassifier.Reason.EXIT_SELF,
            0,
            "stop dev.maplesu.manager due to set debug app state",
        )
        assertEquals(UltraModuleExitCategory.OTHER, selfExit.category)
        assertEquals(UltraModuleExitCode.OTHER_SELF_EXIT, selfExit.code)
    }

    @Test
    fun tallySeparatesForceStopFromNativeCrashes() {
        val classifications = listOf(
            UltraModuleExitClassifier.classify(10, 21, "stop dev.maplesu.manager due to set debug app state"),
            UltraModuleExitClassifier.classify(16, 0, null),
            UltraModuleExitClassifier.classify(5, 0, null),
            UltraModuleExitClassifier.classify(4, 0, null),
            UltraModuleExitClassifier.classify(6, 0, null),
            UltraModuleExitClassifier.classify(99, 0, null),
        )
        val tally = UltraModuleExitTally.of(classifications)
        assertEquals(2, tally.managerForceStop)
        assertEquals(2, tally.nativeOrCrash)
        assertEquals(1, tally.other)
        assertEquals(1, tally.unknown)
        assertEquals(6, tally.total)
    }

    @Test
    fun exitCodesAndCategoriesAreStableUpperSnakeCaseMachines() {
        val codes = UltraModuleExitCode.values().map { it.name }
        assertEquals(codes.size, codes.toSet().size)
        codes.forEach { code ->
            assertTrue("不是稳定的机器码: $code", Regex("^[A-Z][A-Z0-9_]*$").matches(code))
        }
        UltraModuleExitCategory.values().forEach { category ->
            assertTrue(Regex("^[A-Z][A-Z0-9_]*$").matches(category.name))
        }
    }

    @Test
    fun aFullEventWithSanitizedDetailIsDeliverable() {
        val raw = event(
            detail = "path=/data/adb/modules/$moduleId/aah.log token=${"Zq9X".repeat(12)}",
        )
        val envelope = recorded(sanitizer.sanitizeEvidence(raw))
        assertEquals(
            "path=/data/adb/modules/$moduleId/<seg> token=<token>",
            envelope.event.detail,
        )
        assertTrue(envelope.notes.contains("private-path"))
        assertTrue(envelope.notes.contains("token-secret"))
        assertNull(sanitizer.unsafeReason(envelope.event))
        val line = UltraModuleEvidenceJson.encode(envelope.event)
        assertEquals(envelope.event, UltraModuleEvidenceJson.decode(line)!!.event)
    }
}
