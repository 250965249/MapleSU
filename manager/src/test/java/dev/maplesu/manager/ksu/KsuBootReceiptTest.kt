// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * T3 判据（P1–P10）与状态机的**主机**单测（无设备、无 root、无 android）。
 *
 * 覆盖开发文档 §6 T3：
 * - 10 条判据的过/不过各一例（每条都有具名 code）；
 * - 状态机 `Unknown → Ready | StagesNotRun | VersionMismatch | KsudMissing | Broken`；
 * - `bootEpoch` 的 ±90 s 容差边界；
 * - **P8 按 T0 现场的 `mountify` 形态**判（`grep ' KSU '` 恒 0 不得判失败）。
 */
class KsuBootReceiptTest {

    private val epoch = KsuBootReceiptFixture.EPOCH

    private fun receipt(
        probe: KsuBootReceiptFakeProbe,
        kernelVersion: Int? = KsuBootReceiptFixture.KERNEL_VERSION,
        kernelUapi: Int? = KsuBootReceiptFixture.KERNEL_UAPI,
        bootEpoch: Long = epoch,
    ) = KsuBootReceipt(
        probe = probe,
        kernelVersion = { kernelVersion },
        kernelUapi = { kernelUapi },
        bootEpochMs = { bootEpoch },
        clock = { KsuBootReceiptFixture.NOW },
    )

    private fun failedCodes(state: KsuRuntimeState): List<String> = when (state) {
        is KsuRuntimeState.StagesNotRun -> state.failedCodes
        is KsuRuntimeState.Broken -> listOf(state.code)
        else -> emptyList()
    }

    // ── 全绿 ────────────────────────────────────────────────────────────

    @Test
    fun readyWhenEveryJudgePasses() {
        val probe = KsuBootReceiptFakeProbe()
        assertEquals(KsuRuntimeState.Ready, receipt(probe).evaluate())
        assertTrue("探针必须被真的问过", probe.calls > 0)
    }

    // ── P1 / P2 / P7：本 boot 的日志与 preinit ──────────────────────────

    @Test
    fun p1StaleBootLogIsStagesNotRun() {
        val probe = KsuBootReceiptFakeProbe().apply {
            mtimes[KsuBootReceipt.LOG_CAT] = epoch - 200_000L
        }
        val state = receipt(probe).evaluate()
        assertTrue(state is KsuRuntimeState.StagesNotRun)
        assertTrue(
            "P1 code",
            failedCodes(state).contains(KsuBootReceipt.CODE_BOOT_LOG_NOT_REFRESHED),
        )
    }

    @Test
    fun p2StaleDmesgIsStagesNotRun() {
        val probe = KsuBootReceiptFakeProbe().apply {
            mtimes[KsuBootReceipt.DMESG_LOG] = epoch - 200_000L
        }
        val state = receipt(probe).evaluate()
        assertTrue(
            "P2 code",
            failedCodes(state).contains(KsuBootReceipt.CODE_BOOT_DMESG_NOT_REFRESHED),
        )
    }

    @Test
    fun p7MissingPreinitIsStagesNotRun() {
        val probe = KsuBootReceiptFakeProbe().apply {
            mtimes.remove(KsuBootReceipt.PREINIT_STATUS)
        }
        val state = receipt(probe).evaluate()
        assertTrue(
            "P7 code",
            failedCodes(state).contains(KsuBootReceipt.CODE_PREINIT_NOT_GENERATED),
        )
    }

    @Test
    fun missingLogcatIsStagesNotRunNotPass() {
        // 设备验收口径（T3 验收：删 logcat.log → STAGES_NOT_RUN）：文件不存在 = 没跑，不是"未知"。
        val probe = KsuBootReceiptFakeProbe().apply { mtimes.remove(KsuBootReceipt.LOG_CAT) }
        val state = receipt(probe).evaluate()
        assertTrue(state is KsuRuntimeState.StagesNotRun)
        assertTrue(failedCodes(state).contains(KsuBootReceipt.CODE_BOOT_LOG_NOT_REFRESHED))
    }

    // ── P3：版本配对（内核侧读不到 = UNKNOWN）───────────────────────────

    @Test
    fun p3UapiMismatchIsVersionMismatch() {
        val probe = KsuBootReceiptFakeProbe().apply {
            version = KsuVersionInfo(
                version = KsuBootReceiptFixture.KERNEL_VERSION,
                uapiVersion = 6,
                isLkm = true,
                flags = 5L,
            )
        }
        assertEquals(
            KsuRuntimeState.VersionMismatch(
                kernelVersion = KsuBootReceiptFixture.KERNEL_VERSION,
                ksudVersion = KsuBootReceiptFixture.KERNEL_VERSION,
                kernelUapi = KsuBootReceiptFixture.KERNEL_UAPI,
                ksudUapi = 6,
            ),
            receipt(probe).evaluate(),
        )
    }

    @Test
    fun p3OldKernelUapiIsVersionMismatchEvenWithCurrentDaemon() {
        assertEquals(
            KsuRuntimeState.VersionMismatch(
                kernelVersion = KsuBootReceiptFixture.KERNEL_VERSION,
                ksudVersion = KsuBootReceiptFixture.KERNEL_VERSION,
                kernelUapi = 6,
                ksudUapi = KsuBootReceiptFixture.KERNEL_UAPI,
            ),
            receipt(KsuBootReceiptFakeProbe(), kernelUapi = 6).evaluate(),
        )
    }

    @Test
    fun p3VersionMismatchIsVersionMismatch() {
        val probe = KsuBootReceiptFakeProbe().apply {
            version = KsuVersionInfo(version = 32513, uapiVersion = 7, isLkm = true, flags = 5L)
        }
        val state = receipt(probe).evaluate()
        assertTrue(state is KsuRuntimeState.VersionMismatch)
        assertEquals(32513, (state as KsuRuntimeState.VersionMismatch).ksudVersion)
    }

    @Test
    fun p3UnreadableKernelSideIsUnknownNeverPass() {
        val state = receipt(KsuBootReceiptFakeProbe(), kernelVersion = null).evaluate()
        assertEquals(KsuRuntimeState.Unknown, state)
        assertFalse("内核侧读不到不得是 Ready", state == KsuRuntimeState.Ready)
    }

    @Test
    fun unreadableKsudDebugInfoIsKsudMissing() {
        val probe = KsuBootReceiptFakeProbe().apply { version = null }
        assertEquals(KsuRuntimeState.KsudMissing, receipt(probe).evaluate())
    }

    // ── P4：列表可用 ────────────────────────────────────────────────────

    @Test
    fun p4UnparseableModuleListIsBroken() {
        val probe = KsuBootReceiptFakeProbe().apply {
            modules = null
            enabled = null
        }
        val state = receipt(probe).evaluate()
        assertTrue(state is KsuRuntimeState.Broken)
        assertEquals(
            KsuBootReceipt.CODE_MODULE_LIST_UNAVAILABLE,
            (state as KsuRuntimeState.Broken).code,
        )
    }

    // ── P5 / P6：脚本真跑 ───────────────────────────────────────────────

    @Test
    fun p5NoExecMarkerIsStagesNotRun() {
        val probe = KsuBootReceiptFakeProbe().apply { executed = emptyList() }
        val state = receipt(probe).evaluate()
        assertTrue(
            "P5 code",
            failedCodes(state).contains(KsuBootReceipt.CODE_MODULE_SCRIPTS_NOT_EXECUTED),
        )
    }

    @Test
    fun p5UnreadableLogcatIsStagesNotRun() {
        val probe = KsuBootReceiptFakeProbe().apply { executed = null }
        val state = receipt(probe).evaluate()
        assertTrue(
            failedCodes(state).contains(KsuBootReceipt.CODE_MODULE_SCRIPTS_NOT_EXECUTED),
        )
    }

    @Test
    fun p6EnabledButNotExecutedIsPartial() {
        val probe = KsuBootReceiptFakeProbe().apply {
            enabled = listOf("zygisksu", "playintegrityfix")
            executed = listOf("zygisksu")
            modules = listOf("zygisksu", "playintegrityfix")
        }
        val state = receipt(probe).evaluate()
        assertTrue(
            "P6 code",
            failedCodes(state).contains(KsuBootReceipt.CODE_MODULE_EXEC_PARTIAL),
        )
    }

    // ── P8：metamodule 挂载（T0 现场形态）──────────────────────────────

    @Test
    fun p8OverlayLowerdirCountsEvenWhenKsuGrepIsZero() {
        val probe = KsuBootReceiptFakeProbe().apply {
            link = true
            ksuMounts = 0 // T0 §7：mountify 恒为 0，不得据此判失败
            texts[KsuBootReceipt.PROC_MOUNTS] = KsuBootReceiptFixture.MOUNTIFY_STYLE_MOUNT
        }
        assertEquals(KsuRuntimeState.Ready, receipt(probe).evaluate())
    }

    @Test
    fun p8MetamoduleSelfReportCounts() {
        val probe = KsuBootReceiptFakeProbe().apply {
            link = true
            ksuMounts = 0
            texts[KsuBootReceipt.PROC_MOUNTS] = ""
            selfReport = "mountify: mounted 3 modules"
        }
        assertEquals(KsuRuntimeState.Ready, receipt(probe).evaluate())
    }

    @Test
    fun p8NoMountEvidenceIsMetamoduleNotMounted() {
        val probe = KsuBootReceiptFakeProbe().apply {
            link = true
            ksuMounts = 0
            texts[KsuBootReceipt.PROC_MOUNTS] = "tmpfs /tmp tmpfs rw 0 0"
            selfReport = null
        }
        val state = receipt(probe).evaluate()
        assertTrue(state is KsuRuntimeState.Broken)
        assertEquals(
            KsuBootReceipt.CODE_METAMODULE_NOT_MOUNTED,
            (state as KsuRuntimeState.Broken).code,
        )
    }

    @Test
    fun p8SkippedWhenNoMetamodulePointer() {
        val probe = KsuBootReceiptFakeProbe().apply {
            link = false
            ksuMounts = 0
            texts[KsuBootReceipt.PROC_MOUNTS] = ""
        }
        assertEquals(KsuRuntimeState.Ready, receipt(probe).evaluate())
    }

    // ── P9：zygisksu 守护 ───────────────────────────────────────────────

    @Test
    fun p9ZygiskDaemonAbsentIsBroken() {
        val probe = KsuBootReceiptFakeProbe().apply { processes = emptyList() }
        val state = receipt(probe).evaluate()
        assertTrue(state is KsuRuntimeState.Broken)
        assertEquals(
            KsuBootReceipt.CODE_ZYGISK_DAEMON_ABSENT,
            (state as KsuRuntimeState.Broken).code,
        )
    }

    @Test
    fun p9NotApplicableWithoutZygisksu() {
        val probe = KsuBootReceiptFakeProbe().apply {
            modules = listOf("playintegrityfix")
            enabled = listOf("playintegrityfix")
            executed = listOf("playintegrityfix")
            processes = emptyList() // 没装 zygisksu：守护不在也不算故障
        }
        assertEquals(KsuRuntimeState.Ready, receipt(probe).evaluate())
    }

    // ── P10：busybox ───────────────────────────────────────────────────

    @Test
    fun p10UnusableBusyboxIsBroken() {
        val probe = KsuBootReceiptFakeProbe().apply { busybox = false }
        val state = receipt(probe).evaluate()
        assertTrue(state is KsuRuntimeState.Broken)
        assertEquals(
            KsuBootReceipt.CODE_BUSYBOX_UNUSABLE,
            (state as KsuRuntimeState.Broken).code,
        )
    }

    @Test
    fun p10UnreadableBusyboxIsUnknownNotReady() {
        val probe = KsuBootReceiptFakeProbe().apply { busybox = null }
        assertEquals(KsuRuntimeState.Unknown, receipt(probe).evaluate())
    }

    // ── 容差 ±90 s ─────────────────────────────────────────────────────

    @Test
    fun toleranceAcceptsJustInside90Seconds() {
        val probe = KsuBootReceiptFakeProbe().apply {
            mtimes[KsuBootReceipt.LOG_CAT] = epoch - 89_999L
        }
        assertEquals(KsuRuntimeState.Ready, receipt(probe).evaluate())
    }

    @Test
    fun toleranceRejectsJustOutside90Seconds() {
        val probe = KsuBootReceiptFakeProbe().apply {
            mtimes[KsuBootReceipt.LOG_CAT] = epoch - 90_001L
        }
        val state = receipt(probe).evaluate()
        assertTrue(
            "P1 code",
            failedCodes(state).contains(KsuBootReceipt.CODE_BOOT_LOG_NOT_REFRESHED),
        )
    }

    @Test
    fun unknownBootEpochIsUnknownNeverReady() {
        assertEquals(
            KsuRuntimeState.Unknown,
            receipt(KsuBootReceiptFakeProbe(), bootEpoch = -1L).evaluate(),
        )
    }

    // ── 证据解析（生产探针复用）────────────────────────────────────────

    @Test
    fun parseExecutedModuleIdsIgnoresOneShotDotScripts() {
        val ids = KsuBootReceipt.parseExecutedModuleIds(KsuBootReceiptFixture.LOGCAT_SAMPLE)
        assertEquals(
            listOf("zygisksu", "playintegrityfix", "auditpatch", "MapleOwn"),
            ids,
        )
        assertFalse("post-fs-data.d 不属于任何模块", ids.any { it.contains("auditpatch.sh") })
    }

    @Test
    fun parseExecutedModuleIdsRejectsGarbageAfterMarker() {
        val ids = KsuBootReceipt.parseExecutedModuleIds(
            "x ksud::module: exec /data/adb/modules//broken.sh\n" +
                "y ksud::module: exec /data/adb/modules/bad id/x.sh",
        )
        assertEquals(emptyList<String>(), ids)
    }

    @Test
    fun hasModuleMountOnlyLooksAtOverlayOptions() {
        // 挂载点恰好在 /data/adb/modules 下，但没有任何 lower/upper 指向它 → 不算模块挂载。
        assertFalse(
            KsuBootReceipt.hasModuleMount(
                "/dev/block/dm-1 /data/adb/modules ext4 rw,seclabel 0 0",
            ),
        )
        assertTrue(KsuBootReceipt.hasModuleMount(KsuBootReceiptFixture.MOUNTIFY_STYLE_MOUNT))
        assertTrue(
            "metamodule 指针也算",
            KsuBootReceipt.hasModuleMount(
                "overlay /system overlay rw,lowerdir=/data/adb/metamodule/system 0 0",
            ),
        )
        assertFalse("空挂载表", KsuBootReceipt.hasModuleMount(""))
    }

    @Test
    fun parseModuleIdsRejectsUnparseableOutput() {
        assertNull(KsuBootReceipt.parseModuleIds("not json at all"))
        assertNull(KsuBootReceipt.parseModuleIds("{\"id\":\"x\"}"))
        assertNull(KsuBootReceipt.parseModuleIds(""))
    }

    @Test
    fun parseEnabledModuleIdsFiltersDisabledRows() {
        val json = """
            [
              {"id":"zygisksu","enabled":"true"},
              {"id":"disabled_one","enabled":"false"},
              {"id":"no_flag"},
              {"id":"bad id","enabled":"true"}
            ]
        """.trimIndent()
        assertEquals(listOf("zygisksu"), KsuBootReceipt.parseEnabledModuleIds(json))
        assertEquals(
            listOf("zygisksu", "disabled_one", "no_flag"),
            KsuBootReceipt.parseModuleIds(json),
        )
    }
}
