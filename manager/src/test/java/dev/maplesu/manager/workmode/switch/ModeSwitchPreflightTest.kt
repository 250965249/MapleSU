package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.detect.ModeState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

/** S0 边检 + 空间/KMI/AVB 纯函数（02 §2.2 / §2.4 / S0-19 / S0-20）。 */
class ModeSwitchPreflightTest {

    private val bootSha = "a".repeat(64)
    private val initBootSha = "b".repeat(64)

    private fun presentBaseline(): BaselineVerification = BaselineVerification(
        state = BaselineState.PRESENT_OK,
        id = "bl-1",
        check = BaselineCheck("bl-1", BaselineProvenance.OEM_PACKAGE, bootSha, initBootSha, true),
        mismatch = emptyList(),
        blocker = null,
    )

    private fun inputs(): S0Inputs = S0Inputs(
        switchId = UUID.randomUUID().toString(),
        fromMode = WorkMode.LITE,
        toMode = WorkMode.KSU,
        currentMode = WorkMode.LITE,
        modeState = ModeState.MODE_A_ACTIVE,
        planned = listOf(
            PlannedPartition("boot", "RESTORE_BASELINE", 4096, bootSha),
            PlannedPartition("init_boot", "WRITE_CANDIDATE", 4096, initBootSha),
        ),
        baseline = presentBaseline(),
        device = SwitchDeviceFacts("_a", "fw-1", "5.10.198-android13-8-g1234"),
        battery = BatteryFacts(80, false),
        pending = PendingFacts(),
        rootRefusal = null,
        exportReceipt = mapOf("boot" to bootSha, "init_boot" to initBootSha),
        inventory = PartitionInventory(
            present = setOf("boot", "init_boot"),
            sizes = mapOf("boot" to 4096, "init_boot" to 4096),
            readOnly = emptyMap(),
        ),
        freeBytes = 1L shl 40,
    )

    private fun failure(report: S0Report): S0Check = requireNotNull(report.failure())

    @Test
    fun allTwentyTwoChecksPassOnCleanState() {
        val report = ModeSwitchPreflight.evaluate(inputs())
        assertTrue(report.checks.joinToString { it.id + ":" + it.code }, report.ok)
        assertEquals(22, report.checks.size)
        assertEquals("S0-01", report.checks.first().id)
        assertEquals("S0-22", report.checks.last().id)
    }

    @Test
    fun normalBootPlanAcceptsAndroid12WithoutInitBoot() {
        val original = inputs()
        val report = ModeSwitchPreflight.evaluate(original.copy(
            planned = listOf(PlannedPartition("boot", "WRITE_CANDIDATE", 4096, bootSha)),
            inventory = PartitionInventory(setOf("boot"), mapOf("boot" to 4096), emptyMap()),
            device = original.device.copy(kernelRelease = "5.10.198-android12-8-test"),
        ))
        assertTrue(report.checks.joinToString { it.id + ":" + it.code }, report.ok)
    }

    @Test
    fun explicitlySelectedSwitchInputNeedsNoFactoryCleanlinessClaim() {
        val base = presentBaseline()
        val selected = base.copy(check = base.check!!.copy(provenance = BaselineProvenance.USER_SELECTED, clean = false))
        val report = ModeSwitchPreflight.evaluate(inputs().copy(baseline = selected))
        assertTrue(report.checks.joinToString { it.id + ":" + it.code }, report.ok)
    }

    @Test
    fun bothWorkModesReuseOriginalStockDespiteDifferentRunningKernelLabels() {
        val manifest = TestFixtures.baselineManifest(
            firmware = "original-firmware", kernelRelease = "6.6.89-android15-8-stock",
            bootSha = bootSha, initBootSha = initBootSha,
        )
        for (from in listOf(WorkMode.LITE, WorkMode.KSU)) {
            val device = SwitchDeviceFacts("_a", "reported-${from.name}", "6.6.115-android15-8-${from.name}")
            val baseline = BaselineRules.evaluate(manifest, DeviceBootFacts(device.slot, device.firmware, device.kernelRelease))
            val report = ModeSwitchPreflight.evaluate(inputs().copy(
                fromMode = from,
                currentMode = from,
                toMode = if (from == WorkMode.LITE) WorkMode.KSU else WorkMode.LITE,
                modeState = if (from == WorkMode.LITE) ModeState.MODE_A_ACTIVE else ModeState.MODE_B_ACTIVE,
                device = device,
                baseline = baseline,
            ))
            assertTrue(from.name + ":" + report.checks.joinToString { it.id + ":" + it.code }, report.ok)
        }
    }

    @Test
    fun batteryReadingRemainsAnAdvisoryForEveryBoundary() {
        for (level in listOf(-1, 0, 3, 19, 20, 100)) {
            for (charging in listOf(false, true)) {
                val report = ModeSwitchPreflight.evaluate(inputs().copy(battery = BatteryFacts(level, charging)))
                assertTrue("level=$level charging=$charging", report.ok)
                val check = report.checks.single { it.id == "S0-10" }
                assertTrue(check.ok)
                assertEquals("", check.code)
                assertEquals("level=$level charging=$charging", check.detail)
                assertEquals(if (level < 20 && !charging) ModeSwitchCodes.BATTERY_LOW else "", check.advisory)
            }
        }
    }

    @Test
    fun currentModeAlreadyTargetIsSameMode() {
        val report = ModeSwitchPreflight.evaluate(inputs().copy(currentMode = WorkMode.KSU))
        assertEquals("S0-03", failure(report).id)
        assertEquals(ModeSwitchCodes.SAME_MODE, failure(report).code)
    }

    @Test
    fun foreignRootAndNotInstalledAreBlocked() {
        val foreign = ModeSwitchPreflight.evaluate(inputs().copy(modeState = ModeState.FOREIGN_SU))
        assertEquals("S0-01", failure(foreign).id)
        assertEquals(ModeSwitchCodes.FOREIGN_SU, failure(foreign).code)
        val missing = ModeSwitchPreflight.evaluate(inputs().copy(modeState = ModeState.NOT_INSTALLED))
        assertEquals(ModeSwitchCodes.NOT_INSTALLED, failure(missing).code)
        val undetermined = ModeSwitchPreflight.evaluate(inputs().copy(modeState = ModeState.INDETERMINATE))
        assertEquals(ModeSwitchCodes.STATE_UNDETERMINED, failure(undetermined).code)
    }

    @Test
    fun modeStateMustMatchRequestedSourceMode() {
        val report = ModeSwitchPreflight.evaluate(inputs().copy(modeState = ModeState.MODE_B_ACTIVE))
        assertEquals("S0-01", failure(report).id)
        assertEquals(ModeSwitchCodes.STATE_UNDETERMINED, failure(report).code)
    }

    @Test
    fun invalidSlotIsRejected() {
        val report = ModeSwitchPreflight.evaluate(
            inputs().copy(device = SwitchDeviceFacts("_c", "fw-1", "5.10.198-android13-8-g")),
        )
        assertEquals("S0-18", failure(report).id)
        assertEquals(ModeSwitchCodes.SLOT_INVALID, failure(report).code)
    }

    @Test
    fun android12KernelIsUnsupportedForInitBootRoute() {
        val report = ModeSwitchPreflight.evaluate(
            inputs().copy(device = SwitchDeviceFacts("_a", "fw-1", "5.10.198-android12-9-g1234")),
        )
        assertEquals("S0-19", failure(report).id)
        assertEquals(ModeSwitchCodes.KMI_UNSUPPORTED, failure(report).code)
    }

    @Test
    fun android12KernelIsAllowedWhenTargetIsBootOnly() {
        val report = ModeSwitchPreflight.evaluate(
            inputs().copy(
                fromMode = WorkMode.KSU,
                toMode = WorkMode.LITE,
                modeState = ModeState.MODE_B_ACTIVE,
                currentMode = WorkMode.KSU,
                device = SwitchDeviceFacts("_a", "fw-1", "5.10.198-android12-9-g1234"),
                planned = listOf(
                    PlannedPartition("init_boot", "RESTORE_BASELINE", 4096, initBootSha),
                    PlannedPartition("boot", "WRITE_CANDIDATE", 4096, bootSha),
                ),
            ),
        )
        assertTrue(report.checks.joinToString { it.id + ":" + it.code }, report.ok)
    }

    @Test
    fun missingInitBootBlocksKsuTargetButNotLiteTarget() {
        val inventory = PartitionInventory(
            present = setOf("boot"),
            sizes = mapOf("boot" to 4096),
        )
        val ksu = ModeSwitchPreflight.evaluate(inputs().copy(inventory = inventory))
        assertEquals("S0-17", failure(ksu).id)
        assertEquals(ModeSwitchCodes.LAYOUT_UNSUPPORTED, failure(ksu).code)
        val lite = ModeSwitchPreflight.evaluate(
            inputs().copy(
                fromMode = WorkMode.KSU,
                toMode = WorkMode.LITE,
                modeState = ModeState.MODE_B_ACTIVE,
                currentMode = WorkMode.KSU,
                inventory = inventory,
                planned = listOf(PlannedPartition("boot", "WRITE_CANDIDATE", 4096, bootSha)),
            ),
        )
        assertTrue(lite.checks.joinToString { it.id + ":" + it.code }, lite.ok)
    }

    @Test
    fun insufficientSpaceIsBlocked() {
        val report = ModeSwitchPreflight.evaluate(inputs().copy(freeBytes = 1024))
        assertEquals("S0-09", failure(report).id)
        assertEquals(ModeSwitchCodes.SPACE_INSUFFICIENT, failure(report).code)
    }

    @Test
    fun exportReceiptMustCoverEveryPlannedPartitionWithMatchingSha() {
        val missing = ModeSwitchPreflight.evaluate(
            inputs().copy(exportReceipt = mapOf("boot" to bootSha)),
        )
        assertEquals("S0-16", failure(missing).id)
        assertEquals(ModeSwitchCodes.EXPORT_REQUIRED, failure(missing).code)
        val mismatch = ModeSwitchPreflight.evaluate(
            inputs().copy(exportReceipt = mapOf("boot" to bootSha, "init_boot" to "c".repeat(64))),
        )
        assertEquals("S0-16", failure(mismatch).id)
    }

    @Test
    fun unknownAvbLayoutStopsTheSwitch() {
        val report = ModeSwitchPreflight.evaluate(
            inputs().copy(avb = SwitchAvbFacts(ModeSwitchCodes.AVB_LAYOUT_UNKNOWN, "non-zero tail")),
        )
        assertEquals("S0-20", failure(report).id)
        assertEquals(ModeSwitchCodes.AVB_LAYOUT_UNKNOWN, failure(report).code)
    }

    @Test
    fun staleBaselineBlocksS0AndDeviceConsistency() {
        val stale = BaselineVerification(
            BaselineState.STALE, "bl-1", null,
            listOf("firmware:old!=fw-1"), BaselineErrors.BASELINE_STALE,
        )
        val report = ModeSwitchPreflight.evaluate(inputs().copy(baseline = stale))
        assertEquals("S0-04", failure(report).id)
        assertEquals(BaselineErrors.BASELINE_STALE, failure(report).code)
        val codes = report.checks.filter { !it.ok }.map { it.code }.toSet()
        assertEquals(setOf(BaselineErrors.BASELINE_STALE, ModeSwitchCodes.DEVICE_CHANGED), codes)
    }

    @Test
    fun readOnlyPartitionBlocksS0() {
        val report = ModeSwitchPreflight.evaluate(
            inputs().copy(
                inventory = inputs().inventory.copy(readOnly = mapOf("init_boot" to true)),
            ),
        )
        assertEquals("S0-22", failure(report).id)
        assertEquals(ModeSwitchCodes.PARTITION_READONLY, failure(report).code)
    }

    @Test
    fun rootRefusalAndLiveJailbreakLeaseAreBlocked() {
        assertEquals("S0-11",
            failure(ModeSwitchPreflight.evaluate(inputs().copy(rootRefusal = "SWITCH_ROOT_UNAVAILABLE"))).id)
        assertEquals("S0-08",
            failure(ModeSwitchPreflight.evaluate(
                inputs().copy(pending = PendingFacts(jailbreakLeaseActive = true)),
            )).id)
    }

    @Test
    fun historicalInstallAndSwitchRecordsAreAdvisoriesWhileTheLiveWriterStillBlocks() {
        for (install in listOf(false, true)) for (switch in listOf(false, true)) {
            val pending = PendingFacts(installPending = install, switchPending = switch)
            val report = ModeSwitchPreflight.evaluate(inputs().copy(pending = pending))
            assertTrue("install=$install switch=$switch", report.ok)
            assertNull(report.failure())
            assertEquals(if (install) ModeSwitchCodes.INSTALL_PENDING else "",
                report.checks.single { it.id == "S0-06" }.advisory)
            assertEquals(if (switch) ModeSwitchCodes.PENDING else "",
                report.checks.single { it.id == "S0-07" }.advisory)
            val busy = ModeSwitchPreflight.evaluate(inputs().copy(
                pending = pending.copy(deviceLockAvailable = false),
            ))
            assertEquals("S0-14", failure(busy).id)
            assertEquals(ModeSwitchCodes.BUSY, failure(busy).code)
        }
    }

    @Test
    fun implantRestoreMaterialsOnlyRequiredWhenLeavingLite() {
        val leavingLite = ModeSwitchPreflight.evaluate(inputs().copy(implantRestoreReady = false))
        assertEquals("S0-15", failure(leavingLite).id)
        assertEquals(ModeSwitchCodes.IMPLANT_RESTORE_MISSING, failure(leavingLite).code)
        val enteringLite = ModeSwitchPreflight.evaluate(
            inputs().copy(
                fromMode = WorkMode.KSU,
                toMode = WorkMode.LITE,
                modeState = ModeState.MODE_B_ACTIVE,
                currentMode = WorkMode.KSU,
                implantRestoreReady = false,
                planned = listOf(
                    PlannedPartition("init_boot", "RESTORE_BASELINE", 4096, initBootSha),
                    PlannedPartition("boot", "WRITE_CANDIDATE", 4096, bootSha),
                ),
            ),
        )
        assertTrue(enteringLite.checks.joinToString { it.id + ":" + it.code }, enteringLite.ok)
    }

    @Test
    fun selinuxIsRecordedAsAdvisoryAndNeverBlocksS0() {
        // 2026-11-01 用户指令：只有「越狱模式」可拒绝刷写；SELinux 只记录，不得阻断切换。
        // 断言的是**具体返回值**（不是"恒真"）：每个取值都要求 S0-12 ok=true、code 为空、
        // detail 带真实读数，非 Enforcing 时 advisory 精确等于
        // `INSTALLER_SELINUX_NOT_ENFORCING:selinux=<值>`。
        for (value in listOf("Permissive", "Disabled", "Unknown", "Enforcing")) {
            val report = ModeSwitchPreflight.evaluate(
                inputs().copy(device = inputs().device.copy(selinux = value)),
            )
            assertTrue(
                "selinux=$value 不得阻断: " + report.checks.joinToString { it.id + ":" + it.code },
                report.ok,
            )
            assertNull("selinux=$value 不得产生 failure", report.failure())
            val check = report.checks.single { it.id == "S0-12" }
            assertEquals("S0-12", check.id)
            assertTrue("selinux=$value 的 S0-12 必须 ok", check.ok)
            assertEquals("", check.code)
            assertEquals("selinux=$value", check.detail)
            if (value == "Enforcing") {
                assertEquals("", check.advisory)
                assertTrue(report.advisories().isEmpty())
            } else {
                assertEquals(
                    "${ModeSwitchCodes.SELINUX_NOT_ENFORCING}:selinux=$value",
                    check.advisory,
                )
                assertEquals(listOf("S0-12"), report.advisories().map { it.id })
            }
            // 其它 21 项不受影响（矩阵形状不变）。
            assertEquals(22, report.checks.size)
        }
    }

    @Test
    fun selinuxCheckKeepsAppAndServiceViewsIdentical() {
        // S0a（App 侧 evaluate）与 S0b（LocalInstallerGateway / ModeSwitchDeviceDelegate）
        // 共用同一个工厂：同一事实必须得到同一行，否则 UI 矩阵会出现两种结论。
        for (value in listOf("Enforcing", "Permissive", "Disabled", "Unknown", "")) {
            val fromFactory = ModeSwitchPreflight.selinuxCheck(value)
            val fromMatrix = ModeSwitchPreflight.evaluate(
                inputs().copy(device = inputs().device.copy(selinux = value)),
            ).checks.single { it.id == ModeSwitchPreflight.SELINUX_CHECK_ID }
            assertEquals("selinux=$value", fromFactory, fromMatrix)
            assertTrue("selinux=$value", fromFactory.ok)
        }
        // 空白读数是 "Unknown"，不能伪装成 Enforcing。
        assertEquals("selinux=Unknown", ModeSwitchPreflight.selinuxCheck("").detail)
        assertEquals(
            "${ModeSwitchCodes.SELINUX_NOT_ENFORCING}:selinux=Unknown",
            ModeSwitchPreflight.selinuxCheck(" ").advisory,
        )
    }

    @Test
    fun serviceChecksOverrideLocalSuccessAndLocalFailureWinsOnlyForSameId() {
        val report = ModeSwitchPreflight.evaluate(inputs())
        val merged = report.merge(listOf(S0Check("S0-12", false, ModeSwitchCodes.SELINUX_NOT_ENFORCING, "svc")))
        assertFalse(merged.ok)
        assertEquals(ModeSwitchCodes.SELINUX_NOT_ENFORCING, requireNotNull(merged.failure()).code)
    }

    @Test
    fun spaceBudgetCountsTwoCopiesOfEveryPartitionPlusCandidateAndReserve() {
        val sizes = mapOf("boot" to 4096L, "init_boot" to 8192L)
        val required = ModeSwitchSpaceBudget.required(sizes, "init_boot", 1000)
        assertEquals((4096 + 8192) * 2 + 8192 + 1000, required)
        assertNull(ModeSwitchSpaceBudget.check(required, required))
        assertEquals(ModeSwitchCodes.SPACE_INSUFFICIENT, ModeSwitchSpaceBudget.check(required - 1, required))
    }

    @Test
    fun kmiParsingAndSupportRule() {
        assertEquals("android13-5.10", ModeSwitchKmi.parse("5.10.198-android13-8-g1234"))
        assertEquals("android12-4.19", ModeSwitchKmi.parse("4.19.157-android12-9-gabc"))
        assertEquals("android14-6.1", ModeSwitchKmi.parse("android14-6.1"))
        assertNull(ModeSwitchKmi.parse("garbage"))
        assertTrue(ModeSwitchKmi.supported("5.10.198-android13-8-g1234"))
        assertFalse(ModeSwitchKmi.supported("4.19.157-android12-9-gabc"))
        assertFalse(ModeSwitchKmi.supported("garbage"))
    }

    @Test
    fun avbFooterParsingAndVerdicts() {
        val footer = ByteArray(64)
        "AVBf".toByteArray().copyInto(footer, 0)
        putLong(footer, 12, 4096)
        putLong(footer, 20, 0)
        putLong(footer, 28, 64)
        val facts = ModeSwitchAvb.inspectTail(footer, 4096)
        assertTrue(facts.footerPresent)
        assertEquals(4096L, facts.originalImageSize)
        assertNull(ModeSwitchAvb.evaluate(facts, 4096))

        val zero = ByteArray(64)
        assertNull(ModeSwitchAvb.evaluate(ModeSwitchAvb.inspectTail(zero, 4096), 4096))

        val garbage = ByteArray(64) { 0x7f }
        assertEquals(ModeSwitchCodes.AVB_LAYOUT_UNKNOWN,
            ModeSwitchAvb.evaluate(ModeSwitchAvb.inspectTail(garbage, 4096), 4096))

        val oversized = footer.copyOf().also { putLong(it, 12, 8192) }
        assertEquals(ModeSwitchCodes.AVB_LAYOUT_UNKNOWN,
            ModeSwitchAvb.evaluate(ModeSwitchAvb.inspectTail(oversized, 4096), 4096))

        assertTrue(ModeSwitchAvb.hasVbmetaHeader("AVB0".toByteArray() + ByteArray(8)))
        assertFalse(ModeSwitchAvb.hasVbmetaHeader("AVBf".toByteArray() + ByteArray(8)))
        assertNotNull(facts)
    }

    private fun putLong(target: ByteArray, offset: Int, value: Long) {
        for (index in 0 until 8) {
            target[offset + index] = ((value ushr (8 * (7 - index))) and 0xff).toByte()
        }
    }
}
