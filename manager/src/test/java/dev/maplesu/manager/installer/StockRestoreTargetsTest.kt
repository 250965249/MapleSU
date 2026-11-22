package dev.maplesu.manager.installer

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class StockRestoreTargetsTest {
    @Test
    fun completedBootInstallSelectsOnlyItsCarrier() {
        val fixture = Fixture()
        assertEquals(setOf("boot"), fixture.select(fixture.record("boot")).targets)
    }

    @Test
    fun completedInitBootInstallSelectsOnlyItsCarrier() {
        val fixture = Fixture()
        assertEquals(setOf("init_boot"), fixture.select(fixture.record("init_boot", "KSU"), mode = "KSU").targets)
    }

    @Test
    fun actualInitBootCompatibilityWritesRemainRequiredTargets() {
        val fixture = Fixture(includeVendor = true)
        val record = fixture.record("boot", compatibility = setOf("init_boot"))
        val selection = fixture.select(record)
        assertEquals(setOf("boot", "init_boot"), selection.targets)
        failsWith("INSTALLER_STOCK_TARGETS_INVALID") {
            StockRestoreTargets.requireSameTargets(setOf("boot"), selection)
        }
    }

    @Test
    fun vendorBootCompatibilityKeepsTheFullRestoreContract() {
        val fixture = Fixture(includeVendor = true)
        val record = fixture.record("boot", compatibility = setOf("vendor_boot"))
        assertEquals(FULL, fixture.select(record).targets)
    }

    @Test
    fun restoredCompanionIsExcludedEvenWhenItsFinalHashDiffersFromPre() {
        val fixture = Fixture()
        val record = fixture.record("boot")
        fixture.before(record, "init_boot").put("sha256", hash(2))
        assertEquals(setOf("boot"), fixture.select(record).targets)
    }

    @Test
    fun conflictingValidRecordsFailInEitherOrder() {
        val fixture = Fixture()
        val boot = fixture.record("boot", "KSU")
        val initBoot = fixture.record("init_boot", "KSU", id = "22222222-2222-4222-8222-222222222222")
        for (records in listOf(listOf(boot, initBoot), listOf(initBoot, boot))) {
            failsWith("INSTALLER_STOCK_TARGETS_AMBIGUOUS") {
                StockRestoreTargets.select(fixture.snapshot, "KSU", records, CURRENT_BOOT)
            }
        }
    }

    @Test
    fun missingCurrentInstallEvidenceKeepsTheFullRestoreContract() {
        val fixture = Fixture(includeVendor = true)
        val selection = StockRestoreTargets.select(fixture.snapshot, "LITE", emptyList(), CURRENT_BOOT)
        assertEquals(setOf("boot", "init_boot"), selection.targets)
        assertEquals("FULL_NO_CURRENT_INSTALL", selection.coverage)
        assertEquals(emptyMap<String, String>(), selection.sourceProofs)
    }

    @Test
    fun crossModeOrSignedCurrentInstallKeepsFullCoverage() {
        val fixture = Fixture()
        assertEquals(FULL, fixture.select(fixture.record("init_boot", "KSU")).targets)
        val signed = Fixture(includeVbmeta = true)
        val record = signed.record("boot").put("signingMode", "CHAINED")
        signed.before(record, "vbmeta").put("sha256", hash(9))
        assertEquals(FULL, signed.select(record).targets)
    }

    @Test
    fun unsignedInstallAllowsObservedVbmetaWhenItsUntrackedBytesAreUnchanged() {
        val fixture = Fixture(includeVbmeta = true)
        val record = fixture.record("boot")
        record.getJSONObject("expected").remove("vbmeta")
        assertEquals(setOf("boot"), fixture.select(record).targets)
    }

    @Test
    fun changedUntrackedVbmetaKeepsTheFullRestoreContract() {
        val fixture = Fixture(includeVbmeta = true)
        val record = fixture.record("boot")
        record.getJSONObject("expected").remove("vbmeta")
        fixture.before(record, "vbmeta").put("sha256", hash(9))
        assertEquals(FULL, fixture.select(record).targets)
    }

    @Test
    fun slotFirmwarePathSizeAndDeviceMismatchesKeepFullCoverage() {
        val fixture = Fixture()
        val changed = listOf<(JSONObject) -> Unit>(
            { it.getJSONObject("snapshot").put("slotSuffix", "_b") },
            { it.getJSONObject("snapshot").put("firmware", "different-firmware") },
            { fixture.before(it, "boot").put("resolvedPath", "/dev/block/different") },
            { fixture.before(it, "boot").put("size", 8192L) },
            { fixture.before(it, "boot").put("deviceNumber", 999L) },
        )
        changed.forEach { mutate ->
            val record = fixture.record("boot")
            mutate(record)
            assertEquals(FULL, fixture.select(record).targets)
        }
    }

    @Test
    fun fullExpectedMapMustMatchEveryCurrentPartition() {
        val fixture = Fixture(includeVendor = true)
        val missing = fixture.record("boot")
        missing.getJSONObject("expected").remove("vendor_boot")
        assertEquals(FULL, fixture.select(missing).targets)
        val changed = fixture.record("boot")
        changed.getJSONObject("expected").put("init_boot", hash(9))
        assertEquals(FULL, fixture.select(changed).targets)
        val missingPartition = fixture.record("boot")
        missingPartition.getJSONObject("snapshot").getJSONObject("partitions").remove("init_boot")
        assertEquals(FULL, fixture.select(missingPartition).targets)
    }

    @Test
    fun sameBootRequiresTheCompletePartitionIdentity() {
        val fixture = Fixture()
        for (field in listOf("inode", "filesystem")) {
            val record = fixture.record("boot")
            fixture.before(record, "init_boot").put(field, 999L)
            assertEquals(FULL, fixture.select(record).targets)
        }
    }

    @Test
    fun anotherBootAllowsNewInodeAndFilesystemButStillRequiresTheSameDevice() {
        val fixture = Fixture()
        val record = fixture.record("boot").put("bootId", PREVIOUS_BOOT)
        fixture.before(record, "boot").put("inode", 999L).put("filesystem", 999L)
        assertEquals(setOf("boot"), fixture.select(record).targets)
        fixture.before(record, "boot").put("deviceNumber", 999L)
        assertEquals(FULL, fixture.select(record).targets)
    }

    @Test
    fun onlyCompletedNativeInstallRecordsProvideSubsetEvidence() {
        val fixture = Fixture()
        for ((field, value) in listOf(
            "schema" to 2, "kind" to "SWITCH", "operation" to "RESTORE_STOCK", "state" to "PREPARED",
        )) {
            assertEquals(FULL, fixture.select(fixture.record("boot").put(field, value)).targets)
        }
        assertEquals(setOf("boot"), fixture.select(fixture.record("boot").put("state", "REBOOT_REQUIRED")).targets)
    }

    @Test
    fun emptyOrIncompleteActualTargetsFailInsteadOfReportingSuccess() {
        val fixture = Fixture()
        val selection = fixture.select(fixture.record("boot"))
        failsWith("INSTALLER_STOCK_TARGETS_INVALID") {
            StockRestoreTargets.requireSameTargets(emptySet(), selection)
        }
        failsWith("INSTALLER_STOCK_TARGETS_INVALID") {
            StockRestoreTargets.requireSameTargets(setOf("init_boot"), selection)
        }
        StockRestoreTargets.requireSameTargets(setOf("boot"), selection)
    }

    @Test
    fun savedTargetsReplayTheSameProofAcrossCompletedStateChanges() {
        val fixture = Fixture(includeVbmeta = true)
        val source = fixture.record("boot").put("state", "REBOOT_REQUIRED")
        source.getJSONObject("expected").remove("vbmeta")
        val record = saved(fixture, source)
        source.put("state", "BOOT_IMAGE_VERIFIED")
        assertEquals(setOf("boot"), StockRestoreTargets.saved(record, fixture.snapshot, listOf(source)))
    }

    @Test
    fun savedTargetsRejectAnEmptySetOrAnOmittedCompatibilityCarrier() {
        val fixture = Fixture()
        val source = fixture.record("boot", compatibility = setOf("init_boot"))
        for (targets in listOf(emptyList(), listOf("boot"), listOf("boot", "boot", "init_boot"))) {
            val record = saved(fixture, source).put("stockRestoreTargets", JSONArray(targets))
            failsWith("INSTALLER_STOCK_TARGETS_INVALID") {
                StockRestoreTargets.saved(record, fixture.snapshot, listOf(source))
            }
        }
    }

    @Test
    fun savedTargetsRejectMissingOrChangedSourceProofs() {
        val fixture = Fixture()
        val source = fixture.record("boot")
        val record = saved(fixture, source)
        failsWith("INSTALLER_STOCK_TARGETS_INVALID") { StockRestoreTargets.saved(record, fixture.snapshot, emptyList()) }
        fixture.before(source, "boot").put("sha256", hash(8))
        failsWith("INSTALLER_STOCK_TARGETS_INVALID") { StockRestoreTargets.saved(record, fixture.snapshot, listOf(source)) }
    }

    @Test
    fun fullFallbackAndLegacyRecordsKeepEveryCarrier() {
        val fixture = Fixture()
        assertEquals(FULL, StockRestoreTargets.saved(JSONObject(), fixture.snapshot, emptyList()))
        val record = JSONObject().put("stockRestoreSources", JSONObject()).put("stockRestoreTargets", JSONArray(listOf("boot")))
        failsWith("INSTALLER_STOCK_TARGETS_INVALID") { StockRestoreTargets.saved(record, fixture.snapshot, emptyList()) }
    }

    @Test fun signedInitBootWithUnchangedVbmetaSelectsOnlyItsCarrier() {
        val fixture = Fixture(includeVbmeta = true)
        val source = fixture.record("init_boot").put("signingMode", "NON_CHAINED")
        val selection = fixture.select(source)
        assertEquals(setOf("init_boot"), selection.targets)
        assertEquals("CURRENT_NATIVE_INSTALL", selection.coverage)
        assertEquals(1, selection.sourceProofs.size)
        assertEquals(setOf("init_boot"), StockRestoreTargets.saved(saved(fixture, source), fixture.snapshot, listOf(source)))
    }

    @Test fun signedBootWithUnchangedVbmetaPreservesItsSubset() {
        val fixture = Fixture(includeVbmeta = true)
        val source = fixture.record("boot").put("signingMode", "CHAINED")
        assertEquals(setOf("boot"), fixture.select(source).targets)
    }

    @Test fun signedChangedVbmetaRetainsFullSignedCoverage() {
        val fixture = Fixture(includeVbmeta = true)
        val source = fixture.record("init_boot").put("signingMode", "NON_CHAINED")
        fixture.before(source, "vbmeta").put("sha256", hash(9))
        val selection = fixture.select(source)
        assertEquals(FULL, selection.targets)
        assertEquals("FULL_SIGNED_INSTALL", selection.coverage)
        assertEquals(emptyMap<String, String>(), selection.sourceProofs)
    }

    @Test fun signedCompatibilityMustEqualEveryActuallyChangedCarrier() {
        val fixture = Fixture(includeVbmeta = true)
        val source = fixture.record("boot", compatibility = setOf("init_boot")).put("signingMode", "CHAINED")
        assertEquals("CURRENT_NATIVE_INSTALL", fixture.select(source).coverage)
        source.put("compatibilityPartitions", JSONArray())
        assertEquals("FULL_SIGNED_INSTALL", fixture.select(source).coverage)
    }

    @Test fun signedVendorChangeRetainsFullSignedCoverage() {
        val fixture = Fixture(includeVbmeta = true, includeVendor = true)
        val source = fixture.record("boot", compatibility = setOf("vendor_boot")).put("signingMode", "CHAINED")
        assertEquals("FULL_SIGNED_INSTALL", fixture.select(source).coverage)
    }

    @Test fun signedSubsetNeedsCompleteValidPreAndPostCompanionHashes() {
        val fixture = Fixture(includeVbmeta = true)
        for (invalid in listOf("", "not-a-sha256")) {
            val source = fixture.record("init_boot").put("signingMode", "NON_CHAINED")
            fixture.before(source, "vbmeta").put("sha256", invalid)
            assertEquals("FULL_SIGNED_INSTALL", fixture.select(source).coverage)
        }
        val noVbmeta = Fixture()
        assertEquals("FULL_SIGNED_INSTALL", noVbmeta.select(noVbmeta.record("init_boot").put("signingMode", "NON_CHAINED")).coverage)
        val missing = fixture.record("init_boot").put("signingMode", "NON_CHAINED")
        missing.getJSONObject("expected").remove("vbmeta")
        assertEquals(FULL, fixture.select(missing).targets)
    }

    @Test fun signedProofStillRejectsCurrentHashDriftAndSourceMutation() {
        val fixture = Fixture(includeVbmeta = true)
        val source = fixture.record("init_boot").put("signingMode", "NON_CHAINED")
        val restore = saved(fixture, source)
        fixture.before(source, "init_boot").put("sha256", hash(9))
        failsWith("INSTALLER_STOCK_TARGETS_INVALID") { StockRestoreTargets.saved(restore, fixture.snapshot, listOf(source)) }
        source.getJSONObject("expected").put("vbmeta", hash(8))
        assertEquals(FULL, fixture.select(source).targets)
    }

    @Test fun signedIdempotentReinstallKeepsCarrierProofIncludingEarlierInstall() {
        val fixture = Fixture(includeVbmeta = true)
        for ((carrier, mode) in listOf("init_boot" to "NON_CHAINED", "boot" to "CHAINED")) {
            val first = fixture.record(carrier).put("signingMode", mode)
            val noop = fixture.record(carrier, id = "22222222-2222-4222-8222-222222222222").put("signingMode", mode)
            fixture.before(noop, carrier).put("sha256", fixture.snapshot.partitions.getValue(carrier).sha256)
            val selection = fixture.select(noop)
            assertEquals(setOf(carrier), selection.targets)
            assertEquals("CURRENT_NATIVE_INSTALL", selection.coverage)
            assertEquals(setOf(carrier), StockRestoreTargets.saved(saved(fixture, noop), fixture.snapshot, listOf(noop)))
            val combined = StockRestoreTargets.select(fixture.snapshot, "LITE", listOf(first, noop), CURRENT_BOOT)
            assertEquals(setOf(carrier), combined.targets)
            assertEquals(2, combined.sourceProofs.size)
        }
    }

    private fun saved(fixture: Fixture, source: JSONObject): JSONObject {
        val selection = fixture.select(source)
        return JSONObject().put("targetMode", "LITE").put("bootId", CURRENT_BOOT)
            .put("stockRestoreTargets", JSONArray(selection.targets.toList()))
            .put("stockRestoreSources", JSONObject(selection.sourceProofs)).put("stockRestoreCoverage", selection.coverage)
    }

    private class Fixture(includeVendor: Boolean = false, includeVbmeta: Boolean = false) {
        val snapshot = InstallerSnapshot("6.6-device", "firmware-device", "_a", "Enforcing",
            (listOf("boot", "init_boot") + (if (includeVendor) listOf("vendor_boot") else emptyList()) +
                (if (includeVbmeta) listOf("vbmeta") else emptyList())).mapIndexed { index, name ->
                name to BootPartitionSnapshot(name, "/dev/block/by-name/${name}_a", "/dev/block/device$index",
                    4096L, hash(index + 3), BootPartitionIdentity(index + 100L, index + 200L, index + 300L))
            }.toMap())

        fun record(partition: String, mode: String = "LITE", compatibility: Set<String> = emptySet(),
                   id: String = "11111111-1111-4111-8111-111111111111"): JSONObject {
            val partitions = JSONObject()
            val expected = JSONObject()
            snapshot.partitions.forEach { (name, row) ->
                val identity = requireNotNull(row.identity)
                partitions.put(name, JSONObject().put("resolvedPath", row.resolvedPath).put("size", row.size)
                    .put("sha256", if (name == partition || name in compatibility) hash(1) else row.sha256)
                    .put("deviceNumber", identity.deviceNumber).put("inode", identity.inode)
                    .put("filesystem", identity.filesystem))
                expected.put(name, row.sha256)
            }
            return JSONObject().put("schema", 1).put("kind", "NATIVE").put("operation", "INSTALL")
                .put("taskId", id).put("targetMode", mode).put("partition", partition)
                .put("state", "BOOT_IMAGE_VERIFIED").put("bootId", CURRENT_BOOT).put("signingMode", "")
                .put("compatibilityPartitions", JSONArray(compatibility.toList())).put("expected", expected)
                .put("snapshot", JSONObject().put("kernelRelease", snapshot.kernelRelease)
                    .put("firmware", snapshot.firmware).put("slotSuffix", snapshot.slotSuffix)
                    .put("selinux", snapshot.selinux).put("partitions", partitions))
        }

        fun before(record: JSONObject, partition: String): JSONObject =
            record.getJSONObject("snapshot").getJSONObject("partitions").getJSONObject(partition)

        fun select(record: JSONObject, mode: String = "LITE"): StockRestoreTargets.Selection =
            StockRestoreTargets.select(snapshot, mode, listOf(record), CURRENT_BOOT)
    }

    private fun failsWith(message: String, action: () -> Unit) {
        assertEquals(message, assertThrows(RuntimeException::class.java) { action() }.message)
    }

    private companion object {
        val FULL = setOf("boot", "init_boot")
        const val CURRENT_BOOT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        const val PREVIOUS_BOOT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        fun hash(value: Int) = value.toString(16).repeat(64)
    }
}
