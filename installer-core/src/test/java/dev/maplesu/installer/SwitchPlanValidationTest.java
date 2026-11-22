package dev.maplesu.installer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Plan validation cases (02-switch-contract §8.3 P1–P12) plus the fixed partition layout and the
 * "who owns which partition" direction checks. Every failure is asserted by contract code.
 */
public final class SwitchPlanValidationTest {
    private static int passed;
    private static int images;

    private interface Operation { void run() throws Exception; }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        passed++;
    }

    private static void checkFailure(String expectedCode, Operation action) {
        try {
            action.run();
        } catch (SwitchFailure failure) {
            check(expectedCode.equals(failure.code),
                    "expected " + expectedCode + " but got " + failure.code + " (" + failure.detail + ")");
            return;
        } catch (Exception failure) {
            throw new AssertionError("expected " + expectedCode + " but got " + failure, failure);
        }
        throw new AssertionError("expected " + expectedCode + " but the call succeeded");
    }

    /** One staged set of images valid for either direction. */
    private static final class Images {
        final Path bootCurrent;
        final Path bootTarget;
        final Path initCurrent;
        final Path initTarget;
        final byte[] bootCurrentBytes;
        final byte[] bootTargetBytes;
        final byte[] initCurrentBytes;
        final byte[] initTargetBytes;

        Images(Path dir) throws IOException {
            bootCurrentBytes = SwitchFixtures.data(SwitchFixtures.BOOT_SIZE, ++images);
            bootTargetBytes = SwitchFixtures.data(SwitchFixtures.BOOT_SIZE, ++images);
            initCurrentBytes = SwitchFixtures.data(SwitchFixtures.INIT_SIZE, ++images);
            initTargetBytes = SwitchFixtures.data(SwitchFixtures.INIT_SIZE, ++images);
            bootCurrent = SwitchFixtures.write(dir, "pre-boot.img", bootCurrentBytes);
            bootTarget = SwitchFixtures.write(dir, "base-boot.img", bootTargetBytes);
            initCurrent = SwitchFixtures.write(dir, "pre-init_boot.img", initCurrentBytes);
            initTarget = SwitchFixtures.write(dir, "base-init_boot.img", initTargetBytes);
        }

        List<SwitchStep> toKsuSteps() throws IOException {
            return List.of(
                    SwitchFixtures.step("init_boot", StepRole.WRITE_CANDIDATE, initTarget, initCurrent),
                    SwitchFixtures.step("boot", StepRole.RESTORE_BASELINE, bootTarget, bootCurrent));
        }

        List<SwitchStep> toLiteSteps() throws IOException {
            return List.of(
                    SwitchFixtures.step("init_boot", StepRole.RESTORE_BASELINE, initTarget, initCurrent),
                    SwitchFixtures.step("boot", StepRole.WRITE_CANDIDATE, bootTarget, bootCurrent));
        }
    }

    private static SwitchPartitionProvider provider(Images images) throws IOException {
        FakeWritablePartition boot = FakeWritablePartition.create("boot", images.bootCurrentBytes);
        FakeWritablePartition initBoot = FakeWritablePartition.create("init_boot", images.initCurrentBytes);
        return new FakePartitionProvider().add(boot).add(initBoot);
    }

    private static SwitchPlan.Request request(WorkMode from, WorkMode to, List<SwitchStep> steps) {
        return new SwitchPlan.Request(SwitchPlan.SCHEMA, UUID.randomUUID().toString(), from, to,
                "bl-20261029-1", SwitchFixtures.START_BOOT_ID, SwitchFixtures.device(), steps);
    }

    private static SwitchPlan prepared(TempWorkDir dir, Images images, List<SwitchStep> steps)
            throws IOException {
        return InstallerMultiPartitionTransaction.prepare(request(WorkMode.LITE, WorkMode.KSU, steps),
                provider(images), new RecordingSwitchJournal());
    }

    // ------------------------------------------------------------------ P1–P12

    private static void rejectsVbmetaPartition() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            SwitchStep step = new SwitchStep("vbmeta", StepRole.RESTORE_BASELINE,
                    Files.size(images.bootTarget), images.bootTarget, SwitchFixtures.sha(images.bootTargetBytes),
                    images.bootCurrent, SwitchFixtures.sha(images.bootCurrentBytes),
                    SwitchFixtures.tail(images.bootTargetBytes));
            checkFailure("SWITCH_PARTITION_FORBIDDEN", () ->
                    InstallerMultiPartitionTransaction.prepare(request(WorkMode.KSU, WorkMode.LITE, List.of(step)),
                            provider(images), new RecordingSwitchJournal()));
        }
    }

    private static void rejectsUnknownPartitionName() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            SwitchStep step = new SwitchStep("system", StepRole.WRITE_CANDIDATE,
                    Files.size(images.bootTarget), images.bootTarget, SwitchFixtures.sha(images.bootTargetBytes),
                    images.bootCurrent, SwitchFixtures.sha(images.bootCurrentBytes),
                    SwitchFixtures.tail(images.bootTargetBytes));
            checkFailure("SWITCH_PARTITION_FORBIDDEN", () ->
                    InstallerMultiPartitionTransaction.prepare(request(WorkMode.LITE, WorkMode.KSU, List.of(step)),
                            provider(images), new RecordingSwitchJournal()));
        }
    }

    private static void rejectsDuplicatePartition() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            List<SwitchStep> steps = List.of(
                    images.toKsuSteps().get(0), images.toKsuSteps().get(0));
            checkFailure("SWITCH_PLAN_INVALID", () -> prepared(dir, images, steps));
        }
    }

    private static void rejectsTwoCandidateSteps() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            SwitchStep candidateInit = SwitchFixtures.step("init_boot", StepRole.WRITE_CANDIDATE,
                    images.initTarget, images.initCurrent);
            SwitchStep candidateBoot = SwitchFixtures.step("boot", StepRole.WRITE_CANDIDATE,
                    images.bootTarget, images.bootCurrent);
            checkFailure("SWITCH_PLAN_INVALID", () -> prepared(dir, images, List.of(candidateInit, candidateBoot)));
        }
    }

    private static void rejectsCandidateBeforeRestore() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            List<SwitchStep> steps = List.of(
                    SwitchFixtures.step("boot", StepRole.RESTORE_BASELINE, images.bootTarget, images.bootCurrent),
                    SwitchFixtures.step("init_boot", StepRole.WRITE_CANDIDATE, images.initTarget, images.initCurrent));
            checkFailure("SWITCH_PLAN_INVALID", () -> prepared(dir, images, steps));
        }
    }

    private static void acceptsLiteInitBootCarrier() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            SwitchStep initBoot = SwitchFixtures.step("init_boot", StepRole.WRITE_CANDIDATE,
                    images.initTarget, images.initCurrent);
            SwitchPlan plan = InstallerMultiPartitionTransaction.prepare(
                    request(WorkMode.KSU, WorkMode.LITE, List.of(initBoot)), provider(images),
                    new RecordingSwitchJournal());
            check(plan.steps.size() == 1 && plan.steps.get(0).partition.equals("init_boot"),
                    "Ultra init_boot carrier is the complete signed write set");
            check(SwitchPlan.parse(plan.flatFields()).planSha256.equals(plan.planSha256),
                    "Ultra init_boot survives the signed plan round trip");
        }
    }

    private static void rejectsMissingOrShortPreImage() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            Path missing = dir.root.resolve("missing-pre.img");
            SwitchStep absent = new SwitchStep("init_boot", StepRole.WRITE_CANDIDATE,
                    Files.size(images.initTarget), images.initTarget, SwitchFixtures.sha(images.initTargetBytes),
                    missing, SwitchFixtures.sha(images.initCurrentBytes), SwitchFixtures.tail(images.initTargetBytes));
            checkFailure("SWITCH_PRE_IMAGE_INVALID", () -> prepared(dir, images, List.of(absent)));
            byte[] shortPre = java.util.Arrays.copyOf(images.initCurrentBytes, images.initCurrentBytes.length - 1);
            Path shortPath = SwitchFixtures.write(dir.root, "pre-short.img", shortPre);
            SwitchStep shortStep = new SwitchStep("init_boot", StepRole.WRITE_CANDIDATE,
                    Files.size(images.initTarget), images.initTarget, SwitchFixtures.sha(images.initTargetBytes),
                    shortPath, SwitchFixtures.sha(shortPre), SwitchFixtures.tail(images.initTargetBytes));
            checkFailure("SWITCH_PRE_IMAGE_INVALID", () -> prepared(dir, images, List.of(shortStep)));
        }
    }

    private static void rejectsCandidateDigestMismatch() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            String wrongHash = SwitchFixtures.sha(SwitchFixtures.data((int) Files.size(images.initTarget), 777));
            SwitchStep step = new SwitchStep("init_boot", StepRole.WRITE_CANDIDATE,
                    Files.size(images.initTarget), images.initTarget, wrongHash,
                    images.initCurrent, SwitchFixtures.sha(images.initCurrentBytes),
                    SwitchFixtures.tail(images.initTargetBytes));
            checkFailure("PRODUCE_CANDIDATE_CHANGED", () -> prepared(dir, images, List.of(step)));
        }
    }

    private static void rejectsEqualTargetAndPre() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            // Candidate bytes identical to the pre image => this step is a no-op that must be dropped.
            Path same = SwitchFixtures.write(dir.root, "same-init.img", images.initCurrentBytes);
            SwitchStep step = new SwitchStep("init_boot", StepRole.WRITE_CANDIDATE,
                    Files.size(same), same, SwitchFixtures.sha(images.initCurrentBytes),
                    images.initCurrent, SwitchFixtures.sha(images.initCurrentBytes),
                    SwitchFixtures.tail(images.initCurrentBytes));
            checkFailure("SWITCH_STEP_NO_OP", () -> prepared(dir, images, List.of(step)));
        }
    }

    private static void acceptsLitePlanOrder() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            SwitchPlan plan = InstallerMultiPartitionTransaction.prepare(
                    request(WorkMode.KSU, WorkMode.LITE, images.toLiteSteps()), provider(images),
                    new RecordingSwitchJournal());
            check(plan.steps.size() == 2, "P10 two steps");
            check(plan.steps.get(0).partition.equals("init_boot") && plan.steps.get(0).role == StepRole.RESTORE_BASELINE,
                    "P10 restore source first");
            check(plan.steps.get(1).partition.equals("boot") && plan.steps.get(1).role == StepRole.WRITE_CANDIDATE,
                    "P10 candidate target second");
            // The opposite direction must be accepted as well (§8.3 note: test both directions).
            SwitchPlan ksu = InstallerMultiPartitionTransaction.prepare(
                    request(WorkMode.LITE, WorkMode.KSU, images.toKsuSteps()), provider(images),
                    new RecordingSwitchJournal());
            check(ksu.steps.get(0).partition.equals("init_boot") && ksu.steps.get(0).role == StepRole.WRITE_CANDIDATE,
                    "P10 A→B install init_boot first");
            check(ksu.steps.get(1).partition.equals("boot") && ksu.steps.get(1).role == StepRole.RESTORE_BASELINE,
                    "P10 A→B restore boot second");
        }
    }

    private static void acceptsNormalBootCarrierAndPreservesItsPlan() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            SwitchStep boot = SwitchFixtures.step("boot", StepRole.WRITE_CANDIDATE,
                    images.bootTarget, images.bootCurrent);
            SwitchPlan plan = InstallerMultiPartitionTransaction.prepare(
                    request(WorkMode.LITE, WorkMode.KSU, List.of(boot)), provider(images),
                    new RecordingSwitchJournal());
            check(plan.steps.size() == 1 && plan.steps.get(0).partition.equals("boot"),
                    "Normal boot carrier remains the only planned partition");
            check(SwitchPlan.parse(plan.flatFields()).planSha256.equals(plan.planSha256),
                    "Normal boot carrier survives the signed plan round trip");
            SwitchPlan reverse = InstallerMultiPartitionTransaction.prepare(
                    request(WorkMode.KSU, WorkMode.LITE, List.of(boot)), provider(images),
                    new RecordingSwitchJournal());
            check(reverse.steps.size() == 1, "Normal boot to Ultra stays on boot");
        }
    }

    private static void acceptsRestoreFromLiteInitBootCarrier() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            SwitchStep restore = SwitchFixtures.step("init_boot", StepRole.RESTORE_BASELINE,
                    images.initTarget, images.initCurrent);
            SwitchPlan plan = prepared(dir, images, List.of(restore));
            check(plan.steps.size() == 1 && plan.steps.get(0).role == StepRole.RESTORE_BASELINE,
                    "restoring Ultra init_boot does not introduce a boot write");
        }
    }

    private static void planShaStableAndOrderSensitive() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            List<SwitchStep> steps = images.toKsuSteps();
            SwitchPlan.Request base = request(WorkMode.LITE, WorkMode.KSU, steps);
            SwitchPlan first = SwitchPlan.create(base);
            SwitchPlan second = SwitchPlan.create(base);
            check(first.planSha256.equals(second.planSha256), "P11 same input same sha");
            List<SwitchStep> swapped = List.of(steps.get(1), steps.get(0));
            SwitchPlan.Request reorderedRequest = new SwitchPlan.Request(base.schema, base.switchId,
                    base.fromMode, base.toMode, base.baselineId, base.startBootId, base.device, swapped);
            SwitchPlan reordered = SwitchPlan.create(reorderedRequest);
            check(!first.planSha256.equals(reordered.planSha256), "P11 order sensitive sha");
            check(SwitchHashes.isHash(first.planSha256), "P11 sha format");
        }
    }

    private static void flatFieldsRoundTrip() throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Images images = new Images(dir.root);
            SwitchPlan plan = InstallerMultiPartitionTransaction.prepare(
                    request(WorkMode.KSU, WorkMode.LITE, images.toLiteSteps()), provider(images),
                    new RecordingSwitchJournal());
            SwitchPlan parsed = SwitchPlan.parse(plan.flatFields());
            check(parsed.planSha256.equals(plan.planSha256), "P12 sha round trip");
            check(parsed.steps.size() == plan.steps.size(), "P12 step count");
            for (int index = 0; index < plan.steps.size(); index++) {
                check(parsed.steps.get(index).partition.equals(plan.steps.get(index).partition),
                        "P12 partition " + index);
                check(parsed.steps.get(index).role == plan.steps.get(index).role, "P12 role " + index);
                check(parsed.steps.get(index).imageSha256.equals(plan.steps.get(index).imageSha256),
                        "P12 image sha " + index);
            }
            check(parsed.startBootId.equals(plan.startBootId), "P12 start boot id");
            check(parsed.device.equals(plan.device), "P12 device snapshot");
            Map<String, String> tampered = new java.util.LinkedHashMap<>(plan.flatFields());
            tampered.put("planSha256", "0".repeat(64));
            checkFailure("SWITCH_PLAN_INVALID", () -> SwitchPlan.parse(tampered));
            Map<String, String> extra = new java.util.LinkedHashMap<>(plan.flatFields());
            extra.put("extra.key", "x");
            checkFailure("SWITCH_PLAN_INVALID", () -> SwitchPlan.parse(extra));
            Map<String, String> missing = new java.util.LinkedHashMap<>(plan.flatFields());
            missing.remove("step.0.partition");
            checkFailure("SWITCH_PLAN_INVALID", () -> SwitchPlan.parse(missing));
        }
    }

    // ------------------------------------------------------------------ fixed layout

    private static void ownedPartitionPerMode() {
        check(SwitchPartitionLayout.ownedPartition(WorkMode.LITE).equals("boot"), "L1 LITE owns boot");
        check(SwitchPartitionLayout.ownedPartition(WorkMode.KSU).equals("init_boot"), "L1 KSU owns init_boot");
    }

    private static void writeOrderDependsOnTargetMode() {
        // Both directions write init_boot first; each direction retains its own image roles.
        check(SwitchPartitionLayout.writeOrder(WorkMode.KSU).equals(List.of("init_boot", "boot")),
                "L2 to KSU order " + SwitchPartitionLayout.writeOrder(WorkMode.KSU));
        check(SwitchPartitionLayout.writeOrder(WorkMode.LITE).equals(List.of("init_boot", "boot")),
                "L2 to LITE order " + SwitchPartitionLayout.writeOrder(WorkMode.LITE));
    }

    private static void forbiddenAndProbeConstants() {
        check(WritablePartition.ALLOWED.equals(java.util.Set.of("boot", "init_boot")), "L3 allowlist");
        check(!WritablePartition.ALLOWED.contains("vbmeta"), "L3 vbmeta never writable");
        check("vbmeta".equals(WritablePartition.FORBIDDEN), "L3 forbidden constant");
        check(WritablePartition.TAIL_PROBE_BYTES == 64 * 1024, "L3 tail probe 64 KiB");
    }

    public static void main(String[] args) throws Exception {
        rejectsVbmetaPartition();
        rejectsUnknownPartitionName();
        rejectsDuplicatePartition();
        rejectsTwoCandidateSteps();
        rejectsCandidateBeforeRestore();
        acceptsLiteInitBootCarrier();
        rejectsMissingOrShortPreImage();
        rejectsCandidateDigestMismatch();
        rejectsEqualTargetAndPre();
        acceptsLitePlanOrder();
        acceptsNormalBootCarrierAndPreservesItsPlan();
        acceptsRestoreFromLiteInitBootCarrier();
        planShaStableAndOrderSensitive();
        flatFieldsRoundTrip();
        ownedPartitionPerMode();
        writeOrderDependsOnTargetMode();
        forbiddenAndProbeConstants();
        InitBootCarrierTransactionTest.main(new String[0]);
        System.out.println("SwitchPlanValidation: " + passed
                + " checks passed (allowlist, vbmeta, duplicates, roles, order both directions,"
                + " full-length images, plan sha and flat-field round trip)");
    }
}
