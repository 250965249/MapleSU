package dev.maplesu.installer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Shared switch fixtures: deterministic images, plans and a two-partition fake "device". */
final class SwitchFixtures {
    static final int BOOT_SIZE = 300_001;
    static final int INIT_SIZE = 150_001;
    static final String SLOT = "_a";
    static final String FIRMWARE = "fw-1";
    static final String KERNEL = "5.10.198-android13-8-test";
    static final String START_BOOT_ID = "boot-1";

    private SwitchFixtures() {}

    static byte[] data(int size, int seed) {
        byte[] bytes = new byte[size];
        new java.util.Random(seed).nextBytes(bytes);
        return bytes;
    }

    static Path write(Path directory, String name, byte[] bytes) throws IOException {
        Path path = directory.resolve(name);
        Files.write(path, bytes);
        return path;
    }

    static String sha(byte[] bytes) { return SwitchHashes.sha256(bytes); }

    static String tail(byte[] bytes) { return SwitchHashes.tailSha256(bytes); }

    static boolean same(byte[] expected, byte[] actual) { return java.util.Arrays.equals(expected, actual); }

    static Map<String, String> device() {
        return Map.of(SwitchPlan.DEVICE_SLOT, SLOT, SwitchPlan.DEVICE_FIRMWARE, FIRMWARE,
                SwitchPlan.DEVICE_KERNEL, KERNEL, SwitchPlan.DEVICE_SELINUX, "Enforcing");
    }

    static SwitchStep step(String partition, StepRole role, Path image, Path preImage) throws IOException {
        byte[] imageBytes = Files.readAllBytes(image);
        byte[] preBytes = Files.readAllBytes(preImage);
        return new SwitchStep(partition, role, imageBytes.length, image, sha(imageBytes), preImage,
                sha(preBytes), tail(imageBytes));
    }

    /** Same step with a deliberately wrong tail probe, used by the tail-mismatch case. */
    static SwitchStep withTail(SwitchStep step, String tailSha256) {
        return new SwitchStep(step.partition, step.role, step.size, step.image, step.imageSha256,
                step.preImage, step.preSha256, tailSha256);
    }

    /**
     * A fully staged two-partition world. {@code toKsu=true} is A→B(LKM): restore {@code boot} to
     * baseline, write the {@code init_boot} candidate; {@code toKsu=false} is B→A, i.e. the reverse
     * order with the opposite roles.
     */
    static final class World {
        final TempWorkDir dir;
        final boolean toKsu;
        final byte[] bootCurrent;
        final byte[] bootOther;
        final byte[] initCurrent;
        final byte[] initOther;
        final Path bootCurrentImage;
        final Path bootOtherImage;
        final Path initCurrentImage;
        final Path initOtherImage;
        final FakeWritablePartition boot;
        final FakeWritablePartition initBoot;
        final FakePartitionProvider provider;
        final RecordingSwitchJournal journal = new RecordingSwitchJournal();
        final SwitchPlan.Request request;

        World(TempWorkDir dir, boolean toKsu) throws IOException {
            this.dir = dir;
            this.toKsu = toKsu;
            this.bootCurrent = data(BOOT_SIZE, 11);
            this.bootOther = data(BOOT_SIZE, 12);
            this.initCurrent = data(INIT_SIZE, 13);
            this.initOther = data(INIT_SIZE, 14);
            this.bootCurrentImage = write(dir.root, "pre-boot.img", bootCurrent);
            this.bootOtherImage = write(dir.root, "target-boot.img", bootOther);
            this.initCurrentImage = write(dir.root, "pre-init_boot.img", initCurrent);
            this.initOtherImage = write(dir.root, "target-init_boot.img", initOther);
            this.boot = FakeWritablePartition.create("boot", bootCurrent);
            this.initBoot = FakeWritablePartition.create("init_boot", initCurrent);
            this.provider = new FakePartitionProvider().add(boot).add(initBoot);
            List<SwitchStep> steps = new ArrayList<>();
            if (toKsu) {
                steps.add(SwitchFixtures.step("init_boot", StepRole.WRITE_CANDIDATE, initOtherImage, initCurrentImage));
                steps.add(SwitchFixtures.step("boot", StepRole.RESTORE_BASELINE, bootOtherImage, bootCurrentImage));
                this.request = new SwitchPlan.Request(SwitchPlan.SCHEMA, UUID.randomUUID().toString(),
                        WorkMode.LITE, WorkMode.KSU, "bl-20261029-1", START_BOOT_ID, device(), steps);
            } else {
                steps.add(SwitchFixtures.step("init_boot", StepRole.RESTORE_BASELINE, initOtherImage, initCurrentImage));
                steps.add(SwitchFixtures.step("boot", StepRole.WRITE_CANDIDATE, bootOtherImage, bootCurrentImage));
                this.request = new SwitchPlan.Request(SwitchPlan.SCHEMA, UUID.randomUUID().toString(),
                        WorkMode.KSU, WorkMode.LITE, "bl-20261029-1", START_BOOT_ID, device(), steps);
            }
        }

        SwitchPlan prepare() throws IOException {
            return InstallerMultiPartitionTransaction.prepare(request, provider, journal);
        }

        SwitchPlan prepareWith(SwitchJournalSink sink) throws IOException {
            return InstallerMultiPartitionTransaction.prepare(request, provider, sink);
        }

        SwitchPlan.Request requestWith(List<SwitchStep> steps) {
            return new SwitchPlan.Request(request.schema, request.switchId, request.fromMode,
                    request.toMode, request.baselineId, request.startBootId, request.device, steps);
        }

        SwitchStep step(String partition) {
            for (SwitchStep step : request.steps) if (step.partition.equals(partition)) return step;
            throw new AssertionError("no step for " + partition);
        }

        FakeWritablePartition partition(String name) {
            if (name.equals("boot")) return boot;
            if (name.equals("init_boot")) return initBoot;
            throw new AssertionError("no fake partition " + name);
        }

        byte[] currentBytes(String partition) {
            return partition.equals("boot") ? bootCurrent : initCurrent;
        }

        byte[] targetBytes(String partition) {
            return partition.equals("boot") ? bootOther : initOther;
        }

        byte[] bytes(String partition) {
            try {
                return partition(partition).bytes();
            } catch (IOException failure) {
                throw new AssertionError(failure);
            }
        }
    }
}
