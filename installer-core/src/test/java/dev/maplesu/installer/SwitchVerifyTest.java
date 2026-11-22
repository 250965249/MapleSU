package dev.maplesu.installer;

import java.io.IOException;
import java.util.List;

/**
 * S6 read-only verification cases (02-switch-contract §8.5): full-length partition digests, a
 * changed boot id, unchanged device facts and Enforcing SELinux. Host fakes only.
 */
public final class SwitchVerifyTest {
    private static int passed;

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        passed++;
    }

    private static final class Staged {
        final SwitchFixtures.World world;
        final SwitchPlan plan;
        final FakeSwitchFacts facts = new FakeSwitchFacts();

        Staged(TempWorkDir dir) throws IOException {
            this.world = new SwitchFixtures.World(dir, true);
            this.plan = world.prepare();
            var result = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            if (result.state != InstallerMultiPartitionTransaction.State.WRITTEN) {
                throw new AssertionError("staging commit failed: " + result);
            }
            facts.bootId = "boot-2"; // reboot observed
            facts.slotSuffix = SwitchFixtures.SLOT;
            facts.firmware = SwitchFixtures.FIRMWARE;
            facts.kernelRelease = SwitchFixtures.KERNEL;
            facts.selinux = "Enforcing";
        }

        InstallerMultiPartitionTransaction.Result verify() throws IOException {
            return InstallerMultiPartitionTransaction.verify(plan, world.provider, facts, world.journal);
        }
    }

    private static void verifiesAllPartitionsAtTarget() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Staged staged = new Staged(dir);
            int bootWrites = staged.world.boot.writes;
            int initWrites = staged.world.initBoot.writes;
            var result = staged.verify();
            check(result.state == InstallerMultiPartitionTransaction.State.VERIFIED, "V1 verified");
            check(result.code.isEmpty(), "V1 no code");
            check(staged.world.journal.last().op == SwitchOp.VERIFIED, "V1 journal VERIFIED last");
            check(staged.world.boot.writes == bootWrites, "V6 verify is read-only (boot)");
            check(staged.world.initBoot.writes == initWrites, "V6 verify is read-only (init_boot)");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void rejectsPartitionMismatch() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Staged staged = new Staged(dir);
            staged.world.boot.externalWrite(SwitchFixtures.data(SwitchFixtures.BOOT_SIZE, 77));
            var result = staged.verify();
            check(result.state == InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED, "V2 recovery");
            check("VERIFY_PARTITION_MISMATCH".equals(result.code), "V2 code " + result.code);
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void rejectsSameBootId() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Staged staged = new Staged(dir);
            staged.facts.bootId = SwitchFixtures.START_BOOT_ID;
            var result = staged.verify();
            check(result.state == InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED, "V3 recovery");
            check("VERIFY_BOOT_NOT_OBSERVED".equals(result.code), "V3 code " + result.code);
            staged.facts.bootId = "";
            check("VERIFY_BOOT_NOT_OBSERVED".equals(staged.verify().code), "V3 empty boot id rejected");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void rejectsDeviceFactChange() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Staged staged = new Staged(dir);
            staged.facts.firmware = "other-fw";
            check("VERIFY_DEVICE_CHANGED".equals(staged.verify().code), "V4 firmware change");
            staged.facts.firmware = SwitchFixtures.FIRMWARE;
            staged.facts.slotSuffix = "_b";
            check("VERIFY_DEVICE_CHANGED".equals(staged.verify().code), "V4 slot change");
            staged.facts.slotSuffix = SwitchFixtures.SLOT;
            staged.facts.kernelRelease = "5.10.1-other";
            check("VERIFY_DEVICE_CHANGED".equals(staged.verify().code), "V4 kernel change");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void rejectsNonEnforcing() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            Staged staged = new Staged(dir);
            staged.facts.selinux = "Permissive";
            var result = staged.verify();
            check("VERIFY_DEVICE_CHANGED".equals(result.code), "V5 permissive rejected " + result.code);
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void verifyRefusesChangedPlanDeviceSnapshot() throws IOException {
        try (TempWorkDir dir = TempWorkDir.create()) {
            // A plan with a different expected firmware must reject an observed mismatch, not trust S6.
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan.Request request = new SwitchPlan.Request(SwitchPlan.SCHEMA, world.request.switchId,
                    world.request.fromMode, world.request.toMode, world.request.baselineId,
                    SwitchFixtures.START_BOOT_ID,
                    java.util.Map.of(SwitchPlan.DEVICE_SLOT, "_a", SwitchPlan.DEVICE_FIRMWARE, "expected-fw",
                            SwitchPlan.DEVICE_KERNEL, SwitchFixtures.KERNEL, SwitchPlan.DEVICE_SELINUX, "Enforcing"),
                    world.request.steps);
            SwitchPlan plan = InstallerMultiPartitionTransaction.prepare(request, world.provider, world.journal);
            InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            FakeSwitchFacts facts = new FakeSwitchFacts();
            facts.bootId = "boot-2";
            facts.slotSuffix = SwitchFixtures.SLOT;
            facts.firmware = SwitchFixtures.FIRMWARE;
            facts.kernelRelease = SwitchFixtures.KERNEL;
            facts.selinux = "Enforcing";
            var result = InstallerMultiPartitionTransaction.verify(plan, world.provider, facts, world.journal);
            check("VERIFY_DEVICE_CHANGED".equals(result.code), "V7 expected device snapshot enforced");
        }
    }

    public static void main(String[] args) throws Exception {
        verifiesAllPartitionsAtTarget();
        rejectsPartitionMismatch();
        rejectsSameBootId();
        rejectsDeviceFactChange();
        rejectsNonEnforcing();
        verifyRefusesChangedPlanDeviceSnapshot();
        System.out.println("SwitchVerify: " + passed
                + " checks passed (partition digests, reboot observation, device facts, Enforcing, read-only)");
    }
}
