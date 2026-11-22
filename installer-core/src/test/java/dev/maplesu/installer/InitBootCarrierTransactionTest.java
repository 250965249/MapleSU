package dev.maplesu.installer;

import java.nio.file.Files;
import java.util.List;
import java.util.UUID;

/** File-backed transaction checks; no target kernel or device execution is claimed. */
public final class InitBootCarrierTransactionTest {
    private static int passed;

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        passed++;
    }

    private static void run(WorkMode from, WorkMode to, int fault) throws Exception {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchStep step = SwitchFixtures.step("init_boot", StepRole.WRITE_CANDIDATE,
                    world.initOtherImage, world.initCurrentImage);
            SwitchPlan.Request request = new SwitchPlan.Request(SwitchPlan.SCHEMA,
                    UUID.randomUUID().toString(), from, to, "init-boot-carrier",
                    SwitchFixtures.START_BOOT_ID, SwitchFixtures.device(), List.of(step));
            SwitchPlan plan = InstallerMultiPartitionTransaction.prepare(request, world.provider, world.journal);
            plan = SwitchPlan.parse(plan.flatFields());
            world.provider.order.clear();
            if (fault == 1) { world.initBoot.shortWrite = 113; world.initBoot.failWriteAt = 200; }
            if (fault == 2) world.initBoot.corruptAfterSync = 1;
            if (fault == 3) world.initBoot.failSyncAt = 1;
            if (fault == 4) Thread.currentThread().interrupt();
            InstallerMultiPartitionTransaction.Result result;
            try {
                result = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            } finally {
                Thread.interrupted();
            }
            if (fault == 0) {
                check(result.state == InstallerMultiPartitionTransaction.State.WRITTEN, "init_boot committed");
                check(result.written.equals(List.of("init_boot")), "only init_boot in write receipt");
                check(SwitchFixtures.same(world.initOther, world.bytes("init_boot")), "independent target readback");
                Files.delete(world.initOtherImage);
                result = InstallerMultiPartitionTransaction.rollback(plan, world.provider, world.journal);
                check(result.state == InstallerMultiPartitionTransaction.State.ROLLED_BACK,
                        "PRE recovery survives candidate removal");
            } else {
                check(result.state == InstallerMultiPartitionTransaction.State.ROLLED_BACK,
                        "init_boot failure compensated: " + fault + ": " + result);
                check(!result.code.isEmpty(), "original failure remains visible");
            }
            check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")), "init_boot PRE restored");
            check(world.boot.writes == 0 && world.boot.opens == 0, "boot never opened for writing");
            check(SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "boot byte-identical");
            check(world.provider.order.stream().allMatch("init_boot"::equals), "no implicit boot step");
        }
    }

    public static void main(String[] args) throws Exception {
        for (WorkMode to : WorkMode.values()) {
            WorkMode from = to == WorkMode.LITE ? WorkMode.KSU : WorkMode.LITE;
            for (int fault = 0; fault <= 4; fault++) run(from, to, fault);
        }
        System.out.println("InitBootCarrierTransaction: " + passed
                + " checks passed (both directions, signed plan, short write, readback, sync, cancel, PRE recovery; file fixtures only)");
    }
}
