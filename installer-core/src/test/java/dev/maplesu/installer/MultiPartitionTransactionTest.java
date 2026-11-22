package dev.maplesu.installer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * Host fault-injection matrix for {@link InstallerMultiPartitionTransaction}
 * (02-switch-contract §8.2, M1–M15 plus journal/power-loss replay cases). Deterministic I/O
 * faults only: this does not claim hardware, cache or real power-loss coverage.
 */
public final class MultiPartitionTransactionTest {
    private static int passed;

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
        } catch (IOException failure) {
            // Raw journal IOException (02 §4.5): the code is carried in the message by contract.
            check(failure.getMessage() != null && failure.getMessage().startsWith(expectedCode),
                    "expected " + expectedCode + " but got " + failure.getMessage());
            return;
        } catch (Exception failure) {
            throw new AssertionError("expected " + expectedCode + " but got " + failure, failure);
        }
        throw new AssertionError("expected " + expectedCode + " but the call succeeded");
    }

    /** Delegates to a real journal, then simulates a process death after a chosen event is durable. */
    private static final class CrashingJournal implements SwitchJournalSink {
        private final SwitchJournalSink delegate;
        private final Predicate<SwitchEvent> crashAfter;

        CrashingJournal(SwitchJournalSink delegate, Predicate<SwitchEvent> crashAfter) {
            this.delegate = delegate;
            this.crashAfter = crashAfter;
        }

        @Override
        public void append(SwitchEvent event) throws IOException {
            delegate.append(event);
            if (crashAfter.test(event)) throw new AssertionError("simulated power loss after " + event.op);
        }
    }

    private static SwitchOp lastOp(FileSwitchJournal.Replay replay, String partition) {
        SwitchOp last = null;
        for (SwitchEvent event : replay.events) {
            if (event.partition.equals(partition)) last = event.op;
        }
        return last;
    }

    private interface IoAction { void run() throws IOException; }

    private static WritablePartition intercept(WritablePartition delegate, IoAction beforeDigest,
                                                IoAction beforeTail) {
        return new WritablePartition() {
            @Override public String name() { return delegate.name(); }
            @Override public long size() { return delegate.size(); }
            @Override public String sha256() throws IOException { beforeDigest.run(); return delegate.sha256(); }
            @Override public String tailSha256() throws IOException { beforeTail.run(); return delegate.tailSha256(); }
            @Override public BlockDeviceTransaction.Device open() throws IOException { return delegate.open(); }
        };
    }

    // ------------------------------------------------------------------ M1–M15 (§8.2)

    private static void writesBothPartitionsInPlanOrder() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan plan = world.prepare();
            world.provider.order.clear();
            var result = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(result.state == InstallerMultiPartitionTransaction.State.WRITTEN, "M1 state");
            check(result.rebootRequired, "M1 reboot required");
            check(result.written.equals(List.of("init_boot", "boot")), "M1 written order " + result.written);
            check(world.provider.order.equals(List.of("init_boot", "boot")), "M1 get order " + world.provider.order);
            check(SwitchFixtures.same(world.bootOther, world.bytes("boot")), "M1 boot == baseline target");
            check(SwitchFixtures.same(world.initOther, world.bytes("init_boot")), "M1 init_boot == candidate");
            check(result.observedSha256.size() == 2, "M1 both readback observations retained");
            check(SwitchFixtures.sha(world.bytes("boot")).equals(result.observedSha256.get("boot")),
                    "M1 boot observation matches actual bytes");
            check(SwitchFixtures.sha(world.bytes("init_boot")).equals(result.observedSha256.get("init_boot")),
                    "M1 init_boot observation matches actual bytes");
            try {
                result.observedSha256.clear();
                throw new AssertionError("M1 observations must be immutable");
            } catch (UnsupportedOperationException expected) {
                check(result.observedSha256.size() == 2, "M1 immutable observation map retains both entries");
            }
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void intentPrecedesEveryPartitionWrite() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan plan = world.prepare();
            InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(world.journal.events.get(0).op == SwitchOp.PREPARED, "M2 first event PREPARED");
            for (String partition : List.of("boot", "init_boot")) {
                int intent = world.journal.firstIndex(SwitchOp.INTENT, partition);
                int writing = world.journal.firstIndex(SwitchOp.COMMIT_INTENT, partition);
                check(intent >= 0, "M2 intent for " + partition);
                check(writing > intent, "M2 journal intent must precede BDT write for " + partition);
                check(world.journal.firstIndex(SwitchOp.DONE, partition) > writing,
                        "M2 done after single-partition commit for " + partition);
            }
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void journalFailureBeforeWriteTouchesNothing() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan plan = world.prepare();
            world.journal.failOnOp = SwitchOp.INTENT;
            checkFailure("INSTALLER_JOURNAL_WRITE_FAILED", () ->
                    InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal));
            check(world.boot.writes == 0, "M3 no partition write before durable intent");
            check(world.initBoot.writes == 0, "M3 second partition untouched");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void secondPartitionFailureRollsBackFirstInReverseOrder() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, false); // B→A: [init_boot, boot]
            SwitchPlan plan = world.prepare();
            world.boot.shortWrite = 113;
            world.boot.failWriteAt = 250;
            var result = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(result.state == InstallerMultiPartitionTransaction.State.ROLLED_BACK, "M4 rolled back");
            check("WRITE_FAILED".equals(result.code), "M4 code " + result.code);
            check(result.restored.equals(List.of("boot", "init_boot")), "M4 reverse restore order " + result.restored);
            check(result.observedSha256.isEmpty(), "M4 failure publishes no partial success observations");
            check(SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "M4 boot restored to pre");
            check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")), "M4 init_boot restored to pre");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void readbackMismatchRollsBackBoth() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true); // [init_boot, boot]
            SwitchPlan plan = world.prepare();
            world.boot.corruptAfterSync = 1;
            var result = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(result.state == InstallerMultiPartitionTransaction.State.ROLLED_BACK, "M5 rolled back");
            check("WRITE_READBACK_MISMATCH".equals(result.code), "M5 code " + result.code);
            check(SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "M5 boot restored");
            check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")), "M5 init_boot restored");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void rollbackFailureYieldsRecoveryRequired() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan.Request request = world.requestWith(List.of(world.step("init_boot")));
            SwitchPlan plan = InstallerMultiPartitionTransaction.prepare(request, world.provider, world.journal);
            world.initBoot.shortWrite = 113;
            world.initBoot.failWriteAt = 200;
            world.initBoot.failRestore = true;
            var result = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(result.state == InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED, "M6 recovery required");
            check("WRITE_ROLLBACK_FAILED".equals(result.code), "M6 code " + result.code);
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void restoreFailureYieldsRecoveryEvenWhenBytesReachPre() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, false); // to LITE, single boot candidate
            SwitchPlan.Request request = world.requestWith(List.of(world.step("boot")));
            SwitchPlan plan = InstallerMultiPartitionTransaction.prepare(request, world.provider, world.journal);
            // The BDT write is followed by a corrupting sync (readback mismatch); its own restore
            // then copies the pre image but its restore fsync fails. BDT therefore reports
            // RECOVERY_REQUIRED while the bytes happen to read back as pre — the exact case where
            // an early ROLLED_BACK would be a dangerous false negative.
            world.boot.corruptAfterSync = 1;
            world.boot.failSyncAt = 2;
            var result = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "X5 bytes happen to be pre");
            check(result.state == InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED,
                    "X5 UNRESTORABLE must not be reported as ROLLED_BACK");
            check("WRITE_ROLLBACK_FAILED".equals(result.code), "X5 code " + result.code);
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void unexpectedContentAbortsBeforeWrite() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan plan = world.prepare();
            world.boot.externalWrite(SwitchFixtures.data(SwitchFixtures.BOOT_SIZE, 99));
            world.provider.order.clear();
            var result = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(result.state == InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED, "M7 recovery required");
            check("WRITE_PARTITION_UNEXPECTED".equals(result.code), "M7 code " + result.code);
            check(world.boot.writes == 0, "M7 external content is never overwritten");
            check(!SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "M7 third value preserved");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void skipsPartitionAlreadyAtTarget() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, false); // [init_boot restore, boot candidate]
            world.initBoot.externalWrite(world.initOther); // already at the baseline target
            SwitchPlan plan = world.prepare();
            world.provider.order.clear();
            var result = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(result.state == InstallerMultiPartitionTransaction.State.WRITTEN, "M8 written");
            check(result.written.equals(List.of("boot")), "M8 only boot written " + result.written);
            check(world.journal.count(SwitchOp.SKIP, "init_boot") == 1, "M8 skip journaled");
            check(SwitchFixtures.same(world.bootOther, world.bytes("boot")), "M8 target written");
            check(result.observedSha256.size() == 2, "M8 skip and write observations both retained");
            check(SwitchFixtures.sha(world.bytes("init_boot")).equals(result.observedSha256.get("init_boot")),
                    "M8 skipped partition observation matches actual bytes");
            check(SwitchFixtures.sha(world.bytes("boot")).equals(result.observedSha256.get("boot")),
                    "M8 written partition observation matches actual bytes");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void secondCommitIsNoOp() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan plan = world.prepare();
            var first = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(first.state == InstallerMultiPartitionTransaction.State.WRITTEN, "M9 first commit");
            var second = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(second.state == InstallerMultiPartitionTransaction.State.WRITTEN, "M9 second commit state");
            check(second.written.isEmpty(), "M9 second commit writes nothing " + second.written);
            check(world.journal.count(SwitchOp.SKIP, "boot") == 1, "M9 boot skip");
            check(world.journal.count(SwitchOp.SKIP, "init_boot") == 1, "M9 init_boot skip");
            check(second.observedSha256.equals(first.observedSha256), "M9 idempotent commit retains all observations");
            check(second.observedSha256.size() == 2, "M9 second commit observations are complete");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void cancelBeforeCommitLeavesPartitions() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan plan = world.prepare();
            check(plan.steps.size() == 2, "M10 plan has two steps");
            check(world.journal.last().op == SwitchOp.PREPARED, "M10 only PREPARED recorded");
            check(world.journal.count(SwitchOp.INTENT, "boot") == 0, "M10 no intent");
            check(SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "M10 boot untouched");
            check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")), "M10 init_boot untouched");
            check(world.boot.writes == 0 && world.initBoot.writes == 0, "M10 no writes");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void shortReadsAndShortWritesComplete() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan plan = world.prepare();
            world.boot.shortRead = 97;
            world.boot.shortWrite = 113;
            world.initBoot.shortRead = 89;
            world.initBoot.shortWrite = 71;
            var result = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(result.state == InstallerMultiPartitionTransaction.State.WRITTEN, "M11 written");
            check(SwitchFixtures.same(world.bootOther, world.bytes("boot")), "M11 boot target");
            check(SwitchFixtures.same(world.initOther, world.bytes("init_boot")), "M11 init target");
            check(world.boot.writes > 100 && world.initBoot.writes > 100, "M11 many short writes exercised");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void fullLengthDigestRejectsPaddedShortImage() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            byte[] shortImage = java.util.Arrays.copyOf(world.initOther, world.initOther.length - 1);
            Path shortPath = SwitchFixtures.write(dir.root, "candidate-short.img", shortImage);
            SwitchStep step = new SwitchStep("init_boot", StepRole.WRITE_CANDIDATE, SwitchFixtures.INIT_SIZE,
                    shortPath, SwitchFixtures.sha(shortImage), world.initCurrentImage,
                    SwitchFixtures.sha(world.initCurrent), SwitchFixtures.tail(shortImage));
            SwitchPlan.Request request = world.requestWith(List.of(step));
            checkFailure("PRODUCE_OUTPUT_SIZE_INVALID", () ->
                    InstallerMultiPartitionTransaction.prepare(request, world.provider, world.journal));
            check(world.initBoot.writes == 0, "M12 short candidate never reaches BDT");
            byte[] longImage = java.util.Arrays.copyOf(world.initOther, world.initOther.length + 1);
            Path longPath = SwitchFixtures.write(dir.root, "candidate-long.img", longImage);
            SwitchStep longStep = new SwitchStep("init_boot", StepRole.WRITE_CANDIDATE,
                    SwitchFixtures.INIT_SIZE, longPath, SwitchFixtures.sha(longImage),
                    world.initCurrentImage, SwitchFixtures.sha(world.initCurrent),
                    SwitchFixtures.tail(longImage));
            checkFailure("PRODUCE_OUTPUT_SIZE_INVALID", () ->
                    InstallerMultiPartitionTransaction.prepare(world.requestWith(List.of(longStep)),
                            world.provider, world.journal));
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void tailProbeDetectsTruncatedCandidate() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, false); // to LITE: single boot candidate valid
            SwitchStep wrongTail = SwitchFixtures.withTail(world.step("boot"),
                    SwitchFixtures.tail(world.bootCurrent)); // tail of the pre image, not the target
            SwitchPlan.Request request = world.requestWith(List.of(wrongTail));
            SwitchPlan plan = InstallerMultiPartitionTransaction.prepare(request, world.provider, world.journal);
            var result = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(result.state == InstallerMultiPartitionTransaction.State.ROLLED_BACK, "M13 rolled back");
            check("WRITE_TAIL_MISMATCH".equals(result.code), "M13 code " + result.code);
            check(SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "M13 restored to pre");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void maxSizeBoundRejected() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchStep oversized = new SwitchStep("init_boot", StepRole.WRITE_CANDIDATE,
                    BlockDeviceTransaction.MAX_BYTES + 1, world.initOtherImage,
                    SwitchFixtures.sha(world.initOther), world.initCurrentImage,
                    SwitchFixtures.sha(world.initCurrent), SwitchFixtures.tail(world.initOther));
            checkFailure("INSTALLER_DEVICE_SIZE_INVALID", () ->
                    InstallerMultiPartitionTransaction.prepare(world.requestWith(List.of(oversized)),
                            world.provider, world.journal));
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void rollbackUsesPreImageNotBaseline() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan plan = world.prepare();
            var committed = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(committed.state == InstallerMultiPartitionTransaction.State.WRITTEN, "M15 committed");
            var rolled = InstallerMultiPartitionTransaction.rollback(plan, world.provider, world.journal);
            check(rolled.state == InstallerMultiPartitionTransaction.State.ROLLED_BACK, "M15 rolled back");
            check(rolled.restored.equals(List.of("boot", "init_boot")), "M15 reverse rollback order " + rolled.restored);
            check(SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "M15 boot == pre, not baseline");
            check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")), "M15 init_boot == pre, not baseline");
            check(!SwitchFixtures.same(world.bootOther, world.bytes("boot")), "M15 target not kept");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    // ------------------------------------------------------------------ extra fault/durability cases

    private static void fsyncFailureRestoresSinglePartition() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, false);
            SwitchPlan.Request request = world.requestWith(List.of(world.step("boot")));
            SwitchPlan plan = InstallerMultiPartitionTransaction.prepare(request, world.provider, world.journal);
            world.boot.failSyncAt = 1;
            var result = InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            check(result.state == InstallerMultiPartitionTransaction.State.ROLLED_BACK, "X1 rolled back");
            check("WRITE_FAILED".equals(result.code), "X1 code " + result.code);
            check(SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "X1 restored by held FD");
            check(world.boot.syncs >= 2, "X1 restore synced too");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void powerLossBetweenPartitionsResumesFromJournalAndRollsBack() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            Path journalPath = dir.root.resolve("journal.jsonl");
            FileSwitchJournal journal = FileSwitchJournal.open(journalPath, "boot-1", () -> 1000);
            SwitchPlan plan = world.prepareWith(journal);
            try {
                InstallerMultiPartitionTransaction.commit(plan, world.provider,
                        new CrashingJournal(journal,
                                event -> event.op == SwitchOp.DONE && event.partition.equals("init_boot")));
                throw new AssertionError("X2 simulated power loss did not fire");
            } catch (AssertionError expected) {
                check(expected.getMessage().contains("power loss"), "X2 crash observed");
            } finally {
                journal.close();
            }
            FileSwitchJournal.Replay replay = FileSwitchJournal.read(journalPath);
            check(!replay.corrupt, "X2 journal chain intact");
            check(replay.donePartitions().contains("init_boot"), "X2 boot DONE durable before crash");
            check(!replay.touchedPartitions().contains("boot"), "X2 second partition never started");
            check(lastOp(replay, "init_boot") == SwitchOp.DONE, "X2 boot last op DONE");

            FakeWritablePartition boot = FakeWritablePartition.reopen("boot", world.boot.file());
            FakeWritablePartition initBoot = FakeWritablePartition.reopen("init_boot", world.initBoot.file());
            FakePartitionProvider provider = new FakePartitionProvider().add(boot).add(initBoot);
            FileSwitchJournal resumed = FileSwitchJournal.open(journalPath, "boot-1", () -> 2000);
            check(resumed.lastSeq() == replay.lastSeq, "X2 journal sequence resumes");
            var result = InstallerMultiPartitionTransaction.rollback(plan, provider, resumed);
            resumed.close();
            check(result.state == InstallerMultiPartitionTransaction.State.ROLLED_BACK, "X2 recovered to ROLLED_BACK");
            check(result.restored.equals(List.of("init_boot")), "X2 only written partition restored " + result.restored);
            check(SwitchFixtures.same(world.bootCurrent, boot.bytes()), "X2 boot back to pre");
            check(SwitchFixtures.same(world.initCurrent, initBoot.bytes()), "X2 init_boot was never touched");
            FileSwitchJournal.Replay after = FileSwitchJournal.read(journalPath);
            check(!after.corrupt, "X2 recovered journal intact");
            check(after.openIntents().isEmpty(), "X2 no open intent left");
            check(lastOp(after, "init_boot") == SwitchOp.ROLLBACK_DONE, "X2 boot rollback durable");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void powerLossMidWriteRequiresRecoveryWithoutBlindRewrite() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            Path journalPath = dir.root.resolve("journal.jsonl");
            FileSwitchJournal journal = FileSwitchJournal.open(journalPath, "boot-1", () -> 1000);
            SwitchPlan plan = InstallerMultiPartitionTransaction.prepare(world.request, world.provider, journal);
            world.boot.shortWrite = 113;
            world.boot.crashAfterWrites = 350;
            try {
                InstallerMultiPartitionTransaction.commit(plan, world.provider, journal);
                throw new AssertionError("X3 simulated power loss did not fire");
            } catch (AssertionError expected) {
                check(expected.getMessage().contains("power loss"), "X3 crash observed");
            } finally {
                journal.close();
            }
            byte[] partial = world.boot.bytes();
            check(!SwitchFixtures.same(partial, world.bootCurrent)
                    && !SwitchFixtures.same(partial, world.bootOther), "X3 init_boot partially written");
            FileSwitchJournal.Replay replay = FileSwitchJournal.read(journalPath);
            check(replay.openIntents().contains("boot"), "X3 open intent recorded");
            check(replay.donePartitions().contains("init_boot"), "X3 first partition complete");

            FakeWritablePartition boot = FakeWritablePartition.reopen("boot", world.boot.file());
            FakeWritablePartition initBoot = FakeWritablePartition.reopen("init_boot", world.boot.file());
            FakePartitionProvider provider = new FakePartitionProvider().add(boot).add(initBoot);
            FileSwitchJournal resumed = FileSwitchJournal.open(journalPath, "boot-1", () -> 2000);
            byte[] before = boot.bytes();
            var result = InstallerMultiPartitionTransaction.rollback(plan, provider, resumed);
            resumed.close();
            check(result.state == InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED, "X3 recovery required");
            check("WRITE_ROLLBACK_FAILED".equals(result.code), "X3 code " + result.code);
            check(SwitchFixtures.same(before, boot.bytes()), "X3 unattributable content not rewritten");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void parsedPlanRecoversWithoutTheDeletedCandidate() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan plan = world.prepare();
            var saved = plan.flatFields();
            world.initBoot.externalWrite(world.initOther);
            Files.delete(world.initOtherImage);
            SwitchPlan recovered = SwitchPlan.parse(saved);
            check(recovered.flatFields().equals(saved), "R16 exact prepared plan recovered");
            var rollback = InstallerMultiPartitionTransaction.rollback(recovered, world.provider, world.journal);
            check(rollback.state == InstallerMultiPartitionTransaction.State.ROLLED_BACK,
                    "R16 partial completed plan rolls back without candidate");
            check(SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "R16 PRE boot preserved");
            check(world.boot.writes == 0, "R16 PRE boot is not rewritten");
            check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")), "R16 completed init_boot restored");
            check(!Files.exists(world.initOtherImage), "R16 rollback does not recreate candidate");
            check(world.journal.events.stream().filter(event -> event.op == SwitchOp.PREPARED).count() == 1,
                    "R16 no second prepare during recovery");
            world.boot.externalWrite(world.bootOther);
            world.initBoot.externalWrite(world.initOther);
            var verify = InstallerMultiPartitionTransaction.verify(recovered, world.provider,
                    new FakeSwitchFacts(), world.journal);
            check(verify.state == InstallerMultiPartitionTransaction.State.VERIFIED,
                    "R16 verify reads targets and facts without candidate");
            check(!Files.exists(world.initOtherImage), "R16 verify does not recreate candidate");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void journalIsFixedKeyJsonlWithPrevChain() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            Path journalPath = dir.root.resolve("journal.jsonl");
            FileSwitchJournal journal = FileSwitchJournal.open(journalPath, "boot-1", () -> 1000);
            SwitchPlan plan = InstallerMultiPartitionTransaction.prepare(world.request, world.provider, journal);
            var result = InstallerMultiPartitionTransaction.commit(plan, world.provider, journal);
            journal.close();
            check(result.state == InstallerMultiPartitionTransaction.State.WRITTEN, "X4 commit");
            List<String> lines = Files.readAllLines(journalPath, StandardCharsets.UTF_8);
            check(lines.size() == 9, "X4 PREPARED + 4 events per partition, got " + lines.size());
            check(lines.get(0).startsWith("{\"schema\":1,\"seq\":1,"), "X4 fixed key order");
            check(lines.get(0).contains("\"prev\":\"0000000000000000000000000000000000000000000000000000000000000000\""),
                    "X4 first prev is zero hash");
            FileSwitchJournal.Replay replay = FileSwitchJournal.read(journalPath);
            check(!replay.corrupt, "X4 chain valid");
            check(replay.lastSeq == lines.size(), "X4 last seq == line count");
            check(replay.isComplete(plan), "X4 plan complete in journal");
            check(plan.planSha256.equals(replay.planSha256), "X4 plan sha recorded");
            check(plan.switchId.equals(replay.switchId), "X4 switch id recorded");

            Path corrupt = dir.root.resolve("journal-corrupt.jsonl");
            List<String> broken = new ArrayList<>(lines);
            broken.add("{\"schema\":1,\"seq\":999}");
            Files.write(corrupt, broken, StandardCharsets.UTF_8);
            check(FileSwitchJournal.read(corrupt).corrupt, "X4 corrupt journal detected");
            checkFailure("SWITCH_RECOVERY_JOURNAL_CORRUPT", () ->
                    FileSwitchJournal.open(corrupt, "boot-1", () -> 0));
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void postWriteObservationAndDoneFailuresRestoreCurrentPartition() {
        for (String point : List.of("digest", "tail", "done")) {
            try (TempWorkDir dir = TempWorkDir.create()) {
                SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
                SwitchPlan plan = world.prepare();
                boolean[] injected = {false};
                IoAction failAfterWrite = () -> {
                    if (world.initBoot.writes > 0 && !injected[0]) {
                        injected[0] = true;
                        throw new IOException("INSTALLER_DEVICE_READ_FAILED");
                    }
                };
                WritablePartition first = intercept(world.initBoot,
                        point.equals("digest") ? failAfterWrite : () -> {},
                        point.equals("tail") ? failAfterWrite : () -> {});
                FakePartitionProvider provider = new FakePartitionProvider().add(first).add(world.boot);
                SwitchJournalSink journal = event -> {
                    if (point.equals("done") && event.op == SwitchOp.DONE && !injected[0]) {
                        injected[0] = true;
                        throw new IOException("INSTALLER_JOURNAL_WRITE_FAILED");
                    }
                    world.journal.append(event);
                };
                var result = InstallerMultiPartitionTransaction.commit(plan, provider, journal);
                check(injected[0], "R29 " + point + " fault reached");
                check(result.state == (point.equals("done") ? InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED
                                : InstallerMultiPartitionTransaction.State.ROLLED_BACK),
                        "R29 " + point + " recovered");
                check(result.restored.equals(List.of("init_boot")), "R29 current restored once " + point);
                check(result.observedSha256.isEmpty(), "R29 no partial observations " + point);
                check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")), "R29 current PRE " + point);
                check(world.boot.writes == 0, "R29 next partition untouched " + point);
            } catch (IOException failure) {
                throw new AssertionError(failure);
            }
        }
    }

    private static void nextPartitionObservationAndIntentFailuresRestoreEarlierWrite() {
        for (String point : List.of("provider", "digest", "intent")) {
            try (TempWorkDir dir = TempWorkDir.create()) {
                SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
                SwitchPlan plan = world.prepare();
                boolean[] injected = {false};
                WritablePartition second = intercept(world.boot, () -> {
                    if (point.equals("digest") && !injected[0]) {
                        injected[0] = true;
                        throw new IllegalStateException("INSTALLER_PARTITION_CHANGED");
                    }
                }, () -> {});
                SwitchPartitionProvider provider = new SwitchPartitionProvider() {
                    @Override public WritablePartition get(String name) throws IOException {
                        if (name.equals("boot") && point.equals("provider") && !injected[0]) {
                            injected[0] = true;
                            throw new SwitchFailure("SWITCH_PARTITION_LAYOUT_UNSUPPORTED", "injected");
                        }
                        return name.equals("boot") ? second : world.initBoot;
                    }
                    @Override public java.util.Set<String> available() { return world.provider.available(); }
                };
                SwitchJournalSink journal = event -> {
                    if (point.equals("intent") && event.op == SwitchOp.INTENT && event.partition.equals("boot")
                            && !injected[0]) {
                        injected[0] = true;
                        throw new IOException("INSTALLER_JOURNAL_WRITE_FAILED");
                    }
                    world.journal.append(event);
                };
                var result = InstallerMultiPartitionTransaction.commit(plan, provider, journal);
                check(injected[0], "R29 next " + point + " fault reached");
                check(result.state == (point.equals("intent") ? InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED
                                : InstallerMultiPartitionTransaction.State.ROLLED_BACK),
                        "R29 earlier write recovered after " + point);
                check(result.restored.equals(List.of("init_boot")), "R29 earlier restore order " + point);
                check(result.observedSha256.isEmpty(), "R29 next error no success observations " + point);
                check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")), "R29 earlier PRE " + point);
                check(world.boot.writes == 0, "R29 next failed before bytes " + point);
            } catch (IOException failure) {
                throw new AssertionError(failure);
            }
        }
    }

    private static void rollbackRuntimeFailureDoesNotStrandRemainingPartitions() {
        for (boolean explicit : List.of(false, true)) {
            try (TempWorkDir dir = TempWorkDir.create()) {
                SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
                SwitchPlan plan = world.prepare();
                boolean[] armed = {false}, injected = {false};
                WritablePartition second = intercept(world.boot, () -> {
                    if (armed[0] && !injected[0]) {
                        injected[0] = true;
                        throw new IllegalStateException("INSTALLER_PARTITION_CHANGED");
                    }
                }, () -> {});
                FakePartitionProvider provider = new FakePartitionProvider().add(world.initBoot).add(second);
                SwitchJournalSink journal = event -> {
                    world.journal.append(event);
                    if (!explicit && event.op == SwitchOp.DONE && event.partition.equals("boot")) {
                        armed[0] = true;
                        throw new IOException("INSTALLER_JOURNAL_WRITE_FAILED");
                    }
                };
                var committed = InstallerMultiPartitionTransaction.commit(plan, provider, journal);
                InstallerMultiPartitionTransaction.Result result;
                if (explicit) {
                    check(committed.state == InstallerMultiPartitionTransaction.State.WRITTEN, "R29 rollback setup");
                    armed[0] = true;
                    result = InstallerMultiPartitionTransaction.rollback(plan, provider, journal);
                } else result = committed;
                check(injected[0], "R29 rollback runtime fault reached " + explicit);
                check(result.state == InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED,
                        "R29 failed partition remains recovery required " + explicit);
                check("WRITE_ROLLBACK_FAILED".equals(result.code), "R29 rollback failure classified " + explicit);
                check(result.restored.equals(List.of("init_boot")), "R29 remaining partition restored " + explicit);
                check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")), "R29 remaining PRE " + explicit);
                check(SwitchFixtures.same(world.bootOther, world.bytes("boot")), "R29 unreadable partition untouched " + explicit);
            } catch (IOException failure) {
                throw new AssertionError(failure);
            }
        }
    }

    private static void cancellationIsDeferredUntilRecoveryCompletes() {
        for (boolean explicit : List.of(false, true)) {
            try (TempWorkDir dir = TempWorkDir.create()) {
                SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
                SwitchPlan plan = world.prepare();
                IoAction cancellationSensitiveRead = () -> {
                    if (Thread.currentThread().isInterrupted()) throw new IllegalStateException("INSTALLER_CANCELLED");
                };
                FakePartitionProvider provider = new FakePartitionProvider()
                        .add(intercept(world.initBoot, cancellationSensitiveRead, () -> {}))
                        .add(intercept(world.boot, cancellationSensitiveRead, () -> {}));
                SwitchJournalSink journal = event -> {
                    world.journal.append(event);
                    if (!explicit && event.op == SwitchOp.DONE && event.partition.equals("boot")) {
                        Thread.currentThread().interrupt();
                        throw new IOException("INSTALLER_CANCELLED");
                    }
                };
                var committed = InstallerMultiPartitionTransaction.commit(plan, provider, journal);
                InstallerMultiPartitionTransaction.Result result;
                if (explicit) {
                    check(committed.state == InstallerMultiPartitionTransaction.State.WRITTEN, "R29 cancel setup");
                    Thread.currentThread().interrupt();
                    result = InstallerMultiPartitionTransaction.rollback(plan, provider, journal);
                } else result = committed;
                check(Thread.currentThread().isInterrupted(), "R29 caller cancellation retained " + explicit);
                Thread.interrupted();
                check(result.state == (explicit ? InstallerMultiPartitionTransaction.State.ROLLED_BACK
                                : InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED),
                        "R29 cancellation does not stop recovery " + explicit);
                check(result.restored.equals(List.of("boot", "init_boot")), "R29 cancel reverse order " + explicit);
                check(SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "R29 cancelled boot PRE " + explicit);
                check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")), "R29 cancelled init PRE " + explicit);
            } catch (IOException failure) {
                throw new AssertionError(failure);
            } finally {
                Thread.interrupted();
            }
        }
    }

    private static void finalRecoveryObservationRuntimeFailureIsClassified() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan plan = world.prepare();
            InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            int[] reads = {0};
            WritablePartition first = intercept(world.initBoot, () -> {
                if (++reads[0] == 3) throw new IllegalStateException("INSTALLER_DEVICE_READ_FAILED");
            }, () -> {});
            FakePartitionProvider provider = new FakePartitionProvider().add(first).add(world.boot);
            var result = InstallerMultiPartitionTransaction.rollback(plan, provider, world.journal);
            check(reads[0] == 3, "R29 final observation fault reached");
            check(result.state == InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED,
                    "R29 unobserved recovery is not certified");
            check(result.restored.equals(List.of("boot", "init_boot")), "R29 both restore writes completed");
            check(SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "R29 final observation boot PRE");
            check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")), "R29 final observation init PRE");
        } catch (IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static void forwardJournalFailureRestoresBytesWithoutExtendingFailedLog() {
        for (String point : List.of("first-writing", "second-intent", "reboot-pending")) {
            for (boolean runtime : List.of(false, true)) {
                try (TempWorkDir dir = TempWorkDir.create()) {
                    SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
                    SwitchPlan plan = world.prepare();
                    int[] failedAppends = {0};
                    boolean[] failed = {false};
                    SwitchJournalSink journal = event -> {
                        if (failed[0]) failedAppends[0]++;
                        boolean target = point.equals("first-writing") ? event.op == SwitchOp.COMMIT_INTENT
                                : point.equals("second-intent")
                                    ? event.op == SwitchOp.INTENT && event.partition.equals("boot")
                                    : event.op == SwitchOp.REBOOT_PENDING;
                        if (target || failed[0]) {
                            failed[0] = true;
                            failedAppends[0]++;
                            if (runtime) throw new IllegalStateException("INSTALLER_JOURNAL_WRITE_FAILED");
                            throw new IOException("INSTALLER_JOURNAL_WRITE_FAILED");
                        }
                        world.journal.append(event);
                    };
                    var result = InstallerMultiPartitionTransaction.commit(plan, world.provider, journal);
                    check(failed[0] && failedAppends[0] == 1, "R31 failed log append not extended " + point);
                    check(result.state == InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED,
                            "R31 journal failure prevents certified rollback " + point);
                    check("INSTALLER_JOURNAL_WRITE_FAILED".equals(result.detail), "R31 precise log failure " + point);
                    check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")), "R31 current PRE " + point);
                    check(SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "R31 second PRE " + point);
                    check(world.boot.writes == 0, "R31 no second write after failed log " + point);
                    if (point.equals("first-writing")) check(world.initBoot.writes == 0,
                            "R31 first WRITING remains a strict no-byte barrier");
                    check(result.observedSha256.isEmpty(), "R31 failed commit publishes no successful observations");
                } catch (IOException failure) { throw new AssertionError(failure); }
            }
        }
    }

    private static void explicitRecoveryJournalFailureContinuesKnownPartitionsOnly() {
        for (boolean runtime : List.of(false, true)) {
            for (boolean unknown : List.of(false, true)) {
                try (TempWorkDir dir = TempWorkDir.create()) {
                    SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
                    SwitchPlan plan = world.prepare();
                    InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
                    byte[] external = SwitchFixtures.data(SwitchFixtures.BOOT_SIZE, 87);
                    if (unknown) world.boot.externalWrite(external);
                    int previousBootWrites = world.boot.writes;
                    int[] appendCalls = {0};
                    SwitchJournalSink journal = event -> {
                        appendCalls[0]++;
                        if (runtime) throw new IllegalStateException("INSTALLER_JOURNAL_WRITE_FAILED");
                        throw new IOException("INSTALLER_JOURNAL_WRITE_FAILED");
                    };
                    if (runtime) Thread.currentThread().interrupt();
                    var result = InstallerMultiPartitionTransaction.rollback(plan, world.provider, journal);
                    check(Thread.currentThread().isInterrupted() == runtime, "R31 rollback cancellation retained");
                    Thread.interrupted();
                    check(appendCalls[0] == 1, "R31 no append after failed recovery log");
                    check(result.state == InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED,
                            "R31 explicit failed log not certified");
                    check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")),
                            "R31 explicit remaining known partition recovers");
                    check(SwitchFixtures.same(unknown ? external : world.bootCurrent, world.bytes("boot")),
                            "R31 explicit unknown content never overwritten");
                    check(result.restored.equals(unknown ? List.of("init_boot") : List.of("boot", "init_boot")),
                            "R31 actual restored order retained");
                    if (unknown) check(world.boot.writes == previousBootWrites, "R31 unknown has no recovery write");
                } catch (IOException failure) { throw new AssertionError(failure); }
                finally { Thread.interrupted(); }
            }
        }
    }

    private static void recoveryLogErrorStillPropagates() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan plan = world.prepare();
            InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            int previousBootWrites = world.boot.writes;
            AssertionError death = new AssertionError("simulated recovery process death");
            try {
                InstallerMultiPartitionTransaction.rollback(plan, world.provider, event -> { throw death; });
                throw new AssertionError("recovery Error swallowed");
            } catch (AssertionError expected) {
                check(expected == death, "R31 recovery process death propagated");
                check(world.boot.writes == previousBootWrites, "R31 process death stops recovery");
            }
        } catch (IOException failure) { throw new AssertionError(failure); }
    }

    private static void recoveryJournalFailureDoesNotHideDataFailureOrStopOtherPartition() {
        try (TempWorkDir dir = TempWorkDir.create()) {
            SwitchFixtures.World world = new SwitchFixtures.World(dir, true);
            SwitchPlan plan = world.prepare();
            InstallerMultiPartitionTransaction.commit(plan, world.provider, world.journal);
            world.boot.failSyncAt = world.boot.syncs + 1;
            int[] appends = {0};
            var result = InstallerMultiPartitionTransaction.rollback(plan, world.provider, event -> {
                appends[0]++;
                throw new IOException("INSTALLER_JOURNAL_WRITE_FAILED");
            });
            check(appends[0] == 1, "R31 data failure does not resume failed log");
            check(result.state == InstallerMultiPartitionTransaction.State.RECOVERY_REQUIRED &&
                    "INSTALLER_DEVICE_SYNC_FAILED".equals(result.detail), "R31 data recovery failure stays primary");
            check(result.restored.equals(List.of("init_boot")), "R31 remaining partition still certified in memory");
            check(SwitchFixtures.same(world.initCurrent, world.bytes("init_boot")), "R31 remaining PRE after failed sync");
            check(SwitchFixtures.same(world.bootCurrent, world.bytes("boot")), "R31 failed sync bytes alone not success");
        } catch (IOException failure) { throw new AssertionError(failure); }
    }

    public static void main(String[] args) throws Exception {
        writesBothPartitionsInPlanOrder();
        intentPrecedesEveryPartitionWrite();
        journalFailureBeforeWriteTouchesNothing();
        secondPartitionFailureRollsBackFirstInReverseOrder();
        readbackMismatchRollsBackBoth();
        rollbackFailureYieldsRecoveryRequired();
        restoreFailureYieldsRecoveryEvenWhenBytesReachPre();
        unexpectedContentAbortsBeforeWrite();
        skipsPartitionAlreadyAtTarget();
        secondCommitIsNoOp();
        cancelBeforeCommitLeavesPartitions();
        shortReadsAndShortWritesComplete();
        fullLengthDigestRejectsPaddedShortImage();
        tailProbeDetectsTruncatedCandidate();
        maxSizeBoundRejected();
        rollbackUsesPreImageNotBaseline();
        fsyncFailureRestoresSinglePartition();
        powerLossBetweenPartitionsResumesFromJournalAndRollsBack();
        powerLossMidWriteRequiresRecoveryWithoutBlindRewrite();
        parsedPlanRecoversWithoutTheDeletedCandidate();
        journalIsFixedKeyJsonlWithPrevChain();
        postWriteObservationAndDoneFailuresRestoreCurrentPartition();
        nextPartitionObservationAndIntentFailuresRestoreEarlierWrite();
        rollbackRuntimeFailureDoesNotStrandRemainingPartitions();
        cancellationIsDeferredUntilRecoveryCompletes();
        finalRecoveryObservationRuntimeFailureIsClassified();
        forwardJournalFailureRestoresBytesWithoutExtendingFailedLog();
        explicitRecoveryJournalFailureContinuesKnownPartitionsOnly();
        recoveryLogErrorStillPropagates();
        recoveryJournalFailureDoesNotHideDataFailureOrStopOtherPartition();
        System.out.println("MultiPartitionTransaction: " + passed
                + " checks passed (plan order, intent barrier, reverse rollback, short I/O, tail probe,"
                + " fsync failure, journal replay and power-loss recovery)");
    }
}
