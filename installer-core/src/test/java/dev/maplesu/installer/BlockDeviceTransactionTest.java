package dev.maplesu.installer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Deterministic I/O faults; this does not claim hardware or power-loss coverage. */
public final class BlockDeviceTransactionTest {
    private static final byte[] ORIGINAL = new byte[150_001];
    private static final byte[] CANDIDATE = new byte[90_123];
    static { Arrays.fill(ORIGINAL, (byte) 7); Arrays.fill(CANDIDATE, (byte) 19); }

    private static final class Device implements BlockDeviceTransaction.Device {
        final byte[] bytes = ORIGINAL.clone();
        int writes;
        long maxWriteEnd;
        int failWrite = -1;
        int corruptAfterSync;
        boolean badIdentity;
        boolean failRecovery;
        public long size() { return bytes.length; }
        public void revalidate() throws IOException { if (badIdentity) throw new IOException("INSTALLER_PARTITION_CHANGED"); }
        public int read(long offset, byte[] buffer, int length) {
            int count = Math.min(length, 997); // Exercise short reads.
            System.arraycopy(bytes, (int) offset, buffer, 0, count);
            return count;
        }
        public int write(long offset, byte[] buffer, int start, int length) throws IOException {
            writes++;
            if (writes == failWrite || failRecovery && writes >= failWrite) throw new IOException("INSTALLER_DEVICE_WRITE_FAILED");
            int count = Math.min(length, 113); // Exercise short writes.
            System.arraycopy(buffer, start, bytes, (int) offset, count);
            maxWriteEnd = Math.max(maxWriteEnd, offset + count);
            return count;
        }
        public void sync() { if (corruptAfterSync-- > 0) bytes[0] ^= 1; }
        public void close() {}
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("maplesu-block-transaction-test-");
        try {
            Path candidate = root.resolve("candidate.img"), recovery = root.resolve("existing-recovery.img");
            Files.write(candidate, CANDIDATE);
            Files.write(recovery, ORIGINAL);
            String candidateHash = BlockDeviceTransaction.paddedDigest(candidate, CANDIDATE.length);
            String originalHash = BlockDeviceTransaction.paddedDigest(recovery, ORIGINAL.length);
            var states = new ArrayList<String>();
            Device successful = new Device();
            var result = BlockDeviceTransaction.commit(successful, candidate, candidateHash, recovery, originalHash,
                    (state, error) -> states.add(state));
            require(result.rebootRequired && "REBOOT_REQUIRED".equals(result.state), "commit result");
            require(states.equals(List.of("WRITING", "REBOOT_REQUIRED")), "journal barriers");
            require(Arrays.equals(CANDIDATE, Arrays.copyOf(successful.bytes, CANDIDATE.length)), "candidate bytes");
            require(Arrays.equals(new byte[ORIGINAL.length - CANDIDATE.length],
                    Arrays.copyOfRange(successful.bytes, CANDIDATE.length, ORIGINAL.length)), "zero-filled tail");

            Device blocked = new Device();
            blocked.failWrite = 1;
            blocked.failRecovery = true;
            result = BlockDeviceTransaction.commit(blocked, candidate, candidateHash, recovery, originalHash, (s, e) -> {});
            require("RESTORED".equals(result.state) && !result.rebootRequired,
                    "a denied first write with unchanged PRE must not request rescue");
            require(blocked.writes == 1 && Arrays.equals(ORIGINAL, blocked.bytes),
                    "unchanged PRE is verified without another denied write");

            for (int failurePoint : new int[]{1, 250, 1000}) {
                Device faulty = new Device();
                faulty.failWrite = failurePoint;
                states.clear();
                result = BlockDeviceTransaction.commit(faulty, candidate, candidateHash, recovery, originalHash,
                        (state, error) -> states.add(state));
                require("RESTORED".equals(result.state) && !result.rebootRequired, "failed install stays failed");
                require(Arrays.equals(ORIGINAL, faulty.bytes), "partial write restored");
                require(states.equals(List.of("WRITING", "RECOVERY_REQUIRED", "RESTORING", "RESTORED")), "restore journal");
            }

            Device corrupt = new Device();
            corrupt.corruptAfterSync = 1;
            result = BlockDeviceTransaction.commit(corrupt, candidate, candidateHash, recovery, originalHash, (s, e) -> {});
            require("RESTORED".equals(result.state) && "INSTALLER_READBACK_MISMATCH".equals(result.error), "readback rollback");
            require(Arrays.equals(ORIGINAL, corrupt.bytes), "corruption restored");

            Device unrecoverable = new Device();
            unrecoverable.failWrite = 200;
            unrecoverable.failRecovery = true;
            result = BlockDeviceTransaction.commit(unrecoverable, candidate, candidateHash, recovery, originalHash, (s, e) -> {});
            require("RECOVERY_REQUIRED".equals(result.state) && !result.rebootRequired, "failed recovery result");
            unrecoverable.failRecovery = false;
            result = BlockDeviceTransaction.restore(unrecoverable, recovery, originalHash, (s, e) -> {});
            require("RESTORED".equals(result.state) && Arrays.equals(ORIGINAL, unrecoverable.bytes), "resume recovery");

            Device beforeWrite = new Device();
            try {
                BlockDeviceTransaction.commit(beforeWrite, candidate, candidateHash, recovery, originalHash,
                        (state, error) -> { throw new IOException("journal failure"); });
                throw new AssertionError("journal failure accepted");
            } catch (IOException expected) { require(beforeWrite.writes == 0, "journal failure must precede writes"); }
            beforeWrite.bytes[0]++;
            try {
                BlockDeviceTransaction.commit(beforeWrite, candidate, candidateHash, recovery, originalHash, (s, e) -> {});
                throw new AssertionError("changed target accepted");
            } catch (IOException expected) { require(beforeWrite.writes == 0, "target change rejected before write"); }
            Device changedIdentity = new Device();
            changedIdentity.badIdentity = true;
            try {
                BlockDeviceTransaction.commit(changedIdentity, candidate, candidateHash, recovery, originalHash, (s, e) -> {});
                throw new AssertionError("changed identity accepted");
            } catch (IOException expected) { require(changedIdentity.writes == 0, "identity change rejected before write"); }
            Device cancelled = new Device();
            result = BlockDeviceTransaction.commit(cancelled, candidate, candidateHash, recovery, originalHash,
                    (state, error) -> { if (state.equals("WRITING")) Thread.currentThread().interrupt(); });
            require("RESTORED".equals(result.state) && Arrays.equals(ORIGINAL, cancelled.bytes), "cancellation restores");
            require(Thread.interrupted(), "cancellation status preserved after restoration");

            Device wrongHash = new Device();
            try {
                BlockDeviceTransaction.commit(wrongHash, candidate, originalHash, recovery, originalHash, (s, e) -> {});
                throw new AssertionError("wrong candidate hash accepted");
            } catch (IOException expected) {
                require("INSTALLER_IMAGE_CHANGED".equals(expected.getMessage()) && wrongHash.writes == 0,
                        "padded expectation remains bound to the supplied content hash");
            }

            Device truncatedCandidate = new Device();
            long[] candidateWriteEnd = {-1};
            result = BlockDeviceTransaction.commit(truncatedCandidate, candidate, candidateHash, recovery, originalHash,
                    (state, error) -> {
                        if (state.equals("WRITING")) Files.write(candidate, Arrays.copyOf(CANDIDATE, 123));
                        if (state.equals("RESTORING")) candidateWriteEnd[0] = truncatedCandidate.maxWriteEnd;
                    });
            require("RESTORED".equals(result.state) && "INSTALLER_IMAGE_CHANGED".equals(result.error),
                    "candidate EOF enters restoration");
            require(candidateWriteEnd[0] == 123 && Arrays.equals(ORIGINAL, truncatedCandidate.bytes),
                    "candidate early EOF never zero-fills missing content");
            Files.write(candidate, CANDIDATE);

            Device replacedCandidate = new Device();
            candidateWriteEnd[0] = -1;
            result = BlockDeviceTransaction.commit(replacedCandidate, candidate, candidateHash, recovery, originalHash,
                    (state, error) -> {
                        if (state.equals("WRITING")) {
                            byte[] changed = CANDIDATE.clone();
                            changed[0]++;
                            Files.write(candidate, changed);
                        }
                        if (state.equals("RESTORING")) candidateWriteEnd[0] = replacedCandidate.maxWriteEnd;
                    });
            require("RESTORED".equals(result.state) && "INSTALLER_IMAGE_CHANGED".equals(result.error),
                    "same-length candidate drift enters restoration");
            require(candidateWriteEnd[0] == CANDIDATE.length && Arrays.equals(ORIGINAL, replacedCandidate.bytes),
                    "changed candidate hash is detected before zero-tail writes");
            Files.write(candidate, CANDIDATE);

            Device truncatedRecovery = new Device();
            Arrays.fill(truncatedRecovery.bytes, (byte) 29);
            states.clear();
            try {
                BlockDeviceTransaction.restore(truncatedRecovery, recovery, originalHash, (state, error) -> {
                    states.add(state);
                    if (state.equals("RESTORING")) Files.write(recovery, Arrays.copyOf(ORIGINAL, 123));
                });
                throw new AssertionError("truncated recovery accepted");
            } catch (IOException expected) {
                require("INSTALLER_IMAGE_CHANGED".equals(expected.getMessage()), "recovery EOF is an input change");
                require(truncatedRecovery.maxWriteEnd == 123 && truncatedRecovery.bytes[123] == 29 &&
                        truncatedRecovery.bytes[ORIGINAL.length - 1] == 29,
                        "recovery EOF stops without zero-filling the missing PRE");
                require(states.equals(List.of("RESTORING")), "truncated recovery never reports restored");
            }
            Files.write(recovery, ORIGINAL);

            Device extendedRecovery = new Device();
            Arrays.fill(extendedRecovery.bytes, (byte) 31);
            try {
                BlockDeviceTransaction.restore(extendedRecovery, recovery, originalHash, (state, error) -> {
                    if (state.equals("RESTORING")) Files.write(recovery, Arrays.copyOf(ORIGINAL, ORIGINAL.length + 1));
                });
                throw new AssertionError("extended recovery accepted");
            } catch (IOException expected) {
                require("INSTALLER_IMAGE_CHANGED".equals(expected.getMessage()) &&
                        extendedRecovery.maxWriteEnd == ORIGINAL.length,
                        "extra recovery input is rejected without writing beyond the partition");
            }
            Files.write(recovery, ORIGINAL);
            recoveryJournalFailuresDoNotStrandPre(candidate, candidateHash, recovery, originalHash);
            explicitRecoveryJournalFailureIsReportedAfterPre(recovery, originalHash);
            System.out.println("BlockDeviceTransaction: success, tail, short I/O, partial-write rollback, readback failure, recovery resume, fixed input hashes/lengths and prewrite barriers passed");
        } finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void recoveryJournalFailuresDoNotStrandPre(Path candidate, String candidateHash,
                                                              Path recovery, String originalHash) throws Exception {
        for (String point : List.of("RECOVERY_REQUIRED", "RESTORING", "RESTORED", "REBOOT_REQUIRED")) {
            for (boolean runtime : List.of(false, true)) {
                Device device = new Device();
                if (!point.equals("REBOOT_REQUIRED")) device.failWrite = 250;
                boolean[] failed = {false};
                int[] callsAfterFailure = {0};
                var result = BlockDeviceTransaction.commit(device, candidate, candidateHash, recovery, originalHash,
                        (state, error) -> {
                            if (failed[0]) callsAfterFailure[0]++;
                            if (state.equals(point)) {
                                failed[0] = true;
                                if (runtime) throw new IllegalStateException("INSTALLER_JOURNAL_WRITE_FAILED");
                                throw new IOException("INSTALLER_JOURNAL_WRITE_FAILED");
                            }
                        });
                require(failed[0] && callsAfterFailure[0] == 0, "failed append is never extended " + point);
                require(Arrays.equals(ORIGINAL, device.bytes), "PRE bytes recover despite journal " + point);
                require("RECOVERY_REQUIRED".equals(result.state) && !result.rebootRequired,
                        "journal failure prevents certified recovery " + point);
            }
        }
        Device untouched = new Device();
        try {
            BlockDeviceTransaction.commit(untouched, candidate, candidateHash, recovery, originalHash,
                    (state, error) -> { throw new IllegalStateException("INSTALLER_JOURNAL_WRITE_FAILED"); });
            throw new AssertionError("runtime forward barrier bypassed");
        } catch (IllegalStateException expected) {
            require(untouched.writes == 0, "runtime forward journal barrier leaves bytes untouched");
        }
        Device crash = new Device();
        crash.failWrite = 250;
        AssertionError death = new AssertionError("simulated recovery process death");
        try {
            BlockDeviceTransaction.commit(crash, candidate, candidateHash, recovery, originalHash,
                    (state, error) -> { if (state.equals("RESTORING")) throw death; });
            throw new AssertionError("recovery Error swallowed");
        } catch (AssertionError expected) {
            require(expected == death, "recovery Error retains process-death semantics");
        }
    }

    private static void explicitRecoveryJournalFailureIsReportedAfterPre(Path recovery, String originalHash)
            throws Exception {
        for (boolean runtime : List.of(false, true)) {
            Device device = new Device();
            Arrays.fill(device.bytes, (byte) 43);
            Exception journalError = runtime ? new IllegalStateException("INSTALLER_JOURNAL_WRITE_FAILED")
                    : new IOException("INSTALLER_JOURNAL_WRITE_FAILED");
            int[] calls = {0};
            if (runtime) Thread.currentThread().interrupt();
            try {
                BlockDeviceTransaction.restore(device, recovery, originalHash, (state, error) -> {
                    calls[0]++;
                    require(!Thread.currentThread().isInterrupted(), "recovery clears existing cancellation");
                    if (journalError instanceof RuntimeException runtimeError) throw runtimeError;
                    throw (IOException) journalError;
                });
                throw new AssertionError("uncertified explicit recovery accepted");
            } catch (IOException | RuntimeException expected) {
                require(expected == journalError && calls[0] == 1, "explicit recovery preserves first log failure");
                require(Arrays.equals(ORIGINAL, device.bytes), "explicit PRE restored before log failure is reported");
                require(Thread.currentThread().isInterrupted() == runtime, "explicit cancellation restored");
            } finally { Thread.interrupted(); }
        }
        Device failed = new Device();
        Arrays.fill(failed.bytes, (byte) 47);
        failed.failWrite = 1;
        IOException journalError = new IOException("INSTALLER_JOURNAL_WRITE_FAILED");
        try {
            BlockDeviceTransaction.restore(failed, recovery, originalHash, (state, error) -> { throw journalError; });
            throw new AssertionError("data recovery error lost");
        } catch (IOException expected) {
            require("INSTALLER_DEVICE_WRITE_FAILED".equals(expected.getMessage()) &&
                    expected.getSuppressed().length == 1 && expected.getSuppressed()[0] == journalError,
                    "data recovery failure remains primary with journal diagnostic attached");
        }
    }
}
