package dev.maplesu.installer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Random;
import java.util.Properties;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public final class FileInstallTransactionTest {
    private static int passed;
    private static final byte[] ORIGINAL = data(17), CANDIDATE = data(42);

    private static byte[] data(int seed) {
        byte[] bytes = new byte[150_001];
        new Random(seed).nextBytes(bytes);
        return bytes;
    }

    private interface Operation { void run() throws Exception; }

    private static void rejected(Operation action, String code, boolean modified) throws Exception {
        try { action.run(); throw new AssertionError("Accepted " + code); }
        catch (FileInstallTransaction.Failure failure) {
            check(code.equals(failure.code), "rejection code: " + failure.code);
            check(modified == failure.targetMayBeModified, "write stage classification");
        }
    }

    private static FileInstallTransaction prepared(Path root) throws Exception {
        Files.write(root.resolve("candidate.img"), CANDIDATE);
        Files.write(root.resolve("target.img"), ORIGINAL);
        return FileInstallTransaction.prepare(root, root.resolve("candidate.img"), root.resolve("target.img"),
                hash(CANDIDATE), hash(ORIGINAL));
    }

    private static FileInstallTransaction prepared(Path root, FileInstallTransaction.DirectorySync directorySync) throws Exception {
        Files.write(root.resolve("candidate.img"), CANDIDATE);
        Files.write(root.resolve("target.img"), ORIGINAL);
        return FileInstallTransaction.prepare(root, root.resolve("candidate.img"), root.resolve("target.img"),
                hash(CANDIDATE), hash(ORIGINAL), directorySync);
    }

    private static void journalBeforeTargetWrite(Path root) throws Exception {
        var barriers = new ArrayList<String>();
        var parentSynced = new java.util.concurrent.atomic.AtomicBoolean();
        FileInstallTransaction transaction = prepared(root, directory -> {
            if (directory.equals(root)) parentSynced.set(true);
            String state = recordState(directory);
            if (state != null) barriers.add(state);
        });
        check(parentSynced.get(), "the new transaction directory entry is synchronized in its parent");
        check(transaction.directorySyncSupported(), "injected directory synchronization is enabled");
        check(barriers.equals(java.util.List.of("PREPARING", "PREPARED")),
                "preparation synchronizes the backup and identity directory entries before returning");
        barriers.clear();
        transaction.commit((phase, written, channel) -> {
            if (phase.equals("AFTER_WRITE") && written == 65536) {
                check(barriers.contains("WRITING"), "journal parent directory must be synced before the first target write");
            }
        });
        check(barriers.equals(java.util.List.of("WRITING", "WRITTEN", "VERIFIED")),
                "each committed journal state must sync its parent directory after replacement");
    }

    private static void nestedTargetDirectories(Path root) throws Exception {
        Path parent = Files.createDirectories(root.resolve("nested/target"));
        Path candidate = root.resolve("candidate.img"), target = parent.resolve("image.img");
        Files.write(candidate, CANDIDATE);
        Files.write(target, ORIGINAL);
        var synchronizedDirectories = new ArrayList<Path>();
        FileInstallTransaction transaction = FileInstallTransaction.prepare(root, candidate, target,
                hash(CANDIDATE), hash(ORIGINAL), synchronizedDirectories::add);
        check(synchronizedDirectories.subList(0, 3).equals(java.util.List.of(parent, parent.getParent(), root)),
                "target parent entries and transaction root are synchronized from child to parent");
        transaction.commit();
        check(Arrays.equals(CANDIDATE, Files.readAllBytes(target)), "nested regular target committed");
        FileInstallTransaction.open(root, transaction.directory()).restore();
        check(Arrays.equals(ORIGINAL, Files.readAllBytes(target)), "nested regular target restored");
    }

    private static String recordState(Path directory) throws IOException {
        Path record = directory.resolve("record.properties");
        if (!Files.isRegularFile(record)) return null;
        Properties properties = new Properties();
        try (var input = Files.newInputStream(record)) { properties.load(input); }
        return properties.getProperty("state");
    }

    private static void journalSyncFailures(Path root) throws Exception {
        var failWriting = new java.util.concurrent.atomic.AtomicBoolean(true);
        FileInstallTransaction beforeWrite = prepared(root, directory -> {
            if ("WRITING".equals(recordState(directory)) && failWriting.getAndSet(false)) {
                throw new IOException("injected WRITING directory sync failure");
            }
        });
        rejected(beforeWrite::commit, "JOURNAL_FAILED", false);
        targetIs(root, ORIGINAL);
        check(beforeWrite.state() == FileInstallTransaction.State.WRITING,
                "a replaced but unsynced write-intent record stays conservatively in progress");
        FileInstallTransaction.open(root, beforeWrite.directory()).restore();
        targetIs(root, ORIGINAL);

        FileInstallTransaction afterWrite = prepared(root, directory -> {
            if ("WRITTEN".equals(recordState(directory))) throw new IOException("injected WRITTEN directory sync failure");
        });
        rejected(afterWrite::commit, "JOURNAL_FAILED", true);
        targetIs(root, CANDIDATE);
        check(afterWrite.state() == FileInstallTransaction.State.RECOVERY_REQUIRED,
                "post-write journal sync failure requires recovery");
        FileInstallTransaction.open(root, afterWrite.directory()).restore();
        targetIs(root, ORIGINAL);

        FileInstallTransaction recoveryJournal = prepared(root, directory -> {
            String state = recordState(directory);
            if ("VERIFIED".equals(state) || "RECOVERY_REQUIRED".equals(state)) {
                throw new IOException("injected final and recovery directory sync failure");
            }
        });
        try { recoveryJournal.commit(); throw new AssertionError("Accepted failed final journal synchronization"); }
        catch (FileInstallTransaction.Failure failure) {
            check("JOURNAL_FAILED".equals(failure.code) && failure.targetMayBeModified,
                    "failed final journal remains a modified-target failure");
            check(failure.getCause().getSuppressed().length == 1,
                    "failure to persist the recovery state is retained");
        }
        targetIs(root, CANDIDATE);
        FileInstallTransaction.open(root, recoveryJournal.directory()).restore();
        targetIs(root, ORIGINAL);

        var failRestoring = new java.util.concurrent.atomic.AtomicBoolean(true);
        FileInstallTransaction restoring = prepared(root, directory -> {
            if ("RESTORING".equals(recordState(directory)) && failRestoring.getAndSet(false)) {
                throw new IOException("injected RESTORING directory sync failure");
            }
        });
        restoring.commit();
        rejected(restoring::restore, "JOURNAL_FAILED", false);
        targetIs(root, CANDIDATE);
        check(restoring.state() == FileInstallTransaction.State.RESTORING,
                "restore intent is retained without claiming completion");
        restoring.restore();
        targetIs(root, ORIGINAL);
        check(restoring.state() == FileInstallTransaction.State.RESTORED, "restore can be retried after journal failure");
    }

    private static void targetIs(Path root, byte[] expected) throws Exception {
        check(Arrays.equals(expected, Files.readAllBytes(root.resolve("target.img"))), "target contents");
    }

    private static void scenarios(Path root) throws Exception {
        Path source = root.resolve("candidate.img"), target = root.resolve("target.img");
        FileInstallTransaction changed = prepared(root);
        Files.write(source, ORIGINAL);
        rejected(changed::commit, "CANDIDATE_CHANGED", false);
        targetIs(root, ORIGINAL);

        changed = prepared(root);
        Files.write(target, CANDIDATE);
        rejected(changed::commit, "TARGET_CHANGED", false);
        targetIs(root, CANDIDATE);

        for (Path file : new Path[]{source, target}) {
            FileInstallTransaction replacement = prepared(root);
            Path substitute = root.resolve("replacement.img");
            Files.write(substitute, Files.readAllBytes(file));
            Files.move(substitute, file, StandardCopyOption.REPLACE_EXISTING);
            rejected(replacement::commit, "FILE_IDENTITY_CHANGED", false);
            targetIs(root, ORIGINAL);
        }

        FileInstallTransaction damaged = prepared(root);
        Files.write(damaged.directory().resolve("original.img"), CANDIDATE);
        rejected(damaged::commit, "BACKUP_MISMATCH", false);
        targetIs(root, ORIGINAL);

        FileInstallTransaction interrupted = prepared(root);
        rejected(() -> interrupted.commit((phase, count, channel) -> {
            if (phase.equals("AFTER_WRITE")) throw new IOException("injected write failure");
        }), "WRITE_FAILED", true);
        check(interrupted.state() == FileInstallTransaction.State.RECOVERY_REQUIRED, "partial write recorded");
        byte[] partial = Files.readAllBytes(target);
        check(!Arrays.equals(partial, ORIGINAL) && !Arrays.equals(partial, CANDIDATE), "actual partial write");
        FileInstallTransaction.open(root, interrupted.directory()).restore();
        targetIs(root, ORIGINAL);
        check(Arrays.equals(CANDIDATE, Files.readAllBytes(source)), "failed write leaves candidate intact");

        FileInstallTransaction readback = prepared(root);
        rejected(() -> readback.commit((phase, count, channel) -> {
            if (phase.equals("BEFORE_READBACK")) {
                channel.position(0);
                channel.write(ByteBuffer.wrap(new byte[]{(byte) (CANDIDATE[0] ^ 1)}));
                channel.force(true);
            }
        }), "READBACK_MISMATCH", true);
        check(readback.state() == FileInstallTransaction.State.RECOVERY_REQUIRED, "readback failure recorded");
        readback.restore();
        targetIs(root, ORIGINAL);

        FileInstallTransaction cancelled = prepared(root);
        Thread.currentThread().interrupt();
        try { rejected(cancelled::commit, "CANCELLED", false); }
        finally { Thread.interrupted(); }
        targetIs(root, ORIGINAL);

        FileInstallTransaction cancelledWrite = prepared(root);
        try {
            rejected(() -> cancelledWrite.commit((phase, count, channel) -> {
                if (phase.equals("AFTER_WRITE")) Thread.currentThread().interrupt();
            }), "CANCELLED", true);
            check(Thread.currentThread().isInterrupted(), "interrupt status retained");
        } finally { Thread.interrupted(); }
        FileInstallTransaction.open(root, cancelledWrite.directory()).restore();
        targetIs(root, ORIGINAL);

        FileInstallTransaction missingSource = prepared(root);
        missingSource.commit();
        Files.delete(source);
        FileInstallTransaction.open(root, missingSource.directory()).restore();
        targetIs(root, ORIGINAL);
        missingSource.restore();
        targetIs(root, ORIGINAL);
        rejected(missingSource::commit, "INVALID_STATE", false);

        FileInstallTransaction unsafeRestore = prepared(root);
        unsafeRestore.commit();
        Files.write(unsafeRestore.directory().resolve("original.img"), CANDIDATE);
        rejected(unsafeRestore::restore, "BACKUP_MISMATCH", false);
        targetIs(root, CANDIDATE);

        FileInstallTransaction staleRestore = prepared(root);
        staleRestore.commit();
        byte[] laterImage = data(91);
        Files.write(target, laterImage);
        rejected(staleRestore::restore, "TARGET_CHANGED", false);
        targetIs(root, laterImage);

        FileInstallTransaction replacedTarget = prepared(root);
        replacedTarget.commit();
        Path fresh = root.resolve("fresh.img");
        Files.write(fresh, CANDIDATE);
        Files.move(fresh, target, StandardCopyOption.REPLACE_EXISTING);
        rejected(replacedTarget::restore, "FILE_IDENTITY_CHANGED", false);
        targetIs(root, CANDIDATE);

        FileInstallTransaction invalid = prepared(root);
        Path record = invalid.directory().resolve("record.properties");
        Properties properties = new Properties();
        try (var input = Files.newInputStream(record)) { properties.load(input); }
        properties.setProperty("candidateSha256", hash(ORIGINAL));
        try (var output = Files.newOutputStream(record)) { properties.store(output, "test corruption"); }
        rejected(invalid::commit, "TRANSACTION_CHANGED", false);
        targetIs(root, ORIGINAL);

        FileInstallTransaction unrecognized = prepared(root);
        record = unrecognized.directory().resolve("record.properties");
        try (var input = Files.newInputStream(record)) { properties.clear(); properties.load(input); }
        properties.setProperty("state", "BOOT_CONFIRMED");
        try (var output = Files.newOutputStream(record)) { properties.store(output, "test corruption"); }
        rejected(unrecognized::state, "INVALID_RECORD", false);
        targetIs(root, ORIGINAL);

        rejected(() -> FileInstallTransaction.prepare(root, source, source, hash(CANDIDATE), hash(CANDIDATE)),
                "ALIASED_INPUT", false);
        rejected(() -> FileInstallTransaction.prepare(root, source, target, "bad hash", hash(ORIGINAL)),
                "INVALID_HASH", false);
        rejected(() -> FileInstallTransaction.prepare(root, source, root.resolve("../outside-fixture.img"),
                hash(CANDIDATE), hash(ORIGINAL)), "PATH_OUTSIDE_WORKSPACE", false);
        Files.write(source, new byte[0]);
        rejected(() -> FileInstallTransaction.prepare(root, source, target, hash(new byte[0]), hash(ORIGINAL)),
                "INVALID_SIZE", false);

        concurrency(root);
        processDeath(root);
    }

    private static void concurrency(Path root) throws Exception {
        FileInstallTransaction first = prepared(root);
        FileInstallTransaction second = FileInstallTransaction.open(root, first.directory());
        CountDownLatch writing = new CountDownLatch(1), release = new CountDownLatch(1);
        var pool = Executors.newSingleThreadExecutor();
        try {
            var result = pool.submit(() -> {
                first.commit((phase, count, channel) -> {
                    if (phase.equals("AFTER_WRITE") && count == 65536) {
                        writing.countDown();
                        try { if (!release.await(5, TimeUnit.SECONDS)) throw new IOException("test deadline"); }
                        catch (InterruptedException exception) { throw new IOException(exception); }
                    }
                });
                return true;
            });
            check(writing.await(5, TimeUnit.SECONDS), "writer reached actual target write");
            rejected(second::commit, "TRANSACTION_BUSY", false);
            Process child = child("--busy", root, first.directory());
            try {
                check(child.waitFor(10, TimeUnit.SECONDS), "contending process exited");
                check(child.exitValue() == 74, "OS process lock rejected a second writer: "
                        + new String(child.getInputStream().readAllBytes()));
            } finally { if (child.isAlive()) child.destroyForcibly().waitFor(); }
            release.countDown();
            check(result.get(5, TimeUnit.SECONDS), "first writer completed");
            targetIs(root, CANDIDATE);
        } finally {
            release.countDown();
            pool.shutdownNow();
            check(pool.awaitTermination(5, TimeUnit.SECONDS), "writers released");
        }
    }

    private static void processDeath(Path root) throws Exception {
        FileInstallTransaction transaction = prepared(root);
        Process child = child("--crash", root, transaction.directory());
        try {
            check(child.waitFor(10, TimeUnit.SECONDS), "crash child exited");
            check(child.exitValue() == 73, "child terminated at write checkpoint: " + new String(child.getInputStream().readAllBytes()));
        } finally { if (child.isAlive()) child.destroyForcibly().waitFor(); }
        FileInstallTransaction recovered = FileInstallTransaction.open(root, transaction.directory());
        check(recovered.state() == FileInstallTransaction.State.WRITING, "durable in-progress stage");
        byte[] partial = Files.readAllBytes(root.resolve("target.img"));
        check(Arrays.equals(Arrays.copyOf(partial, 65536), Arrays.copyOf(CANDIDATE, 65536))
                && Arrays.equals(Arrays.copyOfRange(partial, 65536, partial.length),
                        Arrays.copyOfRange(ORIGINAL, 65536, ORIGINAL.length)), "actual interrupted target bytes");
        recovered.restore();
        targetIs(root, ORIGINAL);
        check(recovered.state() == FileInstallTransaction.State.RESTORED, "process restart recovery verified");
    }

    private static Process child(String mode, Path root, Path directory) throws IOException {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        return new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                FileInstallTransactionTest.class.getName(), mode, root.toString(), directory.toString())
                .redirectErrorStream(true).start();
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        passed++;
    }

    private static String hash(byte[] bytes) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte value : MessageDigest.getInstance("SHA-256").digest(bytes)) {
            result.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        }
        return result.toString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 3 && args[0].equals("--busy")) {
            try { FileInstallTransaction.open(Path.of(args[1]), Path.of(args[2])).commit(); }
            catch (FileInstallTransaction.Failure failure) {
                if (failure.code.equals("TRANSACTION_BUSY") && !failure.targetMayBeModified) System.exit(74);
                throw failure;
            }
            throw new AssertionError("Concurrent process was accepted");
        }
        if (args.length == 3 && args[0].equals("--crash")) {
            FileInstallTransaction.open(Path.of(args[1]), Path.of(args[2])).commit((phase, count, target) -> {
                if (phase.equals("AFTER_WRITE")) Runtime.getRuntime().halt(73);
            });
            throw new AssertionError("Crash checkpoint was not reached");
        }
        Path root = Files.createTempDirectory("maplesu-file-install-").toRealPath();
        try {
            byte[] original = new byte[150_001], candidate = new byte[original.length];
            new Random(17).nextBytes(original);
            new Random(42).nextBytes(candidate);
            Path source = root.resolve("candidate.img"), target = root.resolve("target.img");
            Files.write(source, candidate);
            Files.write(target, original);
            FileInstallTransaction transaction = FileInstallTransaction.prepare(root, source, target,
                    hash(candidate), hash(original));
            check(transaction.state() == FileInstallTransaction.State.PREPARED, "prepared state");
            check(Arrays.equals(original, Files.readAllBytes(target)), "prepare leaves target unchanged");
            check(Arrays.equals(original, Files.readAllBytes(transaction.directory().resolve("original.img"))),
                    "backup is independently readable");
            transaction.commit();
            check(transaction.state() == FileInstallTransaction.State.VERIFIED, "readback verified state");
            check(Arrays.equals(candidate, Files.readAllBytes(target)), "target contains candidate");
            check(Arrays.equals(candidate, Files.readAllBytes(source)), "source unchanged");
            FileInstallTransaction reopened = FileInstallTransaction.open(root, transaction.directory());
            reopened.restore();
            check(reopened.state() == FileInstallTransaction.State.RESTORED, "persistent restore state");
            check(Arrays.equals(original, Files.readAllBytes(target)), "original restored");
            scenarios(root);
            journalBeforeTargetWrite(root);
            journalSyncFailures(root);
            nestedTargetDirectories(root);
        } finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
        System.out.println("PASS " + passed + " file installation transaction checks");
    }
}
