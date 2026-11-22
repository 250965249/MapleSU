package dev.maplesu.installer;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/** Streaming partition transaction. The caller authenticates, holds and revalidates the device. */
public final class BlockDeviceTransaction {
    private static final int BUFFER_SIZE = 64 * 1024;
    public static final long MAX_BYTES = 512L * 1024 * 1024;

    public interface Device extends Closeable {
        long size();
        void revalidate() throws IOException;
        int read(long offset, byte[] buffer, int length) throws IOException;
        int write(long offset, byte[] buffer, int start, int length) throws IOException;
        void sync() throws IOException;
    }

    /** Forward WRITING is a durable barrier; failed recovery logging does not strand PRE recovery. */
    public interface Journal { void record(String state, String error) throws IOException; }

    public static final class Result {
        public final String state;
        public final String error;
        public final boolean rebootRequired;
        private Result(String state, String error, boolean rebootRequired) {
            this.state = state;
            this.error = error;
            this.rebootRequired = rebootRequired;
        }
    }

    private BlockDeviceTransaction() {}

    public static Result commit(Device device, Path candidate, String candidateSha256,
                                Path recovery, String originalSha256, Journal journal) throws IOException {
        requireHash(candidateSha256);
        requireHash(originalSha256);
        long size = device.size();
        requireSize(size);
        long candidateSize = Files.size(candidate);
        if (candidateSize <= 0 || candidateSize > size) throw failure("INSTALLER_CANDIDATE_SIZE_INVALID");
        String expected = verifyFile(candidate, candidateSize, size, candidateSha256);
        verifyFile(recovery, size, size, originalSha256);
        device.revalidate();
        if (!digest(device).equals(originalSha256)) throw failure("INSTALLER_PARTITION_CHANGED");
        device.revalidate();
        // A journal failure here leaves the partition untouched.
        journal.record("WRITING", "");
        Exception[] journalFailure = {null};
        Journal recoveryJournal = (state, error) -> recordRecovery(journal, journalFailure, state, error);
        try {
            copy(device, candidate, candidateSize, size, candidateSha256, true);
            device.sync();
            device.revalidate();
            if (!digest(device).equals(expected)) throw failure("INSTALLER_READBACK_MISMATCH");
            device.revalidate();
            try { journal.record("REBOOT_REQUIRED", ""); } catch (IOException | RuntimeException error) {
                journalFailure[0] = error;
                throw error;
            }
            return new Result("REBOOT_REQUIRED", "", true);
        } catch (IOException | RuntimeException error) {
            String code = code(error);
            // Cancellation does not abandon a partially written partition. Restore with the held FD.
            boolean interrupted = Thread.interrupted();
            try {
                recoveryJournal.record("RECOVERY_REQUIRED", code);
                restore(device, recovery, originalSha256, recoveryJournal, code);
                return new Result(journalFailure[0] == null ? "RESTORED" : "RECOVERY_REQUIRED", code, false);
            } catch (IOException | RuntimeException restoreError) {
                if (restoreError != error) error.addSuppressed(restoreError);
                recoveryJournal.record("RECOVERY_REQUIRED", code);
                return new Result("RECOVERY_REQUIRED", code, false);
            } finally {
                if (journalFailure[0] != null && journalFailure[0] != error)
                    error.addSuppressed(journalFailure[0]);
                if (interrupted) Thread.currentThread().interrupt();
            }
        }
    }

    public static Result restore(Device device, Path recovery, String originalSha256,
                                 Journal journal) throws IOException {
        Exception[] journalFailure = {null};
        boolean interrupted = Thread.interrupted();
        try {
            restore(device, recovery, originalSha256,
                    (state, error) -> recordRecovery(journal, journalFailure, state, error), "INSTALLER_RECOVERED");
            if (journalFailure[0] instanceof IOException error) throw error;
            if (journalFailure[0] instanceof RuntimeException error) throw error;
            return new Result("RESTORED", "INSTALLER_RECOVERED", false);
        } catch (IOException | RuntimeException error) {
            if (journalFailure[0] != null && journalFailure[0] != error)
                error.addSuppressed(journalFailure[0]);
            throw error;
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    private static void recordRecovery(Journal journal, Exception[] failure, String state, String error) {
        if (failure[0] != null) return; // A failed append may have left a partial line; do not append again.
        try { journal.record(state, error); } catch (IOException | RuntimeException journalError) {
            failure[0] = journalError;
        }
    }

    private static void restore(Device device, Path recovery, String originalSha256,
                                Journal journal, String error) throws IOException {
        requireHash(originalSha256);
        long size = device.size();
        requireSize(size);
        verifyFile(recovery, size, size, originalSha256);
        device.revalidate();
        journal.record("RESTORING", error);
        // A denied first write may leave PRE intact. Verify it rather than issuing another
        // denied write and falsely reporting an unrecoverable, partially flashed partition.
        if (!digest(device).equals(originalSha256)) copy(device, recovery, size, size, originalSha256, false);
        device.sync();
        device.revalidate();
        if (!digest(device).equals(originalSha256)) throw failure("INSTALLER_RECOVERY_READBACK_MISMATCH");
        device.revalidate();
        journal.record("RESTORED", error);
    }

    private static void copy(Device device, Path image, long imageSize, long size,
                             String expected, boolean cancellable) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        MessageDigest digest = sha256();
        long offset = 0;
        try (InputStream input = Files.newInputStream(image)) {
            while (offset < imageSize) {
                if (cancellable && Thread.currentThread().isInterrupted()) throw failure("INSTALLER_CANCELLED");
                int requested = (int) Math.min(buffer.length, imageSize - offset);
                int count = input.read(buffer, 0, requested);
                if (count < 0) throw failure("INSTALLER_IMAGE_CHANGED");
                if (count == 0) throw failure("INSTALLER_IMAGE_READ_FAILED");
                digest.update(buffer, 0, count);
                write(device, offset, buffer, count);
                offset += count;
            }
            if (input.read() != -1 || !hex(digest.digest()).equals(expected))
                throw failure("INSTALLER_IMAGE_CHANGED");
        }
        // Only the known end of a compact candidate may be extended with zero bytes.
        Arrays.fill(buffer, (byte) 0);
        while (offset < size) {
            if (cancellable && Thread.currentThread().isInterrupted()) throw failure("INSTALLER_CANCELLED");
            int count = (int) Math.min(buffer.length, size - offset);
            write(device, offset, buffer, count);
            offset += count;
        }
    }

    private static void write(Device device, long offset, byte[] buffer, int count) throws IOException {
        int written = 0;
        while (written < count) {
            int bytes = device.write(offset + written, buffer, written, count - written);
            if (bytes <= 0 || bytes > count - written) throw failure("INSTALLER_DEVICE_WRITE_FAILED");
            written += bytes;
        }
    }

    public static String digest(Device device) throws IOException {
        MessageDigest digest = sha256();
        byte[] buffer = new byte[BUFFER_SIZE];
        long offset = 0;
        while (offset < device.size()) {
            int requested = (int) Math.min(buffer.length, device.size() - offset);
            int count = device.read(offset, buffer, requested);
            if (count <= 0 || count > requested) throw failure("INSTALLER_DEVICE_READ_FAILED");
            digest.update(buffer, 0, count);
            offset += count;
        }
        return hex(digest.digest());
    }

    public static String paddedDigest(Path image, long size) throws IOException {
        requireSize(size);
        long imageSize = Files.size(image);
        if (imageSize <= 0 || imageSize > size) throw failure("INSTALLER_CANDIDATE_SIZE_INVALID");
        return paddedDigest(image, imageSize, size, null);
    }

    private static String paddedDigest(Path image, long imageSize, long size, String expected) throws IOException {
        MessageDigest digest = sha256();
        MessageDigest content = expected == null ? null : sha256();
        byte[] buffer = new byte[BUFFER_SIZE];
        long total = 0;
        try (InputStream input = Files.newInputStream(image)) {
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (count == 0 || total + count > imageSize) throw failure("INSTALLER_IMAGE_CHANGED");
                digest.update(buffer, 0, count);
                if (content != null) content.update(buffer, 0, count);
                total += count;
            }
        }
        if (total != imageSize) throw failure("INSTALLER_IMAGE_CHANGED");
        if (content != null && !hex(content.digest()).equals(expected)) throw failure("INSTALLER_IMAGE_CHANGED");
        Arrays.fill(buffer, (byte) 0);
        while (total < size) {
            int count = (int) Math.min(buffer.length, size - total);
            digest.update(buffer, 0, count);
            total += count;
        }
        return hex(digest.digest());
    }

    private static String verifyFile(Path file, long imageSize, long size, String expected) throws IOException {
        requireHash(expected);
        if (!Files.isRegularFile(file, java.nio.file.LinkOption.NOFOLLOW_LINKS) || Files.size(file) != imageSize)
            throw failure("INSTALLER_IMAGE_CHANGED");
        return paddedDigest(file, imageSize, size, expected);
    }

    private static void requireSize(long size) throws IOException {
        if (size <= 0 || size > MAX_BYTES) throw failure("INSTALLER_DEVICE_SIZE_INVALID");
    }

    private static void requireHash(String hash) {
        if (hash == null || !hash.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("INSTALLER_HASH_INVALID");
    }

    private static IOException failure(String code) { return new IOException(code); }
    private static String code(Exception error) {
        String message = error.getMessage();
        return message != null && message.matches("INSTALLER_[A-Z_]+") ? message : "INSTALLER_WRITE_FAILED";
    }
    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }
    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(64);
        for (byte value : bytes) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }
}
