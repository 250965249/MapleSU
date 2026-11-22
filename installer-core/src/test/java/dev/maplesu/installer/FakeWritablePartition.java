package dev.maplesu.installer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/**
 * File-backed fake partition with deterministic fault injection. The bytes live in a real file so a
 * "reconstructed" instance after a simulated power loss observes exactly what the previous instance
 * wrote; no hardware or real power-loss behaviour is claimed.
 */
final class FakeWritablePartition implements WritablePartition {
    private final String name;
    private final Path file;
    private final long size;

    /** Max bytes returned per read; default unlimited. */
    int shortRead = Integer.MAX_VALUE;
    /** Max bytes accepted per write; default unlimited. */
    int shortWrite = Integer.MAX_VALUE;
    /** 1-based write call that fails (only that call unless {@link #failRestore}). */
    int failWriteAt = -1;
    /** Fail every write at/after {@link #failWriteAt} (rollback also fails). */
    boolean failRestore;
    /** 1-based sync call that fails (only that call). */
    int failSyncAt = -1;
    /** Flip one byte after this many syncs (decrementing), making the BDT readback fail once. */
    int corruptAfterSync;
    /** Throw an {@link AssertionError} after this many successful writes: simulated process death. */
    int crashAfterWrites = -1;
    /** Device revalidate refuses, simulating an identity change. */
    boolean badIdentity;
    /** Reported read-only flag (S0-22); the orchestrator only records it. */
    boolean readOnly;

    int writes;
    int syncs;
    int opens;
    int reads;

    private FakeWritablePartition(String name, Path file, long size) {
        this.name = name;
        this.file = file;
        this.size = size;
    }

    /** Fresh file-backed partition seeded with {@code initial}. */
    static FakeWritablePartition create(String name, byte[] initial) throws IOException {
        Path file = Files.createTempFile("maplesu-fake-" + name + "-", ".bin");
        Files.write(file, initial);
        return new FakeWritablePartition(name, file, initial.length);
    }

    /** Reopens an existing backing file, as recovery does after a process death. */
    static FakeWritablePartition reopen(String name, Path file) throws IOException {
        return new FakeWritablePartition(name, file, Files.size(file));
    }

    Path file() { return file; }

    byte[] bytes() throws IOException { return Files.readAllBytes(file); }

    /** Test-only third-party mutation: bypasses the device abstraction on purpose. */
    void externalWrite(byte[] replacement) throws IOException {
        if (replacement.length != size) throw new IllegalArgumentException("size");
        Files.write(file, replacement);
    }

    @Override public String name() { return name; }
    @Override public long size() { return size; }
    @Override public boolean readOnly() { return readOnly; }

    @Override public String sha256() throws IOException { return SwitchHashes.sha256(file); }
    @Override public String tailSha256() throws IOException { return SwitchHashes.tailSha256(file); }

    @Override
    public BlockDeviceTransaction.Device open() throws IOException {
        opens++;
        FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE);
        return new DeviceImpl(channel);
    }

    @Override public void close() {}

    private final class DeviceImpl implements BlockDeviceTransaction.Device {
        private final FileChannel channel;

        DeviceImpl(FileChannel channel) { this.channel = channel; }

        @Override public long size() { return size; }

        @Override
        public void revalidate() throws IOException {
            if (badIdentity) throw new IOException("INSTALLER_PARTITION_CHANGED");
        }

        @Override
        public int read(long offset, byte[] buffer, int length) throws IOException {
            reads++;
            int count = (int) Math.min(Math.min(length, shortRead), size - offset);
            if (count <= 0) return -1;
            ByteBuffer target = ByteBuffer.wrap(buffer, 0, count);
            long position = offset;
            while (target.hasRemaining()) {
                int got = channel.read(target, position);
                if (got < 0) throw new IOException("INSTALLER_DEVICE_READ_FAILED");
                if (got == 0) break;
                position += got;
            }
            return count - target.remaining();
        }

        @Override
        public int write(long offset, byte[] buffer, int start, int length) throws IOException {
            writes++;
            if (crashAfterWrites >= 0 && writes > crashAfterWrites) {
                throw new AssertionError("simulated power loss after " + crashAfterWrites + " writes");
            }
            if (failWriteAt > 0 && writes >= failWriteAt && (failRestore || writes == failWriteAt)) {
                throw new IOException("INSTALLER_DEVICE_WRITE_FAILED");
            }
            int count = (int) Math.min(Math.min(length, shortWrite), size - offset);
            if (count <= 0) return 0;
            ByteBuffer source = ByteBuffer.wrap(buffer, start, count);
            long position = offset;
            while (source.hasRemaining()) {
                int wrote = channel.write(source, position);
                if (wrote <= 0) throw new IOException("INSTALLER_DEVICE_WRITE_FAILED");
                position += wrote;
            }
            return count;
        }

        @Override
        public void sync() throws IOException {
            syncs++;
            if (failSyncAt > 0 && syncs == failSyncAt) {
                throw new IOException("INSTALLER_DEVICE_SYNC_FAILED");
            }
            channel.force(true);
            if (corruptAfterSync > 0) {
                corruptAfterSync--;
                byte[] current = Files.readAllBytes(file);
                current[0] ^= 1;
                Files.write(file, current);
            }
        }

        @Override public void close() throws IOException { channel.close(); }
    }

    /** Convenience assertion helper used by the fixtures. */
    static boolean same(byte[] expected, byte[] actual) {
        return Arrays.equals(expected, actual);
    }
}
