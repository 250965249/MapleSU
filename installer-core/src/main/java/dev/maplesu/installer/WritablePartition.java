package dev.maplesu.installer;

import java.io.Closeable;
import java.io.IOException;
import java.util.Set;

/**
 * One authenticated, re-readable partition. Implementations own all platform work: opening
 * held {@code O_RDONLY}/{@code O_WRONLY} descriptors with {@code O_CLOEXEC|O_NOFOLLOW},
 * {@code fstat} identity checks (block/rdev/ino/size),
 * {@code lseek} length, canonical path and runtime property revalidation.
 *
 * <p>Red line 4: this interface exposes no raw write call. Partition bytes are only written by
 * {@link BlockDeviceTransaction#commit}/{@link BlockDeviceTransaction#restore} through the
 * {@link BlockDeviceTransaction.Device} returned by {@link #open()}; the multi-partition
 * transaction is an orchestrator, never a second writer.</p>
 */
public interface WritablePartition extends Closeable {
    /** Red line 2 encoded as a constant: only these partition names may ever be written. */
    Set<String> ALLOWED = Set.of("boot", "init_boot");
    /** Read-only observation of {@code vbmeta} is allowed; writing it is never allowed. */
    String FORBIDDEN = "vbmeta";
    /** Tail probe window; covers v4 signature (16 KiB) and GKI double certificate (16 KiB). */
    int TAIL_PROBE_BYTES = 64 * 1024;

    /** Exactly {@code "boot"} or {@code "init_boot"}. */
    String name();

    long size();

    /** Whole-partition SHA-256 (never a padded short-file digest). */
    String sha256() throws IOException;

    /** SHA-256 of the last {@code min(size, TAIL_PROBE_BYTES)} bytes (02 §4.5.1). */
    String tailSha256() throws IOException;

    /** A new, already revalidated device handle; the caller owns and closes it. */
    BlockDeviceTransaction.Device open() throws IOException;

    /**
     * Last observed read-only flag (S0-22 {@code blockDeviceReadOnly}). S0/4c must clear it before a
     * write; the transaction itself only records it, because host fakes cannot flip block flags.
     */
    default boolean readOnly() { return false; }

    /** Partitions are not necessarily open resources; implementations that are must override. */
    @Override
    default void close() throws IOException {}
}
