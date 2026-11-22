package dev.maplesu.installer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.AccessDeniedException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Bounded regular-file transactions. Device partitions require a separate authenticated installer. */
public final class FileInstallTransaction {
    public enum State { PREPARING, PREPARED, WRITING, WRITTEN, VERIFIED, RESTORING, RESTORED, RECOVERY_REQUIRED }
    public static final long MAX_BYTES = 512L * 1024 * 1024;
    private static final Set<String> KEYS = Set.of("schema", "candidate", "target", "size",
            "candidateSha256", "originalSha256", "state");
    private static final Set<Path> ACTIVE_OPERATIONS = ConcurrentHashMap.newKeySet();
    private final Path root, directory, candidate, target, backup;
    private final Properties metadata;
    private final long size;
    private final DirectorySync directorySync;

    public static final class Failure extends IOException {
        public final String code;
        public final boolean targetMayBeModified;
        private Failure(String code, boolean modified, Throwable cause) {
            super(code, cause);
            this.code = code;
            this.targetMayBeModified = modified;
        }
    }

    // Package-private seam for real partial writes, readback faults and subprocess termination tests.
    interface Checkpoint { void reached(String phase, long written, FileChannel target) throws IOException; }

    interface DirectorySync { void sync(Path directory) throws IOException; }

    private FileInstallTransaction(Path root, Path directory, Properties metadata, DirectorySync directorySync) throws IOException {
        if (!metadata.stringPropertyNames().equals(KEYS) || !"FILE_INSTALL_V1".equals(metadata.getProperty("schema"))) {
            throw error("INVALID_RECORD");
        }
        this.root = root;
        this.directory = directory;
        this.metadata = metadata;
        this.directorySync = directorySync;
        this.candidate = within(root, root.resolve(metadata.getProperty("candidate")));
        this.target = within(root, root.resolve(metadata.getProperty("target")));
        this.backup = directory.resolve("original.img");
        try {
            size = Long.parseLong(metadata.getProperty("size"));
            State.valueOf(metadata.getProperty("state"));
        } catch (IllegalArgumentException exception) { throw error("INVALID_RECORD"); }
        if (size <= 0 || size > MAX_BYTES || candidate.startsWith(directory) || target.startsWith(directory)) {
            throw error("INVALID_RECORD");
        }
        requireHash(metadata.getProperty("candidateSha256"));
        requireHash(metadata.getProperty("originalSha256"));
    }

    public Path directory() { return directory; }

    /** True when directory force is available; this is not a physical power-loss guarantee. */
    public boolean directorySyncSupported() { return directorySync != null; }

    public State state() throws IOException { return State.valueOf(readCurrent().getProperty("state")); }

    public static FileInstallTransaction prepare(Path workspace, Path candidate, Path target,
                                                 String candidateSha256, String originalSha256) throws IOException {
        return prepare(workspace, candidate, target, candidateSha256, originalSha256,
                systemDirectorySync(workspace.toRealPath()));
    }

    static FileInstallTransaction prepare(Path workspace, Path candidate, Path target,
                                         String candidateSha256, String originalSha256, DirectorySync directorySync) throws IOException {
        cancelled();
        requireHash(candidateSha256);
        requireHash(originalSha256);
        Path root = workspace.toRealPath();
        candidate = workspacePath(workspace, root, candidate);
        target = workspacePath(workspace, root, target);
        BasicFileAttributes sourceInfo = regular(root, candidate), targetInfo = regular(root, target);
        long size = sourceInfo.size();
        if (size <= 0 || size > MAX_BYTES || targetInfo.size() != size) throw error("INVALID_SIZE");
        if (Files.isSameFile(candidate, target)) throw error("ALIASED_INPUT");
        try (FileChannel output = channel(target, true); FileLock ignored = lock(output)) {
            try (FileChannel input = channel(candidate, false)) {
                if (!candidateSha256.equals(digest(input))) throw error("CANDIDATE_CHANGED");
            }
            if (!originalSha256.equals(digest(output))) throw error("TARGET_CHANGED");
            Properties record = new Properties();
            record.setProperty("schema", "FILE_INSTALL_V1");
            record.setProperty("candidate", root.relativize(candidate).toString());
            record.setProperty("target", root.relativize(target).toString());
            record.setProperty("size", Long.toString(size));
            record.setProperty("candidateSha256", candidateSha256);
            record.setProperty("originalSha256", originalSha256);
            record.setProperty("state", State.PREPARING.name());
            Path directory = Files.createTempDirectory(root, "transaction-");
            FileInstallTransaction transaction = new FileInstallTransaction(root, directory, record, directorySync);
            transaction.syncParentDirectories(target);
            transaction.createIdentity(candidate);
            transaction.createIdentity(target);
            transaction.checkIdentity(candidate);
            transaction.checkIdentity(target);
            transaction.checkFile(candidate, candidateSha256, "CANDIDATE_CHANGED");
            if (!originalSha256.equals(digest(output))) throw error("TARGET_CHANGED");
            transaction.persist(State.PREPARING);
            try (FileChannel copy = FileChannel.open(transaction.backup, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                copy(output, copy, size, null);
                copy.force(true);
            }
            transaction.createIdentity(transaction.backup);
            transaction.checkFile(transaction.backup, originalSha256, "BACKUP_MISMATCH");
            if (!originalSha256.equals(digest(output))) throw error("TARGET_CHANGED");
            transaction.checkIdentity(target);
            transaction.checkFile(candidate, candidateSha256, "CANDIDATE_CHANGED");
            transaction.checkIdentity(candidate);
            transaction.persist(State.PREPARED);
            return transaction;
        }
    }

    public static FileInstallTransaction open(Path workspace, Path transactionDirectory) throws IOException {
        return open(workspace, transactionDirectory, systemDirectorySync(workspace.toRealPath()));
    }

    static FileInstallTransaction open(Path workspace, Path transactionDirectory, DirectorySync directorySync) throws IOException {
        Path root = workspace.toRealPath(), directory = workspacePath(workspace, root, transactionDirectory);
        checkPath(root, directory, true);
        return new FileInstallTransaction(root, directory, read(root, directory.resolve("record.properties")), directorySync);
    }

    public void commit() throws IOException { commit(null); }

    void commit(Checkpoint checkpoint) throws IOException { execute(false, checkpoint); }

    public void restore() throws IOException { execute(true, null); }

    private void execute(boolean restoring, Checkpoint checkpoint) throws IOException {
        cancelled();
        checkPath(root, directory, true);
        Path lockPath = directory.resolve("operation.lock");
        if (Files.exists(lockPath, LinkOption.NOFOLLOW_LINKS)) regular(root, lockPath);
        if (!ACTIVE_OPERATIONS.add(lockPath)) throw error("TRANSACTION_BUSY");
        try (FileChannel operation = FileChannel.open(lockPath, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS); FileLock ignored = lock(operation)) {
            State state = state();
            if ((!restoring && state != State.PREPARED) || (restoring && state == State.PREPARING)) {
                throw error("INVALID_STATE");
            }
            checkIdentity(target);
            checkFile(backup, metadata.getProperty("originalSha256"), "BACKUP_MISMATCH");
            if (Files.isSameFile(backup, target)) throw error("ALIASED_INPUT");
            Path source = restoring ? backup : candidate;
            String expected = metadata.getProperty(restoring ? "originalSha256" : "candidateSha256");
            if (!restoring) {
                checkIdentity(candidate);
                if (Files.isSameFile(candidate, target) || Files.isSameFile(candidate, backup)) throw error("ALIASED_INPUT");
                checkFile(candidate, expected, "CANDIDATE_CHANGED");
            }
            try (FileChannel input = channel(source, false); FileChannel output = channel(target, true);
                 FileLock targetLock = lock(output)) {
                checkIdentity(target);
                if (!restoring) {
                    checkIdentity(candidate);
                    if (!metadata.getProperty("originalSha256").equals(digest(output))) throw error("TARGET_CHANGED");
                } else if (state == State.VERIFIED || state == State.WRITTEN
                        || state == State.PREPARED || state == State.RESTORED) {
                    String currentHash = metadata.getProperty(state == State.VERIFIED || state == State.WRITTEN
                            ? "candidateSha256" : "originalSha256");
                    if (!currentHash.equals(digest(output))) throw error("TARGET_CHANGED");
                }
                if (input.size() != size || !expected.equals(digest(input))) throw error("SOURCE_CHANGED");
                persist(restoring ? State.RESTORING : State.WRITING);
                try {
                    copy(input, output, size, checkpoint);
                    cancelled();
                    output.force(true);
                    if (!restoring) persist(State.WRITTEN);
                    if (checkpoint != null) checkpoint.reached("BEFORE_READBACK", size, output);
                    if (!expected.equals(digest(output))) throw error("READBACK_MISMATCH");
                    checkIdentity(target);
                    checkFile(backup, metadata.getProperty("originalSha256"), "BACKUP_MISMATCH");
                    persist(restoring ? State.RESTORED : State.VERIFIED);
                } catch (IOException exception) {
                    boolean interrupted = Thread.interrupted();
                    try { persist(State.RECOVERY_REQUIRED); }
                    catch (IOException journalFailure) { exception.addSuppressed(journalFailure); }
                    finally { if (interrupted) Thread.currentThread().interrupt(); }
                    String code = exception instanceof Failure ? ((Failure) exception).code : "WRITE_FAILED";
                    throw new Failure(code, true, exception);
                }
            }
        } finally { ACTIVE_OPERATIONS.remove(lockPath); }
    }

    private Properties readCurrent() throws IOException {
        Properties current = read(root, directory.resolve("record.properties"));
        if (!current.stringPropertyNames().equals(KEYS)) throw error("INVALID_RECORD");
        for (String field : KEYS) {
            if (!field.equals("state") && !metadata.getProperty(field).equals(current.getProperty(field))) {
                throw error("TRANSACTION_CHANGED");
            }
        }
        try { State.valueOf(current.getProperty("state")); }
        catch (IllegalArgumentException exception) { throw error("INVALID_RECORD"); }
        return current;
    }

    private void persist(State state) throws IOException {
        Properties current = new Properties();
        current.putAll(metadata);
        current.setProperty("state", state.name());
        Path pending = Files.createTempFile(directory, "record-", ".pending");
        try {
            try (FileChannel file = channel(pending, true)) {
                current.store(Channels.newOutputStream(file), "MapleSU regular-file transaction");
                file.force(true);
            }
            Files.move(pending, directory.resolve("record.properties"), StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            syncDirectory(directory);
        } catch (IOException exception) {
            throw new Failure("JOURNAL_FAILED", false, exception);
        } finally { Files.deleteIfExists(pending); }
    }

    private void syncDirectory(Path path) throws IOException {
        if (directorySync != null) directorySync.sync(path);
    }

    private void syncParentDirectories(Path path) throws IOException {
        for (Path parent = path.getParent(); parent.startsWith(root); parent = parent.getParent()) {
            syncDirectory(parent);
            if (parent.equals(root)) break;
        }
    }

    private static DirectorySync systemDirectorySync(Path root) throws IOException {
        try {
            forceDirectory(root);
            return FileInstallTransaction::forceDirectory;
        } catch (UnsupportedOperationException exception) {
            return null;
        } catch (AccessDeniedException exception) {
            // The standard Windows provider does not open directory handles through FileChannel.
            if (System.getProperty("os.name", "").startsWith("Windows")) return null;
            throw exception;
        }
    }

    private static void forceDirectory(Path directory) throws IOException {
        try (FileChannel file = FileChannel.open(directory, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            file.force(true);
        }
    }

    private static Properties read(Path root, Path path) throws IOException {
        regular(root, path);
        if (Files.size(path) > 16 * 1024) throw error("INVALID_RECORD");
        Properties result = new Properties();
        try (InputStream input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) { result.load(input); }
        catch (IllegalArgumentException exception) { throw error("INVALID_RECORD"); }
        return result;
    }

    private Path anchor(Path path) {
        return directory.resolve(path.equals(candidate) ? "candidate.identity" : path.equals(target) ? "target.identity" : "backup.identity");
    }

    private void checkIdentity(Path path) throws IOException {
        BasicFileAttributes info = regular(root, path);
        Path anchor = anchor(path);
        regular(root, anchor);
        if (info.size() != size) throw error("FILE_IDENTITY_CHANGED");
        if (Files.isSameFile(path, anchor)) return;
        String identity = unixIdentity(path);
        if (identity == null || Files.size(anchor) > 128
                || !identity.equals(new String(Files.readAllBytes(anchor), StandardCharsets.US_ASCII))) {
            throw error("FILE_IDENTITY_CHANGED");
        }
    }

    private void createIdentity(Path path) throws IOException {
        String identity = unixIdentity(path);
        if (identity == null) {
            Files.createLink(anchor(path), path);
        } else {
            // Android app domains may read stat metadata while denying hard-link creation.
            try (FileChannel file = FileChannel.open(anchor(path), StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                ByteBuffer bytes = ByteBuffer.wrap(identity.getBytes(StandardCharsets.US_ASCII));
                while (bytes.hasRemaining()) file.write(bytes);
                file.force(true);
            }
        }
    }

    private static String unixIdentity(Path path) throws IOException {
        try {
            var attributes = Files.readAttributes(path, "unix:dev,ino", LinkOption.NOFOLLOW_LINKS);
            return "UNIX_FILE_ID_V1:" + attributes.get("dev") + ":" + attributes.get("ino");
        } catch (UnsupportedOperationException exception) { return null; }
    }

    private void checkFile(Path path, String expectedHash, String failure) throws IOException {
        checkIdentity(path);
        try (FileChannel file = channel(path, false)) {
            if (!expectedHash.equals(digest(file))) throw error(failure);
        }
        checkIdentity(path);
    }

    private static Path within(Path root, Path path) throws IOException {
        Path normalized = path.toAbsolutePath().normalize();
        if (normalized.equals(root) || !normalized.startsWith(root)) throw error("PATH_OUTSIDE_WORKSPACE");
        return normalized;
    }

    private static Path workspacePath(Path workspace, Path root, Path path) throws IOException {
        Path suppliedRoot = workspace.toAbsolutePath().normalize(), suppliedPath = path.toAbsolutePath().normalize();
        if (suppliedPath.startsWith(suppliedRoot)) suppliedPath = root.resolve(suppliedRoot.relativize(suppliedPath));
        return within(root, suppliedPath);
    }

    private static BasicFileAttributes regular(Path root, Path path) throws IOException {
        return checkPath(root, path, false);
    }

    private static BasicFileAttributes checkPath(Path root, Path path, boolean directory) throws IOException {
        Path current = root;
        BasicFileAttributes result = null;
        for (Path part : root.relativize(within(root, path))) {
            current = current.resolve(part);
            result = Files.readAttributes(current, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (result.isSymbolicLink() || (!current.equals(path) && !result.isDirectory())) throw error("INVALID_FILE_TYPE");
        }
        if (directory ? !result.isDirectory() : !result.isRegularFile()) throw error("INVALID_FILE_TYPE");
        return result;
    }

    private static FileChannel channel(Path path, boolean write) throws IOException {
        return write ? FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)
                : FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
    }

    private static FileLock lock(FileChannel channel) throws IOException {
        try {
            FileLock lock = channel.tryLock();
            if (lock != null) return lock;
        } catch (OverlappingFileLockException exception) { /* Report contention consistently across processes. */ }
        throw error("TRANSACTION_BUSY");
    }

    private static void copy(FileChannel source, FileChannel target, long size, Checkpoint checkpoint) throws IOException {
        cancelled();
        source.position(0);
        target.position(0);
        ByteBuffer bytes = ByteBuffer.allocate(64 * 1024);
        long written = 0;
        while (written < size) {
            cancelled();
            bytes.clear().limit((int) Math.min(bytes.capacity(), size - written));
            int count = source.read(bytes);
            if (count < 0) throw error("SOURCE_CHANGED");
            bytes.flip();
            while (bytes.hasRemaining()) { cancelled(); target.write(bytes); }
            written += count;
            if (checkpoint != null) checkpoint.reached("AFTER_WRITE", written, target);
        }
    }

    private static String digest(FileChannel source) throws IOException {
        cancelled();
        final MessageDigest digest;
        try { digest = MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException exception) { throw new IllegalStateException(exception); }
        source.position(0);
        ByteBuffer bytes = ByteBuffer.allocate(64 * 1024);
        while (true) {
            cancelled();
            int count = source.read(bytes);
            if (count < 0) break;
            bytes.flip();
            digest.update(bytes);
            bytes.clear();
        }
        StringBuilder result = new StringBuilder(64);
        for (byte value : digest.digest()) {
            result.append(Character.forDigit((value >>> 4) & 15, 16)).append(Character.forDigit(value & 15, 16));
        }
        return result.toString();
    }

    private static void requireHash(String hash) throws IOException {
        if (hash == null || !hash.matches("[0-9a-f]{64}")) throw error("INVALID_HASH");
    }

    private static void cancelled() throws IOException {
        if (Thread.currentThread().isInterrupted()) throw error("CANCELLED");
    }

    private static Failure error(String code) { return new Failure(code, false, null); }
}
