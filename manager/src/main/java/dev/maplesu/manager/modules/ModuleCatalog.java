package dev.maplesu.manager.modules;

import dev.maplesu.manager.ModuleArchiveInspector;
import dev.maplesu.manager.ModuleArchiveInspector.ModuleType;
import dev.maplesu.manager.ModuleArchiveInspector.Report;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

/** App-private package storage. Enabled is a saved preference, never proof of module execution. */
public final class ModuleCatalog {
    private static final long MAX_RECORD_BYTES = 128 * 1024;
    private final Path root, staged, revisions, installed;

    public static final class Failure extends IOException {
        public final String code;
        private Failure(String code) { super(code); this.code = code; }
    }

    public static final class Staged {
        public final String token;
        public final Report report;
        private Staged(String token, Report report) { this.token = token; this.report = report; }
    }

    public static final class Entry {
        public final Report report;
        public final boolean enabled;
        public final long installedAtMillis;
        public final File archive;
        private final String revision;
        private Entry(Report report, boolean enabled, long time, Path archive, String revision) {
            this.report = report; this.enabled = enabled; installedAtMillis = time;
            this.archive = archive.toFile(); this.revision = revision;
        }

        /** Identifies this committed installation, including repeated installs of the same ZIP. */
        public String getRevisionToken() { return revision; }
    }

    /** The caller supplies an app-private directory, outside any executable module search path. */
    public ModuleCatalog(File directory) throws IOException {
        Path requested = directory.toPath().toAbsolutePath().normalize();
        if (Files.exists(requested, LinkOption.NOFOLLOW_LINKS)) requireDirectory(requested);
        else {
            List<Path> missing = new ArrayList<>();
            Path ancestor = requested;
            while (ancestor != null && !Files.exists(ancestor, LinkOption.NOFOLLOW_LINKS)) {
                missing.add(ancestor);
                ancestor = ancestor.getParent();
            }
            if (ancestor == null) throw new NoSuchFileException(requested.toString());
            Path existing = ancestor.toRealPath();
            syncDirectory(existing);
            if (existing.getParent() != null) syncDirectory(existing.getParent());
            for (int index = missing.size() - 1; index >= 0; index--) {
                Path created = missing.get(index);
                try { Files.createDirectory(created); }
                catch (java.nio.file.FileAlreadyExistsException ignored) { /* Another constructor won. */ }
                syncDirectory(created);
                syncDirectory(created.getParent().toRealPath());
            }
        }
        root = requested.toRealPath();
        staged = root.resolve("staged"); revisions = root.resolve("revisions");
        installed = root.resolve("installed");
        directories();
    }

    /** Only bytes matching the previously confirmed archive type and SHA-256 can be staged. */
    public Staged stage(File source, ModuleType confirmedType, String confirmedSha256) throws IOException {
        if (confirmedType == null || confirmedSha256 == null || !confirmedSha256.matches("[0-9a-f]{64}")) {
            throw new Failure("INVALID_MODULE_CONFIRMATION");
        }
        return locked(() -> {
            requireArchive(source.toPath());
            Report original = ModuleArchiveInspector.inspect(source);
            confirm(original, confirmedType, confirmedSha256);
            syncDirectory(root);
            if (root.getParent() != null) syncDirectory(root.getParent());
            String token = token();
            Path temporary = staged.resolve(".copy-" + token), destination = staged.resolve(token);
            Files.createDirectory(temporary);
            boolean published = false;
            IOException failure = null;
            try {
                Path archive = temporary.resolve("archive.zip");
                copyArchive(source.toPath(), archive);
                Report copied = ModuleArchiveInspector.inspect(archive.toFile());
                confirm(copied, confirmedType, confirmedSha256);
                if (!copied.id.equals(original.id)) throw new Failure("MODULE_ID_CHANGED");
                requireArchive(source.toPath());
                ModuleArchiveInspector.verifyUnchanged(source, original);
                Properties receipt = schema();
                receipt.setProperty("type", copied.type.name());
                receipt.setProperty("id", copied.id);
                receipt.setProperty("sha256", copied.sha256);
                try {
                    String previous = readRevision(recordPath(copied.type, copied.id));
                    receipt.setProperty("previousRevisionKnown", "true");
                    receipt.setProperty("previousRevision", previous == null ? "" : previous);
                } catch (IOException ignored) { /* Recovery qualification must not block native installation. */ }
                writeNew(temporary.resolve("confirmation.properties"), receipt);
                syncDirectory(temporary);
                if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) throw new Failure("STAGED_MODULE_EXISTS");
                Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE);
                published = true;
                syncDirectory(staged);
                return new Staged(token, copied);
            } catch (IOException error) {
                failure = error;
                throw error;
            } finally {
                if (!published) {
                    try { removeRevision(temporary); }
                    catch (IOException cleanup) {
                        if (failure == null) throw cleanup;
                        failure.addSuppressed(cleanup);
                    }
                }
            }
        });
    }

    /** Atomically publishes a stored package record. No installer script or native code is run. */
    public Entry commit(String stagedToken) throws IOException {
        checkedToken(stagedToken);
        return locked(() -> {
            Path source = staged.resolve(stagedToken);
            Report report = inspectRevision(source);
            Path record = recordPath(report.type, report.id);
            Entry previous = Files.exists(record, LinkOption.NOFOLLOW_LINKS) ? readEntry(record) : null;
            return publishRevision(stagedToken, source, record, previous);
        });
    }

    /** Completes only the local record for a separately confirmed Host commit. */
    public boolean recoverCommitted(String stagedToken, ModuleType type, String id,
                                    String confirmedSha256) throws IOException {
        checkedToken(stagedToken);
        if (confirmedSha256 == null || !confirmedSha256.matches("[0-9a-f]{64}")) {
            throw new Failure("INVALID_MODULE_CONFIRMATION");
        }
        return locked(() -> {
            Path record = recordPath(type, id);
            String current = readRevision(record);
            Path destination = revisions.resolve(stagedToken);
            if (stagedToken.equals(current)) {
                Entry published = readEntry(record);
                confirm(published.report, type, confirmedSha256);
                if (!id.equals(published.report.id)) throw new Failure("MODULE_RECORD_ID_MISMATCH");
                syncDirectory(destination);
                syncDirectory(root);
                syncDirectory(staged);
                syncDirectory(revisions);
                syncDirectory(installed);
                return true;
            }
            Path source = staged.resolve(stagedToken);
            if (!Files.exists(source, LinkOption.NOFOLLOW_LINKS)) source = destination;
            Report report = inspectRevision(source);
            confirm(report, type, confirmedSha256);
            if (!id.equals(report.id)) throw new Failure("MODULE_RECORD_ID_MISMATCH");
            Properties confirmation = readProperties(source.resolve("confirmation.properties"));
            if (!"true".equals(confirmation.getProperty("previousRevisionKnown")) ||
                    !confirmation.containsKey("previousRevision")) return false;
            String previous = confirmation.getProperty("previousRevision");
            if (!previous.isEmpty()) checkedToken(previous);
            if (current == null ? !previous.isEmpty() : !current.equals(previous)) return false;
            Entry prior = current == null ? null : readEntry(record);
            publishRevision(stagedToken, source, record, prior);
            return true;
        });
    }

    private Entry publishRevision(String stagedToken, Path source, Path record, Entry previous) throws IOException {
        Path destination = revisions.resolve(stagedToken);
        boolean moved = !source.equals(destination);
        if (moved && Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
            throw new Failure("CATALOG_REVISION_EXISTS");
        }
        syncDirectory(root);
        if (moved) Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE);
        Properties pointer = pointer(stagedToken, previous == null || previous.enabled,
                                     System.currentTimeMillis());
        boolean[] pointerPublished = { false };
        try {
            syncDirectory(staged);
            syncDirectory(revisions);
            replaceRecord(record, pointer, Files::deleteIfExists, pointerPublished);
        } catch (IOException error) {
            // A visible pointer keeps its revision even when namespace sync fails.
            if (moved && !pointerPublished[0]) {
                try { Files.move(destination, source, StandardCopyOption.ATOMIC_MOVE); }
                catch (IOException rollback) { error.addSuppressed(rollback); }
                for (Path directory : List.of(revisions, staged)) {
                    try { syncDirectory(directory); }
                    catch (IOException rollback) { error.addSuppressed(rollback); }
                }
            }
            throw error;
        }
        Entry result = readEntry(record);
        if (previous != null) removeRevision(revisions.resolve(previous.revision));
        return result;
    }

    public void discard(String stagedToken) throws IOException {
        checkedToken(stagedToken);
        locked(() -> { removeRevision(staged.resolve(stagedToken)); return null; });
    }

    /**
     * The exact staged ZIP for a token.
     *
     * The native host must consume this path, not the UI's temporary file: the picker's
     * temp copy is deleted in a finally block, and installing from it would either lose
     * the input or install bytes that were never hash-confirmed against the user's confirm.
     */
    public File stagedArchive(String stagedToken) throws IOException {
        checkedToken(stagedToken);
        return locked(() -> {
            Path archive = staged.resolve(stagedToken).resolve("archive.zip");
            if (!Files.isRegularFile(archive, LinkOption.NOFOLLOW_LINKS)) {
                throw new Failure("STAGED_MODULE_MISSING");
            }
            return archive.toFile();
        });
    }

    /** Re-inspects stored ZIP bytes on every read; a corrupt record fails instead of disappearing. */
    public List<Entry> list() throws IOException { return list(null); }

    /** Verify only payloads consumed by this backend; null keeps the full inventory. */
    public List<Entry> list(ModuleType type) throws IOException {
        return locked(() -> {
            List<Entry> entries = new ArrayList<>();
            try (var files = Files.newDirectoryStream(installed, "*.properties")) {
                for (Path file : files) {
                    if (!file.getFileName().toString().matches("[0-9a-f]{64}\\.properties")) {
                        throw new Failure("INVALID_MODULE_RECORD_PATH");
                    }
                    Entry entry = readEntry(file, type);
                    if (entry != null) entries.add(entry);
                }
            }
            entries.sort(Comparator.comparing((Entry entry) -> entry.report.type.name())
                    .thenComparing(entry -> entry.report.id));
            return Collections.unmodifiableList(entries);
        });
    }

    public Entry get(ModuleType type, String id) throws IOException {
        return locked(() -> {
            Path record = recordPath(type, id);
            return Files.exists(record, LinkOption.NOFOLLOW_LINKS) ? readEntry(record) : null;
        });
    }

    /** Reads the installation pointer even when an uninstall has partially removed its archive. */
    public String revision(ModuleType type, String id) throws IOException {
        return locked(() -> {
            String current = readRevision(recordPath(type, id));
            if (current != null) validateRevisionIdentity(current, type, id, false);
            return current;
        });
    }

    public Entry setEnabled(ModuleType type, String id, boolean enabled) throws IOException {
        return locked(() -> {
            Path record = recordPath(type, id);
            Entry current = readEntry(record);
            replaceRecord(record, pointer(current.revision, enabled, current.installedAtMillis));
            return readEntry(record);
        });
    }

    public void uninstall(ModuleType type, String id) throws IOException {
        locked(() -> {
            Path record = recordPath(type, id);
            Entry current = readEntry(record);
            Files.delete(record);
            syncDirectory(installed);
            removeRevision(revisions.resolve(current.revision));
            return null;
        });
    }

    /** Host-installed modules may never have had a Manager archive record. */
    public void uninstallIfPresent(ModuleType type, String id) throws IOException {
        locked(() -> {
            Path record = recordPath(type, id);
            if (!Files.exists(record, LinkOption.NOFOLLOW_LINKS)) {
                syncDirectory(installed);
                return null;
            }
            Entry current = readEntry(record);
            Files.delete(record);
            syncDirectory(installed);
            removeRevision(revisions.resolve(current.revision));
            return null;
        });
    }

    /** A delayed uninstall must not remove a later installation of the same module. */
    public boolean uninstallIfRevision(ModuleType type, String id, String expectedRevision) throws IOException {
        if (expectedRevision != null) checkedToken(expectedRevision);
        return locked(() -> {
            Path record = recordPath(type, id);
            String current = readRevision(record);
            if (current == null) {
                syncDirectory(installed);
                return true;
            }
            if (!current.equals(expectedRevision)) return false;
            validateRevisionIdentity(current, type, id, true);
            removeRevision(revisions.resolve(current));
            Files.delete(record);
            syncDirectory(installed);
            return true;
        });
    }

    private String readRevision(Path record) throws IOException {
        final Properties pointer;
        try { pointer = readProperties(record); }
        catch (NoSuchFileException missing) { return null; }
        String revision = pointer.getProperty("revision", "");
        checkedToken(revision);
        return revision;
    }

    private void validateRevisionIdentity(String revision, ModuleType type, String id,
                                          boolean cleanupStarted) throws IOException {
        final Properties confirmation;
        try {
            Path directory = revisions.resolve(revision);
            if (!Files.readAttributes(directory, java.nio.file.attribute.BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS).isDirectory()) {
                throw new Failure("INVALID_CATALOG_DIRECTORY");
            }
            confirmation = readProperties(directory.resolve("confirmation.properties"));
        } catch (NoSuchFileException missing) {
            if (cleanupStarted) return;
            throw missing;
        }
        if (!type.name().equals(confirmation.getProperty("type")) ||
                !id.equals(confirmation.getProperty("id"))) {
            throw new Failure("MODULE_RECORD_ID_MISMATCH");
        }
    }

    private Entry readEntry(Path path) throws IOException { return readEntry(path, null); }

    private Entry readEntry(Path path, ModuleType requestedType) throws IOException {
        Properties pointer = readProperties(path);
        String revision = pointer.getProperty("revision", "");
        checkedToken(revision);
        String enabled = pointer.getProperty("enabled", "");
        if (!enabled.equals("true") && !enabled.equals("false")) throw new Failure("INVALID_MODULE_RECORD");
        long time;
        try { time = Long.parseLong(pointer.getProperty("installedAtMillis", "")); }
        catch (NumberFormatException error) { throw new Failure("INVALID_MODULE_RECORD"); }
        if (time <= 0) throw new Failure("INVALID_MODULE_RECORD");
        Path directory = revisions.resolve(revision);
        if (requestedType != null) {
            requireDirectory(directory);
            Properties receipt = readProperties(directory.resolve("confirmation.properties"));
            ModuleType storedType;
            try { storedType = ModuleType.valueOf(receipt.getProperty("type", "")); }
            catch (IllegalArgumentException error) { throw new Failure("INVALID_MODULE_RECORD"); }
            if (!path.equals(recordPath(storedType, receipt.getProperty("id")))) {
                throw new Failure("MODULE_RECORD_ID_MISMATCH");
            }
            // Live native state comes from the SDK; its installation ZIP is not a script input.
            if (storedType != requestedType) return null;
        }
        Report report = inspectRevision(directory);
        if (!path.equals(recordPath(report.type, report.id))) throw new Failure("MODULE_RECORD_ID_MISMATCH");
        return new Entry(report, Boolean.parseBoolean(enabled), time, directory.resolve("archive.zip"), revision);
    }

    private Report inspectRevision(Path directory) throws IOException {
        requireDirectory(directory);
        Properties receipt = readProperties(directory.resolve("confirmation.properties"));
        ModuleType type;
        try { type = ModuleType.valueOf(receipt.getProperty("type", "")); }
        catch (IllegalArgumentException error) { throw new Failure("INVALID_MODULE_RECORD"); }
        Path archive = directory.resolve("archive.zip");
        requireArchive(archive);
        Report report = ModuleArchiveInspector.inspect(archive.toFile());
        confirm(report, type, receipt.getProperty("sha256", ""));
        if (!report.id.equals(receipt.getProperty("id"))) throw new Failure("MODULE_RECORD_ID_MISMATCH");
        return report;
    }

    private Path recordPath(ModuleType type, String id) throws IOException {
        if (type == null || id == null || id.isEmpty()) throw new Failure("INVALID_MODULE_ID");
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest((type.name() + "\n" + id).getBytes(StandardCharsets.UTF_8));
            StringBuilder key = new StringBuilder(64);
            for (byte value : hash) key.append(Character.forDigit((value >>> 4) & 15, 16))
                    .append(Character.forDigit(value & 15, 16));
            return installed.resolve(key + ".properties");
        } catch (NoSuchAlgorithmException error) { throw new IllegalStateException(error); }
    }

    private static void confirm(Report report, ModuleType type, String sha256) throws Failure {
        if (report.type != type) throw new Failure("MODULE_TYPE_CONFIRMATION_MISMATCH");
        if (!report.sha256.equals(sha256)) throw new Failure("MODULE_ARCHIVE_CONFIRMATION_MISMATCH");
    }

    private static void requireArchive(Path path) throws IOException {
        requireRegular(path, ModuleArchiveInspector.MAX_ARCHIVE_BYTES);
    }

    private static void requireRegular(Path path, long maximum) throws IOException {
        var attributes = Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class,
                                              LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile() || attributes.size() <= 0 || attributes.size() > maximum) {
            throw new Failure("INVALID_CATALOG_FILE");
        }
    }

    private static void requireDirectory(Path path) throws IOException {
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) throw new Failure("INVALID_CATALOG_DIRECTORY");
    }

    private void directories() throws IOException {
        requireDirectory(root);
        for (Path directory : List.of(staged, revisions, installed)) {
            if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
                try { Files.createDirectory(directory); }
                catch (java.nio.file.FileAlreadyExistsException ignored) { /* Another constructor won. */ }
                syncDirectory(directory);
                syncDirectory(root);
            }
            requireDirectory(directory);
        }
    }

    private static void syncDirectory(Path directory) throws IOException {
        requireDirectory(directory);
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            channel.force(true);
        }
    }

    private static void copyArchive(Path source, Path destination) throws IOException {
        try (FileChannel input = FileChannel.open(source, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
             FileChannel output = FileChannel.open(destination, StandardOpenOption.CREATE_NEW,
                     StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            ByteBuffer bytes = ByteBuffer.allocate(64 * 1024);
            long total = 0;
            for (int read; (read = input.read(bytes)) != -1;) {
                if (Thread.currentThread().isInterrupted()) throw new Failure("CANCELLED");
                if (read > ModuleArchiveInspector.MAX_ARCHIVE_BYTES - total) throw new Failure("ARCHIVE_LIMIT_EXCEEDED");
                total += read;
                bytes.flip();
                while (bytes.hasRemaining()) output.write(bytes);
                bytes.clear();
            }
            output.force(true);
        }
    }

    private static Properties schema() {
        Properties values = new Properties(); values.setProperty("schemaVersion", "1"); return values;
    }

    private static Properties pointer(String revision, boolean enabled, long time) {
        Properties values = schema(); values.setProperty("revision", revision);
        values.setProperty("enabled", Boolean.toString(enabled));
        values.setProperty("installedAtMillis", Long.toString(time)); return values;
    }

    private static Properties readProperties(Path path) throws IOException {
        requireRegular(path, MAX_RECORD_BYTES);
        Properties values = new Properties() {
            @Override public synchronized Object put(Object key, Object value) {
                if (containsKey(key)) throw new IllegalArgumentException("Duplicate catalog property");
                return super.put(key, value);
            }
        };
        try (InputStream input = Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            values.load(input);
        } catch (IllegalArgumentException error) { throw new Failure("INVALID_MODULE_RECORD"); }
        if (!values.getProperty("schemaVersion", "").equals("1")) throw new Failure("INVALID_MODULE_RECORD");
        return values;
    }

    private static void writeNew(Path path, Properties values) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(); values.store(bytes, null);
        if (bytes.size() > MAX_RECORD_BYTES) throw new Failure("INVALID_MODULE_RECORD");
        try (FileChannel output = FileChannel.open(path, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            ByteBuffer data = ByteBuffer.wrap(bytes.toByteArray());
            while (data.hasRemaining()) output.write(data);
            output.force(true);
        }
    }

    private static void replaceRecord(Path destination, Properties values) throws IOException {
        replaceRecord(destination, values, Files::deleteIfExists);
    }

    interface TemporaryCleanup { void delete(Path path) throws IOException; }

    static void replaceRecord(Path destination, Properties values, TemporaryCleanup cleanup) throws IOException {
        replaceRecord(destination, values, cleanup, new boolean[] { false });
    }

    private static void replaceRecord(Path destination, Properties values, TemporaryCleanup cleanup,
                                      boolean[] published) throws IOException {
        Path temporary = destination.resolveSibling(".record-" + token());
        IOException failure = null;
        try {
            writeNew(temporary, values);
            Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            published[0] = true;
            syncDirectory(destination.getParent());
        } catch (IOException error) {
            failure = error;
            throw error;
        } finally {
            if (!published[0]) {
                try { cleanup.delete(temporary); }
                catch (IOException cleanupError) {
                    if (failure == null) throw cleanupError;
                    failure.addSuppressed(cleanupError);
                }
            }
        }
    }

    private static String token() { return UUID.randomUUID().toString().replace("-", ""); }

    private static void checkedToken(String value) throws Failure {
        if (value == null || !value.matches("[0-9a-f]{32}")) throw new Failure("INVALID_STAGED_TOKEN");
    }

    private static void removeRevision(Path directory) throws IOException {
        if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
            syncDirectory(directory.getParent());
            return;
        }
        requireDirectory(directory);
        Files.deleteIfExists(directory.resolve("archive.zip"));
        Files.deleteIfExists(directory.resolve("confirmation.properties"));
        syncDirectory(directory);
        Files.delete(directory);
        syncDirectory(directory.getParent());
    }

    private interface Operation<T> { T run() throws IOException; }

    /**
     * Process-wide lock. The on-disk FileLock only excludes other processes; two
     * {@link ModuleCatalog} instances in this process (the boot service's backend and
     * the UI's list load, for example) would otherwise overlap on the same file and
     * throw {@link OverlappingFileLockException}, which surfaces as MODULE_CATALOG_BUSY.
     * Measured: a real boot run lost its property task to exactly that race.
     */
    private static final Object PROCESS_LOCK = new Object();

    private <T> T locked(Operation<T> operation) throws IOException {
        synchronized (PROCESS_LOCK) {
            directories();
            Path lockPath = root.resolve("catalog.lock");
            if (Files.exists(lockPath, LinkOption.NOFOLLOW_LINKS)
                    && !Files.isRegularFile(lockPath, LinkOption.NOFOLLOW_LINKS)) {
                throw new Failure("INVALID_CATALOG_FILE");
            }
            try (FileChannel lock = FileChannel.open(lockPath, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
                 FileLock ignored = lock.lock()) {
                return operation.run();
            } catch (OverlappingFileLockException error) { throw new Failure("MODULE_CATALOG_BUSY"); }
        }
    }
}
