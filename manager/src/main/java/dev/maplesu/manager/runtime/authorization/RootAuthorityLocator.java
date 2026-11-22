package dev.maplesu.manager.runtime.authorization;

import java.io.IOException;
import java.io.InputStream;
import java.io.FileOutputStream;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;

/** Immutable root-protected selection metadata, never a second permission store.
 * The numeric directory and its journal lock are never moved or copied, so old
 * processes already holding that path keep using exactly the same authority. */
final class RootAuthorityLocator {
    interface Guard {
        void directory(Path path) throws IOException;
        void file(Path path) throws IOException;
        InputStream read(Path path) throws IOException;
        void sync(Path directory) throws IOException;
    }
    interface Initializer { void prepare(Path directory, int historicalManagerUid) throws IOException; }

    static int userId(int uid) {
        if (uid < 0 || uid % 100_000 < 10_000 || uid % 100_000 > 19_999)
            throw new IllegalArgumentException("AUTH_STORE_MANAGER_UID_INVALID");
        return uid / 100_000;
    }

    /* JVM serialization avoids OverlappingFileLockException; the sibling file
     * serializes separate root JVMs. Installation initialization takes layout
     * then journal; journal transactions never acquire the layout lock.
     * No decision bytes are copied, so an in-flight journal transaction need
     * not be stopped or locked to select its unchanged directory. */
    static synchronized Path resolve(Path root, int managerUid, Guard guard,
            Initializer initialize) throws IOException {
        int user = userId(managerUid);
        guard.directory(root);
        Path lockFile = root.resolve("user-" + user + ".authority.lock");
        boolean created = false;
        try {
            try {
                Files.createFile(lockFile, PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString("rw-------")));
            } catch (UnsupportedOperationException hostOnly) {
                Files.createFile(lockFile);
            }
            created = true;
        } catch (FileAlreadyExistsException existing) { /* retain the same lock inode */ }
        guard.file(lockFile);
        try (FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS); FileLock held = channel.lock()) {
            guard.file(lockFile);
            if (created) { channel.force(true); guard.sync(root); }
            Path locator = root.resolve("user-" + user + ".authority");
            Integer selected = exists(locator) ? read(locator, user, guard) : null;
            Integer legacy = null;
            boolean multipleLegacy = false;
            int entries = 0;
            try (DirectoryStream<Path> children = Files.newDirectoryStream(root)) {
                for (Path child : children) {
                    if (++entries > 20_000) throw new IOException("AUTH_AUTHORITY_TOO_MANY_ENTRIES");
                    String name = child.getFileName().toString();
                    if (!name.matches("[0-9]+")) continue;
                    int uid;
                    try { uid = Integer.parseInt(name); }
                    catch (NumberFormatException invalid) { throw new IOException("AUTH_AUTHORITY_SOURCE_INVALID", invalid); }
                    if (uid / 100_000 != user) continue;
                    if (!Integer.toString(uid).equals(name)) throw new IOException("AUTH_AUTHORITY_SOURCE_INVALID");
                    try { userId(uid); }
                    catch (IllegalArgumentException invalid) { throw new IOException("AUTH_AUTHORITY_SOURCE_INVALID", invalid); }
                    if (selected != null && uid != selected) continue;
                    guard.directory(child);
                    if (legacy != null) multipleLegacy = true;
                    // Before locators, the trusted manager fullUID selected its
                    // existing directory. Preserve that authority, not a new or
                    // merged store, when older installations left other paths.
                    if (legacy == null || uid == managerUid) legacy = uid;
                }
            }
            if (selected == null && multipleLegacy && !Integer.valueOf(managerUid).equals(legacy))
                throw new IOException("AUTH_AUTHORITY_CONFLICT");
            if (selected != null && (legacy == null || !selected.equals(legacy)))
                throw new IOException("AUTH_AUTHORITY_SOURCE_MISSING");
            if (selected == null && initialize == null)
                throw new IOException("AUTH_AUTHORITY_LOCATOR_MISSING");
            int uid = selected != null ? selected : legacy != null ? legacy : managerUid;
            Path directory = root.resolve(Integer.toString(uid));
            if (initialize != null) initialize.prepare(directory, uid);
            guard.directory(directory);
            if (selected == null) {
                byte[] bytes = encode(user, uid);
                Path temporary = FileAuthorizationStore.createTemporary(root, "maplesu-authority-");
                try {
                    guard.file(temporary);
                    try (FileOutputStream output = new FileOutputStream(temporary.toFile())) {
                        output.write(bytes);
                        output.getFD().sync();
                    }
                    // The immutable target is absent under the same layout lock.
                    Files.move(temporary, locator, StandardCopyOption.ATOMIC_MOVE);
                    guard.sync(root);
                } finally { Files.deleteIfExists(temporary); }
            } else {
                // Also completes a previous post-rename directory-fsync failure.
                guard.sync(root);
            }
            return directory;
        }
    }

    private static int read(Path locator, int user, Guard guard) throws IOException {
        guard.file(locator);
        byte[] bytes = new byte[128];
        int size = 0;
        try (InputStream input = guard.read(locator)) {
            for (int count; (count = input.read(bytes, size, bytes.length - size)) != -1;) {
                size += count;
                if (size == bytes.length) throw new IOException("AUTH_AUTHORITY_LOCATOR_INVALID");
            }
        }
        String text = new String(bytes, 0, size, StandardCharsets.US_ASCII);
        String[] lines = text.split("\n", -1);
        if (lines.length != 4 || !lines[0].equals("MapleSU authorization locator v1") ||
                !lines[1].equals(Integer.toString(user)) || !lines[3].isEmpty())
            throw new IOException("AUTH_AUTHORITY_LOCATOR_INVALID");
        int uid;
        try { uid = Integer.parseInt(lines[2]); }
        catch (NumberFormatException invalid) { throw new IOException("AUTH_AUTHORITY_LOCATOR_INVALID", invalid); }
        try {
            if (userId(uid) != user || !lines[2].equals(Integer.toString(uid)))
                throw new IllegalArgumentException();
        } catch (IllegalArgumentException invalid) { throw new IOException("AUTH_AUTHORITY_LOCATOR_INVALID", invalid); }
        if (!java.util.Arrays.equals(java.util.Arrays.copyOf(bytes, size), encode(user, uid)))
            throw new IOException("AUTH_AUTHORITY_LOCATOR_INVALID");
        return uid;
    }

    private static byte[] encode(int user, int uid) {
        return ("MapleSU authorization locator v1\n" + user + "\n" + uid + "\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

    private static boolean exists(Path path) throws IOException {
        try {
            Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            return true;
        } catch (java.nio.file.NoSuchFileException absent) { return false; }
    }

    private RootAuthorityLocator() {}
}
