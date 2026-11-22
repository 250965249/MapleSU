package dev.maplesu.manager.runtime.authorization;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Root alone owns the authority. Manager UID selects its Android user, not a new store. */
public final class RootAuthorizationStore {
    private static final Path ROOT = Paths.get("/data/adb/maplesu/authorization");

    public static AuthorizationPolicy open(int managerUid, Path legacyFile,
            AuthorizationPolicy.TrustedIdentityProvider identities) throws IOException {
        return open(managerUid, legacyFile, identities, false);
    }

    public static AuthorizationPolicy openForInstallation(int managerUid, Path legacyFile,
            AuthorizationPolicy.TrustedIdentityProvider identities) throws IOException {
        return open(managerUid, legacyFile, identities, true);
    }

    private static AuthorizationPolicy open(int managerUid, Path legacyFile,
            AuthorizationPolicy.TrustedIdentityProvider identities, boolean installation) throws IOException {
        requireRoot(managerUid);
        final ApplicationIdentity installationIdentity = installation ? identities.read(managerUid) : null;
        if (installation && installationIdentity == null) throw new IOException("AUTH_IDENTITY_UNAVAILABLE");
        try {
            ancestors();
            directory("/data/adb", false);
            directory("/data/adb/maplesu", false);
            directory("/data/adb/maplesu/authorization", true);
            Path directory = RootAuthorityLocator.resolve(ROOT, managerUid, guard(),
                    (selected, historicalUid) -> prepareAuthority(selected, historicalUid, managerUid, legacyFile,
                            installationIdentity));
            return new AuthorizationPolicy(directory.resolve("authorizations.bin"), identities);
        } catch (ErrnoException error) { throw new IOException("AUTH_STORE_FILESYSTEM_FAILED", error); }
    }

    /** The exact same immutable locator used by open; root-side snapshot/ops only.
     * Missing/conflicting selection is an error, never a newly empty authority. */
    public static Path authorityDirectory(int managerUid) throws IOException {
        requireRoot(managerUid);
        try { ancestors(); }
        catch (ErrnoException error) { throw new IOException("AUTH_STORE_FILESYSTEM_FAILED", error); }
        return RootAuthorityLocator.resolve(ROOT, managerUid, guard(), null);
    }

    private static void ancestors() throws ErrnoException, IOException {
        // OS-owned ancestors may be system-owned and have their Android mode.
        for (String ancestor : new String[]{"/", "/data"}) {
            StructStat stat = Os.lstat(ancestor);
            if (!OsConstants.S_ISDIR(stat.st_mode) || (stat.st_uid != 0 && stat.st_uid != 1000)
                    || (stat.st_mode & 0002) != 0
                    || ((stat.st_mode & 0020) != 0 && stat.st_gid != 0 && stat.st_gid != 1000))
                throw new IOException("AUTH_STORE_ANCESTOR_INVALID");
        }
        for (String ancestor : new String[]{"/data/adb", "/data/adb/maplesu"}) {
            try {
                StructStat stat = Os.lstat(ancestor);
                if (!OsConstants.S_ISDIR(stat.st_mode) || stat.st_uid != 0 || (stat.st_mode & 0022) != 0)
                    throw new IOException("AUTH_STORE_DIRECTORY_INVALID");
            } catch (ErrnoException missing) {
                if (missing.errno != OsConstants.ENOENT) throw missing;
                // open() creates missing product ancestors; resolve() still
                // requires its final protected root to exist.
            }
        }
    }

    private static void requireRoot(int managerUid) {
        if (Os.getuid() != 0 || Os.geteuid() != 0) throw new SecurityException("AUTH_STORE_ROOT_REQUIRED");
        RootAuthorityLocator.userId(managerUid);
    }

    private static RootAuthorityLocator.Guard guard() {
        return new RootAuthorityLocator.Guard() {
            public void directory(Path path) throws IOException {
                try {
                    StructStat stat = Os.lstat(path.toString());
                    if (!OsConstants.S_ISDIR(stat.st_mode) || stat.st_uid != 0 || (stat.st_mode & 07777) != 0700)
                        throw new IOException("AUTH_STORE_DIRECTORY_INVALID");
                } catch (ErrnoException error) { throw new IOException("AUTH_STORE_FILESYSTEM_FAILED", error); }
            }
            public void file(Path path) throws IOException {
                try { requirePrivateFile(Os.lstat(path.toString()), 0); }
                catch (ErrnoException error) { throw new IOException("AUTH_STORE_FILESYSTEM_FAILED", error); }
            }
            public FileInputStream read(Path path) throws IOException { return openLegacy(path, 0); }
            public void sync(Path path) throws IOException { syncDirectory(path); }
        };
    }

    private static void prepareAuthority(Path directory, int historicalUid, int managerUid,
            Path legacyFile, ApplicationIdentity installationIdentity) throws IOException {
        try {
            directory(directory.toString(), true);
            // Keep every journal/lock/previous/marker file in place. Reject a
            // malformed protected source; never discard tombstones or merge it.
            try (java.nio.file.DirectoryStream<Path> children = java.nio.file.Files.newDirectoryStream(directory)) {
                for (Path child : children) {
                    if (child.getFileName().toString().equals(SuperuserJournalStore.LOCK)) {
                        StructStat stat = Os.lstat(child.toString());
                        if (!OsConstants.S_ISREG(stat.st_mode) || stat.st_uid != 0 || stat.st_nlink != 1 ||
                                (stat.st_mode & 0022) != 0)
                            throw new IOException("AUTH_STORE_FILE_INVALID");
                    } else requirePrivateFile(Os.lstat(child.toString()), 0);
                }
            }
            privateFile(directory.resolve("authorizations.bin"), 0);
            privateFile(directory.resolve("import-complete"), 0);
            if (missing(directory.resolve("authorizations.bin")) && missing(directory.resolve("import-complete"))) {
                if (historicalUid != managerUid || !missing(directory.resolve(SuperuserJournalStore.FILE)) ||
                        !missing(directory.resolve(SuperuserJournalStore.PREV)))
                    throw new IOException("AUTH_AUTHORITY_LEGACY_INCOMPLETE");
                privateFile(legacyFile, managerUid);
                if (!missing(legacyFile)) {
                    StructStat parent = Os.lstat(legacyFile.toAbsolutePath().getParent().toString());
                    if (!OsConstants.S_ISDIR(parent.st_mode) || parent.st_uid != managerUid
                            || (parent.st_mode & 0002) != 0
                            || ((parent.st_mode & 0020) != 0 && parent.st_gid != managerUid))
                        throw new IOException("AUTH_IMPORT_DIRECTORY_INVALID");
                }
            }
            if (installationIdentity != null && missing(directory.resolve("authorizations.bin")) &&
                    missing(directory.resolve("import-complete")) && missing(legacyFile)) {
                SuperuserTransaction.Outcome initialized = new SuperuserTransaction(directory.toFile(),
                        new FileSuperuserStorePort(directory.resolve("authorizations.bin")),
                        directory.resolve(SuperuserJournalStore.FILE).toFile(), null,
                        System::currentTimeMillis, record -> kotlin.Unit.INSTANCE)
                        .initializeForInstallationIfAbsent(installationIdentity);
                if (!initialized.getOk()) throw new IOException("AUTH_INSTALL_INITIALIZATION_FAILED:" +
                        initialized.getCode() + ":" + initialized.getDetail());
            }
            Path file = RootAuthorizationMigration.prepare(directory, legacyFile, historicalUid,
                    () -> syncDirectory(directory), path -> openLegacy(path, managerUid));
            privateFile(file, 0);
            privateFile(directory.resolve("import-complete"), 0);
            SuperuserJournalStore.read(directory.resolve(SuperuserJournalStore.FILE).toFile());
            syncDirectory(directory);
        } catch (ErrnoException error) { throw new IOException("AUTH_STORE_FILESYSTEM_FAILED", error); }
    }

    private static void directory(String path, boolean strictlyPrivate) throws ErrnoException, IOException {
        try { Os.mkdir(path, 0700); }
        catch (ErrnoException error) { if (error.errno != OsConstants.EEXIST) throw error; }
        StructStat stat = Os.lstat(path);
        if (!OsConstants.S_ISDIR(stat.st_mode) || stat.st_uid != 0
                || (stat.st_mode & 0022) != 0
                || (strictlyPrivate && (stat.st_mode & 07777) != 0700))
            throw new IOException("AUTH_STORE_DIRECTORY_INVALID");
    }

    private static boolean missing(Path path) throws ErrnoException {
        try { Os.lstat(path.toString()); return false; }
        catch (ErrnoException error) { if (error.errno == OsConstants.ENOENT) return true; throw error; }
    }

    private static void privateFile(Path path, int uid) throws ErrnoException, IOException {
        if (missing(path)) return;
        requirePrivateFile(Os.lstat(path.toString()), uid);
    }

    private static void requirePrivateFile(StructStat stat, int uid) throws IOException {
        if (!OsConstants.S_ISREG(stat.st_mode) || stat.st_uid != uid || stat.st_nlink != 1
                || (stat.st_mode & 07777) != 0600)
            throw new IOException("AUTH_STORE_FILE_INVALID");
    }

    private static FileInputStream openLegacy(Path path, int uid) throws IOException {
        FileDescriptor descriptor = null;
        try {
            descriptor = Os.open(path.toString(), OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW
                    | OsConstants.O_CLOEXEC, 0);
            // Validate the opened inode, including a concurrent change of the App-owned parent.
            requirePrivateFile(Os.fstat(descriptor), uid);
            return new FileInputStream(descriptor);
        } catch (ErrnoException | IOException error) {
            if (descriptor != null) try { Os.close(descriptor); } catch (ErrnoException ignored) {}
            throw new IOException("AUTH_IMPORT_OPEN_FAILED", error);
        }
    }

    private static void syncDirectory(Path directory) throws IOException {
        try {
            FileDescriptor descriptor = Os.open(directory.toString(),
                    OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC, 0);
            try {
                StructStat stat = Os.fstat(descriptor);
                if (!OsConstants.S_ISDIR(stat.st_mode) || stat.st_uid != 0 || (stat.st_mode & 07777) != 0700)
                    throw new IOException("AUTH_STORE_DIRECTORY_INVALID");
                Os.fsync(descriptor);
            } finally { Os.close(descriptor); }
        } catch (ErrnoException error) { throw new IOException("AUTH_STORE_SYNC_FAILED", error); }
    }

    private RootAuthorizationStore() {}
}
