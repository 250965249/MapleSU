package dev.maplesu.manager.runtime.authorization;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;

import java.io.FileDescriptor;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/** Publication in the existing root-owned authority, never a new authority. */
final class AuthorizationDurability {
    /** A rename is not undone or replayed when its following durability barrier fails. */
    static final class PublicationException extends IOException {
        final boolean published;
        final boolean directorySynced;

        PublicationException(String stage, boolean published, boolean directorySynced, Throwable cause) {
            super("AUTH_STORE_PUBLICATION_FAILED:published=" + published + ";durability=" +
                    (directorySynced ? "synced" : "unknown") + ";stage=" + stage + ";cause=" +
                    cause.getClass().getSimpleName() + ":" + cause.getMessage(), cause);
            this.published = published;
            this.directorySynced = directorySynced;
        }
    }

    static void atomicReplace(Path temporary, Path target) throws IOException {
        Path directory = target.toAbsolutePath().normalize().getParent();
        if (directory == null || !directory.equals(temporary.toAbsolutePath().normalize().getParent()))
            throw new IOException("AUTH_STORE_STAGING_DIRECTORY_MISMATCH");
        FileDescriptor descriptor = null;
        boolean published = false;
        boolean directorySynced = false;
        String stage = "directory-open";
        Throwable failure = null;
        try {
            descriptor = Os.open(directory.toString(), OsConstants.O_RDONLY | directoryOpenFlag() |
                    OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC, 0);
            stage = "directory-fstat";
            StructStat stat = Os.fstat(descriptor);
            if (!OsConstants.S_ISDIR(stat.st_mode) || stat.st_uid != 0 || (stat.st_mode & 07777) != 0700)
                throw new IOException("AUTH_STORE_DIRECTORY_INVALID");
            stage = "atomic-move";
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            published = true;
            stage = "directory-fsync";
            Os.fsync(descriptor);
            directorySynced = true;
        } catch (IOException | ErrnoException error) {
            PublicationException publication = new PublicationException(stage, published, directorySynced, error);
            failure = publication;
            throw publication;
        } catch (RuntimeException | Error error) {
            failure = error;
            throw error;
        } finally {
            if (descriptor != null) {
                try { Os.close(descriptor); }
                catch (ErrnoException close) {
                    if (failure != null) failure.addSuppressed(close);
                    else throw new PublicationException("directory-close", published, directorySynced, close);
                }
            }
        }
    }

    private static int directoryOpenFlag() throws IOException {
        // O_DIRECTORY is absent from the public Android SDK; use the Android UAPI pair
        // selected by libcore's native O_NOFOLLOW (ARM/ARM64 versus generic Linux ABIs).
        if (OsConstants.O_NOFOLLOW == 0100000) return 040000;
        if (OsConstants.O_NOFOLLOW == 00400000) return 00200000;
        throw new IOException("AUTH_STORE_DIRECTORY_FLAG_UNSUPPORTED");
    }

    private AuthorizationDurability() {}
}
