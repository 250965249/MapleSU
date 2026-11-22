package dev.maplesu.manager.runtime.authorization;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/** One-time byte-preserving import; the caller owns and validates the private directory. */
final class RootAuthorizationMigration {
    private static final int MAX_BYTES = 1024 * 1024;

    interface DirectorySync { void sync() throws IOException; }
    interface LegacyReader { InputStream open(Path file) throws IOException; }

    static Path prepare(Path directory, Path legacy, int managerUid, DirectorySync sync) throws IOException {
        return prepare(directory, legacy, managerUid, sync,
                file -> Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS));
    }

    static Path prepare(Path directory, Path legacy, int managerUid, DirectorySync sync,
            LegacyReader reader) throws IOException {
        Path file = directory.resolve("authorizations.bin");
        Path marker = directory.resolve("import-complete");
        byte[] markerBytes = ("MapleSU authorization owner v1\n" + managerUid + "\n")
                .getBytes(StandardCharsets.US_ASCII);
        boolean marked = Files.exists(marker, LinkOption.NOFOLLOW_LINKS);
        if (marked) {
            requireRegular(marker);
            if (Files.size(marker) != markerBytes.length
                    || !java.util.Arrays.equals(Files.readAllBytes(marker), markerBytes))
                throw new IOException("AUTH_IMPORT_MARKER_INVALID");
        }
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            requireRegular(file);
            new FileAuthorizationStore(file).load();
        } else {
            if (marked) throw new IOException("AUTH_IMPORT_STORE_MISSING");
            if (Files.exists(legacy, LinkOption.NOFOLLOW_LINKS)) {
                requireRegular(legacy);
                Path temporary = FileAuthorizationStore.createTemporary(directory, "maplesu-import-");
                try {
                    try (InputStream input = reader.open(legacy);
                            FileOutputStream output = new FileOutputStream(temporary.toFile())) {
                        byte[] buffer = new byte[4096];
                        int size = 0;
                        int count;
                        while ((count = input.read(buffer)) != -1) {
                            if ((size += count) > MAX_BYTES) throw new IOException("AUTH_STORE_TOO_LARGE");
                            output.write(buffer, 0, count);
                        }
                        output.getFD().sync();
                    }
                    // Validate the isolated copy, never rebind grants to current installations.
                    new FileAuthorizationStore(temporary).load();
                    Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE);
                } finally { Files.deleteIfExists(temporary); }
            } else {
                new FileAuthorizationStore(file).save(new FileAuthorizationStore.State(false,
                        java.util.Collections.emptyMap()));
            }
        }
        if (!marked) {
            sync.sync();
            Path temporary = FileAuthorizationStore.createTemporary(directory, "maplesu-import-marker-");
            try {
                try (FileOutputStream output = new FileOutputStream(temporary.toFile())) {
                    output.write(markerBytes);
                    output.getFD().sync();
                }
                Files.move(temporary, marker, StandardCopyOption.ATOMIC_MOVE);
                sync.sync();
            } finally { Files.deleteIfExists(temporary); }
        }
        return file;
    }

    private static void requireRegular(Path file) throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("AUTH_IMPORT_FILE_INVALID");
    }

    private RootAuthorizationMigration() {}
}
