package dev.maplesu.installer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

/** JUnit-free temporary directory helper in the same style as the existing installer-core fixtures. */
final class TempWorkDir implements AutoCloseable {
    final Path root;

    private TempWorkDir(Path root) { this.root = root; }

    static TempWorkDir create() throws IOException {
        return new TempWorkDir(Files.createTempDirectory("maplesu-switch-test-"));
    }

    @Override
    public void close() {
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // Best effort cleanup; the failure would not invalidate the assertions above.
        }
    }
}
