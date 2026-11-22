package dev.maplesu.installer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Static red-line guard (02-switch-contract §4.7/§8.8): partition bytes may only be written by
 * {@link BlockDeviceTransaction}. New switch sources must not contain any raw write primitive.
 *
 * <p>Allowlisted files: the two pre-existing writers and {@code FileSwitchJournal}, which writes the
 * WAL file (not partition bytes) and is required by the contract to fsync every line.</p>
 */
public final class WritePathGuardTest {
    private static final List<String> FORBIDDEN = List.of("pwrite", "FileChannel.write", ".write(");
    private static final Set<String> ALLOWED_FILES = Set.of(
            "BlockDeviceTransaction.java",   // the single existing partition writer (red line 4)
            "FileInstallTransaction.java",   // pre-existing regular-file transaction, not a partition writer
            "FileSwitchJournal.java");       // WAL file appends only, never a partition

    private static int passed;

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        passed++;
    }

    private static Path sourceDirectory() {
        for (String candidate : List.of("src/main/java/dev/maplesu/installer",
                "installer-core/src/main/java/dev/maplesu/installer")) {
            Path path = Path.of(candidate);
            if (Files.isDirectory(path)) return path;
        }
        throw new AssertionError("installer-core source tree not found from " + Path.of("").toAbsolutePath());
    }

    public static void main(String[] args) throws Exception {
        Path directory = sourceDirectory();
        List<Path> sources = new ArrayList<>();
        try (Stream<Path> paths = Files.list(directory)) {
            paths.filter(path -> path.getFileName().toString().endsWith(".java")).forEach(sources::add);
        }
        check(sources.size() >= 14, "guard scans all installer-core sources, found " + sources.size());
        List<String> violations = new ArrayList<>();
        for (Path source : sources) {
            String name = source.getFileName().toString();
            if (ALLOWED_FILES.contains(name)) continue;
            String text = Files.readString(source, StandardCharsets.UTF_8);
            for (String forbidden : FORBIDDEN) {
                if (text.contains(forbidden)) violations.add(name + " contains " + forbidden);
            }
        }
        check(violations.isEmpty(), "no second partition writer: " + violations);
        String orchestrator = Files.readString(directory.resolve("InstallerMultiPartitionTransaction.java"),
                StandardCharsets.UTF_8);
        check(orchestrator.contains("BlockDeviceTransaction.commit("), "orchestrator uses the single writer (commit)");
        check(orchestrator.contains("BlockDeviceTransaction.restore("), "orchestrator uses the single writer (restore)");
        check(!orchestrator.contains(".write("), "orchestrator performs no write call itself");
        System.out.println("WritePathGuard: " + passed + " checks passed (red line 4 static guard "
                + sources.size() + " sources)");
    }
}
