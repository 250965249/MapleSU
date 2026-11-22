package dev.maplesu.installer;

import android.view.WindowManager;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import com.maplesu.core.ui.MainActivity;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Locale;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

/** Executes the regular-file protocol on Android app-private storage; no device partitions. */
@RunWith(AndroidJUnit4.class)
public final class FileInstallTransactionAndroidTest {
    private static String hash(byte[] bytes) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte value : MessageDigest.getInstance("SHA-256").digest(bytes)) {
            result.append(String.format(Locale.ROOT, "%02x", value & 255));
        }
        return result.toString();
    }

    @Test public void fileTargetBackupReadbackFailureAndRestore() throws Exception {
        try (ActivityScenario<MainActivity> foreground = ActivityScenario.launch(MainActivity.class)) {
            foreground.onActivity(activity -> activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));
            Path root = Files.createTempDirectory(InstrumentationRegistry.getInstrumentation()
                    .getTargetContext().getCacheDir().toPath(), "file-install-test-");
            try {
                byte[] original = new byte[150001], candidate = new byte[150001];
                Arrays.fill(original, (byte) 17);
                Arrays.fill(candidate, (byte) 42);
                Path source = root.resolve("candidate.img"), target = root.resolve("target.img");
                Files.write(source, candidate);
                Files.write(target, original);
                FileInstallTransaction prepared = FileInstallTransaction.prepare(root, source, target,
                        hash(candidate), hash(original));
                assertTrue("Android storage must support the journal directory barrier", prepared.directorySyncSupported());
                assertArrayEquals(original, Files.readAllBytes(target));
                prepared.commit();
                assertEquals(FileInstallTransaction.State.VERIFIED, prepared.state());
                assertArrayEquals(candidate, Files.readAllBytes(target));
                FileInstallTransaction.open(root, root.resolve(prepared.directory().getFileName())).restore();
                assertArrayEquals(original, Files.readAllBytes(target));

                for (boolean corruptReadback : new boolean[]{false, true}) {
                    FileInstallTransaction failing = FileInstallTransaction.prepare(root, source, target,
                            hash(candidate), hash(original));
                    try {
                        failing.commit((phase, count, channel) -> {
                            if (!corruptReadback && phase.equals("AFTER_WRITE")) throw new IOException("test failure");
                            if (corruptReadback && phase.equals("BEFORE_READBACK")) {
                                channel.position(0);
                                channel.write(ByteBuffer.wrap(new byte[]{99}));
                                channel.force(true);
                            }
                        });
                        fail("write failure was accepted");
                    } catch (FileInstallTransaction.Failure expected) {
                        assertEquals(corruptReadback ? "READBACK_MISMATCH" : "WRITE_FAILED", expected.code);
                        assertTrue(expected.targetMayBeModified);
                    }
                    assertEquals(FileInstallTransaction.State.RECOVERY_REQUIRED, failing.state());
                    assertFalse(Arrays.equals(original, Files.readAllBytes(target)));
                    FileInstallTransaction.open(root, failing.directory()).restore();
                    assertArrayEquals(original, Files.readAllBytes(target));
                    assertArrayEquals(candidate, Files.readAllBytes(source));
                }

                for (Path file : new Path[]{source, target}) {
                    FileInstallTransaction replacement = FileInstallTransaction.prepare(root, source, target,
                            hash(candidate), hash(original));
                    Path substitute = root.resolve("replacement.img");
                    Files.write(substitute, Files.readAllBytes(file));
                    Files.move(substitute, file, StandardCopyOption.REPLACE_EXISTING);
                    try {
                        FileInstallTransaction.open(root, replacement.directory()).commit();
                        fail("same-content replacement was accepted");
                    } catch (FileInstallTransaction.Failure expected) {
                        assertEquals("FILE_IDENTITY_CHANGED", expected.code);
                        assertFalse(expected.targetMayBeModified);
                    }
                    assertArrayEquals(original, Files.readAllBytes(target));
                }
            } finally {
                try (var paths = Files.walk(root)) {
                    for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
                }
            }
        }
    }

    @Test public void failedJournalDirectorySyncPreservesTargetAndCanBeRestored() throws Exception {
        Path root = Files.createTempDirectory(InstrumentationRegistry.getInstrumentation()
                .getTargetContext().getCacheDir().toPath(), "file-install-sync-test-");
        try {
            byte[] original = new byte[150001], candidate = new byte[150001];
            Arrays.fill(original, (byte) 17);
            Arrays.fill(candidate, (byte) 42);
            Path source = root.resolve("candidate.img"), target = root.resolve("target.img");
            Files.write(source, candidate);
            Files.write(target, original);
            FileInstallTransaction prepared = FileInstallTransaction.prepare(root, source, target,
                    hash(candidate), hash(original));
            assertTrue(prepared.directorySyncSupported());
            FileInstallTransaction interrupted = FileInstallTransaction.open(root, prepared.directory(), directory -> {
                throw new IOException("DIRECTORY_SYNC_INTERRUPTED");
            });
            assertThrows(IOException.class, interrupted::commit);
            assertArrayEquals(original, Files.readAllBytes(target));
            FileInstallTransaction recovered = FileInstallTransaction.open(root, prepared.directory());
            recovered.restore();
            assertEquals(FileInstallTransaction.State.RESTORED, recovered.state());
            assertArrayEquals(original, Files.readAllBytes(target));
            assertArrayEquals(candidate, Files.readAllBytes(source));
        } finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }
}
