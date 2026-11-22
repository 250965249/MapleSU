package dev.maplesu.manager.runtime.authorization;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class RootAuthorizationMigrationTest {
    @Rule public TemporaryFolder temporary = new TemporaryFolder();
    private static final int MANAGER_UID = 110_481;
    private static final int CLIENT_UID = 110_485;

    private static ApplicationIdentity identity(long updated) {
        return new ApplicationIdentity(CLIENT_UID, "example.client", Collections.singleton("example.client"),
                Collections.singleton(String.join("", Collections.nCopies(64, "a"))),
                100, updated, "/data/app/example/base.apk");
    }

    private Path directory() throws IOException { return temporary.newFolder().toPath(); }

    private Path legacy(boolean enabled) throws IOException {
        Path file = directory().resolve("authorizations.bin");
        AuthorizationPolicy policy = new AuthorizationPolicy(file, uid -> identity(100));
        policy.grant(CLIENT_UID);
        policy.setEnabled(enabled);
        return file;
    }

    private static Path prepare(Path directory, Path legacy) throws IOException {
        return RootAuthorizationMigration.prepare(directory, legacy, MANAGER_UID, () -> {});
    }

    @Test public void importPreservesEncodedBytesEnabledAndFullUidSnapshot() throws Exception {
        Path source = legacy(true);
        Path directory = directory();
        Path target = prepare(directory, source);
        assertArrayEquals(Files.readAllBytes(source), Files.readAllBytes(target));
        AuthorizationPolicy policy = new AuthorizationPolicy(target, uid -> uid == CLIENT_UID ? identity(100) : null);
        assertTrue(policy.isEnabled());
        assertEquals(CLIENT_UID, (int) policy.authorizeAndStart(CLIENT_UID, snapshot -> snapshot.uid));
        assertTrue(Files.exists(directory.resolve("import-complete")));
    }

    @Test public void disabledImportStaysDisabled() throws Exception {
        Path target = prepare(directory(), legacy(false));
        AuthorizationPolicy policy = new AuthorizationPolicy(target, uid -> identity(100));
        assertFalse(policy.isEnabled());
        assertTrue(policy.hasCurrentGrant(CLIENT_UID));
        assertThrows(SecurityException.class, () -> policy.authorizeAndStart(CLIENT_UID, value -> "unexpected"));
    }

    @Test public void importDoesNotRegrantChangedInstallation() throws Exception {
        Path target = prepare(directory(), legacy(true));
        AuthorizationPolicy policy = new AuthorizationPolicy(target, uid -> identity(101));
        assertFalse(policy.hasCurrentGrant(CLIENT_UID));
        assertThrows(SecurityException.class, () -> policy.authorizeAndStart(CLIENT_UID, value -> "unexpected"));
    }

    @Test public void missingLegacyCreatesDisabledEmptyStore() throws Exception {
        Path directory = directory();
        Path target = prepare(directory, directory.resolve("missing-legacy"));
        AuthorizationPolicy policy = new AuthorizationPolicy(target, uid -> identity(100));
        assertFalse(policy.isEnabled());
        assertFalse(policy.hasCurrentGrant(CLIENT_UID));
    }

    @Test public void formalStoreIsAuthoritativeOverLaterLegacyChanges() throws Exception {
        Path source = legacy(true);
        Path directory = directory();
        Path target = prepare(directory, source);
        AuthorizationPolicy policy = new AuthorizationPolicy(target, uid -> identity(100));
        policy.revoke(CLIENT_UID);
        prepare(directory, source);
        assertFalse(new AuthorizationPolicy(target, uid -> identity(100)).hasCurrentGrant(CLIENT_UID));
    }

    @Test public void formalStoreIgnoresBrokenLegacy() throws Exception {
        Path source = legacy(true);
        Path directory = directory();
        Path target = prepare(directory, source);
        Files.write(source, new byte[]{1, 2, 3});
        assertEquals(target, prepare(directory, source));
        assertTrue(new AuthorizationPolicy(target, uid -> identity(100)).hasCurrentGrant(CLIENT_UID));
    }

    @Test public void corruptFormalNeverFallsBackToLegacy() throws Exception {
        Path source = legacy(true);
        Path directory = directory();
        Path target = prepare(directory, source);
        Files.write(target, new byte[]{1});
        assertThrows(IOException.class, () -> prepare(directory, source));
        assertArrayEquals(new byte[]{1}, Files.readAllBytes(target));
    }

    @Test public void markerWithMissingFormalFailsClosed() throws Exception {
        Path source = legacy(true);
        Path directory = directory();
        Files.delete(prepare(directory, source));
        IOException error = assertThrows(IOException.class, () -> prepare(directory, source));
        assertEquals("AUTH_IMPORT_STORE_MISSING", error.getMessage());
        assertFalse(Files.exists(directory.resolve("authorizations.bin")));
    }

    @Test public void validFormalWithoutMarkerIsRetainedAndMarkerCompleted() throws Exception {
        Path source = legacy(true);
        Path directory = directory();
        Path target = directory.resolve("authorizations.bin");
        Files.copy(source, target);
        byte[] original = Files.readAllBytes(target);
        Files.write(source, new byte[]{1});
        prepare(directory, source);
        assertArrayEquals(original, Files.readAllBytes(target));
        assertTrue(Files.exists(directory.resolve("import-complete")));
    }

    @Test public void corruptFormalWithoutMarkerIsNotReplaced() throws Exception {
        Path source = legacy(true);
        Path directory = directory();
        Path target = directory.resolve("authorizations.bin");
        Files.write(target, new byte[]{1});
        assertThrows(IOException.class, () -> prepare(directory, source));
        assertFalse(Files.exists(directory.resolve("import-complete")));
    }

    @Test public void markerIsBoundToFullManagerUid() throws Exception {
        Path source = legacy(true);
        Path directory = directory();
        prepare(directory, source);
        IOException error = assertThrows(IOException.class,
                () -> RootAuthorizationMigration.prepare(directory, source, 10_481, () -> {}));
        assertEquals("AUTH_IMPORT_MARKER_INVALID", error.getMessage());
    }

    @Test public void corruptLegacyLeavesNoFormalOrMarkerOrTemporary() throws Exception {
        Path directory = directory();
        Path source = directory().resolve("authorizations.bin");
        Files.write(source, new byte[]{1});
        assertThrows(IOException.class, () -> prepare(directory, source));
        try (java.util.stream.Stream<Path> files = Files.list(directory)) { assertEquals(0, files.count()); }
    }

    @Test public void oversizedLegacyIsBoundedAndNotImported() throws Exception {
        Path directory = directory();
        Path source = directory().resolve("authorizations.bin");
        Files.write(source, new byte[1024 * 1024 + 1]);
        IOException error = assertThrows(IOException.class, () -> prepare(directory, source));
        assertEquals("AUTH_STORE_TOO_LARGE", error.getMessage());
        assertFalse(Files.exists(directory.resolve("authorizations.bin")));
    }

    @Test public void nonRegularSourceAndMarkerAreRejected() throws Exception {
        Path directory = directory();
        Path source = directory();
        assertThrows(IOException.class, () -> prepare(directory, source));
        Files.createDirectory(directory.resolve("import-complete"));
        assertThrows(IOException.class, () -> prepare(directory, source));
    }

    @Test public void directorySyncFailureDoesNotClaimImportComplete() throws Exception {
        Path source = legacy(true);
        Path directory = directory();
        assertThrows(IOException.class, () -> RootAuthorizationMigration.prepare(directory, source, MANAGER_UID,
                () -> { throw new IOException("sync failure"); }));
        assertTrue(Files.exists(directory.resolve("authorizations.bin")));
        assertFalse(Files.exists(directory.resolve("import-complete")));
        byte[] original = Files.readAllBytes(directory.resolve("authorizations.bin"));
        prepare(directory, source);
        assertArrayEquals(original, Files.readAllBytes(directory.resolve("authorizations.bin")));
    }

    @Test public void directoryIsSyncedBeforeAndAfterPublishingMarker() throws Exception {
        Path source = legacy(true);
        Path directory = directory();
        AtomicInteger syncs = new AtomicInteger();
        RootAuthorizationMigration.prepare(directory, source, MANAGER_UID, () -> {
            assertTrue(Files.exists(directory.resolve("authorizations.bin")));
            syncs.incrementAndGet();
        });
        assertTrue(syncs.get() >= 2);
    }
}
