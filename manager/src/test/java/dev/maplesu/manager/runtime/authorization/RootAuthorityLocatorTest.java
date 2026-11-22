package dev.maplesu.manager.runtime.authorization;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import static org.junit.Assert.*;

public class RootAuthorityLocatorTest {
    @Rule public TemporaryFolder temporary = new TemporaryFolder();
    private static final int MANAGER_UID = 10_498;
    private static final int OLD_UID = 10_481;
    // Host tests exercise selection and real files/locks/rename, not root ownership or SELinux.
    private static final RootAuthorityLocator.Guard GUARD = new RootAuthorityLocator.Guard() {
        public void directory(Path path) throws IOException {
            if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException("TEST_DIRECTORY");
        }
        public void file(Path path) throws IOException {
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException("TEST_FILE");
        }
        public InputStream read(Path path) throws IOException {
            return Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
        }
        public void sync(Path directory) {}
    };
    private static final RootAuthorityLocator.Initializer INITIALIZE = (directory, uid) -> {
        if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) Files.createDirectory(directory);
    };

    private Path root() throws IOException { return temporary.newFolder().toPath(); }
    private static Path source(Path root, int uid) throws IOException {
        return Files.createDirectory(root.resolve(Integer.toString(uid)));
    }
    private static Path resolve(Path root, int uid) throws IOException {
        return RootAuthorityLocator.resolve(root, uid, GUARD, INITIALIZE);
    }
    private Path identity(Path path) throws IOException {
        return Files.createLink(temporary.newFolder().toPath().resolve("reference"), path);
    }

    @Test public void currentManagerExistingAuthorityWinsOverOlderInstallationsWithoutChangingData() throws Exception {
        Path root = root(), old = source(root, OLD_UID), current = source(root, MANAGER_UID);
        Path bin = current.resolve("authorizations.bin"), journal = current.resolve("superuser.journal");
        byte[] binBytes = {1, 4, 9, 8}, journalBytes = {8, 9, 4, 1};
        Files.write(bin, binBytes); Files.write(journal, journalBytes);
        Path lock = Files.createFile(current.resolve("superuser.journal.lock"));
        Path binReference = identity(bin), journalReference = identity(journal), lockReference = identity(lock);
        assertEquals(current, resolve(root, MANAGER_UID));
        assertArrayEquals(binBytes, Files.readAllBytes(bin));
        assertArrayEquals(journalBytes, Files.readAllBytes(journal));
        assertTrue(Files.isSameFile(binReference, bin));
        assertTrue(Files.isSameFile(journalReference, journal));
        assertTrue(Files.isSameFile(lockReference, lock));
        assertTrue(Files.isDirectory(old));
    }

    @Test public void publishedLocatorRemainsSelectedWhenHistoricalDirectoryAppears() throws Exception {
        Path root = root(), selected = source(root, MANAGER_UID);
        assertEquals(selected, resolve(root, MANAGER_UID));
        Path locator = root.resolve("user-0.authority"), lock = root.resolve("user-0.authority.lock");
        byte[] bytes = Files.readAllBytes(locator);
        Path locatorReference = identity(locator), lockReference = identity(lock);
        source(root, OLD_UID);
        assertEquals(selected, resolve(root, MANAGER_UID));
        assertArrayEquals(bytes, Files.readAllBytes(locator));
        assertTrue(Files.isSameFile(locatorReference, locator));
        assertTrue(Files.isSameFile(lockReference, lock));
    }

    @Test public void publishedLocatorDoesNotSwitchToChangedManagerUid() throws Exception {
        Path root = root(), selected = source(root, OLD_UID);
        assertEquals(selected, resolve(root, OLD_UID));
        source(root, MANAGER_UID);
        assertEquals(selected, resolve(root, MANAGER_UID));
    }

    @Test public void uniqueHistoricalAuthorityIsRetained() throws Exception {
        Path root = root(), selected = source(root, OLD_UID);
        assertEquals(selected, resolve(root, MANAGER_UID));
    }

    @Test public void ambiguousHistoryWithoutCurrentAuthorityFailsWithoutCreatingEmptySource() throws Exception {
        Path root = root(); source(root, OLD_UID); source(root, 10_490);
        IOException failure = assertThrows(IOException.class, () -> resolve(root, MANAGER_UID));
        assertEquals("AUTH_AUTHORITY_CONFLICT", failure.getMessage());
        assertFalse(Files.exists(root.resolve(Integer.toString(MANAGER_UID))));
        assertFalse(Files.exists(root.resolve("user-0.authority")));
    }

    @Test public void missingPublishedSourceDoesNotSwitchToAnotherExistingAuthority() throws Exception {
        Path root = root(), selected = source(root, OLD_UID);
        assertEquals(selected, resolve(root, OLD_UID));
        Files.delete(selected); source(root, MANAGER_UID);
        IOException failure = assertThrows(IOException.class, () -> resolve(root, MANAGER_UID));
        assertEquals("AUTH_AUTHORITY_SOURCE_MISSING", failure.getMessage());
    }

    @Test public void otherAndroidUserHistoryDoesNotInterfere() throws Exception {
        Path root = root(), selected = source(root, MANAGER_UID);
        source(root, 110_481); source(root, 110_498);
        assertEquals(selected, resolve(root, MANAGER_UID));
    }

    @Test public void missingLocatorWithoutInitializerStillFails() throws Exception {
        Path root = root(); source(root, MANAGER_UID);
        IOException failure = assertThrows(IOException.class,
                () -> RootAuthorityLocator.resolve(root, MANAGER_UID, GUARD, null));
        assertEquals("AUTH_AUTHORITY_LOCATOR_MISSING", failure.getMessage());
    }

    @Test public void freshInstallationCreatesCurrentManagerAuthority() throws Exception {
        Path root = root();
        assertEquals(root.resolve(Integer.toString(MANAGER_UID)), resolve(root, MANAGER_UID));
    }
}
