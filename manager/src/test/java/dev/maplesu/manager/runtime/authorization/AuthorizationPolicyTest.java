package dev.maplesu.manager.runtime.authorization;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class AuthorizationPolicyTest {
    @Rule public TemporaryFolder temporary = new TemporaryFolder();
    private static final int UID = 10_001;
    private static final String CERT = String.join("", Collections.nCopies(64, "a"));
    private static final String OTHER_CERT = String.join("", Collections.nCopies(64, "b"));

    private static ApplicationIdentity identity(int uid) {
        return identity(uid, "example.app", CERT, 100, 100, "/data/app/example/base.apk");
    }

    private static ApplicationIdentity identity(int uid, String name, String cert, long first, long last, String apk) {
        return new ApplicationIdentity(uid, name, Collections.singleton(name),
                Collections.singleton(cert), first, last, apk);
    }

    private Path path() throws IOException {
        return temporary.newFolder().toPath().resolve("authorization.bin");
    }

    private static void denied(AuthorizationPolicy policy, int uid) throws IOException {
        AtomicInteger starts = new AtomicInteger();
        assertThrows(SecurityException.class, () -> policy.authorizeAndStart(uid, snapshot -> starts.incrementAndGet()));
        assertEquals(0, starts.get());
    }

    @Test public void defaultDenyAndGlobalSwitchAreEnforcedAtTaskCreation() throws Exception {
        AuthorizationPolicy policy = new AuthorizationPolicy(path(), AuthorizationPolicyTest::identity);
        assertFalse(policy.isEnabled());
        denied(policy, UID);
        policy.setEnabled(true);
        denied(policy, UID);
        policy.grant(UID);
        assertEquals("started", policy.authorizeAndStart(UID, snapshot -> "started"));
        policy.setEnabled(false);
        denied(policy, UID);
        assertTrue(policy.hasCurrentGrant(UID));
        policy.setEnabled(true);
        assertEquals(UID, (int) policy.authorizeAndStart(UID, snapshot -> snapshot.uid));
    }

    @Test public void grantsGlobalSwitchAndRevocationSurviveReopening() throws Exception {
        Path file = path();
        AuthorizationPolicy policy = new AuthorizationPolicy(file, AuthorizationPolicyTest::identity);
        policy.grant(UID);
        policy.setEnabled(true);
        AuthorizationPolicy reopened = new AuthorizationPolicy(file, AuthorizationPolicyTest::identity);
        assertTrue(reopened.isEnabled());
        assertEquals(UID, (int) reopened.authorizeAndStart(UID, snapshot -> snapshot.uid));
        reopened.revoke(UID);
        denied(new AuthorizationPolicy(file, AuthorizationPolicyTest::identity), UID);
        reopened.setEnabled(false);
        assertFalse(new AuthorizationPolicy(file, AuthorizationPolicyTest::identity).isEnabled());
    }

    @Test public void grantCountExcludesUninstalledAndReplacedApplications() throws Exception {
        Map<Integer, ApplicationIdentity> current = new HashMap<>();
        current.put(UID, identity(UID));
        current.put(UID + 1, identity(UID + 1));
        AuthorizationPolicy policy = new AuthorizationPolicy(path(), current::get);
        policy.grant(UID);
        policy.grant(UID + 1);
        assertEquals(2, policy.currentGrantCount());
        current.remove(UID);
        assertEquals(1, policy.currentGrantCount());
        current.put(UID + 1, identity(UID + 1, "example.app", OTHER_CERT, 100, 100,
                "/data/app/example/base.apk"));
        assertEquals(0, policy.currentGrantCount());
    }

    @Test public void fullAndroidUidSeparatesUsersWithTheSameAppId() throws Exception {
        AuthorizationPolicy policy = new AuthorizationPolicy(path(), AuthorizationPolicyTest::identity);
        policy.grant(UID);
        policy.setEnabled(true);
        denied(policy, 110_001);
        policy.grant(110_001);
        policy.revoke(UID);
        denied(policy, UID);
        assertEquals(110_001, (int) policy.authorizeAndStart(110_001, snapshot -> snapshot.uid));
    }

    @Test public void sharedIsolatedAndNonApplicationUidsAreRejected() {
        for (int uid : new int[]{-1, 0, 2000, 9999, 20_000, 99_000, 199_000}) {
            assertThrows(IllegalArgumentException.class, () -> identity(uid));
        }
        assertThrows(IllegalArgumentException.class, () -> new ApplicationIdentity(UID, "example.app",
                Arrays.asList("example.app", "example.shared"), Collections.singleton(CERT), 100, 100, "/apk"));
        assertThrows(IllegalArgumentException.class, () -> new ApplicationIdentity(UID, "example.app",
                Collections.emptyList(), Collections.singleton(CERT), 100, 100, "/apk"));
    }

    @Test public void packageSignerUpdateReinstallAndPathChangesInvalidateGrant() throws Exception {
        Map<Integer, ApplicationIdentity> current = new HashMap<>();
        current.put(UID, identity(UID));
        AuthorizationPolicy policy = new AuthorizationPolicy(path(), current::get);
        policy.grant(UID);
        policy.setEnabled(true);
        for (ApplicationIdentity changed : Arrays.asList(
                identity(UID, "example.other", CERT, 100, 100, "/data/app/example/base.apk"),
                identity(UID, "example.app", OTHER_CERT, 100, 100, "/data/app/example/base.apk"),
                identity(UID, "example.app", CERT, 100, 200, "/data/app/example/base.apk"),
                identity(UID, "example.app", CERT, 200, 200, "/data/app/example/base.apk"),
                identity(UID, "example.app", CERT, 100, 100, "/data/app/replaced/base.apk"))) {
            current.put(UID, changed);
            assertFalse(policy.hasCurrentGrant(UID));
            denied(policy, UID);
        }
        policy.grant(UID);
        assertEquals(current.get(UID), policy.authorizeAndStart(UID, snapshot -> snapshot));
    }

    @Test public void signerSnapshotIsDefensivelyCopiedAndAllSignersMatter() throws Exception {
        Set<String> signers = new HashSet<>(Arrays.asList(CERT, OTHER_CERT));
        ApplicationIdentity original = new ApplicationIdentity(UID, "example.app",
                Collections.singleton("example.app"), signers, 100, 100, "/apk");
        signers.clear();
        assertEquals(2, original.signers.size());
        assertThrows(UnsupportedOperationException.class, () -> original.signers.clear());
        Map<Integer, ApplicationIdentity> current = new HashMap<>();
        current.put(UID, original);
        Path file = path();
        AuthorizationPolicy policy = new AuthorizationPolicy(file, current::get);
        policy.grant(UID);
        policy.setEnabled(true);
        assertEquals(original, new AuthorizationPolicy(file, current::get).authorizeAndStart(UID, value -> value));
        current.put(UID, identity(UID, "example.app", CERT, 100, 100, "/apk"));
        denied(policy, UID);
    }

    @Test public void unknownMismatchedAndFailedIdentityReadsNeverStartTasks() throws Exception {
        Map<Integer, ApplicationIdentity> current = new HashMap<>();
        current.put(UID, identity(UID));
        AuthorizationPolicy policy = new AuthorizationPolicy(path(), current::get);
        policy.grant(UID);
        policy.setEnabled(true);
        current.clear();
        denied(policy, UID);
        current.put(UID, identity(110_001));
        denied(policy, UID);
        AuthorizationPolicy failing = new AuthorizationPolicy(path(), uid -> { throw new IOException("PackageManager unavailable"); });
        failing.setEnabled(true);
        AtomicInteger starts = new AtomicInteger();
        assertThrows(IOException.class, () -> failing.authorizeAndStart(UID, snapshot -> starts.incrementAndGet()));
        assertEquals(0, starts.get());
    }

    @Test public void identityIsReadAgainImmediatelyBeforeStarting() throws Exception {
        AtomicInteger reads = new AtomicInteger();
        AuthorizationPolicy policy = new AuthorizationPolicy(path(), uid -> reads.incrementAndGet() < 3
                ? identity(uid) : identity(uid, "example.app", CERT, 100, 200, "/data/app/example/base.apk"));
        policy.grant(UID); // First trusted read.
        policy.setEnabled(true);
        denied(policy, UID); // Second read matches, third read detects the installation change.
        assertEquals(3, reads.get());
    }

    @Test public void revokeSerializesWithTheActualTaskStartAndDeniesSubsequentRequests() throws Exception {
        Path file = path();
        AuthorizationPolicy policy = new AuthorizationPolicy(file, AuthorizationPolicyTest::identity);
        policy.grant(UID);
        policy.setEnabled(true);
        CountDownLatch starting = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch revoking = new CountDownLatch(1);
        ExecutorService threads = Executors.newFixedThreadPool(2);
        try {
            Future<String> started = threads.submit(() -> policy.authorizeAndStart(UID, snapshot -> {
                starting.countDown();
                try {
                    if (!release.await(5, TimeUnit.SECONDS)) throw new IOException("test start timed out");
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    throw new IOException(error);
                }
                return "created";
            }));
            assertTrue(starting.await(5, TimeUnit.SECONDS));
            Future<?> revoked = threads.submit(() -> {
                revoking.countDown();
                policy.revoke(UID);
                return null;
            });
            assertTrue(revoking.await(5, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class, () -> revoked.get(100, TimeUnit.MILLISECONDS));
            release.countDown();
            assertEquals("created", started.get(5, TimeUnit.SECONDS));
            revoked.get(5, TimeUnit.SECONDS);
            denied(policy, UID);
            denied(new AuthorizationPolicy(file, AuthorizationPolicyTest::identity), UID);
        } finally {
            release.countDown();
            threads.shutdownNow();
            assertTrue(threads.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test public void corruptOrTruncatedPersistenceDoesNotProduceAUsablePolicy() throws Exception {
        Path file = path();
        AuthorizationPolicy policy = new AuthorizationPolicy(file, AuthorizationPolicyTest::identity);
        policy.grant(UID);
        policy.setEnabled(true);
        byte[] valid = Files.readAllBytes(file);
        byte[] changed = valid.clone();
        changed[8] ^= 1;
        Files.write(file, changed);
        assertThrows(IOException.class, () -> new AuthorizationPolicy(file, AuthorizationPolicyTest::identity));
        Files.write(file, Arrays.copyOf(valid, 10));
        assertThrows(IOException.class, () -> new AuthorizationPolicy(file, AuthorizationPolicyTest::identity));
    }

    @Test public void failedPersistenceDoesNotPublishAGrantOrGlobalSwitch() throws Exception {
        Path directory = temporary.newFolder().toPath();
        Path file = directory.resolve("authorization.bin");
        AuthorizationPolicy policy = new AuthorizationPolicy(file, AuthorizationPolicyTest::identity);
        Files.delete(directory);
        assertThrows(IOException.class, () -> policy.grant(UID));
        assertThrows(IOException.class, () -> policy.hasCurrentGrant(UID));
        assertThrows(IOException.class, () -> policy.setEnabled(true));
        assertFalse(policy.isEnabled());
    }

    @Test public void authorizedEntryCreatesARealOrdinaryProcessAndPreservesItsExitCode() throws Exception {
        AuthorizationPolicy policy = new AuthorizationPolicy(path(), AuthorizationPolicyTest::identity);
        policy.grant(UID);
        policy.setEnabled(true);
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        String childClasses = Path.of(Exit37.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        Process child = policy.authorizeAndStart(UID, snapshot -> new ProcessBuilder(java, "-cp",
                childClasses, Exit37.class.getName()).start());
        try {
            child.getOutputStream().close();
            assertTrue(child.waitFor(5, TimeUnit.SECONDS));
            assertEquals(37, child.exitValue());
        } finally {
            child.destroyForcibly();
            child.getInputStream().close();
            child.getErrorStream().close();
        }
    }

    @Test public void taskCreationFailureIsNotReportedAsAuthorizationSuccess() throws Exception {
        AuthorizationPolicy policy = new AuthorizationPolicy(path(), AuthorizationPolicyTest::identity);
        policy.grant(UID);
        policy.setEnabled(true);
        IOException failure = new IOException("process creation failed");
        assertSame(failure, assertThrows(IOException.class, () -> policy.authorizeAndStart(UID, snapshot -> { throw failure; })));
    }

    /**
     * The commit is the admission point. A request that was already authorized and
     * prepared must still be refused when the revocation won the lock first, and the
     * prepared child must never be released.
     */
    @Test public void commitIsRefusedWhenRevocationHappenedFirst() throws Exception {
        AuthorizationPolicy policy = new AuthorizationPolicy(path(), AuthorizationPolicyTest::identity);
        policy.grant(UID);
        policy.setEnabled(true);
        AtomicInteger commits = new AtomicInteger();
        assertEquals(UID, policy.authorize(UID).uid);
        policy.revoke(UID);
        assertFalse(policy.commitIfAuthorized(UID, commits::incrementAndGet));
        assertEquals(0, commits.get());
    }

    @Test public void commitIsRefusedWhenSwitchIsOffOrIdentityChanged() throws Exception {
        Path file = path();
        AuthorizationPolicy policy = new AuthorizationPolicy(file, AuthorizationPolicyTest::identity);
        AtomicInteger commits = new AtomicInteger();
        policy.grant(UID);
        assertFalse("global switch off", policy.commitIfAuthorized(UID, commits::incrementAndGet));
        policy.setEnabled(true);
        assertTrue(policy.commitIfAuthorized(UID, commits::incrementAndGet));
        assertEquals(1, commits.get());
        // The installed identity behind the granted uid changed after the grant.
        AuthorizationPolicy changed = new AuthorizationPolicy(file, uid ->
                identity(uid, "example.app", OTHER_CERT, 100, 100, "/data/app/example/base.apk"));
        assertFalse("identity changed", changed.commitIfAuthorized(UID, commits::incrementAndGet));
        assertEquals(1, commits.get());
    }

    @Test public void failingCommitIsReportedAsRefused() throws Exception {
        AuthorizationPolicy policy = new AuthorizationPolicy(path(), AuthorizationPolicyTest::identity);
        policy.grant(UID);
        policy.setEnabled(true);
        assertFalse(policy.commitIfAuthorized(UID, () -> { throw new IOException("channel closed"); }));
    }

    /** A revoke cannot interleave with the commit: the policy lock is the linearization point. */
    @Test public void revocationWaitsForAnInFlightCommit() throws Exception {
        AuthorizationPolicy policy = new AuthorizationPolicy(path(), AuthorizationPolicyTest::identity);
        policy.grant(UID);
        policy.setEnabled(true);
        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger commits = new AtomicInteger();
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> commit = executor.submit(() -> policy.commitIfAuthorized(UID, () -> {
                commits.incrementAndGet();
                inside.countDown();
                try {
                    if (!release.await(5, TimeUnit.SECONDS)) throw new IOException("test latch expired");
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted", interrupted);
                }
            }));
            assertTrue(inside.await(5, TimeUnit.SECONDS));
            Future<?> revoke = executor.submit(() -> { policy.revoke(UID); return null; });
            // The revoke must not complete while the commit still holds the lock.
            assertThrows(TimeoutException.class, () -> revoke.get(300, TimeUnit.MILLISECONDS));
            release.countDown();
            assertTrue(commit.get(5, TimeUnit.SECONDS));
            revoke.get(5, TimeUnit.SECONDS);
            assertEquals(1, commits.get());
            // Once the revocation is visible, a newly prepared request is refused.
            assertFalse(policy.commitIfAuthorized(UID, commits::incrementAndGet));
            assertEquals(1, commits.get());
        } finally {
            executor.shutdownNow();
        }
    }

    public static final class Exit37 {
        public static void main(String[] args) { System.exit(37); }
    }
}
