package dev.maplesu.manager.runtime.authorization;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;

/**
 * The Normal (restricted Binder) facade over the one authority.
 *
 * <p>Its public surface is unchanged on purpose: `NativeSuBinder` and the resident
 * management service keep calling `authorize` / `commitIfAuthorized` / `grant` /
 * `revoke` / `setEnabled`, and therefore read the same list and the same refusal codes as
 * the Ultra endpoint without a single line of change on their side (design §1.2).
 *
 * <p>What changed inside:
 *
 *  - every decision now delegates to {@link ManagerSuperuserPolicy} over a snapshot that
 *    includes the journal (revisions and tombstone watermarks), so a revoke cannot be
 *    resurrected by a record that survived a crash;
 *  - the store is re-read before each decision instead of being cached for the life of
 *    the process, because grants and revokes are written by a one-shot root tool in
 *    another process - a cache is exactly how a revoked application kept its access;
 *  - writes go through {@link SuperuserTransaction} (journal -> bin -> applied), so the
 *    UI path (`AuthorizationTool`) and the resident path produce identical revisions.
 */
public final class AuthorizationPolicy {
    public interface TrustedIdentityProvider {
        /** Resolve the OS-supplied full calling UID; return null when its package identity is unknown. */
        ApplicationIdentity read(int callingUid) throws IOException;
    }

    public interface TaskStarter<T> {
        /** Create the task and return its handle promptly; do not wait for the task to finish here. */
        T start(ApplicationIdentity identity) throws IOException;
    }

    private static final String ORIGIN = "normal";

    private final Object lock = new Object();
    private final TrustedIdentityProvider identities;
    private final FileAuthorizationStore store;
    private final Path privateStore;
    private final Path journalFile;
    private final SuperuserTransaction transaction;
    private FileAuthorizationStore.State state;

    public AuthorizationPolicy(Path privateStore, TrustedIdentityProvider identities) throws IOException {
        this.identities = Objects.requireNonNull(identities);
        this.privateStore = Objects.requireNonNull(privateStore).toAbsolutePath();
        // Same root-only directory as the binary store: the journal inherits its 0700/0600
        // protection, and both files are read/written by the same owner.
        this.journalFile = this.privateStore.getParent() == null ? null
                : this.privateStore.getParent().resolve(SuperuserJournalStore.FILE);
        store = new FileAuthorizationStore(this.privateStore);
        state = store.load();
        transaction = SuperuserTransactions.local(this.privateStore);
    }

    /** Management-only operation: its IPC adapter must first authenticate the Manager. */
    public void setEnabled(boolean enabled) throws IOException {
        synchronized (lock) {
            SuperuserTransaction.Outcome outcome = transaction.setEnabled(enabled, ORIGIN);
            if (!outcome.getOk()) throw new IOException(outcome.getCode());
            refresh();
        }
    }

    public boolean isEnabled() {
        synchronized (lock) {
            try {
                AuthorizationSnapshot current = snapshot();
                return current.getEnabled() && !current.getCorrupt();
            } catch (IOException error) {
                // An unreadable store is "off": fail-closed, and never a cached "on".
                return false;
            }
        }
    }

    /** Persist a grant for the current trusted installation, even when the global switch is off. */
    public void grant(int uid) throws IOException {
        synchronized (lock) {
            ApplicationIdentity identity = readIdentity(uid);
            SuperuserTransaction.Outcome outcome = transaction.grant(identity, ORIGIN);
            if (!outcome.getOk()) throw new IOException(outcome.getCode());
            refresh();
        }
    }

    /** Blocks future task creation after this returns; already started tasks retain their capabilities. */
    public void revoke(int uid) throws IOException {
        synchronized (lock) {
            ApplicationIdentity recorded = state.grants.get(uid);
            String packageName = recorded == null ? null : recorded.packageName;
            SuperuserTransaction.Outcome outcome = transaction.revoke(uid, packageName, ORIGIN);
            if (!outcome.getOk()) throw new IOException(outcome.getCode());
            refresh();
        }
    }

    public boolean hasCurrentGrant(int uid) throws IOException {
        synchronized (lock) {
            refresh();
            if (revoked(uid)) return false;
            ApplicationIdentity current = identities.read(uid);
            // A persisted record outlives its application: an uninstalled or replaced
            // package has no identity any more. That is "not granted", not an error, and
            // dereferencing the missing identity here used to throw on every list load.
            return state.grants.get(uid) != null && state.grants.get(uid).matches(current);
        }
    }

    /**
     * Uids with a persisted record. A caller that needs today's answer must still check
     * {@link #hasCurrentGrant(int)} for each, because a record survives a reinstall.
     */
    public java.util.Set<Integer> grantedUids() {
        synchronized (lock) { return new java.util.HashSet<>(state.grants.keySet()); }
    }

    /** Count only grants which still refer to the same installed package and complete signer set. */
    public int currentGrantCount() throws IOException {
        synchronized (lock) {
            refresh();
            int count = 0;
            for (java.util.Map.Entry<Integer, ApplicationIdentity> grant : state.grants.entrySet()) {
                if (revoked(grant.getKey())) continue;
                ApplicationIdentity current = identities.read(grant.getKey());
                if (grant.getValue().matches(current)) count++;
            }
            return count;
        }
    }

    /**
     * Authorization decision only, taken under the same lock as every other operation.
     *
     * <p>Split out so a caller that must perform a slow step (forking a Root child,
     * a PTY handshake) does not hold the policy lock for that whole step: the lock
     * used to serialise every session start behind up to ten seconds of process
     * setup, which also blocked grant/revoke and the global switch. The caller is
     * required to re-check with {@link #commitIfAuthorized} after the slow step so
     * a revoke or a switch-off that lands during setup still fails the request.
     *
     * <p>callingUid must come from Binder/peer credentials, not an untrusted request
     * field.
     */
    public ApplicationIdentity authorize(int callingUid) throws IOException {
        synchronized (lock) {
            AuthorizationSnapshot authority = snapshot();
            if (!authority.getEnabled()) throw new SecurityException("AUTH_DISABLED");
            if (authority.revoked(callingUid)) throw new SecurityException("AUTH_NOT_GRANTED");
            ApplicationIdentity current = readIdentity(callingUid);
            Decision decision = ManagerSuperuserPolicy.decide(authority, callingUid, current);
            if (!decision.getAllowed()) throw new SecurityException(decision.getReason());
            // Read again: a replacement that lands between the two reads must not be
            // admitted under the old identity. Kept from the original policy.
            if (!current.equals(readIdentity(callingUid))) {
                throw new SecurityException("AUTH_IDENTITY_CHANGED");
            }
            return current;
        }
    }

    /**
     * Admission linearization point: re-decide the request and, in the same critical
     * section, release an already-prepared Root session.
     *
     * <p>A prepared session has forked its child but the user command is still
     * blocked before exec, so nothing observable has happened yet. A revoke or a
     * switch-off that completed before this call makes it return {@code false} and
     * the prepared session is discarded without ever running the command; one that
     * completes afterwards observes an admitted session. The commit itself must be a
     * single non-blocking write to an existing private channel - no fork, no wait, no
     * read - so the lock is never held across process setup.
     *
     * <p>callingUid must come from Binder/peer credentials, not an untrusted request
     * field.
     */
    /** Root owner only: preserves the authenticated Manager's existing self policy. */
    public ApplicationIdentity authorizeSelf(int managerUid) throws IOException {
        synchronized (lock) {
            Decision decision = ManagerSuperuserPolicy.decideSelf(snapshot());
            if (!decision.getAllowed()) throw new SecurityException(decision.getReason());
            return readIdentity(managerUid);
        }
    }

    public interface Commit {
        void commit() throws IOException;
    }

    public boolean commitIfAuthorized(int callingUid, Commit commit) {
        return commitObserved(callingUid, null, commit, false);
    }

    /** A prepared request remains bound to the exact observed installation it admitted. */
    public boolean commitIfAuthorized(int callingUid, ApplicationIdentity expected, Commit commit) {
        Objects.requireNonNull(expected);
        return commitObserved(callingUid, expected, commit, false);
    }

    /** Root owner must supply its authenticated Manager UID, never a request field. */
    public boolean commitSelfIfEnabled(int managerUid, ApplicationIdentity expected, Commit commit) {
        Objects.requireNonNull(expected);
        return commitObserved(managerUid, expected, commit, true);
    }

    private boolean commitObserved(int callingUid, ApplicationIdentity expected, Commit commit, boolean self) {
        synchronized (lock) {
            try (SuperuserJournalStore.CloseableLock ignored =
                    SuperuserJournalStore.acquire(privateStore.getParent().toFile())) {
                AuthorizationSnapshot authority = snapshot();
                if (!authority.getEnabled()) return false;
                if (!self && authority.revoked(callingUid)) return false;
                ApplicationIdentity current = readIdentity(callingUid);
                if (expected != null && (expected.uid != callingUid || !expected.equals(current))) return false;
                if (!(self ? ManagerSuperuserPolicy.decideSelf(authority)
                        : ManagerSuperuserPolicy.decide(authority, callingUid, current)).getAllowed()) {
                    return false;
                }
                commit.commit();
                return true;
            } catch (SecurityException | IOException error) {
                return false;
            }
        }
    }

    /** callingUid must come from Binder/peer credentials, not an untrusted request field. */
    public <T> T authorizeAndStart(int callingUid, TaskStarter<T> starter) throws IOException {
        Objects.requireNonNull(starter);
        synchronized (lock) {
            try (SuperuserJournalStore.CloseableLock ignored =
                    SuperuserJournalStore.acquire(privateStore.getParent().toFile())) {
                ApplicationIdentity current = authorize(callingUid);
                return starter.start(current);
            }
        }
    }

    private ApplicationIdentity readIdentity(int uid) throws IOException {
        ApplicationIdentity identity = identities.read(uid);
        if (identity == null || identity.uid != uid)
            throw new SecurityException("AUTH_IDENTITY_UNAVAILABLE");
        return identity;
    }

    /** The design's revocation predicate, read from the journal next to the store. */
    private boolean revoked(int uid) throws IOException {
        if (journalFile == null) return false;
        return SuperuserJournalStore.revoked(journalFile.toFile(), uid);
    }

    private void refresh() throws IOException {
        state = store.load();
    }

    /** One decision's worth of facts: the binary decision plus the journal's revisions. */
    private AuthorizationSnapshot snapshot() throws IOException {
        if (journalFile == null) return AuthorizationsSnapshot.empty();
        return AuthorizationsSnapshot.load(privateStore, journalFile.toFile());
    }
}
