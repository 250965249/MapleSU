package dev.maplesu.manager.runtime.authorization;

import java.util.Collection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/** Immutable complete installation set for one OS-supplied full UID. */
public final class ApplicationIdentity {
    public static final int MAX_PACKAGES = 1024;
    public final int uid;
    public final Map<String, Installation> members;
    // Stable representative for legacy display/profile fields, never a separate grant.
    public final String packageName;
    public final Set<String> signers;
    public final long firstInstallTime;
    public final long lastUpdateTime;
    public final String apkPath;

    /** Legacy input has facts for exactly one package; it cannot assert a shared-UID set. */
    public ApplicationIdentity(int uid, String packageName, Collection<String> packagesForUid,
            Set<String> signers, long firstInstallTime, long lastUpdateTime, String apkPath) {
        this(uid, Collections.singletonList(new Installation(packageName, signers,
                firstInstallTime, lastUpdateTime, apkPath)));
        Collection<String> packages = packagesForUid == null ? Collections.emptyList() : new ArrayList<>(packagesForUid);
        if (packages.size() != 1 || !packages.contains(packageName)) {
            throw new IllegalArgumentException("AUTH_IDENTITY_INVALID");
        }
    }

    public ApplicationIdentity(int uid, Collection<Installation> installations) {
        if (uid < 0 || uid % 100_000 < 10_000 || uid % 100_000 > 19_999
                || installations == null || installations.isEmpty() || installations.size() > MAX_PACKAGES) {
            throw new IllegalArgumentException("AUTH_IDENTITY_INVALID");
        }
        TreeMap<String, Installation> snapshot = new TreeMap<>();
        for (Installation member : installations) {
            if (member == null || snapshot.put(member.packageName, member) != null) {
                throw new IllegalArgumentException("AUTH_IDENTITY_INVALID");
            }
        }
        this.uid = uid;
        this.members = Collections.unmodifiableMap(snapshot);
        Installation representative = snapshot.firstEntry().getValue();
        this.packageName = representative.packageName;
        this.signers = representative.signers;
        this.firstInstallTime = representative.firstInstallTime;
        this.lastUpdateTime = representative.lastUpdateTime;
        this.apkPath = representative.apkPath;
    }

    /** Grant match: an installed member may update, but may not change UID, membership, signer or install epoch. */
    public boolean matches(ApplicationIdentity current) {
        if (current == null || uid != current.uid || !members.keySet().equals(current.members.keySet())) return false;
        for (Installation recorded : members.values()) {
            Installation installed = current.members.get(recorded.packageName);
            if (recorded.firstInstallTime != installed.firstInstallTime || !recorded.signers.equals(installed.signers)) return false;
        }
        return true;
    }

    /** Exact snapshot equality, including update/path facts, remains the CAS/read-consistency check. */
    @Override public boolean equals(Object other) {
        if (!(other instanceof ApplicationIdentity)) return false;
        ApplicationIdentity value = (ApplicationIdentity) other;
        return uid == value.uid && members.equals(value.members);
    }

    @Override public int hashCode() {
        return Objects.hash(uid, members);
    }

    /** Facts for each installed member; every member participates in grant equality. */
    public static final class Installation {
        public final String packageName;
        public final Set<String> signers;
        public final long firstInstallTime;
        public final long lastUpdateTime;
        public final String apkPath;

        public Installation(String packageName, Set<String> signers, long firstInstallTime,
                long lastUpdateTime, String apkPath) {
            Set<String> signerSnapshot = signers == null ? Collections.emptySet() : new HashSet<>(signers);
            if (packageName == null || packageName.trim().isEmpty() || signerSnapshot.isEmpty()
                    || signerSnapshot.stream().anyMatch(value -> value == null || !value.matches("[0-9a-f]{64}"))
                    || firstInstallTime <= 0 || lastUpdateTime < firstInstallTime
                    || apkPath == null || !apkPath.startsWith("/")) {
                throw new IllegalArgumentException("AUTH_IDENTITY_INVALID");
            }
            this.packageName = packageName;
            this.signers = Collections.unmodifiableSet(signerSnapshot);
            this.firstInstallTime = firstInstallTime;
            this.lastUpdateTime = lastUpdateTime;
            this.apkPath = apkPath;
        }

        @Override public boolean equals(Object other) {
            if (!(other instanceof Installation)) return false;
            Installation value = (Installation) other;
            return packageName.equals(value.packageName) && signers.equals(value.signers)
                    && firstInstallTime == value.firstInstallTime && lastUpdateTime == value.lastUpdateTime
                    && apkPath.equals(value.apkPath);
        }

        @Override public int hashCode() {
            return Objects.hash(packageName, signers, firstInstallTime, lastUpdateTime, apkPath);
        }
    }
}
