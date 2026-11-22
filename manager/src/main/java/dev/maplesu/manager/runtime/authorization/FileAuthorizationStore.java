package dev.maplesu.manager.runtime.authorization;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/** Private service-owned storage; malformed, truncated or non-atomic storage fails closed. */
final class FileAuthorizationStore {
    private static final int MAGIC = 0x4d535541;
    private static final int MAX_BYTES = 1024 * 1024;
    private static final int MAX_GRANTS = 10_000;
    private final Path file;

    static final class State {
        final boolean enabled;
        final Map<Integer, ApplicationIdentity> grants;
        final Map<Integer, StoredSuProfile> profiles;
        State(boolean enabled, Map<Integer, ApplicationIdentity> grants) {
            this(enabled, grants, Collections.emptyMap());
        }
        State(boolean enabled, Map<Integer, ApplicationIdentity> grants, Map<Integer, StoredSuProfile> profiles) {
            this.enabled = enabled;
            this.grants = Collections.unmodifiableMap(new HashMap<>(grants));
            this.profiles = Collections.unmodifiableMap(new HashMap<>(profiles));
        }
    }

    FileAuthorizationStore(Path file) {
        this.file = file.toAbsolutePath().normalize();
    }

    State load() throws IOException {
        if (!Files.exists(file)) return new State(false, Collections.emptyMap());
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (InputStream input = Files.newInputStream(file)) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (bytes.size() + count > MAX_BYTES) throw new IOException("AUTH_STORE_TOO_LARGE");
                bytes.write(buffer, 0, count);
            }
        }
        byte[] encoded = bytes.toByteArray();
        if (encoded.length < 32) throw new IOException("AUTH_STORE_TRUNCATED");
        byte[] body = Arrays.copyOf(encoded, encoded.length - 32);
        if (!MessageDigest.isEqual(digest(body), Arrays.copyOfRange(encoded, body.length, encoded.length)))
            throw new IOException("AUTH_STORE_CORRUPT");
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
            if (input.readInt() != MAGIC) throw new IOException("AUTH_STORE_VERSION");
            int version = input.readInt();
            if (version != 1 && version != 2 && version != 3) throw new IOException("AUTH_STORE_VERSION");
            int enabled = input.readUnsignedByte();
            int count = input.readInt();
            if (enabled > 1 || count < 0 || count > MAX_GRANTS) throw new IOException("AUTH_STORE_INVALID");
            Map<Integer, ApplicationIdentity> grants = new HashMap<>();
            for (int i = 0; i < count; i++) {
                ApplicationIdentity identity = readIdentity(input, version);
                if (grants.put(identity.uid, identity) != null) throw new IOException("AUTH_STORE_DUPLICATE_UID");
            }
            Map<Integer, StoredSuProfile> profiles = new HashMap<>();
            if (version == 3) {
                int countProfiles = input.readInt();
                if (countProfiles < 1 || countProfiles > MAX_GRANTS) throw new IOException("AUTH_STORE_PROFILES");
                for (int i = 0; i < countProfiles; i++) {
                    ApplicationIdentity identity = readIdentity(input, 2);
                    SuProfile profile = readProfile(input, identity.uid);
                    if (profiles.put(identity.uid, new StoredSuProfile(identity, profile)) != null)
                        throw new IOException("AUTH_STORE_DUPLICATE_PROFILE");
                }
            }
            if (input.available() != 0) throw new IOException("AUTH_STORE_TRAILING_DATA");
            State state = new State(enabled == 1, grants, profiles);
            validateProfiles(state);
            return state;
        } catch (IllegalArgumentException exception) {
            throw new IOException("AUTH_STORE_IDENTITY_INVALID", exception);
        }
    }

    void save(State state) throws IOException {
        if (state.grants.size() > MAX_GRANTS || state.profiles.size() > MAX_GRANTS) throw new IOException("AUTH_STORE_TOO_LARGE");
        validateProfiles(state);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(MAGIC);
            output.writeInt(state.profiles.isEmpty() ? 2 : 3);
            output.writeBoolean(state.enabled);
            output.writeInt(state.grants.size());
            for (ApplicationIdentity identity : new TreeMap<>(state.grants).values()) writeIdentity(output, identity);
            if (!state.profiles.isEmpty()) {
                output.writeInt(state.profiles.size());
                for (StoredSuProfile record : new TreeMap<>(state.profiles).values()) {
                    writeIdentity(output, record.getIdentity());
                    writeProfile(output, record.getProfile());
                }
            }
        }
        byte[] body = bytes.toByteArray();
        if (body.length > MAX_BYTES - 32) throw new IOException("AUTH_STORE_TOO_LARGE");
        Path temporary = createTemporary(file.getParent(), "maplesu-auth-");
        Throwable failure = null;
        try {
            try (FileOutputStream output = new FileOutputStream(temporary.toFile())) {
                output.write(body);
                output.write(digest(body));
                output.getFD().sync();
            }
            AuthorizationDurability.atomicReplace(temporary, file);
        } catch (IOException | RuntimeException | Error error) {
            failure = error;
            throw error;
        } finally {
            try { Files.deleteIfExists(temporary); }
            catch (IOException cleanup) {
                if (failure != null) failure.addSuppressed(cleanup);
                else throw cleanup;
            }
        }
    }

    private static ApplicationIdentity readIdentity(DataInputStream input, int version) throws IOException {
        int uid = input.readInt();
        int memberCount = version == 1 ? 1 : input.readInt();
        if (memberCount < 1 || memberCount > ApplicationIdentity.MAX_PACKAGES) throw new IOException("AUTH_STORE_MEMBERS");
        ArrayList<ApplicationIdentity.Installation> members = new ArrayList<>(memberCount);
        for (int member = 0; member < memberCount; member++) {
            String name = input.readUTF();
            long installed = input.readLong();
            long updated = input.readLong();
            String apk = input.readUTF();
            int signerCount = input.readInt();
            if (signerCount < 1 || signerCount > 32) throw new IOException("AUTH_STORE_SIGNERS");
            TreeSet<String> signers = new TreeSet<>();
            for (int j = 0; j < signerCount; j++)
                if (!signers.add(input.readUTF())) throw new IOException("AUTH_STORE_DUPLICATE_SIGNER");
            members.add(new ApplicationIdentity.Installation(name, signers, installed, updated, apk));
        }
        return new ApplicationIdentity(uid, members);
    }

    private static void writeIdentity(DataOutputStream output, ApplicationIdentity identity) throws IOException {
        output.writeInt(identity.uid);
        output.writeInt(identity.members.size());
        for (ApplicationIdentity.Installation member : identity.members.values()) {
            output.writeUTF(member.packageName);
            output.writeLong(member.firstInstallTime);
            output.writeLong(member.lastUpdateTime);
            output.writeUTF(member.apkPath);
            if (member.signers.size() > 32) throw new IOException("AUTH_STORE_SIGNERS");
            output.writeInt(member.signers.size());
            for (String signer : new TreeSet<>(member.signers)) output.writeUTF(signer);
        }
    }

    private static boolean readBoolean(DataInputStream input) throws IOException {
        int value = input.readUnsignedByte();
        if (value > 1) throw new IOException("AUTH_STORE_PROFILE_BOOLEAN");
        return value != 0;
    }

    private static ArrayList<Integer> readIds(DataInputStream input, int limit) throws IOException {
        int count = input.readInt();
        if (count < 0 || count > limit) throw new IOException("AUTH_STORE_PROFILE_COUNT");
        ArrayList<Integer> ids = new ArrayList<>(count);
        for (int i = 0; i < count; i++) ids.add(input.readInt());
        return ids;
    }

    private static SuProfile readProfile(DataInputStream input, int uid) throws IOException {
        int version = input.readInt();
        if (version != SuProfile.VERSION) throw new IOException("AUTH_STORE_PROFILE_VERSION");
        String name = input.readUTF();
        boolean allow = readBoolean(input), rootDefault = readBoolean(input);
        String template = readBoolean(input) ? input.readUTF() : null;
        int targetUid = input.readInt(), targetGid = input.readInt();
        ArrayList<Integer> groups = readIds(input, 32), caps = readIds(input, 64);
        return new SuProfile(name, uid, allow, rootDefault, template, targetUid, targetGid, groups, caps,
                input.readUTF(), input.readInt(), readBoolean(input), readBoolean(input), input.readLong(), version).validated();
    }

    private static void writeProfile(DataOutputStream output, SuProfile profile) throws IOException {
        profile.validated();
        output.writeInt(profile.getVersion()); output.writeUTF(profile.getName());
        output.writeBoolean(profile.getAllowSu()); output.writeBoolean(profile.getRootUseDefault());
        output.writeBoolean(profile.getRootTemplate() != null);
        if (profile.getRootTemplate() != null) output.writeUTF(profile.getRootTemplate());
        output.writeInt(profile.getUid()); output.writeInt(profile.getGid());
        output.writeInt(profile.getGroups().size());
        for (int group : profile.getGroups()) output.writeInt(group);
        output.writeInt(profile.getCapabilities().size());
        for (int cap : profile.getCapabilities()) output.writeInt(cap);
        output.writeUTF(profile.getContext()); output.writeInt(profile.getNamespace());
        output.writeBoolean(profile.getNonRootUseDefault()); output.writeBoolean(profile.getUmountModules());
        output.writeLong(profile.getFlags());
    }

    private static void validateProfiles(State state) throws IOException {
        try {
            for (Map.Entry<Integer, StoredSuProfile> entry : state.profiles.entrySet()) {
                StoredSuProfile record = entry.getValue();
                SuProfile profile = record.getProfile().validated();
                ApplicationIdentity identity = record.getIdentity();
                if (entry.getKey() != identity.uid || profile.getCurrentUid() != identity.uid ||
                        !identity.members.containsKey(profile.getName()) ||
                        (profile.getAllowSu() ? !identity.equals(state.grants.get(identity.uid)) : state.grants.containsKey(identity.uid)))
                    throw new IOException("AUTH_STORE_PROFILE_IDENTITY");
            }
        } catch (IllegalArgumentException error) { throw new IOException("AUTH_STORE_PROFILE_INVALID", error); }
    }

    static Path createTemporary(Path directory, String prefix) throws IOException {
        // Request the POSIX mode directly. Probing FileStore is not reliable inside the Root endpoint:
        // Files.getFileStore throws SecurityException there, which previously aborted NativeSuDaemonService.onCreate
        // before onBind could publish the management endpoint and left every client blocked in prepare.
        // Android/Linux always takes the first branch, so the private 0600 mode stays enforced on device.
        try {
            return Files.createTempFile(directory, prefix, ".tmp",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } catch (UnsupportedOperationException unsupported) {
            // Non-POSIX host (host JVM tests only); the platform has no mode to set.
            return Files.createTempFile(directory, prefix, ".tmp");
        }
    }

    private static byte[] digest(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
