package dev.maplesu.manager.jailbreak;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** MJBL version 1 wire reader. No Android APIs, privilege acquisition or readiness state. */
public final class LeaseProtocol {
    private LeaseProtocol() {}

    public enum Provider {
        GHOSTLOCK(1, "ghostlock"), DIRTYFRAG(2, "dirtyfrag");
        public final int wireId;
        public final String argument;
        Provider(int wireId, String argument) { this.wireId = wireId; this.argument = argument; }
    }

    /** Values observed on the consumer transport, not proof of restored policy or daemon readiness. */
    public record Identity(Provider provider, int workerPid, int uid, String bootId,
                           String domain, int enforcing, int seccomp, long workerStarttime,
                           boolean provesWorkerIdentity) {}

    /**
     * Where the value written back to {@code /sys/fs/selinux/enforce} came from.
     * The App can read selinuxfs only when its own domain allows it; when it
     * cannot, the consumer applies the documented release baseline and labels the
     * result instead of presenting it as the observed entry policy.
     */
    public enum Origin {
        OBSERVED, BASELINE, UNKNOWN, PROVIDER;
        static Origin of(int value) throws IOException {
            switch (value) {
                case 0: return OBSERVED;
                case 1: return BASELINE;
                case 2: return UNKNOWN;
                case 3: return PROVIDER;
                default: throw new IOException("LEASE_RESTORE_ORIGIN_INVALID");
            }
        }
    }

    /**
     * Pre-entry policy restoration reported by the privileged consumer.
     *
     * <p>{@code applied} keeps the four states separate on purpose:
     * <ul>
     *   <li>1 - a value observed before the attempt was written back and read back;</li>
     *   <li>3 - the documented baseline was written back and read back (not the
     *       observed entry value, therefore never reported as "original");</li>
     *   <li>0 - the restoration failed or could not be verified;</li>
     *   <li>2 - the provider restores through its own script; nothing is proven
     *       here, and the product records it as provider-owned.</li>
     * </ul>
     */
    public record Restore(int applied, Origin origin, int enforcing, int checkreqprot,
                          int policy, int unloadErrno) {
        public boolean applicable() { return applied != 2; }
        public boolean failed() { return applied == 0; }
        /** A value was written back and read back; the policy itself did not change. */
        public boolean verified() {
            return (applied == 1 || applied == 3) && enforcing != 0xff && checkreqprot != 0xff;
        }
        public boolean observed() { return applied == 1; }
        public boolean baseline() { return applied == 3; }
        /** Handover requires at least a verified restore; an unverified one is refused. */
        public boolean admitsHandover() { return applied == 1 || applied == 3 || applied == 2; }
        /** True when the product may call this "the entry policy was restored". */
        public boolean provesEntryPolicy() { return applied == 1 && (checkreqprot == 0 || checkreqprot == 1) && policy == 0; }
        public String state() {
            switch (applied) {
                case 1: return "RESTORED_OBSERVED";
                case 3: return "RESTORED_BASELINE";
                case 2: return "PROVIDER_OWNED";
                default: return "FAILED";
            }
        }
    }

    public static Identity readIdentity(InputStream input, Provider provider, byte[] expectedNonce,
                                        String expectedBootId, int peerPid, int peerUid) throws IOException {
        if (provider == null || expectedNonce == null || expectedNonce.length != 32 ||
                !validBootId(expectedBootId)) throw new IllegalArgumentException("LEASE_EXPECTATION_INVALID");
        if (peerUid != 0 || peerPid <= 1) throw new IOException("LEASE_ROOT_PEER_REQUIRED");
        DataInputStream in = new DataInputStream(input);
        if (in.readInt() != 0x4d4a424c) throw new IOException("LEASE_MAGIC_INVALID");
        /*
         * S12: version 2 adds the worker start time and an explicit capability flag.
         * Version 1 stays readable so an older consumer is not rejected outright, but
         * only v2 can prove the worker identity (no pid reuse, root capability seen).
         */
        int version = in.readInt();
        if (version != 1 && version != 2) throw new IOException("LEASE_VERSION_INVALID");
        if (in.readInt() != provider.wireId) throw new IOException("LEASE_PROVIDER_MISMATCH");
        int pid = in.readInt();
        int uid = in.readInt();
        if (pid != peerPid || uid != peerUid) throw new IOException("LEASE_PEER_IDENTITY_MISMATCH");
        long workerStarttime = 0;
        boolean provesWorkerIdentity = false;
        if (version >= 2) {
            long high = in.readInt() & 0xffffffffL;
            long low = in.readInt() & 0xffffffffL;
            workerStarttime = (high << 32) | low;
            if (in.readInt() != 1) throw new IOException("LEASE_CAPABILITY_MISSING");
            if (workerStarttime <= 0) throw new IOException("LEASE_WORKER_STARTTIME_INVALID");
            /*
             * Measured on the reference device: the App domain cannot read /proc/<workerPid>/stat
             * of the consumer's child (the shell domain process is not visible to it),
             * so "unreadable" has to mean "the start time is present but unverified",
             * not "reject the whole lease". A readable value that differs is still a
             * hard failure (pid reuse), and only a verified match counts as proof.
             */
            long observed = workerStarttime(pid);
            if (observed > 0) {
                if (observed != workerStarttime) {
                    throw new IOException("LEASE_WORKER_STARTTIME_MISMATCH");
                }
                provesWorkerIdentity = true;
            }
        }
        byte[] nonce = new byte[32];
        in.readFully(nonce);
        if (!MessageDigest.isEqual(expectedNonce, nonce)) throw new IOException("LEASE_NONCE_MISMATCH");
        String boot = readText(in, 128);
        if (!expectedBootId.equals(boot)) throw new IOException("LEASE_BOOT_MISMATCH");
        String domain = readText(in, 256);
        int enforcing = in.readInt();
        int seccomp = in.readInt();
        if (enforcing != 0 && enforcing != 1) throw new IOException("LEASE_ENFORCING_INVALID");
        if (seccomp < 0 || seccomp > 2) throw new IOException("LEASE_SECCOMP_UNAVAILABLE");
        return new Identity(provider, pid, uid, boot, domain, enforcing, seccomp,
                workerStarttime, provesWorkerIdentity);
    }

    /**
     * Field 22 of `/proc/<pid>/stat`: the start time in clock ticks, which is what
     * makes a pid identity unique (a recycled pid has a different start time).
     * Returns -1 when the record cannot be read, so callers refuse instead of guessing.
     */
    /**
     * Where the observed start time comes from. The default reads /proc, which only
     * exists on the device; the frame tests replace it because they run on a host
     * without /proc and must still exercise both the accept and the reject path.
     */
    static java.util.function.IntFunction<Long> starttimeResolver = LeaseProtocol::readProcStarttime;

    static long workerStarttime(int pid) {
        return starttimeResolver.apply(pid);
    }

    static long readProcStarttime(int pid) {
        try {
            String stat = java.nio.file.Files.readString(java.nio.file.Path.of("/proc/" + pid + "/stat"));
            int close = stat.lastIndexOf(')');
            if (close < 0) return -1;
            String[] rest = stat.substring(close + 1).trim().split("\\s+");
            if (rest.length < 20) return -1;
            return Long.parseLong(rest[19]);
        } catch (Throwable error) {
            return -1;
        }
    }

    /**
     * Reads the shell confirmation. A consumer that failed after the provider
     * transient exists reports a failure frame instead of leaving the App in its
     * provider timeout, so the attempt can restore and report immediately.
     */
    public static int readReady(InputStream input) throws IOException {
        DataInputStream in = new DataInputStream(input);
        int tag = in.readUnsignedByte();
        if (tag == 'F') {
            int stage = in.readUnsignedByte();
            in.readFully(new byte[3]);
            throw new IOException("LEASE_CONSUMER_FAILED:" + stageName(stage));
        }
        if (tag != 'R') throw new IOException("LEASE_EXEC_NOT_CONFIRMED");
        int pid = in.readInt();
        if (pid <= 1) throw new IOException("LEASE_SHELL_PID_INVALID");
        return pid;
    }

    static String stageName(int stage) {
        switch (stage) {
            case 1: return "ARGUMENTS";
            case 2: return "ROOT_WORKER";
            case 3: return "IDENTITY";
            case 4: return "SOCKET";
            case 5: return "PEER";
            case 6: return "STDIO";
            case 7: return "EXEC";
            default: return "UNKNOWN_" + stage;
        }
    }

    /**
     * Restoration frame written by the consumer after stdio admission and before
     * the shell-exec confirmation. Reading it here keeps restoration evidence on
     * the same transport as the lease instead of a log line.
     */
    public static Restore readRestore(InputStream input) throws IOException {
        DataInputStream in = new DataInputStream(input);
        if (in.readUnsignedByte() != 'P') throw new IOException("LEASE_RESTORE_FRAME_INVALID");
        int applied = in.readUnsignedByte();
        Origin origin = Origin.of(in.readUnsignedByte());
        int enforcing = in.readUnsignedByte();
        int checkreqprot = in.readUnsignedByte();
        int policy = in.readUnsignedByte();
        int unloadErrno = in.readInt();
        if (applied > 3) throw new IOException("LEASE_RESTORE_STATE_INVALID");
        if (enforcing != 0xff && enforcing != 0 && enforcing != 1)
            throw new IOException("LEASE_RESTORE_ENFORCING_INVALID");
        // 2 is a consumer-confirmed ENOENT, used only by Ghostlock's reload
        // report. EACCES, malformed content and other errors remain 0xff.
        if (checkreqprot != 0xff && checkreqprot != 0 && checkreqprot != 1 && checkreqprot != 2)
            throw new IOException("LEASE_RESTORE_CHECKREQPROT_INVALID");
        if (checkreqprot == 2 && policy != 2)
            throw new IOException("LEASE_RESTORE_CHECKREQPROT_ABSENCE_INVALID");
        if (policy != 0 && policy != 1 && policy != 2)
            throw new IOException("LEASE_RESTORE_POLICY_INVALID");
        if (unloadErrno < -1 || unloadErrno > 0x7fffffff)
            throw new IOException("LEASE_RESTORE_ERRNO_INVALID");
        // S07: two failed reads are not a match. The boolean components must be
        // observed; the policy digest is a separate dimension that may legitimately
        // be "not compared" (Ghostlock reloads the policy).
        if (applied == 1 && (origin != Origin.OBSERVED || enforcing == 0xff ||
                checkreqprot == 0xff))
            throw new IOException("LEASE_RESTORE_READBACK_MISSING");
        if (applied == 3 && (origin != Origin.BASELINE || enforcing == 0xff ||
                checkreqprot == 0xff))
            throw new IOException("LEASE_RESTORE_BASELINE_READBACK_MISSING");
        if (applied == 2 && origin != Origin.PROVIDER)
            throw new IOException("LEASE_RESTORE_OWNER_INVALID");
        if (applied == 0 && origin == Origin.UNKNOWN && enforcing != 0xff)
            throw new IOException("LEASE_RESTORE_CONTRADICTION");
        if (policy == 1 && applied != 0)
            throw new IOException("LEASE_RESTORE_POLICY_CHANGED");
        return new Restore(applied, origin, enforcing, checkreqprot, policy, unloadErrno);
    }

    /** EOF or any other frame is a transport failure, never a normal exit. */
    public static int readExit(InputStream input) throws IOException {
        DataInputStream in = new DataInputStream(input);
        if (in.readUnsignedByte() != 'X') throw new IOException("LEASE_EXIT_FRAME_INVALID");
        int code = in.readInt();
        if (code < 0 || code > 255) throw new IOException("LEASE_EXIT_CODE_INVALID");
        return code;
    }

    public static boolean validBootId(String value) {
        return value != null && value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    }

    private static String readText(DataInputStream input, int maximum) throws IOException {
        int length = input.readInt();
        if (length <= 0 || length > maximum) throw new IOException("LEASE_FIELD_LENGTH_INVALID");
        byte[] data = new byte[length];
        input.readFully(data);
        final String value;
        try {
            value = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(data)).toString();
        } catch (CharacterCodingException error) {
            throw new IOException("LEASE_FIELD_ENCODING_INVALID", error);
        }
        if (value.indexOf('\0') >= 0 || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0)
            throw new IOException("LEASE_FIELD_CONTENT_INVALID");
        return value;
    }
}
