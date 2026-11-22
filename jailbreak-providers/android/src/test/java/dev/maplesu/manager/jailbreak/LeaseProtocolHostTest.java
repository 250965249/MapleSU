package dev.maplesu.manager.jailbreak;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Plain host main: tests production parsing, with no Android stubs or device privileges. */
public final class LeaseProtocolHostTest {
    private static final String BOOT = "5334f916-9a56-4267-8d79-cb67a4782ece";
    private static final byte[] NONCE = new byte[32];
    private static int checks;
    @FunctionalInterface private interface Action { void run() throws Exception; }

    public static void main(String[] args) throws Exception {
        Arrays.fill(NONCE, (byte) 0xa5);
        for (LeaseProtocol.Provider provider : LeaseProtocol.Provider.values()) {
            byte[] frame = frame(provider, BOOT, "u:r:su:s0", 1, 2);
            LeaseProtocol.Identity id = identity(frame, provider, NONCE, 2345, 0);
            check(id.provider() == provider && id.workerPid() == 2345 && id.uid() == 0,
                    "actual peer identity");
            check(id.bootId().equals(BOOT) && id.domain().equals("u:r:su:s0") &&
                    id.enforcing() == 1 && id.seccomp() == 2, "wire observations");
            byte[] raw = frame(provider, BOOT, "u:r:untrusted_app:s0:c1,c2", 0, 0);
            check(identity(raw, provider, NONCE, 2345, 0).enforcing() == 0,
                    "raw lease does not claim restored enforcing or privileged domain");
            reject(() -> identity(frame, provider, NONCE, 2345, 2000), "shell UID");
            reject(() -> identity(frame, provider, NONCE, 1, 0), "init PID");
            reject(() -> identity(frame, provider, NONCE, 2346, 0), "announced PID mismatch");
            byte[] wrong = frame.clone(); wrong[19] = 1; byte[] uid = wrong;
            reject(() -> identity(uid, provider, NONCE, 2345, 0), "announced UID mismatch");
            wrong = frame.clone(); wrong[0] ^= 1; byte[] magic = wrong;
            reject(() -> identity(magic, provider, NONCE, 2345, 0), "magic");
            wrong = frame.clone(); wrong[7] = 2; byte[] version = wrong;
            reject(() -> identity(version, provider, NONCE, 2345, 0), "version");
            LeaseProtocol.Provider other = provider == LeaseProtocol.Provider.GHOSTLOCK ?
                    LeaseProtocol.Provider.DIRTYFRAG : LeaseProtocol.Provider.GHOSTLOCK;
            reject(() -> identity(frame, other, NONCE, 2345, 0), "provider mismatch");
            for (int position : new int[]{0, 15, 31}) {
                byte[] nonce = NONCE.clone(); nonce[position] ^= 1;
                reject(() -> identity(frame, provider, nonce, 2345, 0), "nonce mismatch");
            }
            for (int length = 0; length < frame.length; length++) {
                byte[] truncated = Arrays.copyOf(frame, length);
                reject(() -> identity(truncated, provider, NONCE, 2345, 0), "truncated identity");
            }
            for (int badLength : new int[]{0, -1, 129, Integer.MAX_VALUE}) {
                byte[] bad = frame.clone(); putInt(bad, 52, badLength);
                reject(() -> identity(bad, provider, NONCE, 2345, 0), "boot length");
            }
            for (int badLength : new int[]{0, -1, 257, Integer.MAX_VALUE}) {
                byte[] bad = frame.clone(); putInt(bad, 92, badLength);
                reject(() -> identity(bad, provider, NONCE, 2345, 0), "domain length");
            }
            reject(() -> identity(frame(provider, "6334f916-9a56-4267-8d79-cb67a4782ece",
                    "u:r:su:s0", 1, 2), provider, NONCE, 2345, 0), "boot mismatch");
            for (String domain : new String[]{"u:r:su:s0\0", "u:r:su:s0\n", "u:r:su:s0\r"}) {
                reject(() -> identity(frame(provider, BOOT, domain, 1, 2), provider, NONCE, 2345, 0),
                        "domain control character");
            }
            byte[] utf8 = frame.clone(); utf8[96] = (byte) 0xff;
            /*
             * S12: version 2 carries the worker start time and a capability flag. A
             * recycled pid cannot pass because the start time differs, and a worker
             * that cannot show the capability flag is refused outright.
             */
            // Any pid: the observed start time comes from the resolver seam below.
            int self = 4242;
            long start = 987654321L;
            LeaseProtocol.starttimeResolver = pid -> start;
            LeaseProtocol.Identity v2 = identity(frameV2(provider, self, start, 1),
                    provider, NONCE, self, 0);
            check(v2.provesWorkerIdentity() && v2.workerStarttime() == start, "v2 proves the worker");
            check(!identity(frame(provider, BOOT, "u:r:su:s0", 1, 2), provider, NONCE, 2345, 0)
                    .provesWorkerIdentity(), "v1 does not claim proof");
            LeaseProtocol.starttimeResolver = pid -> start + 1;
            reject(() -> identity(frameV2(provider, self, start, 1), provider, NONCE, self, 0),
                    "start time mismatch (pid reuse)");
            LeaseProtocol.starttimeResolver = pid -> -1L;
            check(!identity(frameV2(provider, self, start, 1), provider, NONCE, self, 0)
                    .provesWorkerIdentity(), "unreadable start time is not proof");
            reject(() -> identity(frameV2(provider, self, 0, 1), provider, NONCE, self, 0),
                    "missing start time value");
            reject(() -> identity(frameV2(provider, self, start, 0), provider, NONCE, self, 0),
                    "missing capability");
            reject(() -> identity(utf8, provider, NONCE, 2345, 0), "malformed UTF-8");
            for (int enforce : new int[]{-1, 2})
                reject(() -> identity(frame(provider, BOOT, "u:r:su:s0", enforce, 2),
                        provider, NONCE, 2345, 0), "invalid enforcing");
            for (int seccomp : new int[]{-1, 3})
                reject(() -> identity(frame(provider, BOOT, "u:r:su:s0", 1, seccomp),
                        provider, NONCE, 2345, 0), "invalid seccomp");
        }
        check(LeaseProtocol.validBootId(BOOT), "canonical boot");
        check(!LeaseProtocol.validBootId(BOOT.toUpperCase()), "boot hex lower case");
        check(!LeaseProtocol.validBootId(null), "missing boot");
        for (int code : new int[]{0, 1, 126, 137, 255})
            check(LeaseProtocol.readExit(input(event('X', code))) == code, "explicit exit");
        check(LeaseProtocol.readReady(input(event('R', 6789))) == 6789, "exec confirmed");
        for (int pid : new int[]{0, 1, -1})
            reject(() -> LeaseProtocol.readReady(input(event('R', pid))), "invalid child PID");
        for (int code : new int[]{-1, 256})
            reject(() -> LeaseProtocol.readExit(input(event('X', code))), "invalid exit code");
        reject(() -> LeaseProtocol.readReady(input(event('X', 126))), "exec failure not ready");
        reject(() -> LeaseProtocol.readExit(input(event('R', 6789))), "ready not exit");
        for (int length = 0; length < 5; length++) {
            byte[] ready = Arrays.copyOf(event('R', 6789), length);
            byte[] exit = Arrays.copyOf(event('X', 0), length);
            reject(() -> LeaseProtocol.readReady(input(ready)), "ready EOF");
            reject(() -> LeaseProtocol.readExit(input(exit)), "control EOF is not normal exit");
        }
        // Restoration frame: the origin of the written value is part of the frame,
        // so a baseline value can never be presented as the observed entry policy.
        byte[] applied = restore(1, 0, 1, 0, 0, 0);
        LeaseProtocol.Restore restored = LeaseProtocol.readRestore(input(applied));
        check(restored.applicable() && restored.verified() && restored.provesEntryPolicy() &&
                restored.origin() == LeaseProtocol.Origin.OBSERVED && restored.enforcing() == 1 &&
                restored.checkreqprot() == 0 && restored.policy() == 0 &&
                restored.unloadErrno() == 0, "observed restoration reported");
        LeaseProtocol.Restore skipped = LeaseProtocol.readRestore(input(restore(2, 3, 255, 255, 2, -1)));
        check(!skipped.applicable() && !skipped.verified() && !skipped.provesEntryPolicy() &&
                skipped.origin() == LeaseProtocol.Origin.PROVIDER && skipped.enforcing() == 0xff,
                "provider-owned restoration is not a pass");
        LeaseProtocol.Restore failed = LeaseProtocol.readRestore(input(restore(0, 1, 0, 1, 1, 16)));
        check(failed.applicable() && failed.failed() && !failed.verified() &&
                !failed.admitsHandover() && failed.enforcing() == 0 &&
                failed.checkreqprot() == 1 && failed.unloadErrno() == 16, "failed restoration kept");
        // The ordinary App cannot read selinuxfs, so the consumer may apply the
        // release baseline; that is verified but never the entry value.
        // Ghostlock reloads the policy, so its identity is honestly "not compared"
        // while the booleans are verified: verified() holds, provesEntryPolicy() does not.
        LeaseProtocol.Restore reloaded = LeaseProtocol.readRestore(input(restore(3, 1, 1, 0, 2, -1)));
        check(reloaded.verified() && !reloaded.provesEntryPolicy() &&
                reloaded.policy() == 2 && reloaded.origin() == LeaseProtocol.Origin.BASELINE,
                "policy identity not compared is verified but not a proof");
        LeaseProtocol.Restore assumed = LeaseProtocol.readRestore(input(restore(3, 1, 1, 0, 0, 0)));
        check(assumed.verified() && assumed.baseline() && !assumed.provesEntryPolicy() &&
                assumed.origin() == LeaseProtocol.Origin.BASELINE && assumed.enforcing() == 1,
                "baseline restoration stays distinguishable");
        // Newer kernels can omit checkreqprot. Confirmed absence is an explicit
        // readback state; it must never be confused with an unreadable entry.
        for (int[] value : new int[][]{{1, 0}, {3, 1}}) {
            LeaseProtocol.Restore absent = LeaseProtocol.readRestore(input(restore(
                    value[0], value[1], 1, 2, 2, -1)));
            check(absent.verified() && absent.checkreqprot() == 2 && !absent.provesEntryPolicy(),
                    "confirmed optional entry absence is verified separately");
        }
        for (int[] invalid : new int[][]{
                {4, 0, 1, 0, 0, 0},      // applied out of range
                {3, 0, 0, 0, 0, 0},      // baseline without the baseline origin
                {1, 2, 0, 0, 0, 0},      // observed with an unknown origin
                {1, 0, 2, 0, 0, 0},      // enforcing not 0/1/unknown
                {1, 0, 1, 3, 0, 0},      // checkreqprot not 0/1/absent/unknown
                {1, 0, 1, 2, 0, 0},      // absent only belongs to the Ghostlock reload report
                {1, 0, 1, 0, 3, 0},      // policy state out of range
                {1, 0, 1, 0, 1, 0},      // a changed policy cannot be a success
                {1, 0, 0xff, 0, 0, 0},   // restoration without a readback
                {2, 0, 0xff, 0xff, 2, 0},// provider-owned frame with another owner
                {0, 2, 0, 0, 0, 0},      // failure claiming an unknown origin with a value
                {-1, 0, 0, 0, 0, 0},     // negative applied byte
                {1, 0, 1, 0, 0, -2}}) {  // impossible unload errno
            reject(() -> LeaseProtocol.readRestore(input(restore(invalid[0], invalid[1], invalid[2],
                    invalid[3], invalid[4], invalid[5]))), "invalid restoration frame");
        }
        for (int length = 0; length < 10; length++) {
            byte[] truncated = Arrays.copyOf(applied, length);
            reject(() -> LeaseProtocol.readRestore(input(truncated)), "restoration EOF");
        }
        reject(() -> LeaseProtocol.readReady(input(applied)), "restoration is not exec confirmation");
        // A consumer failure is delivered explicitly instead of leaving the App in
        // its provider timeout.
        try {
            LeaseProtocol.readReady(input(new byte[]{'F', 7, 0, 0, 0}));
            throw new IllegalStateException("failure frame accepted as a shell");
        } catch (IOException expected) {
            check("LEASE_CONSUMER_FAILED:EXEC".equals(expected.getMessage()), "failure frame names the stage");
        }
        System.out.println("LeaseProtocolHostTest PASS checks=" + checks);
    }

    private static byte[] restore(int applied, int origin, int enforcing, int checkreqprot,
                                  int policy, int unloadErrno) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeByte('P'); out.writeByte(applied); out.writeByte(origin); out.writeByte(enforcing);
        out.writeByte(checkreqprot); out.writeByte(policy); out.writeInt(unloadErrno);
        return bytes.toByteArray();
    }

    private static LeaseProtocol.Identity identity(byte[] frame, LeaseProtocol.Provider provider,
                                                    byte[] nonce, int pid, int uid) throws IOException {
        return LeaseProtocol.readIdentity(input(frame), provider, nonce, BOOT, pid, uid);
    }
    private static ByteArrayInputStream input(byte[] frame) { return new ByteArrayInputStream(frame); }
    private static byte[] frame(LeaseProtocol.Provider provider, String boot, String domain,
                                int enforce, int seccomp) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeBytes("MJBL"); out.writeInt(1); out.writeInt(provider.wireId);
        out.writeInt(2345); out.writeInt(0); out.write(NONCE);
        text(out, boot); text(out, domain); out.writeInt(enforce); out.writeInt(seccomp);
        return bytes.toByteArray();
    }
    private static byte[] frameV2(LeaseProtocol.Provider provider, int pid, long starttime,
                                  int capability) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeBytes("MJBL"); out.writeInt(2); out.writeInt(provider.wireId);
        out.writeInt(pid); out.writeInt(0);
        out.writeInt((int) (starttime >>> 32)); out.writeInt((int) starttime);
        out.writeInt(capability); out.write(NONCE);
        text(out, BOOT); text(out, "u:r:su:s0"); out.writeInt(1); out.writeInt(2);
        return bytes.toByteArray();
    }
    private static void text(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8); out.writeInt(bytes.length); out.write(bytes);
    }
    private static byte[] event(int tag, int value) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes); out.writeByte(tag); out.writeInt(value);
        return bytes.toByteArray();
    }
    private static void putInt(byte[] data, int offset, int value) {
        for (int i = 0; i < 4; i++) data[offset + i] = (byte) (value >>> (24 - 8 * i));
    }
    private static void check(boolean condition, String label) {
        checks++; if (!condition) throw new AssertionError(label);
    }
    private static void reject(Action action, String label) throws Exception {
        checks++;
        try { action.run(); } catch (IOException expected) { return; }
        throw new AssertionError("Accepted " + label);
    }
}
