package dev.maplesu.manager.jailbreak;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Upstream profile/ACK channel only; MJBL shell traffic uses independent pipes. */
public final class GhostlockWire {
    private static final int MAX_PROFILE = 1 << 20;
    private static final byte[] ACK = "\036GLK_STATUS_ACK\n".getBytes(StandardCharsets.US_ASCII);
    private final byte[] profile;
    private final OutputStream output;
    private boolean written;

    public GhostlockWire(byte[] resolvedProfile, String exactRelease, OutputStream output) {
        if (resolvedProfile == null || exactRelease == null || output == null)
            throw new NullPointerException("profile, release and output required");
        if (exactRelease.isEmpty() || exactRelease.length() > 255 ||
                !exactRelease.matches("[A-Za-z0-9._+\\-]+") ||
                resolvedProfile.length < 18 || resolvedProfile.length > MAX_PROFILE)
            throw new IllegalArgumentException("GHOSTLOCK_PROFILE_BOUNDS");
        byte[] copy = resolvedProfile.clone();
        ByteBuffer header = ByteBuffer.wrap(copy).order(ByteOrder.LITTLE_ENDIAN);
        if (header.getInt() != 0x0d000721 || header.getShort() != 2 ||
                header.getShort() != 1 || header.getShort() != 1)
            throw new IllegalArgumentException("GHOSTLOCK_PROFILE_COMPONENTS");
        int route = Short.toUnsignedInt(header.getShort());
        int length = Short.toUnsignedInt(header.getShort());
        int reserved = Short.toUnsignedInt(header.getShort());
        byte[] release = exactRelease.getBytes(StandardCharsets.US_ASCII);
        if (route < 1 || route > 3 || reserved != 0 || length != release.length ||
                length > copy.length - 18 || !Arrays.equals(release, Arrays.copyOfRange(copy, 16, 16 + length)))
            throw new IllegalArgumentException("GHOSTLOCK_EXACT_PROFILE_REQUIRED");
        // Section semantics remain checked by the pinned native decoder.
        profile = copy;
        this.output = output;
    }

    /** One BE32 length, unchanged LE typed document; stdin stays open for ACK. */
    public synchronized void writeProfile() throws IOException {
        if (written) throw new IllegalStateException("GHOSTLOCK_PROFILE_ALREADY_WRITTEN");
        written = true;
        DataOutputStream framed = new DataOutputStream(output);
        framed.writeInt(profile.length);
        framed.write(profile);
        framed.flush();
    }

    /** Stdout reader calls before UI listeners; this channel never carries shell traffic. */
    public synchronized boolean acknowledge(String line) throws IOException {
        if (!written) throw new IllegalStateException("GHOSTLOCK_PROFILE_NOT_WRITTEN");
        if (line == null || line.length() > 64 ||
                !line.matches("\036GLK_STATUS [a-z0-9_]+ (in_progress|completed)")) return false;
        output.write(ACK);
        output.flush();
        return true;
    }
}
