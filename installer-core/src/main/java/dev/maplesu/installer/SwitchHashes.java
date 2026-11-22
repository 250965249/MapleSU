package dev.maplesu.installer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** SHA-256 helpers shared by the switch contracts; JDK only (installer-core has no dependencies). */
final class SwitchHashes {
    private SwitchHashes() {}

    static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    static String sha256Hex(String value) {
        return hex(sha256().digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    static String sha256(byte[] bytes) {
        return hex(sha256().digest(bytes));
    }

    static String sha256(Path file) throws IOException {
        MessageDigest digest = sha256();
        byte[] buffer = new byte[64 * 1024];
        long total = 0;
        try (InputStream input = Files.newInputStream(file)) {
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (count == 0) throw new IOException("SWITCH_PRE_IMAGE_INVALID: empty read");
                digest.update(buffer, 0, count);
                total += count;
            }
        }
        if (total != Files.size(file)) throw new IOException("SWITCH_PRE_IMAGE_CHANGED: size drifted");
        return hex(digest.digest());
    }

    /** Last {@code min(length, TAIL_PROBE_BYTES)} bytes, as a whole-buffer digest. */
    static String tailSha256(byte[] bytes) {
        int count = Math.min(bytes.length, WritablePartition.TAIL_PROBE_BYTES);
        MessageDigest digest = sha256();
        digest.update(bytes, bytes.length - count, count);
        return hex(digest.digest());
    }

    /** Last {@code min(fileSize, TAIL_PROBE_BYTES)} bytes of a full-length image file. */
    static String tailSha256(Path file) throws IOException {
        long fileSize = Files.size(file);
        int count = (int) Math.min(fileSize, WritablePartition.TAIL_PROBE_BYTES);
        long skip = fileSize - count;
        byte[] buffer = new byte[count];
        try (InputStream input = Files.newInputStream(file)) {
            long skipped = 0;
            while (skipped < skip) {
                long step = input.skip(skip - skipped);
                if (step <= 0) {
                    if (input.read() < 0) throw new IOException("SWITCH_PRE_IMAGE_INVALID: short image");
                    step = 1;
                }
                skipped += step;
            }
            int read = 0;
            while (read < count) {
                int got = input.read(buffer, read, count - read);
                if (got < 0) throw new IOException("SWITCH_PRE_IMAGE_INVALID: short tail");
                read += got;
            }
        }
        return hex(sha256().digest(buffer));
    }

    static boolean isHash(String value) {
        return value != null && value.matches("[0-9a-f]{64}");
    }

    static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(64);
        for (byte value : bytes) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }
}
