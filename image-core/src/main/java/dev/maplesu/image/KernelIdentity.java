package dev.maplesu.image;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One implementation of "what kernel is this?" for raw (decompressed) kernel bytes.
 *
 * <p>Three callers used to answer this differently — {@code UltraKernelSpec.releaseOf},
 * {@code BootImageRoundTrip.release} and {@code BootKernelVersion.parseKmi} — and the Ultra one had no
 * character whitelist, so a kernel whose first hit is the printk format string {@code "Linux version %s"}
 * reported the release {@code "%s"} while the other two reported the real release. That produced
 * "import looks fine, Ultra says RELEASE_UNSUPPORTED:%s" on the same image. Everything here is
 * fail-closed: a candidate must look like a release ({@code digits.digits...}) and consist only of
 * {@code [0-9A-Za-z._+-]}; if two different candidates are found the answer is {@link #AMBIGUOUS}
 * instead of silently taking the first one.
 *
 * <p>This class only reads bytes: no decode, no patch, no device access.
 */
public final class KernelIdentity {
    /** No {@code Linux version} string whose candidate passed the whitelist. */
    public static final String UNREADABLE = "";
    /** Two or more distinct, well-formed releases; callers must fail closed. */
    public static final String AMBIGUOUS = "AMBIGUOUS";
    /** Placeholder used by the JSON reports when {@link #UNREADABLE} is returned. */
    public static final String UNKNOWN = "UNKNOWN";

    public static final String FORMAT_GZIP = "GZIP";
    public static final String FORMAT_LZ4_LEGACY = "LZ4_LEGACY";
    public static final String FORMAT_LZ4_FRAME = "LZ4_FRAME";
    public static final String FORMAT_ZSTD = "ZSTD";
    public static final String FORMAT_XZ = "XZ";
    public static final String FORMAT_RAW_ARM64 = "RAW_ARM64";
    public static final String FORMAT_UNKNOWN = "UNKNOWN";

    public static final String ARCH_ARM64 = "arm64";
    public static final String ARCH_ARM = "arm";
    public static final String ARCH_X86_64 = "x86_64";
    public static final String ARCH_UNKNOWN = "UNKNOWN";

    private static final byte[] RELEASE_MARKER = ascii("Linux version ");
    /** Longest release accepted; the longest real GKI banner observed is 76 bytes. */
    private static final int MAX_RELEASE = 128;
    /** Vendor-compatible KMI grammar: {@code 6.6.89-android15-8-...} → {@code android15-6.6}. */
    private static final Pattern KMI = Pattern.compile("(\\d+\\.\\d+)(?:\\S+)?(android\\d+)");

    private KernelIdentity() {}

    /** Release as it appears in the kernel banner, or {@link #UNREADABLE} / {@link #AMBIGUOUS}. */
    public static String releaseOf(byte[] kernel) {
        return kernel == null ? UNREADABLE : releaseOf(kernel, 0, kernel.length);
    }

    /** Release inside {@code bytes[from, to)}; same whitelist and ambiguity rules. */
    public static String releaseOf(byte[] bytes, int from, int to) {
        if (bytes == null) return UNREADABLE;
        int start = Math.max(0, from), end = Math.min(bytes.length, to);
        if (end - start < RELEASE_MARKER.length) return UNREADABLE;
        String found = UNREADABLE;
        outer:
        for (int index = start; index <= end - RELEASE_MARKER.length; index++) {
            if (bytes[index] != RELEASE_MARKER[0]) continue;
            for (int offset = 1; offset < RELEASE_MARKER.length; offset++) {
                if (bytes[index + offset] != RELEASE_MARKER[offset]) continue outer;
            }
            String candidate = candidate(bytes, index + RELEASE_MARKER.length, end);
            if (candidate.isEmpty()) continue;
            if (found.isEmpty()) { found = candidate; continue; }
            if (!found.equals(candidate)) return AMBIGUOUS;
        }
        return found;
    }

    /** Release for JSON reports: {@link #UNKNOWN} instead of {@link #UNREADABLE}. */
    public static String describeRelease(byte[] kernel) {
        String release = releaseOf(kernel);
        return release.isEmpty() ? UNKNOWN : release;
    }

    /** KMI (`android15-6.6`) derived from the banner release, or {@link #UNREADABLE}. */
    public static String kmiOf(byte[] kernel) {
        return kmiOfRelease(releaseOf(kernel));
    }

    /** KMI from a release string, or {@link #UNREADABLE} when the grammar does not match. */
    public static String kmiOfRelease(String release) {
        if (release == null || release.isEmpty()) return UNREADABLE;
        Matcher match = KMI.matcher(release);
        return match.find() ? match.group(2) + "-" + match.group(1) : UNREADABLE;
    }

    /** Vendor-compatible KMI scan over arbitrary banner text (partial or decompressed buffers). */
    public static String kmiOfText(String text) {
        return text == null ? null : kmiOfRelease(text);
    }

    /**
     * Architecture of a **raw** kernel image. Compressed containers report {@link #ARCH_UNKNOWN};
     * decode them with {@link KernelCompression} first.
     */
    public static String archOf(byte[] raw) {
        if (raw == null) return ARCH_UNKNOWN;
        // arm64 Image: code0..code3 then the "ARM\x64" magic at offset 0x38.
        if (raw.length >= 60 && raw[56] == 'A' && raw[57] == 'R' && raw[58] == 'M' && raw[59] == 'd') {
            return ARCH_ARM64;
        }
        // arm32 zImage: 0x016f2818 at offset 0x24 (little endian).
        if (raw.length >= 40 && (raw[36] & 255) == 0x18 && (raw[37] & 255) == 0x28
                && (raw[38] & 255) == 0x6f && (raw[39] & 255) == 0x01) {
            return ARCH_ARM;
        }
        // x86 bzImage: "HdrS" at offset 0x202.
        if (raw.length >= 518 && raw[514] == 'H' && raw[515] == 'd' && raw[516] == 'r' && raw[517] == 'S') {
            return ARCH_X86_64;
        }
        return ARCH_UNKNOWN;
    }

    /** Compression/container format of a kernel block prefix (same codes as the inspector). */
    public static String formatOf(byte[] prefix) {
        return prefix == null ? FORMAT_UNKNOWN : formatOf(prefix, 0);
    }

    public static String formatOf(byte[] bytes, int offset) {
        if (bytes == null || offset < 0) return FORMAT_UNKNOWN;
        if (starts(bytes, offset, 31, 139)) return FORMAT_GZIP;
        if (starts(bytes, offset, 2, 33, 76, 24)) return FORMAT_LZ4_LEGACY;
        if (starts(bytes, offset, 4, 34, 77, 24)) return FORMAT_LZ4_FRAME;
        if (starts(bytes, offset, 40, 181, 47, 253)) return FORMAT_ZSTD;
        if (starts(bytes, offset, 253, 55, 122, 88, 90, 0)) return FORMAT_XZ;
        if (bytes.length - offset >= 60 && bytes[offset + 56] == 'A' && bytes[offset + 57] == 'R'
                && bytes[offset + 58] == 'M' && bytes[offset + 59] == 'd') return FORMAT_RAW_ARM64;
        return FORMAT_UNKNOWN;
    }

    /** True when the kernel block is a compressed container this build can decode. */
    public static boolean isCompressed(byte[] prefix) {
        return isCompressedFormat(formatOf(prefix));
    }

    public static boolean isCompressedFormat(String format) {
        return FORMAT_GZIP.equals(format) || FORMAT_LZ4_LEGACY.equals(format)
                || FORMAT_LZ4_FRAME.equals(format) || FORMAT_ZSTD.equals(format) || FORMAT_XZ.equals(format);
    }

    public static String sha256(byte[] bytes) {
        try {
            StringBuilder result = new StringBuilder(64);
            for (byte value : MessageDigest.getInstance("SHA-256").digest(bytes)) {
                result.append(String.format(Locale.ROOT, "%02x", value & 255));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    /** Reads the release token at {@code start}; empty when it is not a whitelisted release. */
    private static String candidate(byte[] bytes, int start, int end) {
        if (start >= end) return "";
        int first = bytes[start] & 255;
        if (first < '0' || first > '9') return "";      // rejects "%s" and other format strings
        int position = start;
        while (position < end && position - start < MAX_RELEASE && allowed(bytes[position] & 255)) position++;
        String text = new String(bytes, start, position - start, java.nio.charset.StandardCharsets.US_ASCII);
        return looksLikeRelease(text) ? text : "";
    }

    /** `digits.digits...`: at least one dot with a digit on both sides. */
    private static boolean looksLikeRelease(String text) {
        int dot = text.indexOf('.');
        return dot > 0 && dot < text.length() - 1
                && isDigit(text.charAt(dot - 1)) && isDigit(text.charAt(dot + 1));
    }

    private static boolean allowed(int value) {
        return (value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z')
                || (value >= 'a' && value <= 'z') || value == '.' || value == '-' || value == '_' || value == '+';
    }

    private static boolean isDigit(char value) { return value >= '0' && value <= '9'; }

    private static boolean starts(byte[] bytes, int offset, int... prefix) {
        if (offset < 0 || bytes.length - offset < prefix.length) return false;
        for (int index = 0; index < prefix.length; index++) {
            if ((bytes[offset + index] & 255) != prefix[index]) return false;
        }
        return true;
    }

    private static byte[] ascii(String value) {
        return value.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }
}
