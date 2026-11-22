package dev.maplesu.image;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Independent liblz4/liblzma fixtures; provenance and checksum offsets are in receipt.json. */
public final class RamdiskCodecCompatibilityTest {
    private static int passed;
    private static final List<String> failures = new ArrayList<>();
    private static final String[] FILES = {
        "stock.cpio.lz4", "stock-checksums.cpio.lz4", "stock-crc32.cpio.xz",
        "stock-crc64.cpio.xz", "stock-sha256.cpio.xz"
    };

    private static void check(boolean condition, String message) {
        if (!condition) failures.add(message);
        else passed++;
    }

    private static byte[] fixture(String name) throws IOException {
        try (InputStream stream = RamdiskCodecCompatibilityTest.class
                .getResourceAsStream("/ramdisk-codecs/" + name)) {
            if (stream == null) throw new IOException("MISSING_FIXTURE:" + name);
            return stream.readAllBytes();
        }
    }

    private static byte[] decode(String name, byte[] input, int limit) throws IOException {
        return name.endsWith(".lz4") ? Lz4FrameCodec.decode(input, limit) : XzCodec.decode(input, limit);
    }

    private static byte[] boot(byte[] ramdisk, int version, boolean withKernel) {
        int page = 4096;
        byte[] kernel = withKernel ? "unchanged-kernel".getBytes(StandardCharsets.US_ASCII) : new byte[0];
        int offset = ((page + kernel.length + page - 1) / page) * page;
        byte[] image = new byte[((offset + ramdisk.length + page - 1) / page) * page];
        ByteBuffer header = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        header.put("ANDROID!".getBytes(StandardCharsets.US_ASCII));
        header.putInt(8, kernel.length).putInt(40, version);
        if (version == 0) header.putInt(16, ramdisk.length).putInt(36, page);
        else header.putInt(12, ramdisk.length).putInt(20, 1584);
        System.arraycopy(kernel, 0, image, page, kernel.length);
        System.arraycopy(ramdisk, 0, image, offset, ramdisk.length);
        return image;
    }

    private static void sameArchive(RamdiskInspector.Report expected, RamdiskInspector.Report actual,
            String compression, String label) {
        check(!actual.malformed, label + ": " + actual.errorCode);
        check(actual.form() == RamdiskInspector.Form.STOCK, label + ": stock form");
        check(compression.equals(actual.compression), label + ": compression");
        check(expected.decompressedSha256.equals(actual.decompressedSha256), label + ": decoded hash");
        check(expected.decompressedSize == actual.decompressedSize, label + ": decoded size");
        check(expected.entries.size() == actual.entries.size(), label + ": entry count");
        for (int i = 0; i < Math.min(expected.entries.size(), actual.entries.size()); i++) {
            RamdiskInspector.Entry e = expected.entries.get(i), a = actual.entries.get(i);
            check(e.path.equals(a.path) && e.mode == a.mode && e.size == a.size
                    && e.sha256.equals(a.sha256), label + ": entry " + e.path);
        }
    }

    private static void validAndBounded() throws Exception {
        byte[] raw = fixture("stock.cpio");
        String hash = java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
        check(hash.equals("e63cfbea5bf581bbecdbfecfaf5c8a897347077613bffc7ddfd964a8792cf0e5"),
                "independent GNU cpio reference hash");
        RamdiskInspector.Report expected = RamdiskInspector.inspectRamdisk(raw);
        check(!expected.malformed && expected.entries.size() == 2, "reference archive");
        for (String name : FILES) {
            byte[] encoded = fixture(name), original = encoded.clone();
            String compression = name.endsWith(".lz4") ? "LZ4_FRAME" : "XZ";
            check(Arrays.equals(raw, decode(name, encoded, raw.length)), name + ": external compressed block");
            sameArchive(expected, RamdiskInspector.inspectRamdisk(encoded), compression, name + ": component");
            for (int version : new int[] {0, 4}) {
                sameArchive(expected, RamdiskInspector.inspect(boot(encoded, version, true)), compression,
                        name + ": boot v" + version);
            }
            sameArchive(expected, RamdiskInspector.inspect(boot(encoded, 4, false)), compression,
                    name + ": init_boot v4 kernel=0");
            RamdiskInspector.Report limited = RamdiskInspector.inspectRamdisk(encoded, 100, raw.length - 1);
            check("DECOMPRESSION_LIMIT".equals(limited.errorCode) && limited.entries.isEmpty(),
                    name + ": no partial archive on limit");
            for (int length = 1; length < encoded.length; length++) {
                byte[] truncated = Arrays.copyOf(encoded, length);
                try {
                    decode(name, truncated, raw.length);
                    check(false, name + ": accepted truncated length " + length);
                } catch (IOException expectedError) {
                    passed++;
                }
                RamdiskInspector.Report report = RamdiskInspector.inspectRamdisk(truncated);
                check(report.malformed && report.entries.isEmpty(), name + ": partial CPIO at " + length);
            }
            Thread.currentThread().interrupt();
            try {
                RamdiskInspector.Report cancelled = RamdiskInspector.inspectRamdisk(encoded);
                check("CANCELLED".equals(cancelled.errorCode) && cancelled.entries.isEmpty(),
                        name + ": no partial archive on cancel");
            } finally {
                Thread.interrupted();
            }
            check(Arrays.equals(original, encoded), name + ": input preserved");
        }
    }

    private static void damagedCheck(String name, int offset, int length, String code) throws Exception {
        byte[] original = fixture(name);
        for (int i = 0; i < length; i++) {
            byte[] damaged = original.clone();
            damaged[offset + i] ^= 1;
            try {
                decode(name, damaged, 4096);
                check(false, name + ": accepted checksum byte " + i + " at " + offset);
            } catch (IOException error) {
                check(code.equals(error.getMessage()), name + ": decode error " + error.getMessage());
            }
            RamdiskInspector.Report report = RamdiskInspector.inspectRamdisk(damaged);
            check(code.equals(report.errorCode), name + ": inspector error " + report.errorCode);
            check(report.entries.isEmpty() && report.decompressedSize == 0,
                    name + ": no partial archive on checksum failure");
        }
    }

    public static int check() throws Exception {
        passed = 0;
        failures.clear();
        validAndBounded();
        damagedCheck("stock-checksums.cpio.lz4", 161, 4, "INVALID_LZ4_FRAME_BLOCK_CHECKSUM");
        damagedCheck("stock-checksums.cpio.lz4", 169, 4, "INVALID_LZ4_FRAME_CONTENT_CHECKSUM");
        damagedCheck("stock-crc32.cpio.xz", 132, 4, "INVALID_XZ_CHECK");
        damagedCheck("stock-crc64.cpio.xz", 132, 8, "INVALID_XZ_CHECK");
        damagedCheck("stock-sha256.cpio.xz", 132, 32, "INVALID_XZ_CHECK");
        if (!failures.isEmpty()) throw new AssertionError(failures.size() + " failures:\n"
                + String.join("\n", failures));
        return passed;
    }

    public static void main(String[] args) throws Exception {
        System.out.println(check() + " external ramdisk codec checks passed");
    }
}
