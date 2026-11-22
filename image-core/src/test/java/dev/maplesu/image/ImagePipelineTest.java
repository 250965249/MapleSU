package dev.maplesu.image;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Random;

public final class ImagePipelineTest {
    private static int passed;

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        passed++;
    }

    private static void rejected(byte[] bytes, String format, int limit, String code) throws Exception {
        try {
            KernelCompression.decode(bytes, format, limit);
            throw new AssertionError("Expected rejection: " + code);
        } catch (IOException exception) {
            check(exception.getMessage().startsWith(code), "Wrong rejection: " + exception.getMessage());
        }
    }

    private static byte[] legacy(byte[] block) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{2, 33, 76, 24});
        out.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(block.length).array());
        out.write(block);
        return out.toByteArray();
    }

    private static byte[] fixture(int version, String format) throws Exception {
        return fixture(version, format, 4096);
    }

    private static byte[] fixture(int version, String format, int page) throws Exception {
        byte[] raw = new byte[5017];
        new Random(17).nextBytes(raw);
        byte[] marker = "Linux version 6.6.66-maplesu-fixture ".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(marker, 0, raw, 80, marker.length);
        System.arraycopy(new byte[]{'A', 'R', 'M', 100}, 0, raw, 56, 4);
        byte[] compressed = KernelCompression.encode(raw, format);
        int ramdiskOffset = (page + compressed.length + page - 1) / page * page;
        int nextOffset = (ramdiskOffset + 71 + page - 1) / page * page;
        byte[] image = new byte[nextOffset + page * 4 + 100];
        new Random(42).nextBytes(image); // nonzero padding, ramdisk, signature and trailer
        ByteBuffer header = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        header.put(new byte[]{'A', 'N', 'D', 'R', 'O', 'I', 'D', '!'});
        header.putInt(8, compressed.length);
        header.putInt(40, version);
        if (version < 3) {
            header.putInt(16, 71).putInt(24, 53).putInt(36, page);
            if (version >= 1) {
                header.putInt(1632, 31).putLong(1636, nextOffset + page);
                header.putInt(1644, version == 1 ? 1648 : 1660);
            }
            if (version == 2) header.putInt(1648, 19);
        } else {
            header.putInt(12, 71).putInt(20, version == 4 ? 1584 : 1580);
            if (version == 4) header.putInt(1580, 37);
        }
        System.arraycopy(compressed, 0, image, page, compressed.length);
        return image;
    }

    private static void write(byte[] target, int offset, String value) {
        byte[] bytes = value.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(bytes, 0, target, offset, bytes.length);
    }

    public static void main(String[] args) throws Exception {
        BootImageInspectorTest.main(new String[0]);
        ZstdIntegrityTest.main(new String[0]);
        passed += CodecCancellationTest.check();
        Random random = new Random(20261024);
        for (String format : new String[]{"GZIP", "LZ4_LEGACY", "RAW_ARM64", "LZ4_FRAME", "ZSTD", "XZ"}) {
            for (int length : new int[]{1, 14, 15, 16, 269, 270, 271, 4096, 65536, 8388617}) {
                byte[] raw = new byte[length];
                random.nextBytes(raw);
                check(Arrays.equals(raw, KernelCompression.decode(KernelCompression.encode(raw, format), format,
                        Math.max(raw.length, 1))), format + " round trip " + length);
            }
        }
        byte[] overlap = KernelCompression.decode(legacy(new byte[]{0x1f, 'a', 1, 0, 10, 0x50, 'b', 'c', 'd', 'e', 'f'}), "LZ4_LEGACY", 64);
        check(overlap.length == 35 && overlap[29] == 'a' && overlap[30] == 'b', "overlapping LZ4 match");
        rejected(new byte[4], "LZ4_LEGACY", 64, "INVALID_LZ4_MAGIC");
        rejected(new byte[]{2, 33, 76, 24, 1}, "LZ4_LEGACY", 64, "TRUNCATED_LZ4_BLOCK_HEADER");
        rejected(new byte[]{2, 33, 76, 24, -1, -1, -1, -1}, "LZ4_LEGACY", 64, "INVALID_LZ4_BLOCK_SIZE");
        rejected(legacy(new byte[]{0x10, 'a', 0, 0}), "LZ4_LEGACY", 64, "INVALID_LZ4_OFFSET");
        rejected(legacy(new byte[]{0x10, 'a', 2, 0}), "LZ4_LEGACY", 64, "INVALID_LZ4_OFFSET");
        rejected(legacy(new byte[]{(byte) 0xf0}), "LZ4_LEGACY", 64, "TRUNCATED_LZ4_LENGTH");
        rejected(legacy(new byte[]{0x50, 1}), "LZ4_LEGACY", 64, "TRUNCATED_LZ4_LITERALS");
        rejected(KernelCompression.encode(new byte[500], "LZ4_LEGACY"), "LZ4_LEGACY", 20, "DECOMPRESSION_LIMIT");
        rejected(KernelCompression.encode(new byte[500], "GZIP"), "GZIP", 20, "DECOMPRESSION_LIMIT");
        // W2: the three formerly recognise-only formats now decode, so malformed input has to be
        // rejected structurally instead of by "unsupported".
        rejected(new byte[0], "XZ", 64, "TRUNCATED_XZ");
        rejected(new byte[0], "ZSTD", 64, "INVALID_ZSTD_MAGIC");
        rejected(new byte[0], "LZ4_FRAME", 64, "TRUNCATED_LZ4_FRAME");
        byte[] badXz = new byte[24];
        write(badXz, 0, "");
        System.arraycopy(new byte[]{(byte) 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0, 1}, 0, badXz, 0, 8);
        rejected(badXz, "XZ", 64, "INVALID_XZ_HEADER_CHECKSUM");
        rejected(new byte[]{(byte) 0x28, (byte) 0xb5, 0x2f, (byte) 0xfd, 0x20, 8, 0x41, 0, 0},
                "ZSTD", 64, "TRUNCATED_ZSTD_BLOCK");
        rejected(KernelCompression.encode(new byte[500], "XZ"), "XZ", 20, "DECOMPRESSION_LIMIT");
        rejected(KernelCompression.encode(new byte[500], "ZSTD"), "ZSTD", 20, "DECOMPRESSION_LIMIT");
        rejected(KernelCompression.encode(new byte[500], "LZ4_FRAME"), "LZ4_FRAME", 20, "DECOMPRESSION_LIMIT");
        // Kernel identity: the printk format string must never be mistaken for the release.
        byte[] banner = new byte[512];
        write(banner, 32, "Linux version %s\n");
        write(banner, 96, "Linux version 5.10.226-android12-9-o-gb4f7990ee2d5 #1 SMP\n");
        check(KernelIdentity.releaseOf(banner).equals("5.10.226-android12-9-o-gb4f7990ee2d5"),
                "release skips the %s format string");
        check(KernelIdentity.kmiOf(banner).equals("android12-5.10"), "kmi from release");
        byte[] rawImage = fixture(4, "RAW_ARM64");
        check("arm64".equals(KernelIdentity.archOf(
                Arrays.copyOfRange(rawImage, 4096, 4096 + 5017))), "arm64 detection");
        check("LZ4_FRAME".equals(KernelIdentity.formatOf(new byte[]{4, 34, 77, 24})), "frame detection");
        byte[] ambiguousBanner = banner.clone();
        write(ambiguousBanner, 300, "Linux version 6.1.25-android14-11-o-gf12b379cb280\n");
        check(KernelIdentity.AMBIGUOUS.equals(KernelIdentity.releaseOf(ambiguousBanner)),
                "two distinct banners are ambiguous, never first-wins");
        check(KernelIdentity.releaseOf(new byte[]{'L', 'i', 'n', 'u', 'x'}).isEmpty(), "no banner is unreadable");
        byte[] gzip = KernelCompression.encode(new byte[200], "GZIP");
        gzip[gzip.length - 8] ^= 1;
        try { KernelCompression.decode(gzip, "GZIP", 1000); throw new AssertionError("CRC failure accepted"); }
        catch (IOException expected) { passed++; }
        // Deterministic malformed-block fuzzing must fail with IOException, never indexing exceptions.
        for (int i = 0; i < 1000; i++) {
            byte[] block = new byte[1 + random.nextInt(40)];
            random.nextBytes(block);
            try { KernelCompression.decode(legacy(block), "LZ4_LEGACY", 128); }
            catch (IOException expected) { /* expected for malformed blocks */ }
        }
        passed++;
        Path scratch = Files.createTempDirectory("maplesu-pipeline-test-");
        try {
            for (int version = 0; version <= 4; version++) {
                for (int page : version < 3 ? new int[]{2048, 4096, 8192, 16384} : new int[]{4096}) {
                    for (String format : new String[]{"GZIP", "LZ4_LEGACY", "RAW_ARM64", "LZ4_FRAME", "ZSTD", "XZ"}) {
                        byte[] original = fixture(version, format, page);
                        Path file = scratch.resolve("source.img");
                        Files.write(file, original);
                        BootImageRoundTrip.Report result = BootImageRoundTrip.verify(file.toFile(), scratch.toFile());
                        check(Arrays.equals(original, Files.readAllBytes(file)), "source unchanged " + version + format);
                        check(result.decodedKernelSize == 5017, "decoded size");
                        check("6.6.66-maplesu-fixture".equals(result.kernelRelease), "kernel banner");
                        check(result.toJson().contains("\"flashableCandidate\":false"), "no false flashable status");
                        try (var files = Files.list(scratch)) { check(files.count() == 1, "scratch cleaned"); }
                    }
                }
            }
            Path malformed = scratch.resolve("bad.img");
            byte[] bytes = fixture(4, "LZ4_LEGACY");
            bytes[4100] = -1; bytes[4101] = -1; bytes[4102] = -1; bytes[4103] = -1;
            Files.write(malformed, bytes);
            try { BootImageRoundTrip.verify(malformed.toFile(), scratch.toFile()); throw new AssertionError("invalid LZ4 accepted"); }
            catch (IOException expected) { passed++; }
            check(Arrays.equals(bytes, Files.readAllBytes(malformed)), "failed source unchanged");
            Thread.currentThread().interrupt();
            try { BootImageInspector.inspect(malformed.toFile()); throw new AssertionError("cancellation ignored"); }
            catch (IOException expected) { check("CANCELLED".equals(expected.getMessage()), "cancellation code"); }
            finally { Thread.interrupted(); }
        } finally {
            try (var files = Files.list(scratch)) { for (Path file : files.toList()) Files.delete(file); }
            Files.delete(scratch);
        }
        if (args.length > 0) {
            if (args.length != 2) throw new IllegalArgumentException("Provide zero or two reference paths");
            for (String path : args) {
                File source = new File(path);
                String before = BootImageInspector.inspect(source).sha256;
                File directory = Files.createTempDirectory("maplesu-reference-").toFile();
                try {
                    BootImageRoundTrip.Report result = BootImageRoundTrip.verify(source, directory);
                    check(result.decodedKernelSize == 36387328, "reference raw size");
                    check(result.kernelRelease.startsWith("6.6.66-android15-8-"), "reference release");
                    check(before.equals(BootImageInspector.inspect(source).sha256), "reference source unchanged");
                    System.out.println(result.toJson());
                } finally { Files.delete(directory.toPath()); }
            }
        }
        System.out.println("PASS " + passed + " pipeline checks (plus inspector checks)");
    }
}
