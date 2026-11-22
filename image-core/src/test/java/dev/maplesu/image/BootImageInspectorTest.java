package dev.maplesu.image;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Random;

public final class BootImageInspectorTest {
    private static int passed;

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        passed++;
    }

    private static byte[] fixture(int version) {
        byte[] bytes = new byte[8192];
        ByteBuffer header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        header.put(new byte[]{'A', 'N', 'D', 'R', 'O', 'I', 'D', '!'});
        header.putInt(8, 64);
        header.putInt(20, version == 4 ? 1584 : 1580);
        header.putInt(40, version);
        bytes[4096] = 31;
        bytes[4097] = (byte) 139;
        return bytes;
    }

    private static BootImageInspector.Report inspect(byte[] bytes) throws Exception {
        Path file = Files.createTempFile("maplesu-image-test-", ".img");
        try {
            Files.write(file, bytes);
            return BootImageInspector.inspect(file.toFile());
        } finally {
            Files.delete(file);
        }
    }

    private static byte[] legacyFixture(int version, int pageSize) {
        byte[] bytes = new byte[pageSize * 7 + 17];
        ByteBuffer header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        header.put(new byte[]{'A', 'N', 'D', 'R', 'O', 'I', 'D', '!'});
        header.putInt(8, pageSize + 7).putInt(16, 71).putInt(24, 53);
        header.putInt(36, pageSize).putInt(40, version);
        if (version >= 1) {
            header.putInt(1632, 31).putLong(1636, pageSize * 5L);
            header.putInt(1644, version == 1 ? 1648 : 1660);
        }
        if (version == 2) header.putInt(1648, 19);
        bytes[pageSize] = 31;
        bytes[pageSize + 1] = (byte) 139;
        return bytes;
    }

    private static void invalid(byte[] bytes, String code) throws Exception {
        try {
            inspect(bytes);
            throw new AssertionError("Expected " + code);
        } catch (BootImageInspector.InvalidImageException exception) {
            check(code.equals(exception.code), "Wrong rejection code: " + exception.code);
        }
    }

    public static void main(String[] args) throws Exception {
        check(inspect(fixture(3)).headerVersion == 3, "v3 header");
        check("GZIP".equals(inspect(fixture(4)).compression), "gzip recognition");
        invalid(new byte[20], "TRUNCATED_HEADER");
        invalid(new byte[4096], "INVALID_MAGIC");
        for (int version = 0; version <= 2; version++) {
            for (int page : new int[]{2048, 4096, 8192, 16384}) {
                BootImageInspector.Report legacy = inspect(legacyFixture(version, page));
                check(legacy.headerVersion == version, "legacy version");
                check(legacy.kernelOffset == page, "legacy kernel page");
                check(legacy.ramdiskOffset == page * 3L && legacy.ramdiskSize == 71,
                        "legacy ramdisk follows aligned kernel");
                check("GZIP".equals(legacy.compression), "legacy compression");
                check(legacy.pageSize == page && legacy.headerSize == new int[]{1632, 1648, 1660}[version],
                        "legacy page and header sizes");
                check(legacy.secondOffset == page * 4L && legacy.secondSize == 53, "second stage");
                check(legacy.recoveryDtboOffset == (version == 0 ? 0 : page * 5L)
                        && legacy.recoveryDtboSize == (version == 0 ? 0 : 31), "recovery DTBO");
                check(legacy.dtbOffset == (version == 2 ? page * 6L : 0)
                        && legacy.dtbSize == (version == 2 ? 19 : 0), "DTB");
                check(legacy.signatureSize == 0 && legacy.signatureOffset == 0, "no legacy boot signature");
            }
            byte[] empty = legacyFixture(version, 2048);
            ByteBuffer head = ByteBuffer.wrap(empty).order(ByteOrder.LITTLE_ENDIAN);
            head.putInt(8, 0).putInt(16, 0).putInt(24, 0);
            if (version >= 1) head.putInt(1632, 0).putLong(1636, 0);
            if (version == 2) head.putInt(1648, 0);
            BootImageInspector.Report report = inspect(empty);
            check(report.kernelSize == 0 && report.ramdiskOffset == 2048
                    && report.secondOffset == 2048 && report.recoveryDtboOffset == 0
                    && report.dtbOffset == (version == 2 ? 2048 : 0), "empty legacy components");
            invalid(Arrays.copyOf(empty, new int[]{1632, 1648, 1660}[version] - 1), "TRUNCATED_HEADER");
            invalid(Arrays.copyOf(empty, 2047), "TRUNCATED_HEADER_PAGE");
        }
        for (int page : new int[]{0, 1024, 3072, 65536, -1}) {
            byte[] malformed = legacyFixture(2, 2048);
            ByteBuffer.wrap(malformed).order(ByteOrder.LITTLE_ENDIAN).putInt(36, page);
            invalid(malformed, "INVALID_PAGE_SIZE");
        }
        for (int version : new int[]{1, 2}) {
            for (int size : new int[]{1647, 2049, -1}) {
                byte[] malformed = legacyFixture(version, 2048);
                ByteBuffer.wrap(malformed).order(ByteOrder.LITTLE_ENDIAN).putInt(1644, size);
                invalid(malformed, "INVALID_HEADER_SIZE");
            }
        }
        for (long offset : new long[]{0, 1, 2048, 10239, 10241, 12288, 1L << 32, Long.MAX_VALUE, Long.MIN_VALUE, -1}) {
            byte[] malformed = legacyFixture(2, 2048);
            ByteBuffer.wrap(malformed).order(ByteOrder.LITTLE_ENDIAN).putLong(1636, offset);
            invalid(malformed, "INVALID_RECOVERY_DTBO_OFFSET");
        }
        byte[] absentDtbo = legacyFixture(2, 2048);
        ByteBuffer.wrap(absentDtbo).order(ByteOrder.LITTLE_ENDIAN).putInt(1632, 0);
        invalid(absentDtbo, "INVALID_RECOVERY_DTBO_OFFSET");
        ByteBuffer.wrap(absentDtbo).order(ByteOrder.LITTLE_ENDIAN).putLong(1636, 0);
        check(inspect(absentDtbo).dtbOffset == 10240, "DTB without recovery DTBO");
        for (int field : new int[]{8, 16, 24, 1632, 1648}) {
            byte[] malformed = legacyFixture(2, 2048);
            ByteBuffer.wrap(malformed).order(ByteOrder.LITTLE_ENDIAN).putInt(field, -1);
            invalid(malformed, "COMPONENT_OUT_OF_BOUNDS");
        }
        for (int end : new int[]{2048 + 2055, 6144 + 71, 8192 + 53, 10240 + 31, 12288 + 19}) {
            invalid(Arrays.copyOf(legacyFixture(2, 2048), end - 1), "COMPONENT_OUT_OF_BOUNDS");
        }
        Random random = new Random(20261024);
        for (int i = 0; i < 1000; i++) {
            byte[] malformed = new byte[44 + random.nextInt(20000)];
            random.nextBytes(malformed);
            System.arraycopy(new byte[]{'A', 'N', 'D', 'R', 'O', 'I', 'D', '!'}, 0, malformed, 0, 8);
            ByteBuffer.wrap(malformed).order(ByteOrder.LITTLE_ENDIAN).putInt(40, i % 6);
            try { inspect(malformed); }
            catch (BootImageInspector.InvalidImageException expected) { /* No indexing/overflow failures. */ }
        }
        check(true, "deterministic malformed-header fuzzing");
        byte[] bytes = fixture(5);
        invalid(bytes, "UNSUPPORTED_HEADER");
        bytes = fixture(4);
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(20, 100);
        invalid(bytes, "INVALID_HEADER_SIZE");
        bytes = fixture(4);
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(8, -1);
        invalid(bytes, "COMPONENT_OUT_OF_BOUNDS");
        bytes = fixture(4);
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(12, 100);
        invalid(bytes, "COMPONENT_OUT_OF_BOUNDS");
        bytes = fixture(4);
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(1580, 1);
        invalid(bytes, "COMPONENT_OUT_OF_BOUNDS");
        bytes = fixture(4);
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(8, 0).putInt(12, 64);
        check(inspect(bytes).kernelSize == 0, "init_boot remains identifiable");
        check("NONE".equals(inspect(bytes).compression), "empty kernel compression");
        if (args.length == 0) {
            System.out.println("PASS " + passed + " checks (synthetic fixtures)");
            return;
        }
        if (args.length != 2) throw new IllegalArgumentException("Provide zero or two sample paths");
        BootImageInspector.Report original = BootImageInspector.inspect(new File(args[0]));
        BootImageInspector.Report patched = BootImageInspector.inspect(new File(args[1]));
        check(original.fileSize == 67108864 && patched.fileSize == 67108864, "real file sizes");
        check(original.kernelSize == 17071722 && patched.kernelSize == 17071982, "real kernel sizes");
        check(original.ramdiskSize == 0 && patched.ramdiskSize == 1380093, "real ramdisk delta");
        check("LZ4_LEGACY".equals(original.compression)
                && "LZ4_LEGACY".equals(patched.compression), "real compression");
        check(original.sha256.equals("65b7354f8e8b258f96d73d3701832cdf4141cdb4ec9a9897c08e2c1d28f547e3"), "original intact");
        check(patched.sha256.equals("3a1c906b42db49fca72f4a36a69c92257a67f678d73561d0a11eab3b084475cc"), "patched sample intact");
        System.out.println("PASS " + passed + " checks");
    }
}
