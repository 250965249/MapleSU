package dev.maplesu.image;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipInputStream;

/** File-only production-component round trips; inert CPIO data is not an init or kernel bridge. */
public final class InitBootRoundTripTest {
    private static int passed;
    private static final String HELPER = "maplesu-helper";

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        passed++;
    }

    private static byte[] resource(String name) throws IOException {
        try (InputStream input = InitBootRoundTripTest.class.getResourceAsStream("/" + name)) {
            if (input == null) throw new IOException("Missing fixture: " + name);
            return input.readAllBytes();
        }
    }

    private static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static int align(int value) { return (value + 4095) / 4096 * 4096; }

    private static byte[] image(byte[] encoded) {
        byte[] image = new byte[4096 + align(encoded.length)];
        ByteBuffer header = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        header.put("ANDROID!".getBytes(StandardCharsets.US_ASCII));
        header.putInt(12, encoded.length).putInt(16, 0x12345678).putInt(20, 1584).putInt(40, 4);
        byte[] cmdline = "console=ttyS0 initboot-roundtrip=1".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(cmdline, 0, image, 44, cmdline.length);
        System.arraycopy(encoded, 0, image, 4096, encoded.length);
        return image;
    }

    /** Append one fixture entry before the independently generated archive's fixed trailer. */
    private static byte[] withHelper(byte[] stock, byte[] content) throws IOException {
        int trailer = stock.length - 124;
        check(new String(stock, trailer + 110, 10, StandardCharsets.US_ASCII).equals("TRAILER!!!"),
                "Known GNU cpio fixture trailer");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(stock, 0, trailer);
        byte[] name = HELPER.getBytes(StandardCharsets.US_ASCII);
        long[] fields = {3, 0100755, 0, 0, 1, 0, content.length, 0, 0, 0, 0, name.length + 1, 0};
        out.write("070701".getBytes(StandardCharsets.US_ASCII));
        for (long value : fields)
            out.write(String.format(Locale.ROOT, "%08x", value).getBytes(StandardCharsets.US_ASCII));
        out.write(name); out.write(0);
        while ((out.size() & 3) != 0) out.write(0);
        out.write(content);
        while ((out.size() & 3) != 0) out.write(0);
        out.write(stock, trailer, stock.length - trailer);
        byte[] result = out.toByteArray();
        check(Arrays.equals(Arrays.copyOf(stock, trailer), Arrays.copyOf(result, trailer)),
                "All original CPIO headers and contents retained byte for byte");
        return result;
    }

    private static byte[] encode(byte[] raw, String format) throws IOException {
        if (format.equals("RAW")) return raw.clone();
        if (!format.equals("GZIP")) return KernelCompression.encode(raw, format);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(output)) { gzip.write(raw); }
        return output.toByteArray();
    }

    private static void entries(Path image, byte[] raw, byte[] helper, String format) throws Exception {
        RamdiskInspector.Report report = RamdiskInspector.inspect(image.toFile());
        check(!report.malformed && report.trailerSeen, "Complete CPIO readback: " + report.toJson());
        check(report.headerVersion == 4 && report.ramdiskOffset == 4096, "Kernel-free v4 ramdisk location");
        check(report.compression.equals(format), "Actual encoded format preserved");
        check(report.decompressedSha256.equals(sha(raw)), "Entire decoded archive matches expected bytes");
        Map<String, byte[]> expected = new LinkedHashMap<>();
        expected.put("init", "stock-android-init".getBytes(StandardCharsets.US_ASCII));
        expected.put("system/bin/sh", "stock-shell".getBytes(StandardCharsets.US_ASCII));
        if (helper != null) expected.put(HELPER, helper);
        check(report.entries.size() == expected.size(), "No dropped or duplicated entries");
        for (RamdiskInspector.Entry entry : report.entries) {
            byte[] content = expected.remove(entry.path);
            check(content != null, "Only expected paths");
            check(entry.mode == 0100755 && entry.isRegularFile(), "Original file type and permissions");
            check(entry.size == content.length && entry.sha256.equals(sha(content)), "Per-entry content identity");
        }
        check(expected.isEmpty(), "Original init and every original entry are present");
    }

    private static BootImageRebuilder.Report rebuild(Path source, byte[] encoded, Path output) throws Exception {
        byte[] before = Files.readAllBytes(source);
        Path replacement = output.resolveSibling(output.getFileName() + ".ramdisk");
        Files.write(replacement, encoded);
        BootImageRebuilder.Report report = BootImageRebuilder.rebuildRamdiskV4(
                source.toFile(), replacement.toFile(), output.toFile());
        byte[] result = Files.readAllBytes(output);
        check(report.image.headerVersion == 4 && report.image.kernelSize == 0 && !report.kernelChanged,
                "No kernel introduced or modified");
        check(report.image.ramdiskSize == encoded.length, "Actual replacement length");
        check(Arrays.equals(encoded, Arrays.copyOfRange(result, 4096, 4096 + encoded.length)),
                "Encoded component readback is exact");
        byte[] header = Arrays.copyOf(before, 4096);
        ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN).putInt(12, encoded.length).putInt(1580, 0);
        check(Arrays.equals(header, Arrays.copyOf(result, 4096)), "Other header bytes preserved");
        check(report.equivalence.ok() && report.toJson().contains("\"flashableCandidate\":false"),
                "Declared diff is verified without boot acceptance");
        check(Arrays.equals(before, Files.readAllBytes(source)), "Previous image remains immutable");
        check(Arrays.equals(encoded, Files.readAllBytes(replacement)), "Replacement remains immutable");
        return report;
    }

    private static void unsigned(Path work, byte[] stock, byte[] large, byte[] small) throws Exception {
        for (String format : List.of("RAW", "GZIP", "LZ4_FRAME")) {
            byte[] baseline = format.equals("LZ4_FRAME") ? resource("ramdisk-codecs/stock-checksums.cpio.lz4")
                    : encode(stock, format);
            Path source = work.resolve(format + "-stock.img");
            byte[] original = image(baseline);
            Files.write(source, original);
            entries(source, stock, null, format);
            byte[][] archives = {withHelper(stock, large), withHelper(stock, large), withHelper(stock, small), stock};
            String[] stages = {"grow", "repeat", "shrink", "restore"};
            long previousSize = baseline.length;
            for (int index = 0; index < stages.length; index++) {
                byte[] encoded = index == 3 ? baseline : encode(archives[index], format);
                Path output = work.resolve(format + "-" + stages[index] + ".img");
                BootImageRebuilder.Report report = rebuild(source, encoded, output);
                entries(output, archives[index], index == 3 ? null : index == 2 ? small : large, format);
                if (index == 0) check(encoded.length > previousSize + 4096, "Growth crosses page boundary");
                if (index == 1) check(!report.ramdiskChanged && Arrays.equals(Files.readAllBytes(source), Files.readAllBytes(output)),
                        "Repeated patch is byte-identical without extra entries");
                if (index == 2) check(encoded.length < previousSize, "Later patch shrinks the ramdisk");
                if (index == 3) check(Arrays.equals(original, Files.readAllBytes(output)), "Restoring original encoding restores exact image");
                previousSize = encoded.length;
                source = output;
            }
            System.out.println("PASS init_boot " + format + " grow/repeat/shrink/restore");
        }
    }

    private static boolean initHash(byte[] raw) {
        return ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN).getLong(0) == 2
                && new String(raw, 132, ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN).getInt(56),
                StandardCharsets.UTF_8).equals("init_boot");
    }

    private static void signed(Path work, byte[] stock, byte[] large, byte[] small) throws Exception {
        Path fixtures = Files.createDirectory(work.resolve("avb-fixtures"));
        Set<String> wanted = Set.of("init_boot.img", "vbmeta-nonchained.img", "boot.img",
                "testkey_rsa2048.pem", "testkey_rsa4096.pem");
        try (ZipInputStream zip = new ZipInputStream(InitBootRoundTripTest.class.getResourceAsStream("/lenovo-avb-fixtures.zip"))) {
            for (var entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry())
                if (wanted.contains(entry.getName())) Files.copy(zip, fixtures.resolve(entry.getName()));
        }
        Map<Integer, PrivateKey> keys = new LinkedHashMap<>();
        for (int bits : new int[]{2048, 4096}) keys.put(bits, LenovoAvbSigner.decodeKey(
                Files.readAllBytes(fixtures.resolve("testkey_rsa" + bits + ".pem"))));
        Path boot = fixtures.resolve("boot.img");
        byte[] originalBoot = Files.readAllBytes(boot);
        File original = fixtures.resolve("init_boot.img").toFile();
        byte[] originalInit = Files.readAllBytes(original.toPath());
        Map<String, File> current = Map.of("init_boot", original,
                "vbmeta", fixtures.resolve("vbmeta-nonchained.img").toFile());
        byte[][] archives = {stock, withHelper(stock, large), withHelper(stock, large), withHelper(stock, small), stock};
        String[] stages = {"seed", "grow", "repeat", "shrink", "restore"};
        for (int index = 0; index < stages.length; index++) {
            Path source = current.get("init_boot").toPath();
            byte[] previousInit = Files.readAllBytes(source), previousMeta = Files.readAllBytes(current.get("vbmeta").toPath());
            LenovoAvbSigner.Info parameters = LenovoAvbSigner.read(current.get("vbmeta"));
            byte[] encoded = archives[index];
            Path candidate = work.resolve("signed-" + stages[index] + "-candidate.img");
            BootImageRebuilder.Report report = rebuild(source, encoded, candidate);
            check(report.avbFooterPresent, "Existing footer preserved and relocated");
            if (report.ramdiskChanged) {
                try {
                    LenovoAvbSigner.verifySigned(LenovoAvbSigner.Mode.NON_CHAINED, "init_boot",
                            Map.of("init_boot", candidate.toFile(), "vbmeta", current.get("vbmeta")));
                    throw new AssertionError("Changed candidate retained a valid old hash");
                } catch (IOException expected) {
                    check(expected.getMessage().equals("LENOVO_AVB_HASH_MISMATCH"), "Stale AVB hash is detected");
                }
            }
            Map<String, File> result = LenovoAvbSigner.sign(LenovoAvbSigner.Mode.NON_CHAINED, "init_boot",
                    candidate.toFile(), current.get("init_boot"), Map.of("vbmeta", current.get("vbmeta")),
                    work.resolve("signed-" + stages[index]).toFile(), keys::get, message -> {});
            LenovoAvbSigner.verifySigned(LenovoAvbSigner.Mode.NON_CHAINED, "init_boot", result);
            check(result.keySet().equals(Set.of("init_boot", "vbmeta")), "Signing output excludes boot");
            File target = result.get("init_boot");
            check(target.length() == original.length(), "Partition capacity retained through repeated signing");
            AvbFooter footer = AvbFooter.parse(target);
            check(footer.valid(target.length()) && footer.originalImageSize == 4096 + align(encoded.length),
                    "Signed footer covers actual rebuilt component boundary");
            LenovoAvbSigner.Info after = LenovoAvbSigner.read(result.get("vbmeta"));
            check(after.algorithm == parameters.algorithm && after.rollback == parameters.rollback
                    && after.flags == parameters.flags && Arrays.equals(after.key, parameters.key),
                    "Companion signing identity and parameters preserved");
            if (index > 0) check(after.raw.size() == parameters.raw.size(),
                    "Repeated signing does not accumulate descriptors: " + stages[index]
                            + " before=" + parameters.raw.size() + " after=" + after.raw.size());
            for (byte[] raw : parameters.raw) if (!initHash(raw))
                check(after.raw.stream().anyMatch(value -> Arrays.equals(raw, value)), "Non-target descriptors preserved");
            check(Arrays.equals(previousInit, Files.readAllBytes(source))
                    && Arrays.equals(previousMeta, Files.readAllBytes(current.get("vbmeta").toPath())), "Signing inputs immutable");
            entries(target.toPath(), archives[index], index == 0 || index == 4 ? null : index == 3 ? small : large, "RAW");
            if (index == 2) check(!report.ramdiskChanged && Arrays.equals(previousInit, Files.readAllBytes(target.toPath())),
                    "Signed repeat does not accumulate content or alter target bytes");
            check(Arrays.equals(originalBoot, Files.readAllBytes(boot)), "Separate boot and its kernel remain byte-identical");
            check(Arrays.equals(originalInit, Files.readAllBytes(original.toPath())), "Original signed init_boot remains immutable");
            current = result;
        }
        System.out.println("PASS init_boot AVB seed/grow/repeat/shrink/restore with signature verification");
    }

    public static void main(String[] args) throws Exception {
        Path root = Path.of(System.getProperty("maplesu.root", System.getProperty("java.io.tmpdir")));
        Path work = Files.createTempDirectory(root, "maplesu-initboot-roundtrip-");
        try {
            byte[] stock = resource("ramdisk-codecs/stock.cpio");
            check(sha(stock).equals("e63cfbea5bf581bbecdbfecfaf5c8a897347077613bffc7ddfd964a8792cf0e5"),
                    "Independent cpio fixture identity");
            byte[] large = new byte[12345];
            new Random(173).nextBytes(large);
            byte[] small = "MapleSU inert helper v2".getBytes(StandardCharsets.US_ASCII);
            unsigned(work, stock, large, small);
            signed(work, stock, large, small);
            System.out.println("PASS " + passed + " init_boot roundtrip checks; file-only, no kernel bridge or device boot");
        } finally {
            try (var files = Files.walk(work)) {
                for (Path path : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }
}
