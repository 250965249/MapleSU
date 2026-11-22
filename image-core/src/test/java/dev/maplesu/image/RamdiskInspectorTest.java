package dev.maplesu.image;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Random;

/**
 * Synthetic, byte-level fixtures for {@link RamdiskInspector}.
 *
 * <p>No private device image is required: CPIO newc archives, their gzip/LZ4-legacy
 * encodings and AOSP boot v0/v4 containers are constructed in memory. The suite covers
 * the KSU LKM form, stock form, the Lite (kernel-only) patch variant, malformed
 * archives (truncation, pseudo entries, duplicates, path traversal, missing trailer,
 * oversized limits) and the defensive decoder cases (gzip trailing bytes, LZ4 damage,
 * unsupported compression). Run through {@code :image-core:checkRamdiskFixtures}.
 */
public final class RamdiskInspectorTest {
    private static int passed;

    private static final int S_IFREG = 0100000;
    private static final int S_IFDIR = 0040000;

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        passed++;
    }

    // ------------------------------------------------------------------ CPIO fixtures

    private static final class CpioEntry {
        final String name;
        final int mode;
        final byte[] data;

        CpioEntry(String name, int mode, byte[] data) {
            this.name = name;
            this.mode = mode;
            this.data = data;
        }
    }

    private static CpioEntry file(String name, int mode, String content) {
        return new CpioEntry(name, mode, content.getBytes(StandardCharsets.UTF_8));
    }

    private static CpioEntry file(String name, int mode, byte[] content) {
        return new CpioEntry(name, mode, content);
    }

    private static CpioEntry dir(String name, int mode) {
        return new CpioEntry(name, mode, new byte[0]);
    }

    private static byte[] cpio(List<CpioEntry> entries) {
        return cpio(entries, false, true);
    }

    private static byte[] cpio(List<CpioEntry> entries, boolean crcFormat, boolean trailer) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (CpioEntry entry : entries) writeEntry(out, entry, crcFormat);
        if (trailer) writeEntry(out, new CpioEntry("TRAILER!!!", S_IFREG, new byte[0]), crcFormat);
        return out.toByteArray();
    }

    private static void writeEntry(ByteArrayOutputStream out, CpioEntry entry, boolean crcFormat) {
        byte[] name = entry.name.getBytes(StandardCharsets.UTF_8);
        writeAscii(out, crcFormat ? "070702" : "070701");
        appendHex8(out, 1);                       // ino
        appendHex8(out, entry.mode);
        appendHex8(out, 0);                       // uid
        appendHex8(out, 0);                       // gid
        appendHex8(out, 1);                       // nlink
        appendHex8(out, 0);                       // mtime
        appendHex8(out, entry.data.length);
        appendHex8(out, 0);                       // devmajor
        appendHex8(out, 0);                       // devminor
        appendHex8(out, 0);                       // rdevmajor
        appendHex8(out, 0);                       // rdevminor
        appendHex8(out, name.length + 1);
        appendHex8(out, crcFormat ? checksum(entry.data) : 0);
        out.write(name, 0, name.length);
        out.write(0);
        pad4(out);
        out.write(entry.data, 0, entry.data.length);
        pad4(out);
    }

    private static void writeAscii(ByteArrayOutputStream out, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        out.write(bytes, 0, bytes.length);
    }

    private static void appendHex8(ByteArrayOutputStream out, long value) {
        writeAscii(out, String.format(Locale.ROOT, "%08x", value & 0xffffffffL));
    }

    private static void pad4(ByteArrayOutputStream out) {
        while (out.size() % 4 != 0) out.write(0);
    }

    private static long checksum(byte[] data) {
        long sum = 0;
        for (byte value : data) sum += value & 255;
        return sum;
    }

    /** Minimal CPIO header whose fields the caller wants to corrupt. */
    private static byte[] rawHeader(String magic, int mode, int fileSize, int nameSize, String modeText) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeAscii(out, magic);
        appendHex8(out, 1);
        writeAscii(out, modeText);
        appendHex8(out, 0);
        appendHex8(out, 0);
        appendHex8(out, 1);
        appendHex8(out, 0);
        appendHex8(out, fileSize);
        appendHex8(out, 0);
        appendHex8(out, 0);
        appendHex8(out, 0);
        appendHex8(out, 0);
        appendHex8(out, nameSize);
        appendHex8(out, 0);
        return out.toByteArray();
    }

    private static long align4(long value) { return (value + 3L) & ~3L; }

    // ------------------------------------------------------------------ ramdisk fixtures

    private static List<CpioEntry> ksuEntries(boolean withMaplesuId) {
        List<CpioEntry> entries = new ArrayList<>();
        entries.add(file("init", S_IFREG | 0755, "ksuinit-fixture-v1"));
        entries.add(file("init.real", S_IFREG | 0755, "android-init-fixture"));
        entries.add(file("kernelsu.ko", S_IFREG | 0644, "kernelsu-module-fixture"));
        entries.add(file("ksu_config", S_IFREG | 0644, "uapi=7\n"));
        entries.add(file("ksud", S_IFREG | 0755, "ksud-fixture"));
        entries.add(dir("data/adb/ksu", S_IFDIR | 0755));
        entries.add(file("data/adb/ksu/.allowlist", S_IFREG | 0600, ""));
        if (withMaplesuId) entries.add(file("maplesu_id", S_IFREG | 0644, new byte[0]));
        return entries;
    }

    private static List<CpioEntry> stockEntries() {
        List<CpioEntry> entries = new ArrayList<>();
        entries.add(file("init", S_IFREG | 0755, "stock-android-init"));
        entries.add(dir("system", S_IFDIR | 0755));
        entries.add(dir("system/bin", S_IFDIR | 0755));
        entries.add(file("system/bin/sh", S_IFREG | 0755, "stock-shell"));
        entries.add(file("fstab.qcom", S_IFREG | 0644, "stock-fstab"));
        entries.add(file("sbin/adbd", S_IFREG | 0755, "stock-adbd"));
        return entries;
    }

    private static byte[] ksuRamdisk(boolean withMaplesuId) {
        return cpio(ksuEntries(withMaplesuId));
    }

    private static byte[] stockRamdisk() {
        return cpio(stockEntries());
    }

    // ------------------------------------------------------------------ container fixtures

    private static byte[] containerV4(byte[] kernel, byte[] ramdisk) {
        long offset = align(4096 + kernel.length, 4096);
        byte[] image = new byte[(int) align(offset + ramdisk.length, 4096)];
        ByteBuffer header = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        header.put("ANDROID!".getBytes(StandardCharsets.US_ASCII));
        header.putInt(8, kernel.length).putInt(12, ramdisk.length).putInt(20, 1584).putInt(40, 4);
        System.arraycopy(kernel, 0, image, 4096, kernel.length);
        System.arraycopy(ramdisk, 0, image, (int) offset, ramdisk.length);
        return image;
    }

    private static byte[] containerV0(byte[] kernel, byte[] ramdisk, int pageSize) {
        long offset = align(pageSize + kernel.length, pageSize);
        byte[] image = new byte[(int) align(offset + ramdisk.length, pageSize)];
        ByteBuffer header = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        header.put("ANDROID!".getBytes(StandardCharsets.US_ASCII));
        header.putInt(8, kernel.length).putInt(16, ramdisk.length).putInt(24, 0)
                .putInt(36, pageSize).putInt(40, 0);
        System.arraycopy(kernel, 0, image, pageSize, kernel.length);
        System.arraycopy(ramdisk, 0, image, (int) offset, ramdisk.length);
        return image;
    }

    private static long align(long value, long page) {
        return (value + page - 1) / page * page;
    }

    private static byte[] randomBytes(int length, long seed) {
        byte[] bytes = new byte[length];
        new Random(seed).nextBytes(bytes);
        return bytes;
    }

    // ------------------------------------------------------------------ helpers

    private static RamdiskInspector.Report inspectFile(byte[] bytes) throws IOException {
        Path file = Files.createTempFile("maplesu-ramdisk-fixture-", ".img");
        try {
            Files.write(file, bytes);
            return RamdiskInspector.inspect(file.toFile());
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static String sha256(byte[] bytes) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        StringBuilder out = new StringBuilder(64);
        for (byte value : digest.digest(bytes)) out.append(String.format(Locale.ROOT, "%02x", value & 255));
        return out.toString();
    }

    private static void rejects(byte[] bytes, String code, String label) {
        RamdiskInspector.Report report = RamdiskInspector.inspect(bytes);
        check(report.malformed, label + ": malformed flag");
        check(code.equals(report.errorCode), label + ": expected " + code + " but was " + report.errorCode);
        check(!report.rejectMalformed().ok, label + ": rejectMalformed must fail");
    }

    private static int problemsWith(byte[] bytes, String code) {
        int count = 0;
        for (RamdiskInspector.Problem problem : RamdiskInspector.inspect(bytes).problems) {
            if (code.equals(problem.code)) count++;
        }
        return count;
    }

    // ------------------------------------------------------------------ cases

    private static void ksuLkmForm() throws Exception {
        RamdiskInspector.Report report = RamdiskInspector.inspect(ksuRamdisk(true));
        check("RAMDISK_COMPONENT".equals(report.sourceKind), "source kind");
        check(report.headerVersion == -1, "component header version");
        check("RAW".equals(report.compression), "raw compression");
        check(!report.malformed && report.errorCode == null, "well-formed KSU ramdisk");
        check(report.hasInit && report.hasInitReal && report.hasKernelsuKo && report.hasKsuConfig,
                "KSU marker entries detected");
        check(report.hasMaplesuId && report.hasKsud && report.hasDataAdbKsuPath, "owner/ksud/ksu paths detected");
        check(report.form() == RamdiskInspector.Form.KSU_LKM_OURS, "owned KSU form");
        check(report.requireKsuLkmForm().ok, "requireKsuLkmForm accepts owned form");
        check(report.requireOwnedKsuLkmForm().ok, "requireOwnedKsuLkmForm accepts");
        check(report.rejectMalformed().ok, "rejectMalformed accepts clean archive");
        RamdiskInspector.Verdict stock = report.requireStockForm();
        check(!stock.ok && "STOCK_HAS_KSU_RESIDUE".equals(stock.code), "stock assertion rejects KSU form");
        check(stock.violations.contains("kernelsu.ko") && stock.violations.contains("init.real"),
                "stock violations name the residual entries");
        check(report.trailerSeen && report.trailingBytes == 0, "trailer seen without trailing bytes");
        check(report.entries.size() == 8, "entry count");
        check(report.ksuRelatedPaths.size() >= 5, "ksu related paths");
        RamdiskInspector.Entry init = report.entry("init");
        check(init != null && init.isRegularFile() && init.permissions() == 0755, "init mode");
        check(init.size == "ksuinit-fixture-v1".getBytes(StandardCharsets.UTF_8).length, "init size");
        check(init.offset == align4(110 + "init".getBytes(StandardCharsets.UTF_8).length + 1),
                "first entry data offset");
        RamdiskInspector.Entry module = report.entry("kernelsu.ko");
        check(module != null && module.isRegularFile() && module.size == "kernelsu-module-fixture".length(),
                "kernelsu.ko size");
        check(sha256("kernelsu-module-fixture".getBytes(StandardCharsets.UTF_8)).equals(module.sha256),
                "kernelsu.ko digest");
        String json = report.toJson();
        check(json.contains("\"form\":\"KSU_LKM_OURS\""), "json form");
        check(json.contains("\"hasKernelsuKo\":true") && json.contains("\"malformed\":false"), "json flags");
        check(json.contains("\"entryCount\":8"), "json entry count");
    }

    private static void compatibleKsuForm() throws Exception {
        RamdiskInspector.Report report = RamdiskInspector.inspect(ksuRamdisk(false));
        check(report.form() == RamdiskInspector.Form.KSU_LKM_COMPATIBLE, "official-style KSU compatible form");
        check(report.requireKsuLkmForm().ok, "base LKM form accepted without marker");
        RamdiskInspector.Verdict owned = report.requireOwnedKsuLkmForm();
        check(!owned.ok && "MISSING_MAPLESU_ID".equals(owned.code), "owner marker required by owned form");
        check(report.requireStockForm().code.equals("STOCK_HAS_KSU_RESIDUE"), "compatible is not stock");
    }

    private static void stockForm() throws Exception {
        RamdiskInspector.Report report = RamdiskInspector.inspect(stockRamdisk());
        check(!report.malformed, "stock ramdisk well formed");
        check(report.form() == RamdiskInspector.Form.STOCK, "stock form");
        check(report.requireStockForm().ok, "stock assertion accepts OEM ramdisk");
        RamdiskInspector.Verdict ksu = report.requireKsuLkmForm();
        check(!ksu.ok && "MISSING_KERNELSU_KO".equals(ksu.code), "KSU assertion rejects stock");
        check(ksu.violations.contains("kernelsu.ko") && ksu.violations.contains("init.real"),
                "KSU violations list required entries");
        check(report.entry("init") != null && report.entry("init.real") == null, "stock init only");
        check(report.toJson().contains("\"form\":\"STOCK\""), "json stock form");
    }

    private static void compressedRoundTrip() throws Exception {
        byte[] raw = ksuRamdisk(true);
        for (String format : new String[]{"GZIP", "LZ4_LEGACY"}) {
            byte[] encodedBytes = KernelCompression.encode(raw, format);
            RamdiskInspector.Report report = RamdiskInspector.inspectRamdisk(encodedBytes);
            check(format.equals(report.compression), format + ": compression label");
            check(!report.malformed, format + ": decodes cleanly");
            check(report.entries.size() == 8, format + ": entries");
            check(report.requireKsuLkmForm().ok, format + ": KSU form");
            check(report.decompressedSize == raw.length, format + ": decoded size");
            check(sha256(raw).equals(report.decompressedSha256), format + ": decoded digest");
            check(sha256(encodedBytes).equals(report.sha256), format + ": encoded digest");
            check(report.form() == RamdiskInspector.Form.KSU_LKM_OURS, format + ": form");
        }
    }

    private static void bootV4Container() throws Exception {
        byte[] kernel = randomBytes(1024, 7);
        byte[] ramdisk = KernelCompression.encode(ksuRamdisk(true), "GZIP");
        byte[] image = containerV4(kernel, ramdisk);
        RamdiskInspector.Report fromBytes = RamdiskInspector.inspect(image);
        RamdiskInspector.Report fromFile = inspectFile(image);
        check(fromBytes.headerVersion == 4 && fromFile.headerVersion == 4, "v4 header version");
        check("BOOT_IMAGE".equals(fromBytes.sourceKind), "v4 source kind");
        check(fromBytes.fileSize == image.length && fromFile.fileSize == image.length, "image file size");
        check(fromBytes.ramdiskOffset == align(4096 + kernel.length, 4096), "v4 ramdisk offset");
        check(fromBytes.ramdiskSize == ramdisk.length, "v4 ramdisk size");
        check("GZIP".equals(fromBytes.compression), "v4 ramdisk compression");
        check(fromBytes.requireKsuLkmForm().ok, "v4 candidate KSU form");
        check(fromBytes.hasInit && fromBytes.hasKernelsuKo, "v4 ramdisk markers");
        check(fromBytes.toJson().equals(fromFile.toJson()), "byte and file container reports agree");
    }

    private static void bootLegacyContainer() throws Exception {
        int page = 2048;
        byte[] kernel = randomBytes(256, 11);
        byte[] ramdisk = KernelCompression.encode(stockRamdisk(), "LZ4_LEGACY");
        byte[] image = containerV0(kernel, ramdisk, page);
        RamdiskInspector.Report fromBytes = RamdiskInspector.inspect(image);
        RamdiskInspector.Report fromFile = inspectFile(image);
        check(fromBytes.headerVersion == 0 && fromFile.headerVersion == 0, "v0 header version");
        check(fromBytes.ramdiskOffset == align(page + kernel.length, page), "v0 ramdisk offset");
        check("LZ4_LEGACY".equals(fromBytes.compression), "v0 LZ4 ramdisk");
        check(fromBytes.requireStockForm().ok, "v0 stock ramdisk form");
        check(fromBytes.toJson().equals(fromFile.toJson()), "legacy byte and file reports agree");
    }

    private static void initBootWithoutKernel() throws Exception {
        byte[] ramdisk = KernelCompression.encode(ksuRamdisk(true), "GZIP");
        byte[] image = containerV4(new byte[0], ramdisk);
        RamdiskInspector.Report report = inspectFile(image);
        check(report.headerVersion == 4 && report.ramdiskOffset == 4096, "init_boot layout without kernel");
        check(report.requireKsuLkmForm().ok, "no-kernel container is still valid for ramdisk assertions");
        check(report.ramdiskSize == ramdisk.length, "init_boot ramdisk size");
    }

    private static void litePatchVariant() throws Exception {
        // A = Lite: stock OEM ramdisk, but the kernel component is patched. The ramdisk
        // must stay stock and must never be accepted as the KSU LKM form.
        byte[] stock = KernelCompression.encode(stockRamdisk(), "GZIP");
        byte[] before = containerV4(randomBytes(2048, 21), stock);
        byte[] after = containerV4(randomBytes(2048, 22), stock);
        RamdiskInspector.Report original = RamdiskInspector.inspect(before);
        RamdiskInspector.Report patched = RamdiskInspector.inspect(after);
        check(original.form() == RamdiskInspector.Form.STOCK, "Lite source ramdisk is stock");
        check(patched.form() == RamdiskInspector.Form.STOCK, "Lite patched kernel keeps stock ramdisk form");
        check(patched.requireStockForm().ok, "Lite ramdisk passes stock assertion");
        check(!patched.requireKsuLkmForm().ok, "Lite ramdisk is not a KSU LKM candidate");
        check("MISSING_KERNELSU_KO".equals(patched.requireKsuLkmForm().code), "Lite missing kernelsu.ko");
        check(original.sha256.equals(patched.sha256), "kernel patch leaves the ramdisk bytes untouched");
        check(original.decompressedSha256.equals(patched.decompressedSha256),
                "decoded ramdisk evidence is kernel independent");
        check(original.entries.size() == patched.entries.size(), "kernel patch keeps ramdisk entries");
    }

    private static void trailingDataAfterTrailer() {
        byte[] archive = stockRamdisk();
        RamdiskInspector.Report padded = RamdiskInspector.inspect(concat(archive, new byte[512]));
        check(!padded.malformed, "zero padding after trailer is tolerated");
        byte[] junk = concat(archive, "JUNK".getBytes(StandardCharsets.US_ASCII));
        RamdiskInspector.Report report = RamdiskInspector.inspect(junk);
        check(report.malformed && "TRAILING_DATA".equals(report.errorCode), "non-zero bytes after trailer rejected");
        check(report.trailingBytes == 4, "trailing byte count");
        check(report.rejectMalformed().violations.contains("TRAILING_DATA"), "trailing data named");
    }

    private static void gzipTrailingGarbage() throws Exception {
        byte[] raw = stockRamdisk();
        byte[] gzip = KernelCompression.encode(raw, "GZIP");
        RamdiskInspector.Report padded = RamdiskInspector.inspect(concat(gzip, new byte[256]));
        check(!padded.malformed, "gzip zero page padding is accepted");
        check(padded.requireStockForm().ok, "padded gzip still parses entries");
        byte[] garbage = concat(gzip, new byte[]{1, 2, 3, 4});
        RamdiskInspector.Report report = RamdiskInspector.inspect(garbage);
        check(report.malformed && "TRAILING_DATA".equals(report.errorCode), "gzip trailing garbage rejected");
        check(report.entries.size() == 6, "gzip trailing garbage still reports entries");
    }

    private static void lz4Defects() {
        byte[] magic = {2, 33, 76, 24};
        rejects(concat(magic, new byte[]{0, 0, 0, 0}), "INVALID_LZ4_BLOCK_SIZE", "zero LZ4 block size");
        rejects(concat(magic, new byte[]{1, 2}), "TRUNCATED_LZ4_BLOCK_HEADER", "truncated LZ4 header");
        rejects(concat(magic, new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}),
                "INVALID_LZ4_BLOCK_SIZE", "oversized LZ4 block");
    }

    private static void compressedTrailingData() throws Exception {
        byte[] raw = stockRamdisk();
        for (String format : new String[]{"LZ4_FRAME", "XZ", "ZSTD"}) {
            byte[] encoded = KernelCompression.encode(raw, format);
            RamdiskInspector.Report expected = RamdiskInspector.inspectRamdisk(encoded);
            for (byte[] suffix : new byte[][]{new byte[1], new byte[257]}) {
                RamdiskInspector.Report padded = RamdiskInspector.inspectRamdisk(concat(encoded, suffix));
                check(!padded.malformed && padded.trailingBytes == 0,
                        format + " zero component padding accepted");
                check(padded.decompressedSha256.equals(expected.decompressedSha256)
                        && padded.entries.size() == expected.entries.size(),
                        format + " padding preserves decoded archive");
            }
            for (byte[] suffix : new byte[][]{new byte[]{1}, new byte[]{0, 1, 0, 2, 3, 0},
                    Arrays.copyOf(encoded, 3)}) {
                byte[] tailed = concat(encoded, suffix), original = tailed.clone();
                int nonZero = 0;
                for (byte value : suffix) if (value != 0) nonZero++;
                for (byte[] input : new byte[][]{tailed, containerV4(new byte[0], tailed),
                        containerV4(new byte[71], tailed), containerV0(new byte[71], tailed, 4096)}) {
                    RamdiskInspector.Report report = RamdiskInspector.inspect(input);
                    check(report.malformed && "TRAILING_DATA".equals(report.errorCode),
                            format + " encoded garbage rejected through component/container entry");
                    check(report.trailingBytes == nonZero, format + " encoded nonzero tail counted");
                    check(report.entries.size() == expected.entries.size()
                            && report.decompressedSha256.equals(expected.decompressedSha256),
                            format + " complete entries remain diagnostic after encoded tail error");
                    check(!report.requireStockForm().ok && !report.requireKsuLkmForm().ok,
                            format + " malformed encoded tail never passes a form requirement");
                }
                check(Arrays.equals(original, tailed), format + " encoded tail inspection is read-only");
                check(Arrays.equals(raw, KernelCompression.decode(tailed, format, raw.length)),
                        format + " general kernel decoder retains stream-prefix contract");
                byte[] rebuilt = KernelCompression.encodeKernelComponent(raw, tailed, format);
                check(Arrays.equals(suffix, Arrays.copyOfRange(rebuilt, rebuilt.length - suffix.length,
                        rebuilt.length)), format + " kernel component encoder preserves opaque suffix");
            }
            byte[] decodedGarbage = concat(raw, new byte[]{1, 2});
            byte[] both = concat(KernelCompression.encode(decodedGarbage, format), new byte[]{3});
            RamdiskInspector.Report bothReport = RamdiskInspector.inspectRamdisk(both);
            check(bothReport.malformed && "TRAILING_DATA".equals(bothReport.errorCode)
                    && bothReport.trailingBytes == 3,
                    format + " decoded and encoded nonzero tails both counted");
            byte[] nextFrame = concat(encoded, Arrays.copyOf(encoded, format.equals("XZ") ? 6 : 4));
            RamdiskInspector.Report truncated = RamdiskInspector.inspectRamdisk(nextFrame);
            check(truncated.malformed && truncated.entries.isEmpty(),
                    format + " recognized truncated next stream remains a decode failure");
        }
    }

    private static void compressedFormats() throws Exception {
        for (String format : new String[]{"LZ4_FRAME", "XZ", "ZSTD"}) {
            for (byte[] raw : new byte[][]{stockRamdisk(), ksuRamdisk(true)}) {
                RamdiskInspector.Report expected = RamdiskInspector.inspect(raw);
                byte[] encoded = KernelCompression.encode(raw, format);
                byte[] original = encoded.clone();
                for (byte[] input : new byte[][]{encoded, containerV4(new byte[0], encoded),
                        containerV4(new byte[71], encoded), containerV0(new byte[71], encoded, 4096)}) {
                    RamdiskInspector.Report report = RamdiskInspector.inspect(input);
                    check(!report.malformed, format + " decodes before ramdisk classification: " + report.errorCode);
                    check(format.equals(report.compression), format + " compression retained");
                    check(report.form() == expected.form(), format + " form from actual CPIO");
                    check(expected.decompressedSha256.equals(report.decompressedSha256), format + " complete CPIO retained");
                    check(expected.entries.size() == report.entries.size(), format + " all entries retained");
                    for (RamdiskInspector.Entry entry : expected.entries) {
                        RamdiskInspector.Entry actual = report.entry(entry.path);
                        check(actual != null && actual.mode == entry.mode && actual.size == entry.size
                                && actual.sha256.equals(entry.sha256), format + " entry retained: " + entry.path);
                    }
                }
                check(Arrays.equals(original, encoded), format + " inspection leaves input unchanged");
                RamdiskInspector.Report limited = RamdiskInspector.inspect(encoded,
                        RamdiskInspector.DEFAULT_MAX_ENTRIES, raw.length - 1);
                check("DECOMPRESSION_LIMIT".equals(limited.errorCode), format + " output bounded");
                check(limited.entries.isEmpty(), format + " no partial CPIO on decode failure");
            }
        }
        byte[] frame = {4, 34, 77, 24, 0, 0, 0, 0};
        RamdiskInspector.Report lz4Frame = RamdiskInspector.inspect(frame);
        check(lz4Frame.malformed && "INVALID_LZ4_FRAME_VERSION".equals(lz4Frame.errorCode), "LZ4 frame error retained");
        check("LZ4_FRAME".equals(lz4Frame.compression), "failed compression label retained");
        RamdiskInspector.Report zstd = RamdiskInspector.inspect(new byte[]{0x28, (byte) 0xb5, 0x2f, (byte) 0xfd, 0, 0});
        check(zstd.malformed && "TRUNCATED_ZSTD_BLOCK".equals(zstd.errorCode), "zstd decode failure retained");
        check("ZSTD".equals(zstd.compression), "failed zstd compression label retained");
        RamdiskInspector.Report xz = RamdiskInspector.inspect(new byte[]{(byte) 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0});
        check("TRUNCATED_XZ".equals(xz.errorCode), "xz decode failure retained");
    }

    private static void invalidInputs() {
        RamdiskInspector.Report empty = RamdiskInspector.inspect(new byte[0]);
        check(empty.malformed && "EMPTY_RAMDISK".equals(empty.errorCode), "empty component");
        RamdiskInspector.Report text = RamdiskInspector.inspect("not a ramdisk".getBytes(StandardCharsets.US_ASCII));
        check("INVALID_RAMDISK_MAGIC".equals(text.errorCode), "unknown magic");
        check(!text.requireStockForm().ok, "unknown input is never treated as stock");
        check(text.form() == RamdiskInspector.Form.UNKNOWN, "unknown form for unreadable input");
        RamdiskInspector.Report nullInput = RamdiskInspector.inspect((byte[]) null);
        check("NULL_INPUT".equals(nullInput.errorCode), "null component");
        RamdiskInspector.Report badEntries = RamdiskInspector.inspect(new byte[8], 0, 1024);
        check("INVALID_LIMIT".equals(badEntries.errorCode), "invalid entry limit");
        RamdiskInspector.Report badBytes = RamdiskInspector.inspect(new byte[8], 16, 0);
        check("INVALID_LIMIT".equals(badBytes.errorCode), "invalid byte limit");
        RamdiskInspector.Report hugeLimit = RamdiskInspector.inspect(new byte[8], 16,
                RamdiskInspector.DEFAULT_MAX_BYTES + 1);
        check("INVALID_LIMIT".equals(hugeLimit.errorCode), "limit above codec maximum");
    }

    private static void truncatedCpio() {
        byte[] archive = stockRamdisk();
        rejects(Arrays.copyOf(archive, 60), "TRUNCATED_CPIO_HEADER", "truncated header");
        rejects(Arrays.copyOf(archive, 112), "TRUNCATED_CPIO_NAME", "truncated name");
        byte[] dataEntry = cpio(Arrays.asList(file("blob", S_IFREG | 0644, randomBytes(100, 31))));
        int dataStart = (int) align4(110 + "blob".length() + 1);
        rejects(Arrays.copyOf(dataEntry, dataStart + 50), "TRUNCATED_CPIO_DATA", "truncated file data");
        rejects(cpio(Arrays.asList(file("blob", S_IFREG | 0644, randomBytes(100, 31))), false, false),
                "MISSING_TRAILER", "missing trailer");
    }

    private static void pseudoCpio() {
        byte[] validEntry = cpio(Arrays.asList(file("init", S_IFREG | 0755, "x")), false, false);
        byte[] badMagic = concat(validEntry, new byte[110]);
        rejects(badMagic, "INVALID_CPIO_MAGIC", "pseudo magic");
        byte[] badField = rawHeader("070701", S_IFREG | 0644, 0, 4, "zzzz81ed");
        rejects(concat(badField, new byte[0]), "INVALID_CPIO_HEADER", "non-hex header field");
        byte[] zeroName = rawHeader("070701", S_IFREG | 0644, 0, 0, "000081ed");
        rejects(zeroName, "INVALID_CPIO_HEADER", "zero name size");
        byte[] noTerminator = concat(rawHeader("070701", S_IFREG | 0644, 0, 2, "000081ed"),
                new byte[]{'a', 'b', 'c'});
        rejects(noTerminator, "MALFORMED_CPIO_NAME", "name without NUL terminator");
    }

    private static void duplicateNames() {
        List<CpioEntry> entries = new ArrayList<>();
        entries.add(file("init", S_IFREG | 0755, "first"));
        entries.add(file("init", S_IFREG | 0755, "second"));
        entries.add(file("init.real", S_IFREG | 0755, "android"));
        byte[] archive = cpio(entries);
        RamdiskInspector.Report report = RamdiskInspector.inspect(archive);
        check(report.malformed && "DUPLICATE_ENTRY".equals(report.errorCode),
                "duplicate security-relevant name is fatal");
        check(report.entries.size() == 3, "duplicates do not drop entries");
        check(!report.requireKsuLkmForm().ok && "DUPLICATE_ENTRY".equals(report.requireKsuLkmForm().code),
                "assertions reject duplicated archives");
        check(!report.requireStockForm().ok, "stock assertion rejects ambiguous marker archives");
        // AOSP mkbootfs legitimately repeats a plain directory entry: the real init_boot
        // ramdisk shipped by the reference material contains "dev" twice. That must be a
        // non-fatal finding, otherwise every stock baseline would be rejected.
        List<CpioEntry> benign = new ArrayList<>();
        benign.add(file("init", S_IFREG | 0755, "stock-init"));
        benign.add(dir("dev", S_IFDIR | 0755));
        benign.add(dir("dev", S_IFDIR | 0755));
        benign.add(dir("metadata", S_IFDIR | 0755));
        byte[] benignArchive = cpio(benign);
        RamdiskInspector.Report tolerated = RamdiskInspector.inspect(benignArchive);
        check(!tolerated.malformed, "repeated plain directory entry is not fatal");
        check(tolerated.rejectMalformed().ok, "rejectMalformed tolerates mkbootfs directory repetition");
        check(tolerated.form() == RamdiskInspector.Form.STOCK, "repeated dev keeps stock form");
        check(tolerated.requireStockForm().ok, "stock assertion tolerates repeated dev");
        boolean findingFound = false;
        for (RamdiskInspector.Problem finding : tolerated.findings) {
            if ("DUPLICATE_ENTRY".equals(finding.code) && "dev".equals(finding.detail)) findingFound = true;
        }
        check(findingFound, "duplicate dev is reported as a finding");
        check(tolerated.toJson().contains("\"findings\":[{\"code\":\"DUPLICATE_ENTRY\""), "json lists findings");
    }

    private static void pathTraversal() {
        List<CpioEntry> entries = new ArrayList<>();
        entries.add(file("../init", S_IFREG | 0755, "escape"));
        entries.add(file("/etc/passwd", S_IFREG | 0644, "absolute"));
        entries.add(file("a/../../b", S_IFREG | 0644, "nested"));
        entries.add(file("win\\path", S_IFREG | 0644, "backslash"));
        entries.add(file("bad\nname", S_IFREG | 0644, "control"));
        byte[] archive = cpio(entries);
        RamdiskInspector.Report report = RamdiskInspector.inspect(archive);
        check(report.malformed, "unsafe names are structural findings");
        check(problemsWith(archive, "UNSAFE_PATH") == 5, "all unsafe path classes detected");
        check(report.problems.size() == 5, "one problem per unsafe entry");
        check(report.toJson().contains("\"path\":\"bad\\nname\""), "json escapes control characters");
        check(report.rejectMalformed().violations.contains("UNSAFE_PATH"), "rejectMalformed names UNSAFE_PATH");
    }

    private static void entryLimit() {
        List<CpioEntry> entries = new ArrayList<>();
        for (int index = 0; index < 6; index++) entries.add(file("file" + index, S_IFREG | 0644, "x"));
        RamdiskInspector.Report report = RamdiskInspector.inspect(cpio(entries), 3,
                RamdiskInspector.DEFAULT_MAX_BYTES);
        check("ENTRY_LIMIT_EXCEEDED".equals(report.errorCode), "entry limit enforced");
        check(report.entries.size() == 3, "entry limit stops the scan");
    }

    private static void byteLimits() throws Exception {
        byte[] raw = stockRamdisk();
        RamdiskInspector.Report rawLimit = RamdiskInspector.inspect(raw, RamdiskInspector.DEFAULT_MAX_ENTRIES, 64);
        check("DECOMPRESSION_LIMIT".equals(rawLimit.errorCode), "raw byte limit");
        byte[] gzip = KernelCompression.encode(raw, "GZIP");
        RamdiskInspector.Report gzipLimit = RamdiskInspector.inspect(gzip,
                RamdiskInspector.DEFAULT_MAX_ENTRIES, 100);
        check("DECOMPRESSION_LIMIT".equals(gzipLimit.errorCode), "gzip byte limit");
        // A highly compressible, oversized archive must be rejected while decoding, not OOM.
        byte[] large = new byte[4 * 1024 * 1024];
        RamdiskInspector.Report bomb = RamdiskInspector.inspect(KernelCompression.encode(large, "GZIP"),
                RamdiskInspector.DEFAULT_MAX_ENTRIES, 1024 * 1024);
        check("DECOMPRESSION_LIMIT".equals(bomb.errorCode), "gzip expansion limit");
        check(bomb.entries.isEmpty(), "expansion limit does not parse partial output");
    }

    private static void crcFormat() throws Exception {
        byte[] good = cpio(ksuEntries(true), true, true);
        RamdiskInspector.Report report = RamdiskInspector.inspect(good);
        check(!report.malformed, "070702 archive with matching checksums accepted");
        check(report.requireKsuLkmForm().ok, "070702 KSU form");
        byte[] bad = good.clone();
        System.arraycopy("00000000".getBytes(StandardCharsets.US_ASCII), 0, bad, 6 + 12 * 8, 8);
        RamdiskInspector.Report corrupted = RamdiskInspector.inspect(bad);
        check("CPIO_CHECK_MISMATCH".equals(corrupted.errorCode), "070702 checksum mismatch detected");
    }

    private static void containerDefects() throws Exception {
        byte[] kernel = randomBytes(1024, 41);
        byte[] ramdisk = KernelCompression.encode(stockRamdisk(), "GZIP");
        byte[] image = containerV4(kernel, ramdisk);
        int ramdiskEnd = (int) align(4096 + kernel.length, 4096) + ramdisk.length;
        byte[] truncated = Arrays.copyOf(image, ramdiskEnd - 1);
        RamdiskInspector.Report fileReport = inspectFile(truncated);
        check("CONTAINER_INVALID".equals(fileReport.errorCode), "truncated container rejected by inspector");
        check(fileReport.problems.get(0).detail.equals("COMPONENT_OUT_OF_BOUNDS"), "container failure detail");
        RamdiskInspector.Report byteReport = RamdiskInspector.inspect(truncated);
        check("COMPONENT_OUT_OF_BOUNDS".equals(byteReport.errorCode), "truncated container bounds (bytes)");
        byte[] badPage = new byte[8192];
        System.arraycopy("ANDROID!".getBytes(StandardCharsets.US_ASCII), 0, badPage, 0, 8);
        ByteBuffer.wrap(badPage).order(ByteOrder.LITTLE_ENDIAN).putInt(36, 1234).putInt(40, 0);
        check("INVALID_PAGE_SIZE".equals(RamdiskInspector.inspect(badPage).errorCode), "bad page size");
        byte[] badVersion = Arrays.copyOf(badPage, 8192);
        ByteBuffer.wrap(badVersion).order(ByteOrder.LITTLE_ENDIAN).putInt(40, 9);
        check("UNSUPPORTED_HEADER".equals(RamdiskInspector.inspect(badVersion).errorCode), "bad header version");
        byte[] emptyRamdisk = containerV4(kernel, new byte[0]);
        RamdiskInspector.Report emptyReport = RamdiskInspector.inspect(emptyRamdisk);
        check("EMPTY_RAMDISK".equals(emptyReport.errorCode), "container without ramdisk");
    }

    private static void fileComponentEntryPoint() throws Exception {
        byte[] gzip = KernelCompression.encode(ksuRamdisk(true), "GZIP");
        RamdiskInspector.Report fileReport = RamdiskInspector.inspectRamdisk(writeTemp(gzip).toFile());
        RamdiskInspector.Report bytesReport = RamdiskInspector.inspectRamdisk(gzip);
        check(fileReport.toJson().equals(bytesReport.toJson()), "inspectRamdisk(File) matches bytes");
        check("GZIP".equals(fileReport.compression) && fileReport.requireKsuLkmForm().ok,
                "component file entry point");
        Path malformed = writeTemp("garbage".getBytes(StandardCharsets.US_ASCII));
        check("INVALID_RAMDISK_MAGIC".equals(RamdiskInspector.inspectRamdisk(malformed.toFile()).errorCode),
                "component file with unknown magic");
    }

    private static Path writeTemp(byte[] bytes) throws IOException {
        Path file = Files.createTempFile("maplesu-ramdisk-component-", ".bin");
        Files.write(file, bytes);
        return file;
    }

    private static void cancellation() {
        Thread.currentThread().interrupt();
        try {
            RamdiskInspector.Report report = RamdiskInspector.inspect(ksuRamdisk(true));
            check("CANCELLED".equals(report.errorCode), "cancellation is a structured code");
        } finally {
            Thread.interrupted();
        }
    }

    private static void malformedFuzz() {
        Random random = new Random(20261029);
        for (int iteration = 0; iteration < 300; iteration++) {
            byte[] bytes;
            if (iteration % 3 == 0) {
                bytes = new byte[random.nextInt(4096)];
                random.nextBytes(bytes);
            } else if (iteration % 3 == 1) {
                bytes = new byte[110 + random.nextInt(300)];
                random.nextBytes(bytes);
                System.arraycopy("070701".getBytes(StandardCharsets.US_ASCII), 0, bytes, 0, 6);
            } else {
                bytes = new byte[8 + random.nextInt(600)];
                random.nextBytes(bytes);
                System.arraycopy("ANDROID!".getBytes(StandardCharsets.US_ASCII), 0, bytes, 0, 8);
            }
            try {
                RamdiskInspector.Report report = RamdiskInspector.inspect(bytes);
                if (report.malformed) {
                    check(report.errorCode != null, "fuzz report has a code");
                    check(report.rejectMalformed().code != null, "fuzz verdict has a code");
                }
            } catch (RuntimeException exception) {
                throw new AssertionError("fuzz input threw " + exception.getClass().getSimpleName()
                        + " at iteration " + iteration, exception);
            }
        }
        check(true, "deterministic malformed fuzzing without exceptions");
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    // ------------------------------------------------------------------ main

    public static void main(String[] args) throws Exception {
        ksuLkmForm();
        compatibleKsuForm();
        stockForm();
        compressedRoundTrip();
        bootV4Container();
        bootLegacyContainer();
        initBootWithoutKernel();
        litePatchVariant();
        trailingDataAfterTrailer();
        gzipTrailingGarbage();
        lz4Defects();
        compressedFormats();
        compressedTrailingData();
        invalidInputs();
        truncatedCpio();
        pseudoCpio();
        duplicateNames();
        pathTraversal();
        entryLimit();
        byteLimits();
        crcFormat();
        containerDefects();
        fileComponentEntryPoint();
        cancellation();
        malformedFuzz();
        passed += RamdiskCodecCompatibilityTest.check();
        System.out.println("PASS " + passed + " ramdisk inspector checks (synthetic fixtures)");
    }
}
