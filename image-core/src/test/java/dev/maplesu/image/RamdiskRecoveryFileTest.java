package dev.maplesu.image;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/** Ordinary opaque files only; no SDK, loader, kernel execution or physical partitions. */
public final class RamdiskRecoveryFileTest {
    private static int checks;

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }

    private interface Action { void run() throws Exception; }

    private static void rejected(String code, Action action) throws Exception {
        try {
            action.run();
            throw new AssertionError("Expected " + code);
        } catch (IOException error) {
            check(code.equals(error.getMessage()), "Actual failure: " + error.getMessage());
        }
    }

    private static void existing(Action action) throws Exception {
        try {
            action.run();
            throw new AssertionError("Existing output overwritten");
        } catch (FileAlreadyExistsException expected) {
            checks++;
        }
    }

    private static byte[] fixture(int version, int page, int kernelBytes) {
        int second = version < 3 ? 29 : 0;
        int dtbo = version == 1 || version == 2 ? 37 : 0;
        int dtb = version == 2 ? 41 : 0;
        int ramdiskAt = page + (kernelBytes == 0 ? 0 : page);
        int secondAt = ramdiskAt + page;
        int dtboAt = secondAt + (second == 0 ? 0 : page);
        int dtbAt = dtboAt + (dtbo == 0 ? 0 : page);
        int end = dtbAt + (dtb == 0 ? 0 : page);
        byte[] image = new byte[end];
        ByteBuffer header = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        header.put(new byte[]{'A','N','D','R','O','I','D','!'}).putInt(8, kernelBytes).putInt(40, version);
        if (version >= 3) header.putInt(12, 53).putInt(20, version == 4 ? 1584 : 1580);
        else {
            header.putInt(16, 53).putInt(24, second).putInt(36, page);
            if (version > 0) header.putInt(1632, dtbo).putLong(1636, dtboAt)
                    .putInt(1644, version == 1 ? 1648 : 1660);
            if (version == 2) header.putInt(1648, dtb).putLong(1652, 0x18000000L);
        }
        Arrays.fill(image, page, page + kernelBytes, (byte) 0x31);
        Arrays.fill(image, ramdiskAt, ramdiskAt + 53, (byte) 0x52);
        Arrays.fill(image, secondAt, secondAt + second, (byte) 0x63);
        Arrays.fill(image, dtboAt, dtboAt + dtbo, (byte) 0x74);
        Arrays.fill(image, dtbAt, dtbAt + dtb, (byte) 0x25);
        return image;
    }

    private static void payload(Path file, int bytes, int seed) throws Exception {
        try (FileChannel stream = FileChannel.open(file, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            byte[] block = new byte[64 * 1024];
            for (int index = 0; index < block.length; index++) block[index] = (byte) (index * 31 + seed);
            for (int remaining = bytes; remaining > 0;) {
                int count = Math.min(block.length, remaining);
                ByteBuffer buffer = ByteBuffer.wrap(block, 0, count);
                while (buffer.hasRemaining()) stream.write(buffer);
                remaining -= count;
            }
            stream.force(true);
        }
    }

    private static String sha(Path file) throws Exception {
        try (FileChannel input = FileChannel.open(file, StandardOpenOption.READ)) {
            return BootImageRebuilder.hash(input, 0, input.size());
        }
    }

    private static String region(Path file, long offset, long bytes) throws Exception {
        try (FileChannel input = FileChannel.open(file, StandardOpenOption.READ)) {
            return BootImageRebuilder.hash(input, offset, bytes);
        }
    }

    private static void foreignComponents(Path before, Path after) throws Exception {
        BootImageInspector.Report a = BootImageInspector.inspect(before.toFile());
        BootImageInspector.Report b = BootImageInspector.inspect(after.toFile());
        check(a.headerVersion == b.headerVersion && a.pageSize == b.pageSize, "Container header family preserved");
        long[][] left = {{a.kernelOffset, a.kernelSize}, {a.secondOffset, a.secondSize},
                {a.recoveryDtboOffset, a.recoveryDtboSize}, {a.dtbOffset, a.dtbSize}};
        long[][] right = {{b.kernelOffset, b.kernelSize}, {b.secondOffset, b.secondSize},
                {b.recoveryDtboOffset, b.recoveryDtboSize}, {b.dtbOffset, b.dtbSize}};
        for (int index = 0; index < left.length; index++) {
            check(left[index][1] == right[index][1], "Non-ramdisk component size preserved");
            if (left[index][1] > 0) check(region(before, left[index][0], left[index][1]).equals(
                    region(after, right[index][0], right[index][1])), "Non-ramdisk bytes preserved");
        }
    }

    private static void extracted(Path image, Path output, String expectedSha) throws Exception {
        check(BootImageRebuilder.extractRecoveryRecord(image.toFile(), output.toFile(),
                BootImageRebuilder.OutputPolicy.STRICT), "Record extracted");
        check(expectedSha.equals(sha(output)), "Complete opaque record readback");
        Files.delete(output);
    }

    private static void removeTree(Path directory) throws Exception {
        try (var paths = Files.walk(directory)) {
            for (Path file : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(file);
        }
    }

    private static void matrix(Path root, Path record, Path replacementRecord) throws Exception {
        String recordSha = sha(record), nextSha = sha(replacementRecord);
        int[][] variants = {{0,2048,71}, {0,4096,71}, {1,4096,71}, {1,8192,71},
                {2,8192,71}, {2,16384,71}, {3,4096,71}, {4,4096,71}, {4,4096,0}};
        for (int[] variant : variants) {
            int version = variant[0], page = variant[1], kernel = variant[2];
            Path dir = Files.createTempDirectory(root, "case-");
            try {
                Path source = dir.resolve("source.img"), ramdisk = dir.resolve("ramdisk.bin"),
                        inserted = dir.resolve("inserted.img"), preserved = dir.resolve("preserved.img"),
                        replaced = dir.resolve("replaced.img"), removed = dir.resolve("removed.img"),
                        probe = dir.resolve("extracted.bin"), limited = dir.resolve("limited.img");
                Files.write(source, fixture(version, page, kernel));
                byte[] ramdiskBytes = new byte[page + 9];
                Arrays.fill(ramdiskBytes, (byte) 0x4b);
                Files.write(ramdisk, ramdiskBytes);
                String sourceSha = sha(source), ramdiskSha = sha(ramdisk);
                BootImageRebuilder.Report report = BootImageRebuilder.rebuildRamdiskWithRecoveryFile(
                        source.toFile(), ramdisk.toFile(), inserted.toFile(), record.toFile(),
                        BootImageRebuilder.OutputPolicy.STRICT);
                check(report.ramdiskChanged && !report.kernelChanged && report.equivalence.ok(), "Ramdisk-only declared diff");
                check(report.image.kernelSize == kernel && report.image.ramdiskSize == ramdiskBytes.length,
                        "Init_boot/boot sizes preserved");
                check(region(inserted, report.image.ramdiskOffset, ramdiskBytes.length).equals(ramdiskSha),
                        "Replacement ramdisk bytes match");
                foreignComponents(source, inserted);
                extracted(inserted, probe, recordSha);
                rejected("RECOVERY_RECORD_SIZE_LIMIT", () -> BootImageRebuilder.readRecoveryRecord(inserted.toFile()));
                String insertedSha = sha(inserted);
                existing(() -> BootImageRebuilder.rebuildRamdiskWithRecoveryFile(source.toFile(), ramdisk.toFile(),
                        inserted.toFile(), record.toFile(), BootImageRebuilder.OutputPolicy.STRICT));
                check(insertedSha.equals(sha(inserted)), "Existing output preserved");
                existing(() -> BootImageRebuilder.rebuildRamdiskWithRecoveryFile(source.toFile(), ramdisk.toFile(),
                        source.toFile(), record.toFile(), BootImageRebuilder.OutputPolicy.STRICT));
                existing(() -> BootImageRebuilder.rebuildRamdiskWithRecoveryFile(source.toFile(), ramdisk.toFile(),
                        record.toFile(), record.toFile(), BootImageRebuilder.OutputPolicy.STRICT));
                rejected("RECOVERY_RECORD_CAPACITY_LIMIT", () -> BootImageRebuilder.rebuildRamdiskWithRecoveryFile(
                        source.toFile(), ramdisk.toFile(), limited.toFile(), record.toFile(),
                        BootImageRebuilder.OutputPolicy.STRICT, Files.size(inserted) - 1));
                check(!Files.exists(limited), "Capacity rejected before output creation");
                BootImageRebuilder.rebuildRamdiskWithRecoveryFile(source.toFile(), ramdisk.toFile(), limited.toFile(),
                        record.toFile(), BootImageRebuilder.OutputPolicy.STRICT, Files.size(inserted));
                check(insertedSha.equals(sha(limited)), "Exact capacity bound accepted");
                check(ramdiskSha.equals(sha(ramdisk)), "Replacement ramdisk input preserved");

                Files.write(ramdisk, new byte[]{1,2,3,4,5});
                String nextRamdiskSha = sha(ramdisk);
                BootImageRebuilder.rebuildRamdisk(inserted.toFile(), ramdisk.toFile(), preserved.toFile());
                extracted(preserved, probe, recordSha);
                foreignComponents(source, preserved);
                BootImageRebuilder.rebuildRamdiskWithRecoveryFile(preserved.toFile(), ramdisk.toFile(),
                        replaced.toFile(), replacementRecord.toFile(), BootImageRebuilder.OutputPolicy.STRICT);
                extracted(replaced, probe, nextSha);
                BootImageRebuilder.rebuildRamdiskWithRecoveryFile(replaced.toFile(), ramdisk.toFile(),
                        removed.toFile(), null, BootImageRebuilder.OutputPolicy.STRICT);
                check(BootImageRebuilder.readRecoveryRecord(removed.toFile()) == null, "Explicit file null removes record");
                check(!BootImageRebuilder.extractRecoveryRecord(removed.toFile(), probe.toFile(),
                        BootImageRebuilder.OutputPolicy.STRICT) && !Files.exists(probe), "Removal leaves no opaque record");
                foreignComponents(source, removed);
                check(sourceSha.equals(sha(source)) && recordSha.equals(sha(record)) && nextSha.equals(sha(replacementRecord)) &&
                        nextRamdiskSha.equals(sha(ramdisk)), "Source, replacement and record inputs preserved");
                check(ramdiskSha.equals(region(inserted, report.image.ramdiskOffset, report.image.ramdiskSize)),
                        "Later input edits do not change old output");
            } finally { removeTree(dir); }
        }
    }

    private static byte[] avb(byte[] body, int partitionBytes) {
        byte[] image = Arrays.copyOf(body, partitionBytes);
        System.arraycopy(new byte[]{'A','V','B','0'}, 0, image, body.length, 4);
        int at = image.length - 64;
        ByteBuffer footer = ByteBuffer.wrap(image).order(ByteOrder.BIG_ENDIAN);
        footer.position(at); footer.put(new byte[]{'A','V','B','f'});
        footer.putInt(at + 4, 1).putLong(at + 12, body.length)
                .putLong(at + 20, body.length).putLong(at + 28, 256);
        return image;
    }

    private static void metadataAndFailures(Path root, Path record) throws Exception {
        Path dir = Files.createTempDirectory(root, "metadata-");
        try {
            Path source = dir.resolve("source.img"), ramdisk = dir.resolve("ramdisk.bin"),
                    output = dir.resolve("candidate.img"), extracted = dir.resolve("record.bin"),
                    empty = Files.createFile(dir.resolve("empty.bin"));
            byte[] body = fixture(4, 4096, 0), certificate = new byte[256];
            System.arraycopy(new byte[]{'A','V','B','0'}, 0, certificate, 0, 4);
            Files.write(ramdisk, new byte[8193]);
            for (String kind : new String[]{"declared", "gki", "avb"}) {
                byte[] image;
                if (kind.equals("avb")) image = avb(body, 2 * 1024 * 1024);
                else {
                    image = Arrays.copyOf(body, body.length + (kind.equals("declared") ? 4096 : 16384));
                    System.arraycopy(certificate, 0, image, body.length, certificate.length);
                    if (kind.equals("declared")) ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN).putInt(1580, 256);
                    else System.arraycopy(certificate, 0, image, body.length + 256, certificate.length);
                }
                Files.write(source, image);
                String sourceSha = sha(source);
                BootImageRebuilder.Report report = BootImageRebuilder.rebuildRamdiskWithRecoveryFile(source.toFile(),
                        ramdisk.toFile(), output.toFile(), record.toFile(), BootImageRebuilder.OutputPolicy.STRICT);
                check(report.image.kernelSize == 0 && report.equivalence.ok(), "Metadata init_boot output verified");
                if (kind.equals("declared")) check(report.declaredSignatures == 1, "Declared signature handled by shared writer");
                if (kind.equals("gki")) check(report.trailingGkiCertificates == 2, "GKI pair handled by shared writer");
                if (kind.equals("avb")) {
                    AvbFooter footer = AvbFooter.parse(output.toFile());
                    check(report.avbFooterPresent && footer.valid(Files.size(output)), "Valid AVB footer retained");
                    check(region(source, body.length, 256).equals(region(output, footer.vbmetaOffset, 256)),
                            "Original vbmeta bytes relocated intact");
                }
                extracted(output, extracted, sha(record));
                check(sourceSha.equals(sha(source)), "Metadata source preserved");
                Files.delete(output);
            }
            Files.write(source, body);
            rejected("RECOVERY_RECORD_SIZE_LIMIT", () -> BootImageRebuilder.rebuildRamdiskWithRecoveryFile(
                    source.toFile(), ramdisk.toFile(), output.toFile(), empty.toFile(), BootImageRebuilder.OutputPolicy.STRICT));
            check(!Files.exists(output), "Empty record rejected before output creation");
            for (long capacity : new long[]{0, Long.MAX_VALUE, 1}) {
                rejected("RECOVERY_RECORD_CAPACITY_LIMIT", () -> BootImageRebuilder.rebuildRamdiskWithRecoveryFile(
                        source.toFile(), ramdisk.toFile(), output.toFile(), null,
                        BootImageRebuilder.OutputPolicy.STRICT, capacity));
                check(!Files.exists(output), "Bad removal capacity creates no output");
            }
            Files.write(source, avb(body, 65536));
            String before = sha(source);
            rejected("AVB_PARTITION_SIZE_LIMIT", () -> BootImageRebuilder.rebuildRamdiskWithRecoveryFile(source.toFile(),
                    ramdisk.toFile(), output.toFile(), record.toFile(), BootImageRebuilder.OutputPolicy.STRICT));
            check(!Files.exists(output) && before.equals(sha(source)), "AVB capacity failure preserves source and target absence");
        } finally { removeTree(dir); }
    }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("maplesu-ramdisk-record-");
        try {
            Path record = root.resolve("large-record.bin"), replacement = root.resolve("small-record.bin");
            payload(record, 1024 * 1024 + 37, 7);
            payload(replacement, 173, 19);
            matrix(root, record, replacement);
            metadataAndFailures(root, record);
            System.out.println("RamdiskRecoveryFile: " + checks + " checks passed");
        } finally { removeTree(root); }
    }
}
