package dev.maplesu.image;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/** Ordinary opaque files only; no SDK, kernel execution or physical partitions. */
public final class StreamingRecoveryRebuilderTest {
    private static int checks;

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }

    private static byte[] fixture(int version, int page) {
        byte[] image = new byte[page * 3];
        ByteBuffer header = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        header.put(new byte[]{'A','N','D','R','O','I','D','!'}).putInt(8, 71).putInt(40, version);
        if (version >= 3) header.putInt(12, 53).putInt(20, version == 4 ? 1584 : 1580);
        else {
            header.putInt(16, 53).putInt(36, page);
            if (version > 0) header.putInt(1644, version == 1 ? 1648 : 1660);
        }
        Arrays.fill(image, page, page + 71, (byte) 0x31);
        Arrays.fill(image, page * 2, page * 2 + 53, (byte) 0x52);
        return image;
    }

    private static void payload(Path file, int length) throws Exception {
        try (FileChannel output = FileChannel.open(file, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            byte[] block = new byte[64 * 1024];
            for (int index = 0; index < block.length; index++) block[index] = (byte) (index * 31 + 7);
            int remaining = length;
            while (remaining > 0) {
                int count = Math.min(block.length, remaining);
                ByteBuffer bytes = ByteBuffer.wrap(block, 0, count);
                while (bytes.hasRemaining()) output.write(bytes);
                remaining -= count;
            }
            output.force(true);
        }
    }

    private static String sha(Path file) throws Exception {
        try (FileChannel input = FileChannel.open(file, StandardOpenOption.READ)) {
            return BootImageRebuilder.hash(input, 0, input.size());
        }
    }

    private static void rejected(String code, Action action) throws Exception {
        try {
            action.run();
            throw new AssertionError("Expected " + code);
        } catch (IOException error) {
            check(code.equals(error.getMessage()), "Actual failure " + error.getMessage());
        }
    }

    private interface Action { void run() throws Exception; }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("maplesu-stream-recovery-");
        try {
            Path record = root.resolve("record.bin");
            payload(record, 3 * 1024 * 1024 + 37);
            String recordHash = sha(record);
            for (int version = 0; version <= 4; version++) {
                int page = version == 0 ? 2048 : version == 2 ? 8192 : 4096;
                Path dir = Files.createDirectory(root.resolve("v" + version));
                Path source = dir.resolve("source.img"), kernel = dir.resolve("kernel"),
                        first = dir.resolve("first.img"), second = dir.resolve("second.img"),
                        ramdisk = dir.resolve("ramdisk"), third = dir.resolve("third.img"),
                        extracted = dir.resolve("record.bin"), removed = dir.resolve("removed.img");
                Files.write(source, fixture(version, page));
                Files.write(kernel, new byte[8193]);
                String sourceHash = sha(source);
                BootImageRebuilder.validateRecoveryInput(source.toFile(), BootImageRebuilder.OutputPolicy.STRICT);
                check(!BootImageRebuilder.extractRecoveryRecord(source.toFile(), extracted.toFile(),
                        BootImageRebuilder.OutputPolicy.STRICT), "Absent record returns false");
                check(!Files.exists(extracted), "Absent record creates no output");
                check(BootImageRebuilder.rebuildWithRecoveryFile(source.toFile(), kernel.toFile(), first.toFile(),
                        record.toFile(), BootImageRebuilder.OutputPolicy.STRICT).equivalence.ok(),
                        "Streaming insert has declared differences v" + version);
                rejected("RECOVERY_RECORD_SIZE_LIMIT", () -> BootImageRebuilder.readRecoveryRecord(first.toFile()));
                check(BootImageRebuilder.extractRecoveryRecord(first.toFile(), extracted.toFile(),
                        BootImageRebuilder.OutputPolicy.STRICT), "Streaming extraction found record");
                check(Files.size(extracted) == Files.size(record) && recordHash.equals(sha(extracted)),
                        "Streaming extraction preserves complete bytes");
                try {
                    BootImageRebuilder.extractRecoveryRecord(first.toFile(), extracted.toFile(),
                            BootImageRebuilder.OutputPolicy.STRICT);
                    throw new AssertionError("Existing extraction overwritten");
                } catch (java.nio.file.FileAlreadyExistsException expected) {
                    check(recordHash.equals(sha(extracted)), "Existing extraction remains intact");
                }
                Files.delete(extracted);
                Files.write(kernel, new byte[33]);
                BootImageRebuilder.rebuild(first.toFile(), kernel.toFile(), second.toFile());
                check(BootImageRebuilder.extractRecoveryRecord(second.toFile(), extracted.toFile(),
                        BootImageRebuilder.OutputPolicy.STRICT) && recordHash.equals(sha(extracted)),
                        "Default kernel rebuild preserves large record");
                Files.delete(extracted);
                Files.write(ramdisk, new byte[page + 9]);
                BootImageRebuilder.rebuildRamdisk(second.toFile(), ramdisk.toFile(), third.toFile());
                check(BootImageRebuilder.extractRecoveryRecord(third.toFile(), extracted.toFile(),
                        BootImageRebuilder.OutputPolicy.STRICT) && recordHash.equals(sha(extracted)),
                        "Default ramdisk rebuild preserves large record");
                BootImageRebuilder.rebuild(third.toFile(), kernel.toFile(), removed.toFile(), null);
                check(BootImageRebuilder.readRecoveryRecord(removed.toFile()) == null,
                        "Legacy explicit null removes a large record");
                check(sourceHash.equals(sha(source)) && recordHash.equals(sha(record)),
                        "Original source and record remain unchanged");

                BootImageInspector.Report image = BootImageInspector.inspect(first.toFile());
                long at = ((image.ramdiskOffset + image.ramdiskSize + page - 1) / page) * page;
                try (FileChannel input = FileChannel.open(first, StandardOpenOption.READ)) {
                    ByteBuffer header = ByteBuffer.wrap(BootImageRebuilder.read(input, at, 56)).order(ByteOrder.LITTLE_ENDIAN);
                    check(header.getInt(8) == 1 && header.getInt(12) == 56 && header.getInt(16) == Files.size(record),
                            "MSURREG v1 header and payload length preserved");
                    check(BootImageRebuilder.recoveryRecordEnd(input, at) == at + 56 + Files.size(record),
                            "Signer boundary includes the complete large record");
                }
                try (FileChannel output = FileChannel.open(first, StandardOpenOption.WRITE)) {
                    output.write(ByteBuffer.wrap(new byte[]{99}), at + 56);
                }
                Path badExtract = dir.resolve("bad-extract.bin");
                rejected("RECOVERY_REGION_CHECKSUM", () -> BootImageRebuilder.extractRecoveryRecord(first.toFile(),
                        badExtract.toFile(), BootImageRebuilder.OutputPolicy.STRICT));
                check(!Files.exists(badExtract), "Corrupt record creates no extraction");
            }

            Path source = root.resolve("bounds-source.img"), kernel = root.resolve("bounds-kernel"),
                    empty = root.resolve("empty.bin"), huge = root.resolve("huge.bin"), output = root.resolve("bounds-output.img");
            Files.write(source, fixture(4, 4096)); Files.write(kernel, new byte[71]); Files.createFile(empty);
            rejected("RECOVERY_RECORD_CAPACITY_LIMIT", () -> BootImageRebuilder.rebuildWithRecoveryFile(source.toFile(),
                    kernel.toFile(), output.toFile(), record.toFile(), BootImageRebuilder.OutputPolicy.STRICT, Files.size(source)));
            check(!Files.exists(output), "Optional record capacity limit uses actual layout before output creation");
            rejected("RECOVERY_RECORD_SIZE_LIMIT", () -> BootImageRebuilder.rebuildWithRecoveryFile(source.toFile(),
                    kernel.toFile(), output.toFile(), empty.toFile(), BootImageRebuilder.OutputPolicy.STRICT));
            try (java.io.RandomAccessFile sparse = new java.io.RandomAccessFile(huge.toFile(), "rw")) {
                sparse.setLength(BootImageRebuilder.MAX_RECOVERY_FILE_BYTES + 1);
            }
            rejected("RECOVERY_RECORD_SIZE_LIMIT", () -> BootImageRebuilder.rebuildWithRecoveryFile(source.toFile(),
                    kernel.toFile(), output.toFile(), huge.toFile(), BootImageRebuilder.OutputPolicy.STRICT));
            check(!Files.exists(output), "Invalid record sizes fail before output creation");
            byte[] body = fixture(4, 4096);
            byte[] signed = Arrays.copyOf(body, body.length + 64 * 1024);
            signed[body.length] = 'A'; signed[body.length + 1] = 'V';
            signed[body.length + 2] = 'B'; signed[body.length + 3] = '0';
            int footerAt = signed.length - 64;
            ByteBuffer footer = ByteBuffer.wrap(signed).order(ByteOrder.BIG_ENDIAN);
            footer.position(footerAt); footer.put(new byte[]{'A','V','B','f'});
            footer.putInt(footerAt + 4, 1).putLong(footerAt + 12, body.length)
                    .putLong(footerAt + 20, body.length).putLong(footerAt + 28, 256);
            Files.write(source, signed);
            rejected("AVB_PARTITION_SIZE_LIMIT", () -> BootImageRebuilder.rebuildWithRecoveryFile(source.toFile(),
                    kernel.toFile(), output.toFile(), record.toFile(), BootImageRebuilder.OutputPolicy.STRICT));
            check(!Files.exists(output), "Actual AVB partition capacity fails before output creation");
            Thread.currentThread().interrupt();
            try {
                rejected("CANCELLED", () -> BootImageRebuilder.extractRecoveryRecord(source.toFile(),
                        output.toFile(), BootImageRebuilder.OutputPolicy.STRICT));
                check(Thread.currentThread().isInterrupted(), "Cancellation remains set");
            } finally { Thread.interrupted(); }
            System.out.println("StreamingRecoveryRebuilder: " + checks + " checks passed");
        } finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
            }
        }
    }
}
