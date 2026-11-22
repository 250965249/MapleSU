package dev.maplesu.image;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Ordinary files only; component reconstruction is not kernel or device validation. */
public final class BootImageRebuilderTest {
    private static int passed;

    private static void check(boolean condition, String description) {
        if (!condition) throw new AssertionError(description);
        passed++;
    }

    static byte[] fixture(int kernelSize, int ramdiskSize) {
        int ramdisk = align(4096 + kernelSize);
        byte[] bytes = new byte[align(ramdisk + ramdiskSize)];
        ByteBuffer header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        header.put("ANDROID!".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        header.putInt(8, kernelSize).putInt(12, ramdiskSize).putInt(16, 0x12345678);
        header.putInt(20, 1584).putInt(40, 4);
        byte[] cmdline = "console=ttyS0 test=\"two words\" 枫栖".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        System.arraycopy(cmdline, 0, bytes, 44, cmdline.length);
        Arrays.fill(bytes, 4096, 4096 + kernelSize, (byte) 0x31);
        Arrays.fill(bytes, ramdisk, ramdisk + ramdiskSize, (byte) 0x72);
        return bytes;
    }

    private static int align(int value) { return (value + 4095) / 4096 * 4096; }

    private static byte[] paddedComponents(int version, int page, int kernelSize) {
        int ramdisk = (page + kernelSize + page - 1) / page * page;
        byte[] original = new byte[ramdisk + page];
        ByteBuffer header = ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);
        header.put("ANDROID!".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        header.putInt(8, kernelSize).putInt(40, version);
        if (version >= 3) header.putInt(12, 53).putInt(20, version == 3 ? 1580 : 1584);
        else {
            header.putInt(16, 53).putInt(36, page);
            if (version > 0) header.putInt(1644, version == 1 ? 1648 : 1660);
        }
        Arrays.fill(original, page, page + kernelSize, (byte) 0x31);
        Arrays.fill(original, page + kernelSize, ramdisk, (byte) 0x5a);
        Arrays.fill(original, ramdisk, ramdisk + 53, (byte) 0x72);
        Arrays.fill(original, ramdisk + 53, original.length, (byte) 0x6b);
        return original;
    }

    private static void componentPadding(Path source, Path component, Path output) throws Exception {
        for (int version = 0; version <= 5; version++) {
            int page = version == 0 ? 2048 : version == 1 ? 8192 : version == 2 ? 16384 : 4096;
            byte[] original = paddedComponents(Math.min(version, 4), page, version == 5 ? 0 : 71);
            Files.write(source, original);
            BootImageInspector.Report before = BootImageInspector.inspect(source.toFile());
            for (boolean ramdisk : new boolean[]{false, true}) {
                if (version == 5 && !ramdisk) continue;
                int oldSize = ramdisk ? 53 : 71;
                for (int size : new int[]{oldSize, oldSize + 1, page * 2 + 1, 17}) {
                    byte[] replacement = new byte[size]; Arrays.fill(replacement, (byte) 0x44);
                    Files.write(component, replacement);
                    BootImageRebuilder.Report report = ramdisk
                            ? BootImageRebuilder.rebuildRamdisk(source.toFile(), component.toFile(), output.toFile())
                            : BootImageRebuilder.rebuild(source.toFile(), component.toFile(), output.toFile());
                    byte[] result = Files.readAllBytes(output);
                    int offset = (int) (ramdisk ? report.image.ramdiskOffset : report.image.kernelOffset);
                    check(Arrays.equals(replacement, Arrays.copyOfRange(result, offset, offset + size)), "Component bytes");
                    int other = (int) (ramdisk ? before.kernelOffset : before.ramdiskOffset);
                    int otherSize = (int) (ramdisk ? before.kernelSize : before.ramdiskSize);
                    int relocated = (int) (ramdisk ? report.image.kernelOffset : report.image.ramdiskOffset);
                    int otherSpan = (otherSize + page - 1) / page * page;
                    check(Arrays.equals(Arrays.copyOfRange(original, other, other + otherSpan),
                            Arrays.copyOfRange(result, relocated, relocated + otherSpan)), "Other component and padding preserved");
                    int end = offset + size, aligned = (end + page - 1) / page * page;
                    byte[] expected = size == oldSize ? Arrays.copyOfRange(original,
                            (int) (ramdisk ? before.ramdiskOffset : before.kernelOffset) + oldSize,
                            (int) (ramdisk ? before.ramdiskOffset : before.kernelOffset) + oldSize + aligned - end)
                            : new byte[aligned - end];
                    check(Arrays.equals(expected, Arrays.copyOfRange(result, end, aligned)), "Retained or rebuilt target padding");
                    check(report.equivalence.ok() && report.equivalence.uncoveredBytes == 0, "Declared writes only");
                    check(Arrays.equals(original, Files.readAllBytes(source)), "Padded source unchanged");
                    Files.delete(output);
                }
            }
        }
    }

    private static void otherHeaders(Path source, Path kernel, Path output) throws Exception {
        byte[] replacement = new byte[16385];
        Arrays.fill(replacement, (byte) 0x4b);
        Files.write(kernel, replacement);
        for (int version = 0; version <= 3; version++) {
            for (int page : new int[]{2048, 4096, 8192, 16384}) {
                if (version == 3 && page != 4096) continue;
                int[] sizes = {71, 53, version < 3 ? 39 : 0, version == 1 || version == 2 ? 17 : 0,
                        version == 2 ? 7 : 0};
                int count = version == 3 ? 2 : version + 3;
                byte[] original = new byte[page * (count + 1)];
                ByteBuffer fields = ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);
                fields.put("ANDROID!".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                fields.putInt(8, sizes[0]).putInt(40, version);
                if (version == 3) fields.putInt(12, sizes[1]).putInt(20, 1580);
                else {
                    fields.putInt(16, sizes[1]).putInt(24, sizes[2]).putInt(36, page);
                    if (version > 0) fields.putInt(1632, sizes[3]).putLong(1636, page * 4L)
                            .putInt(1644, version == 1 ? 1648 : 1660);
                    if (version == 2) fields.putInt(1648, sizes[4]);
                }
                for (int index = 0; index < count; index++)
                    Arrays.fill(original, page * (index + 1), page * (index + 1) + sizes[index], (byte) (31 + index));
                Files.write(source, original);
                BootImageRebuilder.Report report = BootImageRebuilder.rebuild(source.toFile(), kernel.toFile(), output.toFile());
                byte[] result = Files.readAllBytes(output);
                check(report.image.headerVersion == version && report.image.pageSize == page, "Boot layout retained");
                check(report.image.kernelSize == replacement.length && report.kernelChanged, "Replacement kernel recorded");
                check(Arrays.equals(replacement, Arrays.copyOfRange(result, page, page + replacement.length)), "Kernel content");
                int next = ((page + replacement.length + page - 1) / page) * page;
                for (int index = 1; index < count; index++) {
                    check(Arrays.equals(Arrays.copyOfRange(original, page * (index + 1), page * (index + 1) + sizes[index]),
                            Arrays.copyOfRange(result, next, next + sizes[index])), "Non-kernel component retained");
                    next += page;
                }
                check(next == result.length && Arrays.equals(original, Files.readAllBytes(source)), "Original unchanged and alignment valid");
                check(report.toJson().contains("REBUILD_BOOT_V" + version), "Report describes actual header");
                Files.delete(output);
            }
        }
    }

    private static void rejected(Path source, Path kernel, Path output, byte[] bytes, String code) throws Exception {
        Files.write(source, bytes);
        try {
            BootImageRebuilder.rebuildV4(source.toFile(), kernel.toFile(), output.toFile());
            throw new AssertionError("Expected " + code);
        } catch (IOException error) {
            check(code.equals(error.getMessage()), "Unexpected error: " + error);
        }
        check(!Files.exists(output), "Rejected output published");
        check(Arrays.equals(bytes, Files.readAllBytes(source)), "Rejected source changed");
    }

    private static void cleanupFailures() throws IOException {
        for (Throwable primary : new Throwable[]{new IOException("WRITE_FAILED"),
                new IllegalStateException("WRITE_FAILED"), new AssertionError("WRITE_FAILED")}) {
            IOException outputFailure = new IOException("OUTPUT_CLEANUP_FAILED");
            AssertionError anchorFailure = new AssertionError("ANCHOR_CLEANUP_FAILED");
            int[] calls = {0};
            BootImageRebuilder.cleanup(() -> { calls[0]++; throw outputFailure; },
                    () -> { calls[0]++; throw anchorFailure; }, primary);
            check(calls[0] == 2, "Both cleanup actions attempted after primary failure");
            check(Arrays.equals(primary.getSuppressed(), new Throwable[]{outputFailure, anchorFailure}),
                    "Primary failure retains cleanup errors in order");
        }
        IOException outputFailure = new IOException("OUTPUT_CLEANUP_FAILED");
        IllegalStateException anchorFailure = new IllegalStateException("ANCHOR_CLEANUP_FAILED");
        try {
            BootImageRebuilder.cleanup(() -> { throw outputFailure; }, () -> { throw anchorFailure; }, null);
            throw new AssertionError("Cleanup failures swallowed after successful write");
        } catch (IOException actual) {
            check(actual == outputFailure, "First cleanup error is reported unchanged");
            check(Arrays.equals(actual.getSuppressed(), new Throwable[]{anchorFailure}),
                    "Later cleanup error is suppressed");
        }
        IOException onlyAnchorFailure = new IOException("ANCHOR_CLEANUP_FAILED");
        try {
            BootImageRebuilder.cleanup(() -> {}, () -> { throw onlyAnchorFailure; }, null);
            throw new AssertionError("Anchor cleanup failure swallowed after successful write");
        } catch (IOException actual) {
            check(actual == onlyAnchorFailure, "Successful write still reports anchor cleanup failure");
        }
        IOException sameFailure = new IOException("WRITE_FAILED");
        BootImageRebuilder.cleanup(() -> { throw sameFailure; }, () -> {}, sameFailure);
        check(sameFailure.getSuppressed().length == 0, "Cleanup does not self-suppress primary failure");
        int[] calls = {0};
        BootImageRebuilder.cleanup(() -> calls[0]++, () -> calls[0]++, null);
        check(calls[0] == 2, "Successful cleanup runs both actions");
    }

    public static void main(String[] args) throws Exception {
        cleanupFailures();
        Path work = Files.createTempDirectory("maplesu-rebuild-test-");
        Path source = work.resolve("boot.img"), kernel = work.resolve("kernel"), output = work.resolve("output.img");
        try {
            byte[] original = fixture(71, 53);
            byte[] replacement = new byte[8193];
            Arrays.fill(replacement, (byte) 0x4b);
            Files.write(source, original);
            Files.write(kernel, replacement);
            BootImageRebuilder.Report report = BootImageRebuilder.rebuildV4(source.toFile(), kernel.toFile(), output.toFile(), () -> {
                if (Files.readAttributes(output, java.nio.file.attribute.BasicFileAttributes.class,
                        java.nio.file.LinkOption.NOFOLLOW_LINKS).fileKey() != null) {
                    try (var entries = Files.newDirectoryStream(work, ".maplesu-rebuild-*.pending")) {
                        check(!entries.iterator().hasNext(), "Basic file key avoids a hard-link anchor during rebuild");
                    }
                }
            });
            byte[] result = Files.readAllBytes(output);
            check(result.length == 20480, "Cross-page rebuild length");
            check(report.image.kernelSize == replacement.length, "Replacement length");
            check(Arrays.equals(replacement, Arrays.copyOfRange(result, 4096, 4096 + replacement.length)), "Replacement bytes");
            check(Arrays.equals(Arrays.copyOfRange(original, 8192, 8245), Arrays.copyOfRange(result, 16384, 16437)), "Ramdisk moved intact");
            check(Arrays.equals(Arrays.copyOfRange(original, 12, 1580), Arrays.copyOfRange(result, 12, 1580)), "Header fields preserved");
            check(Arrays.equals(original, Files.readAllBytes(source)), "Original remains unchanged");
            check(report.toJson().contains("\"flashableCandidate\":false"), "No flashable claim");
            check(report.kernelChanged, "Changed payload recorded");
            check("861eb56eb000412a9f5236857b13f622c3a3107cf232589316d745a273f9d782".equals(report.image.sha256), "Android/desktop golden output");
            try {
                BootImageRebuilder.rebuildV4(source.toFile(), kernel.toFile(), output.toFile());
                throw new AssertionError("Output overwritten");
            } catch (java.nio.file.FileAlreadyExistsException expected) {
                check(Arrays.equals(result, Files.readAllBytes(output)), "Existing output preserved");
            }
            Files.delete(output);
            Path displaced = work.resolve("displaced.img");
            try {
                BootImageRebuilder.rebuildV4(source.toFile(), kernel.toFile(), output.toFile(), () -> {
                    Files.move(output, displaced);
                    Files.write(output, result);
                });
                throw new AssertionError("Same-content output replacement accepted");
            } catch (IOException expected) {
                check("OUTPUT_IDENTITY_CHANGED".equals(expected.getMessage()), "Output identity failure reported");
                check(Arrays.equals(result, Files.readAllBytes(output)), "Replacement file preserved during cleanup");
            } finally { Files.deleteIfExists(displaced); Files.deleteIfExists(output); }
            try {
                BootImageRebuilder.rebuildV4(source.toFile(), kernel.toFile(), output.toFile(), () -> Files.write(kernel, new byte[]{1}));
                throw new AssertionError("Changed replacement input accepted");
            } catch (IOException expected) {
                check("SOURCE_CHANGED".equals(expected.getMessage()), "Input change reported");
                check(!Files.exists(output), "Changed-input output removed");
            }
            Files.write(kernel, Arrays.copyOfRange(original, 4096, 4167));
            report = BootImageRebuilder.rebuildV4(source.toFile(), kernel.toFile(), output.toFile());
            check(!report.kernelChanged, "Identical payload recorded");
            check(Arrays.equals(original, Files.readAllBytes(output)), "Unsigned same-component rebuild is identical");
            Files.delete(output);
            byte[] certificate = new byte[256];
            System.arraycopy(new byte[]{'A', 'V', 'B', '0'}, 0, certificate, 0, 4);
            byte[] declared = Arrays.copyOf(original, original.length + 4096);
            ByteBuffer.wrap(declared).order(ByteOrder.LITTLE_ENDIAN).putInt(1580, certificate.length);
            System.arraycopy(certificate, 0, declared, original.length, certificate.length);
            Files.write(source, declared);
            report = BootImageRebuilder.rebuildV4(source.toFile(), kernel.toFile(), output.toFile());
            check(report.declaredSignatures == 1 && Arrays.equals(original, Files.readAllBytes(output)), "Declared certificate removed");
            Files.delete(output);
            // OnePlus 10 Pro (5.10) declares the slot but leaves it zero-filled.
            byte[] emptySlot = Arrays.copyOf(original, original.length + 4096);
            ByteBuffer.wrap(emptySlot).order(ByteOrder.LITTLE_ENDIAN).putInt(1580, 4096);
            Files.write(source, emptySlot);
            report = BootImageRebuilder.rebuildV4(source.toFile(), kernel.toFile(), output.toFile());
            check(report.declaredSignatureSlotEmpty && report.declaredSignatures == 1,
                    "Zero-filled declared signature slot dropped without AVB validation");
            check(Arrays.equals(original, Files.readAllBytes(output)), "Empty slot leaves the canonical image");
            check(report.toJson().contains("\"declaredSignatureSlotEmpty\":true"), "Report names the empty slot");
            Files.delete(output);
            byte[] corruptCertificate = declared.clone();
            ByteBuffer.wrap(corruptCertificate).order(ByteOrder.BIG_ENDIAN).putLong(original.length + 12, Long.MAX_VALUE);
            rejected(source, kernel, output, corruptCertificate, "INVALID_AVB_METADATA");
            byte[] gki = Arrays.copyOf(original, original.length + 16384);
            System.arraycopy(certificate, 0, gki, original.length, 256);
            System.arraycopy(certificate, 0, gki, original.length + 256, 256);
            Files.write(source, gki);
            report = BootImageRebuilder.rebuildV4(source.toFile(), kernel.toFile(), output.toFile());
            check(report.trailingGkiCertificates == 2 && Arrays.equals(original, Files.readAllBytes(output)), "GKI pair removed");
            Files.delete(output);
            gki[original.length + 256] = 0;
            rejected(source, kernel, output, gki, "INVALID_AVB_METADATA");
            byte[] avb = Arrays.copyOf(original, original.length + 16384);
            System.arraycopy(certificate, 0, avb, original.length, 256);
            ByteBuffer footer = ByteBuffer.wrap(avb).order(ByteOrder.BIG_ENDIAN);
            int at = avb.length - 64;
            footer.position(at); footer.put(new byte[]{'A', 'V', 'B', 'f'});
            footer.putInt(at + 4, 1).putLong(at + 12, original.length)
                    .putLong(at + 20, original.length).putLong(at + 28, 256);
            Files.write(source, avb);
            Files.write(kernel, replacement);
            report = BootImageRebuilder.rebuildV4(source.toFile(), kernel.toFile(), output.toFile());
            byte[] retained = Files.readAllBytes(output);
            check(report.avbFooterPresent && retained.length == avb.length, "AVB partition length preserved");
            ByteBuffer retainedFooter = ByteBuffer.wrap(retained).order(ByteOrder.BIG_ENDIAN);
            check(Arrays.equals(Arrays.copyOfRange(avb, at, at + 12), Arrays.copyOfRange(retained, at, at + 12)),
                    "AVB footer header preserved");
            check(retainedFooter.getLong(at + 12) == 20480 && retainedFooter.getLong(at + 20) == 20480 &&
                    retainedFooter.getLong(at + 28) == certificate.length, "AVB footer relocated after new payload");
            check(Arrays.equals(certificate, Arrays.copyOfRange(retained, 20480, 20480 + certificate.length)),
                    "Outer vbmeta preserved byte for byte");
            check(report.toJson().contains("\"avbFooterRemoved\":false") &&
                    report.toJson().contains("\"avbFooterPreserved\":true") &&
                    report.toJson().contains("\"originalSignaturesReverified\":false"),
                    "Metadata retention does not claim replacement authentication");
            check(Arrays.equals(avb, Files.readAllBytes(source)), "AVB source remains unchanged");
            Files.delete(output);
            byte[] tooSmall = Arrays.copyOf(avb, original.length + 320);
            System.arraycopy(avb, at, tooSmall, tooSmall.length - 64, 64);
            rejected(source, kernel, output, tooSmall, "AVB_PARTITION_SIZE_LIMIT");
            footer.putLong(at + 20, avb.length);
            rejected(source, kernel, output, avb, "INVALID_AVB_FOOTER");
            Files.write(kernel, Arrays.copyOfRange(original, 4096, 4167));
            for (int index : new int[]{24, 1584}) {
                byte[] invalid = original.clone(); invalid[index] = 1;
                rejected(source, kernel, output, invalid, "NONCANONICAL_BOOT_PADDING");
            }
            byte[] version = original.clone(); ByteBuffer.wrap(version).order(ByteOrder.LITTLE_ENDIAN).putInt(40, 3);
            rejected(source, kernel, output, version, "EXPECTED_BOOT_V4");
            byte[] noKernel = fixture(0, 53);
            rejected(source, kernel, output, noKernel, "EXPECTED_BOOT_V4");
            byte[] badHeader = original.clone(); ByteBuffer.wrap(badHeader).order(ByteOrder.LITTLE_ENDIAN).putInt(20, 1600);
            rejected(source, kernel, output, badHeader, "EXPECTED_BOOT_V4");
            byte[] cmdline = original.clone(); Arrays.fill(cmdline, 44, 1580, (byte) 'a');
            rejected(source, kernel, output, cmdline, "NONCANONICAL_CMDLINE");
            cmdline = original.clone(); cmdline[46] = 0;
            rejected(source, kernel, output, cmdline, "NONCANONICAL_CMDLINE");
            cmdline = original.clone(); cmdline[44] = (byte) 0xff;
            rejected(source, kernel, output, cmdline, "NONCANONICAL_CMDLINE");
            byte[] trailer = Arrays.copyOf(original, original.length + 4096); trailer[original.length] = 1;
            rejected(source, kernel, output, trailer, "UNRECOGNIZED_BOOT_TRAILER");
            byte[] padded = Arrays.copyOf(original, original.length + 4096);
            Files.write(source, padded);
            report = BootImageRebuilder.rebuildV4(source.toFile(), kernel.toFile(), output.toFile());
            check(Files.size(output) == original.length && report.removedTrailingBytes == 4096, "Zero partition padding removed");
            Files.delete(output);
            Files.write(source, original);
            Thread.currentThread().interrupt();
            try {
                BootImageRebuilder.rebuildV4(source.toFile(), kernel.toFile(), output.toFile());
                throw new AssertionError("Interrupted rebuild accepted");
            } catch (IOException expected) {
                check("CANCELLED".equals(expected.getMessage()), "Cancellation reported");
                check(Thread.currentThread().isInterrupted(), "Cancellation marker preserved");
                check(!Files.exists(output), "Cancelled output absent");
            } finally { Thread.interrupted(); }
            Files.write(kernel, new byte[0]);
            rejected(source, kernel, output, original, "REPLACEMENT_KERNEL_SIZE_LIMIT");
            otherHeaders(source, kernel, output);
            componentPadding(source, kernel, output);
            System.out.println("PASS " + passed + " shared boot v0-v4 rebuild checks");
        } finally {
            Files.deleteIfExists(output); Files.deleteIfExists(kernel); Files.deleteIfExists(source); Files.delete(work);
        }
    }
}
