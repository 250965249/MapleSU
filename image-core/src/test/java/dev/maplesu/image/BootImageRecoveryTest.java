package dev.maplesu.image;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;

/** Exact ordinary input containers; no kernel execution, SDK generation or device operations. */
public final class BootImageRecoveryTest {
    private static int checks;
    private static final BootImageRebuilder.OutputPolicy STRICT = BootImageRebuilder.OutputPolicy.STRICT;

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        checks++;
    }

    private static int align(int value, int page) { return (value + page - 1) / page * page; }
    private static byte[] content(int length, int seed) {
        byte[] bytes = new byte[length];
        for (int index = 0; index < length; index++) bytes[index] = (byte) (seed + index * 29);
        return bytes;
    }

    private static byte[] fixture(int version, int page, byte[] kernel, byte[] ramdisk) {
        byte[][] parts = {kernel, ramdisk, content(version < 3 ? 39 : 0, 91),
                content(version == 1 || version == 2 ? 17 : 0, 111), content(version == 2 ? 7 : 0, 131)};
        int count = version < 3 ? version + 3 : 2;
        int length = page;
        for (int index = 0; index < count; index++) length += align(parts[index].length, page);
        byte[] bytes = new byte[length];
        ByteBuffer header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        header.put(new byte[]{'A','N','D','R','O','I','D','!'}).putInt(8, kernel.length).putInt(40, version);
        if (version >= 3) header.putInt(12, ramdisk.length).putInt(20, version == 3 ? 1580 : 1584);
        else {
            header.putInt(16, ramdisk.length).putInt(24, parts[2].length).putInt(36, page);
            if (version > 0) header.putInt(1632, parts[3].length)
                    .putLong(1636, page + align(kernel.length, page) + align(ramdisk.length, page) + align(parts[2].length, page))
                    .putInt(1644, version == 1 ? 1648 : 1660);
            if (version == 2) header.putInt(1648, parts[4].length);
            Arrays.fill(bytes, 576, 608, (byte) 0x4d); // Original id is restored verbatim, not recomputed.
        }
        int offset = page;
        for (int index = 0; index < count; index++) {
            System.arraycopy(parts[index], 0, bytes, offset, parts[index].length);
            Arrays.fill(bytes, offset + parts[index].length, offset + align(parts[index].length, page), (byte) (81 + index));
            offset += align(parts[index].length, page);
        }
        return bytes;
    }

    private static byte[] metadata(byte[] plain, boolean declared, boolean gki, boolean footer) {
        byte[] bytes = plain;
        byte[] certificate = new byte[256];
        System.arraycopy(new byte[]{'A','V','B','0'}, 0, certificate, 0, 4);
        if (declared) {
            bytes = Arrays.copyOf(bytes, bytes.length + 4096);
            ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(1580, certificate.length);
            System.arraycopy(certificate, 0, bytes, plain.length, certificate.length);
        }
        if (gki) {
            int at = bytes.length;
            bytes = Arrays.copyOf(bytes, at + 16384);
            System.arraycopy(certificate, 0, bytes, at, certificate.length);
            System.arraycopy(certificate, 0, bytes, at + certificate.length, certificate.length);
        }
        if (footer) {
            int body = bytes.length, offset = align(body, 4096);
            bytes = Arrays.copyOf(bytes, offset + 65536);
            System.arraycopy(certificate, 0, bytes, offset, certificate.length);
            int at = bytes.length - 64;
            ByteBuffer fields = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
            fields.position(at); fields.put(new byte[]{'A','V','B','f'});
            fields.putInt(at + 4, 1).putLong(at + 12, body).putLong(at + 20, offset).putLong(at + 28, 256);
        } else bytes = Arrays.copyOf(bytes, bytes.length + 4096); // Exact trailing partition zeros.
        return bytes;
    }

    private static void roundTrip(Path work, String name, byte[] original, BootImageRecovery.Component target,
                                  byte[] replacement, BootImageRebuilder.OutputPolicy policy) throws Exception {
        Path dir = Files.createDirectory(work.resolve(name));
        Path source = dir.resolve("source.img"), snapshot = dir.resolve("snapshot.bin"), current = dir.resolve("current.img");
        Path originalComponent = dir.resolve("original.component"), next = dir.resolve("next.component"), restored = dir.resolve("restored.img");
        Files.write(source, original);
        BootImageInspector.Report layout = BootImageInspector.inspect(source.toFile());
        int offset = (int) (target == BootImageRecovery.Component.KERNEL ? layout.kernelOffset : layout.ramdiskOffset);
        int length = (int) (target == BootImageRecovery.Component.KERNEL ? layout.kernelSize : layout.ramdiskSize);
        byte[] component = Arrays.copyOfRange(original, offset, offset + length);
        Files.write(originalComponent, component); Files.write(next, replacement);
        BootImageRecovery.Snapshot record = BootImageRecovery.capture(source.toFile(), target, snapshot.toFile(), policy);
        check(record.originalImageBytes == original.length && record.originalImageSha256.equals(layout.sha256), "Original input bound");
        check(record.target == target && record.targetComponentBytes == length, "Target semantics bound");
        check(ByteBuffer.wrap(Files.readAllBytes(snapshot)).order(ByteOrder.LITTLE_ENDIAN).getInt(8) == 1,
                "Nonempty targets retain snapshot format v1");
        check(record.snapshotBytes < 1024 * 1024, "Small metadata and component references stay compact");
        if (target == BootImageRecovery.Component.KERNEL)
            BootImageRebuilder.rebuildWithPolicy(source.toFile(), next.toFile(), current.toFile(), policy);
        else BootImageRebuilder.rebuildRamdisk(source.toFile(), next.toFile(), current.toFile());
        check(!Arrays.equals(original, Files.readAllBytes(current)), "Fixture actually changes the container");
        BootImageRecovery.RestoreReport report = BootImageRecovery.restore(current.toFile(), originalComponent.toFile(), snapshot.toFile(), restored.toFile());
        check(Arrays.equals(original, Files.readAllBytes(restored)), "Full original bytes restored including padding and metadata");
        check(report.exactInputRestored && !report.originalSignaturesReverified && !report.flashableCandidate, "Precise evidence only");
        check(Arrays.equals(original, Files.readAllBytes(source)) && Arrays.equals(component, Files.readAllBytes(originalComponent)), "Source inputs remain intact");
        check(BootImageRecovery.read(snapshot.toFile()).snapshotSha256.equals(record.snapshotSha256), "Stable snapshot identity");
    }

    private static void compactZeroTail(Path work) throws Exception {
        Path directory = Files.createDirectory(work.resolve("compact-zero-tail"));
        Path source = directory.resolve("source.img"), snapshot = directory.resolve("snapshot.bin");
        Path current = directory.resolve("current.img"), restored = directory.resolve("restored.img");
        Path component = directory.resolve("original.component"), next = directory.resolve("next.component");
        byte[] kernel = content(71, 31);
        byte[] original = Arrays.copyOf(fixture(4, 4096, kernel, content(53, 71)), 77824);
        Files.write(source, original); Files.write(component, kernel); Files.write(next, content(8193, 9));
        BootImageRecovery.Snapshot record = BootImageRecovery.capture(source.toFile(),
                BootImageRecovery.Component.KERNEL, snapshot.toFile(), STRICT);
        check(record.snapshotBytes < original.length / 4,
                "Nonzero component padding does not retain the long zero tail as literal bytes");
        BootImageRebuilder.rebuild(source.toFile(), next.toFile(), current.toFile());
        BootImageRecovery.restore(current.toFile(), component.toFile(), snapshot.toFile(), restored.toFile());
        check(Arrays.equals(original, Files.readAllBytes(restored)), "Compact snapshot restores every original byte");
        check(Arrays.equals(original, Files.readAllBytes(source)), "Compact capture preserves the source");
    }

    private static void emptyRamdiskRoundTrip(Path work, int version, int page, boolean footer) throws Exception {
        Path directory = Files.createDirectory(work.resolve("empty-v" + version + "-p" + page + "-a" + footer));
        Path source = directory.resolve("source.img"), snapshot = directory.resolve("snapshot.bin");
        Path current = directory.resolve("current.img"), extracted = directory.resolve("extracted.bin");
        Path empty = directory.resolve("original.component"), next = directory.resolve("next.component");
        Path restored = directory.resolve("restored.img");
        byte[] original = metadata(fixture(version, page, content(71, 31), new byte[0]),
                version == 4, version >= 3, footer);
        if (footer) {
            // This success matrix needs room for the original nonzero 16KiB page padding too.
            byte[] roomy = Arrays.copyOf(original, original.length + 256 * 1024);
            Arrays.fill(roomy, original.length - 64, original.length, (byte) 0);
            System.arraycopy(original, original.length - 64, roomy, roomy.length - 64, 64);
            original = roomy;
        }
        byte[] replacement = content(8193, 91);
        Files.write(source, original); Files.write(empty, new byte[0]); Files.write(next, replacement);
        BootImageRecovery.Snapshot saved = BootImageRecovery.capture(source.toFile(),
                BootImageRecovery.Component.RAMDISK, snapshot.toFile(), STRICT);
        byte[] record = Files.readAllBytes(snapshot);
        check(ByteBuffer.wrap(record).order(ByteOrder.LITTLE_ENDIAN).getInt(8) == 2,
                "Only the originally empty ramdisk uses snapshot format v2");
        check(saved.target == BootImageRecovery.Component.RAMDISK && saved.targetComponentBytes == 0 &&
                saved.targetComponentSha256.equals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                "Empty target binds its actual zero length and empty SHA256");
        BootImageRebuilder.rebuildRamdiskWithRecoveryFile(source.toFile(), next.toFile(), current.toFile(),
                snapshot.toFile(), STRICT);
        check(BootImageInspector.inspect(current.toFile()).ramdiskSize == replacement.length,
                "The real ramdisk writer installs a nonempty component into the empty slot");
        check(BootImageRebuilder.extractRecoveryRecord(current.toFile(), extracted.toFile(), STRICT) &&
                Arrays.equals(record, Files.readAllBytes(extracted)), "The container carries the actual v2 snapshot");
        byte[] before = Files.readAllBytes(current);
        BootImageRecovery.RestoreReport report = BootImageRecovery.restore(current.toFile(), empty.toFile(),
                extracted.toFile(), restored.toFile());
        check(Arrays.equals(original, Files.readAllBytes(restored)) && report.image.ramdiskSize == 0,
                "The first input is restored exactly with no ramdisk component");
        check(BootImageRebuilder.readRecoveryRecord(restored.toFile()) == null,
                "Restoring the first input removes the later recovery record");
        check(Arrays.equals(original, Files.readAllBytes(source)) && Arrays.equals(before, Files.readAllBytes(current)) &&
                Files.size(empty) == 0, "All source inputs remain unchanged");
        if (version == 4 && !footer) {
            Path preserved = directory.resolve("preserved.img"), removed = directory.resolve("removed.img");
            BootImageRebuilder.rebuildRamdisk(current.toFile(), next.toFile(), preserved.toFile());
            check(Arrays.equals(record, BootImageRebuilder.readRecoveryRecord(preserved.toFile())),
                    "A later default ramdisk rebuild preserves the v2 record");
            BootImageRebuilder.rebuildRamdiskWithRecoveryFile(current.toFile(), next.toFile(), removed.toFile(), null, STRICT);
            check(BootImageRebuilder.readRecoveryRecord(removed.toFile()) == null,
                    "Explicit record removal keeps its existing meaning");
        }
    }

    private static void rejectSnapshot(Path snapshot, byte[] bytes, String code) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(Arrays.copyOf(bytes, bytes.length - 32));
        System.arraycopy(hash, 0, bytes, bytes.length - 32, 32);
        Files.write(snapshot, bytes);
        try { BootImageRecovery.read(snapshot.toFile()); throw new AssertionError("Invalid empty-target snapshot accepted"); }
        catch (IOException expected) { check(code.equals(expected.getMessage()), "Strict empty-target validation: " + code); }
    }

    private static void rejectedEmptyRamdisk(Path work) throws Exception {
        Path directory = Files.createDirectory(work.resolve("reject-empty-ramdisk"));
        Path source = directory.resolve("source.img"), snapshot = directory.resolve("snapshot.bin");
        Path target = directory.resolve("original.component"), current = directory.resolve("current.img");
        Path next = directory.resolve("next.component"), output = directory.resolve("output.img");
        Files.write(source, fixture(4, 4096, content(71, 31), new byte[0]));
        Files.write(target, new byte[0]); Files.write(next, content(8193, 91));
        BootImageRecovery.capture(source.toFile(), BootImageRecovery.Component.RAMDISK, snapshot.toFile(), STRICT);
        byte[] saved = Files.readAllBytes(snapshot);
        for (int version : new int[]{-1, 0, 3, Integer.MAX_VALUE}) {
            byte[] broken = saved.clone();
            ByteBuffer.wrap(broken).order(ByteOrder.LITTLE_ENDIAN).putInt(8, version);
            rejectSnapshot(snapshot, broken, "BOOT_RECOVERY_FORMAT");
        }
        byte[] broken = saved.clone(); broken[0] ^= 1;
        rejectSnapshot(snapshot, broken, "BOOT_RECOVERY_FORMAT");
        broken = saved.clone(); ByteBuffer.wrap(broken).order(ByteOrder.LITTLE_ENDIAN).putInt(8, 1);
        rejectSnapshot(snapshot, broken, "BOOT_RECOVERY_HEADER");
        broken = saved.clone(); ByteBuffer.wrap(broken).order(ByteOrder.LITTLE_ENDIAN).putInt(56, 0);
        rejectSnapshot(snapshot, broken, "BOOT_RECOVERY_HEADER");
        broken = saved.clone(); ByteBuffer.wrap(broken).order(ByteOrder.LITTLE_ENDIAN).putLong(64, 1);
        rejectSnapshot(snapshot, broken, "BOOT_RECOVERY_HEADER");
        broken = saved.clone(); broken[72] ^= 1;
        rejectSnapshot(snapshot, broken, "BOOT_RECOVERY_HEADER");
        broken = saved.clone();
        ByteBuffer fields = ByteBuffer.wrap(broken).order(ByteOrder.LITTLE_ENDIAN);
        boolean changed = false;
        int at = 112;
        for (int index = 0; index < fields.getInt(60); index++) {
            int kind = fields.getInt(at), component = fields.getInt(at + 4);
            long length = fields.getLong(at + 16);
            if (kind == 2 && component == 1) {
                fields.putInt(at + 4, 2); changed = true; break;
            }
            at += 56 + (kind == 0 ? (int) length : 0);
        }
        check(changed, "The conflicting component fixture changes a real kernel span");
        rejectSnapshot(snapshot, broken, "BOOT_RECOVERY_TARGET_MISMATCH");
        Files.write(snapshot, saved);
        BootImageRebuilder.rebuildRamdiskWithRecoveryFile(source.toFile(), next.toFile(), current.toFile(), snapshot.toFile(), STRICT);
        Files.write(target, new byte[]{1});
        try { BootImageRecovery.restore(current.toFile(), target.toFile(), snapshot.toFile(), output.toFile());
            throw new AssertionError("Nonempty original file accepted for an empty target"); }
        catch (IOException expected) { check("BOOT_RECOVERY_TARGET_MISMATCH".equals(expected.getMessage()) &&
                !Files.exists(output), "The original target must be an actual zero-byte file"); }
        Files.write(source, fixture(4, 4096, new byte[0], content(53, 71)));
        Path noKernel = directory.resolve("no-kernel.bin");
        try { BootImageRecovery.capture(source.toFile(), BootImageRecovery.Component.KERNEL, noKernel.toFile(), STRICT);
            throw new AssertionError("Empty kernel target accepted"); }
        catch (IOException expected) { check("BOOT_RECOVERY_TARGET_MISSING".equals(expected.getMessage()) &&
                !Files.exists(noKernel), "Empty kernel capture stays unsupported"); }
    }

    private static void rejected(Path work) throws Exception {
        Path source = work.resolve("reject-source.img"), snapshot = work.resolve("reject.snapshot"), current = work.resolve("reject-current.img");
        Path component = work.resolve("reject.component"), next = work.resolve("reject-next.component"), output = work.resolve("reject-output.img");
        byte[] original = fixture(4, 4096, content(71, 31), content(53, 71));
        Files.write(source, original); Files.write(component, content(71, 31)); Files.write(next, content(8193, 5));
        BootImageRecovery.capture(source.toFile(), BootImageRecovery.Component.KERNEL, snapshot.toFile(), STRICT);
        BootImageRebuilder.rebuild(source.toFile(), next.toFile(), current.toFile());
        byte[] saved = Files.readAllBytes(snapshot), present = Files.readAllBytes(current);
        byte[] broken = saved.clone(); broken[112 + 56] ^= 7; Files.write(snapshot, broken);
        try { BootImageRecovery.read(snapshot.toFile()); throw new AssertionError("Damaged snapshot accepted"); }
        catch (IOException expected) { check("BOOT_RECOVERY_CHECKSUM".equals(expected.getMessage()), "Snapshot checksum enforced"); }
        broken = saved.clone(); ByteBuffer.wrap(broken).order(ByteOrder.LITTLE_ENDIAN).putLong(16, Long.MAX_VALUE);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(Arrays.copyOf(broken, broken.length - 32));
        System.arraycopy(hash, 0, broken, broken.length - 32, 32); Files.write(snapshot, broken);
        try { BootImageRecovery.read(snapshot.toFile()); throw new AssertionError("Oversized original accepted"); }
        catch (IOException expected) { check("BOOT_RECOVERY_HEADER".equals(expected.getMessage()), "Resigned bad lengths rejected"); }
        Files.write(snapshot, saved);
        BootImageInspector.Report layout = BootImageInspector.inspect(current.toFile());
        present[(int) layout.ramdiskOffset] ^= 3; Files.write(current, present);
        try { BootImageRecovery.restore(current.toFile(), component.toFile(), snapshot.toFile(), output.toFile()); throw new AssertionError("Changed component accepted"); }
        catch (IOException expected) { check("BOOT_RECOVERY_COMPONENT_CHANGED".equals(expected.getMessage()) && !Files.exists(output), "Changed non-target fails before output"); }
        present[(int) layout.ramdiskOffset] ^= 3; Files.write(current, present);
        Files.write(component, content(71, 90));
        try { BootImageRecovery.restore(current.toFile(), component.toFile(), snapshot.toFile(), output.toFile()); throw new AssertionError("Wrong original target accepted"); }
        catch (IOException expected) { check("BOOT_RECOVERY_INPUT_CHANGED".equals(expected.getMessage()) && !Files.exists(output), "Original target digest bound"); }
        Files.write(component, content(71, 31));
        broken = saved.clone(); broken[24] ^= 1;
        hash = MessageDigest.getInstance("SHA-256").digest(Arrays.copyOf(broken, broken.length - 32));
        System.arraycopy(hash, 0, broken, broken.length - 32, 32); Files.write(snapshot, broken);
        try { BootImageRecovery.restore(current.toFile(), component.toFile(), snapshot.toFile(), output.toFile()); throw new AssertionError("Wrong full original digest accepted"); }
        catch (IOException expected) { check("BOOT_RECOVERY_READBACK_MISMATCH".equals(expected.getMessage()) && !Files.exists(output), "Unverified output removed after full digest failure"); }
        Files.write(snapshot, saved); Files.write(output, new byte[]{9, 8, 7});
        try { BootImageRecovery.restore(current.toFile(), component.toFile(), snapshot.toFile(), output.toFile()); throw new AssertionError("Existing output replaced"); }
        catch (java.nio.file.FileAlreadyExistsException expected) { check(Arrays.equals(new byte[]{9, 8, 7}, Files.readAllBytes(output)), "Existing output preserved"); }
        Path unknown = work.resolve("unknown-tail.img");
        byte[] unrecognized = Arrays.copyOf(original, original.length + 4096);
        unrecognized[original.length] = 0x33; Files.write(unknown, unrecognized);
        try { BootImageRecovery.capture(unknown.toFile(), BootImageRecovery.Component.KERNEL, work.resolve("unknown.snapshot").toFile(), STRICT); throw new AssertionError("Unknown nonzero tail accepted"); }
        catch (IOException expected) { check("UNRECOGNIZED_BOOT_TRAILER".equals(expected.getMessage()) && !Files.exists(work.resolve("unknown.snapshot")), "Capture reuses the writer tail inventory"); }
        Thread.currentThread().interrupt();
        try { BootImageRecovery.capture(source.toFile(), BootImageRecovery.Component.KERNEL, work.resolve("cancel.snapshot").toFile(), STRICT); throw new AssertionError("Cancellation ignored"); }
        catch (IOException expected) { check("CANCELLED".equals(expected.getMessage()) && Thread.currentThread().isInterrupted(), "Cancellation preserved"); }
        finally { Thread.interrupted(); }
    }

    public static void main(String[] args) throws Exception {
        Path work = Files.createTempDirectory("maplesu-container-recovery-");
        try {
            for (int version = 0; version <= 4; version++) for (int page : new int[]{2048, 4096, 8192, 16384}) {
                if (version >= 3 && page != 4096) continue;
                for (boolean footer : new boolean[]{false, true}) {
                    byte[] base = fixture(version, page, content(71, 31), content(53, 71));
                    roundTrip(work, "v" + version + "-p" + page + "-a" + footer,
                            metadata(base, version == 4, version >= 3, footer), BootImageRecovery.Component.KERNEL,
                            content(8193, 9), STRICT);
                }
            }
            roundTrip(work, "init-boot", metadata(fixture(4, 4096, new byte[0], content(53, 71)), true, true, true),
                    BootImageRecovery.Component.RAMDISK, content(8193, 91), STRICT);
            for (String codec : new String[]{"RAW_ARM64", "GZIP", "LZ4_LEGACY", "LZ4_FRAME", "XZ", "ZSTD"}) {
                byte[] first = KernelCompression.encode(content(70001, 21), codec);
                byte[] changed = KernelCompression.encode(content(80003, 37), codec);
                roundTrip(work, "codec-" + codec, metadata(fixture(4, 4096, first, content(53, 71)), true, true, true),
                        BootImageRecovery.Component.KERNEL, changed, STRICT);
            }
            byte[] bad = Arrays.copyOf(fixture(4, 4096, content(71, 31), content(53, 71)), 65536);
            ByteBuffer footer = ByteBuffer.wrap(bad).order(ByteOrder.BIG_ENDIAN);
            footer.position(bad.length - 64); footer.put(new byte[]{'A','V','B','f'}); footer.putInt(bad.length - 60, 1);
            roundTrip(work, "discard-invalid-footer", bad, BootImageRecovery.Component.KERNEL, content(97, 39),
                    BootImageRebuilder.OutputPolicy.DISCARD_INVALID_AVB_IF_ZERO_TAIL);
            compactZeroTail(work);
            for (int version = 0; version <= 4; version++) for (int page : new int[]{2048, 4096, 8192, 16384}) {
                if (version >= 3 && page != 4096) continue;
                for (boolean withFooter : new boolean[]{false, true}) emptyRamdiskRoundTrip(work, version, page, withFooter);
            }
            rejectedEmptyRamdisk(work);
            rejected(work);
            check(true, "All ordinary recovery fixtures complete");
            System.out.println("BootImageRecovery: " + checks + " checks passed");
        } finally {
            try (var paths = Files.walk(work)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toArray(Path[]::new)) Files.deleteIfExists(path);
            }
        }
    }
}
