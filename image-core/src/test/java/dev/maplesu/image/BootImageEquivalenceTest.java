package dev.maplesu.image;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Fixtures for the "only declared bytes differ" contract.
 *
 * <p>Synthetic part: a v4 rebuild with a same-size payload must declare every changed byte, and two
 * sabotage cases must be rejected (an undeclared byte, and a declared header field that is not on the
 * AOSP whitelist). Real part (skipped when the reference images are absent): the device-proven
 * 6.6.89 stock image plus the k21 kernel artefact must rebuild with a fully covered journal, and the
 * rebuild must be idempotent.
 */
public final class BootImageEquivalenceTest {
    private static int passed;
    /** Resolved against the Gradle-provided repository root; '.' when run from the repo root. */
    private static final java.io.File ROOT = new java.io.File(System.getProperty("maplesu.root", "."));
    private static final java.io.File STOCK =
            new java.io.File(ROOT, "SKRoot_Reference/Boots/OnePlusAce6_6.6/boot.img");
    private static final java.io.File KERNEL = new java.io.File(ROOT, "build/flash/k21-kernel.bin");
    private static final java.io.File GOLDEN = new java.io.File(ROOT, "build/flash/k21-boot.img");
    private static final java.io.File ACE6_PLUS =
            new java.io.File(ROOT, "SKRoot_Reference/Boots/Oneplus_Ace6_Plus_6.12/boot.img");

    private static void check(boolean condition, String description) {
        if (!condition) throw new AssertionError(description);
        passed++;
    }

    private static byte[] kernelBlock(File image) throws IOException {
        BootImageInspector.Report report = BootImageInspector.inspect(image);
        byte[] bytes = new byte[(int) report.kernelSize];
        try (RandomAccessFile input = new RandomAccessFile(image, "r")) {
            input.seek(report.kernelOffset);
            input.readFully(bytes);
        }
        return bytes;
    }

    public static void main(String[] args) throws Exception {
        Path work = Files.createTempDirectory("maplesu-equivalence-");
        try {
            Path source = work.resolve("source.img"), kernel = work.resolve("kernel"),
                    output = work.resolve("output.img");
            synthetic(work, source, kernel, output);
            declaredRangeUnion(work);
            exactDifferenceGaps(work);
            truncatedRanges(work);
            avbFooter(work);
            if (STOCK.isFile() && KERNEL.isFile()) {
                reference(work);
            } else {
                System.out.println("SKIP reference equivalence (stock/kernel artefacts absent)");
            }
            if (args.length > 0) sweep(work, args);
            System.out.println("PASS " + passed + " boot image equivalence checks");
        } finally {
            try (var files = Files.list(work)) { for (Path file : files.toList()) Files.deleteIfExists(file); }
            Files.deleteIfExists(work);
        }
    }

    private static void synthetic(Path work, Path source, Path kernel, Path output) throws Exception {
        // Same-size payload: the only declared ranges are the kernel block, two header fields and
        // the two footer words, so the journal stays byte-precise.
        byte[] original = BootImageRebuilderTest.fixture(8192, 4096);
        Files.write(source, original);
        byte[] replacement = Arrays.copyOfRange(original, 4096, 4096 + 8192);
        for (int index = 0; index < replacement.length; index += 97) replacement[index] ^= 0x5a;
        Files.write(kernel, replacement);
        BootImageRebuilder.Report report =
                BootImageRebuilder.rebuildV4(source.toFile(), kernel.toFile(), output.toFile());
        check(report.equivalence.ok(), "same-size rebuild declares every changed byte");
        check(report.journal.strict(), "same-size journal is byte-precise");
        check(report.equivalence.changedBytes > 0, "patch really changed bytes");
        check(report.equivalence.changedBytes <= report.equivalence.declaredBytes, "diff inside declaration");
        check(report.toJson().contains("\"equivalenceVerified\":true"), "report carries the verdict");
        check(report.toJson().contains("\"declaredDiffOnly\":true"), "report carries the coverage flag");

        // Sabotage 1: one byte outside every declared range (cmdline byte 90 of the output).
        byte[] tampered = Files.readAllBytes(output);
        tampered[90] ^= 1;
        Files.write(output, tampered);
        BootImageEquivalence.Verification undeclared =
                BootImageEquivalence.verify(source.toFile(), output.toFile(), report.journal);
        check("REBUILD_DIFF_OUTSIDE_DECLARED".equals(undeclared.code), "undeclared byte detected");
        check(!undeclared.ok() && undeclared.uncovered.size() == 1, "undeclared range reported once");
        Files.delete(output);

        // Sabotage 2: a declared HEADER_FIELD that is not on the AOSP whitelist still fails.
        BootImageEquivalence.Journal forged = new BootImageEquivalence.Journal();
        forged.shape(4, 1584, 4096);
        forged.outputSize(original.length);
        forged.add(BootImageEquivalence.HEADER_FIELD, 40, 4);
        byte[] header = Files.readAllBytes(source);
        header[40] = 9;
        Files.write(output, header);
        BootImageEquivalence.Verification headerAudit =
                BootImageEquivalence.verify(source.toFile(), output.toFile(), forged);
        check("REBUILD_HEADER_FIELD_NOT_ALLOWED".equals(headerAudit.code), "non-whitelisted header field rejected");
        Files.delete(output);

        // diff() is independent of the journal and reports the exact ranges.
        byte[] changed = original.clone();
        changed[10] = 1;
        changed[10 + 4096] = 1;
        Path other = work.resolve("other.img");
        Files.write(other, changed);
        BootImageEquivalence.Diff diff = BootImageEquivalence.diff(source.toFile(), other.toFile());
        check(diff.changedBytes == 2 && diff.ranges.size() == 2, "diff counts isolated bytes");
        check(diff.ranges.get(0).offset == 10 && diff.ranges.get(1).offset == 10 + 4096, "diff offsets");
        Files.delete(other);
        Files.deleteIfExists(kernel);
    }

    private static void exactDifferenceGaps(Path work) throws Exception {
        Path source = work.resolve("gap-source.img"), output = work.resolve("gap-output.img");
        byte[] original = new byte[(1 << 16) + 32];
        Files.write(source, original);
        for (int[] pair : new int[][] {{4096, 4098}, {4096, 4100}, {65534, 65536}, {65535, 65536}}) {
            byte[] changed = original.clone();
            changed[pair[0]] = 1;
            changed[pair[1]] = 1;
            Files.write(output, changed);
            BootImageEquivalence.Journal journal = new BootImageEquivalence.Journal();
            journal.shape(4, 1584, 4096);
            journal.outputSize(changed.length);
            journal.add(BootImageEquivalence.RECOVERY_RECORD, pair[0], 1);
            journal.add(BootImageEquivalence.RECOVERY_RECORD, pair[1], 1);
            BootImageEquivalence.Verification verified =
                    BootImageEquivalence.verify(source.toFile(), output.toFile(), journal);
            boolean adjacent = pair[1] == pair[0] + 1;
            check(verified.ok() && verified.changedBytes == 2 && verified.uncoveredBytes == 0,
                    "exact changes stay covered across byte gaps and input chunks");
            check(verified.diff.ranges.size() == (adjacent ? 1 : 2),
                    "only truly adjacent differences are coalesced");
            if (!adjacent) {
                changed[pair[0] + 1] = 1;
                Files.write(output, changed);
                check("REBUILD_DIFF_OUTSIDE_DECLARED".equals(
                        BootImageEquivalence.verify(source.toFile(), output.toFile(), journal).code),
                        "an actual undeclared change inside the gap remains rejected");
            }
        }
        Files.delete(source);
        Files.delete(output);
    }

    private static void declaredRangeUnion(Path work) throws Exception {
        Path source = work.resolve("union-source.img"), output = work.resolve("union-output.img");
        byte[] original = new byte[8192], changed = original.clone();
        Arrays.fill(changed, 4096, 4102, (byte) 1);
        Files.write(source, original);
        Files.write(output, changed);
        BootImageEquivalence.Journal adjacent = new BootImageEquivalence.Journal();
        adjacent.shape(4, 1584, 4096);
        adjacent.outputSize(changed.length);
        // The record and its zero padding are independent, adjacent declarations. A measured
        // difference may cross their boundary and must be covered by the union in either order.
        adjacent.add(BootImageEquivalence.TRAILING_ZERO, 4100, 2);
        adjacent.add(BootImageEquivalence.RECOVERY_RECORD, 4098, 2);
        adjacent.add(BootImageEquivalence.RECOVERY_RECORD, 4096, 2);
        BootImageEquivalence.Verification joined =
                BootImageEquivalence.verify(source.toFile(), output.toFile(), adjacent);
        check(joined.ok() && joined.uncoveredBytes == 0, "adjacent declarations jointly cover one difference");
        check(joined.diff.ranges.size() == 1 && joined.diff.ranges.get(0).length == 6,
                "boundary regression uses a single measured difference");
        check(joined.declaredBytes == 6, "adjacent union keeps precise declared byte count");

        BootImageEquivalence.Journal overlap = new BootImageEquivalence.Journal();
        overlap.shape(4, 1584, 4096);
        overlap.outputSize(changed.length);
        overlap.add(BootImageEquivalence.TRAILING_ZERO, 4098, 4);
        overlap.add(BootImageEquivalence.RECOVERY_RECORD, 4096, 4);
        check(BootImageEquivalence.verify(source.toFile(), output.toFile(), overlap).ok(),
                "overlapping declarations jointly cover one difference");
        check(overlap.declaredBytes() == 6, "overlapping union counts bytes once");

        BootImageEquivalence.Journal gap = new BootImageEquivalence.Journal();
        gap.shape(4, 1584, 4096);
        gap.outputSize(changed.length);
        gap.add(BootImageEquivalence.RECOVERY_RECORD, 4096, 3);
        gap.add(BootImageEquivalence.TRAILING_ZERO, 4100, 2);
        BootImageEquivalence.Verification changedGap =
                BootImageEquivalence.verify(source.toFile(), output.toFile(), gap);
        check("REBUILD_DIFF_OUTSIDE_DECLARED".equals(changedGap.code), "one undeclared changed byte is rejected");
        changed[4099] = 0;
        Files.write(output, changed);
        BootImageEquivalence.Verification mergedGap =
                BootImageEquivalence.verify(source.toFile(), output.toFile(), gap);
        check(mergedGap.diff.ranges.size() == 2 && mergedGap.diff.ranges.get(0).offset == 4096 &&
                mergedGap.diff.ranges.get(0).length == 3 && mergedGap.diff.ranges.get(1).offset == 4100 &&
                mergedGap.diff.ranges.get(1).length == 2, "unchanged gap remains outside measured differences");
        check(mergedGap.ok() && mergedGap.changedBytes == 5 && mergedGap.uncoveredBytes == 0,
                "independently declared changes do not require the unchanged gap");

        Arrays.fill(changed, (byte) 0);
        changed[40] = 1;
        changed[41] = 1;
        Files.write(output, changed);
        BootImageEquivalence.Journal header = new BootImageEquivalence.Journal();
        header.shape(4, 1584, 4096);
        header.outputSize(changed.length);
        header.add(BootImageEquivalence.RECOVERY_RECORD, 40, 1);
        header.add(BootImageEquivalence.TRAILING_ZERO, 41, 1);
        check("REBUILD_HEADER_FIELD_UNDECLARED".equals(
                BootImageEquivalence.verify(source.toFile(), output.toFile(), header).code),
                "union coverage does not permit non-header declarations in the header");
        header.add(BootImageEquivalence.HEADER_FIELD, 40, 2);
        check("REBUILD_HEADER_FIELD_NOT_ALLOWED".equals(
                BootImageEquivalence.verify(source.toFile(), output.toFile(), header).code),
                "union coverage retains the AOSP header field whitelist");
        Files.delete(source);
        Files.delete(output);
    }

    private static void truncatedRanges(Path work) throws Exception {
        Path source = work.resolve("many-source.img"), output = work.resolve("many-output.img");
        byte[] original = new byte[32768], changed = original.clone();
        for (int index = 0; index < 5000; index++) changed[4096 + index * 4] = 1;
        Files.write(source, original);
        Files.write(output, changed);
        BootImageEquivalence.Journal journal = new BootImageEquivalence.Journal();
        journal.shape(4, 1584, 4096);
        journal.outputSize(changed.length);
        journal.add(BootImageEquivalence.COMPONENT, 4096, 20000);
        BootImageEquivalence.Verification legal =
                BootImageEquivalence.verify(source.toFile(), output.toFile(), journal);
        check(legal.ok() && legal.diff.truncated, "legal differences beyond the report limit pass");
        check(legal.changedBytes == 5000 && legal.diff.ranges.size() == 4096,
                "full byte count with a bounded difference report");

        changed[25000] = 1;
        Files.write(output, changed);
        BootImageEquivalence.Verification late =
                BootImageEquivalence.verify(source.toFile(), output.toFile(), journal);
        check("REBUILD_DIFF_OUTSIDE_DECLARED".equals(late.code), "late undeclared byte rejected");
        check(late.uncoveredBytes == 1 && late.uncovered.size() == 1 && late.uncovered.get(0).offset == 25000,
                "late undeclared byte reported beyond the difference limit");

        changed[25000] = 0;
        byte[] extended = Arrays.copyOf(changed, changed.length + 8);
        Files.write(output, extended);
        journal.outputSize(extended.length);
        BootImageEquivalence.Verification tail =
                BootImageEquivalence.verify(source.toFile(), output.toFile(), journal);
        check("REBUILD_DIFF_OUTSIDE_DECLARED".equals(tail.code) && tail.uncoveredBytes == 8,
                "undeclared length delta beyond the difference limit rejected");
        check(tail.uncovered.size() == 1 && tail.uncovered.get(0).offset == changed.length,
                "late length delta reported");

        Files.write(output, changed);
        BootImageEquivalence.Journal empty = new BootImageEquivalence.Journal();
        empty.shape(4, 1584, 4096);
        empty.outputSize(changed.length);
        BootImageEquivalence.Verification allUncovered =
                BootImageEquivalence.verify(source.toFile(), output.toFile(), empty);
        check(!allUncovered.ok() && allUncovered.uncoveredBytes == 5000,
                "every uncovered range contributes beyond the report limit");
        check(allUncovered.uncovered.size() == 4096, "uncovered report stays bounded");
        Files.delete(source);
        Files.delete(output);
    }

    /**
     * AVB footer: one big-endian parser. The regression guard is the endianness/offset pair the
     * baseline gate used to get wrong (LE at +8/+16/+24 instead of BE at +12/+20/+28).
     */
    private static void avbFooter(Path work) throws Exception {
        long originalSize = 8192, vbmetaSize = 320;
        byte[] footer = new byte[AvbFooter.SIZE];
        System.arraycopy(new byte[]{'A', 'V', 'B', 'f'}, 0, footer, 0, 4);
        putBe32(footer, 4, 1);                       // version major
        putBe32(footer, 8, 0);                       // version minor
        putBe64(footer, AvbFooter.OFFSET_ORIGINAL_IMAGE_SIZE, originalSize);
        putBe64(footer, AvbFooter.OFFSET_VBMETA_OFFSET, originalSize);
        putBe64(footer, AvbFooter.OFFSET_VBMETA_SIZE, vbmetaSize);
        Path image = work.resolve("avb.img");
        byte[] bytes = new byte[(int) (originalSize + vbmetaSize + AvbFooter.SIZE)];
        System.arraycopy(footer, 0, bytes, bytes.length - AvbFooter.SIZE, AvbFooter.SIZE);
        Files.write(image, bytes);
        AvbFooter parsed = AvbFooter.parse(image.toFile());
        check(parsed.present, "footer detected");
        check(parsed.versionMajor == 1 && parsed.versionMinor == 0, "footer version read big-endian");
        check(parsed.originalImageSize == originalSize, "footer original_image_size read big-endian");
        check(parsed.vbmetaOffset == originalSize && parsed.vbmetaSize == vbmetaSize, "footer vbmeta range");
        check(parsed.valid(bytes.length), "valid footer accepted");
        check(parsed.reservedZero, "reserved tail reported as zero");

        // Non-zero version_minor is exactly what the old LE/+8 read mistook for the image size.
        byte[] shifted = bytes.clone();
        putBe32(shifted, shifted.length - AvbFooter.SIZE + 8, 0x01020304);
        Files.write(image, shifted);
        AvbFooter minor = AvbFooter.parse(image.toFile());
        check(minor.versionMinor == 0x01020304L && minor.originalImageSize == originalSize,
                "version_minor never leaks into original_image_size");

        // Range violations are reported, not silently accepted.
        byte[] badSize = bytes.clone();
        putBe64(badSize, badSize.length - AvbFooter.SIZE + AvbFooter.OFFSET_VBMETA_SIZE, 1);
        Files.write(image, badSize);
        check("AVB_VBMETA_SIZE_RANGE".equals(AvbFooter.parse(image.toFile()).invalidReason(bytes.length)),
                "undersized vbmeta rejected");
        byte[] badOffset = bytes.clone();
        putBe64(badOffset, badOffset.length - AvbFooter.SIZE + AvbFooter.OFFSET_VBMETA_OFFSET, originalSize - 1);
        Files.write(image, badOffset);
        check("AVB_VBMETA_OFFSET_RANGE".equals(AvbFooter.parse(image.toFile()).invalidReason(bytes.length)),
                "vbmeta before the payload rejected");
        // uint64 fields with bit 63 set must not become valid negative Java file offsets.
        long[][] unsignedCases = {
                {8192, 8192, 320},
                {Long.MIN_VALUE, 8192, 320},
                {-1, 8192, 320},
                {-1, -1, 320},
                {8192, Long.MIN_VALUE, 320},
                {8192, -1, 320},
                {8192, 8192, Long.MIN_VALUE},
                {8192, 8192, -1},
                {Long.MAX_VALUE, 8192, 320},
                {8192, 8192, 321}
        };
        String[] unsignedReasons = {
                "", "AVB_ORIGINAL_SIZE_RANGE", "AVB_ORIGINAL_SIZE_RANGE", "AVB_ORIGINAL_SIZE_RANGE",
                "AVB_VBMETA_OFFSET_RANGE", "AVB_VBMETA_OFFSET_RANGE",
                "AVB_VBMETA_SIZE_RANGE", "AVB_VBMETA_SIZE_RANGE",
                "AVB_ORIGINAL_SIZE_RANGE", "AVB_VBMETA_SIZE_RANGE"
        };
        for (int index = 0; index < unsignedCases.length; index++) {
            byte[] unsigned = bytes.clone();
            int at = unsigned.length - AvbFooter.SIZE;
            putBe64(unsigned, at + AvbFooter.OFFSET_ORIGINAL_IMAGE_SIZE, unsignedCases[index][0]);
            putBe64(unsigned, at + AvbFooter.OFFSET_VBMETA_OFFSET, unsignedCases[index][1]);
            putBe64(unsigned, at + AvbFooter.OFFSET_VBMETA_SIZE, unsignedCases[index][2]);
            Files.write(image, unsigned);
            AvbFooter actual = AvbFooter.parse(image.toFile());
            check(unsignedReasons[index].equals(actual.invalidReason(unsigned.length))
                            && actual.valid(unsigned.length) == unsignedReasons[index].isEmpty(),
                    "unsigned footer range case " + index);
        }
        Files.write(image, new byte[1024]);
        check(!AvbFooter.parse(image.toFile()).present && AvbFooter.parse(image.toFile()).invalidReason(1024).isEmpty(),
                "no footer is not a failure");
        Files.delete(image);
    }

    private static void putBe32(byte[] target, int offset, long value) {
        for (int index = 0; index < 4; index++) target[offset + index] = (byte) (value >>> ((3 - index) * 8));
    }

    private static void putBe64(byte[] target, int offset, long value) {
        for (int index = 0; index < 8; index++) target[offset + index] = (byte) (value >>> ((7 - index) * 8));
    }

    /** Device-proven base: stock 6.6.89 + k21 kernel must reproduce the recorded k21 image. */
    private static void reference(Path work) throws Exception {
        File stock = STOCK, kernel = KERNEL;
        Path output = work.resolve("k21.img");
        BootImageRebuilder.Report report =
                BootImageRebuilder.rebuildV4(stock, kernel, output.toFile());
        check(report.equivalence.ok(), "stock+k21: every changed byte was declared");
        check(report.journal.strict(), "stock+k21: journal is byte-precise");
        System.out.println("reference journal: changed=" + report.equivalence.changedBytes
                + " declared=" + report.equivalence.declaredBytes
                + " strict=" + report.journal.strict());
        if (GOLDEN.isFile()) {
            byte[] expected = Files.readAllBytes(GOLDEN.toPath());
            byte[] actual = Files.readAllBytes(output);
            check(Arrays.equals(expected, actual), "stock+k21 reproduces the recorded k21 image byte for byte");
            check(BootImageRoundTrip.sha256(actual)
                    .equals("6c7a451d0f6675d358ac0bcca7979a83fb30051d30d301a22ecec8d6da9ff5c2"),
                    "recorded k21 digest");
            // Idempotency: rebuilding the result with the same payload is a no-op.
            Path again = work.resolve("k21-again.img");
            BootImageRebuilder.Report second = BootImageRebuilder.rebuildV4(output.toFile(), kernel, again.toFile());
            check(!second.kernelChanged, "idempotent rebuild reports unchanged payload");
            check(Arrays.equals(actual, Files.readAllBytes(again)), "idempotent rebuild is byte identical");
            check(second.equivalence.ok(), "idempotent rebuild declares every byte");
            Files.delete(again);
        }
        Files.delete(output);
        if (ACE6_PLUS.isFile()) compressed(ACE6_PLUS, work);
    }

    /**
     * LZ4-legacy kernel re-encoded the way the Ultra path does it (decode -> literal re-encode): the
     * container grows by ~2x, so the tail is honestly reported as a relocation.
     */
    private static void compressed(File image, Path work) throws Exception {
        Path kernel = work.resolve("ace6plus.kernel"), output = work.resolve("ace6plus.img");
        BootImageInspector.Report layout = BootImageInspector.inspect(image);
        byte[] raw = KernelCompression.decode(kernelBlock(image), layout.compression,
                KernelCompression.MAX_KERNEL_BYTES);
        Files.write(kernel, KernelCompression.encode(raw, layout.compression));
        BootImageRebuilder.Report report = BootImageRebuilder.rebuildV4(image, kernel.toFile(), output.toFile());
        check(report.equivalence.ok(), "lz4-legacy image: every changed byte was declared");
        check(!report.journal.strict(), "grown payload is reported as a relocation, not a byte-precise claim");
        check(report.equivalence.changedBytes > 0 && report.equivalence.uncoveredBytes == 0, "relocated tail covered");
        Files.delete(kernel);
        Files.delete(output);
    }

    private static void sweep(Path work, String[] paths) throws Exception {
        Path kernel = work.resolve("sweep.kernel"), output = work.resolve("sweep.img");
        for (String path : paths) {
            File image = new File(path);
            if (!image.isFile()) continue;
            Files.write(kernel, kernelBlock(image));
            BootImageRebuilder.Report report = BootImageRebuilder.rebuildV4(image, kernel.toFile(), output.toFile());
            check(report.equivalence.ok(), "sweep declares every byte: " + image.getName());
            check(report.equivalence.uncoveredBytes == 0, "sweep has no uncovered byte: " + image.getName());
            System.out.println("sweep " + image.getName() + " changed=" + report.equivalence.changedBytes
                    + " declared=" + report.equivalence.declaredBytes + " strict=" + report.journal.strict());
            Files.delete(output);
        }
        Files.deleteIfExists(kernel);
    }
}
