package dev.maplesu.image;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Small container fixtures only; this test does not establish a bootable or signed image. */
public final class BootImageInvalidAvbCandidateTest {
    private static int passed, failed;

    private static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
    }

    private static byte[] components() {
        byte[] image = new byte[12288];
        ByteBuffer header = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        header.put("ANDROID!".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        header.putInt(8, 71).putInt(12, 53).putInt(20, 1584).putInt(40, 4);
        Arrays.fill(image, 4096, 4167, (byte) 0x31);
        Arrays.fill(image, 8192, 8245, (byte) 0x72);
        return image;
    }

    private static byte[] footer(byte[] body, long originalSize, long offset, long size) {
        byte[] image = Arrays.copyOf(body, 32768);
        int at = image.length - 64;
        ByteBuffer tail = ByteBuffer.wrap(image).order(ByteOrder.BIG_ENDIAN);
        tail.position(at); tail.put(new byte[]{'A', 'V', 'B', 'f'});
        tail.putInt(at + 4, 1).putLong(at + 12, originalSize)
                .putLong(at + 20, offset).putLong(at + 28, size);
        return image;
    }

    private static void strictRejection(Path source, Path replacement, Path output,
                                        byte[] bytes, String expected) throws Exception {
        Files.write(source, bytes);
        BootImageInspector.Report layout = BootImageInspector.inspect(source.toFile());
        check(layout.kernelSize == 71 && layout.ramdiskSize == 53, "components are inspectable");
        for (boolean read : new boolean[]{true, false}) {
            try {
                if (read) BootImageRebuilder.readRecoveryRecord(source.toFile());
                else BootImageRebuilder.rebuild(source.toFile(), replacement.toFile(), output.toFile());
                throw new AssertionError("strict accepted invalid AVB");
            } catch (IOException error) {
                check(expected.equals(error.getMessage()), "strict error: " + error.getMessage());
            }
        }
        check(!Files.exists(output), "strict published output");
        check(Arrays.equals(bytes, Files.readAllBytes(source)), "strict changed source");
    }

    private static BootImageRebuilder.Report candidate(Path source, Path replacement, Path output)
            throws IOException {
        return BootImageRebuilder.rebuildWithPolicy(source.toFile(), replacement.toFile(), output.toFile(),
                BootImageRebuilder.OutputPolicy.DISCARD_INVALID_AVB_IF_ZERO_TAIL);
    }

    private static void candidateWithoutMetadata(Path source, Path replacement, Path output,
                                                 byte[] bytes) throws Exception {
        Files.write(source, bytes);
        check(BootImageRebuilder.readRecoveryRecord(source.toFile(),
                BootImageRebuilder.OutputPolicy.DISCARD_INVALID_AVB_IF_ZERO_TAIL) == null,
                "candidate reader invents no recovery record");
        BootImageRebuilder.Report report = candidate(source, replacement, output);
        byte[] rebuilt = Files.readAllBytes(output);
        check(rebuilt.length == components().length, "candidate compact component length");
        check(Arrays.equals(Files.readAllBytes(replacement), Arrays.copyOfRange(rebuilt, 4096, 4167)),
                "candidate replacement exact");
        check(Arrays.equals(Arrays.copyOfRange(bytes, 8192, 8245), Arrays.copyOfRange(rebuilt, 8192, 8245)),
                "candidate ramdisk exact");
        check(!AvbFooter.parse(rebuilt.length < 64 ? rebuilt : Arrays.copyOfRange(rebuilt, rebuilt.length - 64, rebuilt.length)).present,
                "candidate has no appended footer");
        check(report.equivalence.ok(), "candidate declared changes verified");
        check(BootImageRebuilder.readRecoveryRecord(output.toFile()) == null, "no invented recovery record");
        check(Arrays.equals(bytes, Files.readAllBytes(source)), "candidate changed source");
        check(report.toJson().contains("\"originalSignaturesReverified\":false"), "no signature verification claim");
        if (AvbFooter.parse(bytes.length < 64 ? bytes : Arrays.copyOfRange(bytes, bytes.length - 64, bytes.length)).present) {
            check(report.sourceAvbFooterPresent && !report.avbFooterPresent, "source and output footer states differ");
            check(report.avbFooterDiscardReason != null, "discard reason recorded");
            check(report.toJson().contains("\"avbFooterRemoved\":true"), "removed footer reported");
            check(report.toJson().contains("\"avbFooterPreserved\":false"), "invalid footer not preserved");
            check(report.toJson().contains("\"oldMetadataRetained\":false"), "missing metadata not restored");
        }
    }

    private static void rejectedCandidate(Path source, Path replacement, Path output, byte[] bytes)
            throws Exception {
        Files.write(source, bytes);
        try {
            candidate(source, replacement, output);
            throw new AssertionError("invalid component or unknown content accepted");
        } catch (IOException expected) {
            check(!Files.exists(output), "rejected output published");
            check(Arrays.equals(bytes, Files.readAllBytes(source)), "rejected source changed");
        }
    }

    private static void validFooterPreserved(Path source, Path replacement, Path output) throws Exception {
        byte[] bytes = footer(components(), 12288, 12288, 256);
        System.arraycopy(new byte[]{'A', 'V', 'B', '0'}, 0, bytes, 12288, 4);
        Files.write(source, bytes);
        BootImageRebuilder.Report report = candidate(source, replacement, output);
        check(report.avbFooterPresent && AvbFooter.parse(output.toFile()).present, "valid footer retained");
        check(report.toJson().contains("\"avbFooterPreserved\":true"), "valid retention reported");
        byte[] result = Files.readAllBytes(output);
        check(Arrays.equals(Arrays.copyOfRange(bytes, 12288, 12544), Arrays.copyOfRange(result, 12288, 12544)),
                "valid metadata exact");
        check(Arrays.equals(bytes, Files.readAllBytes(source)), "valid source changed");
    }

    interface Case { void run() throws Exception; }

    private static void run(String label, Path output, Case test) throws Exception {
        Files.deleteIfExists(output);
        try { test.run(); passed++; System.out.println("PASS " + label); }
        catch (Exception | AssertionError error) {
            failed++; System.out.println("FAIL " + label + " " + error.getClass().getSimpleName() + ":" + error.getMessage());
        } finally { Files.deleteIfExists(output); }
    }

    public static void main(String[] args) throws Exception {
        Path work = Path.of(args[0]); Files.createDirectories(work);
        Path source = work.resolve("input.img"), replacement = work.resolve("kernel"), output = work.resolve("candidate.img");
        byte[] kernel = new byte[71]; Arrays.fill(kernel, (byte) 0x4b); Files.write(replacement, kernel);
        byte[] stale = footer(components(), 8192, 8192, 256);
        byte[] missing = footer(components(), 12288, 12288, 256);
        byte[] range = footer(components(), 12288, 32768, 256);
        run("strict-stale-footer-read-and-rebuild", output,
                () -> strictRejection(source, replacement, output, stale, "INVALID_AVB_FOOTER"));
        run("strict-missing-metadata-read-and-rebuild", output,
                () -> strictRejection(source, replacement, output, missing, "INVALID_AVB_METADATA"));
        run("strict-out-of-range-footer-read-and-rebuild", output,
                () -> strictRejection(source, replacement, output, range, "INVALID_AVB_FOOTER"));
        run("candidate-stale-footer-zero-tail", output,
                () -> candidateWithoutMetadata(source, replacement, output, stale));
        run("candidate-missing-metadata-zero-tail", output,
                () -> candidateWithoutMetadata(source, replacement, output, missing));
        run("candidate-range-footer-zero-tail", output,
                () -> candidateWithoutMetadata(source, replacement, output, range));
        run("candidate-without-footer-zero-tail", output,
                () -> candidateWithoutMetadata(source, replacement, output, Arrays.copyOf(components(), 32768)));
        run("valid-avb-preserved", output, () -> validFooterPreserved(source, replacement, output));
        byte[] unknown = stale.clone(); unknown[13000] = 7;
        run("unknown-nonzero-tail-rejected", output, () -> rejectedCandidate(source, replacement, output, unknown));
        byte[] truncatedFooter = Arrays.copyOf(stale, stale.length - 1);
        run("truncated-footer-rejected", output, () -> rejectedCandidate(source, replacement, output, truncatedFooter));
        byte[] componentOverflow = stale.clone();
        ByteBuffer.wrap(componentOverflow).order(ByteOrder.LITTLE_ENDIAN).putInt(8, componentOverflow.length);
        run("component-overflow-rejected", output, () -> rejectedCandidate(source, replacement, output, componentOverflow));
        byte[] headerTruncated = Arrays.copyOf(components(), 100);
        run("truncated-header-rejected", output, () -> rejectedCandidate(source, replacement, output, headerTruncated));
        Files.delete(source); Files.delete(replacement); Files.delete(work);
        System.out.println("RESULT passed=" + passed + " failed=" + failed);
        if (failed != 0) throw new AssertionError(failed + " candidate contracts unmet");
    }
}
