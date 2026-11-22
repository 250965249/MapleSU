import dev.maplesu.image.AvbFooter;
import dev.maplesu.image.BootImageInspector;
import dev.maplesu.image.BootImageRebuilder;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;

/** Source-launched host harness; unchanged real kernel components, no kernel patch generation. */
public final class InvalidAvbRealContainerMain {
    private static void check(boolean value, String label) throws IOException {
        if (!value) throw new IOException(label);
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static long align(long value, long page) {
        return (value + page - 1) / page * page;
    }

    private static ByteBuffer block(FileChannel file, long offset, int length) throws IOException {
        ByteBuffer bytes = ByteBuffer.allocate(length);
        while (bytes.hasRemaining()) {
            int count = file.read(bytes, offset + bytes.position());
            if (count < 0) throw new IOException("TRUNCATED_VERIFICATION_RANGE");
        }
        return bytes.flip();
    }

    private static String hash(FileChannel file, long offset, long length) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (long position = 0; position < length;) {
            int count = (int) Math.min(65536, length - position);
            digest.update(block(file, offset + position, count));
            position += count;
        }
        return java.util.HexFormat.of().formatHex(digest.digest());
    }

    private static boolean equal(FileChannel left, long leftOffset, FileChannel right,
                                 long rightOffset, long length) throws IOException {
        for (long position = 0; position < length;) {
            int count = (int) Math.min(65536, length - position);
            if (!block(left, leftOffset + position, count).equals(block(right, rightOffset + position, count)))
                return false;
            position += count;
        }
        return true;
    }

    private static boolean zero(FileChannel file, long offset, long length) throws IOException {
        for (long position = 0; position < length;) {
            int count = (int) Math.min(65536, length - position);
            ByteBuffer bytes = block(file, offset + position, count);
            while (bytes.hasRemaining()) if (bytes.get() != 0) return false;
            position += count;
        }
        return true;
    }

    private static long[][] parts(BootImageInspector.Report layout) {
        return new long[][] {{layout.kernelOffset, layout.kernelSize}, {layout.ramdiskOffset, layout.ramdiskSize},
                {layout.secondOffset, layout.secondSize}, {layout.recoveryDtboOffset, layout.recoveryDtboSize},
                {layout.dtbOffset, layout.dtbSize}, {layout.signatureOffset, layout.signatureSize}};
    }

    public static void main(String[] args) throws Exception {
        Path input = Path.of(args[0]).toAbsolutePath(), scratch = Path.of(args[1]).toAbsolutePath();
        Path evidence = Path.of(args[2]).toAbsolutePath();
        Files.createDirectory(scratch); Files.createDirectories(evidence);
        Path kernel = scratch.resolve("original-kernel-component.bin"), output = scratch.resolve("candidate.img");
        BootImageInspector.Report before = BootImageInspector.inspect(input.toFile());
        check(before.sha256.equals(args[3]), "INPUT_IDENTITY_DIFFERS_FROM_FROZEN_R2");
        check(before.headerVersion == 4 && before.signatureSize == 0, "EXPECTED_FROZEN_V4_ZERO_SIGNATURE");
        check(AvbFooter.parse(input.toFile()).present, "EXPECTED_SOURCE_AVB_FOOTER");
        long bodyEnd = before.pageSize;
        for (long[] part : parts(before)) if (part[1] > 0)
            bodyEnd = Math.max(bodyEnd, align(part[0] + part[1], before.pageSize));
        long peak = 0;
        try {
            try (FileChannel source = FileChannel.open(input, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
                 FileChannel copy = FileChannel.open(kernel, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                for (long position = 0; position < before.kernelSize;) {
                    int count = (int) Math.min(65536, before.kernelSize - position);
                    ByteBuffer bytes = block(source, before.kernelOffset + position, count);
                    while (bytes.hasRemaining()) copy.write(bytes);
                    position += count;
                }
                copy.force(true);
            }
            String strictCode;
            try {
                BootImageRebuilder.readRecoveryRecord(input.toFile());
                throw new IOException("STRICT_READER_ACCEPTED_STALE_FOOTER");
            } catch (BootImageRebuilder.ValidationException expected) {
                strictCode = expected.getMessage();
                check(strictCode.equals("INVALID_AVB_FOOTER"), "UNEXPECTED_STRICT_FAILURE");
            }
            check(BootImageRebuilder.readRecoveryRecord(input.toFile(),
                    BootImageRebuilder.OutputPolicy.DISCARD_INVALID_AVB_IF_ZERO_TAIL) == null,
                    "SOURCE_RECOVERY_RECORD_WAS_INVENTED");
            BootImageRebuilder.Report rebuild = BootImageRebuilder.rebuildWithPolicy(input.toFile(),
                    kernel.toFile(), output.toFile(), BootImageRebuilder.OutputPolicy.DISCARD_INVALID_AVB_IF_ZERO_TAIL);
            peak = Files.size(kernel) + Files.size(output);
            check(peak <= 128L * 1024 * 1024, "SCRATCH_BYTES_LIMIT");
            BootImageInspector.Report after = BootImageInspector.inspect(output.toFile());
            check(after.fileSize == bodyEnd, "CANDIDATE_HAS_UNEXPECTED_TRAILER");
            check(!AvbFooter.parse(output.toFile()).present, "INVALID_FOOTER_RETAINED");
            check(BootImageRebuilder.readRecoveryRecord(output.toFile()) == null, "OUTPUT_RECORD_WAS_INVENTED");
            check(rebuild.equivalence.ok() && !rebuild.kernelChanged && !rebuild.ramdiskChanged,
                    "SAME_COMPONENT_REBUILD_NOT_EQUIVALENT");
            check(rebuild.sourceAvbFooterPresent && rebuild.avbFooterRemoved && !rebuild.avbFooterPresent,
                    "FOOTER_STATE_REPORT_DIFFERS");
            String[] names = {"kernel", "ramdisk", "second", "recoveryDtbo", "dtb", "signature"};
            long[][] oldParts = parts(before), newParts = parts(after);
            StringBuilder components = new StringBuilder("[");
            String sourceTailHash, sourceHeaderHash, outputHeaderHash;
            long sourceTailBytes = before.fileSize - 64 - bodyEnd;
            try (FileChannel source = FileChannel.open(input, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
                 FileChannel result = FileChannel.open(output, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                check(equal(source, 0, result, 0, bodyEnd), "COMPONENT_BODY_BYTES_DIFFER");
                check(zero(source, bodyEnd, sourceTailBytes), "SOURCE_POST_COMPONENT_TAIL_NOT_ZERO");
                sourceTailHash = hash(source, bodyEnd, sourceTailBytes);
                sourceHeaderHash = hash(source, 0, before.pageSize);
                outputHeaderHash = hash(result, 0, after.pageSize);
                check(sourceHeaderHash.equals(outputHeaderHash), "HEADER_PAGE_CHANGED");
                Files.write(evidence.resolve("input-header.bin"), block(source, 0, 1584).array());
                Files.write(evidence.resolve("input-footer.bin"), block(source, before.fileSize - 64, 64).array());
                Files.write(evidence.resolve("output-header.bin"), block(result, 0, 1584).array());
                for (int index = 0; index < names.length; index++) {
                    long[] old = oldParts[index], next = newParts[index];
                    check(old[1] == next[1], "COMPONENT_SIZE_CHANGED:" + names[index]);
                    boolean exact = equal(source, old[0], result, next[0], old[1]);
                    String originalHash = hash(source, old[0], old[1]), outputHash = hash(result, next[0], next[1]);
                    check(exact && originalHash.equals(outputHash), "COMPONENT_BYTES_CHANGED:" + names[index]);
                    if (index > 0) components.append(',');
                    components.append("{\"name\":").append(quote(names[index])).append(",\"sourceOffset\":")
                            .append(old[0]).append(",\"outputOffset\":").append(next[0]).append(",\"bytes\":")
                            .append(old[1]).append(",\"sourceSha256\":").append(quote(originalHash))
                            .append(",\"outputSha256\":").append(quote(outputHash)).append(",\"fullBytesEqual\":true}");
                }
            }
            components.append(']');
            BootImageInspector.Report unchanged = BootImageInspector.inspect(input.toFile());
            check(unchanged.fileSize == before.fileSize && unchanged.sha256.equals(before.sha256), "INPUT_CHANGED");
            String json = "{\"schema\":\"maplesu-invalid-avb-real-container/1\",\"inputPath\":" + quote(input.toString())
                    + ",\"input\":" + before.toJson() + ",\"inputAfter\":" + unchanged.toJson()
                    + ",\"output\":" + after.toJson() + ",\"rebuild\":" + rebuild.toJson()
                    + ",\"strictReadFailure\":" + quote(strictCode) + ",\"components\":" + components
                    + ",\"sourceHeaderPageSha256\":" + quote(sourceHeaderHash)
                    + ",\"outputHeaderPageSha256\":" + quote(outputHeaderHash)
                    + ",\"sourceTail\":{\"start\":" + bodyEnd + ",\"bytes\":" + sourceTailBytes
                    + ",\"sha256\":" + quote(sourceTailHash) + ",\"allZero\":true}"
                    + ",\"outputUnknownTailBytes\":0,\"fullBodyBytesEqual\":true,\"inputUnchanged\":true"
                    + ",\"scratchPeakLogicalBytes\":" + peak
                    + ",\"kernelPatched\":false,\"SDKOrRootValidated\":false,\"deviceTest\":false,\"partitionWrites\":false}";
            Files.writeString(evidence.resolve("result.json"), json + "\n");
            System.out.println("PASS " + input.getFileName() + " componentBytes=" + before.kernelSize
                    + " candidateBytes=" + after.fileSize + " sha256=" + after.sha256);
        } finally {
            // Only these two paths were created by this invocation; no recursive cleanup or source deletion.
            Files.deleteIfExists(output); Files.deleteIfExists(kernel); Files.delete(scratch);
        }
    }
}
