package dev.maplesu.image;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Exact input-container recovery; component payloads are copied, never executed or re-encoded. */
public final class BootImageRecovery {
    public static final long MAX_SNAPSHOT_BYTES = 64L * 1024 * 1024;
    private static final long MAX_IMAGE_BYTES = 512L * 1024 * 1024;
    private static final int HEADER_BYTES = 112, SPAN_BYTES = 56, SHA_BYTES = 32, MAX_SPANS = 16384;
    private static final int LITERAL = 0, ZERO = 1, COMPONENT = 2;
    private static final byte[] MAGIC = {'M', 'S', 'U', 'B', 'I', 'M', 'G', 0};
    private static final byte[] ZERO_SHA = new byte[SHA_BYTES];
    private static final String EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    public enum Component { KERNEL, RAMDISK }

    /** Only capture's bounded encoding limits are optional recovery-capacity failures. */
    public static final class CapacityException extends IOException {
        private CapacityException(String code) { super(code); }
    }

    public static final class Snapshot {
        public final long originalImageBytes, targetComponentBytes, snapshotBytes;
        public final String originalImageSha256, targetComponentSha256, snapshotSha256;
        public final Component target;
        private final List<Span> spans;

        private Snapshot(long originalBytes, String originalSha, Component target, long targetBytes,
                         String targetSha, long snapshotBytes, String snapshotSha, List<Span> spans) {
            originalImageBytes = originalBytes; originalImageSha256 = originalSha; this.target = target;
            targetComponentBytes = targetBytes; targetComponentSha256 = targetSha;
            this.snapshotBytes = snapshotBytes; snapshotSha256 = snapshotSha;
            this.spans = List.copyOf(spans);
        }
    }

    public static final class RestoreReport {
        public final BootImageInspector.Report image;
        public final long originalImageBytes;
        public final String originalImageSha256;
        public final boolean exactInputRestored = true;
        public final boolean originalSignaturesReverified = false;
        public final boolean flashableCandidate = false;

        private RestoreReport(BootImageInspector.Report image, Snapshot snapshot) {
            this.image = image; originalImageBytes = snapshot.originalImageBytes;
            originalImageSha256 = snapshot.originalImageSha256;
        }
    }

    private static final class Span {
        final int kind, component;
        final long offset;
        long length, dataOffset;
        String sha256;

        Span(int kind, int component, long offset, long length, String hash) {
            this.kind = kind; this.component = component; this.offset = offset;
            this.length = length; sha256 = hash;
        }
    }

    private BootImageRecovery() {}

    /** Captures every original byte not supplied later by a bound component. */
    public static Snapshot capture(File original, Component target, File snapshot,
                                   BootImageRebuilder.OutputPolicy policy) throws IOException {
        Objects.requireNonNull(target, "target"); Objects.requireNonNull(policy, "policy");
        BootImageRebuilder.cancelled();
        BootImageRebuilder.validateRecoveryInput(original, policy);
        Path source = original.toPath(), output = snapshot.toPath();
        BasicFileAttributes identity = BootImageRebuilder.input(source, 1632, MAX_IMAGE_BYTES,
                "BOOT_RECOVERY_IMAGE_SIZE_LIMIT");
        Path anchor = anchor(output);
        BootImageRebuilder.OutputIdentity outputIdentity = null;
        boolean created = false;
        Throwable failure = null;
        Snapshot result;
        try (FileChannel input = FileChannel.open(source, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            BootImageInspector.Report layout = BootImageInspector.inspect(original);
            String originalSha = BootImageRebuilder.hash(input, 0, identity.size());
            if (layout.fileSize != identity.size() || !layout.sha256.equals(originalSha)) throw error("SOURCE_CHANGED");
            long[] targetRegion = component(layout, target.ordinal() + 1);
            boolean emptyRamdisk = target == Component.RAMDISK && targetRegion[1] == 0;
            if (targetRegion[1] <= 0 && !emptyRamdisk) throw error("BOOT_RECOVERY_TARGET_MISSING");
            List<Span> spans = new ArrayList<>();
            List<Span> components = new ArrayList<>();
            for (int id = 1; id <= 5; id++) {
                long[] region = component(layout, id);
                if (region[1] > 0) components.add(new Span(COMPONENT, id, region[0], region[1],
                        BootImageRebuilder.hash(input, region[0], region[1])));
            }
            components.sort(Comparator.comparingLong(span -> span.offset));
            long position = 0;
            for (Span part : components) {
                if (part.offset < position || part.length > identity.size() - part.offset)
                    throw error("BOOT_RECOVERY_COMPONENT_LAYOUT");
                gap(input, spans, position, part.offset);
                spans.add(part); position = part.offset + part.length;
            }
            gap(input, spans, position, identity.size());
            if (spans.isEmpty()) throw error("BOOT_RECOVERY_SPAN_LIMIT");
            if (spans.size() > MAX_SPANS) throw new CapacityException("BOOT_RECOVERY_SPAN_LIMIT");
            long encodedBytes = HEADER_BYTES + SHA_BYTES + (long) spans.size() * SPAN_BYTES;
            String targetSha = emptyRamdisk ? EMPTY_SHA256 : null;
            for (Span span : spans) {
                if (span.kind == LITERAL) {
                    encodedBytes += span.length;
                    span.sha256 = BootImageRebuilder.hash(input, span.offset, span.length);
                }
                if (span.kind == COMPONENT && span.component == target.ordinal() + 1) targetSha = span.sha256;
            }
            if (encodedBytes > MAX_SNAPSHOT_BYTES) throw new CapacityException("BOOT_RECOVERY_SNAPSHOT_SIZE_LIMIT");
            try (FileChannel destination = FileChannel.open(output, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                created = true; outputIdentity = BootImageRebuilder.OutputIdentity.capture(output, anchor);
                ByteBuffer header = buffer(HEADER_BYTES).put(MAGIC).putInt(emptyRamdisk ? 2 : 1).putInt(HEADER_BYTES)
                        .putLong(identity.size()).put(unhex(originalSha)).putInt(target.ordinal())
                        .putInt(spans.size()).putLong(targetRegion[1]).put(unhex(targetSha)).putLong(0);
                header.flip(); BootImageRebuilder.write(destination, header);
                for (Span span : spans) {
                    ByteBuffer record = buffer(SPAN_BYTES).putInt(span.kind).putInt(span.component)
                            .putLong(span.offset).putLong(span.length)
                            .put(span.kind == ZERO ? ZERO_SHA : unhex(span.sha256));
                    record.flip(); BootImageRebuilder.write(destination, record);
                    if (span.kind == LITERAL) BootImageRebuilder.copy(input, span.offset, span.length, destination);
                }
                if (destination.position() != encodedBytes - SHA_BYTES) throw error("BOOT_RECOVERY_RECORD_LENGTH");
                BootImageRebuilder.write(destination, ByteBuffer.wrap(unhex(
                        BootImageRebuilder.hash(destination, 0, destination.position()))));
                destination.force(true);
                result = read(snapshot);
                if (!outputIdentity.matches(output) || destination.size() != encodedBytes ||
                        !result.originalImageSha256.equals(originalSha) ||
                        !result.snapshotSha256.equals(BootImageRebuilder.hash(destination, 0, encodedBytes)))
                    throw error("BOOT_RECOVERY_READBACK_MISMATCH");
                BootImageRebuilder.unchanged(source, identity, input, originalSha);
                BootImageRebuilder.cancelled();
            }
        } catch (IOException | RuntimeException | Error exception) {
            failure = exception; throw exception;
        } finally {
            cleanup(output, outputIdentity, created && failure != null, failure);
        }
        return result;
    }

    /** Reads v1 nonempty targets or v2 empty ramdisks; literals remain bounded file ranges. */
    public static Snapshot read(File snapshot) throws IOException {
        Path source = snapshot.toPath();
        BasicFileAttributes identity = BootImageRebuilder.input(source,
                HEADER_BYTES + SPAN_BYTES + SHA_BYTES, MAX_SNAPSHOT_BYTES, "BOOT_RECOVERY_SNAPSHOT_SIZE_LIMIT");
        try (FileChannel input = FileChannel.open(source, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            String snapshotSha = BootImageRebuilder.hash(input, 0, identity.size());
            String expected = hex(BootImageRebuilder.read(input, identity.size() - SHA_BYTES, SHA_BYTES));
            if (!expected.equals(BootImageRebuilder.hash(input, 0, identity.size() - SHA_BYTES)))
                throw error("BOOT_RECOVERY_CHECKSUM");
            ByteBuffer header = ByteBuffer.wrap(BootImageRebuilder.read(input, 0, HEADER_BYTES)).order(ByteOrder.LITTLE_ENDIAN);
            byte[] magic = new byte[MAGIC.length]; header.get(magic);
            int version = header.getInt();
            if (!Arrays.equals(magic, MAGIC) || (version != 1 && version != 2) || header.getInt() != HEADER_BYTES)
                throw error("BOOT_RECOVERY_FORMAT");
            long originalBytes = header.getLong();
            String originalSha = hashField(header);
            int targetId = header.getInt(), count = header.getInt();
            long targetBytes = header.getLong();
            String targetSha = hashField(header);
            boolean emptyRamdisk = version == 2;
            if (header.getLong() != 0 || originalBytes < 1632 || originalBytes > MAX_IMAGE_BYTES ||
                    targetId < 0 || targetId >= Component.values().length || targetBytes < 0 ||
                    (!emptyRamdisk && targetBytes == 0) ||
                    (emptyRamdisk && (targetId != Component.RAMDISK.ordinal() || targetBytes != 0 ||
                            !EMPTY_SHA256.equals(targetSha))) ||
                    targetBytes > originalBytes || count <= 0 || count > MAX_SPANS)
                throw error("BOOT_RECOVERY_HEADER");
            List<Span> spans = new ArrayList<>(count);
            boolean[] components = new boolean[6];
            long cursor = 0, position = HEADER_BYTES;
            boolean targetFound = emptyRamdisk;
            for (int index = 0; index < count; index++) {
                if (SPAN_BYTES > identity.size() - SHA_BYTES - position) throw error("BOOT_RECOVERY_RECORD_LENGTH");
                ByteBuffer record = ByteBuffer.wrap(BootImageRebuilder.read(input, position, SPAN_BYTES))
                        .order(ByteOrder.LITTLE_ENDIAN);
                int kind = record.getInt(), id = record.getInt();
                long offset = record.getLong(), length = record.getLong();
                String hash = hashField(record);
                position += SPAN_BYTES;
                if (offset != cursor || length <= 0 || length > originalBytes - offset ||
                        kind < LITERAL || kind > COMPONENT || (kind != COMPONENT && id != 0))
                    throw error("BOOT_RECOVERY_SPAN");
                Span span = new Span(kind, id, offset, length, hash);
                if (kind == COMPONENT) {
                    if (id < 1 || id > 5 || components[id]) throw error("BOOT_RECOVERY_COMPONENT_LAYOUT");
                    components[id] = true;
                    if (id == targetId + 1) {
                        if (length != targetBytes || !hash.equals(targetSha)) throw error("BOOT_RECOVERY_TARGET_MISMATCH");
                        targetFound = true;
                    }
                } else if (kind == LITERAL) {
                    long required = (long) (count - index - 1) * SPAN_BYTES + SHA_BYTES;
                    if (required > identity.size() - position || length > identity.size() - position - required)
                        throw error("BOOT_RECOVERY_RECORD_LENGTH");
                    span.dataOffset = position;
                    if (!hash.equals(BootImageRebuilder.hash(input, position, length))) throw error("BOOT_RECOVERY_CHECKSUM");
                    position += length;
                } else if (!hash.equals(hex(ZERO_SHA))) throw error("BOOT_RECOVERY_RESERVED");
                cursor += length; spans.add(span);
            }
            if (!targetFound || cursor != originalBytes || position != identity.size() - SHA_BYTES)
                throw error("BOOT_RECOVERY_RECORD_LENGTH");
            BootImageRebuilder.unchanged(source, identity, input, snapshotSha);
            return new Snapshot(originalBytes, originalSha, Component.values()[targetId], targetBytes,
                    targetSha, identity.size(), snapshotSha, spans);
        }
    }

    /** Restores original offsets, header, metadata and padding without normalizing any bytes. */
    public static RestoreReport restore(File current, File originalTarget, File snapshot, File output) throws IOException {
        Snapshot saved = read(snapshot);
        Path currentPath = current.toPath(), targetPath = originalTarget.toPath(), snapshotPath = snapshot.toPath();
        Path outputPath = output.toPath();
        BasicFileAttributes currentIdentity = BootImageRebuilder.input(currentPath, 1632, MAX_IMAGE_BYTES,
                "BOOT_RECOVERY_IMAGE_SIZE_LIMIT");
        BasicFileAttributes targetIdentity = BootImageRebuilder.input(targetPath, saved.targetComponentBytes,
                saved.targetComponentBytes, "BOOT_RECOVERY_TARGET_MISMATCH");
        BasicFileAttributes snapshotIdentity = BootImageRebuilder.input(snapshotPath, saved.snapshotBytes,
                saved.snapshotBytes, "BOOT_RECOVERY_SNAPSHOT_SIZE_LIMIT");
        BootImageRebuilder.OutputIdentity outputIdentity = null;
        boolean created = false;
        Throwable failure = null;
        RestoreReport result;
        try (FileChannel present = FileChannel.open(currentPath, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
             FileChannel target = FileChannel.open(targetPath, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
             FileChannel recipe = FileChannel.open(snapshotPath, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            BootImageInspector.Report layout = BootImageInspector.inspect(current);
            String currentSha = BootImageRebuilder.hash(present, 0, currentIdentity.size());
            if (layout.fileSize != currentIdentity.size() || !layout.sha256.equals(currentSha) ||
                    !saved.targetComponentSha256.equals(BootImageRebuilder.hash(target, 0, targetIdentity.size())) ||
                    !saved.snapshotSha256.equals(BootImageRebuilder.hash(recipe, 0, snapshotIdentity.size())))
                throw error("BOOT_RECOVERY_INPUT_CHANGED");
            for (Span span : saved.spans) if (span.kind == COMPONENT && span.component != saved.target.ordinal() + 1) {
                long[] region = component(layout, span.component);
                if (region[1] != span.length || !span.sha256.equals(BootImageRebuilder.hash(present, region[0], region[1])))
                    throw error("BOOT_RECOVERY_COMPONENT_CHANGED");
            }
            try (FileChannel destination = FileChannel.open(outputPath, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                created = true; outputIdentity = BootImageRebuilder.OutputIdentity.capture(outputPath, anchor(outputPath));
                for (Span span : saved.spans) {
                    if (destination.position() != span.offset) throw error("BOOT_RECOVERY_SPAN");
                    if (span.kind == ZERO) BootImageRebuilder.zeros(destination, span.length);
                    else if (span.kind == LITERAL) BootImageRebuilder.copy(recipe, span.dataOffset, span.length, destination);
                    else if (span.component == saved.target.ordinal() + 1) BootImageRebuilder.copy(target, 0, span.length, destination);
                    else BootImageRebuilder.copy(present, component(layout, span.component)[0], span.length, destination);
                }
                destination.force(true);
                if (destination.size() != saved.originalImageBytes ||
                        !saved.originalImageSha256.equals(BootImageRebuilder.hash(destination, 0, destination.size())))
                    throw error("BOOT_RECOVERY_READBACK_MISMATCH");
                BootImageInspector.Report restored = BootImageInspector.inspect(output);
                if (!outputIdentity.matches(outputPath) || restored.fileSize != saved.originalImageBytes ||
                        !restored.sha256.equals(saved.originalImageSha256)) throw error("BOOT_RECOVERY_READBACK_MISMATCH");
                if (saved.targetComponentBytes == 0 && restored.ramdiskSize != 0)
                    throw error("BOOT_RECOVERY_TARGET_MISMATCH");
                for (Span span : saved.spans) if (span.kind == COMPONENT) {
                    long[] region = component(restored, span.component);
                    if (region[0] != span.offset || region[1] != span.length)
                        throw error("BOOT_RECOVERY_COMPONENT_LAYOUT");
                }
                BootImageRebuilder.unchanged(currentPath, currentIdentity, present, currentSha);
                BootImageRebuilder.unchanged(targetPath, targetIdentity, target, saved.targetComponentSha256);
                BootImageRebuilder.unchanged(snapshotPath, snapshotIdentity, recipe, saved.snapshotSha256);
                BootImageRebuilder.cancelled();
                result = new RestoreReport(restored, saved);
            }
        } catch (IOException | RuntimeException | Error exception) {
            failure = exception; throw exception;
        } finally {
            cleanup(outputPath, outputIdentity, created && failure != null, failure);
        }
        return result;
    }

    private static void gap(FileChannel source, List<Span> spans, long start, long end) throws IOException {
        for (long position = start; position < end;) {
            int count = (int) Math.min(64 * 1024, end - position);
            byte[] bytes = BootImageRebuilder.read(source, position, count);
            for (int at = 0; at < count;) {
                long offset = position + at;
                int length = Math.min(count - at, 4096 - (int) (offset % 4096));
                boolean zero = true;
                for (int index = at; index < at + length; index++)
                    if (bytes[index] != 0) { zero = false; break; }
                int kind = zero ? ZERO : LITERAL;
                Span previous = spans.isEmpty() ? null : spans.get(spans.size() - 1);
                if (previous != null && previous.kind == kind && previous.component == 0 &&
                        previous.offset + previous.length == offset) previous.length += length;
                else spans.add(new Span(kind, 0, offset, length, null));
                at += length;
            }
            position += count;
        }
    }

    private static long[] component(BootImageInspector.Report layout, int id) throws IOException {
        switch (id) {
            case 1: return new long[]{layout.kernelOffset, layout.kernelSize};
            case 2: return new long[]{layout.ramdiskOffset, layout.ramdiskSize};
            case 3: return new long[]{layout.secondOffset, layout.secondSize};
            case 4: return new long[]{layout.recoveryDtboOffset, layout.recoveryDtboSize};
            case 5: return new long[]{layout.dtbOffset, layout.dtbSize};
            default: throw error("BOOT_RECOVERY_COMPONENT_LAYOUT");
        }
    }

    private static Path anchor(Path output) {
        return output.toAbsolutePath().getParent().resolve(".maplesu-recovery-" + UUID.randomUUID() + ".pending");
    }

    private static void cleanup(Path output, BootImageRebuilder.OutputIdentity identity, boolean remove,
                                Throwable primary) throws IOException {
        BootImageRebuilder.cleanup(() -> {
            if (remove && identity != null && identity.matches(output)) Files.deleteIfExists(output);
        }, () -> {
            if (identity != null && identity.anchor != null) Files.deleteIfExists(identity.anchor);
        }, primary);
    }

    private static ByteBuffer buffer(int bytes) { return ByteBuffer.allocate(bytes).order(ByteOrder.LITTLE_ENDIAN); }
    private static String hashField(ByteBuffer input) { byte[] bytes = new byte[SHA_BYTES]; input.get(bytes); return hex(bytes); }
    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) result.append(Character.forDigit((value >>> 4) & 15, 16)).append(Character.forDigit(value & 15, 16));
        return result.toString();
    }
    private static byte[] unhex(String value) {
        byte[] bytes = new byte[value.length() / 2];
        for (int index = 0; index < bytes.length; index++) bytes[index] = (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
        return bytes;
    }
    private static IOException error(String code) { return new IOException(code); }
}
