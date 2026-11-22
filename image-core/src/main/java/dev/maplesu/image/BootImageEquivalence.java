package dev.maplesu.image;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * First-class "only the declared bytes may differ" contract for boot image rebuilds.
 *
 * <p>A rebuild is proven equivalent when every byte that differs between the source and the output
 * falls inside a range the rebuilder declared it would write. That turns the previously implicit
 * assumption ("the writer only touches kernel_size, the kernel block, dropped signatures/GKI
 * certificates, the relocated vbmeta and two footer fields") into an executable assertion, which is
 * the only portable safety net available for images that have no golden output digest.
 *
 * <p>Two independent halves:
 * <ul>
 *   <li>{@link Journal} — the claim, produced by {@link BootImageRebuilder};</li>
 *   <li>{@link #diff} / {@link #verify} — the measurement, which never trusts the claim.</li>
 * </ul>
 *
 * <p>Header bytes get a second, stricter rule: a differing byte below the header page must be
 * covered by a {@code HEADER_FIELD} entry whose offset is on the AOSP field whitelist for that
 * header version. A writer that silently edits another header field therefore fails even though the
 * range was declared.
 */
public final class BootImageEquivalence {
    public static final String HEADER_FIELD = "HEADER_FIELD";
    public static final String KERNEL = "KERNEL";
    public static final String COMPONENT = "COMPONENT";
    /** Tail rewritten because a component changed size: honest but not a byte-precise claim. */
    public static final String COMPONENT_RELOCATED = "COMPONENT_RELOCATED";
    public static final String DROPPED_SIGNATURE = "DROPPED_SIGNATURE";
    public static final String DROPPED_GKI = "DROPPED_GKI";
    public static final String RECOVERY_RECORD = "RECOVERY_RECORD";
    public static final String AVB_VBMETA = "AVB_VBMETA_RELOCATE";
    public static final String AVB_FOOTER = "AVB_FOOTER_FIELD";
    public static final String TRAILING_ZERO = "TRAILING_ZERO";
    public static final String TRAILING_TRUNCATED = "TRAILING_TRUNCATED";

    /** Ranges merged when adjacent; keeps the JSON bounded on byte-shifted images. */
    private static final int MAX_RANGES = 4096;

    private BootImageEquivalence() {}

    /** One declared write. Offsets are file offsets in the output image. */
    public static final class Entry {
        public final String kind;
        public final long offset, length;

        Entry(String kind, long offset, long length) {
            this.kind = kind; this.offset = offset; this.length = length;
        }

        boolean covers(long start, long end) {
            return start >= offset && end <= offset + length;
        }
    }

    /** The rebuilder's claim: what it wrote, and the container shape it wrote it into. */
    public static final class Journal {
        private final List<Entry> entries = new ArrayList<>();
        private long outputSize = -1;
        private int version = -1, headerSize = -1, pageSize = -1;

        public List<Entry> entries() { return entries; }

        void shape(int version, int headerSize, int pageSize) {
            this.version = version; this.headerSize = headerSize; this.pageSize = pageSize;
        }

        void outputSize(long size) { outputSize = size; }

        public long outputSize() { return outputSize; }

        public Journal add(String kind, long offset, long length) {
            if (length > 0 && offset >= 0) entries.add(new Entry(kind, offset, length));
            return this;
        }

        /** True when every declared range is byte-precise (no size-changing relocation). */
        public boolean strict() {
            for (Entry entry : entries) {
                if (COMPONENT_RELOCATED.equals(entry.kind) || TRAILING_TRUNCATED.equals(entry.kind)) return false;
            }
            return true;
        }

        public long declaredBytes() { return unionLengths(); }

        /** Header offsets AOSP writes for this version; every other header byte must match. */
        boolean allowedHeaderField(long offset, long length) {
            if (offset == 8 && length <= 4) return true;                       // kernel_size
            if (version < 3 && offset == 16 && length <= 4) return true;       // ramdisk_size
            if (version >= 3 && offset == 12 && length <= 4) return true;      // ramdisk_size
            if (version == 4 && offset == 1580 && length <= 4) return true;     // signature_size
            if ((version == 1 || version == 2) && offset == 1636 && length <= 8) return true;  // recovery_dtbo
            if (version < 3 && offset == 576 && length <= 32) return true;      // SHA-1 id
            return false;
        }

        /** A measured difference can span adjacent or overlapping declared writes. */
        boolean covers(long start, long end) {
            long cursor = start;
            while (cursor < end) {
                long next = cursor;
                for (Entry entry : entries) {
                    long entryEnd = entry.offset + entry.length;
                    if (entry.offset <= cursor && entryEnd > next) next = entryEnd;
                }
                if (next == cursor) return false;
                cursor = next;
            }
            return true;
        }

        boolean coversHeaderField(long start, long end) {
            for (Entry entry : entries) {
                if (HEADER_FIELD.equals(entry.kind) && entry.covers(start, end)) return true;
            }
            return false;
        }

        long unionLengths() {
            List<long[]> ranges = new ArrayList<>();
            for (Entry entry : entries) ranges.add(new long[]{entry.offset, entry.offset + entry.length});
            return BootImageEquivalence.unionLength(ranges);
        }

        public String toJson() {
            StringBuilder json = new StringBuilder(64 + entries.size() * 48);
            json.append("{\"schemaVersion\":1,\"headerVersion\":").append(version)
                    .append(",\"headerSize\":").append(headerSize)
                    .append(",\"pageSize\":").append(pageSize)
                    .append(",\"outputSize\":").append(outputSize)
                    .append(",\"strict\":").append(strict())
                    .append(",\"declaredBytes\":").append(declaredBytes())
                    .append(",\"entries\":[");
            for (int index = 0; index < entries.size(); index++) {
                Entry entry = entries.get(index);
                if (index > 0) json.append(',');
                json.append(String.format(Locale.ROOT, "{\"kind\":\"%s\",\"offset\":%d,\"length\":%d}",
                        entry.kind, entry.offset, entry.length));
            }
            return json.append("]}").toString();
        }
    }

    /** A contiguous differing range. */
    public static final class Range {
        public final long offset, length;

        Range(long offset, long length) { this.offset = offset; this.length = length; }

        public String toJson() {
            return String.format(Locale.ROOT, "{\"offset\":%d,\"length\":%d}", offset, length);
        }
    }

    /** Measured differences between two files. */
    public static final class Diff {
        public final long changedBytes, sourceSize, outputSize;
        public final boolean truncated;
        public final List<Range> ranges;

        Diff(long changedBytes, long sourceSize, long outputSize, boolean truncated, List<Range> ranges) {
            this.changedBytes = changedBytes; this.sourceSize = sourceSize;
            this.outputSize = outputSize; this.truncated = truncated; this.ranges = ranges;
        }

        public String toJson() {
            StringBuilder json = new StringBuilder(128 + ranges.size() * 40);
            json.append(String.format(Locale.ROOT,
                    "{\"schemaVersion\":1,\"operation\":\"BOOT_IMAGE_DIFF\",\"sourceSize\":%d,"
                            + "\"outputSize\":%d,\"changedBytes\":%d,\"rangesTruncated\":%s,\"ranges\":[",
                    sourceSize, outputSize, changedBytes, truncated));
            for (int index = 0; index < ranges.size(); index++) {
                if (index > 0) json.append(',');
                json.append(ranges.get(index).toJson());
            }
            return json.append("]}").toString();
        }
    }

    /** Result of {@link #verify}. {@code code} is empty on success. */
    public static final class Verification {
        public final String code;
        public final long changedBytes, declaredBytes, uncoveredBytes;
        public final List<Range> uncovered;
        public final Diff diff;

        Verification(String code, long changedBytes, long declaredBytes, long uncoveredBytes,
                     List<Range> uncovered, Diff diff) {
            this.code = code; this.changedBytes = changedBytes; this.declaredBytes = declaredBytes;
            this.uncoveredBytes = uncoveredBytes; this.uncovered = uncovered; this.diff = diff;
        }

        public boolean ok() { return code.isEmpty(); }

        public String toJson() {
            StringBuilder json = new StringBuilder(160);
            json.append(String.format(Locale.ROOT,
                    "{\"schemaVersion\":1,\"operation\":\"BOOT_IMAGE_EQUIVALENCE\",\"verdict\":\"%s\","
                            + "\"code\":\"%s\",\"changedBytes\":%d,\"declaredBytes\":%d,\"uncoveredBytes\":%d,"
                            + "\"uncovered\":[",
                    ok() ? "PASS" : "FAIL", code, changedBytes, declaredBytes, uncoveredBytes));
            for (int index = 0; index < uncovered.size(); index++) {
                if (index > 0) json.append(',');
                json.append(uncovered.get(index).toJson());
            }
            return json.append("],\"diff\":").append(diff.toJson()).append('}').toString();
        }
    }

    /** Byte-precise diff of two images; merges adjacent ranges and caps the reported list. */
    public static Diff diff(File source, File output) throws IOException {
        return scan(source, output, null);
    }

    private interface RangeVisitor {
        void visit(long start, long end);
    }

    /** Visits every difference even after the public report reaches its size limit. */
    private static Diff scan(File source, File output, RangeVisitor visitor) throws IOException {
        long sourceSize = source.length(), outputSize = output.length();
        long changed = 0;
        boolean truncated = false;
        List<Range> ranges = new ArrayList<>();
        try (RandomAccessFile left = new RandomAccessFile(source, "r");
             RandomAccessFile right = new RandomAccessFile(output, "r")) {
            byte[] a = new byte[1 << 16], b = new byte[1 << 16];
            long position = 0, common = Math.min(sourceSize, outputSize);
            long runStart = -1, runEnd = -1;
            while (position < common) {
                if (Thread.currentThread().isInterrupted()) throw new IOException("CANCELLED");
                int length = (int) Math.min(a.length, common - position);
                left.seek(position);
                left.readFully(a, 0, length);
                right.seek(position);
                right.readFully(b, 0, length);
                for (int index = 0; index < length; index++) {
                    if (a[index] == b[index]) continue;
                    changed++;
                    long at = position + index;
                    if (runStart >= 0 && at == runEnd) { runEnd = at + 1; continue; }
                    if (runStart >= 0) truncated |= add(ranges, runStart, runEnd, visitor);
                    runStart = at; runEnd = at + 1;
                }
                position += length;
            }
            if (runStart >= 0) truncated |= add(ranges, runStart, runEnd, visitor);
        }
        if (sourceSize != outputSize) {
            long at = Math.min(sourceSize, outputSize), to = Math.max(sourceSize, outputSize);
            truncated |= add(ranges, at, to, visitor);
        }
        return new Diff(changed, sourceSize, outputSize, truncated, ranges);
    }

    /**
     * @return true when the range list hit {@link #MAX_RANGES} and was truncated
     */
    private static boolean add(List<Range> ranges, long start, long end, RangeVisitor visitor) {
        if (visitor != null) visitor.visit(start, end);
        if (ranges.size() >= MAX_RANGES) return true;
        ranges.add(new Range(start, end - start));
        return false;
    }

    /**
     * Asserts {@code diff(source, output) ⊆ journal} and that header changes stay on the AOSP field
     * whitelist. Never writes files.
     */
    public static Verification verify(File source, File output, Journal journal) throws IOException {
        Coverage coverage = new Coverage(journal);
        Diff diff = scan(source, output, coverage::check);
        if (journal.outputSize() >= 0 && diff.outputSize != journal.outputSize()) {
            return new Verification("OUTPUT_SIZE_MISMATCH", diff.changedBytes, journal.declaredBytes(),
                    diff.changedBytes, new ArrayList<>(diff.ranges), diff);
        }
        return new Verification(coverage.code, diff.changedBytes, journal.declaredBytes(), coverage.uncoveredBytes,
                coverage.uncovered, diff);
    }

    private static final class Coverage {
        final Journal journal;
        final List<Range> uncovered = new ArrayList<>();
        long uncoveredBytes;
        String code = "";

        Coverage(Journal journal) { this.journal = journal; }

        void check(long start, long end) {
            if (!journal.covers(start, end)) {
                add(uncovered, start, end, null);
                uncoveredBytes += end - start;
                if (code.isEmpty()) code = "REBUILD_DIFF_OUTSIDE_DECLARED";
                return;
            }
            if (start < journal.pageSize && !journal.coversHeaderField(start, end)) {
                if (code.isEmpty()) code = "REBUILD_HEADER_FIELD_UNDECLARED";
                add(uncovered, start, end, null);
                uncoveredBytes += end - start;
                return;
            }
            if (start < journal.pageSize) {
                for (Entry entry : journal.entries()) {
                    if (!HEADER_FIELD.equals(entry.kind) || !entry.covers(start, end)) continue;
                    if (!journal.allowedHeaderField(entry.offset, entry.length)) {
                        if (code.isEmpty()) code = "REBUILD_HEADER_FIELD_NOT_ALLOWED";
                        break;
                    }
                }
            }
        }
    }

    static long unionLength(List<long[]> ranges) {
        if (ranges.isEmpty()) return 0;
        ranges.sort((left, right) -> Long.compare(left[0], right[0]));
        long total = 0, start = ranges.get(0)[0], end = ranges.get(0)[1];
        for (int index = 1; index < ranges.size(); index++) {
            long[] range = ranges.get(index);
            if (range[0] > end) { total += end - start; start = range[0]; end = range[1]; }
            else if (range[1] > end) end = range[1];
        }
        return total + (end - start);
    }
}
