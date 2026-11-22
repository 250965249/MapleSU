package dev.maplesu.image;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Read-only inspection of an Android ramdisk component: a CPIO "newc" archive
 * (magic {@code 070701}/\u200b{@code 070702}) that may be stored raw, gzip-compressed or
 * LZ4-legacy, LZ4-frame, XZ or Zstandard compressed, either standalone or inside an AOSP boot v0-v4 container.
 *
 * <p>This class is the host-testable assertion layer for the KSU LKM candidate.
 * It never executes input,
 * never trusts producer metadata and never requires a kernel component, so an
 * init_boot image can be validated directly. Malformed input is reported as a
 * structured problem list; it does not throw and cannot allocate from declared
 * CPIO sizes beyond the caller-supplied byte budget. Security-relevant anomalies
 * (truncation, unsafe paths, trailing garbage, repeated marker entries) are fatal
 * {@code problems}; benign real-world quirks, such as the repeated directory entry
 * that AOSP mkbootfs emits, are non-fatal {@code findings}.
 *
 * <p>Form vocabulary follows the four frozen ksud {@code boot-info ramdisk-state}
 * words, adapted to the MapleSU layout decision (kernelsu.ko instead of sevenk.ko,
 * {@code maplesu_id} marker instead of the 7K entry):
 * {@code ours} = kernelsu.ko + init.real + maplesu_id, {@code compatible} =
 * kernelsu.ko + init.real without the marker, {@code foreign} = another SU marker,
 * {@code stock} = no marker at all. An unreadable archive is {@code unknown}; it is
 * never reported as stock.
 *
 * <p>All byte offsets are offsets in the decoded CPIO archive unless stated otherwise.
 */
public final class RamdiskInspector {
    /** Default number of CPIO entries accepted before the archive is rejected. */
    public static final int DEFAULT_MAX_ENTRIES = 16384;
    /** Default decoded-CPIO byte budget (also caps the encoded component). */
    public static final long DEFAULT_MAX_BYTES = 128L * 1024 * 1024;
    /** Largest complete boot image accepted by the file entry point. */
    public static final long MAX_IMAGE_BYTES = 512L * 1024 * 1024;
    /** Largest ramdisk component accepted by the byte entry points. */
    public static final long MAX_COMPONENT_BYTES = 128L * 1024 * 1024;

    private static final int MAX_ENTRIES_LIMIT = 1000000;
    private static final int MAX_PROBLEMS = 64;
    private static final int MAX_KSU_PATHS = 64;
    private static final int MAX_DETAIL_PATH = 128;
    private static final int CPIO_HEADER_BYTES = 110;
    private static final int GZIP_HEADER_BYTES = 10;
    private static final int GZIP_TRAILER_BYTES = 8;

    /** Container layout of AOSP boot header versions 0-4; index is the header version. */
    private static final int[] MINIMUM_HEADER_BYTES = {1632, 1648, 1660, 1580, 1584};

    /** Ramdisk ownership form; mirrors the frozen ksud four-word vocabulary plus unknown. */
    public enum Form { KSU_LKM_OURS, KSU_LKM_COMPATIBLE, FOREIGN_ARTIFACT, STOCK, UNKNOWN }

    private RamdiskInspector() {}

    /** One CPIO entry. {@code offset}/{@code sha256} always describe the file data bytes. */
    public static final class Entry {
        public final String path;
        public final int mode;
        public final long size;
        public final long offset;
        public final String sha256;
        final int headerOffset, endOffset;
        final long uid, gid, links;
        final boolean crc;

        private Entry(String path, int mode, long size, long offset, String sha256,
                      int headerOffset, int endOffset, long uid, long gid, long links, boolean crc) {
            this.path = path;
            this.mode = mode;
            this.size = size;
            this.offset = offset;
            this.sha256 = sha256;
            this.headerOffset = headerOffset;
            this.endOffset = endOffset;
            this.uid = uid; this.gid = gid; this.links = links; this.crc = crc;
        }

        public boolean isRegularFile() { return (mode & 0170000) == 0100000; }

        public boolean isDirectory() { return (mode & 0170000) == 0040000; }

        public boolean isSymbolicLink() { return (mode & 0170000) == 0120000; }

        /** Permission bits only (no file type). */
        public int permissions() { return mode & 07777; }

        public String toJson() {
            StringBuilder out = new StringBuilder(160);
            out.append("{\"path\":");
            appendJsonString(out, path);
            out.append(",\"mode\":").append(mode);
            out.append(",\"fileType\":").append(mode & 0170000);
            out.append(",\"permissions\":").append(mode & 07777);
            out.append(",\"size\":").append(size);
            out.append(",\"offset\":").append(offset);
            out.append(",\"sha256\":");
            appendJsonString(out, sha256);
            return out.append('}').toString();
        }
    }

    /** One structural finding. A report is malformed iff {@code problems} is not empty. */
    public static final class Problem {
        public final String code;
        public final String detail;
        public final long offset;

        private Problem(String code, String detail, long offset) {
            this.code = code;
            this.detail = detail;
            this.offset = offset;
        }

        public String toJson() {
            StringBuilder out = new StringBuilder(96);
            out.append("{\"code\":");
            appendJsonString(out, code);
            out.append(",\"detail\":");
            appendJsonString(out, detail);
            return out.append(",\"offset\":").append(offset).append('}').toString();
        }
    }

    /** Structured assertion outcome. Codes are stable machine identifiers, never prose. */
    public static final class Verdict {
        public final boolean ok;
        public final String code;
        public final List<String> violations;
        public final String detail;

        private Verdict(boolean ok, String code, List<String> violations, String detail) {
            this.ok = ok;
            this.code = code;
            this.violations = Collections.unmodifiableList(new ArrayList<>(violations));
            this.detail = detail;
        }

        public String toJson() {
            StringBuilder out = new StringBuilder(128);
            out.append("{\"ok\":").append(ok).append(",\"code\":");
            appendJsonString(out, code);
            out.append(",\"violations\":[");
            for (int index = 0; index < violations.size(); index++) {
                if (index > 0) out.append(',');
                appendJsonString(out, violations.get(index));
            }
            out.append("],\"detail\":");
            appendJsonString(out, detail);
            return out.append('}').toString();
        }

        @Override
        public String toString() { return toJson(); }
    }

    /** Complete read-only scan result. Constructed only through the static entry points. */
    public static final class Report {
        public final String sourceKind;
        public final long fileSize;
        public final int headerVersion;
        public final String compression;
        public final long ramdiskOffset;
        public final long ramdiskSize;
        public final List<Entry> entries;
        public final boolean hasInit;
        public final boolean hasInitReal;
        public final boolean hasKernelsuKo;
        public final boolean hasKsuConfig;
        public final boolean hasMaplesuId;
        public final boolean hasKsud;
        public final boolean hasSevenkKo;
        public final boolean hasMagiskMarker;
        public final boolean hasDataAdbKsuPath;
        public final List<String> ksuRelatedPaths;
        /** Fatal structural problems; non-empty means the archive must be rejected. */
        public final List<Problem> problems;
        /** Non-fatal observations (for example a legitimate repeated mkbootfs directory entry). */
        public final List<Problem> findings;
        public final String errorCode;
        public final boolean malformed;
        public final String sha256;
        public final String decompressedSha256;
        public final long decompressedSize;
        public final boolean trailerSeen;
        public final long trailingBytes;
        final int trailerOffset;
        final boolean trailerCrc;
        private final Form form;

        private Report(Builder builder) {
            sourceKind = builder.sourceKind;
            fileSize = builder.fileSize;
            headerVersion = builder.headerVersion;
            compression = builder.compression;
            ramdiskOffset = builder.ramdiskOffset;
            ramdiskSize = builder.ramdiskSize;
            entries = Collections.unmodifiableList(new ArrayList<>(builder.entries));
            problems = Collections.unmodifiableList(new ArrayList<>(builder.problems));
            findings = Collections.unmodifiableList(new ArrayList<>(builder.findings));
            errorCode = problems.isEmpty() ? null : problems.get(0).code;
            malformed = !problems.isEmpty();
            sha256 = builder.sha256;
            decompressedSha256 = builder.decompressedSha256;
            decompressedSize = builder.decompressedSize;
            trailerSeen = builder.trailerSeen;
            trailingBytes = builder.trailingBytes;
            trailerOffset = builder.trailerOffset;
            trailerCrc = builder.trailerCrc;
            boolean init = false, initReal = false, kernelsu = false, ksuConfig = false, maplesu = false;
            boolean ksud = false, sevenk = false, magisk = false, dataAdbKsu = false;
            List<String> related = new ArrayList<>();
            for (Entry entry : entries) {
                String path = normalize(entry.path);
                if (path.equals("init")) init = true;
                if (path.equals("init.real")) initReal = true;
                if (path.equals("kernelsu.ko")) kernelsu = true;
                if (path.equals("ksu_config")) ksuConfig = true;
                if (path.equals("maplesu_id")) maplesu = true;
                if (path.equals("sevenk.ko")) sevenk = true;
                if (path.equals("ksud") || path.endsWith("/ksud")) ksud = true;
                if (path.contains("data/adb/ksu")) dataAdbKsu = true;
                if (magiskMarker(path)) magisk = true;
                if (path.contains("ksu") || path.equals("maplesu_id") || path.equals("sevenk.ko")) {
                    if (related.size() < MAX_KSU_PATHS) related.add(entry.path);
                }
            }
            hasInit = init;
            hasInitReal = initReal;
            hasKernelsuKo = kernelsu;
            hasKsuConfig = ksuConfig;
            hasMaplesuId = maplesu;
            hasKsud = ksud;
            hasSevenkKo = sevenk;
            hasMagiskMarker = magisk;
            hasDataAdbKsuPath = dataAdbKsu;
            ksuRelatedPaths = Collections.unmodifiableList(related);
            form = classifyForm();
        }

        private Form classifyForm() {
            if (malformed) return Form.UNKNOWN;
            if (hasSevenkKo) return Form.FOREIGN_ARTIFACT;
            if (hasKernelsuKo && hasInitReal) {
                return hasMaplesuId ? Form.KSU_LKM_OURS : Form.KSU_LKM_COMPATIBLE;
            }
            if (hasKernelsuKo || hasInitReal || hasKsuConfig || hasKsud || hasDataAdbKsuPath
                    || hasMagiskMarker || !ksuRelatedPaths.isEmpty()) {
                return Form.FOREIGN_ARTIFACT;
            }
            return Form.STOCK;
        }

        public Form form() { return form; }

        /** First entry with a matching normalize()d path, or null. */
        public Entry entry(String path) {
            String normalized = normalize(path);
            for (Entry entry : entries) {
                if (normalize(entry.path).equals(normalized)) return entry;
            }
            return null;
        }

        public boolean has(String path) { return entry(path) != null; }

        /**
         * Required KSU LKM layout:
         * init (new ksuinit), init.real, kernelsu.ko and a parseable ksu_config.
         * The maplesu_id ownership marker is intentionally not required here (it is
         * added by the branch producer and asserted by {@link #requireOwnedKsuLkmForm()}).
         */
        public Verdict requireKsuLkmForm() {
            if (malformed) return malformedVerdict("requireKsuLkmForm");
            if (hasSevenkKo) {
                return new Verdict(false, "FOREIGN_ARTIFACT",
                        Collections.singletonList("sevenk.ko"), "sevenk.ko must not exist");
            }
            List<String> missing = new ArrayList<>();
            if (!hasKernelsuKo) missing.add("MISSING_KERNELSU_KO");
            if (!hasInitReal) missing.add("MISSING_INIT_REAL");
            if (!hasInit) missing.add("MISSING_INIT");
            if (!hasKsuConfig) missing.add("MISSING_KSU_CONFIG");
            if (!missing.isEmpty()) {
                List<String> violations = new ArrayList<>();
                for (String code : missing) violations.add(entryNameFor(code));
                return new Verdict(false, missing.get(0), violations,
                        joinCodes(missing, "KSU_LKM_ENTRIES_MISSING"));
            }
            return new Verdict(true, "OK", Collections.<String>emptyList(), "");
        }

        /** KSU LKM form plus the 0-byte maplesu_id ownership marker (branch-built images). */
        public Verdict requireOwnedKsuLkmForm() {
            Verdict base = requireKsuLkmForm();
            if (!base.ok) return base;
            if (!hasMaplesuId) {
                return new Verdict(false, "MISSING_MAPLESU_ID",
                        Collections.singletonList("maplesu_id"), "maplesu_id ownership marker is absent");
            }
            return new Verdict(true, "OK", Collections.<String>emptyList(), "");
        }

        /** Stock form: no KSU/MapleSU residue in the ramdisk. */
        public Verdict requireStockForm() {
            if (malformed) return malformedVerdict("requireStockForm");
            List<String> residue = new ArrayList<>();
            for (Entry entry : entries) {
                String path = normalize(entry.path);
                boolean ksuResidue = path.equals("init.real") || path.equals("kernelsu.ko")
                        || path.equals("ksu_config") || path.equals("maplesu_id")
                        || path.equals("sevenk.ko") || path.equals("ksud") || path.endsWith("/ksud")
                        || path.contains("data/adb/ksu") || path.contains("ksu");
                if (ksuResidue && !residue.contains(entry.path) && residue.size() < MAX_KSU_PATHS) {
                    residue.add(entry.path);
                }
            }
            if (!residue.isEmpty()) {
                return new Verdict(false, "STOCK_HAS_KSU_RESIDUE", residue, "KSU residue in ramdisk");
            }
            return new Verdict(true, "OK", Collections.<String>emptyList(), "");
        }

        /** Strict structural gate: any decoded problem rejects the archive. */
        public Verdict rejectMalformed() {
            if (!malformed) return new Verdict(true, "OK", Collections.<String>emptyList(), "");
            Set<String> codes = new HashSet<>();
            List<String> violations = new ArrayList<>();
            for (Problem problem : problems) {
                if (codes.add(problem.code) && violations.size() < MAX_PROBLEMS) violations.add(problem.code);
            }
            return new Verdict(false, errorCode, violations, "RAMDISK_MALFORMED");
        }

        private Verdict malformedVerdict(String operation) {
            List<String> codes = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            for (Problem problem : problems) {
                if (seen.add(problem.code) && codes.size() < MAX_PROBLEMS) codes.add(problem.code);
            }
            return new Verdict(false, errorCode, codes, operation + ":RAMDISK_MALFORMED");
        }

        public String toJson() {
            StringBuilder out = new StringBuilder(2048);
            out.append("{\"schemaVersion\":1,\"operation\":\"INSPECT_RAMDISK\",\"sourceKind\":");
            appendJsonString(out, sourceKind);
            out.append(",\"fileSize\":").append(fileSize);
            out.append(",\"headerVersion\":").append(headerVersion);
            out.append(",\"compression\":");
            appendJsonString(out, compression);
            out.append(",\"ramdiskOffset\":").append(ramdiskOffset);
            out.append(",\"ramdiskSize\":").append(ramdiskSize);
            out.append(",\"sha256\":");
            appendJsonString(out, sha256);
            out.append(",\"decompressedSha256\":");
            appendJsonString(out, decompressedSha256);
            out.append(",\"decompressedSize\":").append(decompressedSize);
            out.append(",\"trailerSeen\":").append(trailerSeen);
            out.append(",\"trailingBytes\":").append(trailingBytes);
            out.append(",\"malformed\":").append(malformed);
            out.append(",\"errorCode\":");
            if (errorCode == null) out.append("null");
            else appendJsonString(out, errorCode);
            out.append(",\"form\":");
            appendJsonString(out, form.name());
            out.append(",\"hasInit\":").append(hasInit);
            out.append(",\"hasInitReal\":").append(hasInitReal);
            out.append(",\"hasKernelsuKo\":").append(hasKernelsuKo);
            out.append(",\"hasKsuConfig\":").append(hasKsuConfig);
            out.append(",\"hasMaplesuId\":").append(hasMaplesuId);
            out.append(",\"hasKsud\":").append(hasKsud);
            out.append(",\"hasSevenkKo\":").append(hasSevenkKo);
            out.append(",\"hasMagiskMarker\":").append(hasMagiskMarker);
            out.append(",\"hasDataAdbKsuPath\":").append(hasDataAdbKsuPath);
            out.append(",\"ksuRelatedPaths\":[");
            for (int index = 0; index < ksuRelatedPaths.size(); index++) {
                if (index > 0) out.append(',');
                appendJsonString(out, ksuRelatedPaths.get(index));
            }
            out.append("],\"entryCount\":").append(entries.size());
            out.append(",\"entries\":[");
            for (int index = 0; index < entries.size(); index++) {
                if (index > 0) out.append(',');
                out.append(entries.get(index).toJson());
            }
            out.append("],\"problems\":[");
            for (int index = 0; index < problems.size(); index++) {
                if (index > 0) out.append(',');
                out.append(problems.get(index).toJson());
            }
            out.append("],\"findings\":[");
            for (int index = 0; index < findings.size(); index++) {
                if (index > 0) out.append(',');
                out.append(findings.get(index).toJson());
            }
            return out.append("]}").toString();
        }

        @Override
        public String toString() { return toJson(); }
    }

    /** Immutable decoded container location used by the byte[] entry point. */
    private static final class ContainerLocation {
        String errorCode;
        int headerVersion = -1;
        long ramdiskOffset;
        long ramdiskSize;
    }

    /** Accumulates fields before the public immutable Report is built. */
    private static final class Builder {
        final String sourceKind;
        final long fileSize;
        final int headerVersion;
        String compression = "NONE";
        long ramdiskOffset;
        long ramdiskSize;
        final List<Entry> entries = new ArrayList<>();
        final List<Problem> problems = new ArrayList<>();
        final List<Problem> findings = new ArrayList<>();
        String sha256 = "";
        String decompressedSha256 = "";
        long decompressedSize;
        boolean trailerSeen;
        int trailerOffset = -1;
        boolean trailerCrc;
        long trailingBytes;
        private boolean overflow;
        private boolean findingsOverflow;

        Builder(String sourceKind, long fileSize, int headerVersion, String compression,
                long ramdiskOffset, long ramdiskSize) {
            this.sourceKind = sourceKind;
            this.fileSize = fileSize;
            this.headerVersion = headerVersion;
            this.compression = compression;
            this.ramdiskOffset = ramdiskOffset;
            this.ramdiskSize = ramdiskSize;
        }

        void problem(String code, String detail, long offset) {
            if (problems.size() < MAX_PROBLEMS) {
                problems.add(new Problem(code, boundedDetail(detail), offset));
            } else if (!overflow) {
                overflow = true;
                problems.add(new Problem("PROBLEM_LIMIT_REACHED", "", offset));
            }
        }

        void finding(String code, String detail, long offset) {
            if (findings.size() < MAX_PROBLEMS) {
                findings.add(new Problem(code, boundedDetail(detail), offset));
            } else if (!findingsOverflow) {
                findingsOverflow = true;
                findings.add(new Problem("FINDING_LIMIT_REACHED", "", offset));
            }
        }

        Report build() { return new Report(this); }
    }

    // ------------------------------------------------------------------ entry points

    public static Report inspect(File image) throws IOException {
        return inspect(image, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_BYTES);
    }

    /** Inspects a full boot/init_boot image file, or a ramdisk component when it has no ANDROID! magic. */
    public static Report inspect(File image, int maxEntries, long maxBytes) throws IOException {
        if (image == null) throw new IOException("NULL_INPUT");
        BasicFileAttributes attributes = Files.readAttributes(image.toPath(), BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile()) throw new IOException("NOT_A_REGULAR_FILE");
        long length = attributes.size();
        if (length > MAX_IMAGE_BYTES) {
            return failure("BOOT_IMAGE", length, -1, "NONE", 0, 0, "INPUT_SIZE_LIMIT", "", null, maxEntries, maxBytes);
        }
        if (length < 8) {
            return failure("BOOT_IMAGE", length, -1, "NONE", 0, 0, "INPUT_TOO_SMALL", "", null, maxEntries, maxBytes);
        }
        byte[] prefix = new byte[8];
        try (RandomAccessFile input = new RandomAccessFile(image, "r")) {
            input.readFully(prefix);
        }
        if (asciiEquals(prefix, "ANDROID!")) return inspectContainerFile(image, length, maxEntries, maxBytes);
        if (length > MAX_COMPONENT_BYTES) {
            return failure("RAMDISK_COMPONENT", length, -1, "NONE", 0, length, "INPUT_SIZE_LIMIT", "",
                    null, maxEntries, maxBytes);
        }
        byte[] encoded = Files.readAllBytes(image.toPath());
        if (encoded.length != length) {
            return failure("RAMDISK_COMPONENT", length, -1, "NONE", 0, length, "INPUT_CHANGED", "",
                    null, maxEntries, maxBytes);
        }
        return inspectComponent(encoded, maxEntries, maxBytes, "RAMDISK_COMPONENT", length, -1, 0, length);
    }

    /** Inspects complete image bytes; a component without ANDROID! magic is accepted as well. */
    public static Report inspect(byte[] imageBytes) {
        return inspect(imageBytes, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_BYTES);
    }

    public static Report inspect(byte[] imageBytes, int maxEntries, long maxBytes) {
        if (imageBytes == null) {
            return failure("BOOT_IMAGE", 0, -1, "NONE", 0, 0, "NULL_INPUT", "", null, maxEntries, maxBytes);
        }
        long length = imageBytes.length;
        if (length > MAX_IMAGE_BYTES) {
            return failure("BOOT_IMAGE", length, -1, "NONE", 0, 0, "INPUT_SIZE_LIMIT", "", null, maxEntries, maxBytes);
        }
        if (startsWith(imageBytes, "ANDROID!")) {
            ContainerLocation location = locateContainer(imageBytes);
            if (location.errorCode != null) {
                return failure("BOOT_IMAGE", length, location.headerVersion, "NONE",
                        location.ramdiskOffset, location.ramdiskSize, location.errorCode, "", null,
                        maxEntries, maxBytes);
            }
            if (location.ramdiskSize <= 0) {
                return failure("BOOT_IMAGE", length, location.headerVersion, "NONE",
                        location.ramdiskOffset, 0, "EMPTY_RAMDISK", "", null, maxEntries, maxBytes);
            }
            if (location.ramdiskSize > MAX_COMPONENT_BYTES) {
                return failure("BOOT_IMAGE", length, location.headerVersion, "NONE",
                        location.ramdiskOffset, location.ramdiskSize, "COMPONENT_SIZE_LIMIT", "", null,
                        maxEntries, maxBytes);
            }
            byte[] encoded = Arrays.copyOfRange(imageBytes, (int) location.ramdiskOffset,
                    (int) (location.ramdiskOffset + location.ramdiskSize));
            return inspectComponent(encoded, maxEntries, maxBytes, "BOOT_IMAGE", length,
                    location.headerVersion, location.ramdiskOffset, location.ramdiskSize);
        }
        if (length > MAX_COMPONENT_BYTES) {
            return failure("RAMDISK_COMPONENT", length, -1, "NONE", 0, length, "INPUT_SIZE_LIMIT", "",
                    null, maxEntries, maxBytes);
        }
        return inspectComponent(imageBytes, maxEntries, maxBytes, "RAMDISK_COMPONENT", length, -1, 0, length);
    }

    /** Inspects the already-extracted (still compressed) ramdisk component bytes. */
    public static Report inspectRamdisk(byte[] encodedComponent) {
        return inspectRamdisk(encodedComponent, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_BYTES);
    }

    public static Report inspectRamdisk(byte[] encodedComponent, int maxEntries, long maxBytes) {
        if (encodedComponent == null) {
            return failure("RAMDISK_COMPONENT", 0, -1, "NONE", 0, 0, "NULL_INPUT", "", null,
                    maxEntries, maxBytes);
        }
        long length = encodedComponent.length;
        if (length > MAX_COMPONENT_BYTES) {
            return failure("RAMDISK_COMPONENT", length, -1, "NONE", 0, length, "INPUT_SIZE_LIMIT", "",
                    null, maxEntries, maxBytes);
        }
        return inspectComponent(encodedComponent, maxEntries, maxBytes, "RAMDISK_COMPONENT", length,
                -1, 0, length);
    }

    public static Report inspectRamdisk(File component) throws IOException {
        return inspectRamdisk(component, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_BYTES);
    }

    public static Report inspectRamdisk(File component, int maxEntries, long maxBytes) throws IOException {
        if (component == null) throw new IOException("NULL_INPUT");
        BasicFileAttributes attributes = Files.readAttributes(component.toPath(), BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile()) throw new IOException("NOT_A_REGULAR_FILE");
        long length = attributes.size();
        if (length > MAX_COMPONENT_BYTES) {
            return failure("RAMDISK_COMPONENT", length, -1, "NONE", 0, length, "INPUT_SIZE_LIMIT", "",
                    null, maxEntries, maxBytes);
        }
        byte[] encoded = Files.readAllBytes(component.toPath());
        if (encoded.length != length) {
            return failure("RAMDISK_COMPONENT", length, -1, "NONE", 0, length, "INPUT_CHANGED", "",
                    null, maxEntries, maxBytes);
        }
        return inspectComponent(encoded, maxEntries, maxBytes, "RAMDISK_COMPONENT", length, -1, 0, length);
    }

    private static Report inspectContainerFile(File image, long length, int maxEntries, long maxBytes)
            throws IOException {
        BootImageInspector.Report layout;
        try {
            layout = BootImageInspector.inspect(image);
        } catch (BootImageInspector.InvalidImageException exception) {
            return failure("BOOT_IMAGE", length, -1, "NONE", 0, 0, "CONTAINER_INVALID",
                    exception.code, null, maxEntries, maxBytes);
        }
        if (layout.ramdiskSize <= 0) {
            return failure("BOOT_IMAGE", length, layout.headerVersion, "NONE",
                    layout.ramdiskOffset, 0, "EMPTY_RAMDISK", "", null, maxEntries, maxBytes);
        }
        if (layout.ramdiskSize > MAX_COMPONENT_BYTES) {
            return failure("BOOT_IMAGE", length, layout.headerVersion, "NONE",
                    layout.ramdiskOffset, layout.ramdiskSize, "COMPONENT_SIZE_LIMIT", "", null,
                    maxEntries, maxBytes);
        }
        byte[] encoded = new byte[(int) layout.ramdiskSize];
        try (RandomAccessFile input = new RandomAccessFile(image, "r")) {
            if (input.length() < layout.ramdiskOffset + layout.ramdiskSize) {
                return failure("BOOT_IMAGE", length, layout.headerVersion, "NONE",
                        layout.ramdiskOffset, layout.ramdiskSize, "COMPONENT_OUT_OF_BOUNDS", "", null,
                        maxEntries, maxBytes);
            }
            input.seek(layout.ramdiskOffset);
            input.readFully(encoded);
        }
        return inspectComponent(encoded, maxEntries, maxBytes, "BOOT_IMAGE", length,
                layout.headerVersion, layout.ramdiskOffset, layout.ramdiskSize);
    }

    // ------------------------------------------------------------------ component decoding

    private static Report inspectComponent(byte[] encoded, int maxEntries, long maxBytes,
                                           String sourceKind, long fileSize, int headerVersion,
                                           long ramdiskOffset, long ramdiskSize) {
        if (maxEntries <= 0 || maxEntries > MAX_ENTRIES_LIMIT
                || maxBytes <= 0 || maxBytes > DEFAULT_MAX_BYTES) {
            return failure(sourceKind, fileSize, headerVersion, "NONE", ramdiskOffset, ramdiskSize,
                    "INVALID_LIMIT", "", null, maxEntries, maxBytes);
        }
        if (encoded == null) {
            return failure(sourceKind, fileSize, headerVersion, "NONE", ramdiskOffset, ramdiskSize,
                    "NULL_INPUT", "", null, maxEntries, maxBytes);
        }
        if (encoded.length == 0) {
            return failure(sourceKind, fileSize, headerVersion, "NONE", ramdiskOffset, ramdiskSize,
                    "EMPTY_RAMDISK", "", null, maxEntries, maxBytes);
        }
        if (encoded.length > MAX_COMPONENT_BYTES) {
            return failure(sourceKind, fileSize, headerVersion, "NONE", ramdiskOffset, ramdiskSize,
                    "COMPONENT_SIZE_LIMIT", "", null, maxEntries, maxBytes);
        }
        String compression = detectCompression(encoded);
        if (compression == null) {
            return failure(sourceKind, fileSize, headerVersion, "NONE", ramdiskOffset, ramdiskSize,
                    "INVALID_RAMDISK_MAGIC", "", encoded, maxEntries, maxBytes);
        }
        if (compression.startsWith("UNSUPPORTED:")) {
            Builder builder = new Builder(sourceKind, fileSize, headerVersion, "UNSUPPORTED",
                    ramdiskOffset, ramdiskSize);
            builder.sha256 = digest(encoded);
            builder.problem("UNSUPPORTED_COMPRESSION", compression.substring("UNSUPPORTED:".length()), 0);
            return builder.build();
        }
        byte[] decoded;
        int encodedEnd = encoded.length;
        try {
            if ("RAW".equals(compression)) {
                if (encoded.length > maxBytes) {
                    return failure(sourceKind, fileSize, headerVersion, compression, ramdiskOffset,
                            ramdiskSize, "DECOMPRESSION_LIMIT", "", encoded, maxEntries, maxBytes);
                }
                decoded = encoded.clone();
            } else {
                int limit = (int) Math.min(maxBytes, (long) KernelCompression.MAX_KERNEL_BYTES);
                if ("LZ4_FRAME".equals(compression) || "XZ".equals(compression) || "ZSTD".equals(compression)) {
                    int[] consumed = {0};
                    decoded = "LZ4_FRAME".equals(compression)
                            ? Lz4FrameCodec.decode(encoded, limit, consumed)
                            : "XZ".equals(compression) ? XzCodec.decode(encoded, limit, consumed)
                            : ZstdCodec.decode(encoded, limit, consumed);
                    encodedEnd = consumed[0];
                } else {
                    decoded = KernelCompression.decode(encoded, compression, limit);
                }
            }
        } catch (IOException exception) {
            return failure(sourceKind, fileSize, headerVersion, compression, ramdiskOffset, ramdiskSize,
                    decodeErrorCode(compression, exception), "", encoded, maxEntries, maxBytes);
        }
        Builder builder = new Builder(sourceKind, fileSize, headerVersion, compression,
                ramdiskOffset, ramdiskSize);
        builder.sha256 = digest(encoded);
        if ("GZIP".equals(compression)) {
            // java.util.zip.GZIPInputStream ignores trailing bytes after the trailer; CPIO
            // permits a page-padded component, so only all-zero padding is accepted.
            GzipCheck check = checkGzipEnvelope(encoded,
                    (int) Math.min(maxBytes, (long) KernelCompression.MAX_KERNEL_BYTES));
            if (check.problem != null) builder.problem(check.problem.code, check.problem.detail,
                    check.problem.offset);
            if (check.trailing > 0) builder.trailingBytes = check.trailing;
        }
        if (Thread.currentThread().isInterrupted()) {
            builder.problem("CANCELLED", "", 0);
            return builder.build();
        }
        parseCpio(decoded, maxEntries, builder);
        // Kernel components may have opaque suffixes; a ramdisk may only have zero padding.
        long encodedTrailing = 0;
        for (int index = encodedEnd; index < encoded.length; index++) {
            if ((index & 65535) == 0 && Thread.currentThread().isInterrupted()) {
                builder.problem("CANCELLED", "", index);
                return builder.build();
            }
            if (encoded[index] != 0) encodedTrailing++;
        }
        if (encodedTrailing > 0) {
            builder.problem("TRAILING_DATA", "encodedNonZeroBytes=" + encodedTrailing, encodedEnd);
            builder.trailingBytes += encodedTrailing;
        }
        builder.decompressedSha256 = digest(decoded);
        builder.decompressedSize = decoded.length;
        return builder.build();
    }

    /** Detects the component compression from magic bytes; returns null for unknown content. */
    private static String detectCompression(byte[] bytes) {
        if (bytes.length >= 4 && (bytes[0] & 255) == 0x1f && (bytes[1] & 255) == 0x8b) return "GZIP";
        if (bytes.length >= 4 && bytes[0] == 2 && bytes[1] == 33 && bytes[2] == 76 && bytes[3] == 24) {
            return "LZ4_LEGACY";
        }
        if (bytes.length >= 4 && bytes[0] == 4 && bytes[1] == 34 && bytes[2] == 77 && bytes[3] == 24) {
            return "LZ4_FRAME";
        }
        if (ZstdCodec.matches(bytes)) return "ZSTD";
        if (bytes.length >= 6 && (bytes[0] & 255) == 0xfd && bytes[1] == 0x37 && bytes[2] == 0x7a
                && bytes[3] == 0x58 && bytes[4] == 0x5a && bytes[5] == 0x00) {
            return "XZ";
        }
        if (startsWith(bytes, "070701") || startsWith(bytes, "070702")) return "RAW";
        return null;
    }

    private static String decodeErrorCode(String compression, IOException exception) {
        String message = exception.getMessage();
        if (message == null) return "DECOMPRESSION_FAILED";
        switch (message) {
            case "CANCELLED":
            case "DECOMPRESSION_LIMIT":
            case "INVALID_LZ4_MAGIC":
            case "TRUNCATED_LZ4_BLOCK_HEADER":
            case "INVALID_LZ4_BLOCK_SIZE":
            case "TRUNCATED_LZ4_LENGTH":
            case "TRUNCATED_LZ4_LITERALS":
            case "TRUNCATED_LZ4_OFFSET":
            case "INVALID_LZ4_OFFSET":
            case "EMPTY_LZ4_BLOCK":
                return message;
            case "EMPTY_KERNEL":
                return "EMPTY_RAMDISK";
            default:
                if ("LZ4_FRAME".equals(compression) || "XZ".equals(compression) || "ZSTD".equals(compression)) return message;
                return "GZIP".equals(compression) ? "INVALID_GZIP_STREAM" : "INVALID_LZ4_STREAM";
        }
    }

    // ------------------------------------------------------------------ gzip envelope

    private static final class GzipCheck {
        Problem problem;
        long trailing;
    }

    /**
     * Walks one RFC 1952 member and requires that nothing but zero padding follows its
     * trailer. A second member or arbitrary appended bytes are TRAILING_DATA. This is
     * needed because Java's GZIPInputStream silently ignores bytes after the trailer.
     */
    private static GzipCheck checkGzipEnvelope(byte[] input, int limit) {
        GzipCheck result = new GzipCheck();
        if (input.length < GZIP_HEADER_BYTES + GZIP_TRAILER_BYTES) {
            result.problem = new Problem("TRUNCATED_GZIP", "", 0);
            return result;
        }
        if ((input[0] & 255) != 0x1f || (input[1] & 255) != 0x8b) {
            result.problem = new Problem("INVALID_GZIP_HEADER", "", 0);
            return result;
        }
        if ((input[2] & 255) != 8) {
            result.problem = new Problem("UNSUPPORTED_GZIP_METHOD", "", 0);
            return result;
        }
        int flags = input[3] & 255;
        if ((flags & 0xe0) != 0) {
            result.problem = new Problem("INVALID_GZIP_HEADER", "reservedFlagBits", 0);
            return result;
        }
        int position = GZIP_HEADER_BYTES;
        if ((flags & 4) != 0) { // FEXTRA
            if (input.length - position < 2) {
                result.problem = new Problem("TRUNCATED_GZIP", "", position);
                return result;
            }
            int extra = (input[position] & 255) | ((input[position + 1] & 255) << 8);
            position += 2;
            if (extra > input.length - position) {
                result.problem = new Problem("TRUNCATED_GZIP", "", position);
                return result;
            }
            position += extra;
        }
        if ((flags & 8) != 0) { // FNAME
            int terminator = indexOfZero(input, position);
            if (terminator < 0) {
                result.problem = new Problem("TRUNCATED_GZIP", "", position);
                return result;
            }
            position = terminator + 1;
        }
        if ((flags & 16) != 0) { // FCOMMENT
            int terminator = indexOfZero(input, position);
            if (terminator < 0) {
                result.problem = new Problem("TRUNCATED_GZIP", "", position);
                return result;
            }
            position = terminator + 1;
        }
        if ((flags & 2) != 0) { // FHCRC
            if (input.length - position < 2) {
                result.problem = new Problem("TRUNCATED_GZIP", "", position);
                return result;
            }
            int stored = (input[position] & 255) | ((input[position + 1] & 255) << 8);
            CRC32 headerCrc = new CRC32();
            headerCrc.update(input, 0, position);
            if ((int) (headerCrc.getValue() & 0xffff) != stored) {
                result.problem = new Problem("GZIP_HEADER_CRC_MISMATCH", "", position);
                return result;
            }
            position += 2;
        }
        Inflater inflater = new Inflater(true);
        try {
            inflater.setInput(input, position, input.length - position);
            byte[] sink = new byte[64 * 1024];
            long total = 0;
            CRC32 crc = new CRC32();
            while (!inflater.finished()) {
                int count;
                try {
                    count = inflater.inflate(sink);
                } catch (DataFormatException exception) {
                    result.problem = new Problem("INVALID_GZIP_STREAM", "", position);
                    return result;
                }
                if (count == 0) {
                    if (inflater.needsInput()) {
                        result.problem = new Problem("TRUNCATED_GZIP", "", position);
                    } else {
                        result.problem = new Problem("INVALID_GZIP_STREAM", "", position);
                    }
                    return result;
                }
                crc.update(sink, 0, count);
                total += count;
                if (total > limit) {
                    result.problem = new Problem("DECOMPRESSION_LIMIT", "", position);
                    return result;
                }
            }
            long trailerStart = (long) input.length - inflater.getRemaining();
            if (trailerStart + GZIP_TRAILER_BYTES > input.length) {
                result.problem = new Problem("TRUNCATED_GZIP_TRAILER", "", trailerStart);
                return result;
            }
            int trailer = (int) trailerStart;
            long expectedCrc = u32(input, trailer);
            long expectedSize = u32(input, trailer + 4);
            if (crc.getValue() != expectedCrc) {
                result.problem = new Problem("GZIP_CRC_MISMATCH", "", trailer);
                return result;
            }
            if ((total & 0xffffffffL) != expectedSize) {
                result.problem = new Problem("GZIP_SIZE_MISMATCH", "", trailer);
                return result;
            }
            int end = trailer + GZIP_TRAILER_BYTES;
            long nonZero = 0;
            for (int index = end; index < input.length; index++) {
                if (input[index] != 0) nonZero++;
            }
            if (nonZero > 0) {
                result.problem = new Problem("TRAILING_DATA", "nonZeroBytes=" + nonZero, end);
                result.trailing = nonZero;
            }
            return result;
        } finally {
            inflater.end();
        }
    }

    private static int indexOfZero(byte[] bytes, int from) {
        for (int index = from; index < bytes.length; index++) {
            if (bytes[index] == 0) return index;
        }
        return -1;
    }

    // ------------------------------------------------------------------ CPIO newc

    private static void parseCpio(byte[] data, int maxEntries, Builder builder) {
        Set<String> names = new HashSet<>();
        int position = 0;
        while (true) {
            if (Thread.currentThread().isInterrupted()) {
                builder.problem("CANCELLED", "", position);
                return;
            }
            if (position >= data.length) {
                builder.problem("MISSING_TRAILER", "", position);
                builder.trailerSeen = false;
                return;
            }
            if (data.length - position < CPIO_HEADER_BYTES) {
                builder.problem("TRUNCATED_CPIO_HEADER", "", position);
                return;
            }
            int magic = cpioMagic(data, position);
            if (magic < 0) {
                builder.problem("INVALID_CPIO_MAGIC", "", position);
                return;
            }
            long[] fields = new long[13];
            for (int index = 0; index < fields.length; index++) {
                long value = hex8(data, position + 6 + index * 8);
                if (value < 0) {
                    builder.problem("INVALID_CPIO_HEADER", "field" + index, position);
                    return;
                }
                fields[index] = value;
            }
            long mode = fields[1];
            long fileSize = fields[6];
            long nameSize = fields[11];
            long check = fields[12];
            if (nameSize <= 0) {
                builder.problem("INVALID_CPIO_HEADER", "namesize", position);
                return;
            }
            int nameOffset = position + CPIO_HEADER_BYTES;
            if (nameSize > data.length - nameOffset) {
                builder.problem("TRUNCATED_CPIO_NAME", "", position);
                return;
            }
            int nameLength = (int) nameSize;
            if (data[nameOffset + nameLength - 1] != 0) {
                builder.problem("MALFORMED_CPIO_NAME", "missingTerminator", position);
                return;
            }
            for (int index = 0; index < nameLength - 1; index++) {
                if (data[nameOffset + index] == 0) {
                    builder.problem("MALFORMED_CPIO_NAME", "embeddedTerminator", position);
                    return;
                }
            }
            String path = new String(data, nameOffset, nameLength - 1, StandardCharsets.ISO_8859_1);
            long dataOffsetLong = align4((long) nameOffset + nameLength);
            if (fileSize > data.length) {
                builder.problem("TRUNCATED_CPIO_DATA", path, dataOffsetLong);
                return;
            }
            if (dataOffsetLong > data.length) {
                // Some writers omit the zero pad after the final name; tolerate it only
                // for a zero-length entry (the trailer) and never for file data.
                if (fileSize != 0) {
                    builder.problem("TRUNCATED_CPIO_DATA", path, dataOffsetLong);
                    return;
                }
                dataOffsetLong = data.length;
            }
            if (fileSize > data.length - dataOffsetLong) {
                builder.problem("TRUNCATED_CPIO_DATA", path, dataOffsetLong);
                return;
            }
            int dataOffset = (int) dataOffsetLong;
            int size = (int) fileSize;
            if ("TRAILER!!!".equals(path)) {
                if (fileSize != 0) {
                    builder.problem("MALFORMED_TRAILER", "fileSize=" + fileSize, position);
                    return;
                }
                builder.trailerSeen = true;
                builder.trailerOffset = position;
                builder.trailerCrc = magic == 1;
                long next = align4((long) dataOffset + size);
                if (next > data.length) next = data.length;
                long trailing = 0;
                for (int index = (int) next; index < data.length; index++) {
                    if (data[index] != 0) trailing++;
                }
                if (trailing > 0) {
                    builder.problem("TRAILING_DATA", "nonZeroBytes=" + trailing, next);
                    builder.trailingBytes = trailing;
                }
                return;
            }
            if (builder.entries.size() >= maxEntries) {
                builder.problem("ENTRY_LIMIT_EXCEEDED", "maxEntries=" + maxEntries, position);
                return;
            }
            builder.entries.add(new Entry(path, (int) mode, fileSize, dataOffset, digest(data, dataOffset, size),
                    position, (int) align4((long) dataOffset + size), fields[2], fields[3], fields[4], magic == 1));
            if (!names.add(path)) {
                // AOSP mkbootfs legitimately repeats plain directory entries (for example
                // "dev" in real init_boot ramdisks), but a repeated security-relevant entry
                // makes ownership assertions ambiguous and must reject the archive.
                if (criticalName(path)) builder.problem("DUPLICATE_ENTRY", path, position);
                else builder.finding("DUPLICATE_ENTRY", path, position);
            }
            if (unsafePath(path)) builder.problem("UNSAFE_PATH", path, position);
            if (magic == 1 && (mode & 0170000L) == 0100000L) {
                long sum = 0;
                for (int index = 0; index < size; index++) sum += data[dataOffset + index] & 255;
                if (sum != (check & 0xffffffffL)) builder.problem("CPIO_CHECK_MISMATCH", path, position);
            }
            long next = align4((long) dataOffset + size);
            if (next > data.length) {
                builder.problem("TRUNCATED_CPIO_DATA", path, next);
                return;
            }
            if (next <= position) {
                builder.problem("INVALID_CPIO_LAYOUT", "noForwardProgress", position);
                return;
            }
            position = (int) next;
        }
    }

    /** 0 = newc (070701), 1 = crc (070702), -1 = not a CPIO newc header. */
    private static int cpioMagic(byte[] bytes, int offset) {
        if (startsWith(bytes, offset, "070701")) return 0;
        if (startsWith(bytes, offset, "070702")) return 1;
        return -1;
    }

    private static long hex8(byte[] bytes, int offset) {
        long value = 0;
        for (int index = 0; index < 8; index++) {
            int digit = Character.digit((char) (bytes[offset + index] & 255), 16);
            if (digit < 0) return -1;
            value = (value << 4) | digit;
        }
        return value;
    }

    // ------------------------------------------------------------------ container locator

    /**
     * Locates the ramdisk component in AOSP boot header v0-v4 bytes. This is a bounded
     * locator only; the file entry point delegates full container validation to
     * {@link BootImageInspector}.
     */
    private static ContainerLocation locateContainer(byte[] bytes) {
        ContainerLocation location = new ContainerLocation();
        if (bytes.length < 44) {
            location.errorCode = "TRUNCATED_HEADER";
            return location;
        }
        long version = u32(bytes, 40);
        if (version > 4) {
            location.errorCode = "UNSUPPORTED_HEADER";
            return location;
        }
        location.headerVersion = (int) version;
        int minimum = MINIMUM_HEADER_BYTES[(int) version];
        if (bytes.length < minimum) {
            location.errorCode = "TRUNCATED_HEADER";
            return location;
        }
        boolean legacy = version < 3;
        long pageSize = legacy ? u32(bytes, 36) : 4096;
        if (pageSize != 2048 && pageSize != 4096 && pageSize != 8192 && pageSize != 16384) {
            location.errorCode = "INVALID_PAGE_SIZE";
            return location;
        }
        long headerSize = version == 0 ? minimum : u32(bytes, legacy ? 1644 : 20);
        if (headerSize < minimum || headerSize > pageSize) {
            location.errorCode = "INVALID_HEADER_SIZE";
            return location;
        }
        if (bytes.length < pageSize) {
            location.errorCode = "TRUNCATED_HEADER_PAGE";
            return location;
        }
        long kernelSize = u32(bytes, 8);
        long ramdiskSize = u32(bytes, legacy ? 16 : 12);
        if (kernelSize > bytes.length - pageSize) {
            location.errorCode = "COMPONENT_OUT_OF_BOUNDS";
            return location;
        }
        long ramdiskOffset = align(pageSize + kernelSize, pageSize);
        location.ramdiskOffset = ramdiskOffset;
        location.ramdiskSize = ramdiskSize;
        if (ramdiskOffset > bytes.length || ramdiskSize > bytes.length - ramdiskOffset) {
            location.errorCode = "COMPONENT_OUT_OF_BOUNDS";
            return location;
        }
        return location;
    }

    // ------------------------------------------------------------------ failure helpers

    private static Report failure(String sourceKind, long fileSize, int headerVersion, String compression,
                                  long ramdiskOffset, long ramdiskSize, String code, String detail,
                                  byte[] encoded, int maxEntries, long maxBytes) {
        Builder builder = new Builder(sourceKind, fileSize, headerVersion, compression,
                ramdiskOffset, ramdiskSize);
        builder.problem(code, detail, 0);
        if (encoded != null && encoded.length <= MAX_COMPONENT_BYTES) builder.sha256 = digest(encoded);
        return builder.build();
    }

    // ------------------------------------------------------------------ small utilities

    private static boolean magiskMarker(String path) {
        return path.equals("magisk") || path.equals("magisk32") || path.equals("magisk64")
                || path.equals("magiskinit") || path.equals(".backup") || path.startsWith(".backup/")
                || path.equals("overlay.d") || path.startsWith("overlay.d/")
                || path.equals("init.magisk");
    }

    private static boolean unsafePath(String path) {
        if (path.isEmpty()) return true;
        if (path.charAt(0) == '/' || path.charAt(0) == '\\') return true;
        for (int index = 0; index < path.length(); index++) {
            char value = path.charAt(index);
            if (value < 0x20 || value == 0x7f || value == '\\') return true;
        }
        int start = 0;
        while (start <= path.length()) {
            int end = path.indexOf('/', start);
            if (end < 0) end = path.length();
            if (end - start == 2 && path.charAt(start) == '.' && path.charAt(start + 1) == '.') return true;
            if (end == path.length()) break;
            start = end + 1;
        }
        return false;
    }

    /** Names whose presence/ownership drives assertions; a duplicate of these is fatal. */
    private static boolean criticalName(String path) {
        String normalized = normalize(path);
        return normalized.equals("init") || normalized.equals("init.real")
                || normalized.equals("kernelsu.ko") || normalized.equals("ksu_config")
                || normalized.equals("maplesu_id") || normalized.equals("sevenk.ko")
                || normalized.equals("ksud") || normalized.endsWith("/ksud")
                || normalized.contains("data/adb/ksu");
    }

    private static String normalize(String path) {
        String value = path;
        while (value.startsWith("./")) value = value.substring(2);
        return value;
    }

    private static String entryNameFor(String code) {
        switch (code) {
            case "MISSING_KERNELSU_KO": return "kernelsu.ko";
            case "MISSING_INIT_REAL": return "init.real";
            case "MISSING_INIT": return "init";
            case "MISSING_KSU_CONFIG": return "ksu_config";
            case "MISSING_MAPLESU_ID": return "maplesu_id";
            default: return code;
        }
    }

    private static String joinCodes(List<String> codes, String suffix) {
        StringBuilder out = new StringBuilder();
        for (int index = 0; index < codes.size(); index++) {
            if (index > 0) out.append(',');
            out.append(codes.get(index));
        }
        return out.length() == 0 ? suffix : out.toString();
    }

    private static String boundedDetail(String detail) {
        if (detail == null) return "";
        if (detail.length() <= MAX_DETAIL_PATH) return detail;
        return detail.substring(0, MAX_DETAIL_PATH);
    }

    private static long align4(long value) { return (value + 3L) & ~3L; }

    private static long align(long value, long pageSize) {
        return (value + pageSize - 1) / pageSize * pageSize;
    }

    private static long u32(byte[] bytes, int offset) {
        return (bytes[offset] & 255L) | ((bytes[offset + 1] & 255L) << 8)
                | ((bytes[offset + 2] & 255L) << 16) | ((bytes[offset + 3] & 255L) << 24);
    }

    private static boolean startsWith(byte[] bytes, String prefix) {
        return startsWith(bytes, 0, prefix);
    }

    private static boolean startsWith(byte[] bytes, int offset, String prefix) {
        if (bytes.length - offset < prefix.length()) return false;
        for (int index = 0; index < prefix.length(); index++) {
            if ((bytes[offset + index] & 255) != prefix.charAt(index)) return false;
        }
        return true;
    }

    private static boolean asciiEquals(byte[] bytes, String value) {
        return startsWith(bytes, 0, value);
    }

    private static String digest(byte[] bytes) {
        return digest(bytes, 0, bytes.length);
    }

    private static String digest(byte[] bytes, int offset, int length) {
        final MessageDigest hash;
        try {
            hash = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
        hash.update(bytes, offset, length);
        StringBuilder out = new StringBuilder(64);
        for (byte value : hash.digest()) out.append(String.format(Locale.ROOT, "%02x", value & 255));
        return out.toString();
    }

    /** Minimal JSON string escaping; the inspector must never echo raw control bytes. */
    private static void appendJsonString(StringBuilder out, String value) {
        out.append('"');
        String text = value == null ? "" : value;
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            switch (character) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (character < 0x20 || character == 0x7f) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) character));
                    } else {
                        out.append(character);
                    }
            }
        }
        out.append('"');
    }

    public static void main(String[] args) {
        if (args.length < 1 || args.length > 3) {
            System.err.println("Usage: RamdiskInspector <boot-or-ramdisk.img> [maxEntries] [maxBytes]");
            System.exit(2);
        }
        try {
            File source = new File(args[0]);
            int maxEntries = args.length >= 2 ? Integer.parseInt(args[1]) : DEFAULT_MAX_ENTRIES;
            long maxBytes = args.length >= 3 ? Long.parseLong(args[2]) : DEFAULT_MAX_BYTES;
            Report report = inspect(source, maxEntries, maxBytes);
            System.out.println(report.toJson());
            if (report.malformed) {
                System.err.println(report.errorCode);
                System.exit(2);
            }
        } catch (IOException exception) {
            System.err.println("RAMDISK_READ_FAILED");
            System.exit(3);
        } catch (NumberFormatException exception) {
            System.err.println("INVALID_ARGUMENT");
            System.exit(2);
        }
    }
}
