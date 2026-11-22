package dev.maplesu.image;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.Arrays;

/** Read-only inspection of AOSP Android boot header v0-v4 containers. */
public final class BootImageInspector {
    private static final long PAGE_SIZE = 4096;

    private BootImageInspector() {}

    public static final class InvalidImageException extends IOException {
        public final String code;

        InvalidImageException(String code) {
            super(code);
            this.code = code;
        }
    }

    public static final class Report {
        public final long fileSize;
        public final int headerVersion;
        public final long headerSize;
        public final long pageSize;
        public final long kernelOffset;
        public final long kernelSize;
        public final long ramdiskOffset;
        public final long ramdiskSize;
        public final long secondOffset;
        public final long secondSize;
        public final long recoveryDtboOffset;
        public final long recoveryDtboSize;
        public final long dtbOffset;
        public final long dtbSize;
        public final long signatureOffset;
        public final long signatureSize;
        public final String compression;
        public final String sha256;

        private Report(long fileSize, int version, long headerSize, long pageSize, long kernelSize,
                       long ramdiskOffset, long ramdiskSize, long secondOffset, long secondSize,
                       long recoveryDtboOffset, long recoveryDtboSize, long dtbOffset, long dtbSize, long signatureOffset,
                       long signatureSize, String compression, String sha256) {
            this.fileSize = fileSize;
            this.headerVersion = version;
            this.headerSize = headerSize;
            this.pageSize = pageSize;
            this.kernelOffset = pageSize;
            this.kernelSize = kernelSize;
            this.ramdiskOffset = ramdiskOffset;
            this.ramdiskSize = ramdiskSize;
            this.secondOffset = secondOffset;
            this.secondSize = secondSize;
            this.recoveryDtboOffset = recoveryDtboOffset;
            this.recoveryDtboSize = recoveryDtboSize;
            this.dtbOffset = dtbOffset;
            this.dtbSize = dtbSize;
            this.signatureOffset = signatureOffset;
            this.signatureSize = signatureSize;
            this.compression = compression;
            this.sha256 = sha256;
        }

        public String toJson() {
            return String.format(Locale.ROOT,
                    "{\"schemaVersion\":1,\"fileSize\":%d,\"headerVersion\":%d,"
                    + "\"headerSize\":%d,\"pageSize\":%d,\"kernelOffset\":%d,\"kernelSize\":%d,"
                    + "\"ramdiskOffset\":%d,\"ramdiskSize\":%d,"
                    + "\"secondOffset\":%d,\"secondSize\":%d,"
                    + "\"recoveryDtboOffset\":%d,\"recoveryDtboSize\":%d,"
                    + "\"dtbOffset\":%d,\"dtbSize\":%d,"
                    + "\"signatureOffset\":%d,\"signatureSize\":%d,"
                    + "\"compression\":\"%s\",\"sha256\":\"%s\","
                    + "\"containsKernel\":%s,\"patchSupport\":\"NOT_EVALUATED\"}",
                    fileSize, headerVersion, headerSize, pageSize, kernelOffset, kernelSize,
                    ramdiskOffset, ramdiskSize, secondOffset, secondSize,
                    recoveryDtboOffset, recoveryDtboSize, dtbOffset, dtbSize, signatureOffset, signatureSize,
                    compression, sha256, kernelSize > 0);
        }
    }

    public static Report inspect(File file) throws IOException {
        try (RandomAccessFile input = new RandomAccessFile(file, "r")) {
            long length = input.length();
            if (length < 44) throw invalid("TRUNCATED_HEADER");
            byte[] header = new byte[(int) Math.min(length, PAGE_SIZE)];
            input.readFully(header);
            byte[] magic = {'A', 'N', 'D', 'R', 'O', 'I', 'D', '!'};
            for (int i = 0; i < magic.length; i++) {
                if (header[i] != magic[i]) throw invalid("INVALID_MAGIC");
            }
            long version = u32(header, 40);
            if (version > 4) throw invalid("UNSUPPORTED_HEADER");
            int minimumHeader = new int[]{1632, 1648, 1660, 1580, 1584}[(int) version];
            if (header.length < minimumHeader) throw invalid("TRUNCATED_HEADER");
            boolean legacy = version < 3;
            long pageSize = legacy ? u32(header, 36) : PAGE_SIZE;
            // Match the supported page sizes in AOSP mkbootimg; do not infer vendor layouts.
            if (pageSize != 2048 && pageSize != 4096 && pageSize != 8192 && pageSize != 16384) {
                throw invalid("INVALID_PAGE_SIZE");
            }
            long headerSize = version == 0 ? minimumHeader : u32(header, legacy ? 1644 : 20);
            if (headerSize < minimumHeader || headerSize > pageSize) {
                throw invalid("INVALID_HEADER_SIZE");
            }
            if (length < pageSize) throw invalid("TRUNCATED_HEADER_PAGE");
            long kernelSize = u32(header, 8);
            long ramdiskSize = u32(header, legacy ? 16 : 12);
            long secondSize = legacy ? u32(header, 24) : 0;
            long recoveryDtboSize = version == 1 || version == 2 ? u32(header, 1632) : 0;
            long dtbSize = version == 2 ? u32(header, 1648) : 0;
            long signatureSize = version == 4 ? u32(header, 1580) : 0;
            checkRegion(pageSize, kernelSize, length);
            long ramdiskOffset = align(pageSize + kernelSize, pageSize);
            checkRegion(ramdiskOffset, ramdiskSize, length);
            long afterRamdisk = align(ramdiskOffset + ramdiskSize, pageSize);
            long secondOffset = legacy ? afterRamdisk : 0;
            checkRegion(secondOffset, secondSize, length);
            long afterSecond = align(afterRamdisk + secondSize, pageSize);
            long recoveryDtboOffset = 0;
            if (version == 1 || version == 2) {
                long low = u32(header, 1636), high = u32(header, 1640);
                // Validate uint64 before using it in signed file offsets or arithmetic.
                if (high > 0x7fffffffL) throw invalid("INVALID_RECOVERY_DTBO_OFFSET");
                recoveryDtboOffset = low | (high << 32);
                // AOSP's DTB position uses page counts, while DTBO extraction uses this field.
                // Require both interpretations to agree, including zero for an absent DTBO.
                if (recoveryDtboOffset != (recoveryDtboSize == 0 ? 0 : afterSecond)) {
                    throw invalid("INVALID_RECOVERY_DTBO_OFFSET");
                }
            }
            checkRegion(recoveryDtboOffset, recoveryDtboSize, length);
            long dtbOffset = version == 2 ? align(afterSecond + recoveryDtboSize, pageSize) : 0;
            checkRegion(dtbOffset, dtbSize, length);
            long signatureOffset = legacy ? 0 : afterRamdisk;
            checkRegion(signatureOffset, signatureSize, length);
            String compression = "NONE";
            if (kernelSize > 0) {
                byte[] prefix = new byte[(int) Math.min(kernelSize, 64)];
                input.seek(pageSize);
                input.readFully(prefix);
                compression = compression(prefix);
            }
            input.seek(0);
            String sha256 = digest(input);
            byte[] afterHeader = new byte[header.length];
            input.seek(0);
            input.readFully(afterHeader);
            if (input.length() != length || !Arrays.equals(header, afterHeader)) {
                throw invalid("SOURCE_CHANGED");
            }
            return new Report(length, (int) version, headerSize, pageSize, kernelSize,
                    ramdiskOffset, ramdiskSize, secondOffset, secondSize,
                    recoveryDtboOffset, recoveryDtboSize, dtbOffset, dtbSize, signatureOffset, signatureSize,
                    compression, sha256);
        }
    }

    private static long u32(byte[] bytes, int offset) {
        return (bytes[offset] & 255L) | ((bytes[offset + 1] & 255L) << 8)
                | ((bytes[offset + 2] & 255L) << 16) | ((bytes[offset + 3] & 255L) << 24);
    }

    private static long align(long offset, long pageSize) {
        return ((offset + pageSize - 1) / pageSize) * pageSize;
    }

    private static void checkRegion(long offset, long size, long fileSize) throws IOException {
        if (size > 0 && (offset > fileSize || size > fileSize - offset)) {
            throw invalid("COMPONENT_OUT_OF_BOUNDS");
        }
    }

    /** One container-format detector for the inspector, the codecs and the manager adapters. */
    private static String compression(byte[] bytes) {
        return KernelIdentity.formatOf(bytes);
    }

    private static String digest(RandomAccessFile input) throws IOException {
        final MessageDigest hash;
        try {
            hash = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
        byte[] buffer = new byte[64 * 1024];
        int count;
        while ((count = input.read(buffer)) != -1) {
            if (Thread.currentThread().isInterrupted()) throw new IOException("CANCELLED");
            hash.update(buffer, 0, count);
        }
        StringBuilder hex = new StringBuilder(64);
        for (byte value : hash.digest()) hex.append(String.format(Locale.ROOT, "%02x", value & 255));
        return hex.toString();
    }

    private static InvalidImageException invalid(String code) {
        return new InvalidImageException(code);
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: BootImageInspector <boot.img>");
            System.exit(2);
        }
        try {
            System.out.println(inspect(new File(args[0])).toJson());
        } catch (InvalidImageException exception) {
            System.err.println(exception.code);
            System.exit(2);
        } catch (IOException exception) {
            System.err.println("IMAGE_READ_FAILED");
            System.exit(3);
        }
    }
}
