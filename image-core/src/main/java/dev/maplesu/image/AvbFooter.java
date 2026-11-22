package dev.maplesu.image;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Locale;

/**
 * The 64-byte AVB footer at the end of a partition, parsed once for every caller.
 *
 * <p>Layout written by {@code avbtool} (all fields **big-endian**):
 * <pre>
 * +0   magic "AVBf"      +4  version_major   +8   version_minor
 * +12  original_image_size (u64)   +20 vbmeta_offset (u64)   +28 vbmeta_size (u64)
 * +36  reserved (28 bytes, zero)
 * </pre>
 *
 * <p>Three implementations existed and one of them — the baseline cleanliness gate — read
 * {@code LE @ +8/+16/+24}, i.e. the wrong endianness *and* the wrong offsets ({@code +8} is
 * {@code version_minor}; {@code +16} is the high half of {@code original_image_size}). On the
 * reference images those wrong fields all read as zero, so that gate always answered "fine". This
 * class is the single implementation; it is strictly read-only: nothing is signed, re-signed or
 * re-verified, and no field is ever written.
 */
public final class AvbFooter {
    public static final int SIZE = 64;
    /** Field offsets inside the 64-byte footer; shared by readers and by the rebuilder's writer. */
    public static final int OFFSET_ORIGINAL_IMAGE_SIZE = 12;
    public static final int OFFSET_VBMETA_OFFSET = 20;
    public static final int OFFSET_VBMETA_SIZE = 28;
    /** Smallest plausible vbmeta blob; guards against a footer that points at a stub. */
    public static final int MIN_VBMETA = 256;

    public final boolean present;
    public final long versionMajor, versionMinor;
    public final long originalImageSize, vbmetaOffset, vbmetaSize;
    /** Reserved tail bytes 36..64 are all zero (spec-required; reported, not enforced). */
    public final boolean reservedZero;

    private AvbFooter(boolean present, long major, long minor, long originalSize,
                      long vbmetaOffset, long vbmetaSize, boolean reservedZero) {
        this.present = present;
        this.versionMajor = major; this.versionMinor = minor;
        this.originalImageSize = originalSize; this.vbmetaOffset = vbmetaOffset;
        this.vbmetaSize = vbmetaSize; this.reservedZero = reservedZero;
    }

    private static final AvbFooter ABSENT = new AvbFooter(false, 0, 0, 0, 0, 0, true);

    /** Reads the last 64 bytes of {@code image}; an image without {@code AVBf} returns {@link #absent()}. */
    public static AvbFooter parse(File image) throws IOException {
        long length = image.length();
        if (length < SIZE) return ABSENT;
        byte[] footer = new byte[SIZE];
        try (RandomAccessFile input = new RandomAccessFile(image, "r")) {
            input.seek(length - SIZE);
            input.readFully(footer);
        }
        return parse(footer);
    }

    /** Parses an already-read 64-byte footer; anything shorter or without the magic is absent. */
    public static AvbFooter parse(byte[] footer) {
        if (footer == null || footer.length < SIZE) return ABSENT;
        if (footer[0] != 'A' || footer[1] != 'V' || footer[2] != 'B' || footer[3] != 'f') return ABSENT;
        boolean reservedZero = true;
        for (int index = 36; index < SIZE; index++) {
            if (footer[index] != 0) { reservedZero = false; break; }
        }
        return new AvbFooter(true, u32(footer, 4), u32(footer, 8),
                u64(footer, OFFSET_ORIGINAL_IMAGE_SIZE), u64(footer, OFFSET_VBMETA_OFFSET),
                u64(footer, OFFSET_VBMETA_SIZE), reservedZero);
    }

    public static AvbFooter absent() { return ABSENT; }

    /**
     * Self-consistency against the real file length: the original image and the vbmeta region must
     * both live inside the partition and the vbmeta region must follow the original image.
     */
    public boolean valid(long fileSize) { return invalidReason(fileSize).isEmpty(); }

    /** Empty when valid; otherwise a stable code, e.g. {@code AVB_VBMETA_OFFSET_RANGE}. */
    public String invalidReason(long fileSize) {
        if (!present) return "";
        if (fileSize < SIZE) return "AVB_PARTITION_TOO_SMALL";
        if (originalImageSize < 0 || originalImageSize > fileSize) return "AVB_ORIGINAL_SIZE_RANGE";
        if (vbmetaOffset < originalImageSize || vbmetaOffset > fileSize - SIZE) return "AVB_VBMETA_OFFSET_RANGE";
        if (vbmetaSize < MIN_VBMETA) return "AVB_VBMETA_SIZE_RANGE";
        if (vbmetaSize > fileSize - SIZE - vbmetaOffset) return "AVB_VBMETA_SIZE_RANGE";
        return "";
    }

    public String toJson() {
        if (!present) return "{\"present\":false}";
        return String.format(Locale.ROOT,
                "{\"present\":true,\"versionMajor\":%d,\"versionMinor\":%d,\"originalImageSize\":%d,"
                        + "\"vbmetaOffset\":%d,\"vbmetaSize\":%d,\"reservedZero\":%s}",
                versionMajor, versionMinor, originalImageSize, vbmetaOffset, vbmetaSize, reservedZero);
    }

    private static long u32(byte[] bytes, int offset) {
        return ((bytes[offset] & 255L) << 24) | ((bytes[offset + 1] & 255L) << 16)
                | ((bytes[offset + 2] & 255L) << 8) | (bytes[offset + 3] & 255L);
    }

    private static long u64(byte[] bytes, int offset) {
        long value = 0;
        for (int index = 0; index < 8; index++) value = (value << 8) | (bytes[offset + index] & 255L);
        return value;
    }
}
