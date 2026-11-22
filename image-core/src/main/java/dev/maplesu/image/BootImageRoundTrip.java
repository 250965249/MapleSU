package dev.maplesu.image;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.util.Locale;

/** Lossless no-change rebuild plus an independent codec round trip. Never creates a patched image. */
public final class BootImageRoundTrip {
    private BootImageRoundTrip() {}

    public static final class Report {
        public final BootImageInspector.Report image;
        public final int decodedKernelSize;
        public final String decodedKernelSha256;
        public final String kernelRelease;

        private Report(BootImageInspector.Report image, int size, String hash, String release) {
            this.image = image;
            this.decodedKernelSize = size;
            this.decodedKernelSha256 = hash;
            this.kernelRelease = release;
        }

        public String toJson() {
            return String.format(Locale.ROOT,
                    "{\"schemaVersion\":1,\"operation\":\"LOSSLESS_ROUNDTRIP\","
                    + "\"image\":%s,\"decodedKernelSize\":%d,\"decodedKernelSha256\":\"%s\","
                    + "\"kernelRelease\":\"%s\",\"codecRoundTripVerified\":true,"
                    + "\"containerByteIdentical\":true,\"sourceUnchanged\":true,"
                    + "\"flashableCandidate\":false}",
                    image.toJson(), decodedKernelSize, decodedKernelSha256, kernelRelease);
        }
    }

    public static Report verify(File source, File scratchDirectory) throws IOException {
        BootImageInspector.Report image = BootImageInspector.inspect(source);
        if (image.kernelSize == 0) throw new IOException("NO_KERNEL");
        if (image.kernelSize > KernelCompression.MAX_KERNEL_BYTES) throw new IOException("KERNEL_SIZE_LIMIT");
        byte[] compressed = new byte[(int) image.kernelSize];
        try (RandomAccessFile input = new RandomAccessFile(source, "r")) {
            input.seek(image.kernelOffset);
            input.readFully(compressed);
        }
        KernelCheck kernel = checkCodec(compressed, image.compression);
        // Reuse the original compressed component when payload is unchanged. This preserves
        // signature bytes, nonzero alignment, ramdisk, AVB/trailing data and partition padding.
        File rebuilt = File.createTempFile("maplesu-roundtrip-", ".bin", scratchDirectory);
        try {
            try (RandomAccessFile input = new RandomAccessFile(source, "r");
                 RandomAccessFile output = new RandomAccessFile(rebuilt, "rw")) {
                copy(input, output, image.kernelOffset);
                output.write(compressed);
                input.seek(image.kernelOffset + image.kernelSize);
                copy(input, output, image.fileSize - input.getFilePointer());
                output.getFD().sync();
            }
            BootImageInspector.Report result = BootImageInspector.inspect(rebuilt);
            if (result.fileSize != image.fileSize || !image.sha256.equals(result.sha256)) {
                throw new IOException("ROUNDTRIP_MISMATCH");
            }
            BootImageInspector.Report after = BootImageInspector.inspect(source);
            if (!image.sha256.equals(after.sha256) || after.fileSize != image.fileSize) {
                throw new IOException("SOURCE_CHANGED");
            }
            return new Report(image, kernel.size, kernel.hash, kernel.release);
        } finally {
            Files.deleteIfExists(rebuilt.toPath());
        }
    }

    private static KernelCheck checkCodec(byte[] compressed, String format) throws IOException {
        byte[] raw = KernelCompression.decode(compressed, format, KernelCompression.MAX_KERNEL_BYTES);
        KernelCheck check = new KernelCheck(raw.length, sha256(raw), release(raw));
        byte[] encoded = KernelCompression.encodeKernelComponent(raw, compressed, format);
        // Keep the new raw buffer in a separate scope to allow collection on Android.
        raw = null;
        byte[] decoded = KernelCompression.decode(encoded, format, KernelCompression.MAX_KERNEL_BYTES);
        if (decoded.length != check.size || !check.hash.equals(sha256(decoded))) {
            throw new IOException("CODEC_ROUNDTRIP_MISMATCH");
        }
        return check;
    }

    private static final class KernelCheck {
        final int size;
        final String hash, release;
        KernelCheck(int size, String hash, String release) {
            this.size = size; this.hash = hash; this.release = release;
        }
    }

    private static void copy(RandomAccessFile in, RandomAccessFile out, long remaining) throws IOException {
        byte[] buffer = new byte[64 * 1024];
        while (remaining > 0) {
            if (Thread.currentThread().isInterrupted()) throw new IOException("CANCELLED");
            int count = in.read(buffer, 0, (int) Math.min(buffer.length, remaining));
            if (count < 0) throw new IOException("SOURCE_CHANGED");
            out.write(buffer, 0, count);
            remaining -= count;
        }
    }

    public static String sha256(byte[] bytes) {
        return KernelIdentity.sha256(bytes);
    }

    /**
     * Release for this report. Delegates to {@link KernelIdentity}, the single implementation the
     * Ultra path and {@code BootKernelVersion} also use; an unreadable banner still reads "UNKNOWN"
     * and two distinct banners still read "AMBIGUOUS" so callers stay fail-closed.
     */
    private static String release(byte[] bytes) {
        return KernelIdentity.describeRelease(bytes);
    }
}
