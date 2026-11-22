import dev.maplesu.image.BootImageInspector;
import dev.maplesu.image.KernelCompression;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;

/** Decode with the production image-core, including legacy LZ4 and modern containers. */
public final class ImageCredentialDecode {
    public static void main(String[] args) throws Exception {
        var image = new File(args[0]);
        var report = BootImageInspector.inspect(image);
        if (report.kernelSize <= 0 || report.kernelSize > KernelCompression.MAX_KERNEL_BYTES)
            throw new IllegalArgumentException("IMAGE_KERNEL_SIZE_INVALID");
        var container = new byte[(int) report.kernelSize];
        try (var input = new RandomAccessFile(image, "r")) {
            input.seek(report.kernelOffset);
            input.readFully(container);
        }
        Files.write(Path.of(args[1]), KernelCompression.decode(container, report.compression,
            KernelCompression.MAX_KERNEL_BYTES));
    }
}
