package dev.maplesu.image;

import java.nio.file.Files;
import java.nio.file.Path;

/** Test-only bridge used by the independent Python/liblz4 oracle. */
public final class CodecInterop {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) throw new IllegalArgumentException("operation format input output");
        byte[] input = Files.readAllBytes(Path.of(args[2]));
        byte[] result;
        if ("encode".equals(args[0])) result = KernelCompression.encode(input, args[1]);
        else if ("decode".equals(args[0])) result = KernelCompression.decode(input, args[1], KernelCompression.MAX_KERNEL_BYTES);
        else throw new IllegalArgumentException("operation");
        Files.write(Path.of(args[3]), result);
    }
}
