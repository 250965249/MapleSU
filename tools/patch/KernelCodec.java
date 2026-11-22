package dev.maplesu.image;

import java.nio.file.Files;
import java.nio.file.Path;

/** Minimal codec driver for the offline candidate builder: decode/encode the kernel component. */
public final class KernelCodec {
    private KernelCodec() {}

    public static void main(String[] args) throws Exception {
        if ((args.length != 3 && args.length != 4)
                || !(args[0].equals("decode") || args[0].equals("encode"))) {
            System.err.println("usage: KernelCodec decode|encode <in> <out> [format]");
            System.exit(2);
        }
        byte[] in = Files.readAllBytes(Path.of(args[1]));
        String format = args.length == 4 ? args[3] : "LZ4_LEGACY";
        byte[] out = args[0].equals("decode")
                ? KernelCompression.decode(in, format, KernelCompression.MAX_KERNEL_BYTES)
                : KernelCompression.encode(in, format);
        Files.write(Path.of(args[2]), out);
        System.out.println(args[0].toUpperCase() + "_OK in=" + in.length + " out=" + out.length);
    }
}
