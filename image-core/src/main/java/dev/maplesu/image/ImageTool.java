package dev.maplesu.image;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/** The same implementation used by Manager; stdout contains one JSON result. */
public final class ImageTool {
    private ImageTool() {}

    public static int run(String[] args) {
        boolean ramdisk = args.length == 4 && ("rebuild-ramdisk".equals(args[0]) || "rebuild-ramdisk-v4".equals(args[0]));
        boolean rebuild = args.length == 4 && ("rebuild".equals(args[0]) || "rebuild-v4".equals(args[0]) || ramdisk);
        boolean diff = args.length == 3 && "diff".equals(args[0]);
        if (!rebuild && !diff && (args.length != 2 || !("inspect".equals(args[0]) || "roundtrip".equals(args[0])))) {
            System.err.println("Usage: java -jar image-core.jar <inspect|roundtrip> <boot.img>"
                    + " | diff <a.img> <b.img>"
                    + " | rebuild[-v4] <boot.img> <kernel> <new-output.img>"
                    + " | rebuild-ramdisk[-v4] <boot-or-init_boot.img> <encoded-ramdisk> <new-output.img>");
            return 2;
        }
        try {
            File source = new File(args[1]);
            if (diff) {
                System.out.println(BootImageEquivalence.diff(source, new File(args[2])).toJson());
            } else if (rebuild) {
                BootImageRebuilder.Report report = ramdisk
                        ? "rebuild-ramdisk-v4".equals(args[0])
                        ? BootImageRebuilder.rebuildRamdiskV4(source, new File(args[2]), new File(args[3]))
                        : BootImageRebuilder.rebuildRamdisk(source, new File(args[2]), new File(args[3]))
                        : "rebuild-v4".equals(args[0])
                        ? BootImageRebuilder.rebuildV4(source, new File(args[2]), new File(args[3]))
                        : BootImageRebuilder.rebuild(source, new File(args[2]), new File(args[3]));
                System.out.println(report.toJson());
            } else if ("inspect".equals(args[0])) {
                System.out.println(BootImageInspector.inspect(source).toJson());
            } else {
                File scratch = Files.createTempDirectory("maplesu-").toFile();
                try {
                    System.out.println(BootImageRoundTrip.verify(source, scratch).toJson());
                } finally {
                    Files.delete(scratch.toPath());
                }
            }
            return 0;
        } catch (IOException exception) {
            // Never echo input paths or arbitrary untrusted strings in exported diagnostics.
            System.err.println("IMAGE_OPERATION_FAILED");
            return 3;
        }
    }

    public static void main(String[] args) { System.exit(run(args)); }
}
