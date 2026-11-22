package dev.maplesu.image;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** Uses the production codec entry points, with a valid input and an existing cancellation. */
public final class CodecCancellationTest {
    private CodecCancellationTest() {}

    static int check() throws Exception {
        List<String> failures = new ArrayList<>();
        int passed = 0;
        for (String format : new String[]{"RAW_ARM64", "GZIP", "LZ4_LEGACY"}) {
            byte[] raw = new byte[1024];
            byte[] encoded = KernelCompression.encode(raw, format);
            for (boolean encoding : new boolean[]{true, false}) {
                String operation = format + (encoding ? " encode" : " decode");
                Thread.currentThread().interrupt();
                try {
                    if (encoding) KernelCompression.encode(raw, format);
                    else KernelCompression.decode(encoded, format, raw.length);
                    failures.add(operation + " ignored cancellation");
                } catch (IOException exception) {
                    if (!"CANCELLED".equals(exception.getMessage()) || !Thread.currentThread().isInterrupted()) {
                        failures.add(operation + " changed the cancellation contract");
                    } else passed++;
                } finally {
                    Thread.interrupted();
                }
            }
        }
        if (!failures.isEmpty()) throw new AssertionError(String.join("; ", failures));
        return passed;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("PASS " + check() + " codec cancellation checks");
    }
}
