package dev.maplesu.image;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class VendorBootInspectorTest {
    private static int passed;
    private static byte[] fixture(int version, int page) {
        byte[] b = new byte[32768];
        ByteBuffer h = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
        h.put("VNDRBOOT".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        h.putInt(8, version).putInt(12, page).putInt(24, 64).putInt(2096, version == 3 ? 2112 : 2128).putInt(2100, 8);
        if (version == 4) {
            int start = ((2128 + page - 1) / page + 2) * page;
            h.putInt(2112, 216).putInt(2116, 2).putInt(2120, 108).putInt(2124, 4);
            h.putInt(start, 32).putInt(start + 4, 0).putInt(start + 108, 32).putInt(start + 112, 32);
        }
        return b;
    }
    private static VendorBootInspector.Report inspect(byte[] bytes) throws Exception {
        Path file = Files.createTempFile("vivo-vendor-test-", ".img");
        try { Files.write(file, bytes); return VendorBootInspector.inspect(file.toFile()); }
        finally { Files.delete(file); }
    }
    private static void reject(byte[] bytes) throws Exception {
        try { inspect(bytes); throw new AssertionError("invalid fixture accepted"); }
        catch (java.io.IOException expected) { passed++; }
    }
    public static void main(String[] args) throws Exception {
        for (int v : new int[]{3,4}) for (int p : new int[]{2048,4096}) {
            VendorBootInspector.Report report = inspect(fixture(v,p));
            if (report.headerVersion != v || report.ramdiskSize != 64 || report.fragmentCount != (v == 3 ? 1 : 2) || report.sha256.length() != 64)
                throw new AssertionError("header mismatch");
            passed++;
        }
        byte[] b = fixture(4,4096); b[0] = 0; reject(b);
        b = fixture(4,4096); ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(2116,4097); reject(b);
        b = fixture(4,4096); ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(12288+112,31); reject(b);
        b = fixture(4,4096); ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(12288+108,33); reject(b);
        reject(Arrays.copyOf(fixture(4,4096), 12300));
        reject(Arrays.copyOf(fixture(3,4096), 8193));
        System.out.println("VendorBootInspector: " + passed + " checks passed");
    }
}
