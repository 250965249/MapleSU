package dev.maplesu.manager.jailbreak;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class GhostlockWireHostTest {
    private static int checks;
    private static void check(boolean condition) {
        checks++;
        if (!condition) throw new AssertionError("check " + checks);
    }
    private static void rejected(Runnable action) {
        boolean failed = false;
        try { action.run(); } catch (IllegalArgumentException | IllegalStateException expected) { failed = true; }
        check(failed);
    }
    private static byte[] profile(String release, int route) {
        byte[] name = release.getBytes(StandardCharsets.US_ASCII);
        ByteBuffer bytes = ByteBuffer.allocate(18 + name.length).order(ByteOrder.LITTLE_ENDIAN);
        bytes.putInt(0x0d000721).putShort((short) 2).putShort((short) 1).putShort((short) 1);
        bytes.putShort((short) route).putShort((short) name.length).putShort((short) 0).put(name).putShort((short) 0);
        return bytes.array();
    }
    public static void main(String[] args) throws IOException {
        String release = "6.6.89-android15-8-fixture";
        for (int route = 1; route <= 3; route++) {
            byte[] original = profile(release, route), source = original.clone();
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            GhostlockWire wire = new GhostlockWire(source, release, output);
            Arrays.fill(source, (byte) 0);
            rejected(() -> {
                try { wire.acknowledge("\036GLK_STATUS w1a completed"); }
                catch (IOException error) { throw new AssertionError(error); }
            });
            wire.writeProfile();
            DataInputStream framed = new DataInputStream(new ByteArrayInputStream(output.toByteArray()));
            check(framed.readInt() == original.length);
            check(Arrays.equals(framed.readNBytes(original.length), original));
            check(framed.available() == 0);
            rejected(() -> {
                try { wire.writeProfile(); } catch (IOException error) { throw new AssertionError(error); }
            });
            for (String line : new String[]{"\036GLK_STATUS w1a in_progress",
                    "\036GLK_STATUS w1a completed", "\036GLK_STATUS w3 completed"}) {
                int before = output.size();
                check(wire.acknowledge(line));
                check(new String(Arrays.copyOfRange(output.toByteArray(), before, output.size()),
                        StandardCharsets.US_ASCII).equals("\036GLK_STATUS_ACK\n"));
            }
            int before = output.size();
            for (String line : new String[]{null, "", "KernelSU ready", "uid=0", "MJBL",
                    "\036GLK_STATUS_ACK", "\036GLK_STATUS w1a ready", "\036GLK_STATUS w1a completed\n",
                    "\036GLK_STATUS w1a completed\r", "\036GLK_STATUS w1a completed extra", "x".repeat(8192)})
                check(!wire.acknowledge(line));
            check(output.size() == before);
        }
        byte[] good = profile(release, 1);
        for (int length = 0; length < 18; length++) {
            byte[] truncated = Arrays.copyOf(good, length);
            rejected(() -> new GhostlockWire(truncated, release, new ByteArrayOutputStream()));
        }
        for (int index : new int[]{0, 4, 6, 8, 10, 12, 14, 16}) {
            byte[] changed = good.clone(); changed[index] ^= 0x7f;
            rejected(() -> new GhostlockWire(changed, release, new ByteArrayOutputStream()));
        }
        rejected(() -> new GhostlockWire(good, release + "x", new ByteArrayOutputStream()));
        rejected(() -> new GhostlockWire(good, "", new ByteArrayOutputStream()));
        rejected(() -> new GhostlockWire(good, "x\ny", new ByteArrayOutputStream()));
        rejected(() -> new GhostlockWire(new byte[(1 << 20) + 1], release, new ByteArrayOutputStream()));
        System.out.println("GhostlockWireHostTest: " + checks + " assertions passed");
    }
}
