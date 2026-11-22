package dev.maplesu.manager.jailbreak;

import android.content.Context;
import android.net.IpSecAlgorithm;
import android.net.IpSecManager;
import android.net.IpSecTransform;

import java.io.Closeable;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Direct-App resource setup from pinned DirtyFrag ExploitRunner.java.
 * Acquisition is separate from process execution, module identity, restoration
 * and daemon state. No ADB, Shizuku, su or preferences are used.
 */
public final class DirtyfragIpSecSession implements Closeable {
    private final IpSecManager.UdpEncapsulationSocket encap;
    private final IpSecManager.SecurityParameterIndex spi;
    private final IpSecTransform transform;
    private final DatagramSocket senderReservation;
    private final byte[] key;
    private final AtomicBoolean closed = new AtomicBoolean();

    private DirtyfragIpSecSession(IpSecManager.UdpEncapsulationSocket encap,
                                 IpSecManager.SecurityParameterIndex spi,
                                 IpSecTransform transform, DatagramSocket senderReservation, byte[] key) {
        this.encap = encap;
        this.spi = spi;
        this.transform = transform;
        this.senderReservation = senderReservation;
        this.key = key;
    }

    /** Caller keeps this session alive until native cleanup has completed. */
    public static DirtyfragIpSecSession open(Context context) throws Exception {
        if (context == null) throw new NullPointerException("context");
        IpSecManager manager = (IpSecManager) context.getSystemService(Context.IPSEC_SERVICE);
        if (manager == null) throw new IOException("DIRTYFRAG_IPSEC_SERVICE_MISSING");
        IpSecManager.UdpEncapsulationSocket encap = null;
        IpSecManager.SecurityParameterIndex spi = null;
        IpSecTransform transform = null;
        DatagramSocket sender = null;
        byte[] key = new byte[32];
        try {
            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            encap = manager.openUdpEncapsulationSocket();
            spi = manager.allocateSecurityParameterIndex(loopback);
            new SecureRandom().nextBytes(key);
            // Keep the upstream ephemeral sender-port selection while setup is
            // in progress; release it only when handing argv to the native owner.
            sender = new DatagramSocket();
            transform = new IpSecTransform.Builder(context)
                    .setEncryption(new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, key))
                    .setIpv4Encapsulation(encap, sender.getLocalPort())
                    .buildTransportModeTransform(loopback, spi);
            return new DirtyfragIpSecSession(encap, spi, transform, sender, key);
        } catch (Exception error) {
            closeAfterFailure(transform, error);
            closeAfterFailure(spi, error);
            closeAfterFailure(encap, error);
            closeAfterFailure(sender, error);
            Arrays.fill(key, (byte) 0);
            throw error;
        }
    }

    /**
     * Native first-stage flags only, not a ready-to-run product command.
     * The caller must apply exact target/module admission before process start.
     * Flags contain a per-session key; do not log or persist this list.
     */
    public synchronized List<String> nativeArguments() {
        if (closed.get()) throw new IllegalStateException("DIRTYFRAG_IPSEC_SESSION_CLOSED");
        if (senderReservation.isClosed()) throw new IllegalStateException("DIRTYFRAG_ARGUMENTS_ALREADY_TRANSFERRED");
        StringBuilder hex = new StringBuilder(64);
        for (byte value : key) hex.append(Character.forDigit((value >>> 4) & 15, 16))
                .append(Character.forDigit(value & 15, 16));
        int senderPort = senderReservation.getLocalPort();
        senderReservation.close();
        return List.of("--encap-port", Integer.toString(encap.getPort()),
                "--sender-port", Integer.toString(senderPort),
                "--spi", Integer.toUnsignedString(spi.getSpi()), "--aes-key", hex.toString());
    }

    /** Transform must be removed before releasing its SPI and encapsulation socket. */
    private static void closeAfterFailure(AutoCloseable resource, Exception primary) {
        if (resource != null) try { resource.close(); } catch (Exception error) { primary.addSuppressed(error); }
    }

    @Override public synchronized void close() throws IOException {
        if (!closed.compareAndSet(false, true)) return;
        try { transform.close(); }
        finally {
            try { spi.close(); }
            finally {
                try { encap.close(); }
                finally { senderReservation.close(); Arrays.fill(key, (byte) 0); }
            }
        }
    }
}
