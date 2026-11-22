package dev.maplesu.manager.jailbreak;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

/**
 * Measured support matrix for the built-in providers.
 *
 * <p>A KMI-compatible kernel is a candidate, never an exact target: the chain
 * patches a vendor build's own text and dispatches that build's own helper, so
 * "the release parses to android15-6.6" only says the module was built for a
 * family. An exact target is bound to the release, the build fingerprint, the
 * SoC and the security patch it was actually measured on, and everything else is
 * refused with the precise reason instead of being admitted as "close enough".
 *
 * <p>Every entry cites the evidence directory that produced it; adding an entry
 * without a measurement would be a false support claim.
 */
public final class JailbreakTargets {
    public static final String PROVIDER_DIRTYFRAG = "dirtyfrag";
    public static final String PROVIDER_GHOSTLOCK = "ghostlock";

    public record Target(String provider, String kernelRelease, String fingerprint, String soc,
                         String securityPatch, String evidence) {}

    public enum Verdict {
        /** The exact measured build; the provider may run. */
        VERIFIED_TARGET,
        /** Same KMI family, different build: refused, never silently accepted. */
        KMI_CANDIDATE,
        /** Not even the family is packaged. */
        UNSUPPORTED
    }

    /**
     * Only builds that returned UID 0 through the real provider chain and passed
     * the restoration gate are listed.
     */
    private static final List<Target> VERIFIED = List.of(
            new Target(PROVIDER_DIRTYFRAG,
                    "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k",
                    "OnePlus/PLQ110/OP6113L1:16/BP2A.250605.015/"
                            + "B.48f7ba8-2511085-251139b:user/release-keys",
                    "SM8750", "2026-05-01",
                    ".analysis/jailbreak-dual-mode-20261026/provider-device/agent4"));

    private JailbreakTargets() {}

    public static List<Target> verified() { return VERIFIED; }

    public static Verdict verdict(String provider, String release, String fingerprint, String soc,
                                 String securityPatch, boolean kmiPackaged) {
        for (Target target : VERIFIED) {
            if (!target.provider().equals(provider)) continue;
            if (!target.kernelRelease().equals(release)) continue;
            if (!target.fingerprint().equals(fingerprint)) continue;
            if (!target.soc().equals(soc)) continue;
            if (!target.securityPatch().equals(securityPatch)) continue;
            return Verdict.VERIFIED_TARGET;
        }
        return kmiPackaged ? Verdict.KMI_CANDIDATE : Verdict.UNSUPPORTED;
    }

    /** Stable identity of one exact target, recorded with every attempt. */
    public static String targetId(String provider, String release, String fingerprint, String soc,
                                  String securityPatch) throws IOException {
        final MessageDigest digest;
        try { digest = MessageDigest.getInstance("SHA-256"); }
        catch (Exception error) { throw new IOException("DIRTYFRAG_DIGEST_UNAVAILABLE", error); }
        String identity = provider + "\n" + release + "\n" + fingerprint + "\n" + soc + "\n"
                + securityPatch;
        StringBuilder hex = new StringBuilder(64);
        for (byte value : digest.digest(identity.getBytes(StandardCharsets.UTF_8)))
            hex.append(Character.forDigit((value >>> 4) & 15, 16))
                    .append(Character.forDigit(value & 15, 16));
        return hex.toString();
    }
}
