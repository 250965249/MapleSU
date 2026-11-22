package dev.maplesu.manager.runtime;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Test APK entry point, launched as its real UID independently of the Manager process. */
public final class StandaloneSuLifecycleProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("existing|new|denied");
        boolean existing = "existing".equals(args[0]);
        boolean denied = "denied".equals(args[0]);
        String command = existing
                ? "id -u; printf SESSION_STARTED; printf '\\n'; sleep 12; id -u; getenforce"
                : "id -u; getenforce; exit 37";
        Process child = new ProcessBuilder("/dev/maplesu/bin/su", "-c", command)
                .redirectErrorStream(true).start();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(child.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            StringBuilder transcript = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
                System.out.flush();
                transcript.append(line).append('\n');
            }
            if (!child.waitFor(20, TimeUnit.SECONDS)) throw new IllegalStateException("su timeout");
            int expected = denied ? 77 : existing ? 0 : 37;
            if (child.exitValue() != expected || (!denied && !transcript.toString().contains("Enforcing")))
                throw new IllegalStateException("su exit=" + child.exitValue() + " expected=" + expected);
            System.out.println("LIFECYCLE_PROBE_PASSED mode=" + args[0] + " exit=" + child.exitValue());
        } finally { child.destroyForcibly(); }
    }
}
