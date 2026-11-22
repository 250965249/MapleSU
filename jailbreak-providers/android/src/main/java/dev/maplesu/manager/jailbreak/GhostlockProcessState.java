package dev.maplesu.manager.jailbreak;

/** Provider lifetime is separate from the detached worker's restore lifetime. */
final class GhostlockProcessState {
    private volatile boolean dispatched;
    private volatile boolean statusDisabled;
    private volatile String stage = "starting";

    void observe(String line) {
        if ("\036GLK_STATUS_DISABLED".equals(line)) statusDisabled = true;
        if (line.matches("\036GLK_STATUS [a-z0-9_]+ (in_progress|completed)")) {
            stage = line.substring(12);
            if ("\036GLK_STATUS maplesu_dispatch completed".equals(line)) dispatched = true;
        }
    }

    String failure(Integer exitCode) {
        if (exitCode == null || dispatched || (statusDisabled && exitCode == 0)) return null;
        return "GHOSTLOCK_PROVIDER_EXIT_BEFORE_HANDOVER:" + exitCode;
    }

    String stage() { return stage; }
}
