package dev.maplesu.installer;

/** Mutable device facts for verify and device-changed cases. */
final class FakeSwitchFacts implements SwitchFacts {
    String bootId = "boot-2";
    String slotSuffix = "_a";
    String firmware = "fw-1";
    String kernelRelease = "5.10.198-android13-8-test";
    String selinux = "Enforcing";

    @Override public String bootId() { return bootId; }
    @Override public String slotSuffix() { return slotSuffix; }
    @Override public String firmware() { return firmware; }
    @Override public String kernelRelease() { return kernelRelease; }
    @Override public String selinux() { return selinux; }
}
