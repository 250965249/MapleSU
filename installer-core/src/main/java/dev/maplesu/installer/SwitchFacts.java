package dev.maplesu.installer;

/**
 * Device facts observed by the service (02-switch-contract §3.6 / §4.4). Host tests provide fakes;
 * the Android implementation reads {@code boot_id}, slot suffix, build id and {@code uname -r}.
 */
public interface SwitchFacts {
    /** {@code /proc/sys/kernel/random/boot_id}; must change across the switch reboot. */
    String bootId();

    /** {@code ro.boot.slot_suffix} ({@code ""}, {@code "_a"} or {@code "_b"}). */
    String slotSuffix();

    /** {@code ro.build.display.id}. */
    String firmware();

    /** {@code uname -r}. */
    String kernelRelease();

    /** Must be {@code "Enforcing"}; anything else is a device change (S0-12 / §3.6). */
    String selinux();
}
