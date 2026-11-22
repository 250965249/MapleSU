package dev.maplesu.installer;

import java.nio.file.Path;
import java.util.Objects;

/**
 * One immutable plan step (02-switch-contract §4.3): write {@link #image} into {@link #partition}
 * and keep {@link #preImage} as the only rollback source.
 *
 * <p>Both images must be exactly {@link #size} bytes; the prepare validation rejects short or long
 * files, so the {@link BlockDeviceTransaction} zero-fill branch can never run for a switch.</p>
 */
public final class SwitchStep {
    public final String partition;
    public final StepRole role;
    /** Must equal the real partition length; also equals {@code Files.size(image)}. */
    public final long size;
    public final Path image;
    public final String imageSha256;
    /** Full pre-switch content; the only rollback source. */
    public final Path preImage;
    public final String preSha256;
    /** Expected tail probe of the written target (02 §4.5.1). */
    public final String tailSha256;

    public SwitchStep(String partition, StepRole role, long size, Path image, String imageSha256,
                      Path preImage, String preSha256, String tailSha256) {
        this.partition = Objects.requireNonNull(partition, "partition");
        this.role = Objects.requireNonNull(role, "role");
        this.size = size;
        this.image = Objects.requireNonNull(image, "image");
        this.imageSha256 = Objects.requireNonNull(imageSha256, "imageSha256");
        this.preImage = Objects.requireNonNull(preImage, "preImage");
        this.preSha256 = Objects.requireNonNull(preSha256, "preSha256");
        this.tailSha256 = Objects.requireNonNull(tailSha256, "tailSha256");
    }

    /** Journal step id: 4c restores the source partition, 4d writes the target candidate. */
    public String stepId() {
        return role == StepRole.RESTORE_BASELINE ? "4c" : "4d";
    }

    @Override
    public String toString() {
        return partition + ":" + role + ":" + size;
    }
}
