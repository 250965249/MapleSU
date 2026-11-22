package dev.maplesu.installer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable, host-verifiable switch plan (02-switch-contract §4.3): which partitions change, in
 * which role order, from which full-length source images, with which pre-switch images.
 *
 * <p>{@link #planSha256} is the SHA-256 of {@link #canonicalForm}; it is order sensitive and does
 * not depend on a JSON library, so the service can independently recompute it (§5.6 step 8).</p>
 */
public final class SwitchPlan {
    public static final String SCHEMA = "MAPLESU_SWITCH_PLAN_V1";
    public static final String DEVICE_SLOT = "slotSuffix";
    public static final String DEVICE_FIRMWARE = "firmware";
    public static final String DEVICE_KERNEL = "kernelRelease";
    public static final String DEVICE_SELINUX = "selinux";
    public static final List<String> DEVICE_KEYS =
            List.of(DEVICE_SLOT, DEVICE_FIRMWARE, DEVICE_KERNEL, DEVICE_SELINUX);

    public final String schema;
    public final String switchId;
    public final WorkMode fromMode;
    public final WorkMode toMode;
    public final String baselineId;
    public final String planSha256;
    /** Boot id observed at begin; verify must see a different one (§3.6 6.2). */
    public final String startBootId;
    /** Expected device facts; verify compares the observed facts against these (§3.2 device). */
    public final Map<String, String> device;
    /** Already ordered by {@link SwitchPartitionLayout#writeOrder(WorkMode)}. */
    public final List<SwitchStep> steps;

    /** prepare input; the plan sha and step ordering are computed by {@code prepare}. */
    public static final class Request {
        public final String schema;
        public final String switchId;
        public final WorkMode fromMode;
        public final WorkMode toMode;
        public final String baselineId;
        public final String startBootId;
        public final Map<String, String> device;
        public final List<SwitchStep> steps;

        public Request(String schema, String switchId, WorkMode fromMode, WorkMode toMode,
                       String baselineId, String startBootId, Map<String, String> device,
                       List<SwitchStep> steps) {
            this.schema = schema;
            this.switchId = switchId;
            this.fromMode = fromMode;
            this.toMode = toMode;
            this.baselineId = baselineId;
            this.startBootId = startBootId == null ? "" : startBootId;
            this.device = device == null ? Map.of() : Map.copyOf(device);
            this.steps = steps == null ? null : List.copyOf(steps);
        }

        /** Host fixtures that do not exercise verify can omit the device snapshot. */
        public Request(String schema, String switchId, WorkMode fromMode, WorkMode toMode,
                       String baselineId, List<SwitchStep> steps) {
            this(schema, switchId, fromMode, toMode, baselineId, "", Map.of(), steps);
        }
    }

    private SwitchPlan(String schema, String switchId, WorkMode fromMode, WorkMode toMode,
                       String baselineId, String planSha256, String startBootId,
                       Map<String, String> device, List<SwitchStep> steps) {
        this.schema = schema;
        this.switchId = switchId;
        this.fromMode = fromMode;
        this.toMode = toMode;
        this.baselineId = baselineId;
        this.planSha256 = planSha256;
        this.startBootId = startBootId == null ? "" : startBootId;
        this.device = Map.copyOf(device);
        this.steps = List.copyOf(steps);
    }

    /** Builds a plan and computes its canonical sha; structural validation stays in prepare. */
    public static SwitchPlan create(Request request) throws SwitchFailure {
        if (request == null) throw new SwitchFailure("SWITCH_PLAN_INVALID", "missing request");
        Objects.requireNonNull(request.steps, "steps");
        String sha = SwitchHashes.sha256Hex(canonicalForm(request.switchId, request.fromMode,
                request.toMode, request.baselineId, request.steps));
        return new SwitchPlan(request.schema, request.switchId, request.fromMode, request.toMode,
                request.baselineId, sha, request.startBootId, request.device, request.steps);
    }

    /**
     * Canonical, order-sensitive field string. Deliberately excludes host paths and the device
     * snapshot: only switch semantics (which bytes into which partition, in which role order) are
     * bound by the plan sha; the device snapshot rides along for verify and lives in switch.json.
     */
    public static String canonicalForm(String switchId, WorkMode fromMode, WorkMode toMode,
                                       String baselineId, List<SwitchStep> steps) {
        StringBuilder result = new StringBuilder(512);
        result.append("schema=").append(SCHEMA).append('\n');
        result.append("switchId=").append(nullToEmpty(switchId)).append('\n');
        result.append("fromMode=").append(fromMode).append('\n');
        result.append("toMode=").append(toMode).append('\n');
        result.append("baselineId=").append(nullToEmpty(baselineId)).append('\n');
        if (steps != null) {
            for (int index = 0; index < steps.size(); index++) {
                SwitchStep step = steps.get(index);
                result.append("step.").append(index).append(".partition=").append(step.partition).append('\n');
                result.append("step.").append(index).append(".role=").append(step.role).append('\n');
                result.append("step.").append(index).append(".size=").append(step.size).append('\n');
                result.append("step.").append(index).append(".imageSha256=").append(step.imageSha256).append('\n');
                result.append("step.").append(index).append(".preSha256=").append(step.preSha256).append('\n');
                result.append("step.").append(index).append(".tailSha256=").append(step.tailSha256).append('\n');
            }
        }
        return result.toString();
    }

    /** Flat (string to string) transport form; the manager AIDL Bundle carries the same fields. */
    public Map<String, String> flatFields() {
        Map<String, String> flat = new LinkedHashMap<>();
        flat.put("schema", schema);
        flat.put("switchId", switchId);
        flat.put("fromMode", String.valueOf(fromMode));
        flat.put("toMode", String.valueOf(toMode));
        flat.put("baselineId", baselineId);
        flat.put("startBootId", startBootId);
        for (String key : DEVICE_KEYS) flat.put("device." + key, device.getOrDefault(key, ""));
        flat.put("step.count", Integer.toString(steps.size()));
        flat.put("planSha256", planSha256);
        for (int index = 0; index < steps.size(); index++) {
            SwitchStep step = steps.get(index);
            String prefix = "step." + index + ".";
            flat.put(prefix + "partition", step.partition);
            flat.put(prefix + "role", String.valueOf(step.role));
            flat.put(prefix + "size", Long.toString(step.size));
            flat.put(prefix + "image", step.image.toString());
            flat.put(prefix + "imageSha256", step.imageSha256);
            flat.put(prefix + "preImage", step.preImage.toString());
            flat.put(prefix + "preSha256", step.preSha256);
            flat.put(prefix + "tailSha256", step.tailSha256);
        }
        return flat;
    }

    /** Structural re-parse of the transport form; validates the exact key set and recomputes sha. */
    public static SwitchPlan parse(Map<String, String> flatFields) throws IOException {
        if (flatFields == null) throw new SwitchFailure("SWITCH_PLAN_INVALID", "missing flat fields");
        Map<String, String> flat = new LinkedHashMap<>(flatFields);
        String schema = required(flat, "schema");
        String switchId = required(flat, "switchId");
        WorkMode fromMode = mode(required(flat, "fromMode"));
        WorkMode toMode = mode(required(flat, "toMode"));
        String baselineId = required(flat, "baselineId");
        String startBootId = required(flat, "startBootId");
        Map<String, String> device = new LinkedHashMap<>();
        for (String key : DEVICE_KEYS) device.put(key, required(flat, "device." + key));
        int count;
        try {
            count = Integer.parseInt(required(flat, "step.count"));
        } catch (NumberFormatException invalid) {
            throw new SwitchFailure("SWITCH_PLAN_INVALID", "step.count");
        }
        if (count < 0 || count > 16) throw new SwitchFailure("SWITCH_PLAN_INVALID", "step.count");
        List<SwitchStep> steps = new ArrayList<>();
        for (int index = 0; index < count; index++) {
            String prefix = "step." + index + ".";
            String partition = required(flat, prefix + "partition");
            StepRole role;
            try {
                role = StepRole.valueOf(required(flat, prefix + "role"));
            } catch (IllegalArgumentException invalid) {
                throw new SwitchFailure("SWITCH_PLAN_INVALID", prefix + "role");
            }
            long size;
            try {
                size = Long.parseLong(required(flat, prefix + "size"));
            } catch (NumberFormatException invalid) {
                throw new SwitchFailure("SWITCH_PLAN_INVALID", prefix + "size");
            }
            steps.add(new SwitchStep(partition, role, size, Path.of(required(flat, prefix + "image")),
                    required(flat, prefix + "imageSha256"), Path.of(required(flat, prefix + "preImage")),
                    required(flat, prefix + "preSha256"), required(flat, prefix + "tailSha256")));
        }
        String expectedSha = required(flat, "planSha256");
        String computedSha = SwitchHashes.sha256Hex(canonicalForm(switchId, fromMode, toMode, baselineId, steps));
        if (!computedSha.equals(expectedSha)) {
            throw new SwitchFailure("SWITCH_PLAN_INVALID", "planSha256 mismatch");
        }
        if (!flat.isEmpty()) {
            throw new SwitchFailure("SWITCH_PLAN_INVALID", "unexpected plan key " + flat.keySet().iterator().next());
        }
        return new SwitchPlan(schema, switchId, fromMode, toMode, baselineId, computedSha,
                startBootId, device, steps);
    }

    /** Convenience used by prepare: full-length regular file with the expected digest. */
    static boolean isFullLength(Path image, long size) {
        try {
            return image != null
                    && Files.isRegularFile(image, LinkOption.NOFOLLOW_LINKS)
                    && Files.size(image) == size;
        } catch (IOException unreadable) {
            return false;
        }
    }

    private static String required(Map<String, String> flat, String key) throws SwitchFailure {
        String value = flat.remove(key);
        if (value == null) throw new SwitchFailure("SWITCH_PLAN_INVALID", "missing " + key);
        return value;
    }

    private static WorkMode mode(String value) throws SwitchFailure {
        try {
            return WorkMode.valueOf(value);
        } catch (IllegalArgumentException invalid) {
            throw new SwitchFailure("SWITCH_PLAN_INVALID", "mode " + value);
        }
    }

    private static String nullToEmpty(String value) { return value == null ? "" : value; }
}
