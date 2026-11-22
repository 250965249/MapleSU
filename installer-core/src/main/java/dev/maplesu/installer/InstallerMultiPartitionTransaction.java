package dev.maplesu.installer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Multi-partition switch orchestrator (02-switch-contract §4). It never writes partition bytes:
 * every byte goes through {@link BlockDeviceTransaction#commit} / {@link
 * BlockDeviceTransaction#restore} on a held {@link BlockDeviceTransaction.Device} (red line 4).
 * Its own job is order, intent-before-write journaling, cross-partition reverse rollback, terminal
 * classification and read-only S6 verification.
 *
 * <p>{@code prepare} touches no partition; {@code commit} writes in plan order and rolls back in
 * reverse order on any failure; {@code rollback} restores reverse order using the pre images only;
 * {@code verify} re-reads each partition and refuses to accept "not rebooted" as success.</p>
 */
public final class InstallerMultiPartitionTransaction {
    public enum State { WRITTEN, ROLLED_BACK, RECOVERY_REQUIRED, VERIFIED }

    public static final class Result {
        public final State state;
        /** Empty on success; a {@code SWITCH_*}/{@code WRITE_*}/{@code VERIFY_*} code otherwise. */
        public final String code;
        /** Raw inner code for diagnosis (may be an {@code INSTALLER_*} code). */
        public final String detail;
        public final boolean rebootRequired;
        /** Partitions actually written this call, in plan order (empty for rollback results). */
        public final List<String> written;
        /** Partitions restored by rollback, in rollback order. */
        public final List<String> restored;
        /** Full digests observed during a completed commit, including idempotent skips. */
        public final Map<String, String> observedSha256;

        private Result(State state, String code, String detail, boolean rebootRequired,
                       List<String> written, List<String> restored) {
            this(state, code, detail, rebootRequired, written, restored, Map.of());
        }

        private Result(State state, String code, String detail, boolean rebootRequired,
                       List<String> written, List<String> restored, Map<String, String> observedSha256) {
            this.state = state;
            this.code = code == null ? "" : code;
            this.detail = detail == null ? "" : detail;
            this.rebootRequired = rebootRequired;
            this.written = List.copyOf(written);
            this.restored = List.copyOf(restored);
            this.observedSha256 = Map.copyOf(observedSha256);
        }

        @Override
        public String toString() {
            return state + "[" + code + "] written=" + written + " restored=" + restored;
        }
    }

    private InstallerMultiPartitionTransaction() {}

    /**
     * Read-only validation + plan creation (§4.3.1, all 14 checks) + one durable {@code PREPARED}
     * journal event. No partition bytes and no partition state are modified.
     */
    public static SwitchPlan prepare(SwitchPlan.Request request, SwitchPartitionProvider partitions,
                                     SwitchJournalSink journal) throws IOException {
        validateStructure(request);
        validateImages(request.steps);
        validatePartitions(request, partitions);
        SwitchPlan plan = SwitchPlan.create(request);
        journal.append(SwitchEvent.forPlan(plan, "S3", "prepare", "", SwitchOp.PREPARED,
                plan.planSha256, "", ""));
        return plan;
    }

    /**
     * Writes every step in plan order: content decision → idempotent skip → durable {@code INTENT}
     * → single-partition {@link BlockDeviceTransaction} → independent full readback + tail probe →
     * durable {@code DONE}. Recoverable failures after a write attempt enter reverse rollback;
     * failures before the first durable intent leave partitions untouched and propagate.
     */
    public static Result commit(SwitchPlan plan, SwitchPartitionProvider partitions,
                                SwitchJournalSink sink) throws IOException {
        if (plan == null) throw new SwitchFailure("SWITCH_PLAN_INVALID", "missing plan");
        Exception[] journalFailure = {null};
        SwitchJournalSink journal = event -> {
            if (journalFailure[0] instanceof IOException error) throw error;
            if (journalFailure[0] instanceof RuntimeException error) throw error;
            try { sink.append(event); } catch (IOException | RuntimeException error) {
                journalFailure[0] = error;
                throw error;
            }
        };
        List<String> written = new ArrayList<>();
        Map<String, String> observedSha256 = new LinkedHashMap<>();
        for (SwitchStep step : plan.steps) {
            Disposition disposition = Disposition.NOT_WRITTEN;
            try {
                WritablePartition partition = partition(partitions, step.partition);
                String observed = partition.sha256();
                if (observed.equals(step.imageSha256)) {
                    journal.append(event(plan, "S4", step.stepId(), step.partition, SwitchOp.SKIP,
                            step.imageSha256, observed, ""));
                    observedSha256.put(step.partition, observed);
                    continue;
                }
                if (!observed.equals(step.preSha256)) {
                    // External writer won the race: never overwrite, never assume rollback is safe.
                    return rollbackAndClassify(plan, partitions, journal, journalFailure, "WRITE_PARTITION_UNEXPECTED",
                            "SWITCH_PARTITION_UNEXPECTED", written, step, disposition);
                }
                // F3: the intent must be durable before the first partition byte.
                journal.append(event(plan, "S4", step.stepId(), step.partition, SwitchOp.INTENT,
                        step.imageSha256, observed, ""));
                disposition = Disposition.NEEDS_ROLLBACK;
                BlockDeviceTransaction.Result single;
                try (BlockDeviceTransaction.Device device = partition.open()) {
                    single = BlockDeviceTransaction.commit(device, step.image, step.imageSha256,
                            step.preImage, step.preSha256,
                            (state, error) -> journal.append(bdtEvent(plan, step, state, error)));
                    if (!"REBOOT_REQUIRED".equals(single.state)) {
                        disposition = "RESTORED".equals(single.state)
                                ? Disposition.ALREADY_RESTORED : Disposition.UNRESTORABLE;
                    }
                }
                if (!"REBOOT_REQUIRED".equals(single.state)) {
                    return rollbackAndClassify(plan, partitions, journal, journalFailure, writeCode(single.error),
                            single.error, written, step, disposition);
                }
                String after = partition.sha256();
                if (!after.equals(step.imageSha256)) {
                    return rollbackAndClassify(plan, partitions, journal, journalFailure, "WRITE_READBACK_MISMATCH",
                            "WRITE_READBACK_MISMATCH", written, step, disposition);
                }
                if (!partition.tailSha256().equals(step.tailSha256)) {
                    return rollbackAndClassify(plan, partitions, journal, journalFailure, "WRITE_TAIL_MISMATCH",
                            "WRITE_TAIL_MISMATCH", written, step, disposition);
                }
                journal.append(event(plan, "S4", step.stepId(), step.partition, SwitchOp.DONE,
                        step.imageSha256, after, ""));
                written.add(step.partition);
                observedSha256.put(step.partition, after);
            } catch (IOException | RuntimeException failure) {
                if (written.isEmpty() && disposition == Disposition.NOT_WRITTEN) throw failure;
                return rollbackAndClassify(plan, partitions, journal, journalFailure, "WRITE_IO_FAILED",
                        codeOf(failure), written, step, disposition);
            }
        }
        return new Result(State.WRITTEN, "", "", true, written, List.of(), observedSha256);
    }

    /** Explicit rollback: reverse plan order, pre image only, never overwrite unknown content. */
    public static Result rollback(SwitchPlan plan, SwitchPartitionProvider partitions,
                                  SwitchJournalSink sink) throws IOException {
        if (plan == null) throw new SwitchFailure("SWITCH_PLAN_INVALID", "missing plan");
        Exception[] journalFailure = {null};
        SwitchJournalSink journal = event -> appendRecovery(sink, journalFailure, event);
        List<String> restored = new ArrayList<>();
        List<SwitchStep> reverse = new ArrayList<>(plan.steps);
        Collections.reverse(reverse);
        boolean interrupted = Thread.interrupted();
        String rollbackFailure = "";
        try {
            for (SwitchStep step : reverse) {
                interrupted |= Thread.interrupted();
                try {
                    RollbackOutcome outcome = rollbackSingle(plan, partitions, journal, step);
                    if (outcome == RollbackOutcome.RESTORED) restored.add(step.partition);
                    if (outcome == RollbackOutcome.UNAUTHORISED && rollbackFailure.isEmpty()) {
                        rollbackFailure = "SWITCH_PARTITION_UNEXPECTED";
                    }
                } catch (IOException | RuntimeException failure) {
                    if (rollbackFailure.isEmpty()) rollbackFailure = codeOf(failure);
                }
            }
            interrupted |= Thread.interrupted();
            boolean allPre = allPre(plan, partitions);
            if (rollbackFailure.isEmpty() && journalFailure[0] != null)
                rollbackFailure = codeOf(journalFailure[0]);
            if (!rollbackFailure.isEmpty() || !allPre) {
                return new Result(State.RECOVERY_REQUIRED, "WRITE_ROLLBACK_FAILED",
                        rollbackFailure.isEmpty() ? "READBACK_MISMATCH" : rollbackFailure,
                        false, List.of(), restored);
            }
            return new Result(State.ROLLED_BACK, "", "", false, List.of(), restored);
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    /**
     * S6 server part (§3.6 6.1/6.2): full-length partition digests at target, boot id changed, device
     * facts unchanged and SELinux still Enforcing. Read-only: no write call is reachable from here.
     */
    public static Result verify(SwitchPlan plan, SwitchPartitionProvider partitions, SwitchFacts facts,
                                SwitchJournalSink journal) throws IOException {
        if (plan == null) throw new SwitchFailure("SWITCH_PLAN_INVALID", "missing plan");
        for (SwitchStep step : plan.steps) {
            WritablePartition partition = partition(partitions, step.partition);
            String observed = partition.sha256();
            if (!observed.equals(step.imageSha256)) {
                journal.append(event(plan, "S6", "6.1", step.partition, SwitchOp.FAIL,
                        step.imageSha256, observed, "VERIFY_PARTITION_MISMATCH"));
                return new Result(State.RECOVERY_REQUIRED, "VERIFY_PARTITION_MISMATCH",
                        "SWITCH_PARTITION_UNEXPECTED", false, List.of(), List.of());
            }
        }
        String bootId = facts == null ? "" : facts.bootId();
        if (bootId == null || bootId.isEmpty() || bootId.equals(plan.startBootId)) {
            return verifyFailure(plan, journal, "VERIFY_BOOT_NOT_OBSERVED", "bootId");
        }
        if (facts == null || !matches(plan, SwitchPlan.DEVICE_SLOT, facts.slotSuffix())
                || !matches(plan, SwitchPlan.DEVICE_FIRMWARE, facts.firmware())
                || !matches(plan, SwitchPlan.DEVICE_KERNEL, facts.kernelRelease())
                || !"Enforcing".equals(facts.selinux())) {
            return verifyFailure(plan, journal, "VERIFY_DEVICE_CHANGED", "device facts");
        }
        journal.append(event(plan, "S6", "6.2", "", SwitchOp.VERIFIED, "", "", ""));
        return new Result(State.VERIFIED, "", "", false, List.of(), List.of());
    }

    private static Result verifyFailure(SwitchPlan plan, SwitchJournalSink journal, String code,
                                        String detail) throws IOException {
        journal.append(event(plan, "S6", "6.2", "", SwitchOp.FAIL, "", "", code));
        return new Result(State.RECOVERY_REQUIRED, code, detail, false, List.of(), List.of());
    }

    private static boolean matches(SwitchPlan plan, String key, String observed) {
        String expected = plan.device.getOrDefault(key, "");
        if (expected.isEmpty()) return true; // host plans may omit the snapshot
        return expected.equals(observed);
    }

    // ------------------------------------------------------------------ prepare validation (§4.3.1)

    private static void validateStructure(SwitchPlan.Request request) throws SwitchFailure {
        if (request == null) throw invalid("missing request");
        if (!SwitchPlan.SCHEMA.equals(request.schema)) throw invalid("schema");
        if (!canonicalUuid(request.switchId)) throw invalid("switchId");
        if (request.fromMode == null || request.toMode == null) throw invalid("mode");
        if (request.baselineId == null) throw invalid("baselineId");
        if (request.steps == null) throw invalid("steps");
        Set<String> seen = new LinkedHashSet<>();
        int candidates = 0;
        for (SwitchStep step : request.steps) {
            if (step == null) throw invalid("null step");
            // 3. allowlist, with the vbmeta red line spelled out in the code.
            if (WritablePartition.FORBIDDEN.equals(step.partition)
                    || !WritablePartition.ALLOWED.contains(step.partition)) {
                throw new SwitchFailure("SWITCH_PARTITION_FORBIDDEN", step.partition);
            }
            // 4. no duplicate partition.
            if (!seen.add(step.partition)) throw invalid("duplicate " + step.partition);
            // 5/6. The signed steps pin the actual target/source carrier; modes bound their allowlists.
            if (step.role == StepRole.WRITE_CANDIDATE) {
                candidates++;
                if (candidates > 1) throw invalid("two candidates");
                if (!SwitchPartitionLayout.allowsPartition(request.toMode, step.partition)) {
                    throw invalid("candidate on " + step.partition);
                }
            } else if (!SwitchPartitionLayout.allowsPartition(request.fromMode, step.partition)) {
                throw invalid("restore on " + step.partition);
            }
            if (!SwitchHashes.isHash(step.imageSha256) || !SwitchHashes.isHash(step.preSha256)
                    || !SwitchHashes.isHash(step.tailSha256)) {
                throw invalid("hash " + step.partition);
            }
            // 12. size bound; checked before touching the filesystem so an oversized plan is cheap.
            if (step.size <= 0 || step.size > BlockDeviceTransaction.MAX_BYTES) {
                throw new SwitchFailure("INSTALLER_DEVICE_SIZE_INVALID", Long.toString(step.size));
            }
        }
        // 7. Both directions write init_boot before boot, filtered to present partitions.
        List<String> expectedOrder = new ArrayList<>();
        for (String name : SwitchPartitionLayout.writeOrder(request.toMode)) {
            for (SwitchStep step : request.steps) if (step.partition.equals(name)) expectedOrder.add(name);
        }
        List<String> actualOrder = new ArrayList<>();
        for (SwitchStep step : request.steps) actualOrder.add(step.partition);
        if (!actualOrder.equals(expectedOrder)) throw invalid("write order " + actualOrder);
    }

    private static void validateImages(List<SwitchStep> steps) throws SwitchFailure {
        for (SwitchStep step : steps) {
            // 8. short images are refused before BDT; its zero-fill branch must never run.
            if (!SwitchPlan.isFullLength(step.image, step.size)) {
                throw new SwitchFailure("PRODUCE_OUTPUT_SIZE_INVALID", step.partition);
            }
            // 9. the pre image is the only rollback source; it must be full length too.
            if (!SwitchPlan.isFullLength(step.preImage, step.size)) {
                throw new SwitchFailure("SWITCH_PRE_IMAGE_INVALID", step.partition);
            }
            // 10. the images must still be the ones the plan pinned.
            if (!hashFile(step.image, "PRODUCE_CANDIDATE_CHANGED", step.partition).equals(step.imageSha256)) {
                throw new SwitchFailure("PRODUCE_CANDIDATE_CHANGED", step.partition);
            }
            if (!hashFile(step.preImage, "SWITCH_PRE_IMAGE_CHANGED", step.partition).equals(step.preSha256)) {
                throw new SwitchFailure("SWITCH_PRE_IMAGE_CHANGED", step.partition);
            }
            // 11. a no-op step must be dropped by the caller, not silently written.
            if (step.imageSha256.equals(step.preSha256)) {
                throw new SwitchFailure("SWITCH_STEP_NO_OP", step.partition);
            }
        }
    }

    private static void validatePartitions(SwitchPlan.Request request, SwitchPartitionProvider provider)
            throws IOException {
        for (SwitchStep step : request.steps) {
            // 13. the real partition exists and matches the planned length.
            WritablePartition partition = partition(provider, step.partition);
            if (partition.size() != step.size) {
                throw new SwitchFailure("SWITCH_PARTITION_LAYOUT_UNSUPPORTED",
                        step.partition + " size " + partition.size());
            }
            // 14. current content must be pre or target; anything else is an external writer.
            String observed = partition.sha256();
            if (!observed.equals(step.preSha256) && !observed.equals(step.imageSha256)) {
                throw new SwitchFailure("SWITCH_PARTITION_UNEXPECTED", step.partition);
            }
        }
    }

    // ------------------------------------------------------------------ rollback machinery (§4.6)

    private enum Disposition { NOT_WRITTEN, NEEDS_ROLLBACK, ALREADY_RESTORED, UNRESTORABLE }

    private enum RollbackOutcome { SKIPPED, RESTORED, UNAUTHORISED }

    private static Result rollbackAndClassify(SwitchPlan plan, SwitchPartitionProvider partitions,
                                              SwitchJournalSink sink, Exception[] journalFailure,
                                              String layerCode, String detail,
                                              List<String> written, SwitchStep currentStep,
                                              Disposition disposition) {
        SwitchJournalSink journal = event -> appendRecovery(sink, journalFailure, event);
        List<String> restored = new ArrayList<>();
        if (disposition == Disposition.ALREADY_RESTORED && currentStep != null) {
            restored.add(currentStep.partition);
        }
        List<SwitchStep> candidates = new ArrayList<>();
        if (disposition == Disposition.NEEDS_ROLLBACK && currentStep != null) candidates.add(currentStep);
        for (int index = written.size() - 1; index >= 0; index--) {
            for (SwitchStep step : plan.steps) {
                if (step.partition.equals(written.get(index))) {
                    candidates.add(step);
                    break;
                }
            }
        }
        boolean interrupted = Thread.interrupted();
        String rollbackFailure = "";
        try {
            for (SwitchStep step : candidates) {
                interrupted |= Thread.interrupted();
                try {
                    RollbackOutcome outcome = rollbackSingle(plan, partitions, journal, step);
                    if (outcome == RollbackOutcome.RESTORED) restored.add(step.partition);
                    if (outcome == RollbackOutcome.UNAUTHORISED && rollbackFailure.isEmpty()) {
                        rollbackFailure = "SWITCH_PARTITION_UNEXPECTED";
                    }
                } catch (IOException | RuntimeException failure) {
                    if (rollbackFailure.isEmpty()) rollbackFailure = codeOf(failure);
                }
            }
            interrupted |= Thread.interrupted();
            boolean allPre = allPre(plan, partitions);
            if (rollbackFailure.isEmpty() && journalFailure[0] != null)
                rollbackFailure = codeOf(journalFailure[0]);
            // UNRESTORABLE includes a failed restore fsync even when bytes read back as PRE.
            if (allPre && rollbackFailure.isEmpty() && disposition != Disposition.UNRESTORABLE) {
                return new Result(State.ROLLED_BACK, layerCode, detail, false, List.of(), restored);
            }
            String code = !rollbackFailure.isEmpty() || disposition == Disposition.UNRESTORABLE
                    ? "WRITE_ROLLBACK_FAILED" : layerCode;
            return new Result(State.RECOVERY_REQUIRED, code,
                    rollbackFailure.isEmpty() ? detail : rollbackFailure, false, List.of(), restored);
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    private static RollbackOutcome rollbackSingle(SwitchPlan plan, SwitchPartitionProvider partitions,
                                                  SwitchJournalSink journal, SwitchStep step)
            throws IOException {
        WritablePartition partition = partition(partitions, step.partition);
        String observed = partition.sha256();
        if (observed.equals(step.preSha256)) {
            journal.append(event(plan, "RB", step.stepId(), step.partition, SwitchOp.ROLLBACK_DONE,
                    step.preSha256, observed, ""));
            return RollbackOutcome.SKIPPED;
        }
        if (!observed.equals(step.imageSha256)) {
            // Never blind-write over content we cannot attribute; external recovery is required.
            journal.append(event(plan, "RB", step.stepId(), step.partition, SwitchOp.RECOVERY_REQUIRED,
                    step.preSha256, observed, "SWITCH_PARTITION_UNEXPECTED"));
            return RollbackOutcome.UNAUTHORISED;
        }
        journal.append(event(plan, "RB", step.stepId(), step.partition, SwitchOp.ROLLBACK_INTENT,
                step.preSha256, observed, ""));
        try (BlockDeviceTransaction.Device device = partition.open()) {
            BlockDeviceTransaction.restore(device, step.preImage, step.preSha256,
                    (state, error) -> journal.append(bdtEvent(plan, step, state, error)));
        }
        String after = partition.sha256();
        if (!after.equals(step.preSha256)) {
            throw new SwitchFailure("WRITE_ROLLBACK_FAILED", "READBACK_MISMATCH");
        }
        journal.append(event(plan, "RB", step.stepId(), step.partition, SwitchOp.ROLLBACK_DONE,
                step.preSha256, after, ""));
        return RollbackOutcome.RESTORED;
    }

    private static boolean allPre(SwitchPlan plan, SwitchPartitionProvider partitions) {
        for (SwitchStep step : plan.steps) {
            try {
                if (!partition(partitions, step.partition).sha256().equals(step.preSha256)) return false;
            } catch (IOException | RuntimeException unreadable) {
                return false;
            }
        }
        return true;
    }

    // ------------------------------------------------------------------ helpers

    private static void appendRecovery(SwitchJournalSink journal, Exception[] failure, SwitchEvent event) {
        if (failure[0] != null) return; // Preserve a possibly partial failed append; continue PRE recovery only.
        try { journal.append(event); } catch (IOException | RuntimeException error) {
            failure[0] = error;
        }
    }

    private static SwitchEvent event(SwitchPlan plan, String stage, String step, String partition,
                                     SwitchOp op, String expected, String observed, String code) {
        return SwitchEvent.forPlan(plan, stage, step, partition, op, expected, observed, code);
    }

    /** Adapter from the single-partition journal barrier to switch events (§4.7). */
    private static SwitchEvent bdtEvent(SwitchPlan plan, SwitchStep step, String state, String error) {
        SwitchOp op;
        switch (state == null ? "" : state) {
            case "WRITING": op = SwitchOp.COMMIT_INTENT; break;
            case "REBOOT_REQUIRED": op = SwitchOp.REBOOT_PENDING; break;
            case "RESTORING": op = SwitchOp.ROLLBACK_INTENT; break;
            case "RESTORED": op = SwitchOp.ROLLBACK_DONE; break;
            case "RECOVERY_REQUIRED": op = SwitchOp.RECOVERY_REQUIRED; break;
            default: op = SwitchOp.FAIL;
        }
        return event(plan, "S4", step.stepId(), step.partition, op, step.imageSha256, "", error);
    }

    private static String writeCode(String bdtError) {
        return bdtError != null && bdtError.contains("READBACK") ? "WRITE_READBACK_MISMATCH" : "WRITE_FAILED";
    }

    private static String codeOf(Throwable failure) {
        if (failure instanceof SwitchFailure) return ((SwitchFailure) failure).code;
        String message = failure.getMessage();
        return message != null && message.matches("[A-Z][A-Z0-9_]*") ? message : "WRITE_IO_FAILED";
    }

    private static WritablePartition partition(SwitchPartitionProvider provider, String name)
            throws IOException {
        if (provider == null) {
            throw new SwitchFailure("SWITCH_PARTITION_LAYOUT_UNSUPPORTED", "missing provider");
        }
        WritablePartition partition;
        try {
            partition = provider.get(name);
        } catch (SwitchFailure failure) {
            throw failure;
        } catch (IOException failure) {
            throw new SwitchFailure("SWITCH_PARTITION_LAYOUT_UNSUPPORTED",
                    name + ": " + failure.getMessage(), failure);
        }
        if (partition == null || !name.equals(partition.name())) {
            throw new SwitchFailure("SWITCH_PARTITION_LAYOUT_UNSUPPORTED", "identity " + name);
        }
        return partition;
    }

    private static boolean canonicalUuid(String value) {
        if (value == null) return false;
        try {
            return UUID.fromString(value).toString().equals(value);
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static SwitchFailure invalid(String detail) {
        return new SwitchFailure("SWITCH_PLAN_INVALID", detail);
    }

    private static String hashFile(java.nio.file.Path file, String code, String partition)
            throws SwitchFailure {
        try {
            return SwitchHashes.sha256(file);
        } catch (IOException failure) {
            throw new SwitchFailure(code, partition, failure);
        }
    }
}
