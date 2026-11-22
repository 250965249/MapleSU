package dev.maplesu.installer;

/**
 * One immutable journal record (02-switch-contract §3.3). {@code seq} is assigned by the journal
 * sink on append, because only the sink knows the durable sequence; callers create events with
 * {@code seq == 0}. {@code prev} is a per-line journal-chain field and is not part of the event.
 */
public final class SwitchEvent {
    public static final int SCHEMA = 1;

    public final int schema;
    public final long seq;
    public final String switchId;
    public final String planSha256;
    public final String bootId;
    public final long atUptimeMs;
    public final String stage;
    public final String step;
    /** Empty string for non-partition events (prepared/verified/failure). */
    public final String partition;
    public final SwitchOp op;
    public final String expectedSha256;
    public final String observedSha256;
    public final String code;

    public SwitchEvent(int schema, long seq, String switchId, String planSha256, String bootId,
                       long atUptimeMs, String stage, String step, String partition, SwitchOp op,
                       String expectedSha256, String observedSha256, String code) {
        this.schema = schema;
        this.seq = seq;
        this.switchId = require(switchId);
        this.planSha256 = require(planSha256);
        this.bootId = bootId == null ? "" : bootId;
        this.atUptimeMs = atUptimeMs;
        this.stage = stage == null ? "" : stage;
        this.step = step == null ? "" : step;
        this.partition = partition == null ? "" : partition;
        this.op = op;
        this.expectedSha256 = expectedSha256 == null ? "" : expectedSha256;
        this.observedSha256 = observedSha256 == null ? "" : observedSha256;
        this.code = code == null ? "" : code;
    }

    /** Creates a not-yet-sequenced event for a plan; the sink assigns {@code seq} and boot facts. */
    public static SwitchEvent forPlan(SwitchPlan plan, String stage, String step, String partition,
                                      SwitchOp op, String expectedSha256, String observedSha256,
                                      String code) {
        if (plan == null) throw new IllegalArgumentException("SWITCH_PLAN_INVALID");
        return new SwitchEvent(SCHEMA, 0, plan.switchId, plan.planSha256, "", 0, stage, step,
                partition, op, expectedSha256, observedSha256, code);
    }

    public SwitchEvent withSeq(long newSeq) {
        return new SwitchEvent(schema, newSeq, switchId, planSha256, bootId, atUptimeMs, stage, step,
                partition, op, expectedSha256, observedSha256, code);
    }

    public SwitchEvent withBoot(String newBootId, long newAtUptimeMs) {
        return new SwitchEvent(schema, seq, switchId, planSha256, newBootId, newAtUptimeMs, stage,
                step, partition, op, expectedSha256, observedSha256, code);
    }

    private static String require(String value) {
        if (value == null) throw new IllegalArgumentException("SWITCH_PLAN_INVALID");
        return value;
    }
}
