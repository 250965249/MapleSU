package com.topjohnwu.superuser;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Host transport substitute; command parsing stays in the production Kotlin source. */
public final class Shell implements AutoCloseable {
    private final Map<String, Result> replies;
    public final List<String> commands = new ArrayList<>();

    public Shell(Map<String, Result> replies) { this.replies = replies; }
    public boolean isRoot() { return true; }
    public boolean isAlive() { return true; }
    public Job newJob() { return new Job(); }
    @Override public void close() {}

    public final class Job {
        private String command;
        public Job add(String... values) { command = String.join("\n", values); return this; }
        public Job to(List<String> out, List<String> err) { return this; }
        public Result exec() {
            commands.add(command);
            return replies.getOrDefault(command, new Result(127, List.of(), List.of("unconfigured command")));
        }
    }

    public static final class Result {
        private final int code;
        private final List<String> out;
        private final List<String> err;
        public Result(int code, List<String> out, List<String> err) {
            this.code = code; this.out = out; this.err = err;
        }
        public int getCode() { return code; }
        public List<String> getOut() { return out; }
        public List<String> getErr() { return err; }
        public boolean isSuccess() { return code == 0; }
    }

    public static final class Builder {
        public static Builder create() { return new Builder(); }
        public Builder setContext(Object context) { return this; }
        public Builder setTimeout(long seconds) { return this; }
        public Shell build(String... command) { return new Shell(Map.of()); }
    }
}
