package dev.maplesu.installer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Name to fake partition provider that records {@code get()} order for write-order assertions. */
final class FakePartitionProvider implements SwitchPartitionProvider {
    private final Map<String, WritablePartition> partitions = new LinkedHashMap<>();
    /** Every {@code get()} call in order; cleared by tests between prepare and commit. */
    final List<String> order = new ArrayList<>();

    FakePartitionProvider add(WritablePartition partition) {
        partitions.put(partition.name(), partition);
        return this;
    }

    @Override
    public WritablePartition get(String name) throws IOException {
        WritablePartition partition = partitions.get(name);
        if (partition == null) throw new IOException("SWITCH_PARTITION_LAYOUT_UNSUPPORTED: " + name);
        order.add(name);
        return partition;
    }

    @Override
    public Set<String> available() {
        return new LinkedHashSet<>(partitions.keySet());
    }
}
