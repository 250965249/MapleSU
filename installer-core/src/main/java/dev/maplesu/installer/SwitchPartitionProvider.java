package dev.maplesu.installer;

import java.io.IOException;
import java.util.Set;

/**
 * Resolves partitions by name. The implementation owns the allowlist ({@code boot}/{@code
 * init_boot}) and must refuse {@code vbmeta} and any unknown name with an {@link IOException}.
 */
public interface SwitchPartitionProvider {
    WritablePartition get(String name) throws IOException;

    Set<String> available() throws IOException;
}
