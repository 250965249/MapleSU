package dev.maplesu.installer;

/**
 * What one plan step does to its partition. Write order is defined by SwitchPartitionLayout.
 */
public enum StepRole { RESTORE_BASELINE, WRITE_CANDIDATE }
