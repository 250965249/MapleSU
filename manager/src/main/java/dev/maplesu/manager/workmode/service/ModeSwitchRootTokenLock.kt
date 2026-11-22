package dev.maplesu.manager.workmode.service

import java.io.File
import java.io.RandomAccessFile

private val modeSwitchRootTokenMonitor = Any()

/** JVM file locks throw on overlap; serialize local sessions before locking across processes. */
internal fun <T> withLockedModeSwitchRootToken(file: File, readOrCreate: (RandomAccessFile) -> T): T =
    synchronized(modeSwitchRootTokenMonitor) {
        RandomAccessFile(file, "rw").use { handle ->
            handle.channel.lock().use {
                readOrCreate(handle)
            }
        }
    }
