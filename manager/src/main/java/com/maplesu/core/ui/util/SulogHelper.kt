package com.maplesu.core.ui.util

import android.os.SystemClock
import com.topjohnwu.superuser.io.SuFile
import com.topjohnwu.superuser.io.SuFileInputStream
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import java.io.InputStreamReader
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.ArrayDeque
import java.util.Locale

private const val SULOG_DIR_LITE = "/data/adb/sevenk/log"

/**
 * Normal（KernelSU）的 sulog 目录。
 *
 * 事实：ksud 的 `defs.rs:17` 把日志写在 `/data/adb/ksu/log`；`/data/adb/sevenk/log`
 * 是 Ultra 的实现细节。以前恒读 sevenk 目录 → Normal 下永远"没有日志"（看上去像功能正常）。
 */
private const val SULOG_DIR_KSU = "/data/adb/ksu/log"

private const val SULOG_LINE_LIMIT = 1000
private const val SULOG_FILE_PREFIX = "sulog-"
private const val SULOG_FILE_SUFFIX = ".log"
private val SULOG_FILE_NAME_REGEX = Regex("""$SULOG_FILE_PREFIX(\d{4}-\d{2}-\d{2})(?:-(\d+))?$SULOG_FILE_SUFFIX""")
private const val NS_PER_MILLISECOND = 1_000_000L
private val SULOG_TIMESTAMP_FORMATTER: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.US)

/**
 * 当前模式的 sulog 目录（纯函数，主机可测）。
 *
 * `null`（未判定）按 LITE 处理 —— 与 `getKsuDaemonPath()` 的既有语义一致，
 * 且这里只影响"读哪个目录"，不会产生 root 调用。
 */
internal fun sulogDirectory(mode: WorkMode?): String = when (mode) {
    WorkMode.KSU -> SULOG_DIR_KSU
    WorkMode.LITE, null -> SULOG_DIR_LITE
}

/** sulog 的读/清执行面：模式决定走哪条通道（KSU = root shell；LITE = SuFile）。 */
internal interface SulogTransport {
    fun list(directory: String): List<String>
    fun read(path: String, limit: Int): List<String>
    fun clear(path: String): Boolean
    fun delete(path: String): Boolean
}

/** LITE/未判定：既有 `SuFile` 通道（行为不变）。 */
internal object SuFileSulogTransport : SulogTransport {
    override fun list(directory: String): List<String> =
        SuFile(directory).list().orEmpty().toList()

    override fun read(path: String, limit: Int): List<String> {
        val suFile = SuFile(path)
        if (!suFile.isFile) return emptyList()
        val lines = ArrayDeque<String>(limit)
        SuFileInputStream.open(suFile).use { input ->
            InputStreamReader(input).buffered().useLines { sequence ->
                sequence.forEach { line ->
                    if (lines.size == limit) lines.removeFirst()
                    lines.addLast(line)
                }
            }
        }
        return lines.toList()
    }

    override fun clear(path: String): Boolean = SuFile(path).clear()

    override fun delete(path: String): Boolean = SuFile(path).delete()
}

/** 一条 root shell 命令的结果（只保留 sulog 需要的两个事实，便于主机注入 fake）。 */
internal data class SulogCommandResult(
    val code: Int,
    val out: List<String> = emptyList(),
) {
    val ok: Boolean get() = code == 0
}

/**
 * 生产 runner：KSU root shell（`getRootShell()` 在 KSU 下走 `ksud debug su`）。
 * 顶层函数：构造函数默认值引用它不涉及任何类内成员解析。
 */
private fun defaultSulogRunner(): (String) -> SulogCommandResult = { command ->
    val result = runCatching {
        getRootShell().newJob().add(command)
            .to(ArrayList<String>(), ArrayList<String>()).exec()
    }.getOrNull()
    if (result == null) {
        SulogCommandResult(-1)
    } else {
        SulogCommandResult(result.code, result.out)
    }
}

/**
 * KSU：`/data/adb` 是 0700 root，`SuFile` 走的是 libsu 的默认 shell（app uid），
 * 在 Normal 下读不到 ksud 的日志目录；这里改用 KSU root shell（`getRootShell()`）。
 *
 * [runner] 是注入缝：生产默认走 libsu root shell；主机单测注入 fake，从而可以断言
 * **命令形态**（`ls -1 '<dir>'` / `tail -n <n> '<path>'` / `rm -f '<path>'`）而不用起进程。
 */
internal class KsuRootShellSulogTransport(
    private val runner: (String) -> SulogCommandResult = defaultSulogRunner(),
) : SulogTransport {
    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    private fun exec(command: String): SulogCommandResult =
        runCatching { runner(command) }.getOrDefault(SulogCommandResult(-1))

    override fun list(directory: String): List<String> {
        val result = exec("/system/bin/ls -1 ${quote(directory)} 2>/dev/null")
        if (!result.ok) return emptyList()
        return result.out.map { it.trim() }.filter { it.isNotEmpty() }
    }

    override fun read(path: String, limit: Int): List<String> {
        val result = exec("/system/bin/tail -n $limit ${quote(path)} 2>/dev/null")
        if (!result.ok) return emptyList()
        return result.out
    }

    override fun clear(path: String): Boolean = exec(": > ${quote(path)}").ok

    override fun delete(path: String): Boolean = exec("/system/bin/rm -f ${quote(path)}").ok
}

/** 进程内 transport 选择点（生产按模式选；主机测试可注入 fake）。 */
internal object SulogTransports {
    @Volatile
    private var override: SulogTransport? = null

    fun installForTest(transport: SulogTransport?) {
        override = transport
    }

    fun forMode(mode: WorkMode? = ModeRuntime.active): SulogTransport =
        override ?: when (mode) {
            WorkMode.KSU -> KsuRootShellSulogTransport()
            WorkMode.LITE, null -> SuFileSulogTransport
        }
}

data class SulogFile(
    val name: String,
    val path: String,
)

enum class SulogFileCleanAction {
    Clear,
    Delete,
}

enum class SulogEventType {
    RootExecve,
    SuCompat,
    IoctlGrantRoot,
    DaemonEvent,
    Dropped,
    Unknown,
}

enum class SulogEventFilter(val eventType: SulogEventType?) {
    RootExecve(SulogEventType.RootExecve),
    SuCompat(SulogEventType.SuCompat),
    IoctlGrantRoot(SulogEventType.IoctlGrantRoot),
    DaemonEvent(SulogEventType.DaemonEvent),
}

fun defaultSulogEventFilters(): Set<SulogEventFilter> = SulogEventFilter.entries.toSet()

data class SulogEntry(
    val key: String,
    val eventType: SulogEventType,
    val rawLine: String,
    val timestampText: String?,
    val fields: Map<String, String>,
) {
    val searchableText: String by lazy {
        buildString {
            append(rawLine)
            append('\n')
            timestampText?.let {
                append(it)
                append('\n')
            }
            fields.values.forEach {
                append(it)
                append(' ')
            }
        }.lowercase()
    }
}

internal fun parseSulogFileNames(fileNames: List<String>): List<String> {
    return fileNames
        .mapNotNull { name ->
            val match = SULOG_FILE_NAME_REGEX.matchEntire(name) ?: return@mapNotNull null
            val date = LocalDate.parse(match.groupValues[1])
            val rotation = match.groupValues[2].takeIf { it.isNotEmpty() }?.toInt() ?: 0
            Triple(name, date, rotation)
        }
        .sortedWith(compareByDescending<Triple<String, LocalDate, Int>> { it.second }.thenByDescending { it.third })
        .map { it.first }
}

internal fun resolveSulogFileCleanAction(
    files: List<SulogFile>,
    selectedFilePath: String,
): SulogFileCleanAction {
    val latestFilePath = files.firstOrNull()?.path
    return if (selectedFilePath == latestFilePath) {
        SulogFileCleanAction.Clear
    } else {
        SulogFileCleanAction.Delete
    }
}

/**
 * 当前模式的 sulog 文件列表。
 *
 * 目录随模式变化（Ultra=`/data/adb/sevenk/log`，Normal=`/data/adb/ksu/log`），
 * 读取通道也随模式变化（Normal 必须走 KSU root shell）。
 */
fun listSulogFiles(): List<SulogFile> {
    val directory = sulogDirectory(ModeRuntime.active)
    val transport = SulogTransports.forMode()
    val fileNames = transport.list(directory)
    return parseSulogFileNames(fileNames).map { name ->
        SulogFile(name = name, path = "$directory/$name")
    }
}

fun readSulogFile(path: String): List<String> =
    SulogTransports.forMode().read(path, SULOG_LINE_LIMIT)

fun parseSulogLines(lines: List<String>): List<SulogEntry> {
    val currentTimeMillis = System.currentTimeMillis()
    val uptimeMillis = SystemClock.uptimeMillis()
    val zoneId = ZoneId.systemDefault()
    return lines.mapNotNull { line ->
        line.takeIf { it.isNotBlank() }?.let {
            parseSulogLine(
                line = it,
                currentTimeMillis = currentTimeMillis,
                uptimeMillis = uptimeMillis,
                zoneId = zoneId,
            )
        }
    }
}

fun buildVisibleSulogEntries(
    entries: List<SulogEntry>,
    searchText: String,
    selectedFilters: Set<SulogEventFilter>,
): List<SulogEntry> {
    val normalizedQuery = searchText.trim().lowercase()
    val activeEventTypes = selectedFilters.mapNotNull { it.eventType }.toSet()
    return entries.asReversed().filter { entry ->
        val alwaysVisible = entry.eventType == SulogEventType.Dropped || entry.eventType == SulogEventType.Unknown
        val filterMatches = alwaysVisible || entry.eventType in activeEventTypes
        val queryMatches = normalizedQuery.isEmpty() || entry.searchableText.contains(normalizedQuery)
        filterMatches && queryMatches
    }
}

fun parseSulogLine(
    line: String,
    currentTimeMillis: Long = System.currentTimeMillis(),
    uptimeMillis: Long = -1L,
    zoneId: ZoneId = ZoneId.systemDefault(),
): SulogEntry {
    val fields = parseKeyValueLine(line)
    val eventType = when (fields["type"]) {
        "root_execve" -> SulogEventType.RootExecve
        "sucompat" -> SulogEventType.SuCompat
        "ioctl_grant_root" -> SulogEventType.IoctlGrantRoot
        "daemon_restart", "daemon_start" -> SulogEventType.DaemonEvent
        "dropped" -> SulogEventType.Dropped
        else -> SulogEventType.Unknown
    }
    val key = when (eventType) {
        SulogEventType.DaemonEvent -> "daemon_restart_${fields["restart"]}_${fields["boot_id"]}"
        else -> fields["seq"] ?: line
    }
    val timestampText = parseSulogTimestampText(
        timestampNs = fields["ts_ns"],
        currentTimeMillis = currentTimeMillis,
        uptimeMillis = uptimeMillis,
        zoneId = zoneId,
    )
    return SulogEntry(
        key = key,
        eventType = eventType,
        rawLine = line,
        timestampText = timestampText,
        fields = fields,
    )
}

private fun parseKeyValueLine(line: String): Map<String, String> {
    return buildMap {
        var index = 0
        while (index < line.length) {
            while (index < line.length && line[index].isWhitespace()) {
                index++
            }
            if (index >= line.length) break

            val keyStart = index
            while (index < line.length && line[index] != '=' && !line[index].isWhitespace()) {
                index++
            }
            if (index >= line.length || line[index] != '=') {
                while (index < line.length && !line[index].isWhitespace()) {
                    index++
                }
                continue
            }

            val key = line.substring(keyStart, index)
            index++
            val (value, nextIndex) = if (index < line.length && line[index] == '"') {
                parseQuotedSulogValue(line, index + 1)
            } else {
                parseUnquotedSulogValue(line, index)
            }
            if (key.isNotEmpty()) {
                put(key, value)
            }
            index = nextIndex
        }
    }
}

private fun parseQuotedSulogValue(line: String, startIndex: Int): Pair<String, Int> {
    val value = StringBuilder()
    var index = startIndex
    while (index < line.length) {
        when (val ch = line[index]) {
            '"' -> return value.toString() to (index + 1)
            '\\' -> index = appendEscapedSulogChar(line, index, value)
            else -> {
                value.append(ch)
                index++
            }
        }
    }
    return value.toString() to index
}

private fun parseUnquotedSulogValue(line: String, startIndex: Int): Pair<String, Int> {
    var index = startIndex
    while (index < line.length && !line[index].isWhitespace()) {
        index++
    }
    return line.substring(startIndex, index) to index
}

private fun appendEscapedSulogChar(line: String, slashIndex: Int, value: StringBuilder): Int {
    val nextIndex = slashIndex + 1
    if (nextIndex >= line.length) {
        value.append('\\')
        return nextIndex
    }

    return when (val escaped = line[nextIndex]) {
        '\\' -> {
            value.append('\\')
            nextIndex + 1
        }
        '"' -> {
            value.append('"')
            nextIndex + 1
        }
        'n' -> {
            value.append('\n')
            nextIndex + 1
        }
        'r' -> {
            value.append('\r')
            nextIndex + 1
        }
        't' -> {
            value.append('\t')
            nextIndex + 1
        }
        'x' -> appendHexEscapedSulogChar(line, nextIndex, value)
        else -> {
            value.append(escaped)
            nextIndex + 1
        }
    }
}

private fun appendHexEscapedSulogChar(line: String, xIndex: Int, value: StringBuilder): Int {
    val hexStart = xIndex + 1
    val hexEnd = hexStart + 2
    if (hexEnd <= line.length) {
        val code = line.substring(hexStart, hexEnd).toIntOrNull(16)
        if (code != null) {
            value.append(code.toChar())
            return hexEnd
        }
    }

    value.append('x')
    return xIndex + 1
}

internal fun parseSulogTimestampText(
    timestampNs: String?,
    currentTimeMillis: Long = System.currentTimeMillis(),
    uptimeMillis: Long = -1L,
    zoneId: ZoneId = ZoneId.systemDefault(),
): String? {
    val timestampNanos = timestampNs?.toLongOrNull() ?: return null
    if (timestampNanos < 0 || uptimeMillis < 0) return null

    val bootTimeMillis = currentTimeMillis - uptimeMillis
    if (bootTimeMillis < 0) return null

    val eventTimeMillis = bootTimeMillis + (timestampNanos / NS_PER_MILLISECOND)
    if (eventTimeMillis < 0) return null

    return Instant.ofEpochMilli(eventTimeMillis)
        .atZone(zoneId)
        .format(SULOG_TIMESTAMP_FORMATTER)
}

internal fun String.toSulogDisplayName(): String {
    return if (startsWith(SULOG_FILE_PREFIX) && endsWith(SULOG_FILE_SUFFIX)) {
        removePrefix(SULOG_FILE_PREFIX).removeSuffix(SULOG_FILE_SUFFIX)
    } else {
        this
    }
}

fun cleanSulogFile(path: String): Boolean = SulogTransports.forMode().clear(path)

fun deleteSulogFile(path: String): Boolean = SulogTransports.forMode().delete(path)
