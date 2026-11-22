package dev.maplesu.manager.modules.compat

/**
 * Ultra 模块故障证据（P0 §4.3）：结构化事件、单行 JSONL、脱敏策略、退出原因分类。
 *
 * 诊断构建保留模块与管理器的**首次**异常记录，每条事件含 `operationId`、boot ID、
 * 设备时间/主机 UTC、进程身份、阶段、返回码、构建摘要；root key、完整私有目录与无关用户数据
 * 不进入交付包；pstore 为空要明确写空；管理器 FORCE STOP 与原生异常分别统计；SDK 默认会清
 * tombstone，旧日志缺失不算无故障。
 *
 * ## 这个文件只做纯逻辑
 *
 * 没有 `import android.*`，没有 IO，不取当前时间，不读系统属性，不联网：
 *  - 时间是调用方传进来的（[UltraModuleEvent.hostUtcIso] / [UltraModuleEvent.deviceTimeIso]）；
 *  - 设备属性、退出记录、日志都由采集端读好后传进来；
 *  - 编码/解码是 `String -> String`，JVM 单测可以直接跑。
 *
 * 这样做的理由：本仓库的 Android `org.json` 在 JVM 单测里是 stub（见 `ModuleModeRouter` 与
 * `ModuleListParsers` 的注释），一旦把序列化交给 `org.json`，证据格式就只有上设备才能验证。
 * 证据格式恰恰是最不能靠“上设备再说”的部分，所以这里自带一个极简、扁平、可 round-trip 的
 * JSONL 编解码。仓库里已有的纯 JVM JSON 工具（`liteweb/LiteWebCore.kt` 的 `LiteWebJson`）只
 * 支持“扁平对象 + 字符串值”，解析回来就是 `Map<String, String>`：`null` 与「字段缺失」不可区分，
 * 数字/布尔都退化成字符串，且它属于另一个功能模块。事件格式需要「字段缺失」与 `null` 区分、
 * 需要保留 Int 字段的失败语义，所以不复用它（取舍记录在 `.analysis/.../w1-c/EVIDENCE.md`）。
 *
 * ## 脱敏的默认策略是「宁可少记，不泄露」
 *
 * [UltraModuleEvidenceSanitizer] 默认 [UltraModuleUnsafeRedactionPolicy.DROP_WHOLE_EVENT]：一条事件
 * 的 detail 只要**无法安全脱敏**（控制字符、超长、私钥块等），整条事件丢弃，而不是把可疑原文
 * 带进交付包。少一条事件是可见的（计数会少），泄露一次是不可撤销的。
 * 需要“至少留下发生了什么”的采集端可以显式改成 [UltraModuleUnsafeRedactionPolicy.KEEP_WITH_MARKER]，
 * 那时 detail 会变成 `<detail-dropped:原因>`，原因码本身不含原文。
 *
 * ## FORCE STOP 不是崩溃
 *
 * 冻结排查 §2 明确批评过把「调试状态变更导致的 FORCE STOP」当成模块导致的 crash。
 * [UltraModuleExitClassifier] 因此把 `ApplicationExitInfo` 的 reason/subreason 分成四类，并且
 * **崩溃原因（SIGNALED / CRASH / CRASH_NATIVE）优先级最高、description 不能把崩溃改判成别类**；
 * 反过来，未知 reason 也绝不会落进崩溃桶。`dumpsys activity exit-info` 的实测样本见冻结证据
 * `app-exit-info.txt`：`reason=10 (USER REQUESTED) subreason=21 (FORCE STOP)
 * description=stop dev.maplesu.manager due to set debug app state`。
 */
object UltraModuleEvidenceSchema {
    /** JSONL 每行的字段顺序，发布后不得改动（解码器容忍缺字段与未知字段，编码器不省略字段）。 */
    val FIELDS: List<String> = listOf(
        "operationId",
        "action",
        "bootId",
        "deviceTimeIso",
        "hostUtcIso",
        "processRole",
        "processPid",
        "phase",
        "returnCode",
        "buildDigest",
        "outcome",
        "detail",
    )
}

/**
 * 事件发生在哪个进程里。§4.3 要求“进程身份”可核对：同一份模块在宿主、守护、WebUI 加载器里
 * 各有自己的对象（冻结排查 §4 的 E7），事件必须能区分它们，否则统计会把不同进程的记录混在一起。
 *
 * 枚举名就是 JSONL 里的稳定字符串（大写机器码，与 [UltraModuleReasonCode] 的风格一致）。
 */
enum class UltraModuleProcessRole {
    /** MapleSU 管理器主进程（`dev.maplesu.manager`）。 */
    MANAGER,

    /** 模块自己的原生守护进程。 */
    MODULE_DAEMON,

    /** 加载 WebUI 的进程（SDK 的 `start_module_web_ui_server_async` 拉起的那一侧）。 */
    WEBUI_LOADER,

    /** 采集端不知道是哪个进程：不猜，按未知记录。 */
    UNKNOWN,
}

/**
 * 事件处在模块生命周期的哪一个阶段。
 *
 * 阶段用枚举而不是自由字符串：§4.3 的统计按阶段做（“首次异常记录”要能定位到阶段），
 * 自由字符串会让同一步骤出现多种写法。无法识别的阶段一律 [UNKNOWN]。
 */
enum class UltraModulePhase {
    /** 执行前静态兼容检查（§4.1，此时还没有加载任何原生代码）。 */
    PRE_EXEC_CHECK,

    /** 加载/执行模块原生入口（SDK 模块入口、ELF 加载）。 */
    NATIVE_ENTRY,

    /** 启动模块原生守护。 */
    DAEMON_START,

    /** 启动/打开模块 WebUI。 */
    WEBUI_START,

    /** 开发单次运行。 */
    RUN_ONCE,

    /** 停止模块（正常停止或停止请求）。 */
    STOP,

    /** 卸载模块。 */
    UNINSTALL,

    /** 开机/维护阶段的恢复动作（§4.2）。 */
    BOOT_RECOVERY,

    /** 未识别的阶段。 */
    UNKNOWN,
}

/**
 * 这次动作的结果。注意 `SUCCESS` 只表示**这一步**返回了成功，不表示模块兼容、也不表示内核影响
 * 已经撤销（开发方案 §4.1/§6.3）。
 */
enum class UltraModuleOutcome {
    /** 这一步按回执成功结束。 */
    SUCCESS,

    /** 这一步失败（进程仍在，能记录到失败）。 */
    FAILURE,

    /** 这一步在执行前被拦下（例如 §4.1 的 KNOWN_INCOMPATIBLE）。 */
    BLOCKED,

    /** 这一步没有走完（进程消失、被停止、超时），原因可能不在这条事件里。 */
    INTERRUPTED,

    /** 采集端无法判断结果：不猜。 */
    UNKNOWN,
}

/**
 * 一条故障证据事件。
 *
 * 字段顺序与 [UltraModuleEvidenceSchema.FIELDS] 一致；JSONL 编码不省略字段，缺值写成 `null`
 * （`bootId`/`operationId`/`hostUtcIso` 是必填的字符串，没有就不该造事件——句柄见
 * [UltraModuleEvidenceSanitizer.sanitizeEvidence]）。
 *
 * @param operationId 一次操作的稳定标识（管理器生成，例如 UUID）。**同一个操作的多阶段事件共用它**，
 *   这是把“安装 → 原生入口 → 守护 → WebUI”串起来唯一的键。
 * @param action 五个会真正让模块原生代码跑起来的入口之一（§4.1 要求全部覆盖）。
 * @param bootId 设备本次启动的 ID（`/proc/sys/kernel/random/boot_id`）。空串表示**未知**：
 *   不允许用某个具体值替代，否则事后无法判断两条事件是否同一次启动。
 * @param deviceTimeIso 设备本地时间（ISO-8601，带偏移量或 `Z`）。设备时钟可能与主机不一致，
 *   所以两个时间都记、互不覆盖。可空：采集端没读到就写 null，不伪造。
 * @param hostUtcIso 主机 UTC 时间（ISO-8601，必须带 `Z` 或偏移量）。必填：没有它无法与主机侧
 *   的采集记录对齐。
 * @param processRole 进程身份。
 * @param processPid 进程 PID（可空）。PID 只在一次启动内有效，跨启动比较必须带 `bootId`。
 * @param phase 生命周期阶段。
 * @param returnCode 这一步的返回码（SDK/Hook/系统回执里的整数）。可空：没有返回码时写 null，
 *   不把「没有返回码」写成 0。
 * @param buildDigest 构建摘要（管理器 APK 或模块 ELF 的十六进制摘要）。只允许十六进制摘要，
 *   不做自由文本：自由文本会变成新的泄露面。
 * @param outcome 结果。[UltraModuleOutcome.UNKNOWN] 是合法值。
 * @param detail 脱敏后的补充说明。**进入交付包之前必须经过 [UltraModuleEvidenceSanitizer]**：
 *   本类不阻止调用方塞原文，[UltraModuleEvidenceSanitizer.sanitizeEvidence] 才负责把关。
 */
data class UltraModuleEvent(
    val operationId: String,
    val action: UltraModuleAction,
    val bootId: String,
    val deviceTimeIso: String? = null,
    val hostUtcIso: String,
    val processRole: UltraModuleProcessRole = UltraModuleProcessRole.UNKNOWN,
    val processPid: Int? = null,
    val phase: UltraModulePhase = UltraModulePhase.UNKNOWN,
    val returnCode: Int? = null,
    val buildDigest: String? = null,
    val outcome: UltraModuleOutcome = UltraModuleOutcome.UNKNOWN,
    val detail: String = "",
)

/** [UltraModuleEvidenceJson.decode] 的结果：事件本身 + 这次解析降级了哪些字段。 */
data class UltraModuleDecodedEvent(
    val event: UltraModuleEvent,
    /**
     * 缺失或取值无法识别的字段名。这些字段在 [event] 里是**默认值**，默认值不是事实：
     * 聚合/统计要把它们当“不完整事件”，不能把默认的 `INSTALL`/`UNKNOWN` 当成观测结果。
     */
    val missingFields: List<String> = emptyList(),
    /** 本行里出现但本 schema 不认识的字段名（向前兼容：忽略，但记录，方便发现格式漂移）。 */
    val ignoredFields: List<String> = emptyList(),
)

/** [UltraModuleEvidenceJson.decodeLines] 的结果：解析成功的事件 + 被拒绝的行号（1 起）。 */
data class UltraModuleDecodedLines(
    val events: List<UltraModuleDecodedEvent> = emptyList(),
    val rejectedLines: List<Int> = emptyList(),
)

/**
 * 单行 JSON（JSONL）编解码。
 *
 * 约束：
 *  - 只编码扁平对象；字段顺序固定为 [UltraModuleEvidenceSchema.FIELDS]；
 *  - `encode(decode(encode(e))) == encode(e)`，且 `decode(encode(e)).event == e`；
 *  - 缺字段照常解析（缺失字段进 [UltraModuleDecodedEvent.missingFields]），未知字段忽略但记录；
 *  - 行不是合法扁平 JSON 对象时返回 null，不猜、不做“尽力修复”（坏行进
 *    [UltraModuleDecodedLines.rejectedLines]）。
 *
 * 只支持本 schema 需要的值类型：字符串、整数、`null`。布尔与嵌套结构不产出；遇到时按“取值
 * 无法识别”处理（进 missingFields），不会让整行失败。
 */
object UltraModuleEvidenceJson {

    private const val NULL = "null"

    /** 把一个事件编码成单行 JSON。字段顺序稳定，不输出换行。 */
    fun encode(event: UltraModuleEvent): String {
        val parts = ArrayList<String>(UltraModuleEvidenceSchema.FIELDS.size)
        fun put(name: String, encoded: String) {
            parts += "\"" + name + "\":" + encoded
        }
        put("operationId", quote(event.operationId))
        put("action", quote(event.action.name))
        put("bootId", quote(event.bootId))
        put("deviceTimeIso", event.deviceTimeIso?.let(::quote) ?: NULL)
        put("hostUtcIso", quote(event.hostUtcIso))
        put("processRole", quote(event.processRole.name))
        put("processPid", event.processPid?.toString() ?: NULL)
        put("phase", quote(event.phase.name))
        put("returnCode", event.returnCode?.toString() ?: NULL)
        put("buildDigest", event.buildDigest?.let(::quote) ?: NULL)
        put("outcome", quote(event.outcome.name))
        put("detail", quote(event.detail))
        return parts.joinToString(separator = ",", prefix = "{", postfix = "}")
    }

    /**
     * JSONL 的“一行”。当前实现与 [encode] 相同（编码结果不含换行），单独留一个名字是为了让
     * 调用方按行写文件时语义清楚：写 `encodeLine(event) + "\n"`。
     */
    fun encodeLine(event: UltraModuleEvent): String = encode(event)

    /** 解析一行。返回 null 表示这一行不是合法的扁平 JSON 对象。 */
    fun decode(line: String): UltraModuleDecodedEvent? {
        val text = line.trim()
        if (text.isEmpty()) return null
        val document = JsonObjectReader(text).readObject() ?: return null
        val missing = ArrayList<String>(4)
        val ignored = document.keys.filter { it !in UltraModuleEvidenceSchema.FIELDS }

        fun textField(name: String): String? = (document[name] as? JsonValue.Text)?.value
        fun intField(name: String): Int? = (document[name] as? JsonValue.Number)?.raw?.toIntOrNull()
        fun requiredText(name: String): String {
            val value = textField(name)
            if (value == null) missing += name
            return value.orEmpty()
        }
        fun <T : Enum<T>> enumField(name: String, allowed: Array<T>, fallback: T): T {
            val raw = textField(name)
            if (raw == null) {
                missing += name
                return fallback
            }
            val parsed = allowed.firstOrNull { it.name == raw }
            if (parsed == null) missing += name
            return parsed ?: fallback
        }

        val event = UltraModuleEvent(
            operationId = requiredText("operationId"),
            action = enumField("action", UltraModuleAction.values(), UltraModuleAction.INSTALL),
            bootId = requiredText("bootId"),
            deviceTimeIso = textField("deviceTimeIso"),
            hostUtcIso = requiredText("hostUtcIso"),
            processRole = enumField(
                "processRole",
                UltraModuleProcessRole.values(),
                UltraModuleProcessRole.UNKNOWN,
            ),
            processPid = intField("processPid"),
            phase = enumField("phase", UltraModulePhase.values(), UltraModulePhase.UNKNOWN),
            returnCode = intField("returnCode"),
            buildDigest = textField("buildDigest"),
            outcome = enumField("outcome", UltraModuleOutcome.values(), UltraModuleOutcome.UNKNOWN),
            detail = requiredText("detail"),
        )
        return UltraModuleDecodedEvent(event, missing, ignored)
    }

    /**
     * 按行解析整份 JSONL。空行跳过；坏行进 [UltraModuleDecodedLines.rejectedLines]（1 起行号），
     * 不抛异常、不丢整份文件。
     */
    fun decodeLines(content: String): UltraModuleDecodedLines {
        val events = ArrayList<UltraModuleDecodedEvent>()
        val rejected = ArrayList<Int>()
        content.lineSequence().forEachIndexed { index, line ->
            if (line.isBlank()) return@forEachIndexed
            val decoded = decode(line)
            if (decoded == null) rejected += index + 1 else events += decoded
        }
        return UltraModuleDecodedLines(events, rejected)
    }

    // ------------------------------------------------------------------ escaping

    private fun quote(value: String): String {
        val out = StringBuilder(value.length + 2)
        out.append('"')
        for (character in value) {
            when (character) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                else -> if (character.code < 0x20 || character.code == 0x7f) {
                    out.append("\\u")
                    val hex = character.code.toString(16)
                    repeat(4 - hex.length) { out.append('0') }
                    out.append(hex)
                } else {
                    out.append(character)
                }
            }
        }
        return out.append('"').toString()
    }

    // ------------------------------------------------------------------ minimal JSON (flat)

    private sealed interface JsonValue {
        data class Text(val value: String) : JsonValue
        data class Number(val raw: String) : JsonValue
        /** `null`/布尔/嵌套结构：本 schema 不使用，保留原文以便区分“存在但不可用”和“缺失”。 */
        data class Opaque(val raw: String) : JsonValue
    }

    /**
     * 只解析扁平对象。故意不实现完整 JSON：
     *  - 支持 `{ "k": "v", "n": 1, "x": null }`；
     *  - 嵌套值按 Opaque 跳过（本 schema 不产出，也不会因为别人的新字段而整行失败）；
     *  - 语法错误、尾随垃圾、非对象 → null。
     */
    private class JsonObjectReader(private val source: String) {
        private var position = 0
        private val length = source.length

        fun readObject(): LinkedHashMap<String, JsonValue>? {
            skipWhitespace()
            if (position >= length || source[position] != '{') return null
            position++
            val result = LinkedHashMap<String, JsonValue>()
            fun complete(): LinkedHashMap<String, JsonValue>? {
                skipWhitespace()
                return if (position == length) result else null
            }
            skipWhitespace()
            if (position < length && source[position] == '}') {
                position++
                return complete()
            }
            while (true) {
                skipWhitespace()
                val key = readString() ?: return null
                skipWhitespace()
                if (position >= length || source[position] != ':') return null
                position++
                val value = readValue() ?: return null
                result[key] = value
                skipWhitespace()
                if (position >= length) return null
                when (source[position]) {
                    ',' -> position++
                    '}' -> {
                        position++
                        return complete()
                    }
                    else -> return null
                }
            }
        }

        private fun skipWhitespace() {
            while (position < length && source[position].isWhitespace()) position++
        }

        private fun readString(): String? {
            if (position >= length || source[position] != '"') return null
            position++
            val out = StringBuilder()
            while (position < length) {
                val character = source[position++]
                when {
                    character == '"' -> return out.toString()
                    character == '\\' -> {
                        if (position >= length) return null
                        when (val escape = source[position++]) {
                            '"' -> out.append('"')
                            '\\' -> out.append('\\')
                            '/' -> out.append('/')
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000C')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> {
                                if (position + 4 > length) return null
                                val code = source.substring(position, position + 4).toIntOrNull(16)
                                    ?: return null
                                out.append(code.toChar())
                                position += 4
                            }
                            else -> return null
                        }
                    }
                    character.code < 0x20 -> return null
                    else -> out.append(character)
                }
            }
            return null
        }

        private fun readValue(): JsonValue? {
            skipWhitespace()
            if (position >= length) return null
            return when (source[position]) {
                '"' -> readString()?.let { JsonValue.Text(it) }
                '{', '[' -> readNested()
                else -> readBare()
            }
        }

        /** 跳过一整段嵌套结构并保留原文（本 schema 不产出，只用于向前兼容）。 */
        private fun readNested(): JsonValue.Opaque? {
            val start = position
            var depth = 0
            while (position < length) {
                when (source[position]) {
                    '"' -> {
                        // 字符串里的括号不算深度；直接复用转义扫描，但不要写进结果。
                        if (skipString() == null) return null
                        continue
                    }
                    '{', '[' -> depth++
                    '}', ']' -> {
                        depth--
                        if (depth == 0) {
                            position++
                            return JsonValue.Opaque(source.substring(start, position))
                        }
                    }
                }
                position++
            }
            return null
        }

        private fun skipString(): String? {
            if (position >= length || source[position] != '"') return null
            position++
            val out = StringBuilder()
            while (position < length) {
                val character = source[position++]
                when {
                    character == '"' -> return out.toString()
                    character == '\\' -> {
                        if (position >= length) return null
                        when (source[position++]) {
                            'u' -> {
                                if (position + 4 > length) return null
                                position += 4
                            }
                            else -> Unit
                        }
                    }
                    else -> Unit
                }
            }
            return null
        }

        private fun readBare(): JsonValue? {
            val start = position
            while (position < length && source[position] !in ",}]\t\r\n ") position++
            val raw = source.substring(start, position).trim()
            if (raw.isEmpty()) return null
            return when {
                NUMBER.matches(raw) -> JsonValue.Number(raw)
                else -> JsonValue.Opaque(raw)
            }
        }

        private companion object {
            val NUMBER = Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
        }
    }
}

/** [UltraModuleEvidenceSanitizer.sanitizeDetail] 的结果。 */
sealed interface UltraModuleSanitizedDetail {
    /** 已脱敏的 detail。[hits] 是命中的规则名（不含原文）。 */
    data class Redacted(val text: String, val hits: List<String>) : UltraModuleSanitizedDetail

    /** 无法安全脱敏。[reason] 是稳定原因码，可以进交付包；原文不出现。 */
    data class Unsafe(val reason: String) : UltraModuleSanitizedDetail
}

/** [UltraModuleEvidenceSanitizer.sanitizeEvidence] 的结果。 */
sealed interface UltraModuleEvidenceWrite {
    /** 可以进交付包的事件。[notes] 是脱敏/降级记录（不含原文）。 */
    data class Recorded(val event: UltraModuleEvent, val notes: List<String>) : UltraModuleEvidenceWrite

    /** 整条丢弃。[reason] 是稳定原因码；丢弃本身应当被计数，不能静默。 */
    data class Dropped(val reason: String) : UltraModuleEvidenceWrite
}

/** detail 无法安全脱敏时的处置方式。 */
enum class UltraModuleUnsafeRedactionPolicy {
    /** 默认：整条事件丢弃。宁可少记一条，也不把无法证明已脱敏的原文带进交付包。 */
    DROP_WHOLE_EVENT,

    /**
     * 保底：事件保留，detail 换成 `<detail-dropped:原因>`。
     * 只在“必须知道这一步发生过”的场景使用；原因码本身不含原文，但语义比丢掉事件弱。
     */
    KEEP_WITH_MARKER,
}

class UltraModuleEvidenceSanitizer(
    val policy: UltraModuleUnsafeRedactionPolicy = UltraModuleUnsafeRedactionPolicy.DROP_WHOLE_EVENT,
) {

    /**
     * 结构保持的路径脱敏。
     *
     * 保留：`/data`、已知公共环境段（`adb`/`data`/`user`/`media`/`local`/`misc`/`system`/`vendor`）、
     * `modules`、模块 id（32 位十六进制）或模块名（≤47 位的安全字符），以及**段数**。
     * 替换：不认识的环境段 → `<env>`；包名 → `<package>`；用户号 → `<user>`；
     * 其余实例段（配置、日志、缓存目录名）→ `<data-item>`/`<seg>`。
     *
     * 这样一条路径仍然能回答“它在哪个环境、是不是模块目录、有多深”，但回答不了“这台设备的
     * 完整私有目录长什么样”。非 `/data` 路径原样返回：它们不是本类定义的私有目录，其中的
     * secret 由 [redact] 的规则 2/3 处理。
     */
    fun redactPath(path: String): String {
        val trimmed = path.trim()
        if (trimmed.isEmpty()) return ""
        val absolute = if (trimmed.startsWith('/')) trimmed else "/$trimmed"
        val segments = absolute.split('/').filter { it.isNotEmpty() }
        if (segments.isEmpty() || segments[0] != "data") return path
        if (segments.size == 1) return "/data"

        val environment = segments[1]
        val environmentIsPublic = environment in PUBLIC_ENV_SEGMENTS
        val result = ArrayList<String>(segments.size + 2)
        result += "data"
        result += if (environmentIsPublic) environment else ENV_PLACEHOLDER

        // 模块目录可能是 /data/adb/modules/<模块>，也可能是 /data/<环境>/modules/<模块>
        // （冻结证据里 Ultra 宿主的模块目录就不在 /data/adb 下）。
        val modulesIndex = (2..3).firstOrNull { it < segments.size && segments[it] == "modules" }
        if (modulesIndex != null) {
            for (index in 2 until modulesIndex) result += SEGMENT_PLACEHOLDER
            result += "modules"
            val moduleIndex = modulesIndex + 1
            if (moduleIndex < segments.size) {
                result += moduleSegmentPlaceholder(segments[moduleIndex])
                for (index in (moduleIndex + 1) until segments.size) result += SEGMENT_PLACEHOLDER
            }
            return "/" + result.joinToString("/")
        }

        when {
            environment == "data" -> {
                if (segments.size > 2) result += PACKAGE_PLACEHOLDER
                for (index in 3 until segments.size) result += SEGMENT_PLACEHOLDER
            }
            environment == "user" -> {
                if (segments.size > 2) result += USER_PLACEHOLDER
                if (segments.size > 3) result += PACKAGE_PLACEHOLDER
                for (index in 4 until segments.size) result += SEGMENT_PLACEHOLDER
            }
            environment == "media" -> {
                if (segments.size > 2) result += USER_PLACEHOLDER
                for (index in 3 until segments.size) result += SEGMENT_PLACEHOLDER
            }
            environmentIsPublic -> {
                if (segments.size > 2) result += DATA_ITEM_PLACEHOLDER
                for (index in 3 until segments.size) result += SEGMENT_PLACEHOLDER
            }
            else -> {
                for (index in 2 until segments.size) result += SEGMENT_PLACEHOLDER
            }
        }
        return "/" + result.joinToString("/")
    }

    /** 只做替换的脱敏（不判断安全性）。需要“不能安全脱敏就丢弃”的语义请用 [sanitizeDetail]。 */
    fun redact(text: String): String = redactWithHits(text).first

    /** 与 [redact] 相同，但返回命中的规则名，便于把“这条被改过”记进 notes（不含原文）。 */
    fun redactWithHits(text: String): Pair<String, List<String>> {
        if (text.isEmpty()) return text to emptyList()
        val hits = LinkedHashSet<String>()
        val redacted = SCAN.replace(text) { match ->
            val groups = match.groups
            when {
                groups[1] != null -> {
                    hits += "private-path"
                    redactPath(trimPartialPlaceholder(match.value))
                }
                groups[2] != null -> {
                    hits += "relative-private-path"
                    redactPath(trimPartialPlaceholder(match.value))
                }
                groups[3] != null -> {
                    hits += "hex-secret"
                    HEX_PLACEHOLDER
                }
                else -> {
                    hits += "token-secret"
                    TOKEN_PLACEHOLDER
                }
            }
        }
        return redacted to hits.toList()
    }

    /**
     * 把 detail 变成可交付文本；不安全时返回 [UltraModuleSanitizedDetail.Unsafe]。
     *
     * detail 已经是脱敏后文本时再调用一次是幂等的（模块 id 的例外位置在规则里排除了）。
     */
    fun sanitizeDetail(text: String): UltraModuleSanitizedDetail {
        unsafeDetailReason(text)?.let { return UltraModuleSanitizedDetail.Unsafe(it) }
        val (redacted, hits) = redactWithHits(text)
        return UltraModuleSanitizedDetail.Redacted(redacted, hits)
    }

    /**
     * 校验一条事件的**结构化字段**是否可交付（detail 必须已脱敏或由 [sanitizeEvidence] 提供）。
     * 返回 null 表示没有问题；否则是稳定原因码。
     *
     * 这些字段不合格时一律丢弃整条事件：`operationId`/`bootId` 不干净会让事件无法与其它证据
     * 对齐，`hostUtcIso` 不是 ISO-8601 就无法判断时区，PID 越界说明采集端读错了东西。
     * 这些不是“泄露”问题，而是“这条记录不可信”问题，所以 [UltraModuleUnsafeRedactionPolicy]
     * 不改变它们的处置。
     */
    fun unsafeReason(event: UltraModuleEvent): String? {
        if (!MACHINE_TOKEN.matches(event.operationId)) return "operation-id-not-machine-safe"
        if (event.bootId.isNotEmpty() && !MACHINE_TOKEN.matches(event.bootId)) {
            return "boot-id-not-machine-safe"
        }
        if (!ISO_8601.matches(event.hostUtcIso)) return "host-utc-not-iso8601"
        val deviceTime = event.deviceTimeIso
        if (deviceTime != null && !ISO_8601.matches(deviceTime)) return "device-time-not-iso8601"
        val pid = event.processPid
        if (pid != null && (pid <= 0 || pid > MAX_LINUX_PID)) return "process-pid-out-of-range"
        if (event.detail.length > MAX_DETAIL_CHARS) return "detail-too-long"
        if (redact(event.detail) != event.detail) return "detail-not-fully-redacted"
        return null
    }

    /**
     * 把一条原始事件变成可交付事件：
     *  1. detail 脱敏；无法安全脱敏时按 [policy] 丢弃整条或换成原因标记；
     *  2. `buildDigest` 只允许十六进制摘要（32/40/64 位），否则置空并记 note（不让自由文本混进摘要字段）；
     *  3. 结构化字段校验失败 → 一律丢弃（见 [unsafeReason]）。
     *
     * 返回 [UltraModuleEvidenceWrite.Recorded] 才允许写进 JSONL；[UltraModuleEvidenceWrite.Dropped]
     * 必须计数，否则“少了一条”会变成不可见。
     */
    fun sanitizeEvidence(raw: UltraModuleEvent): UltraModuleEvidenceWrite {
        val notes = ArrayList<String>(4)
        val detail = when (val sanitized = sanitizeDetail(raw.detail)) {
            is UltraModuleSanitizedDetail.Unsafe -> {
                if (policy == UltraModuleUnsafeRedactionPolicy.DROP_WHOLE_EVENT) {
                    return UltraModuleEvidenceWrite.Dropped("detail:${sanitized.reason}")
                }
                notes += "detail-dropped:${sanitized.reason}"
                "$DROPPED_DETAIL_PREFIX${sanitized.reason}>"
            }
            is UltraModuleSanitizedDetail.Redacted -> {
                notes += sanitized.hits
                sanitized.text
            }
        }
        val event = raw.copy(detail = detail, buildDigest = normalizeBuildDigest(raw.buildDigest, notes))
        unsafeReason(event)?.let { return UltraModuleEvidenceWrite.Dropped("fields:$it") }
        return UltraModuleEvidenceWrite.Recorded(event, notes.distinct())
    }

    // ------------------------------------------------------------------ internals

    private fun unsafeDetailReason(text: String): String? {
        if (text.length > MAX_DETAIL_CHARS) return "detail-too-long"
        if (text.any { it.isISOControl() && it != '\n' && it != '\r' && it != '\t' }) {
            return "detail-has-control-characters"
        }
        if (hasUnpairedSurrogate(text)) return "detail-has-unpaired-surrogate"
        if (PEM_PRIVATE_KEY.containsMatchIn(text)) return "detail-has-private-key-block"
        return null
    }

    private fun hasUnpairedSurrogate(text: String): Boolean {
        var index = 0
        while (index < text.length) {
            val character = text[index]
            if (character.isHighSurrogate()) {
                if (index + 1 >= text.length || !text[index + 1].isLowSurrogate()) return true
                index += 2
                continue
            }
            if (character.isLowSurrogate()) return true
            index++
        }
        return false
    }

    private fun normalizeBuildDigest(value: String?, notes: MutableList<String>): String? {
        val trimmed = value?.trim().orEmpty()
        if (trimmed.isEmpty()) return null
        val normalized = trimmed.lowercase()
        if (BUILD_DIGEST.matches(normalized)) return normalized
        notes += "build-digest-dropped"
        return null
    }

    /**
     * 路径匹配的收尾：去掉句末标点，并处理“占位符被匹配截断”的情况。
     *
     * 已经脱敏过的 detail 里会出现 `/data/adb/modules/<module>/<seg>` 这样的文本；正则允许 `<`
     * `>` 是为了让这种文本再跑一遍时仍是固定点（幂等），遇到被截断的半个占位符（`<` 之后不是
     * 完整 `>`）就退回 `<` 之前，避免把半个占位符当成路径段。
     */
    private fun trimPartialPlaceholder(raw: String): String {
        val trimmed = raw.trimEnd('.', ',', '/')
        val open = trimmed.indexOf('<')
        if (open < 0) return trimmed
        if (trimmed.endsWith(">")) return trimmed
        val head = trimmed.substring(0, open).trimEnd('/')
        return if (head.isEmpty()) "/" else head
    }

    /**
     * 模块目录名的处置。模块 id（32 位十六进制）与短模块名是公开身份，保留；其余一律 `<module>`：
     *  - 32 位十六进制 = 冻结证据里的模块 id，是审计必需的键；
     *  - ≤47 位安全字符 = 模块自己声明的目录名，冻结证据里同样原样保留；
     *  - 更长的、含 32 位以上十六进制的（可能是 key）→ `<module>`。
     */
    private fun moduleSegmentPlaceholder(segment: String): String = when {
        MODULE_ID.matches(segment) -> segment
        SAFE_MODULE_NAME.matches(segment) && !HEX_RUN.containsMatchIn(segment) -> segment
        else -> MODULE_PLACEHOLDER
    }

    companion object {
        /**
         * detail 上限。超过就丢：证据 detail 不是日志转储，超长通常意味着抓错了对象
         * （例如整段 logcat），而越长的文本越难保证脱敏完整。
         */
        const val MAX_DETAIL_CHARS = 4096

        /** Linux 的 PID 上限（`pid_max` 默认 4194304）。超出说明字段被写坏了。 */
        const val MAX_LINUX_PID = 4_194_304

        const val HEX_PLACEHOLDER = "<hex>"
        const val TOKEN_PLACEHOLDER = "<token>"
        const val ENV_PLACEHOLDER = "<env>"
        const val MODULE_PLACEHOLDER = "<module>"
        const val PACKAGE_PLACEHOLDER = "<package>"
        const val USER_PLACEHOLDER = "<user>"
        const val DATA_ITEM_PLACEHOLDER = "<data-item>"
        const val SEGMENT_PLACEHOLDER = "<seg>"
        const val DROPPED_DETAIL_PREFIX = "<detail-dropped:"

        private val PUBLIC_ENV_SEGMENTS = setOf(
            "adb",
            "data",
            "user",
            "media",
            "local",
            "misc",
            "system",
            "vendor",
            "app",
            "dalvik-cache",
        )

        private val MACHINE_TOKEN = Regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
        private val ISO_8601 =
            Regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})$")
        private val MODULE_ID = Regex("^[0-9a-fA-F]{32}$")
        private val SAFE_MODULE_NAME = Regex("^[A-Za-z0-9._-]{1,47}$")
        private val HEX_RUN = Regex("[0-9a-fA-F]{32,}")
        private val BUILD_DIGEST = Regex("^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
        private val PEM_PRIVATE_KEY = Regex("-----BEGIN [A-Z ]*PRIVATE KEY-----")

        /**
         * 单趟扫描：路径、相对私有路径、十六进制 secret、长凭据。必须单趟，否则“模块目录里的
         * 模块 id”会被后续的十六进制规则再替换一次（那就不可核对、也不再幂等）。
         * 十六进制规则的 `(?<!/modules/)` 就是为这个例外位置准备的（定长，Java 正则支持）。
         */
        private val SCAN = Regex(
            """(/data/[A-Za-z0-9._/<>-]+)""" +
                """|(?<![0-9A-Za-z._/-])(data/(?:adb|data|user|media|local|misc|system|vendor)/[A-Za-z0-9._/<>-]+)""" +
                """|(?<!/modules/)(?<![0-9A-Za-z])([0-9a-fA-F]{32,})(?![0-9A-Za-z])""" +
                """|(?<![0-9A-Za-z])([A-Za-z0-9+/_-]{48,}={0,2})(?![0-9A-Za-z+/=_-])""",
        )
    }
}

/**
 * 退出原因类别。§4.3 要求“管理器 FORCE STOP 与原生异常分别统计”，所以崩溃和外部终止必须是
 * 两个桶，不能合成一个“异常退出”。
 */
enum class UltraModuleExitCategory {
    /**
     * 由外部动作终止的进程：用户/调试器/安装更新/系统策略。**不是崩溃**。
     * 冻结证据里的 `stop dev.maplesu.manager due to set debug app state` 属于这一类。
     */
    MANAGER_FORCE_STOP,

    /** 进程自己死了：收到信号、Java 未捕获异常、原生崩溃。这是真正要追的“原生异常”。 */
    NATIVE_OR_CRASH,

    /** 其它已知终止原因（ANR、主动 exit、低内存、初始化失败、依赖死亡、freezer 等）。 */
    OTHER,

    /** 没有 reason、reason 不认识或超出已知范围。**不属于崩溃桶**。 */
    UNKNOWN,
}

/**
 * 稳定机器码。枚举名即线上码；发布后不要改名。
 */
enum class UltraModuleExitCode {
    /** 系统明确给出 FORCE STOP subreason，但没有更具体的 description。 */
    FORCE_STOP_EXPLICIT_SUBREASON,
    FORCE_STOP_USER_REQUESTED,
    FORCE_STOP_USER_STOPPED,
    /** `description=stop <pkg> due to set debug app state`（冻结证据 #0/#1/#4/#5/#6）。 */
    FORCE_STOP_DEBUG_APP,
    /** `description=stop <pkg> due to finished inst state`（冻结证据 #2/#3/#8/#9/#14/#15）。 */
    FORCE_STOP_INSTRUMENTATION_FINISHED,
    /** `description=stop <pkg> due to installPackageLI state`（冻结证据 #7/#10–#13）。 */
    FORCE_STOP_PACKAGE_INSTALL,
    FORCE_STOP_PACKAGE_UPDATED,
    FORCE_STOP_PACKAGE_STATE_CHANGE,
    FORCE_STOP_PERMISSION_CHANGE,
    /** `REASON_SIGNALED`：被信号杀死（可能是 SDK/模块/系统，也可能是 SIGKILL）。 */
    CRASH_SIGNALED,
    /** `REASON_CRASH`：Java 层未捕获异常。 */
    CRASH_JAVA,
    /** `REASON_CRASH_NATIVE`：原生崩溃（tombstone 通常在这里）。 */
    CRASH_NATIVE,
    OTHER_ANR,
    OTHER_SELF_EXIT,
    OTHER_LOW_MEMORY,
    OTHER_INIT_FAILURE,
    OTHER_EXCESSIVE_RESOURCE,
    OTHER_DEPENDENCY_DIED,
    OTHER_FREEZER,
    OTHER_UNSPECIFIED,
    /** reason 缺失（`REASON_UNKNOWN`）：不知道原因，不猜。 */
    UNKNOWN_MISSING_REASON,
    /** reason 数值不在已知表里：不知道原因，不猜。 */
    UNKNOWN_UNRECOGNIZED_REASON,
}

/**
 * 从 description 里认出来的补充信息。只用于在**已经确定不是崩溃**的前提下细分原因码，
 * 不参与“这是不是崩溃”的判断（否则一次描述漂移就能把崩溃洗掉）。
 */
enum class UltraModuleExitMarker {
    DEBUG_APP,
    FORCE_STOP,
    INSTRUMENTATION_FINISHED,
    PACKAGE_INSTALL,
}

/**
 * 一次退出记录的判定结果。
 *
 * [countsAsForceStop] / [countsAsNativeOrCrash] 是给统计用的：**两个都为 false 才是不计入任何
 * 崩溃统计的“其它/未知”**，不允许用 `category != ...` 之类的反推，避免把 UNKNOWN 又数进崩溃。
 */
data class UltraModuleExitClassification(
    val category: UltraModuleExitCategory,
    val code: UltraModuleExitCode,
    val reason: Int,
    val subreason: Int,
    val marker: UltraModuleExitMarker? = null,
) {
    val countsAsForceStop: Boolean get() = category == UltraModuleExitCategory.MANAGER_FORCE_STOP

    val countsAsNativeOrCrash: Boolean get() = category == UltraModuleExitCategory.NATIVE_OR_CRASH

    /** 机器可读摘要（不含原始 description 文本，避免把设备输出的自由文本带进交付包）。 */
    fun summary(): String = buildString {
        append("reason=").append(reason)
        append(" subreason=").append(subreason)
        append(" category=").append(category.name)
        append(" code=").append(code.name)
        if (marker != null) append(" marker=").append(marker.name)
    }
}

/**
 * 分类计数：FORCE STOP 与原生异常分别统计（§4.3）。
 * [total] 必须等于四类之和；丢弃/未知不并入崩溃。
 */
data class UltraModuleExitTally(
    val managerForceStop: Int = 0,
    val nativeOrCrash: Int = 0,
    val other: Int = 0,
    val unknown: Int = 0,
) {
    val total: Int get() = managerForceStop + nativeOrCrash + other + unknown

    fun plus(classification: UltraModuleExitClassification): UltraModuleExitTally = when (classification.category) {
        UltraModuleExitCategory.MANAGER_FORCE_STOP -> copy(managerForceStop = managerForceStop + 1)
        UltraModuleExitCategory.NATIVE_OR_CRASH -> copy(nativeOrCrash = nativeOrCrash + 1)
        UltraModuleExitCategory.OTHER -> copy(other = other + 1)
        UltraModuleExitCategory.UNKNOWN -> copy(unknown = unknown + 1)
    }

    companion object {
        fun of(classifications: Iterable<UltraModuleExitClassification>): UltraModuleExitTally =
            classifications.fold(UltraModuleExitTally()) { tally, item -> tally.plus(item) }
    }
}

/**
 * 把 `ApplicationExitInfo` 的 reason/subreason/description 分类。
 *
 * ## 为什么不 import `android.app.ApplicationExitInfo`
 *
 * 那是 Android 框架类，JVM 单测里不可用（`android.jar` 是 stub）。这里按 AOSP 的常量**抄一份
 * 数值**并注释来源；数值是跨 API 稳定的（API 30 起没有改过已有取值）。
 * **不 import 的代价**：平台若新增 reason，本类会把它归到
 * [UltraModuleExitCode.UNKNOWN_UNRECOGNIZED_REASON]（未知，不是崩溃）——这正是想要的方向：
 * 新原因先记未知，等有证据再归类，而不是默认当崩溃。
 *
 * ## 判定顺序（顺序本身就是规则）
 *
 * 1. **崩溃原因优先**：`CRASH_NATIVE`/`CRASH`/`SIGNALED` 直接进 [UltraModuleExitCategory.NATIVE_OR_CRASH]，
 *    description 不能把它们改判成 FORCE STOP。反过来才允许 description 细分非崩溃原因。
 * 2. `ANR` 进 [UltraModuleExitCategory.OTHER]（“无响应”不是崩溃，也不是外部 force stop）。
 * 3. 明确的 FORCE STOP：subreason = 21，或 reason ∈ {USER_REQUESTED, USER_STOPPED,
 *    PERMISSION_CHANGE, PACKAGE_STATE_CHANGE, PACKAGE_UPDATED}。
 * 4. reason 本身不提供信息（`UNKNOWN`/`OTHER`/不认识的数值）但有 FORCE STOP 描述 → 按
 *    description 归 FORCE STOP（冻结证据里系统 stop 的 description 就是唯一线索）。
 * 5. 其它已知非崩溃原因 → [UltraModuleExitCategory.OTHER]。
 * 6. `REASON_UNKNOWN` → [UltraModuleExitCategory.UNKNOWN]；不认识的数值 → UNKNOWN。
 */
object UltraModuleExitClassifier {

    /** 与 `android.app.ApplicationExitInfo.REASON_*` 同值（API 30+，取值稳定）。 */
    object Reason {
        const val UNKNOWN = 0
        const val EXIT_SELF = 1
        const val SIGNALED = 2
        const val LOW_MEMORY = 3
        const val CRASH = 4
        const val CRASH_NATIVE = 5
        const val ANR = 6
        const val INITIALIZATION_FAILURE = 7
        const val PERMISSION_CHANGE = 8
        const val EXCESSIVE_RESOURCE_USAGE = 9
        const val USER_REQUESTED = 10
        const val USER_STOPPED = 11
        const val DEPENDENCY_DIED = 12
        const val OTHER = 13
        const val FREEZER = 14
        const val PACKAGE_STATE_CHANGE = 15
        const val PACKAGE_UPDATED = 16
    }

    /**
     * 与 `android.app.ApplicationExitInfo.SUBREASON_*` 同值。
     *
     * `SUBREASON_FORCE_STOP = 21` 不在公开文档里，但**本机实测**的 `dumpsys activity exit-info`
     * 输出就是 `subreason=21 (FORCE STOP)`（冻结证据 `app-exit-info.txt` 第 8 行起）。平台自己
     * 打出的标签是这条数值最强的来源；这里只把它当“系统明确说这是 FORCE STOP”的信号用。
     */
    object Subreason {
        const val UNKNOWN = 0
        const val WAIT_FOR_DEBUGGER = 1
        const val LOW_MEMORY = 2
        const val IMPERCEPTIBLE = 3
        const val EXCESSIVE_CPU = 4
        const val CACHED_IDLE_FORCE_STOP = 5
        const val FORCE_STOP = 21
    }

    fun classify(reason: Int, subreason: Int, description: String? = null): UltraModuleExitClassification {
        val marker = markerOf(description)

        // 1) 崩溃优先，description 不能改判。这是 §2 那条错误归类的反向保护。
        when (reason) {
            Reason.CRASH_NATIVE -> return exit(UltraModuleExitCategory.NATIVE_OR_CRASH, UltraModuleExitCode.CRASH_NATIVE, reason, subreason, null)
            Reason.CRASH -> return exit(UltraModuleExitCategory.NATIVE_OR_CRASH, UltraModuleExitCode.CRASH_JAVA, reason, subreason, null)
            Reason.SIGNALED -> return exit(UltraModuleExitCategory.NATIVE_OR_CRASH, UltraModuleExitCode.CRASH_SIGNALED, reason, subreason, null)
            Reason.ANR -> return exit(UltraModuleExitCategory.OTHER, UltraModuleExitCode.OTHER_ANR, reason, subreason, marker)
        }

        // 2) 系统明确给出 FORCE STOP subreason。
        if (subreason == Subreason.FORCE_STOP) {
            return exit(
                UltraModuleExitCategory.MANAGER_FORCE_STOP,
                marker?.let(::forceStopCodeForMarker) ?: UltraModuleExitCode.FORCE_STOP_EXPLICIT_SUBREASON,
                reason,
                subreason,
                marker,
            )
        }

        // 3) reason 自己就说明是外部终止。
        when (reason) {
            Reason.USER_REQUESTED, Reason.USER_STOPPED -> return exit(
                UltraModuleExitCategory.MANAGER_FORCE_STOP,
                marker?.let(::forceStopCodeForMarker)
                    ?: if (reason == Reason.USER_STOPPED) UltraModuleExitCode.FORCE_STOP_USER_STOPPED else UltraModuleExitCode.FORCE_STOP_USER_REQUESTED,
                reason,
                subreason,
                marker,
            )
            Reason.PERMISSION_CHANGE -> return exit(UltraModuleExitCategory.MANAGER_FORCE_STOP, UltraModuleExitCode.FORCE_STOP_PERMISSION_CHANGE, reason, subreason, marker)
            Reason.PACKAGE_STATE_CHANGE -> return exit(UltraModuleExitCategory.MANAGER_FORCE_STOP, UltraModuleExitCode.FORCE_STOP_PACKAGE_STATE_CHANGE, reason, subreason, marker)
            Reason.PACKAGE_UPDATED -> return exit(UltraModuleExitCategory.MANAGER_FORCE_STOP, UltraModuleExitCode.FORCE_STOP_PACKAGE_UPDATED, reason, subreason, marker)
        }

        // 4) reason 不提供信息时，description 里的 stop 线索是唯一证据。
        if (marker != null && (reason == Reason.UNKNOWN || reason == Reason.OTHER || reason !in 0..16)) {
            return exit(UltraModuleExitCategory.MANAGER_FORCE_STOP, forceStopCodeForMarker(marker), reason, subreason, marker)
        }

        // 5) 其它已知非崩溃原因。
        val known = when (reason) {
            Reason.EXIT_SELF -> UltraModuleExitCode.OTHER_SELF_EXIT
            Reason.LOW_MEMORY -> UltraModuleExitCode.OTHER_LOW_MEMORY
            Reason.INITIALIZATION_FAILURE -> UltraModuleExitCode.OTHER_INIT_FAILURE
            Reason.EXCESSIVE_RESOURCE_USAGE -> UltraModuleExitCode.OTHER_EXCESSIVE_RESOURCE
            Reason.DEPENDENCY_DIED -> UltraModuleExitCode.OTHER_DEPENDENCY_DIED
            Reason.FREEZER -> UltraModuleExitCode.OTHER_FREEZER
            Reason.OTHER -> UltraModuleExitCode.OTHER_UNSPECIFIED
            else -> null
        }
        if (known != null) return exit(UltraModuleExitCategory.OTHER, known, reason, subreason, marker)

        // 6) 未知：不猜，也绝不进崩溃桶。
        val code = if (reason == Reason.UNKNOWN) {
            UltraModuleExitCode.UNKNOWN_MISSING_REASON
        } else {
            UltraModuleExitCode.UNKNOWN_UNRECOGNIZED_REASON
        }
        return exit(UltraModuleExitCategory.UNKNOWN, code, reason, subreason, marker)
    }

    /** 从 description 里认补充线索（大小写不敏感）。只认冻结证据里出现过的系统 stop 文案。 */
    fun markerOf(description: String?): UltraModuleExitMarker? {
        val text = description?.lowercase() ?: return null
        if (text.isEmpty()) return null
        return when {
            text.contains("set debug app state") -> UltraModuleExitMarker.DEBUG_APP
            text.contains("finished inst") -> UltraModuleExitMarker.INSTRUMENTATION_FINISHED
            text.contains("installpackageli") -> UltraModuleExitMarker.PACKAGE_INSTALL
            text.contains("force stop") || text.contains("force-stop") || text.contains("forcestop") ->
                UltraModuleExitMarker.FORCE_STOP
            else -> null
        }
    }

    private fun forceStopCodeForMarker(marker: UltraModuleExitMarker): UltraModuleExitCode = when (marker) {
        UltraModuleExitMarker.DEBUG_APP -> UltraModuleExitCode.FORCE_STOP_DEBUG_APP
        UltraModuleExitMarker.INSTRUMENTATION_FINISHED -> UltraModuleExitCode.FORCE_STOP_INSTRUMENTATION_FINISHED
        UltraModuleExitMarker.PACKAGE_INSTALL -> UltraModuleExitCode.FORCE_STOP_PACKAGE_INSTALL
        UltraModuleExitMarker.FORCE_STOP -> UltraModuleExitCode.FORCE_STOP_EXPLICIT_SUBREASON
    }

    private fun exit(
        category: UltraModuleExitCategory,
        code: UltraModuleExitCode,
        reason: Int,
        subreason: Int,
        marker: UltraModuleExitMarker?,
    ): UltraModuleExitClassification = UltraModuleExitClassification(category, code, reason, subreason, marker)
}
