package me.yuki.fina.adbroot.flow

import android.util.JsonReader
import me.yuki.fina.adbroot.core.KernelMap
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader
import java.nio.charset.Charset

/**
 * 生成 /data/adb/kall 需要的假 kallsyms：
 * 官方符号表 + 本次运行的 slide，格式和 /proc/kallsyms 一致（"%016x 类型 名字"）。
 */
object Kallsyms {

    fun build(symbolsJson: File, out: File, slide: Long): Int {
        if (!symbolsJson.exists()) return 0
        var count = 0
        val sb = StringBuilder(9 * 1024 * 1024)
        FileInputStream(symbolsJson).use { fis ->
            JsonReader(InputStreamReader(fis, Charset.forName("UTF-8"))).use { reader ->
                reader.beginObject()
                while (reader.hasNext()) {
                    if (reader.nextName() != "symbols") {
                        reader.skipValue()
                        continue
                    }
                    reader.beginArray()
                    while (reader.hasNext()) {
                        var name = ""
                        var type = ""
                        var address = ""
                        reader.beginObject()
                        while (reader.hasNext()) {
                            when (reader.nextName()) {
                                "name" -> name = reader.nextString()
                                "type" -> type = reader.nextString()
                                "address" -> address = reader.nextString()
                                else -> reader.skipValue()
                            }
                        }
                        reader.endObject()
                        if (name.isEmpty() || name.any { it == ' ' || it == '\t' || it == '\n' }) continue
                        val base = KernelMap.parseU64(address) ?: continue
                        sb.append(String.format("%016x %s %s\n", base + slide, type, name))
                        count++
                    }
                    reader.endArray()
                }
                reader.endObject()
            }
        }
        out.writeText(sb.toString(), Charset.forName("US-ASCII"))
        return count
    }
}
