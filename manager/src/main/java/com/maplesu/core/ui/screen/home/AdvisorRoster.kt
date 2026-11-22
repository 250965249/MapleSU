package com.maplesu.core.ui.screen.home

import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.PI
import kotlin.math.atan2
import kotlin.math.ceil
import kotlin.math.hypot
import kotlin.math.roundToLong
import kotlin.math.sqrt

/*
 * MapleSU 用户顾问计划：名单、头像墙的座位与鱼眼缩放。
 *
 * 名单是 assets/maplesu/advisors/members.json，头像在同目录的 avatars/ 下、按 id 命名。README 里的头像墙由
 * tools/brand/render_advisor_wall.py 从同一份文件生成；这里的排座和缩放与脚本逐项一致，两边是同一面墙。
 */

internal enum class AdvisorGroup(val key: String) {
    AUTHOR("author"),
    THANKS("thanks"),
    BETA("beta"),
}

internal enum class AdvisorLink { GITHUB, TELEGRAM }

internal data class Advisor(
    val id: String,
    val name: String,
    val group: AdvisorGroup,
    /** 特别致谢成员同时参与了内测。 */
    val beta: Boolean = false,
    val role: String? = null,
    val roleEn: String? = null,
    val tags: List<String> = emptyList(),
    val github: String? = null,
    val telegram: String? = null,
    val signature: String? = null,
) {
    /** 身份徽章：作者或特别致谢在前，同时参与内测的再加一枚内测徽章。 */
    val badges: List<AdvisorGroup>
        get() = if (beta && group != AdvisorGroup.BETA) listOf(group, AdvisorGroup.BETA) else listOf(group)

    val links: List<Pair<AdvisorLink, String>>
        get() = buildList {
            github?.let { add(AdvisorLink.GITHUB to "https://github.com/$it") }
            telegram?.let { add(AdvisorLink.TELEGRAM to "https://t.me/$it") }
        }

    /** 英文界面优先用 role_en，没有译文时退回中文原文。 */
    fun role(english: Boolean): String? = if (english) roleEn ?: role else role
}

/** 一位成员在六边形格点上的座位：格距为 1 的坐标，[shell] 是从中心数起的第几圈。 */
internal data class AdvisorSeat(val advisor: Advisor, val x: Double, val y: Double, val shell: Int) {
    val distance: Double get() = hypot(x, y)
}

internal object AdvisorRoster {
    const val MEMBERS_ASSET = "maplesu/advisors/members.json"
    const val AVATAR_DIR = "maplesu/advisors/avatars"

    private val ID = Regex("^[a-z0-9][a-z0-9-]*$")
    private val SQRT3 = sqrt(3.0)

    /**
     * 解析 members.json。字段不完整、重复或分组未知的成员直接跳过：名单的完整校验由
     * render_advisor_wall.py 在单元测试里把关，这里只保证界面不因一条坏数据崩溃。
     */
    fun parse(text: String): List<Advisor> {
        val array = JSONObject(text).optJSONArray("members") ?: return emptyList()
        val seen = HashSet<String>()
        return (0 until array.length()).mapNotNull { index ->
            val item = array.optJSONObject(index) ?: return@mapNotNull null
            val id = item.optString("id")
            val name = item.optString("name").trim()
            val group = AdvisorGroup.entries.firstOrNull { it.key == item.optString("group") }
            if (!ID.matches(id) || name.isEmpty() || group == null || !seen.add(id)) return@mapNotNull null
            Advisor(
                id = id,
                name = name,
                group = group,
                beta = item.optBoolean("beta"),
                role = item.text("role"),
                roleEn = item.text("role_en"),
                tags = item.optJSONArray("tags")?.strings().orEmpty(),
                github = item.text("github"),
                telegram = item.text("telegram"),
                signature = item.text("signature"),
            )
        }
    }

    /** 作者、特别致谢、内测用户，组内保持名单顺序。 */
    fun ordered(members: List<Advisor>): List<Advisor> = members.sortedBy { it.group.ordinal }

    /** 单位格距的尖顶六边形格点 (x, y)，按到中心的距离分圈，圈内从正上方起顺时针排列。 */
    fun shells(count: Int): List<List<Pair<Double, Double>>> {
        val reach = ceil(sqrt(count.toDouble())).toInt() + 2
        val cells = ArrayList<Cell>()
        for (q in -reach..reach) {
            for (r in -reach..reach) {
                val x = q + r / 2.0
                val y = r * SQRT3 / 2
                val angle = (atan2(x, -y) + 2 * PI) % (2 * PI)
                cells.add(Cell(micro(hypot(x, y)), micro(angle), x, y))
            }
        }
        cells.sortWith(compareBy<Cell>({ it.distance }, { it.angle }))
        val shells = ArrayList<List<Pair<Double, Double>>>()
        var start = 0
        for (end in 1..cells.size) {
            if (end == cells.size || cells[end].distance != cells[start].distance) {
                shells.add(cells.subList(start, end).map { it.x to it.y })
                start = end
            }
        }
        return shells
    }

    /** 从 [slots] 里尽量均匀地挑出 [count] 个。 */
    fun spread(count: Int, slots: List<Int>): List<Int> = List(count) { k -> slots[k * slots.size / count] }

    /**
     * 作者居中，然后是特别致谢成员、内测用户，一圈一圈往外坐。某一组坐不满一圈时均匀散开，下一组坐
     * 剩下的位子；最外面没坐满的一圈整体均匀散开。结果按圈、圈内按顺时针排列。
     */
    fun seats(members: List<Advisor>): List<AdvisorSeat> {
        var queue = ordered(members)
        val placed = ArrayList<AdvisorSeat>(queue.size)
        for ((shell, cells) in shells(queue.size).withIndex()) {
            if (queue.isEmpty()) break
            val take = queue.take(cells.size)
            queue = queue.drop(cells.size)
            var free = spread(take.size, cells.indices.toList())
            val chosen = HashMap<Int, Advisor>()
            val runs = runs(take)
            for (run in runs.dropLast(1)) {
                val picks = spread(run.size, free)
                picks.zip(run).forEach { (slot, advisor) -> chosen[slot] = advisor }
                free = free.filterNot { it in picks }
            }
            free.zip(runs.last()).forEach { (slot, advisor) -> chosen[slot] = advisor }
            for (slot in chosen.keys.sorted()) {
                val (x, y) = cells[slot]
                placed.add(AdvisorSeat(chosen.getValue(slot), x, y, shell))
            }
        }
        return placed
    }

    private class Cell(val distance: Long, val angle: Long, val x: Double, val y: Double)

    /** 与脚本的 round(value, 6) 同一精度，避免浮点误差把同一圈拆开。 */
    private fun micro(value: Double): Long = (value * 1_000_000).roundToLong()

    /** 连续同组的成员分成一段。 */
    private fun runs(members: List<Advisor>): List<List<Advisor>> {
        val runs = ArrayList<MutableList<Advisor>>()
        for (advisor in members) {
            if (runs.isEmpty() || runs.last().first().group != advisor.group) {
                runs.add(mutableListOf(advisor))
            } else {
                runs.last().add(advisor)
            }
        }
        return runs
    }

    private fun JSONObject.text(key: String): String? =
        if (has(key)) optString(key).trim().takeIf { it.isNotEmpty() } else null

    private fun JSONArray.strings(): List<String> =
        (0 until length()).mapNotNull { index -> optString(index).trim().takeIf { it.isNotEmpty() } }
}

/**
 * 头像墙的鱼眼：靠近中心的头像保持原大，越往外越小。参数与 render_advisor_wall.py 相同。
 *
 * 距离都以透镜半径为单位：[scale] 是头像在归一化半径 u 处的缩放，[radius] 是它的积分，即头像实际画在
 * 离中心多远——这样相邻的头像按各自缩小后的大小挨着，不会互相压住或拉开空隙。
 */
internal object AdvisorLens {
    const val FLAT = 0.2f
    const val EDGE_SCALE = 0.5f
    const val FADE_END = 1.75f
    const val FILL = 0.9f
    const val AUTHOR_SCALE = 1.42f

    /** 透镜半径是格距的几倍（脚本里的 LENS / PITCH）。 */
    const val LENS_PITCHES = 245f / 104f

    fun scale(u: Float): Float = when {
        u <= FLAT -> 1f
        u <= 1f -> 1f - (1f - EDGE_SCALE) * smooth((u - FLAT) / (1f - FLAT))
        else -> EDGE_SCALE * (1f - smooth((u - 1f) / (FADE_END - 1f)))
    }

    fun radius(u: Float): Float {
        if (u <= FLAT) return u
        val inner = 1f - FLAT
        if (u <= 1f) return u - (1f - EDGE_SCALE) * inner * smoothArea((u - FLAT) / inner)
        val outer = FADE_END - 1f
        val t = ((u - 1f) / outer).coerceAtMost(1f)
        return 1f - (1f - EDGE_SCALE) * inner * 0.5f + EDGE_SCALE * outer * (t - smoothArea(t))
    }

    private fun smooth(t: Float): Float {
        val c = t.coerceIn(0f, 1f)
        return c * c * (3f - 2f * c)
    }

    /** [smooth] 在 0..t 上的积分。 */
    private fun smoothArea(t: Float): Float {
        val c = t.coerceIn(0f, 1f)
        return c * c * c - c * c * c * c / 2f
    }
}
