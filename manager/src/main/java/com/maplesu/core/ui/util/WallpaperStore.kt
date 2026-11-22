package com.maplesu.core.ui.util

import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalConfiguration
import com.maplesu.core.data.repository.SettingsRepositoryImpl
import com.maplesu.core.ksuApp
import java.io.File

/**
 * 个性化壁纸:背景图 / 背景视频。**竖屏、横屏各存一套**(v0.13.160)。
 *
 * 文件存在应用私有目录,不需要任何存储权限。
 * 路径和类型记在设置里,换壁纸不用重编 APK。
 *
 * 分朝向规则(重要,见 [Slot] / [effective]):
 * · [Slot.PORTRAIT] 用的是**老的那份**设置(key 没变),老用户升级后数据原样保留;
 * · [Slot.LANDSCAPE] 是新加的第二份;
 * · 横屏那份**没设**(或文件丢了)→ 自动回退到竖屏那份 = 升级前的样子。
 *   所以老用户什么都不做,观感和以前一模一样。
 *
 * ⛔ 2026-10-30:**内置默认壁纸已彻底移除**。全新安装不再播种默认图,
 * 设置里"没有壁纸"时只画纯主题背景(不写文件、不报错);
 * 用户自己选的壁纸原样保留,渲染侧也只认用户自己那份(见 [resolveDrawn])。
 * 判"读不出来"靠 [hasOwn] 里的可读性探测(存在 + 非空 + 试读 1 字节),见 [isUsable]。
 */
object WallpaperStore {

    /** 换壁纸后 +1,界面靠它触发刷新 */
    var version by mutableIntStateOf(0)
        private set

    /**
     * 🟡（v2.14）Compose 快照状态**统一在主线程上改**。
     *
     * `version` 是 `object` 里的 `mutableIntStateOf`：**写**发生在 IO 线程
     * （换壁纸 / 恢复默认 / 移除都是后台执行器在跑），**读**发生在组合期（主线程）。
     * 跨线程写全局快照状态时机不确定 —— 轻则"换完壁纸界面没立刻刷新"，
     * 重则在下一次快照合并时抛
     * `IllegalStateException: Reading a state that was created after the snapshot was taken`
     * 这类只在真机上偶发、本地永远复现不出来的错。
     * 现在一律走这里：不在主线程就 post 回主线程再改（语义不变，只是延后一帧）。
     */
    private val mainHandler by lazy { android.os.Handler(android.os.Looper.getMainLooper()) }

    private fun bump() {
        if (android.os.Looper.myLooper() === android.os.Looper.getMainLooper()) {
            version++
        } else {
            mainHandler.post { version++ }
        }
    }

    private val repo by lazy { SettingsRepositoryImpl() }

    /**
     * 壁纸槽位:竖屏一份、横屏一份。
     *
     * [PORTRAIT] 就是**原来那一份**(pref key 照旧,老数据不动),
     * 同时充当横屏没单独设时的"通用默认"。
     */
    enum class Slot(val label: String, val dirName: String) {
        PORTRAIT("竖屏", "wallpaper"),
        LANDSCAPE("横屏", "wallpaper_land"),
    }

    private fun kindOf(slot: Slot): String =
        if (slot == Slot.PORTRAIT) repo.wallpaperKind else repo.wallpaperLandKind

    private fun setKind(slot: Slot, value: String) {
        if (slot == Slot.PORTRAIT) repo.wallpaperKind = value else repo.wallpaperLandKind = value
    }

    private fun pathOf(slot: Slot): String =
        if (slot == Slot.PORTRAIT) repo.wallpaperPath else repo.wallpaperLandPath

    private fun setPath(slot: Slot, value: String) {
        if (slot == Slot.PORTRAIT) repo.wallpaperPath = value else repo.wallpaperLandPath = value
    }

    /**
     * 某个朝向**实际生效**的槽位:横屏没单独设 → 回退到竖屏那份(升级前行为)。
     * 注意判据是"文件真的在"([hasOwn]),设置里写着但文件丢了也算没设。
     */
    fun effective(slot: Slot): Slot =
        if (slot == Slot.LANDSCAPE && !hasOwn(Slot.LANDSCAPE)) Slot.PORTRAIT else slot

    /** 某个朝向实际生效的壁纸类型(none / image / video) */
    fun effectiveKind(slot: Slot = Slot.PORTRAIT): String = kindOf(effective(slot))

    /** 某个朝向实际生效的壁纸文件(横屏没单独设时给的就是竖屏那张) */
    fun effectiveFile(slot: Slot = Slot.PORTRAIT): File? = fileOf(effective(slot))

    /** 原来那份(竖屏)壁纸的类型 —— 兼容老调用 */
    fun kind(): String = kindOf(Slot.PORTRAIT)

    /** 某个槽位自己设的壁纸类型(不算回退) */
    fun kind(slot: Slot): String = kindOf(slot)

    /**
     * 某个槽位**自己**有没有可用的壁纸文件(设置里有 + 文件真的读得出来,不算回退)。
     *
     * ⚠️ v2.1(审计 P0-1):判据从 `isFile` 加强成 [isUsable] ——
     * 光看"文件在"是不够的:真机上出现过壁纸文件在、`isFile` 为 true,
     * 但 App **读不出来**(被 root 或别的 uid `chmod 000`、或被 SELinux 挡住)。
     * 那时界面会按"有壁纸"变半透明,却一个像素都解码不出来 →
     * 用户只看到一片灰底,还以为壁纸被吞了。
     * 现在这种文件算"没有",于是自动回退到另一槽;两边都没有就留纯主题背景。
     */
    fun hasOwn(slot: Slot): Boolean {
        val p = pathOf(slot)
        return AppearancePrefsPolicy.hasWallpaper(kindOf(slot)) && p.isNotEmpty() && isUsable(File(p))
    }

    /**
     * 这个朝向**会不会画出壁纸** —— 主题据此决定要不要半透明。
     * 横屏没单独设时看竖屏那份,所以老用户结果和以前一致。
     *
     * 判据是"设置里说这个朝向有壁纸"(空串/`none` 都算没有);
     * 没有内置默认图兜底,所以这里不再假设"一定有东西可画"。
     */
    fun hasWallpaper(slot: Slot): Boolean =
        AppearancePrefsPolicy.hasWallpaper(kindOf(effective(slot)))

    /** 兼容老调用 = 竖屏那份 */
    fun hasWallpaper(): Boolean = hasWallpaper(Slot.PORTRAIT)

    /**
     * 自愈:设置里写着有壁纸,但**文件真的没了**。
     *
     * 以前这种情况是【静默失败】——界面仍按"有壁纸"把卡片/背景变半透明,
     * 却什么都画不出来,用户只看到"壁纸没了",而设置里还显示"当前:图片",极难排查。
     * 现在直接复原成未设置(顺手清掉壁纸主色),界面回到正常观感。
     *
     * 竖屏、横屏两份各自检查:横屏那份丢了就只清横屏那份 → 横屏自动退回竖屏那张。
     *
     * ⚠️ v2.1(审计 P0-1)**关键区分**:只有"文件不存在"才算丢。
     * 文件还在、只是**读不出来**(被 chmod 000 / SELinux 挡住)时**绝不能清设置** ——
     * 那是一次可恢复的权限问题,清掉等于把用户自己设的壁纸扔了;
     * 这种交给渲染链回退到另一槽;两边都不行就是纯主题背景([resolveDrawn] 返回 null)。
     *
     * 本函数要 stat + 试读文件,**必须在 IO 线程调**(界面侧见 WallpaperHost 的
     * LaunchedEffect + withContext(IO);审计 P2-7)。
     *
     * @return 是否做了自愈(调用方可以据此提示用户)
     */
    fun healIfBroken(): Boolean {
        var healed = false
        for (slot in Slot.entries) {
            if (kindOf(slot) == "none") continue
            val p = pathOf(slot)
            // 文件在(哪怕读不出来)→ 不清,交给回退链
            if (p.isNotEmpty() && File(p).isFile) continue
            setPath(slot, "")
            setKind(slot, "none")
            healed = true
        }
        if (!healed) return false
        // 主色取自竖屏那张;竖屏被清掉时主色也得清,否则会拿旧主色去配色
        if (kindOf(Slot.PORTRAIT) == "none") runCatching { repo.wallpaperSeedColor = 0 }
        bump()
        return true
    }

    /** 某一份壁纸设置看起来有、但文件**读不出来**(丢了 / 被改权限都算) —— 给设置页显示 + 回退提示用 */
    fun looksBroken(slot: Slot = Slot.PORTRAIT): Boolean = kindOf(slot) != "none" && !hasOwn(slot)

    /**
     * 文件"真能用吗":存在 + 非空 + **能读**。
     *
     * 为什么必须试读 1 字节:`isFile` 只证明目录项存在,证明不了 App 读得到它。
     * 真机上遇到过壁纸文件在、`isFile` 为 true,却被别的 uid `chmod 000`
     * (或 SELinux 拦下) —— 只看 isFile 就会当成"有壁纸",
     * 界面变半透明却解码不出任何东西 = 一片灰底(审计 P0-1)。
     * 试读正好 1 字节:够暴露 EACCES,又不会把大文件读进内存。
     */
    private fun isUsable(f: File): Boolean {
        if (!f.isFile) return false
        if (f.length() <= 0L) return false
        return runCatching { java.io.FileInputStream(f).use { it.read() } }.isSuccess
    }

    private fun fileOf(slot: Slot): File? {
        val p = pathOf(slot)
        if (p.isEmpty()) return null
        val f = File(p)
        return if (f.isFile) f else null
    }

    /** 某个槽位的壁纸文件(不算回退) */
    fun file(context: Context, slot: Slot): File? = fileOf(slot)

    /** 竖屏(原来那份)壁纸文件 —— 兼容老调用 */
    fun file(context: Context): File? = fileOf(Slot.PORTRAIT)

    /**
     * 复制用户选的图/视频进来,并记住类型。
     * 返回 null = 成功;返回字符串 = 失败原因(界面会提示出来,不再静默失败)
     *
     * @param slot 存到哪一份(竖屏 / 横屏)
     */
    fun save(context: Context, uri: Uri, isVideo: Boolean, slot: Slot = Slot.PORTRAIT): String? {
        // 先保证目录**真的可写**(审计 P1-4):以前只 mkdirs() 不问成败,
        // 目录不可写时后面会在 openInputStream/copyTo 那步抛一个难懂的错误。
        val dir = PrivateDir.ensure(context, slot.dirName)
            ?: return "存不进去:应用私有目录不可写(磁盘可能满了)"
        val err = runCatching {
            val ext = if (isVideo) guessVideoExt(context, uri) else "png"
            val dst = File(dir, "wallpaper.$ext")
            // 🔴（v2.18）**先写临时文件 → 校验 → rename 顶替 → 成功后才删旧文件**。
            // 旧写法是 `dir.listFiles()?.forEach { it.delete() }` 先把用户现有壁纸删掉再写：
            // 选到只读/远程 URI（openInputStream 返回 null）、磁盘满、或 copyTo 中途被杀
            // ⇒ 旧壁纸**永久没了**、新壁纸也没写成，`setPath` 还没更新 —— 用户只能重新找原图。
            // 临时文件用固定名：渲染只看 `pathOf(slot)` 指的文件，`.part` 不会被当成壁纸；
            // 万一这次中途被杀，下次保存直接覆盖它，不留垃圾。
            val tmp = File(dir, "wallpaper.$ext.part")
            val input = context.contentResolver.openInputStream(uri)
                ?: return@runCatching "打不开这个文件(权限或格式问题)"
            input.use { ins -> tmp.outputStream().use { outs -> ins.copyTo(outs) } }

            if (!tmp.isFile || tmp.length() <= 0L) {
                tmp.delete()
                return@runCatching "写入失败(文件为空)"
            }
            // 写盘之后**回读一次**:写成功但读不回来(权限/磁盘)等于没写
            if (!isUsable(tmp)) {
                tmp.delete()
                return@runCatching "写入后读不回来(权限或磁盘问题)"
            }

            // 同一目录内 rename 是原子的：要么还是旧的、要么已经是新的，不存在半截
            if (dst.exists() && !dst.delete()) {
                tmp.delete()
                return@runCatching "旧壁纸删不掉(顶替不了)"
            }
            if (!tmp.renameTo(dst)) {
                tmp.delete()
                return@runCatching "落盘失败(顶替不了旧文件)"
            }
            // 顶替成功之后，才清掉这一槽位里**别的**旧文件（例如从图片换成视频留下的 .png）
            dir.listFiles()?.forEach { f ->
                if (f.name != dst.name && f.name.startsWith("wallpaper.")) f.delete()
            }

            setPath(slot, dst.absolutePath)
            setKind(slot, if (isVideo) "video" else "image")
            null
        }.getOrElse { "保存失败:${it.javaClass.simpleName} ${it.message}" }

        // 图片的话顺便把主色提出来(存成设置,主题那边直接读,不用每次算)。
        // 换成视频时要把旧图片的主色清掉,否则会拿旧主色去配色。
        // 主色只认竖屏那张(主题种子色全给一套,横屏那份不参与,免得转个屏整套配色跳变)。
        if (err == null && slot == Slot.PORTRAIT) {
            repo.wallpaperSeedColor = if (isVideo) 0 else extractSeedColor(context)
        }

        // 用户第一次选壁纸时顺手打开「界面透明化」（默认是关的）。
        // 只在 `ui_translucent` 从未保存过时动手：用户手动关过就尊重他的选择。
        if (err == null &&
            AppearancePrefsPolicy.autoEnableTranslucentOnWallpaperPick(repo.uiTranslucentChosen)
        ) {
            repo.uiTranslucent = true
        }

        if (err == null) bump()
        return err
    }

    private fun guessVideoExt(context: Context, uri: Uri): String {
        // 先看真实文件名后缀(最准),再退回 MIME
        runCatching {
            context.contentResolver.query(uri, null, null, null, null)?.use { c ->
                if (c.moveToFirst()) {
                    val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) {
                        val name = c.getString(idx) ?: ""
                        val ext = name.substringAfterLast('.', "").lowercase()
                        if (ext in setOf("mp4", "webm", "mkv", "mov", "3gp", "avi", "ts")) return ext
                    }
                }
            }
        }
        val mime = runCatching { context.contentResolver.getType(uri) }.getOrNull() ?: ""
        return when {
            mime.contains("webm") -> "webm"
            mime.contains("matroska") -> "mkv"
            mime.contains("3gpp") -> "3gp"
            mime.contains("quicktime") -> "mov"
            mime.contains("x-msvideo") -> "avi"
            else -> "mp4"
        }
    }

    /** 两份壁纸一起清掉(设置里的「移除壁纸」= 恢复纯色背景) */
    fun clear() {
        clear(Slot.PORTRAIT)
        clear(Slot.LANDSCAPE)
    }

    /** 只清某一份(设置里的「移除横屏壁纸」) */
    fun clear(slot: Slot) {
        // Imported resources are immutable and may still be needed by export or another slot.
        runCatching { fileOf(slot)?.takeUnless { it.absolutePath.replace('\\','/').contains("/themes/generations/") }?.delete() }
        runCatching { File(ksuApp.filesDir, slot.dirName).deleteRecursively() }
        setPath(slot, "")
        setKind(slot, "none")
        if (slot == Slot.PORTRAIT) runCatching { repo.wallpaperSeedColor = 0 }
        if (slot == Slot.PORTRAIT) {
            val prefs = AppearancePreferences.prefs(ksuApp)
            if (prefs.contains("theme_document")) {
                val j = com.maplesu.core.theme.ThemeRuntime.document(ksuApp)
                j.put("isBackgroundEnabled",false).put("isVideoBackgroundEnabled",false)
                prefs.edit().putString("theme_document",j.toString()).putBoolean("theme_modified",true).apply()
            }
        }
        bump()
    }

    /** 最大边长:超过就降采样,避免大图直接全尺寸解码把内存撑爆 */
    private const val MAX_SIDE = 2400

    /**
     * 解码某个朝向**自己那份**壁纸(横屏没单独设时给的就是竖屏那张)。
     * 先只读尺寸算 inSampleSize,再按最大边 [MAX_SIDE] 采样解码 —— 4K 图也不会整张进内存。
     *
     * 只在 [resolveDrawn] 里用。调用方应先过 [hasOwn](可读性探测),
     * 免得对读不出来的文件调 `BitmapFactory` —— 那会在 logcat 里刷
     * `Unable to decode stream`(没意义又吵)。
     */
    private fun decodeFile(f: File): ImageBitmap? = runCatching {
        // 先只读尺寸
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(f.absolutePath, bounds)
        var sample = 1
        val maxSide = maxOf(bounds.outWidth, bounds.outHeight)
        while (maxSide / sample > MAX_SIDE) sample *= 2

        val opts = BitmapFactory.Options().apply {
            inSampleSize = sample
            inPreferredConfig = android.graphics.Bitmap.Config.RGB_565
        }
        BitmapFactory.decodeFile(f.absolutePath, opts)?.asImageBitmap()
    }.getOrNull()

    /** 解码某个朝向实际要画的壁纸(横向回退由 [effective] 负责);给设置页预览用 */
    fun loadImage(context: Context, slot: Slot = Slot.PORTRAIT): ImageBitmap? {
        val real = effective(slot)
        if (kindOf(real) != "image") return null
        val f = fileOf(real) ?: return null
        if (!isUsable(f)) return null
        return decodeFile(f)
    }

    /**
     * 渲染链的最终产物：**只可能是用户自己那份**（图或视频）。
     *
     * 没有内置默认图兜底；算不出可画的东西时 [resolveDrawn] 返回 `null`，
     * 宿主直接留纯主题背景（不报错、不弹提示）。
     */
    sealed interface Drawn {
        /** 用户自己的图(已解码好) */
        data class Img(val bitmap: ImageBitmap) : Drawn

        /** 用户自己的视频(是否真能播由 MediaPlayer 说了算,出错回调见 WallpaperHost) */
        data class Vid(val path: String) : Drawn
    }

    /**
     * 算出**这次到底画什么**(阻塞、要读盘/解码 —— 必须在 IO 线程调)。
     *
     * 链:`自己这个朝向 → 另一朝向`，只在"设置里说这份有壁纸"
     * ([hasOwn],含可读性探测)的槽位里挑,图片还必须真解码成功才算数。
     * 都挑不出来 → `null`（纯主题背景），**不再退到任何内置默认图**。
     *
     * @param skipVideo 视频播放失败后置 true 再算一次:跳过视频候选,试另一槽的图
     */
    fun resolveDrawn(slot: Slot, skipVideo: Boolean = false): Drawn? {
        val primary = effective(slot)
        val secondary = if (primary == Slot.PORTRAIT) Slot.LANDSCAPE else Slot.PORTRAIT

        for (s in listOf(primary, secondary)) {
            if (!hasOwn(s)) continue
            val f = fileOf(s) ?: continue
            when (kindOf(s)) {
                "video" -> if (!skipVideo) return Drawn.Vid(f.absolutePath)
                "image" -> decodeFile(f)?.let { return Drawn.Img(it) }
            }
        }
        return null
    }
}

/**
 * 现在该用哪个壁纸槽位:宽 > 高 = 横屏([WallpaperStore.Slot.LANDSCAPE]),否则竖屏。
 *
 * 用 Compose 的 configuration 读,转屏时它会变 → 调用方会重组,所以是**实时切换**的。
 *
 * ⚠️ v2.1(审计 P3-10)修正旧注释:这里原来写着
 *   「MainActivity 没声明 configChanges,转屏本来就会重建 Activity;两条路都成立」。
 *   前半句其实**是对的**(核对 `AndroidManifest.xml`:`MainActivity` 的 `<activity>` 里
 *   确实没有 `android:configChanges`;**全清单唯一一处** configChanges 在第 115 行,
 *   属于 `WebUIActivity`,不是 MainActivity)。
 *   但"靠 Activity 重建"这条路**不能当成设计依据**:一旦哪天给 MainActivity 补上
 *   configChanges(或者它被放进声明了 configChanges 的宿主里),这条路就断了。
 *   所以按**只有 Compose 重组这条路**来保证实时切换:
 *   `LocalConfiguration` 变化 → 这里返回新槽位 → 调用方重组。
 */
@Composable
fun rememberWallpaperSlot(): WallpaperStore.Slot {
    val config = LocalConfiguration.current
    return if (config.screenWidthDp > config.screenHeightDp) {
        WallpaperStore.Slot.LANDSCAPE
    } else {
        WallpaperStore.Slot.PORTRAIT
    }
}

/**
 * "现在**会不会**有壁纸画在界面底下" —— 给"大面积背景容器"用的判据(v2.8)。
 *
 * 为什么要有它:壁纸层([WallpaperHost])在最底下,任何画在它上面、**不透明**的
 * 整屏背景都会把壁纸盖掉(用户 2026-09-21 报的"超级用户页搜索时壁纸变纯色"
 * 就是搜索浮层的整屏遮罩干的)。所以凡是"铺满一屏的背景",都要先问这句:
 * 有壁纸 → **别画不透明底**(页面背景本来就是透明的,卡片自己带半透明底);
 * 没壁纸 → 照旧(观感一个像素都不变)。
 *
 * 判据与 [WallpaperHost] 里"要不要画壁纸"那一句**完全同源**
 * ([WallpaperStore.hasWallpaper]:设置里说这个朝向有壁纸就按有壁纸处理),
 * 所以两边不会打架。没有壁纸时全部走纯主题背景,不存在默认图。
 *
 * 用 [WallpaperPrefs.observe] 挂钩 → 换/删壁纸后立刻生效,不用重启。
 */
@Composable
fun rememberWallpaperVisible(): Boolean {
    val rev = WallpaperPrefs.observe()
    val slot = rememberWallpaperSlot()
    return androidx.compose.runtime.remember(rev, slot) {
        WallpaperStore.hasWallpaper(slot)
    }
}

/**
 * 从壁纸里挑一个"主色"当主题种子色。
 *
 * 做法很朴素但够用:把图缩到很小 → 按 8 档量化颜色 → 按 HSV 的
 * 鲜艳度 + 中亮度加权计票 → 票数最高的那一桶取平均色。
 * 跳过近乎透明/纯黑/纯白的像素,避免取到"灰"或者"黑"。
 */
fun extractSeedColor(context: Context): Int {
    val f = WallpaperStore.file(context) ?: return 0
    return extractSeedColor(f)
}

/** Theme transactions extract from staged resources before publishing their preference pointer. */
internal fun extractSeedColor(f: File): Int {
    return runCatching {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(f.absolutePath, bounds)
        val maxSide = maxOf(bounds.outWidth, bounds.outHeight)
        if (maxSide <= 0) return@runCatching 0

        var sample = 1
        while (maxSide / sample > 64) sample *= 2
        val opts = BitmapFactory.Options().apply {
            inSampleSize = sample
            inPreferredConfig = android.graphics.Bitmap.Config.ARGB_8888
        }
        val bmp = BitmapFactory.decodeFile(f.absolutePath, opts) ?: return@runCatching 0

        data class Bucket(var weight: Float, var r: Float, var g: Float, var b: Float, var n: Int)

        val buckets = HashMap<Int, Bucket>()
        val hsv = FloatArray(3)

        for (y in 0 until bmp.height) {
            for (x in 0 until bmp.width) {
                val c = bmp.getPixel(x, y)
                if ((c ushr 24) and 0xff < 200) continue          // 太透明
                val r = (c shr 16) and 0xff
                val g = (c shr 8) and 0xff
                val b = c and 0xff

                android.graphics.Color.RGBToHSV(r, g, b, hsv)
                val h = hsv[0]
                val sat = hsv[1]
                val `val` = hsv[2]

                if (`val` < 0.12f) continue                        // 太黑
                if (sat < 0.10f) continue                          // 太灰
                if (`val` > 0.96f && sat < 0.15f) continue          // 太白

                // 加权:鲜艳的、亮度适中的更"像主色"
                val weight = (sat * 2.2f + (1f - kotlin.math.abs(`val` - 0.62f))) *
                    (0.4f + sat)
                if (weight <= 0f) continue

                val key = ((h / 20f).toInt() shl 16) or ((r shr 5) shl 10) or
                    ((g shr 5) shl 5) or (b shr 5)

                val bucket = buckets.getOrPut(key) { Bucket(0f, 0f, 0f, 0f, 0) }
                bucket.weight += weight
                bucket.r += r.toFloat()
                bucket.g += g.toFloat()
                bucket.b += b.toFloat()
                bucket.n++
            }
        }
        bmp.recycle()

        val best = buckets.values.maxByOrNull { it.weight } ?: return@runCatching 0
        if (best.n == 0) return@runCatching 0
        android.graphics.Color.rgb(
            (best.r / best.n).toInt().coerceIn(0, 255),
            (best.g / best.n).toInt().coerceIn(0, 255),
            (best.b / best.n).toInt().coerceIn(0, 255),
        )
    }.getOrDefault(0)
}
