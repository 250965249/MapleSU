package com.maplesu.core.ui.screen.home

import android.content.Context
import android.graphics.BitmapFactory
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FloatExponentialDecaySpec
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateDecay
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.calculateCentroid
import androidx.compose.foundation.gestures.calculatePan
import androidx.compose.foundation.gestures.calculateZoom
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.geometry.center
import androidx.compose.ui.geometry.isSpecified
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollDispatcher
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.input.pointer.PointerInputScope
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.positionChanged
import androidx.compose.ui.input.pointer.util.VelocityTracker
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.Velocity
import androidx.compose.ui.unit.constrainHeight
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.abs
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

/*
 * 「关于 MapleSU」里的用户顾问计划卡片，Miuix 与 Material 共用这一份。
 *
 * 收起时是一行叠放的头像和成员数。点开后，叠放的头像从原位飞进六边形头像墙，其余成员从「+N」里
 * 按圈依次涌出，卡片同时长高；墙可以拖动、双指缩放，中间的头像最大、越往外越小（与 README 里的头像墙
 * 同一套排座和鱼眼，见 AdvisorRoster.kt）。点按头像，它飞到墙顶放大，其余头像散开淡出，下面浮出介绍；
 * 返回时原路回去。
 *
 * 所有位置都是三个进度的纯函数：展开 e、详情 d，以及拖动/缩放；动画中途反向也不会跳。皮肤只决定
 * 字体、颜色和形状（[AdvisorWallStyle]），以及系统返回键怎么接（各皮肤的弹窗不同）。
 */

/** 皮肤给卡片的外观。文字样式已带颜色；徽章、标签和按钮的颜色由卡片按枫叶色板决定。 */
@Immutable
internal data class AdvisorWallStyle(
    val dark: Boolean,
    val shape: Shape,
    val title: TextStyle,
    val body: TextStyle,
    val name: TextStyle,
    val role: TextStyle,
    val note: TextStyle,
    val label: TextStyle,
    val button: TextStyle,
    val content: Color,
    val secondary: Color,
    val chip: Color,
    val hairline: Color,
    val buttonShape: Shape,
    val buttonHeight: Dp,
)

/**
 * @param backHandler 详情打开时接住系统返回键：Miuix 的弹窗与页面同窗，Material 的弹窗是独立窗口，
 *   接法不同，由皮肤提供。
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
internal fun AdvisorWallCard(
    style: AdvisorWallStyle,
    backHandler: @Composable (enabled: Boolean, onBack: () -> Unit) -> Unit,
    modifier: Modifier = Modifier,
    initiallyExpanded: Boolean = false,
) {
    val context = LocalContext.current
    val members = remember { AdvisorAssets.roster(context) }
    if (members.isEmpty()) return
    val scope = rememberCoroutineScope()
    val state = remember(members) { AdvisorWallState(members, scope) }
    LaunchedEffect(state, initiallyExpanded) {
        if (initiallyExpanded) state.open()
    }
    val pictures by produceState(emptyMap<String, ImageBitmap>(), members) {
        value = withContext(Dispatchers.IO) { AdvisorAssets.avatars(context, members) }
    }
    val palette = remember(style.dark) { AdvisorPalette(style.dark) }
    val english = stringResource(R.string.advisors_language) == "en"
    val uriHandler = LocalUriHandler.current
    val dispatcher = remember { NestedScrollDispatcher() }
    val connection = remember { object : NestedScrollConnection {} }

    backHandler(state.detailOpen) { state.back() }

    val title = stringResource(R.string.advisors_title)
    val stateLabel = stringResource(if (state.expanded) R.string.advisors_expanded else R.string.advisors_collapsed)
    val viewLabel = stringResource(R.string.advisors_view)
    val backLabel = stringResource(R.string.advisors_back)
    val groupLabels = AdvisorGroup.entries.associateWith { stringResource(it.label) }
    val selected = state.selected

    Layout(
        modifier = modifier
            .bringIntoViewRequester(state.requester)
            .onGloballyPositioned { state.revealGrowth(it.size) }
            .clip(style.shape)
            .background(palette.card)
            .drawBehind { drawGlow(state, palette) }
            .nestedScroll(connection, dispatcher)
            .pointerInput(state) { wallGestures(state, dispatcher) },
        content = {
            BasicText(
                text = title,
                style = style.title,
                modifier = Modifier.semantics(mergeDescendants = true) {
                    role = Role.Button
                    stateDescription = stateLabel
                    onClick { state.toggle(); true }
                },
            )
            AdvisorGlyph(Glyph.CHEVRON, style.secondary)
            BasicText(
                text = stringResource(R.string.advisors_summary, members.size),
                style = style.body,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = if (state.expanded) Modifier.clearAndSetSemantics { } else Modifier,
            )
            BasicText(
                text = stringResource(R.string.advisors_hint),
                style = style.body,
                modifier = if (state.expanded && selected < 0) Modifier else Modifier.clearAndSetSemantics { },
            )
            Box(
                modifier = Modifier.background(palette.mapleTint, CircleShape).clearAndSetSemantics { },
                contentAlignment = Alignment.Center,
            ) {
                if (state.hidden > 0) BasicText("+${state.hidden}", style = style.label.copy(color = palette.mapleInk))
            }
            Box {
                if (selected >= 0) AdvisorBackButton(backLabel, style, onClick = state::back)
            }
            Box(contentAlignment = Alignment.TopCenter) {
                if (selected >= 0) {
                    AdvisorDetail(
                        advisor = state.seats[selected].advisor,
                        style = style,
                        palette = palette,
                        english = english,
                        groupLabels = groupLabels,
                        onOpen = { url -> runCatching { uriHandler.openUri(url) } },
                    )
                }
            }
            state.seats.forEachIndexed { index, seat ->
                key(seat.advisor.id) {
                    val advisor = seat.advisor
                    val semantics = when {
                        !state.expanded -> Modifier.clearAndSetSemantics { }
                        selected == index -> Modifier.semantics {
                            contentDescription = advisor.name
                            onClick(label = backLabel) { state.back(); true }
                        }
                        selected >= 0 -> Modifier.clearAndSetSemantics { }
                        else -> Modifier.semantics {
                            contentDescription = (listOf(advisor.name) + advisor.badges.map { groupLabels.getValue(it) })
                                .joinToString("，")
                            role = Role.Button
                            onClick(label = viewLabel) { state.select(index); true }
                        }
                    }
                    AdvisorAvatar(advisor, pictures[advisor.id], style, semantics)
                }
            }
        },
    ) { measurables, constraints ->
        val width = if (constraints.hasBoundedWidth) constraints.maxWidth else 320.dp.roundToPx()
        val pad = PAD.toPx()
        val face = FACE.toPx()
        val faceStep = FACE_STEP.toPx()
        val inner = (width - 2 * pad).roundToInt().coerceAtLeast(0)
        val chevronSize = CHEVRON.roundToPx()
        val avatarSize = DETAIL_AVATAR.roundToPx()

        val titleText = measurables[0].measure(Constraints(maxWidth = (inner - chevronSize - 8.dp.roundToPx()).coerceAtLeast(0)))
        val chevron = measurables[1].measure(Constraints.fixed(chevronSize, chevronSize))
        val pile = state.facepile
        val pileWidth = face + faceStep * (pile - 1) + if (state.hidden > 0) faceStep else 0f
        val summaryX = pad + pileWidth + 10.dp.toPx()
        val summary = measurables[2].measure(Constraints(maxWidth = (width - summaryX - pad).roundToInt().coerceAtLeast(0)))
        val hint = measurables[3].measure(Constraints(maxWidth = inner))
        val bubble = measurables[4].measure(Constraints.fixed(face.roundToInt(), face.roundToInt()))
        val back = measurables[5].measure(Constraints(maxWidth = inner))
        val detailPanel = measurables[6].measure(Constraints(minWidth = inner, maxWidth = inner))
        val avatars = List(measurables.size - 7) { measurables[7 + it].measure(Constraints.fixed(avatarSize, avatarSize)) }

        val rowTop = pad + titleText.height + ROW_GAP.toPx()
        val rowHeight = max(face, max(hint.height, back.height).toFloat())
        val wallTop = rowTop + rowHeight + WALL_GAP.toPx()
        val wallHeight = (width * 0.92f).coerceIn(WALL_MIN.toPx(), WALL_MAX.toPx())
        val lens = min(width.toFloat(), wallHeight) / 2f - 4.dp.toPx()
        val pitch = lens / AdvisorLens.LENS_PITCHES
        val g = WallGeometry(
            width = width.toFloat(),
            pad = pad,
            face = face,
            faceStep = faceStep,
            rowTop = rowTop,
            wallTop = wallTop,
            wallHeight = wallHeight,
            centerX = width / 2f,
            centerY = wallTop + wallHeight / 2f,
            lens = lens,
            pitch = pitch,
            base = pitch * AdvisorLens.FILL,
            detailSize = avatarSize.toFloat(),
            detailCenterY = wallTop + DETAIL_TOP.toPx() + avatarSize / 2f,
        )
        state.geometry = g

        val e = state.expand.value
        val d = state.detail.value
        val dc = Ease.clamp(d)
        val detailTop = g.detailCenterY + avatarSize / 2f + DETAIL_GAP.toPx()
        val detailArea = detailTop - wallTop + detailPanel.height + pad
        val area = Ease.lerp(wallHeight, max(wallHeight, detailArea), dc)
        val collapsedHeight = rowTop + face + pad
        // 卡片先于头像长高（展开过半就到位），飞进墙里的头像不会被卡片底边切掉。
        val height = Ease.lerp(collapsedHeight, wallTop + area, Ease.outCubic(e / 0.55f))
        val rowCenter = rowTop + face / 2f
        val expandedRowCenter = rowTop + rowHeight / 2f
        val hintIn = Ease.clamp((e - 0.45f) / 0.4f)
        val backIn = Ease.clamp((d - 0.3f) / 0.5f)

        layout(width, constraints.constrainHeight(height.roundToInt())) {
            titleText.place(pad.roundToInt(), pad.roundToInt())
            chevron.placeWithLayer(width - pad.roundToInt() - chevronSize, pad.roundToInt() + (titleText.height - chevronSize) / 2) {
                rotationZ = 180f * Ease.inOutCubic(e)
            }
            summary.placeWithLayer(summaryX.roundToInt(), (rowCenter - summary.height / 2f).roundToInt()) {
                alpha = 1f - Ease.clamp(e / 0.25f)
            }
            hint.placeWithLayer(pad.roundToInt(), (expandedRowCenter - hint.height / 2f).roundToInt()) {
                alpha = hintIn * (1f - Ease.clamp(d * 3f))
                translationY = (1f - hintIn) * 6.dp.toPx()
            }
            bubble.placeWithLayer((g.pad + faceStep * pile).roundToInt(), rowTop.roundToInt(), zIndex = 60f) {
                val gone = Ease.clamp(e * 3f)
                alpha = 1f - gone
                scaleX = 1f - 0.35f * gone
                scaleY = 1f - 0.35f * gone
            }
            back.placeWithLayer(pad.roundToInt(), (expandedRowCenter - back.height / 2f).roundToInt()) {
                alpha = backIn * Ease.clamp(e)
                translationX = -(1f - backIn) * 12.dp.toPx()
            }
            detailPanel.placeWithLayer(pad.roundToInt(), detailTop.roundToInt()) {
                alpha = Ease.clamp((d - 0.5f) / 0.5f) * Ease.clamp(e)
                translationY = (1f - dc) * 20.dp.toPx()
            }
            val frame = state.frame(g, e, d)
            avatars.forEachIndexed { index, avatar ->
                val x = frame[index * 4]
                val y = frame[index * 4 + 1]
                val size = frame[index * 4 + 2]
                val fade = frame[index * 4 + 3]
                val z = if (index == selected && d > 0f) 100f else state.zIndex(index)
                avatar.placeWithLayer(0, 0, zIndex = z) {
                    translationX = x - avatarSize / 2f
                    translationY = y - avatarSize / 2f
                    scaleX = size / avatarSize
                    scaleY = size / avatarSize
                    alpha = fade
                    compositingStrategy = CompositingStrategy.ModulateAlpha
                }
            }
        }
    }
}

// ── 状态 ───────────────────────────────────────────────────────────────────────────────

private const val MAX_DELAY = 0.35f
private const val MIN_ZOOM = 0.7f
private const val MAX_ZOOM = 1.6f
private const val EXPAND_MS = 700
private const val COLLAPSE_MS = 520
private val PAD = 14.dp
private val FACE = 30.dp
private val FACE_STEP = 22.dp
private val ROW_GAP = 8.dp
private val WALL_GAP = 4.dp
private val WALL_MIN = 250.dp
private val WALL_MAX = 340.dp
private val CHEVRON = 20.dp
private val DETAIL_AVATAR = 88.dp
private val DETAIL_TOP = 12.dp
private val DETAIL_GAP = 12.dp

/** 上一次布局量出的尺寸，单位是像素；手势和绘制都按它换算。 */
private class WallGeometry(
    val width: Float,
    val pad: Float,
    val face: Float,
    val faceStep: Float,
    val rowTop: Float,
    val wallTop: Float,
    val wallHeight: Float,
    val centerX: Float,
    val centerY: Float,
    val lens: Float,
    val pitch: Float,
    val base: Float,
    val detailSize: Float,
    val detailCenterY: Float,
)

@OptIn(ExperimentalFoundationApi::class)
@Stable
private class AdvisorWallState(members: List<Advisor>, private val scope: CoroutineScope) {
    val seats = AdvisorRoster.seats(members)

    /** 收起时叠放显示的人数：作者和前三位特别致谢成员（按名单顺序）。 */
    val facepile = minOf(4, seats.size)
    val hidden = seats.size - facepile
    private val rank = IntArray(seats.size).also { rank ->
        val order = AdvisorRoster.ordered(members)
        seats.forEachIndexed { index, seat -> rank[index] = order.indexOf(seat.advisor) }
    }
    private val author = seats.indexOfFirst { it.advisor.group == AdvisorGroup.AUTHOR }
    private val outerShell = seats.maxOf { it.shell }.coerceAtLeast(1)
    private val reach = seats.maxOf { it.distance }.toFloat()

    val expand = Animatable(0f)
    val detail = Animatable(0f)
    val requester = BringIntoViewRequester()
    var expanded by mutableStateOf(false)
        private set
    var selected by mutableIntStateOf(-1)
        private set
    var detailOpen by mutableStateOf(false)
        private set

    /** 镜头对准的格点位置（1 倍缩放下的像素，格点原点即作者）。 */
    private var camera by mutableStateOf(Offset.Zero)
    private var zoom by mutableFloatStateOf(1f)

    /** 布局时写入、手势时读取，不参与重组。 */
    var geometry: WallGeometry? = null
    private val last = FloatArray(seats.size * 4)
    private var flingJob: Job? = null
    private var revealJob: Job? = null
    private var measuredSize = IntSize.Zero

    /** 只有完全展开、没在看详情时，墙面才接拖动；其余时候手势留给外层滚动。 */
    val pannable: Boolean get() = expanded && expand.value > 0.98f && !detailOpen && detail.value < 0.05f

    fun toggle() = if (expanded) collapse() else open()

    /** 随已布局的卡片一起下滑；请求期间会持续读取最新尺寸，避免等展开结束再滚动。 */
    fun revealGrowth(size: IntSize) {
        val growing = size.height > measuredSize.height
        measuredSize = size
        if (expanded && growing) reveal()
    }

    private fun reveal() {
        if (revealJob?.isActive == true) return
        revealJob = scope.launch { requester.bringIntoView() }
    }

    fun open() {
        expanded = true
        scope.launch {
            expand.animateTo(1f, tween(duration(EXPAND_MS, 1f - expand.value), easing = LinearEasing))
        }
    }

    fun collapse() {
        expanded = false
        detailOpen = false
        revealJob?.cancel()
        stopFling()
        scope.launch {
            detail.animateTo(0f, DETAIL_SPRING)
            if (!detailOpen) selected = -1
        }
        scope.launch {
            expand.animateTo(0f, tween(duration(COLLAPSE_MS, expand.value), easing = LinearEasing))
            detail.snapTo(0f)
            selected = -1
            camera = Offset.Zero
            zoom = 1f
        }
    }

    fun select(index: Int) {
        if (!expanded || index !in seats.indices) return
        if (selected >= 0 && selected != index && detail.value > 0.05f) return
        stopFling()
        selected = index
        detailOpen = true
        reveal()
        scope.launch {
            detail.animateTo(1f, DETAIL_SPRING)
        }
    }

    fun back() {
        if (!detailOpen) return
        detailOpen = false
        revealJob?.cancel()
        scope.launch {
            detail.animateTo(0f, DETAIL_SPRING)
            if (!detailOpen) selected = -1
        }
    }

    fun tap(position: Offset) {
        val g = geometry ?: return
        if (!expanded || position.y < g.wallTop) {
            toggle()
            return
        }
        val hit = hit(position)
        when {
            detailOpen -> if (hit == selected) back()
            hit >= 0 -> select(hit)
        }
    }

    /** 拖动墙面：返回实际用掉的位移（屏幕像素），到边以后剩下的交给外层滚动。 */
    fun panBy(delta: Offset): Offset {
        val g = geometry ?: return Offset.Zero
        val target = (camera - delta / zoom).within(reach * g.pitch)
        val used = (camera - target) * zoom
        camera = target
        return used
    }

    /** 双指缩放，手指下的那一点尽量不动（透镜中心附近不变形，这样估算足够）。 */
    fun zoomBy(factor: Float, focus: Offset) {
        val g = geometry ?: return
        val next = (zoom * factor).coerceIn(MIN_ZOOM, MAX_ZOOM)
        if (next == zoom) return
        val from = Offset(focus.x - g.centerX, focus.y - g.centerY)
        camera = (camera + from / zoom - from / next).within(reach * g.pitch)
        zoom = next
    }

    /** 松手后的惯性，返回墙面用不掉、要交给外层的速度。 */
    suspend fun fling(velocity: Velocity): Velocity {
        val speed = hypot(velocity.x, velocity.y)
        if (speed < 50f || !pannable) return velocity
        val dx = velocity.x / speed
        val dy = velocity.y / speed
        val g = geometry ?: return velocity
        if ((camera - Offset(dx, dy) / zoom).within(reach * g.pitch) == camera) return velocity
        var travelled = 0f
        animateDecay(0f, speed, FloatExponentialDecaySpec(frictionMultiplier = 1.6f)) { value, _ ->
            val step = value - travelled
            travelled = value
            panBy(Offset(dx * step, dy * step))
        }
        return Velocity.Zero
    }

    fun launchFling(velocity: Velocity, dispatcher: NestedScrollDispatcher) {
        flingJob = scope.launch {
            val left = velocity - dispatcher.dispatchPreFling(velocity)
            val rest = fling(left)
            dispatcher.dispatchPostFling(left - rest, rest)
        }
    }

    fun stopFling(): Boolean {
        val running = flingJob?.isActive == true
        flingJob?.cancel()
        flingJob = null
        return running
    }

    fun zIndex(index: Int): Float = (facepile - rank[index]).coerceAtLeast(0) * 10f + (10 - seats[index].shell)

    /** 点到的头像：只认看得见的，按圆形判断。 */
    private fun hit(position: Offset): Int {
        var best = -1
        var bestDistance = Float.MAX_VALUE
        for (index in seats.indices) {
            val radius = last[index * 4 + 2] / 2f
            if (last[index * 4 + 3] < 0.4f || radius < 6f) continue
            val distance = hypot(position.x - last[index * 4], position.y - last[index * 4 + 1])
            if (distance <= radius * 1.08f && distance < bestDistance) {
                best = index
                bestDistance = distance
            }
        }
        return best
    }

    /**
     * 这一帧每个头像的中心 x、y、直径和不透明度，按 4 个一组排列。
     *
     * 收起位置 → 墙上位置 → 详情位置三层插值；每个头像按所在的圈错开起步，内圈先到。
     */
    fun frame(g: WallGeometry, e: Float, d: Float): FloatArray {
        val count = seats.size
        val wx = FloatArray(count)
        val wy = FloatArray(count)
        val ws = FloatArray(count)
        for (index in 0 until count) {
            val seat = seats[index]
            val vx = (seat.x.toFloat() * g.pitch - camera.x) * zoom
            val vy = (seat.y.toFloat() * g.pitch - camera.y) * zoom
            val distance = hypot(vx, vy)
            val u = distance / g.lens
            val drawn = AdvisorLens.radius(u) * g.lens
            wx[index] = if (distance > 0f) vx / distance * drawn else 0f
            wy[index] = if (distance > 0f) vy / distance * drawn else 0f
            ws[index] = g.base * zoom * AdvisorLens.scale(u) * if (index == author) AdvisorLens.AUTHOR_SCALE else 1f
        }
        if (author >= 0) {
            // 作者画得更大，其余头像从作者身边让开同样的距离（作者被拖到边上变小时，让得也少）。
            val push = ws[author] * (1f - 1f / AdvisorLens.AUTHOR_SCALE) / 2f
            for (index in 0 until count) {
                if (index == author) continue
                val dx = wx[index] - wx[author]
                val dy = wy[index] - wy[author]
                val gap = hypot(dx, dy)
                if (gap > 0f) {
                    wx[index] += dx / gap * push
                    wy[index] += dy / gap * push
                }
            }
        }
        val band = g.base * 0.5f
        val pick = selected
        val dc = Ease.clamp(d)
        val sx = if (pick >= 0) wx[pick] + g.centerX else 0f
        val sy = if (pick >= 0) wy[pick] + g.centerY else 0f
        val bubbleX = g.pad + g.face / 2f + g.faceStep * facepile
        val rowCenter = g.rowTop + g.face / 2f
        for (index in 0 until count) {
            val x = wx[index] + g.centerX
            val y = wy[index] + g.centerY
            val edge = Ease.ramp(x / band) * Ease.ramp((g.width - x) / band) *
                Ease.ramp((y - g.wallTop) / band) * Ease.ramp((g.wallTop + g.wallHeight - y) / band)

            // 打开（墙 ↔ 详情）
            var ox = x
            var oy = y
            var os = ws[index]
            var oa = edge
            if (pick >= 0) {
                if (index == pick) {
                    // 选中的头像先到位，介绍随后浮出，不会压在名字上；弹簧冲过 1 时照常回弹。
                    val lift = if (d < 1f) 1f - (1f - d) * (1f - d) else d
                    ox = Ease.lerp(x, g.width / 2f, lift)
                    oy = Ease.lerp(y, g.detailCenterY, lift)
                    os = Ease.lerp(ws[index], g.detailSize, lift)
                    oa = Ease.lerp(edge, 1f, dc)
                } else {
                    val dx = x - sx
                    val dy = y - sy
                    val gap = hypot(dx, dy).coerceAtLeast(1f)
                    val scatter = (g.base * 0.6f + gap * 0.25f) * dc
                    ox = x + dx / gap * scatter
                    oy = y + dy / gap * scatter
                    os = ws[index] * (1f - 0.3f * dc)
                    oa = edge * (1f - Ease.clamp(d * 1.6f))
                }
            }

            // 收起（叠放的头像组 ↔ 打开）
            val inPile = rank[index] < facepile
            val cx = if (inPile) g.pad + g.face / 2f + g.faceStep * rank[index] else bubbleX
            val cs = if (inPile) g.face else g.face * 0.45f
            val delay = MAX_DELAY * seats[index].shell / outerShell
            val t = Ease.clamp((e - delay) / (1f - MAX_DELAY))
            val p = Ease.outBack(t)
            val out = index * 4
            last[out] = Ease.lerp(cx, ox, p)
            last[out + 1] = Ease.lerp(rowCenter, oy, p)
            last[out + 2] = Ease.lerp(cs, os, p).coerceAtLeast(0f)
            last[out + 3] = if (inPile) Ease.lerp(1f, oa, t) else oa * Ease.clamp(t * 3f)
        }
        return last
    }

    private fun duration(full: Int, remaining: Float): Int = (full * abs(remaining)).roundToInt().coerceAtLeast(120)

    private fun Offset.within(limit: Float): Offset {
        val distance = getDistance()
        return if (distance <= limit || distance == 0f) this else this * (limit / distance)
    }
}

private val DETAIL_SPRING = spring<Float>(dampingRatio = 0.84f, stiffness = 320f)

/** 墙面手势：单指拖动带惯性、双指缩放、点按。墙拖到头时，剩下的位移交给外层滚动。 */
private suspend fun PointerInputScope.wallGestures(state: AdvisorWallState, dispatcher: NestedScrollDispatcher) {
    awaitEachGesture {
        val down = awaitFirstDown()
        val interrupted = state.stopFling()
        val g = state.geometry
        val pannable = state.pannable && g != null && down.position.y >= g.wallTop
        val tracker = VelocityTracker()
        tracker.addPosition(down.uptimeMillis, down.position)
        var travel = Offset.Zero
        var span = 1f
        var dragging = false
        var pinched = false
        var tap = !interrupted
        while (true) {
            val event = awaitPointerEvent()
            val pressed = event.changes.count { it.pressed }
            if (pressed == 0) {
                val up = event.changes.firstOrNull { it.id == down.id }
                when {
                    tap && up != null && !up.isConsumed -> state.tap(up.position)
                    dragging && !pinched -> {
                        val max = viewConfiguration.maximumFlingVelocity
                        val velocity = tracker.calculateVelocity()
                        state.launchFling(
                            Velocity(velocity.x.coerceIn(-max, max), velocity.y.coerceIn(-max, max)),
                            dispatcher,
                        )
                    }
                }
                break
            }
            if (event.changes.any { it.isConsumed }) break
            if (pressed > 1) {
                pinched = true
                tap = false
            }
            val pan = event.calculatePan()
            val zoom = event.calculateZoom()
            if (!dragging) {
                travel += pan
                span *= zoom
                if (travel.getDistance() > viewConfiguration.touchSlop || abs(1f - span) > 0.04f) {
                    tap = false
                    dragging = pannable
                }
            }
            if (!dragging) continue
            if (pressed > 1) {
                val centroid = event.calculateCentroid()
                if (centroid.isSpecified) state.zoomBy(zoom, centroid)
            }
            val left = pan - dispatcher.dispatchPreScroll(pan, NestedScrollSource.UserInput)
            val used = state.panBy(left)
            dispatcher.dispatchPostScroll(used, left - used, NestedScrollSource.UserInput)
            event.changes.forEach { if (it.positionChanged()) it.consume() }
            event.changes.firstOrNull { it.id == down.id }?.let { tracker.addPosition(it.uptimeMillis, it.position) }
        }
    }
}

private fun DrawScope.drawGlow(state: AdvisorWallState, palette: AdvisorPalette) {
    val g = state.geometry ?: return
    val strength = Ease.outCubic(state.expand.value) * (1f - 0.75f * Ease.clamp(state.detail.value))
    if (strength <= 0f) return
    val center = Offset(g.centerX, g.centerY)
    val radius = g.lens * 1.15f
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(palette.glow.copy(alpha = palette.glow.alpha * strength), Color.Transparent),
            center = center,
            radius = radius,
        ),
        radius = radius,
        center = center,
    )
}

// ── 外观 ───────────────────────────────────────────────────────────────────────────────

/** 枫叶色板，与品牌 Banner、README 头像墙同源。 */
@Immutable
private class AdvisorPalette(dark: Boolean) {
    val card = if (dark) Color(0x1FF58B55) else Color(0x14F58B55)
    val glow = if (dark) Color(0x33F58B55) else Color(0x2EF58B55)
    val mapleTint = if (dark) Color(0x33F58B55) else Color(0xFFFFE9DC)
    val mapleInk = if (dark) Color(0xFFFFB05C) else Color(0xFFB23F27)
    val github = if (dark) Color(0xFFF0F3F6) else Color(0xFF1F2328)
    val onGithub = if (dark) Color(0xFF1F2328) else Color.White
    val telegram = Color(0xFF2AABEE)
    val onTelegram = Color.White
}

private val AUTHOR_RING = arrayOf(0f to Color(0xFFEAC26C), 0.45f to Color(0xFFF58B55), 1f to Color(0xFFD95343))
private val MAPLE_RING = listOf(Color(0xFFFFB05C), Color(0xFFD95343))

private val AdvisorGroup.label: Int
    get() = when (this) {
        AdvisorGroup.AUTHOR -> R.string.advisors_author
        AdvisorGroup.THANKS -> R.string.advisors_thanks
        AdvisorGroup.BETA -> R.string.advisors_beta
    }

/** 标签：技术本身的颜色，图形是自绘的简笔，不用各家的商标。 */
private class TagLook(val accent: Color, val inkLight: Color, val inkDark: Color, val glyph: Glyph)

private val TAG_LOOKS = mapOf(
    "UI" to TagLook(Color(0xFFF58B55), Color(0xFFB23F27), Color(0xFFFFB05C), Glyph.LAYOUT),
    "Kotlin" to TagLook(Color(0xFF7F52FF), Color(0xFF5B2FE0), Color(0xFFB9A5FF), Glyph.KOTLIN),
    "C++" to TagLook(Color(0xFF00599C), Color(0xFF00599C), Color(0xFF7CC0F5), Glyph.CODE),
)

/** 头像：图片裁成圆形；作者是金到枫红的环，特别致谢是枫叶环，内测用户是一圈细线。 */
@Composable
private fun AdvisorAvatar(advisor: Advisor, picture: ImageBitmap?, style: AdvisorWallStyle, modifier: Modifier) {
    Spacer(
        modifier.drawWithCache {
            val diameter = size.minDimension
            val (ringShare, gapShare) = when (advisor.group) {
                AdvisorGroup.AUTHOR -> 0.055f to 0.035f
                AdvisorGroup.THANKS -> 0.05f to 0.04f
                AdvisorGroup.BETA -> 0f to 0f
            }
            val ringWidth = diameter * ringShare
            val radius = diameter / 2f - ringWidth - diameter * gapShare
            val ring = when (advisor.group) {
                AdvisorGroup.AUTHOR -> Brush.linearGradient(*AUTHOR_RING, start = Offset.Zero, end = Offset(diameter, diameter))
                AdvisorGroup.THANKS -> Brush.linearGradient(MAPLE_RING, start = Offset.Zero, end = Offset(diameter, diameter))
                AdvisorGroup.BETA -> null
            }
            val middle = size.center
            val round = Path().apply { addOval(Rect(middle, radius)) }
            val hairline = 1.5.dp.toPx()
            val topLeft = IntOffset((middle.x - radius).roundToInt(), (middle.y - radius).roundToInt())
            val side = (radius * 2f).roundToInt()
            onDrawBehind {
                if (ring != null) drawCircle(ring, radius = diameter / 2f - ringWidth / 2f, style = Stroke(ringWidth))
                if (picture != null) {
                    clipPath(round) {
                        drawImage(
                            image = picture,
                            dstOffset = topLeft,
                            dstSize = IntSize(side, side),
                            filterQuality = FilterQuality.Medium,
                        )
                    }
                } else {
                    drawCircle(style.chip, radius = radius)
                }
                if (ring == null) drawCircle(style.hairline, radius = radius - hairline / 2f, style = Stroke(hairline))
            }
        },
    )
}

/** 详情：名字、身份徽章、介绍、标签、签名和主页按钮，居中排在大头像下面。 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AdvisorDetail(
    advisor: Advisor,
    style: AdvisorWallStyle,
    palette: AdvisorPalette,
    english: Boolean,
    groupLabels: Map<AdvisorGroup, String>,
    onOpen: (String) -> Unit,
) {
    Column(
        modifier = Modifier.widthIn(max = 360.dp).padding(start = 4.dp, end = 4.dp, bottom = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        BasicText(text = advisor.name, style = style.name, modifier = Modifier.semantics { heading() })
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(6.dp, Alignment.CenterHorizontally),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            advisor.badges.forEach { AdvisorBadge(it, groupLabels.getValue(it), style, palette) }
        }
        val role = advisor.role(english)
        when {
            role != null -> BasicText(text = role, style = style.role)
            advisor.group == AdvisorGroup.BETA -> BasicText(text = stringResource(R.string.advisors_beta_thanks), style = style.note)
        }
        if (advisor.tags.isNotEmpty()) {
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(6.dp, Alignment.CenterHorizontally),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                advisor.tags.forEach { AdvisorTag(it, style) }
            }
        }
        advisor.signature?.let {
            BasicText(
                text = it,
                style = style.note.copy(color = palette.mapleInk),
                modifier = Modifier
                    .background(palette.mapleTint, RoundedCornerShape(12.dp))
                    .padding(horizontal = 16.dp, vertical = 12.dp),
            )
        }
        val links = advisor.links
        if (links.isNotEmpty()) {
            val openLabel = stringResource(R.string.advisors_open_link)
            FlowRow(
                modifier = Modifier.padding(top = 6.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp, Alignment.CenterHorizontally),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                links.forEach { (kind, url) ->
                    val (background, content) = when (kind) {
                        AdvisorLink.GITHUB -> palette.github to palette.onGithub
                        AdvisorLink.TELEGRAM -> palette.telegram to palette.onTelegram
                    }
                    AdvisorLinkButton(
                        label = if (kind == AdvisorLink.GITHUB) "GitHub" else "Telegram",
                        clickLabel = openLabel,
                        background = background,
                        content = content,
                        style = style,
                        onClick = { onOpen(url) },
                    )
                }
            }
        }
    }
}

@Composable
private fun AdvisorBadge(group: AdvisorGroup, text: String, style: AdvisorWallStyle, palette: AdvisorPalette) {
    val pill = Modifier.clip(RoundedCornerShape(50))
    val (modifier, color) = when (group) {
        AdvisorGroup.AUTHOR -> pill.background(Brush.horizontalGradient(MAPLE_RING)) to Color.White
        AdvisorGroup.THANKS -> pill.background(palette.mapleTint) to palette.mapleInk
        AdvisorGroup.BETA -> pill.background(style.chip) to style.secondary
    }
    BasicText(
        text = text,
        style = style.label.copy(color = color),
        modifier = modifier.padding(horizontal = 10.dp, vertical = 3.dp),
    )
}

@Composable
private fun AdvisorTag(tag: String, style: AdvisorWallStyle) {
    val look = TAG_LOOKS[tag]
    val ink = when {
        look == null -> style.secondary
        style.dark -> look.inkDark
        else -> look.inkLight
    }
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(look?.accent?.copy(alpha = if (style.dark) 0.2f else 0.1f) ?: style.chip)
            .padding(start = if (look != null) 3.dp else 10.dp, end = 10.dp, top = 3.dp, bottom = 3.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(5.dp),
    ) {
        if (look != null) {
            Box(
                modifier = Modifier.size(18.dp).background(look.accent, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                AdvisorGlyph(look.glyph, Color.White, Modifier.size(12.dp))
            }
        }
        BasicText(text = tag, style = style.label.copy(color = ink))
    }
}

@Composable
private fun AdvisorLinkButton(
    label: String,
    clickLabel: String,
    background: Color,
    content: Color,
    style: AdvisorWallStyle,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .heightIn(min = style.buttonHeight)
            .clip(style.buttonShape)
            .background(background)
            .clickable(onClickLabel = clickLabel, role = Role.Button, onClick = onClick)
            .padding(horizontal = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        BasicText(text = label, style = style.button.copy(color = content))
        AdvisorGlyph(Glyph.OPEN, content, Modifier.size(14.dp))
    }
}

@Composable
private fun AdvisorBackButton(label: String, style: AdvisorWallStyle, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(style.chip)
            .clickable(role = Role.Button, onClick = onClick)
            .padding(start = 8.dp, end = 12.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        AdvisorGlyph(Glyph.BACK, style.content, Modifier.size(16.dp))
        BasicText(text = label, style = style.body.copy(color = style.content))
    }
}

// ── 图形 ───────────────────────────────────────────────────────────────────────────────

/** 卡片里的小图形，按 0..1 的方框自绘，两套皮肤一致。 */
private enum class Glyph { CHEVRON, BACK, OPEN, LAYOUT, KOTLIN, CODE }

@Composable
private fun AdvisorGlyph(glyph: Glyph, color: Color, modifier: Modifier = Modifier) {
    Canvas(modifier) { drawGlyph(glyph, color) }
}

private fun DrawScope.drawGlyph(glyph: Glyph, color: Color) {
    val s = size.minDimension
    val stroke = Stroke(width = s * 0.1f, cap = StrokeCap.Round, join = StrokeJoin.Round)
    fun line(vararg points: Float) {
        val path = Path()
        path.moveTo(points[0] * s, points[1] * s)
        for (k in 2 until points.size step 2) path.lineTo(points[k] * s, points[k + 1] * s)
        drawPath(path, color, style = stroke)
    }
    when (glyph) {
        Glyph.CHEVRON -> line(0.26f, 0.4f, 0.5f, 0.64f, 0.74f, 0.4f)
        Glyph.BACK -> {
            line(0.8f, 0.5f, 0.22f, 0.5f)
            line(0.46f, 0.26f, 0.22f, 0.5f, 0.46f, 0.74f)
        }
        Glyph.OPEN -> {
            line(0.3f, 0.7f, 0.7f, 0.3f)
            line(0.38f, 0.3f, 0.7f, 0.3f, 0.7f, 0.62f)
        }
        Glyph.LAYOUT -> {
            drawRoundRect(
                color = color,
                topLeft = Offset(0.17f * s, 0.2f * s),
                size = Size(0.66f * s, 0.6f * s),
                cornerRadius = CornerRadius(0.12f * s),
                style = Stroke(width = s * 0.1f),
            )
            line(0.17f, 0.43f, 0.83f, 0.43f)
            line(0.43f, 0.43f, 0.43f, 0.8f)
        }
        Glyph.KOTLIN -> {
            val path = Path()
            path.moveTo(0.22f * s, 0.22f * s)
            path.lineTo(0.78f * s, 0.22f * s)
            path.lineTo(0.5f * s, 0.5f * s)
            path.lineTo(0.78f * s, 0.78f * s)
            path.lineTo(0.22f * s, 0.78f * s)
            path.close()
            drawPath(path, color)
        }
        Glyph.CODE -> {
            line(0.34f, 0.3f, 0.14f, 0.5f, 0.34f, 0.7f)
            line(0.66f, 0.3f, 0.86f, 0.5f, 0.66f, 0.7f)
            line(0.56f, 0.24f, 0.44f, 0.76f)
        }
    }
}

// ── 数据 ───────────────────────────────────────────────────────────────────────────────

private object AdvisorAssets {
    fun roster(context: Context): List<Advisor> = runCatching {
        context.assets.open(AdvisorRoster.MEMBERS_ASSET).use { AdvisorRoster.parse(it.readBytes().toString(Charsets.UTF_8)) }
    }.getOrDefault(emptyList())

    /** 后台线程解码全部头像；开 mipmap，缩成叠放的小头像时不起锯齿。 */
    fun avatars(context: Context, members: List<Advisor>): Map<String, ImageBitmap> {
        val files = runCatching { context.assets.list(AdvisorRoster.AVATAR_DIR) }.getOrNull().orEmpty().toSet()
        val pictures = HashMap<String, ImageBitmap>()
        for (member in members) {
            val file = listOf("${member.id}.jpg", "${member.id}.png").firstOrNull { it in files } ?: continue
            val bitmap = runCatching {
                context.assets.open("${AdvisorRoster.AVATAR_DIR}/$file").use { BitmapFactory.decodeStream(it) }
            }.getOrNull() ?: continue
            bitmap.setHasMipMap(true)
            bitmap.prepareToDraw()
            pictures[member.id] = bitmap.asImageBitmap()
        }
        return pictures
    }
}

// ── 缓动 ───────────────────────────────────────────────────────────────────────────────

private object Ease {
    fun clamp(value: Float): Float = value.coerceIn(0f, 1f)

    fun lerp(from: Float, to: Float, t: Float): Float = from + (to - from) * t

    fun outCubic(t: Float): Float {
        val c = 1f - clamp(t)
        return 1f - c * c * c
    }

    fun inOutCubic(t: Float): Float {
        val c = clamp(t)
        if (c < 0.5f) return 4f * c * c * c
        val f = -2f * c + 2f
        return 1f - f * f * f / 2f
    }

    /** 收尾略冲过一点（约 5%）再回来，头像落位时有弹性。 */
    fun outBack(t: Float): Float {
        val c = clamp(t) - 1f
        return 1f + 2.2f * c * c * c + 1.2f * c * c
    }

    /** 边缘淡出：0 以下全透明，1 以上不透明，中间平滑过渡。 */
    fun ramp(t: Float): Float {
        val c = clamp(t)
        return c * c * (3f - 2f * c)
    }
}
