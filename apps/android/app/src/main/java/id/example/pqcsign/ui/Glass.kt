package id.example.pqcsign.ui

import android.animation.ValueAnimator
import android.content.Context
import android.content.res.Configuration
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.SweepGradient
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.view.MotionEvent
import android.view.View
import android.view.animation.DecelerateInterpolator
import androidx.dynamicanimation.animation.SpringAnimation
import androidx.dynamicanimation.animation.SpringForce
import com.google.android.material.card.MaterialCardView
import id.example.pqcsign.R
import kotlin.math.abs
import kotlin.math.hypot
import kotlin.math.min
import kotlin.math.sin

/**
 * Liquid Glass visual system for the Android client.
 *
 * Mirrors the desktop (Wails) theme: an animated backdrop of photo + mesh
 * gradient + topographic contours + data-flow particles, with translucent
 * "glass" cards on top.
 *
 * Cursor-driven effects have no cursor on a phone, so they are remapped:
 *   spotlight / 3D tilt -> the touch point
 *   mouse parallax      -> the accelerometer (device tilt)
 *
 * Palette: Assets/PALET-WARNA-PQC-PDF-SIGN-LIQUID-GLASS.txt
 */
object Glass {

    fun isDark(ctx: Context): Boolean =
        (ctx.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
            Configuration.UI_MODE_NIGHT_YES

    // -- surfaces ---------------------------------------------------------
    fun cardFill(ctx: Context): Int    = if (isDark(ctx)) 0x94091930.toInt() else 0x85FFFFFF.toInt()
    fun cardStroke(ctx: Context): Int  = if (isDark(ctx)) 0x3393D6FF.toInt() else 0xC7FFFFFF.toInt()
    fun highlight(ctx: Context): Int   = if (isDark(ctx)) 0x61BEE9FF.toInt() else 0xEBFFFFFF.toInt()
    fun chrome(ctx: Context): Int      = if (isDark(ctx)) 0x99050E1E.toInt() else 0x94FFFFFF.toInt()

    // -- accents ----------------------------------------------------------
    fun accent(ctx: Context): Int      = if (isDark(ctx)) 0xFF0A9FFF.toInt() else 0xFF169BFF.toInt()
    fun cyan(ctx: Context): Int        = if (isDark(ctx)) 0xFF1CDFF5.toInt() else 0xFF35D9F5.toInt()
    fun violet(ctx: Context): Int      = if (isDark(ctx)) 0xFF9566FF.toInt() else 0xFF7B55E7.toInt()
    fun textPrimary(ctx: Context): Int = if (isDark(ctx)) 0xFFF3F9FF.toInt() else 0xFF102A43.toInt()
    fun textMuted(ctx: Context): Int   = if (isDark(ctx)) 0xFF7F9DB8.toInt() else 0xFF829AB1.toInt()

    fun spot(ctx: Context): Int        = if (isDark(ctx)) 0x2B1CDFF5 else 0x3335D9F5

    /** Plus Jakarta Sans, bundled in res/font. Falls back to the system face. */
    fun typeface(ctx: Context, bold: Boolean = false): android.graphics.Typeface? = try {
        val base = androidx.core.content.res.ResourcesCompat.getFont(ctx, R.font.plus_jakarta_sans)
        if (base != null && bold) android.graphics.Typeface.create(base, android.graphics.Typeface.BOLD) else base
    } catch (_: Throwable) {
        if (bold) android.graphics.Typeface.DEFAULT_BOLD else android.graphics.Typeface.DEFAULT
    }

    /** Manual light/dark override, remembered per device. "" = follow system. */
    private const val PREF = "pqc_ui"
    private const val KEY_THEME = "theme"

    fun savedTheme(ctx: Context): String =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).getString(KEY_THEME, "") ?: ""

    fun saveTheme(ctx: Context, mode: String) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit().putString(KEY_THEME, mode).apply()
    }

    /** Apply the stored choice to AppCompat's day/night mode. */
    fun applySavedTheme(ctx: Context) {
        androidx.appcompat.app.AppCompatDelegate.setDefaultNightMode(
            when (savedTheme(ctx)) {
                "dark" -> androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_YES
                "light" -> androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_NO
                else -> androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
            }
        )
    }

    /** Flip to the opposite of what is showing now and persist it. */
    fun toggleTheme(ctx: Context) {
        saveTheme(ctx, if (isDark(ctx)) "light" else "dark")
        applySavedTheme(ctx)
    }

    /** Device-local tally of verifications (the server keeps no per-user count). */
    fun verifyCount(ctx: Context): Int =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).getInt("verify_count", 0)

    fun bumpVerifyCount(ctx: Context) {
        val sp = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
        sp.edit().putInt("verify_count", sp.getInt("verify_count", 0) + 1).apply()
    }

    /** Count-up animation for a dashboard figure. */
    fun countUp(tv: android.widget.TextView, to: Int) {
        if (to <= 0) { tv.text = "0"; return }
        ValueAnimator.ofInt(0, to).apply {
            duration = 900
            interpolator = DecelerateInterpolator(2f)
            addUpdateListener { tv.text = (it.animatedValue as Int).toString() }
            start()
        }
    }

    /** Stagger Reveal - children rise in one after another. */
    fun staggerReveal(group: android.view.ViewGroup, startDelay: Long = 40L) {
        for (i in 0 until group.childCount) {
            val c = group.getChildAt(i)
            c.alpha = 0f
            c.translationY = dp(c.context, 18f)
            c.scaleX = 0.99f; c.scaleY = 0.99f
            c.animate()
                .alpha(1f).translationY(0f).scaleX(1f).scaleY(1f)
                .setStartDelay(startDelay + i * 55L)
                .setDuration(430L)
                .setInterpolator(DecelerateInterpolator(1.6f))
                .start()
        }
    }

    /** Microinteraction: spring press feedback that never eats the click. */
    fun springPress(v: View) {
        val sx = SpringAnimation(v, SpringAnimation.SCALE_X, 1f).apply {
            spring.stiffness = SpringForce.STIFFNESS_LOW
            spring.dampingRatio = SpringForce.DAMPING_RATIO_MEDIUM_BOUNCY
        }
        val sy = SpringAnimation(v, SpringAnimation.SCALE_Y, 1f).apply {
            spring.stiffness = SpringForce.STIFFNESS_LOW
            spring.dampingRatio = SpringForce.DAMPING_RATIO_MEDIUM_BOUNCY
        }
        v.setOnTouchListener { view, e ->
            when (e.actionMasked) {
                MotionEvent.ACTION_DOWN -> { sx.cancel(); sy.cancel(); view.scaleX = 0.965f; view.scaleY = 0.965f }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> { sx.start(); sy.start() }
            }
            false   // never consume - the click listener still fires
        }
    }

    fun dp(ctx: Context, v: Float) = v * ctx.resources.displayMetrics.density
}

/* =====================================================================
   Verification loader - a document with a scan line sweeping down it,
   matching the desktop client's loader.
   ===================================================================== */
class ScanDocView(context: Context) : View(context) {

    private val frame = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = Glass.dp(context, 1.5f)
    }
    private val rule = Paint(Paint.ANTI_ALIAS_FLAG)
    private val scan = Paint(Paint.ANTI_ALIAS_FLAG)
    private var t = 0f
    private var anim: ValueAnimator? = null

    override fun onMeasure(w: Int, h: Int) {
        setMeasuredDimension(Glass.dp(context, 34f).toInt(), Glass.dp(context, 44f).toInt())
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        anim = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 1500
            repeatCount = ValueAnimator.INFINITE
            interpolator = null
            addUpdateListener { t = it.animatedValue as Float; invalidate() }
            start()
        }
    }

    override fun onDetachedFromWindow() {
        anim?.cancel(); anim = null
        super.onDetachedFromWindow()
    }

    override fun onDraw(c: Canvas) {
        val w = width.toFloat(); val h = height.toFloat()
        if (w <= 0f || h <= 0f) return
        val r = Glass.dp(context, 5f)

        frame.color = Glass.accent(context)
        c.drawRoundRect(RectF(1f, 1f, w - 1f, h - 1f), r, r, frame)

        // ruled lines of a page
        rule.color = (Glass.textMuted(context) and 0x00FFFFFF) or 0x80000000.toInt()
        val pad = Glass.dp(context, 6f)
        val lh = Glass.dp(context, 2f)
        var y = Glass.dp(context, 8f)
        while (y < h - pad) {
            c.drawRoundRect(RectF(pad, y, w - pad, y + lh), lh, lh, rule)
            y += Glass.dp(context, 7f)
        }

        // the scan line sweeping top to bottom
        val band = Glass.dp(context, 9f)
        val cy = -band + t * (h + band)
        scan.shader = android.graphics.LinearGradient(
            0f, cy, 0f, cy + band,
            intArrayOf(0x00000000, Glass.cyan(context), 0x00000000),
            floatArrayOf(0f, 0.5f, 1f), Shader.TileMode.CLAMP)
        c.drawRect(RectF(1f, cy, w - 1f, cy + band), scan)
        scan.shader = null
    }
}

/* =====================================================================
   Dashboard bar chart - six months of signing activity, bars growing in
   with a staggered spring.
   ===================================================================== */
class BarChartView(context: Context) : View(context) {

    private val barPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val txtPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        textSize = Glass.dp(context, 10.5f)
        typeface = Glass.typeface(context, false)
    }
    private val numPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        textSize = Glass.dp(context, 11f)
        typeface = Glass.typeface(context, true)
    }
    private var labels: List<String> = emptyList()
    private var values: List<Int> = emptyList()
    private var progress = 0f

    fun setData(labels: List<String>, values: List<Int>) {
        this.labels = labels; this.values = values
        progress = 0f
        ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 950
            interpolator = DecelerateInterpolator(2.2f)
            addUpdateListener { progress = it.animatedValue as Float; invalidate() }
            start()
        }
    }

    override fun onMeasure(w: Int, h: Int) {
        setMeasuredDimension(MeasureSpec.getSize(w), Glass.dp(context, 132f).toInt())
    }

    override fun onDraw(c: Canvas) {
        if (labels.isEmpty()) return
        val n = labels.size
        val padB = Glass.dp(context, 20f)
        val padT = Glass.dp(context, 18f)
        val gap = Glass.dp(context, 9f)
        val colW = (width - gap * (n - 1)) / n
        val maxV = (values.maxOrNull() ?: 0).coerceAtLeast(1)
        val zone = height - padB - padT

        txtPaint.color = Glass.textMuted(context)
        numPaint.color = Glass.textMuted(context)

        for (i in 0 until n) {
            val left = i * (colW + gap)
            val cx = left + colW / 2f
            // stagger: each bar starts a little after the previous one
            val local = ((progress - i * 0.07f) / 0.6f).coerceIn(0f, 1f)
            val target = if (maxV == 0) 0f else values[i].toFloat() / maxV
            val hBar = (zone * target * local).coerceAtLeast(Glass.dp(context, 2f))
            val top = height - padB - hBar
            barPaint.shader = android.graphics.LinearGradient(
                cx, top, cx, height - padB,
                Glass.cyan(context), Glass.accent(context), Shader.TileMode.CLAMP)
            val r = Glass.dp(context, 6f)
            c.drawRoundRect(RectF(left, top, left + colW, height - padB), r, r, barPaint)
            barPaint.shader = null
            if (values[i] > 0 && local > 0.6f) {
                c.drawText(values[i].toString(), cx, top - Glass.dp(context, 5f), numPaint)
            }
            c.drawText(labels[i], cx, height - Glass.dp(context, 5f), txtPaint)
        }
    }
}

/* =====================================================================
   Animated backdrop: photo + mesh gradient + topography + data flow,
   with accelerometer parallax.
   ===================================================================== */
class LiquidBackgroundView(context: Context) : View(context), SensorEventListener {

    private val dark = Glass.isDark(context)
    private var photo: Bitmap? = null
    private val photoPaint = Paint(Paint.FILTER_BITMAP_FLAG or Paint.ANTI_ALIAS_FLAG)
    private val meshPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = Glass.dp(context, 1f)
    }
    private val dotPaint = Paint(Paint.ANTI_ALIAS_FLAG)

    private var t = 0f
    private var anim: ValueAnimator? = null

    // parallax (device tilt)
    private var sensors: SensorManager? = null
    private var px = 0f; private var py = 0f
    private var tpx = 0f; private var tpy = 0f
    private val maxShift get() = Glass.dp(context, 14f)

    // topography grid
    private val cell = Glass.dp(context, 26f)
    private var cols = 0; private var rows = 0
    private var field: FloatArray = FloatArray(0)
    private var segs: FloatArray = FloatArray(0)

    // particles
    private class P(var x: Float, var y: Float, var vx: Float, var vy: Float, var r: Float, var a: Float)
    private val parts = ArrayList<P>()

    init {
        setLayerType(LAYER_TYPE_HARDWARE, null)
        photo = try {
            val o = BitmapFactory.Options().apply { inSampleSize = 2 }
            val b = BitmapFactory.decodeResource(resources, R.drawable.bg_app, o)
            if (b != null) frost(b) else null
        } catch (_: Throwable) { null }
    }

    /** cheap frosted-glass blur: shrink hard, grow back bilinear */
    private fun frost(src: Bitmap): Bitmap {
        val w = (src.width / 7).coerceAtLeast(24)
        val h = (src.height / 7).coerceAtLeast(24)
        val small = Bitmap.createScaledBitmap(src, w, h, true)
        val out = Bitmap.createScaledBitmap(small, src.width, src.height, true)
        if (small != out) small.recycle()
        if (src != out) src.recycle()
        return out
    }

    override fun onSizeChanged(w: Int, h: Int, ow: Int, oh: Int) {
        super.onSizeChanged(w, h, ow, oh)
        cols = (w / cell).toInt() + 2
        rows = (h / cell).toInt() + 2
        field = FloatArray(cols * rows)
        segs = FloatArray(cols * rows * 8)
        parts.clear()
        val n = min(52, (w * h / 26000f).toInt().coerceAtLeast(18))
        repeat(n) {
            parts.add(P(
                Math.random().toFloat() * w, Math.random().toFloat() * h,
                (Math.random().toFloat() - 0.5f) * 0.25f,
                -0.12f - Math.random().toFloat() * 0.28f,
                Glass.dp(context, 0.8f + Math.random().toFloat() * 1.4f),
                0.25f + Math.random().toFloat() * 0.5f))
        }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        anim = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 1000; repeatCount = ValueAnimator.INFINITE
            addUpdateListener { t += 0.016f; step(); invalidate() }
            start()
        }
        sensors = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
        sensors?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)?.let {
            sensors?.registerListener(this, it, SensorManager.SENSOR_DELAY_UI)
        }
    }

    override fun onDetachedFromWindow() {
        anim?.cancel(); anim = null
        sensors?.unregisterListener(this); sensors = null
        super.onDetachedFromWindow()
    }

    override fun onSensorChanged(e: SensorEvent) {
        // x/y in m/s^2; clamp to a gentle range so the drift stays subtle
        tpx = (-e.values[0] / 9.81f).coerceIn(-1f, 1f) * maxShift
        tpy = ((e.values[1] / 9.81f) - 0.5f).coerceIn(-1f, 1f) * maxShift
    }

    override fun onAccuracyChanged(s: Sensor?, a: Int) {}

    private fun step() {
        px += (tpx - px) * 0.06f
        py += (tpy - py) * 0.06f
        val w = width.toFloat(); val h = height.toFloat()
        for (p in parts) {
            p.x += p.vx; p.y += p.vy
            if (p.y < -12f) { p.y = h + 12f; p.x = Math.random().toFloat() * w }
            if (p.x < -12f) p.x = w + 12f
            if (p.x > w + 12f) p.x = -12f
        }
    }

    private fun sample(x: Float, y: Float): Float =
        (sin(x * 0.85f + t * 0.22f) * 0.55f +
         sin(y * 0.72f - t * 0.17f) * 0.50f +
         sin((x + y) * 0.52f + t * 0.29f) * 0.42f +
         sin((x - y) * 0.38f - t * 0.13f) * 0.36f +
         sin(hypot(x - 2.2f, y - 1.3f) * 1.05f - t * 0.34f) * 0.50f)

    override fun onDraw(canvas: Canvas) {
        val w = width.toFloat(); val h = height.toFloat()
        if (w <= 0f || h <= 0f) return

        // ---- 1. photo, centre-cropped, drifting with device tilt --------
        photo?.let { bm ->
            val scale = maxOf(w / bm.width, h / bm.height) * 1.12f
            val dw = bm.width * scale; val dh = bm.height * scale
            val left = (w - dw) / 2f + px
            val top = (h - dh) / 2f + py
            photoPaint.alpha = if (dark) 200 else 175
            canvas.drawBitmap(bm, null, RectF(left, top, left + dw, top + dh), photoPaint)
        } ?: canvas.drawColor(if (dark) 0xFF050B18.toInt() else 0xFFF7FBFF.toInt())

        // ---- 2. mesh gradient: slow drifting colour blobs ---------------
        drawBlob(canvas, w * 0.14f + sin(t * 0.11f) * w * 0.06f + px * 1.6f,
                 h * 0.18f + sin(t * 0.09f) * h * 0.05f + py * 1.6f, w * 0.55f,
                 Glass.accent(context), if (dark) 0.30f else 0.20f)
        drawBlob(canvas, w * 0.86f + sin(t * 0.13f + 2f) * w * 0.05f + px * 1.6f,
                 h * 0.30f + sin(t * 0.10f + 1f) * h * 0.06f + py * 1.6f, w * 0.50f,
                 Glass.cyan(context), if (dark) 0.26f else 0.17f)
        drawBlob(canvas, w * 0.70f + sin(t * 0.08f + 4f) * w * 0.07f + px * 1.6f,
                 h * 0.85f + sin(t * 0.12f + 3f) * h * 0.04f + py * 1.6f, w * 0.62f,
                 Glass.violet(context), if (dark) 0.26f else 0.15f)

        // ---- 3. legibility veil ----------------------------------------
        canvas.drawColor(if (dark) 0x9E050E1E.toInt() else 0xB8F7FBFF.toInt())

        // ---- 4. animated topography (marching squares) ------------------
        drawTopography(canvas)

        // ---- 5. particle / data flow -----------------------------------
        drawParticles(canvas)
    }

    private fun drawBlob(c: Canvas, cx: Float, cy: Float, r: Float, color: Int, alpha: Float) {
        if (r <= 0f) return
        val a = (alpha * 255).toInt().coerceIn(0, 255)
        meshPaint.shader = RadialGradient(cx, cy, r,
            (color and 0x00FFFFFF) or (a shl 24), color and 0x00FFFFFF, Shader.TileMode.CLAMP)
        c.drawCircle(cx, cy, r, meshPaint)
        meshPaint.shader = null
    }

    private fun drawTopography(c: Canvas) {
        if (cols < 2 || rows < 2) return
        val sx = 3.0f / cols; val sy = 2.0f / rows
        for (r in 0 until rows) for (cc in 0 until cols) field[r * cols + cc] = sample(cc * sx, r * sy)

        val levels = 8
        val ox = px * 2.2f; val oy = py * 2.2f
        for (li in 0 until levels) {
            val lv = -1.5f + (li / (levels - 1f)) * 3.0f
            val k = 1f - abs(li / (levels - 1f) - 0.5f) * 2f
            var n = 0
            for (r in 0 until rows - 1) {
                for (cc in 0 until cols - 1) {
                    val i = r * cols + cc
                    val tl = field[i]; val tr = field[i + 1]
                    val bl = field[i + cols]; val br = field[i + cols + 1]
                    var idx = 0
                    if (tl > lv) idx = idx or 8
                    if (tr > lv) idx = idx or 4
                    if (br > lv) idx = idx or 2
                    if (bl > lv) idx = idx or 1
                    if (idx == 0 || idx == 15) continue
                    val x = cc * cell + ox; val y = r * cell + oy
                    fun ip(a: Float, b: Float) = if (abs(b - a) < 1e-6f) 0.5f else (lv - a) / (b - a)
                    val txp = x + cell * ip(tl, tr); val typ = y
                    val rxp = x + cell;              val ryp = y + cell * ip(tr, br)
                    val bxp = x + cell * ip(bl, br); val byp = y + cell
                    val lxp = x;                     val lyp = y + cell * ip(tl, bl)
                    fun put(x1: Float, y1: Float, x2: Float, y2: Float) {
                        if (n + 4 > segs.size) return
                        segs[n] = x1; segs[n + 1] = y1; segs[n + 2] = x2; segs[n + 3] = y2; n += 4
                    }
                    when (idx) {
                        1, 14 -> put(lxp, lyp, bxp, byp)
                        2, 13 -> put(bxp, byp, rxp, ryp)
                        3, 12 -> put(lxp, lyp, rxp, ryp)
                        4, 11 -> put(txp, typ, rxp, ryp)
                        6, 9  -> put(txp, typ, bxp, byp)
                        7, 8  -> put(lxp, lyp, txp, typ)
                        5     -> { put(lxp, lyp, txp, typ); put(bxp, byp, rxp, ryp) }
                        10    -> { put(lxp, lyp, bxp, byp); put(txp, typ, rxp, ryp) }
                    }
                }
            }
            if (n == 0) continue
            val a = ((if (dark) 0.05f + k * 0.17f else 0.04f + k * 0.12f) * 255).toInt()
            linePaint.color = if (dark) (a shl 24) or 0x5AC8FF else (a shl 24) or 0x1878BE
            c.drawLines(segs, 0, n, linePaint)
        }
    }

    private fun drawParticles(c: Canvas) {
        val base = if (dark) 0x78E1FF else 0x1482C8
        val ox = px * 3.0f; val oy = py * 3.0f
        // links first so the nodes sit on top
        for (i in parts.indices) {
            for (j in i + 1 until parts.size) {
                val dx = parts[i].x - parts[j].x; val dy = parts[i].y - parts[j].y
                val d2 = dx * dx + dy * dy
                val maxD = Glass.dp(context, 92f)
                if (d2 > maxD * maxD) continue
                val o = (1f - Math.sqrt(d2.toDouble()).toFloat() / maxD) * (if (dark) 0.20f else 0.13f)
                linePaint.color = ((o * 255).toInt() shl 24) or base
                c.drawLine(parts[i].x + ox, parts[i].y + oy, parts[j].x + ox, parts[j].y + oy, linePaint)
            }
        }
        for (p in parts) {
            dotPaint.color = ((p.a * (if (dark) 0.85f else 0.6f) * 255).toInt() shl 24) or base
            c.drawCircle(p.x + ox, p.y + oy, p.r, dotPaint)
        }
    }
}

/* =====================================================================
   Glass card: translucent fill, luminous border, touch spotlight,
   3D tilt and (optionally) a rotating border gradient.
   ===================================================================== */
class GlassCard(context: Context, private val glow: Boolean = false) : MaterialCardView(context) {

    private val spotPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val hiPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = Glass.dp(context, 1.5f)
    }
    private var spotX = -1f; private var spotY = -1f
    private var spotA = 0f
    private var ang = 0f
    private var glowAnim: ValueAnimator? = null

    private val tiltMax = 7f

    init {
        setWillNotDraw(false)
        radius = Glass.dp(context, 18f)
        cardElevation = 0f
        strokeWidth = Glass.dp(context, 1f).toInt()
        setStrokeColor(Glass.cardStroke(context))
        setCardBackgroundColor(Glass.cardFill(context))
        cameraDistance = Glass.dp(context, 2600f)
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (glow) {
            glowAnim = ValueAnimator.ofFloat(0f, 360f).apply {
                duration = 6000; repeatCount = ValueAnimator.INFINITE
                interpolator = null
                addUpdateListener { ang = it.animatedValue as Float; invalidate() }
                start()
            }
        }
    }

    override fun onDetachedFromWindow() {
        glowAnim?.cancel(); glowAnim = null
        super.onDetachedFromWindow()
    }

    /** Spotlight + 3D tilt follow the finger; both spring back on release. */
    @Suppress("ClickableViewAccessibility")
    override fun onTouchEvent(e: MotionEvent): Boolean {
        when (e.actionMasked) {
            MotionEvent.ACTION_DOWN, MotionEvent.ACTION_MOVE -> {
                spotX = e.x; spotY = e.y; spotA = 1f
                val cx = e.x / width - 0.5f
                val cy = e.y / height - 0.5f
                rotationY = cx * tiltMax
                rotationX = -cy * tiltMax
                invalidate()
            }
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                spotA = 0f
                SpringAnimation(this, SpringAnimation.ROTATION_X, 0f).apply {
                    spring.stiffness = SpringForce.STIFFNESS_LOW
                    spring.dampingRatio = SpringForce.DAMPING_RATIO_MEDIUM_BOUNCY
                }.start()
                SpringAnimation(this, SpringAnimation.ROTATION_Y, 0f).apply {
                    spring.stiffness = SpringForce.STIFFNESS_LOW
                    spring.dampingRatio = SpringForce.DAMPING_RATIO_MEDIUM_BOUNCY
                }.start()
                invalidate()
            }
        }
        return super.onTouchEvent(e)
    }

    // drawn after the card background, before the children
    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (spotA > 0f && spotX >= 0f && width > 0) {
            val r = Glass.dp(context, 220f)
            spotPaint.shader = RadialGradient(spotX, spotY, r,
                Glass.spot(context), Glass.spot(context) and 0x00FFFFFF, Shader.TileMode.CLAMP)
            canvas.drawRoundRect(RectF(0f, 0f, width.toFloat(), height.toFloat()),
                radius, radius, spotPaint)
            spotPaint.shader = null
        }
    }

    // drawn on top of the children
    override fun dispatchDraw(canvas: Canvas) {
        super.dispatchDraw(canvas)
        val w = width.toFloat(); val h = height.toFloat()
        if (w <= 0f || h <= 0f) return

        // wet-glass top edge
        hiPaint.color = Glass.highlight(context)
        hiPaint.strokeWidth = Glass.dp(context, 1f)
        canvas.drawLine(w * 0.14f, 1f, w * 0.86f, 1f, hiPaint)

        // rotating border gradient on the important cards
        if (glow) {
            val m = Matrix().apply { setRotate(ang, w / 2f, h / 2f) }
            val sg = SweepGradient(w / 2f, h / 2f,
                intArrayOf(0x00000000, Glass.cyan(context), Glass.violet(context), 0x00000000, 0x00000000),
                floatArrayOf(0f, 0.06f, 0.13f, 0.26f, 1f))
            sg.setLocalMatrix(m)
            glowPaint.shader = sg
            val inset = Glass.dp(context, 0.75f)
            canvas.drawRoundRect(RectF(inset, inset, w - inset, h - inset), radius, radius, glowPaint)
            glowPaint.shader = null
        }
    }
}
