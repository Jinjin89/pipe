// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.view.View
import android.view.animation.LinearInterpolator

/** The round connect button: grey when off, a spinning arc while connecting, teal with a glow when on. */
internal class PowerButton(context: Context) : View(context) {
    enum class State { OFF, CONNECTING, ON }

    var state = State.OFF
        set(value) {
            if (field == value) return
            field = value
            sync()
            invalidate()
        }

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val box = RectF()
    private var sweep = 0f
    private val spinner = ValueAnimator.ofFloat(0f, 360f).apply {
        duration = 1100
        repeatCount = ValueAnimator.INFINITE
        interpolator = LinearInterpolator()
        addUpdateListener {
            sweep = it.animatedValue as Float
            invalidate()
        }
    }

    init {
        isClickable = true
        isFocusable = true
        contentDescription = "Connect"
    }

    private fun sync() {
        contentDescription = when (state) {
            State.OFF -> "Connect"
            State.CONNECTING -> "Connecting"
            State.ON -> "Disconnect"
        }
        if (state == State.CONNECTING && isAttachedToWindow) {
            // With animations turned off the arc simply stays still.
            if (ValueAnimator.areAnimatorsEnabled() && !spinner.isRunning) spinner.start()
        } else if (spinner.isRunning) {
            spinner.cancel()
        }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        sync()
    }

    override fun onDetachedFromWindow() {
        spinner.cancel()
        super.onDetachedFromWindow()
    }

    override fun onMeasure(widthSpec: Int, heightSpec: Int) {
        val size = context.dp(168)
        setMeasuredDimension(resolveSize(size, widthSpec), resolveSize(size, heightSpec))
    }

    override fun onDraw(canvas: Canvas) {
        val cx = width / 2f
        val cy = height / 2f
        val glow = context.dp(14).toFloat()
        val radius = minOf(width, height) / 2f - glow
        val ring = context.dp(6).toFloat()
        val teal = context.c(R.color.connected)
        paint.style = Paint.Style.FILL
        when (state) {
            State.ON -> {
                paint.color = withAlpha(teal, 40)
                canvas.drawCircle(cx, cy, radius + glow, paint)
                paint.color = withAlpha(teal, 70)
                canvas.drawCircle(cx, cy, radius + glow / 2, paint)
                paint.color = teal
                canvas.drawCircle(cx, cy, radius, paint)
            }
            else -> {
                paint.color = context.c(R.color.surface2)
                canvas.drawCircle(cx, cy, radius, paint)
                paint.style = Paint.Style.STROKE
                paint.strokeWidth = ring
                paint.color = context.c(R.color.border)
                canvas.drawCircle(cx, cy, radius - ring / 2, paint)
                if (state == State.CONNECTING) {
                    paint.color = context.c(R.color.primary)
                    paint.strokeCap = Paint.Cap.ROUND
                    box.set(cx - radius + ring / 2, cy - radius + ring / 2, cx + radius - ring / 2, cy + radius - ring / 2)
                    canvas.drawArc(box, if (spinner.isRunning) sweep - 90f else -90f, 110f, false, paint)
                }
            }
        }
        drawPowerIcon(canvas, cx, cy, radius * 0.36f)
    }

    private fun drawPowerIcon(canvas: Canvas, cx: Float, cy: Float, r: Float) {
        paint.style = Paint.Style.STROKE
        paint.strokeCap = Paint.Cap.ROUND
        paint.strokeWidth = context.dp(6).toFloat()
        paint.color = when (state) {
            State.ON -> context.c(R.color.surface)
            State.CONNECTING -> context.c(R.color.primary)
            State.OFF -> context.c(R.color.muted)
        }
        box.set(cx - r, cy - r, cx + r, cy + r)
        canvas.drawArc(box, -55f, 290f, false, paint)
        canvas.drawLine(cx, cy - r * 1.2f, cx, cy - r * 0.1f, paint)
    }

    private fun withAlpha(color: Int, alpha: Int): Int = (color and 0x00FFFFFF) or (alpha shl 24)
}
