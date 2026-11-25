// SPDX-License-Identifier: GPL-3.0-or-later

package io.pipe.app

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.ImageFormat
import android.graphics.Matrix
import android.graphics.RectF
import android.graphics.SurfaceTexture
import android.graphics.drawable.GradientDrawable
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.hardware.camera2.params.OutputConfiguration
import android.hardware.camera2.params.SessionConfiguration
import android.media.ImageReader
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.util.Size
import android.view.Gravity
import android.view.Surface
import android.view.TextureView
import android.view.View
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import mobile.Mobile
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.abs

class ScanActivity : Activity() {
    private lateinit var textureView: TextureView
    private lateinit var statusText: TextView

    private val cameraLock = Any()
    private var cameraDevice: CameraDevice? = null
    private var captureSession: CameraCaptureSession? = null
    private var imageReader: ImageReader? = null
    private var previewSurface: Surface? = null
    private var previewSize: Size? = null
    private var closing = false

    private var bgThread: HandlerThread? = null
    private var bgHandler: Handler? = null
    private var yBuffer: ByteArray? = null
    private var lastDecodeMs = 0L
    private val found = AtomicBoolean(false)

    private val surfaceListener = object : TextureView.SurfaceTextureListener {
        override fun onSurfaceTextureAvailable(surface: SurfaceTexture, width: Int, height: Int) {
            openCamera(width, height)
        }

        override fun onSurfaceTextureSizeChanged(surface: SurfaceTexture, width: Int, height: Int) {
            configureTransform(width, height)
        }

        override fun onSurfaceTextureDestroyed(surface: SurfaceTexture): Boolean = true

        override fun onSurfaceTextureUpdated(surface: SurfaceTexture) = Unit
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE) // the preview may show a credential QR
        val root = FrameLayout(this).apply { setBackgroundColor(Color.BLACK) }
        textureView = TextureView(this)
        root.addView(textureView, MATCH, MATCH)

        val overlay = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val topBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(0x99000000.toInt())
            setPadding(dp(16), dp(10), dp(16), dp(10))
        }
        topBar.add(text("Scan QR code", 18f, Color.WHITE, true), 0, WRAP, weight = 1f)
        topBar.add(button("Cancel").apply { setOnClickListener { finish() } }, WRAP, WRAP)
        overlay.add(topBar, MATCH, WRAP)

        val center = FrameLayout(this)
        val reticle = View(this).apply {
            background = GradientDrawable().apply {
                setColor(Color.TRANSPARENT)
                cornerRadius = dp(16).toFloat()
                setStroke(dp(2), 0xCCFFFFFF.toInt())
            }
        }
        center.addView(reticle, FrameLayout.LayoutParams(dp(240), dp(240), Gravity.CENTER))
        statusText = text("Fit the Pipe QR code in the square", 14f, Color.WHITE).apply {
            gravity = Gravity.CENTER
            setPadding(dp(16), dp(10), dp(16), dp(10))
            background = shape(0x99000000.toInt(), 12)
        }
        center.addView(statusText, FrameLayout.LayoutParams(WRAP, WRAP, Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL).apply {
            bottomMargin = dp(24)
            marginStart = dp(16)
            marginEnd = dp(16)
        })
        overlay.add(center, MATCH, 0, weight = 1f)

        val bottomBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            setBackgroundColor(0x99000000.toInt())
            setPadding(dp(16), dp(12), dp(16), dp(16))
        }
        bottomBar.add(button("From image").apply {
            setOnClickListener {
                setResult(RESULT_FROM_IMAGE)
                finish()
            }
        }, MATCH, WRAP)
        overlay.add(bottomBar, MATCH, WRAP)

        root.addView(overlay, MATCH, MATCH)
        setContentView(root)
        overlay.padForSystemBars()
    }

    override fun onResume() {
        super.onResume()
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            finish()
            return
        }
        found.set(false)
        synchronized(cameraLock) { closing = false }
        val thread = HandlerThread("pipe-qr").apply { start() }
        bgThread = thread
        bgHandler = Handler(thread.looper)
        if (textureView.isAvailable) {
            openCamera(textureView.width, textureView.height)
        } else {
            textureView.surfaceTextureListener = surfaceListener
        }
    }

    override fun onPause() {
        textureView.surfaceTextureListener = null
        closeCamera()
        stopBackground()
        super.onPause()
    }

    override fun finish() {
        closeCamera()
        super.finish()
    }

    private fun stopBackground() {
        val thread = bgThread ?: return
        bgThread = null
        bgHandler = null
        thread.quitSafely()
        runCatching { thread.join(500) }
    }

    private fun openCamera(viewWidth: Int, viewHeight: Int) {
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) return
        val handler = bgHandler ?: return
        val manager = getSystemService(CameraManager::class.java)
        val cameraId = try {
            chooseCamera(manager)
        } catch (_: Exception) {
            null
        }
        if (cameraId == null) {
            showCameraError("No camera available. Use From image instead.")
            return
        }
        try {
            val chars = manager.getCameraCharacteristics(cameraId)
            val map = chars.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
            if (map == null) {
                showCameraError("Could not start the camera. Use From image instead.")
                return
            }
            val analysisSize = chooseAnalysisSize(map.getOutputSizes(ImageFormat.YUV_420_888))
            val preview = choosePreviewSize(map.getOutputSizes(SurfaceTexture::class.java), analysisSize)
            previewSize = preview
            configureTransform(viewWidth, viewHeight)

            val afModes = chars.get(CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES) ?: IntArray(0)
            val continuousAf = CameraCharacteristics.CONTROL_AF_MODE_CONTINUOUS_PICTURE in afModes

            val reader = ImageReader.newInstance(analysisSize.width, analysisSize.height, ImageFormat.YUV_420_888, 2)
            reader.setOnImageAvailableListener({ r -> onFrame(r) }, handler)
            synchronized(cameraLock) {
                if (closing) {
                    reader.close()
                    return
                }
                imageReader?.close()
                imageReader = reader
            }

            manager.openCamera(cameraId, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    synchronized(cameraLock) {
                        if (closing) {
                            device.close()
                            return
                        }
                        cameraDevice = device
                    }
                    startSession(device, preview, reader, continuousAf)
                }

                override fun onDisconnected(device: CameraDevice) {
                    closeCamera()
                    device.close()
                }

                override fun onError(device: CameraDevice, error: Int) {
                    closeCamera()
                    device.close()
                    showCameraError("Could not open the camera. Use From image instead.")
                }
            }, handler)
        } catch (_: Exception) {
            closeCamera()
            showCameraError("Could not open the camera. Use From image instead.")
        }
    }

    private fun startSession(device: CameraDevice, preview: Size, reader: ImageReader, continuousAf: Boolean) {
        val handler = bgHandler ?: return
        val texture = textureView.surfaceTexture ?: return
        texture.setDefaultBufferSize(preview.width, preview.height)
        val surface = Surface(texture)
        synchronized(cameraLock) {
            if (closing || cameraDevice !== device) {
                surface.release()
                return
            }
            previewSurface?.release()
            previewSurface = surface
        }

        val stateCallback = object : CameraCaptureSession.StateCallback() {
            override fun onConfigured(session: CameraCaptureSession) {
                synchronized(cameraLock) {
                    if (closing || cameraDevice !== device) {
                        session.close()
                        return
                    }
                    captureSession = session
                }
                try {
                    val request = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                        addTarget(surface)
                        addTarget(reader.surface)
                        if (continuousAf) {
                            set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                        }
                    }
                    session.setRepeatingRequest(request.build(), null, handler)
                } catch (_: Exception) {
                    closeCamera()
                    showCameraError("Camera preview failed. Use From image instead.")
                }
            }

            override fun onConfigureFailed(session: CameraCaptureSession) {
                closeCamera()
                showCameraError("Camera preview failed. Use From image instead.")
            }
        }

        try {
            val surfaces = listOf(surface, reader.surface)
            if (Build.VERSION.SDK_INT >= 28) {
                val config = SessionConfiguration(
                    SessionConfiguration.SESSION_REGULAR,
                    surfaces.map(::OutputConfiguration),
                    { cmd -> handler.post(cmd) },
                    stateCallback,
                )
                device.createCaptureSession(config)
            } else {
                @Suppress("DEPRECATION")
                device.createCaptureSession(surfaces, stateCallback, handler)
            }
        } catch (_: Exception) {
            closeCamera()
            showCameraError("Camera preview failed. Use From image instead.")
        }
    }

    private fun onFrame(reader: ImageReader) {
        val image = try {
            reader.acquireLatestImage()
        } catch (_: Exception) {
            null
        } ?: return
        var closed = false
        try {
            if (found.get()) return
            val now = SystemClock.elapsedRealtime()
            if (now - lastDecodeMs < MIN_FRAME_INTERVAL_MS) return
            lastDecodeMs = now

            val plane = image.planes[0]
            if (plane.pixelStride != 1) return
            val buffer = plane.buffer
            val rowStride = plane.rowStride
            val width = image.width
            val height = image.height
            val required = rowStride * (height - 1) + width
            if (width <= 0 || height <= 0 || rowStride < width || required <= 0 || buffer.remaining() < required) return

            val bytes = yBuffer?.takeIf { it.size == required } ?: ByteArray(required).also { yBuffer = it }
            synchronized(cameraLock) {
                // closeCamera takes this lock first, so the reader can't close mid-copy,
                // and a frame from an earlier session never runs against a new one.
                if (closing || reader !== imageReader) return
                buffer.get(bytes, 0, required)
                image.close()
                closed = true
            }

            val link = Mobile.decodeQRFrame(bytes, width.toLong(), height.toLong(), rowStride.toLong())
            if (link.isNotEmpty() && found.compareAndSet(false, true)) {
                closeCamera()
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        setResult(RESULT_OK, Intent().putExtra(EXTRA_LINK, link))
                        finish()
                    }
                }
            }
        } catch (_: Exception) {
            // Never log frames or decoded text.
        } finally {
            if (!closed) runCatching { image.close() }
        }
    }

    private fun closeCamera() {
        val session: CameraCaptureSession?
        val device: CameraDevice?
        val reader: ImageReader?
        val surface: Surface?
        synchronized(cameraLock) {
            closing = true
            session = captureSession
            device = cameraDevice
            reader = imageReader
            surface = previewSurface
            captureSession = null
            cameraDevice = null
            imageReader = null
            previewSurface = null
        }
        runCatching { session?.close() }
        runCatching { device?.close() }
        runCatching { reader?.close() }
        runCatching { surface?.release() }
    }

    private fun showCameraError(message: String) {
        runOnUiThread {
            if (!isFinishing && !isDestroyed) statusText.text = message
        }
    }

    private fun chooseCamera(manager: CameraManager): String? {
        var fallback: String? = null
        for (id in manager.cameraIdList) {
            if (fallback == null) fallback = id
            val facing = manager.getCameraCharacteristics(id).get(CameraCharacteristics.LENS_FACING)
            if (facing == CameraCharacteristics.LENS_FACING_BACK) return id
        }
        return fallback
    }

    // Every camera can stream the preview and YUV together when both are at
    // most the display size or 1080p, whichever is smaller (Camera2's PREVIEW).
    private fun fitsPreviewStream(size: Size): Boolean {
        val m = resources.displayMetrics
        return maxOf(size.width, size.height) <= minOf(1920, maxOf(m.widthPixels, m.heightPixels)) &&
            minOf(size.width, size.height) <= minOf(1080, minOf(m.widthPixels, m.heightPixels))
    }

    // More pixels per QR module read a dense code from farther away and through
    // more blur. Cameras crop the short side for wider frames, so the longest
    // frame has the most pixels per degree.
    private fun chooseAnalysisSize(sizes: Array<Size>?): Size {
        val usable = sizes.orEmpty().filter { it.width.toLong() * it.height.toLong() <= MAX_QR_PIXELS }
        if (usable.isEmpty()) return Size(640, 480)
        val safe = usable.filter(::fitsPreviewStream)
        if (safe.isEmpty()) return usable.minBy { it.width * it.height }
        return safe.maxWith(compareBy<Size> { maxOf(it.width, it.height) }.thenBy { minOf(it.width, it.height) })
    }

    private fun choosePreviewSize(sizes: Array<Size>?, target: Size): Size {
        val all = sizes.orEmpty().toList()
        if (all.isEmpty()) return target
        val safe = all.filter(::fitsPreviewStream)
        val pool = safe.filter { maxOf(it.width, it.height) <= 1280 }.ifEmpty { safe }.ifEmpty { listOf(all.minBy { it.width * it.height }) }
        val targetRatio = target.width.toDouble() / target.height.toDouble()
        return pool.minBy {
            abs(it.width.toDouble() / it.height.toDouble() - targetRatio) * 1000.0 +
                abs(it.width * it.height - 960 * 720) / 100000.0
        }
    }

    private fun configureTransform(viewWidth: Int, viewHeight: Int) {
        val preview = previewSize ?: return
        if (viewWidth <= 0 || viewHeight <= 0) return
        val rotation = if (Build.VERSION.SDK_INT >= 30) {
            display?.rotation ?: Surface.ROTATION_0
        } else {
            @Suppress("DEPRECATION")
            windowManager.defaultDisplay.rotation
        }
        val matrix = Matrix()
        val viewRect = RectF(0f, 0f, viewWidth.toFloat(), viewHeight.toFloat())
        val bufferRect = RectF(0f, 0f, preview.height.toFloat(), preview.width.toFloat())
        val cx = viewRect.centerX()
        val cy = viewRect.centerY()
        if (rotation == Surface.ROTATION_90 || rotation == Surface.ROTATION_270) {
            bufferRect.offset(cx - bufferRect.centerX(), cy - bufferRect.centerY())
            matrix.setRectToRect(viewRect, bufferRect, Matrix.ScaleToFit.FILL)
            val scale = maxOf(
                viewHeight.toFloat() / preview.height,
                viewWidth.toFloat() / preview.width,
            )
            matrix.postScale(scale, scale, cx, cy)
            matrix.postRotate(90f * (rotation - 2), cx, cy)
        } else {
            val bufferAspect = preview.height.toFloat() / preview.width.toFloat()
            val viewAspect = viewWidth.toFloat() / viewHeight.toFloat()
            val sx = if (viewAspect > bufferAspect) 1f else bufferAspect / viewAspect
            val sy = if (viewAspect > bufferAspect) viewAspect / bufferAspect else 1f
            matrix.setScale(sx, sy, cx, cy)
            if (rotation == Surface.ROTATION_180) {
                matrix.postRotate(180f, cx, cy)
            }
        }
        textureView.setTransform(matrix)
    }

    companion object {
        const val EXTRA_LINK = "link"
        const val RESULT_FROM_IMAGE = Activity.RESULT_FIRST_USER + 1
        private const val MIN_FRAME_INTERVAL_MS = 100L
    }
}
