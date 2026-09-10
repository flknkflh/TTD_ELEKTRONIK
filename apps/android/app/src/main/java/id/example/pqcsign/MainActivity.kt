package id.example.pqcsign

import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import id.example.pqcsign.net.ApiClient
import kotlin.math.roundToInt
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.view.ContextThemeWrapper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.widget.NestedScrollView
import com.google.android.material.appbar.AppBarLayout
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.color.MaterialColors
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.tabs.TabLayout
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import id.example.pqcsign.app.AppCore
import id.example.pqcsign.app.AppState
import kotlin.concurrent.thread

/**
 * PQC PDF Sign — Android client (Rencana V1 §21). Material 3, built in code:
 * a tab bar over a swappable content area. Pre-login: Masuk / Daftar /
 * Verifikasi (public, no account). Post-login: Beranda / Tanda Tangan /
 * Verifikasi / Akun. All crypto stays in AppCore / the AAR.
 */
private const val APP_VERSION = "v0.4.0"

class MainActivity : AppCompatActivity() {

    private lateinit var core: AppCore
    private lateinit var toolbar: MaterialToolbar
    private lateinit var tabs: TabLayout
    private lateinit var progress: LinearProgressIndicator
    private lateinit var container: LinearLayout

    private var loggedIn = false
    private var signReason = "Persetujuan"
    private var signIssuedPlace = ""
    private var lastSigned: ByteArray? = null

    // QR placement (Rencana RB-2c) — must match the server's stampAspect.
    private val STAMP_ASPECT = 0.42f
    private var pendingSignUri: Uri? = null
    private var signPageIndex = 0
    private var signPageCount = 1
    private var boxXFrac = 0.60
    private var boxYFrac = 0.78
    private var boxWFrac = 0.26
    private var placementHost: LinearLayout? = null
    private var pageView: ImageView? = null
    private var qrBoxView: View? = null
    private var qrHandleView: View? = null
    private var placementBuilt = false
    private var pageNumberInput: android.widget.EditText? = null
    private var pageTotalLabel: TextView? = null
    private var pageNavPrev: View? = null
    private var pageNavNext: View? = null
    private val savedStamps = mutableListOf<ApiClient.StampPlacement>()
    private var stampCountLabel: TextView? = null

    // result sinks for the current screen
    private var signResult: LinearLayout? = null
    private var verifyResult: LinearLayout? = null

    private val pickToSign = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) startPlacement(uri)
    }
    private val pickToVerify = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) runVerify(uri)
    }
    private var pendingHashId = ""
    private val pickToHashVerify = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) runHashVerify(uri)
    }
    private var qrServer = ""
    private val scanQr = registerForActivityResult(ScanContract()) { r ->
        r.contents?.let { onQrScanned(it) }
    }
    private val saveSigned = registerForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri ->
        val bytes = lastSigned
        if (uri != null && bytes != null) {
            contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
            snack("Tersimpan (${bytes.size / 1024} KB)")
        }
    }

    // ---------------------------------------------------------------- layout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        core = AppCore(this, AppState(this))

        val surface = MaterialColors.getColor(this, com.google.android.material.R.attr.colorSurface, Color.WHITE)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(surface)
        }

        val appBar = AppBarLayout(this).apply { elevation = dpF(0.5f) }
        toolbar = MaterialToolbar(this).apply {
            title = "PQC PDF Sign"
            setTitleTextColor(onSurface())
        }
        tabs = TabLayout(this).apply {
            tabMode = TabLayout.MODE_SCROLLABLE
            tabGravity = TabLayout.GRAVITY_START
        }
        appBar.addView(toolbar, AppBarLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        appBar.addView(tabs, AppBarLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        root.addView(appBar, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        progress = LinearProgressIndicator(this).apply {
            isIndeterminate = true
            visibility = View.GONE
        }
        root.addView(progress, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(24))
        }
        val scroll = NestedScrollView(this).apply { isFillViewport = true; addView(container) }
        root.addView(scroll, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        setContentView(root)

        tabs.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) = render(tab.position)
            override fun onTabUnselected(tab: TabLayout.Tab) {}
            override fun onTabReselected(tab: TabLayout.Tab) {}
        })
        rebuildTabs()
    }

    private fun rebuildTabs() {
        val titles = if (loggedIn)
            listOf("Beranda", "Tanda Tangan", "Verifikasi", "Akun")
        else
            listOf("Masuk", "Daftar", "Verifikasi")
        tabs.removeAllTabs()
        titles.forEach { tabs.addTab(tabs.newTab().setText(it)) }
        toolbar.subtitle = if (loggedIn) core.state.accountEmail else null
        render(0)
    }

    private fun render(pos: Int) {
        signResult = null; verifyResult = null
        val v = if (loggedIn) when (pos) {
            0 -> screenHome(); 1 -> screenSign(); 2 -> screenVerify(); else -> screenAccount()
        } else when (pos) {
            0 -> screenLogin(); 1 -> screenRegister(); else -> screenVerifyPublic()
        }
        container.removeAllViews()
        container.addView(v)
    }

    // ---------------------------------------------------------------- screens

    private fun screenLogin(): View = page {
        addView(heading("Masuk"))
        addView(card {
            val srv = field(this, "Alamat server", core.state.serverUrl)
            val email = field(this, "Email", core.state.accountEmail ?: "")
            val pw = field(this, "Kata sandi", password = true)
            addView(primary("Masuk") {
                task {
                    core.connect(srv.text.toString().trim(), true)
                    core.login(email.text.toString().trim(), pw.text.toString())
                    val cs = core.ensureEnrolled()
                    runOnUiThread {
                        loggedIn = true
                        rebuildTabs()
                        val ok = cs.state == "active"
                        snack(if (ok) "Masuk. Sertifikat aktif." else "Masuk. Sertifikat: ${cs.state}")
                    }
                }
            })
        })
        addView(hint("Belum punya akun? Buka tab “Daftar”."))
        addView(hint("Versi $APP_VERSION"))
    }

    private fun screenRegister(): View = page {
        addView(heading("Daftar akun"))
        addView(card {
            val srv = field(this, "Alamat server", core.state.serverUrl)
            val name = field(this, "Nama lengkap (dengan gelar)")
            val position = field(this, "Jabatan")
            val nip = field(this, "NIP")
            val org = field(this, "Instansi / unit")
            val email = field(this, "Email")
            val pw = field(this, "Kata sandi (min. 8 karakter)", password = true)
            addView(primary("Daftar") {
                task {
                    core.connect(srv.text.toString().trim(), true)
                    val r = core.register(
                        name.text.toString().trim(), org.text.toString().trim(),
                        email.text.toString().trim(), pw.text.toString(),
                        position.text.toString().trim(), nip.text.toString().trim(),
                    )
                    runOnUiThread { snack(r.message.ifEmpty { "Akun dibuat (${r.status})" }) }
                }
            })
        })
        addView(hint("Akun harus disetujui admin sebelum bisa dipakai."))
    }

    private fun screenVerifyPublic(): View = page {
        addView(heading("Verifikasi dokumen"))
        addView(hint("Terbuka untuk umum — tidak perlu akun."))
        addView(card {
            val srv = field(this, "Alamat server", core.state.serverUrl)
            addView(tonal("Pilih PDF & verifikasi") {
                pendingVerifyServer = srv.text.toString().trim()
                pickToVerify.launch(arrayOf("application/pdf"))
            })
            addView(tonal("Pindai QR") {
                qrServer = srv.text.toString().trim()
                scanQr.launch(scanOpts())
            })
        })
        verifyResult = LinearLayout(themed()).apply { orientation = LinearLayout.VERTICAL }
        addView(verifyResult)
    }

    private fun scanOpts() = ScanOptions().apply {
        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
        setPrompt("Arahkan kamera ke QR pada dokumen")
        setBeepEnabled(false)
        setOrientationLocked(false)
    }

    private fun screenHome(): View = page {
        addView(heading("Halo 👋"))
        addView(card {
            val status = TextView(themed()).apply { text = "Memeriksa sertifikat…" }
            addView(status)
            task {
                val cs = core.certificateStatus()
                runOnUiThread {
                    status.text = when (cs.state) {
                        "active" -> "Sertifikat aktif — siap menandatangani."
                        "pending" -> "Sertifikat belum terbit. Coba lagi sebentar."
                        else -> "Status sertifikat: ${cs.state}"
                    }
                }
            }
        })
        addView(bigAction("✍️", "Tanda Tangani Dokumen", "Pilih PDF, tandatangani di perangkat ini") {
            tabs.getTabAt(1)?.select()
        })
        addView(bigAction("🔍", "Verifikasi Dokumen", "Periksa keaslian sebuah PDF bertanda tangan") {
            tabs.getTabAt(2)?.select()
        })
    }

    private fun screenSign(): View = page {
        addView(heading("Tanda tangani dokumen"))
        addView(card {
            val reason = field(this, "Alasan penandatanganan", "Persetujuan")
            val place = field(this, "Dikeluarkan di (kota)")
            addView(primary("Pilih PDF") {
                signReason = reason.text.toString().trim().ifEmpty { "Persetujuan" }
                signIssuedPlace = place.text.toString().trim()
                pickToSign.launch(arrayOf("application/pdf"))
            })
            addView(tonal("Simpan PDF hasil") {
                if (lastSigned == null) snack("Belum ada hasil") else saveSigned.launch("dokumen-bertandatangan.pdf")
            })
            addView(hint("QR “TTD Elektronik” ditempel di titik yang Anda pilih pada dokumen."))
        })
        placementHost = LinearLayout(themed()).apply { orientation = LinearLayout.VERTICAL }
        addView(placementHost)
        signResult = LinearLayout(themed()).apply { orientation = LinearLayout.VERTICAL }
        addView(signResult)
    }

    private fun screenVerify(): View = page {
        addView(heading("Verifikasi dokumen"))
        addView(card {
            addView(tonal("Pilih PDF & verifikasi") {
                pendingVerifyServer = null // logged-in -> local offline verify
                pickToVerify.launch(arrayOf("application/pdf"))
            })
            addView(tonal("Pindai QR") {
                qrServer = core.state.serverUrl
                scanQr.launch(scanOpts())
            })
            addView(hint("Pindai QR memakai alamat server tempat Anda masuk."))
        })
        addView(card {
            addView(TextView(themed()).apply {
                text = "Verifikasi tanpa unggah"; typeface = Typeface.DEFAULT_BOLD
            })
            val hashId = field(this, "ID verifikasi (dari QR)")
            addView(tonal("Pilih PDF & cocokkan sidik jari") {
                pendingHashId = hashId.text.toString().trim()
                if (pendingHashId.isEmpty()) { snack("Isi ID verifikasi dulu"); return@tonal }
                pickToHashVerify.launch(arrayOf("application/pdf"))
            })
            addView(hint("Berkas tidak diunggah — hanya SHA-512 (64 byte) yang dikirim. " +
                "Cocok untuk dokumen rahasia atau berkas yang terlalu besar untuk diunggah."))
        })
        verifyResult = LinearLayout(themed()).apply { orientation = LinearLayout.VERTICAL }
        addView(verifyResult)
    }

    private fun screenAccount(): View = page {
        addView(heading("Akun & keamanan"))
        addView(card {
            addView(TextView(themed()).apply { text = core.state.accountEmail ?: "-"; typeface = Typeface.DEFAULT_BOLD })
            val status = TextView(themed()).apply {
                text = "—"; setPadding(0, dp(6), 0, 0)
            }
            addView(status)
            task {
                val cs = core.certificateStatus()
                runOnUiThread { status.text = "Sertifikat: ${cs.state}" + (cs.serial?.let { "  ·  $it" } ?: "") }
            }
        })
        addView(card {
            addView(tonal("Laporkan perangkat hilang") {
                task { core.reportLost(); runOnUiThread { snack("Dilaporkan ke server.") } }
            })
            addView(danger("Reset perangkat ini") {
                task { core.reset(); runOnUiThread { snack("Kunci & sertifikat lokal dihapus.") } }
            })
            addView(text("Keluar") {
                loggedIn = false
                rebuildTabs()
            })
        })
    }

    // ---------------------------------------------------------------- sign flow

    private var pendingVerifyServer: String? = null

    /** After the user picks a PDF: show the page with a draggable QR box. */
    private fun startPlacement(uri: Uri) {
        pendingSignUri = uri
        signPageIndex = 0
        boxXFrac = 0.60; boxYFrac = 0.78; boxWFrac = 0.26
        savedStamps.clear()
        signResult?.removeAllViews()
        placementBuilt = false
        placementHost?.removeAllViews()
        loadPage()
    }

    private fun changePage(delta: Int) {
        val n = (signPageIndex + delta).coerceIn(0, signPageCount - 1)
        if (n == signPageIndex) return
        signPageIndex = n
        loadPage()
    }

    /** Jump to the page typed in the number box (1-based). */
    private fun gotoTypedPage() {
        val et = pageNumberInput ?: return
        val n = et.text?.toString()?.trim()?.toIntOrNull()
        val idx = ((n ?: (signPageIndex + 1)) - 1).coerceIn(0, signPageCount - 1)
        (getSystemService(INPUT_METHOD_SERVICE) as? android.view.inputmethod.InputMethodManager)
            ?.hideSoftInputFromWindow(et.windowToken, 0)
        et.clearFocus()
        if (idx == signPageIndex) { et.setText((signPageIndex + 1).toString()); return }
        signPageIndex = idx
        loadPage()
    }

    /** Renders the current page off the UI thread, then only swaps the
     *  bitmap into the existing views — the view tree and touch listeners are
     *  built once, so page turns and dragging stay smooth. */
    private fun loadPage() {
        val host = placementHost ?: return
        val uri = pendingSignUri ?: return
        task {
            val pi = core.renderPdfPage(uri, signPageIndex, 1080)
            signPageIndex = pi.pageIndex
            signPageCount = pi.pageCount
            runOnUiThread {
                if (!placementBuilt) buildPlacementScaffold(host)
                pageView?.setImageBitmap(pi.bitmap)
                if (pageNumberInput?.isFocused != true) pageNumberInput?.setText((signPageIndex + 1).toString())
                pageTotalLabel?.text = "/ $signPageCount"
                pageNavPrev?.apply { isEnabled = signPageIndex > 0; alpha = if (isEnabled) 1f else 0.4f }
                pageNavNext?.apply { isEnabled = signPageIndex < signPageCount - 1; alpha = if (isEnabled) 1f else 0.4f }
                pageView?.post { applyBoxFromFracs() }
            }
        }
    }

    private fun buildPlacementScaffold(host: LinearLayout) {
        host.removeAllViews()
        val ctx = themed()

        fun navBtn(glyph: String, onTap: () -> Unit) = MaterialButton(ctx).apply {
            text = glyph
            textSize = 18f
            insetTop = 0; insetBottom = 0
            setBackgroundColor(MaterialColors.getColor(this, com.google.android.material.R.attr.colorSecondaryContainer, Color.LTGRAY))
            setTextColor(MaterialColors.getColor(this, com.google.android.material.R.attr.colorOnSecondaryContainer, Color.BLACK))
            layoutParams = LinearLayout.LayoutParams(dp(56), dp(48))
            setOnClickListener { onTap() }
        }
        host.addView(LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(10), 0, dp(4))
            addView(TextView(ctx).apply {
                text = "Halaman"; setPadding(0, 0, dp(10), 0)
            })
            pageNavPrev = navBtn("◀") { changePage(-1) }.also { addView(it) }
            pageNumberInput = android.widget.EditText(ctx).apply {
                inputType = InputType.TYPE_CLASS_NUMBER
                setText("1")
                gravity = Gravity.CENTER
                setPadding(dp(6), dp(8), dp(6), dp(8))
                layoutParams = LinearLayout.LayoutParams(dp(60), WRAP_CONTENT).apply {
                    marginStart = dp(8); marginEnd = dp(6)
                }
                setOnEditorActionListener { _, _, _ -> gotoTypedPage(); true }
            }
            addView(pageNumberInput)
            pageTotalLabel = TextView(ctx).apply { text = "/ 1"; setPadding(0, 0, dp(8), 0) }
            addView(pageTotalLabel)
            pageNavNext = navBtn("▶") { changePage(1) }.also { addView(it) }
        })
        host.addView(hint("Seret kotak QR ke kolom tanda tangan. Tarik titik di sudut untuk mengubah ukuran. Ganti halaman dengan ◀ ▶ atau ketik nomor lalu Enter."))

        val frame = FrameLayout(ctx).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(6) }
        }
        val iv = ImageView(ctx).apply {
            layoutParams = FrameLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
            adjustViewBounds = true
            scaleType = ImageView.ScaleType.FIT_CENTER
        }
        val box = View(ctx).apply {
            layoutParams = FrameLayout.LayoutParams(dp(10), dp(10))
            background = GradientDrawable().apply {
                setColor(0x224F46E5.toInt())
                setStroke(dp(2), 0xFF4F46E5.toInt())
                cornerRadius = dp(3).toFloat()
            }
        }
        val handle = View(ctx).apply {
            layoutParams = FrameLayout.LayoutParams(dp(28), dp(28))
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(0xFF4F46E5.toInt())
                setStroke(dp(2), Color.WHITE)
            }
        }
        frame.addView(iv); frame.addView(box); frame.addView(handle)
        host.addView(frame)
        pageView = iv; qrBoxView = box; qrHandleView = handle

        wireBoxDrag(box, handle)
        wireHandleDrag(box, handle)

        host.addView(LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(10), 0, 0)
            stampCountLabel = TextView(ctx).apply { text = "Titik QR: 1"; setPadding(0, 0, dp(12), 0) }
            addView(stampCountLabel)
            addView(text("＋ Tambah titik QR") {
                savedStamps.add(ApiClient.StampPlacement(signPageIndex + 1, boxXFrac, boxYFrac, boxWFrac))
                stampCountLabel?.text = "Titik QR: ${savedStamps.size + 1}"
                boxXFrac = (boxXFrac - 0.04).coerceIn(0.0, 0.9)
                boxYFrac = (boxYFrac - 0.04).coerceIn(0.0, 0.9)
                applyBoxFromFracs()
                snack("Titik QR ditambahkan.")
            })
        })

        host.addView(primary("Tanda tangani di sini") {
            pendingSignUri?.let { confirmThenSign(it) }
        })
        placementBuilt = true
    }

    private fun applyBoxFromFracs() {
        val iv = pageView ?: return
        val box = qrBoxView ?: return
        val handle = qrHandleView ?: return
        val dispW = iv.width.toFloat()
        val dispH = iv.height.toFloat()
        if (dispW <= 0f || dispH <= 0f) return
        var w = (boxWFrac * dispW).toFloat().coerceIn(0.10f * dispW, dispW)
        var h = w * STAMP_ASPECT
        if (h > dispH) { h = dispH; w = h / STAMP_ASPECT }
        val lp = box.layoutParams as FrameLayout.LayoutParams
        lp.width = w.roundToInt(); lp.height = h.roundToInt()
        box.layoutParams = lp
        val x = (boxXFrac * dispW).toFloat().coerceIn(0f, dispW - w)
        val y = (boxYFrac * dispH).toFloat().coerceIn(0f, dispH - h)
        box.x = x; box.y = y
        handle.x = x + w - handle.layoutParams.width / 2f
        handle.y = y + h - handle.layoutParams.height / 2f
        boxXFrac = (x / dispW).toDouble()
        boxYFrac = (y / dispH).toDouble()
        boxWFrac = (w / dispW).toDouble()
    }

    private fun wireBoxDrag(box: View, handle: View) {
        var offX = 0f
        var offY = 0f
        box.setOnTouchListener { _, e ->
            val iv = pageView ?: return@setOnTouchListener false
            val dispW = iv.width.toFloat()
            val dispH = iv.height.toFloat()
            when (e.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    box.parent?.requestDisallowInterceptTouchEvent(true) // stop the scroll view stealing the drag
                    offX = e.rawX - box.x; offY = e.rawY - box.y; true
                }
                MotionEvent.ACTION_MOVE -> {
                    val x = (e.rawX - offX).coerceIn(0f, dispW - box.width)
                    val y = (e.rawY - offY).coerceIn(0f, dispH - box.height)
                    box.x = x; box.y = y
                    handle.x = x + box.width - handle.layoutParams.width / 2f
                    handle.y = y + box.height - handle.layoutParams.height / 2f
                    boxXFrac = (x / dispW).toDouble()
                    boxYFrac = (y / dispH).toDouble()
                    true
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    box.parent?.requestDisallowInterceptTouchEvent(false); true
                }
                else -> false
            }
        }
    }

    private fun wireHandleDrag(box: View, handle: View) {
        var downX = 0f
        var startW = 0
        handle.setOnTouchListener { _, e ->
            val iv = pageView ?: return@setOnTouchListener false
            val dispW = iv.width.toFloat()
            val dispH = iv.height.toFloat()
            when (e.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    handle.parent?.requestDisallowInterceptTouchEvent(true)
                    downX = e.rawX; startW = box.width; true
                }
                MotionEvent.ACTION_MOVE -> {
                    var w = (startW + (e.rawX - downX)).coerceIn(0.10f * dispW, dispW - box.x)
                    var h = w * STAMP_ASPECT
                    if (box.y + h > dispH) { h = dispH - box.y; w = h / STAMP_ASPECT }
                    val lp = box.layoutParams as FrameLayout.LayoutParams
                    lp.width = w.roundToInt(); lp.height = h.roundToInt()
                    box.layoutParams = lp
                    handle.x = box.x + w - handle.layoutParams.width / 2f
                    handle.y = box.y + h - handle.layoutParams.height / 2f
                    boxWFrac = (w / dispW).toDouble()
                    true
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    handle.parent?.requestDisallowInterceptTouchEvent(false); true
                }
                else -> false
            }
        }
    }

    private fun confirmThenSign(uri: Uri) {
        val can = BiometricManager.from(this).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        )
        if (can != BiometricManager.BIOMETRIC_SUCCESS) {
            doSign(uri)
            return
        }
        BiometricPrompt(
            this, ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = doSign(uri)
                override fun onAuthenticationError(code: Int, msg: CharSequence) { snack("Dibatalkan: $msg") }
            },
        ).authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Konfirmasi tanda tangan")
                .setSubtitle("Buka kunci untuk memakai kunci perangkat")
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
                .build(),
        )
    }

    private fun doSign(uri: Uri) {
        val sink = signResult ?: return
        val places = savedStamps.toMutableList().apply {
            add(ApiClient.StampPlacement(signPageIndex + 1, boxXFrac, boxYFrac, boxWFrac))
        }
        task {
            val r = core.signPdf(uri, signReason, core.state.accountEmail ?: "", places, signIssuedPlace)
            lastSigned = r.signedPdf
            runOnUiThread {
                sink.removeAllViews()
                sink.addView(
                    verdictCard(
                        true, "Dokumen ditandatangani",
                        listOf(
                            "Status server" to r.serverStatus,
                            "ID verifikasi" to r.publicId,
                            "Tautan / QR" to r.verificationUrl,
                        ),
                        "Tap “Simpan PDF hasil” untuk mengunduh berkasnya.",
                    ),
                )
            }
        }
    }

    private fun runVerify(uri: Uri) {
        val sink = verifyResult ?: return
        val server = pendingVerifyServer
        task {
            val json = if (server != null) core.verifyPublic(server, uri) else core.verifyPdf(uri)
            runOnUiThread { sink.removeAllViews(); sink.addView(verdictFromJson(json)) }
        }
    }

    /** Hash-only check: digest the file on-device and ask the server whether
     *  that is the byte sequence it issued for the id. Nothing of the document
     *  is uploaded. */
    private fun runHashVerify(uri: Uri) {
        val sink = verifyResult ?: return
        val srv = core.state.serverUrl
        val id = pendingHashId
        task {
            val res = core.verifyByHash(srv, id, uri)
            runOnUiThread { sink.removeAllViews(); sink.addView(verdictFromHash(res)) }
        }
    }

    private fun verdictFromHash(res: org.json.JSONObject): View {
        if (!res.optBoolean("match")) {
            return verdictCard(
                false, "TIDAK COCOK", emptyList(),
                "Berkas ini berbeda dari yang diterbitkan server untuk ID tersebut.",
            )
        }
        val rec = res.optJSONObject("record")
        val storedOnly = res.optString("verification_status") == "stored_unverified"
        val rows = mutableListOf("ID verifikasi" to res.optString("public_id"))
        rec?.let {
            rows += listOf(
                "Penanda tangan" to it.optString("signer_name"),
                "Jabatan" to it.optString("position"),
                "NIP" to it.optString("nip"),
                "Perangkat" to it.optString("device_label"),
                "No. sertifikat" to it.optString("certificate_serial"),
                "Waktu (klaim perangkat)" to it.optString("client_claimed_signing_time"),
                "Diterima server" to it.optString("server_received_at"),
            )
        }
        return verdictCard(
            true, "COCOK", rows,
            if (storedOnly)
                "Server tidak pernah memverifikasi tanda tangan berkas ini (terlalu besar saat diserahkan) — kecocokan di atas hanya membuktikan bytenya sama dengan salinan server."
            else
                "Berkas ini byte-identik dengan yang diterbitkan server untuk ID tersebut.",
        )
    }

    /** A scanned QR resolves to the server record for that signature — the
     *  same thing an external scan of the same QR lands on. */
    private fun onQrScanned(text: String) {
        val sink = verifyResult ?: return
        val srv = qrServer.ifBlank { core.state.serverUrl }.trimEnd('/')
        task {
            val json = core.recordFromQr(srv, text)
            runOnUiThread { sink.removeAllViews(); sink.addView(verdictFromRecord(json)) }
        }
    }

    private fun verdictFromRecord(json: String): View {
        val rec = runCatching { org.json.JSONObject(json) }.getOrNull()
            ?: return verdictCard(false, "Hasil tidak terbaca", emptyList())
        val status = rec.optString("certificate_status", "active")
        val ok = status == "active"
        val title = when (status) {
            "revoked" -> "Sertifikat DICABUT — tanda tangan tidak sah"
            "device_reported_lost" -> "Perangkat DILAPORKAN HILANG"
            "not_server_verified" -> "Terdaftar — TIDAK diverifikasi server"
            else -> "Terdaftar & terverifikasi"
        }
        val id = rec.optString("public_id")
        val rows = buildList {
            add("Penanda tangan" to rec.optString("signer_name"))
            add("Perangkat" to rec.optString("device_label"))
            if (status == "not_server_verified")
                add("Status verifikasi" to "hanya disimpan (berkas besar) — SHA-512 dicatat")
            add("No. sertifikat" to rec.optString("certificate_serial"))
            add("Sidik jari sertifikat" to rec.optString("certificate_fingerprint"))
            add("Waktu (klaim perangkat)" to rec.optString("client_claimed_signing_time"))
            add("Diterima server" to rec.optString("server_received_at"))
            add("ID verifikasi" to id)
        }
        val wrap = LinearLayout(themed()).apply { orientation = LinearLayout.VERTICAL }
        wrap.addView(
            verdictCard(
                ok, title, rows,
                rec.optString("note").ifEmpty {
                    "Halaman ini mencocokkan catatan server. Untuk memeriksa keutuhan isi, verifikasi berkas PDF-nya (menu “Pilih PDF”)."
                },
            ),
        )
        // The server no longer serves the stored PDF publicly. Matching the
        // file the user already holds against the recorded SHA-512 is the
        // check that replaces "open the copy from the server".
        return wrap
    }

    // ---------------------------------------------------------------- verdict

    private fun verdictFromJson(json: String): View {
        val top = runCatching { org.json.JSONObject(json) }.getOrNull()
            ?: return verdictCard(false, "Hasil tidak terbaca", emptyList())
        val o = top.optJSONObject("verification") ?: top
        val sigs = o.optJSONArray("signatures")
        if (o.optBoolean("valid") && sigs != null && sigs.length() > 0) {
            val s = sigs.getJSONObject(0)
            val subject = s.optString("subject")
            val name = Regex("CN=([^,]+)").find(subject)?.groupValues?.get(1) ?: "-"
            val org = Regex("O=([^,]+)").find(subject)?.groupValues?.get(1) ?: "-"
            val pid = s.optString("contact").removePrefix("pqc-public-id:")
            val rows = mutableListOf(
                "Penanda tangan" to name,
                "Instansi" to org,
                "Algoritma" to s.optString("algorithm"),
                "Alasan" to s.optString("reason").ifEmpty { "-" },
                "Waktu (klaim perangkat)" to s.optString("client_claimed_signing_time"),
                "No. sertifikat" to s.optString("certificate_serial"),
                "Rantai tepercaya" to if (s.optBoolean("trusted_chain")) "ya" else "TIDAK",
                "Sertifikat dicabut" to if (s.optBoolean("revoked")) "YA" else "tidak",
            )
            val storedOnly = top.optJSONObject("record")?.optString("verification_status") == "stored_unverified"
            if (top.optBoolean("registered"))
                rows += "Terdaftar di server" to if (storedOnly) "ya (disimpan, tidak diverifikasi server)" else "ya"
            if (top.has("hash_match"))
                rows += "Sidik jari cocok dengan catatan server" to
                    if (top.optBoolean("hash_match")) "ya" else "TIDAK — berkas berbeda"
            if (pid.isNotEmpty()) rows += "ID verifikasi" to pid
            return verdictCard(
                true, "Tanda tangan SAH", rows,
                if (storedOnly)
                    "Berkas terlalu besar untuk diverifikasi otomatis oleh server saat diserahkan — server hanya menyimpan salinan & mencatat SHA-512-nya. Pemeriksaan kriptografis di atas dijalankan ulang sekarang atas berkas ini."
                else
                    "Waktu di atas dari jam perangkat penandatangan, bukan stempel waktu tepercaya.",
            )
        }
        val errs = o.optJSONArray("errors") ?: sigs?.optJSONObject(0)?.optJSONArray("errors")
        var detail = (0 until (errs?.length() ?: 0)).joinToString("\n") { "• " + errs!!.optString(it) }
        if (top.has("hash_match") && !top.optBoolean("hash_match")) {
            detail = (detail + "\n• Sidik jari SHA-512 berkas ini tidak cocok dengan catatan server.").trim()
        }
        return verdictCard(
            false, "Tanda tangan TIDAK sah / tidak ditemukan", emptyList(),
            detail.ifEmpty { "Dokumen tidak memuat tanda tangan ML-DSA-65 yang valid." },
        )
    }

    private fun verdictCard(ok: Boolean, title: String, rows: List<Pair<String, String>>, note: String? = null): View =
        card {
            val color = if (ok) 0xFF15803D.toInt() else 0xFFB91C1C.toInt()
            val head = LinearLayout(themed()).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            head.addView(TextView(themed()).apply {
                text = if (ok) "✓" else "✕"
                setTextColor(Color.WHITE); textSize = 16f; gravity = Gravity.CENTER
                val sz = dp(32)
                background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(color) }
                layoutParams = LinearLayout.LayoutParams(sz, sz)
            })
            head.addView(TextView(themed()).apply {
                text = title; setTextColor(color); textSize = 16f; typeface = Typeface.DEFAULT_BOLD
                setPadding(dp(12), 0, 0, 0)
            })
            addView(head)
            rows.forEach { (k, v) ->
                if (v.isBlank()) return@forEach
                val r = LinearLayout(themed()).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(8), 0, 0) }
                r.addView(TextView(themed()).apply {
                    text = k; setTextColor(muted()); textSize = 13f
                    layoutParams = LinearLayout.LayoutParams(dp(132), WRAP_CONTENT)
                })
                r.addView(TextView(themed()).apply {
                    text = v; textSize = 13f; setTextIsSelectable(true)
                    layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
                })
                addView(r)
            }
            note?.let {
                addView(TextView(themed()).apply {
                    text = it; setTextColor(muted()); textSize = 12f; setPadding(0, dp(12), 0, 0)
                })
            }
        }

    // ---------------------------------------------------------------- infra

    private fun task(work: () -> Unit) {
        progress.visibility = View.VISIBLE
        container.isEnabled = false
        thread {
            var err: String? = null
            try { work() } catch (t: Throwable) { err = errText(t) }
            runOnUiThread {
                progress.visibility = View.GONE
                container.isEnabled = true
                err?.let { snack(it) }
            }
        }
    }

    private fun errText(t: Throwable): String {
        val m = t.message ?: t.javaClass.simpleName
        return when {
            m.contains("pending", true) || m.contains("persetujuan", true) -> "Akun belum disetujui admin."
            m.contains("disabled", true) || m.contains("dinonaktifkan", true) -> "Akun dinonaktifkan. Hubungi admin."
            m.contains("invalid credentials", true) -> "Email atau kata sandi salah."
            m.contains("failed to connect", true) || m.contains("Unable to resolve host", true) -> "Tidak bisa terhubung ke server."
            m.contains("sudah memiliki tanda tangan", true) || m.contains("message digest mismatch", true) ||
                m.contains("exactly one signature", true) -> "Dokumen ini sudah ditandatangani. Sistem hanya mendukung satu tanda tangan per dokumen."
            m.contains("device not found", true) || m.contains("no active certificate", true) ->
                "Perangkat belum dikenali server. Tab Akun → “Reset perangkat ini”, lalu masuk lagi."
            else -> m
        }
    }

    private fun snack(s: String) = Snackbar.make(container, s, Snackbar.LENGTH_LONG).show()

    // ---- view builders ----

    private fun themed() = ContextThemeWrapper(this, com.google.android.material.R.style.Theme_Material3_DayNight)

    private inline fun page(build: LinearLayout.() -> Unit) =
        LinearLayout(themed()).apply { orientation = LinearLayout.VERTICAL; build() }

    private inline fun card(build: LinearLayout.() -> Unit): View {
        val inner = LinearLayout(themed()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
            build()
        }
        return MaterialCardView(themed()).apply {
            radius = dpF(16f)
            cardElevation = dpF(0f)
            strokeWidth = dp(1)
            strokeColor = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOutlineVariant, Color.LTGRAY)
            useCompatPadding = false
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(12) }
            addView(inner)
        }
    }

    private fun heading(t: String) = TextView(themed()).apply {
        text = t; textSize = 20f; typeface = Typeface.DEFAULT_BOLD; setTextColor(onSurface())
        setPadding(0, dp(4), 0, dp(4))
    }

    private fun hint(t: String) = TextView(themed()).apply {
        text = t; textSize = 12.5f; setTextColor(muted()); setPadding(dp(2), dp(10), dp(2), 0)
    }

    private fun field(parent: LinearLayout, hint: String, text: String = "", password: Boolean = false): TextInputEditText {
        val til = TextInputLayout(themed()).apply {
            this.hint = hint
            boxBackgroundMode = TextInputLayout.BOX_BACKGROUND_FILLED
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(10) }
        }
        val et = TextInputEditText(til.context).apply {
            setText(text)
            if (password) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        til.addView(et)
        parent.addView(til)
        return et
    }

    private fun mkBtn(label: String, onClick: () -> Unit) = MaterialButton(themed()).apply {
        text = label
        setOnClickListener { onClick() }
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(12) }
    }

    private fun primary(l: String, c: () -> Unit) = mkBtn(l, c)

    private fun tonal(l: String, c: () -> Unit) = mkBtn(l, c).apply {
        setBackgroundColor(MaterialColors.getColor(this, com.google.android.material.R.attr.colorSecondaryContainer, Color.LTGRAY))
        setTextColor(MaterialColors.getColor(this, com.google.android.material.R.attr.colorOnSecondaryContainer, Color.BLACK))
    }

    private fun text(l: String, c: () -> Unit) = mkBtn(l, c).apply {
        setBackgroundColor(Color.TRANSPARENT)
        setTextColor(MaterialColors.getColor(this, com.google.android.material.R.attr.colorPrimary, Color.BLUE))
    }

    private fun danger(l: String, c: () -> Unit) = mkBtn(l, c).apply {
        setBackgroundColor(Color.TRANSPARENT)
        setTextColor(0xFFB91C1C.toInt())
        strokeWidth = dp(1)
        strokeColor = android.content.res.ColorStateList.valueOf(0x55B91C1C)
    }

    private fun bigAction(icon: String, title: String, desc: String, onClick: () -> Unit): View {
        val row = LinearLayout(themed()).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }
        row.addView(TextView(themed()).apply {
            text = icon; textSize = 22f; gravity = Gravity.CENTER
            val sz = dp(44)
            background = GradientDrawable().apply {
                cornerRadius = dpF(12f)
                setColor(MaterialColors.getColor(row, com.google.android.material.R.attr.colorPrimaryContainer, Color.LTGRAY))
            }
            layoutParams = LinearLayout.LayoutParams(sz, sz)
        })
        val txt = LinearLayout(themed()).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(14), 0, 0, 0)
        }
        txt.addView(TextView(themed()).apply { text = title; textSize = 15f; typeface = Typeface.DEFAULT_BOLD; setTextColor(onSurface()) })
        txt.addView(TextView(themed()).apply { text = desc; textSize = 12.5f; setTextColor(muted()) })
        row.addView(txt)
        return MaterialCardView(themed()).apply {
            radius = dpF(16f); cardElevation = dpF(0f); strokeWidth = dp(1)
            strokeColor = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOutlineVariant, Color.LTGRAY)
            isClickable = true; isFocusable = true
            setOnClickListener { onClick() }
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(12) }
            addView(row)
        }
    }

    private fun onSurface() = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOnSurface, Color.BLACK)
    private fun muted() = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOnSurfaceVariant, Color.GRAY)
    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
    private fun dpF(v: Float) = v * resources.displayMetrics.density
}
