package id.example.pqcsign

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.animation.DecelerateInterpolator
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import id.example.pqcsign.net.ApiClient
import id.example.pqcsign.update.AppUpdater
import kotlin.math.roundToInt
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.view.ContextThemeWrapper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
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
import id.example.pqcsign.app.Dn
import id.example.pqcsign.app.AppState
import id.example.pqcsign.ui.BarChartView
import id.example.pqcsign.ui.Glass
import id.example.pqcsign.ui.GlassCard
import id.example.pqcsign.ui.LiquidBackgroundView
import id.example.pqcsign.ui.ScanDocView
import kotlin.concurrent.thread

/**
 * PQC PDF Sign — Android client (Rencana V1 §21). Material 3, built in code:
 * a tab bar over a swappable content area. Pre-login: Masuk / Daftar /
 * Verifikasi (public, no account). Post-login: Beranda / Tanda Tangan /
 * Verifikasi / Akun. All crypto stays in AppCore / the AAR.
 */
private val APP_VERSION = "v" + BuildConfig.VERSION_NAME
private const val MENU_THEME = 1001

class MainActivity : AppCompatActivity() {

    private val appUpdater by lazy { AppUpdater(this) }

    private lateinit var core: AppCore
    private lateinit var toolbar: MaterialToolbar
    private lateinit var tabs: TabLayout
    private lateinit var progress: LinearProgressIndicator
    private lateinit var container: LinearLayout

    private var loggedIn = false
    private var signReason = "Persetujuan"
    private var signIssuedPlace = ""
    private var signLetterNo = ""
    private var signLetterSubject = ""
    private var lastSigned: ByteArray? = null
    private var saveButton: MaterialButton? = null
    private var changeDocButton: MaterialButton? = null

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
        if (uri == null) return@registerForActivityResult
        val size = core.fileSize(uri)
        if (size > AppCore.MAX_SIGN_BYTES) {
            snack("Berkas ${mbText(size)} MB melebihi batas ${AppCore.MAX_SIGN_MB} MB. Kompres atau pecah PDF-nya dulu.")
            return@registerForActivityResult
        }
        changeDocButton?.visibility = View.VISIBLE
        startPlacement(uri)
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
        Glass.applySavedTheme(this)   // must precede super so the right config is inflated
        super.onCreate(savedInstanceState)
        core = AppCore(this, AppState(this))
        buildUi()
        rebuildTabs()
    }

    /** Builds the whole view tree. Called again after a light/dark switch. */
    private fun buildUi() {
        // Liquid Glass: everything above the animated backdrop is transparent.
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.TRANSPARENT)
        }

        val appBar = AppBarLayout(this).apply {
            elevation = 0f
            stateListAnimator = null
            setBackgroundColor(Glass.chrome(this@MainActivity))
        }
        toolbar = MaterialToolbar(this).apply {
            title = "PQC PDF Sign"
            setTitleTextColor(onSurface())
            setBackgroundColor(Color.TRANSPARENT)
            Glass.typeface(context, true)?.let { tf ->
                // MaterialToolbar has no title-typeface setter; reach the TextView
                post {
                    for (i in 0 until childCount) {
                        (getChildAt(i) as? TextView)?.typeface = tf
                    }
                }
            }
            // brand mark, kept across every screen change
            logo = runCatching {
                val src = BitmapFactory.decodeResource(resources, R.drawable.logo_pdfsign)
                BitmapDrawable(resources, Bitmap.createScaledBitmap(src, dp(30), dp(30), true))
            }.getOrNull()

            // Back on every screen that has somewhere to go back to, plus a
            // light/dark switch.
            navigationIcon = ContextCompat.getDrawable(
                this@MainActivity, androidx.appcompat.R.drawable.abc_ic_ab_back_material
            )?.apply { setTint(onSurface()) }
            setNavigationOnClickListener { goBack() }
            menu.add(0, MENU_THEME, 0, "Ganti tema").apply {
                setShowAsAction(android.view.MenuItem.SHOW_AS_ACTION_ALWAYS)
            }
            setOnMenuItemClickListener { item ->
                when (item.itemId) {
                    9007 -> { appUpdater.showAbout(); true }
                    MENU_THEME -> { Glass.toggleTheme(this@MainActivity); true }
                    else -> false
                }
            }
            menu.add(0, 9007, 1, "Tentang")
        }
        tabs = TabLayout(this).apply {
            tabMode = TabLayout.MODE_SCROLLABLE
            tabGravity = TabLayout.GRAVITY_START
            setBackgroundColor(Color.TRANSPARENT)
            setSelectedTabIndicatorColor(Glass.cyan(this@MainActivity))
            setTabTextColors(Glass.textMuted(this@MainActivity), Glass.textPrimary(this@MainActivity))
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
            // generous bottom padding so the last field still clears the
            // keyboard once the window is resized around it
            setPadding(dp(16), dp(16), dp(16), dp(72))
        }
        val scroll = NestedScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(Color.TRANSPARENT)
            clipToPadding = false
            isScrollbarFadingEnabled = true
            addView(container)
        }
        root.addView(scroll, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        // the animated backdrop sits behind the whole UI
        val stack = FrameLayout(this).apply {
            addView(LiquidBackgroundView(this@MainActivity),
                FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
            addView(root, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        }

        // Android 15+ always draws the app behind the system bars, and the
        // keyboard then no longer shrinks the window on its own. Opt in on
        // every version and pad the content by the bars and the keyboard, so
        // the scroll area ends at the top of the keyboard: everything below
        // can still be scrolled to, and the focused field is kept in view.
        // Only `root` is padded - the backdrop keeps drawing edge to edge.
        enableEdgeToEdge()
        setContentView(stack)
        ViewCompat.setOnApplyWindowInsetsListener(stack) { _, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            root.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, ime.bottom))
            insets
        }

        tabs.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) = render(tab.position)
            override fun onTabUnselected(tab: TabLayout.Tab) {}
            override fun onTabReselected(tab: TabLayout.Tab) {}
        })
    }

    /**
     * One Back affordance for the whole app: leave a sub-screen for the first
     * tab, and on the first tab fall through to the system behaviour.
     */
    private fun goBack() {
        val pos = tabs.selectedTabPosition
        if (pos > 0) tabs.getTabAt(0)?.select() else onBackPressedDispatcher.onBackPressed()
    }

    /** Back arrow only where there is somewhere to go; theme icon follows the mode. */
    private fun syncChrome() {
        val canGoBack = tabs.selectedTabPosition > 0
        toolbar.navigationIcon = if (canGoBack)
            ContextCompat.getDrawable(this, androidx.appcompat.R.drawable.abc_ic_ab_back_material)
                ?.apply { setTint(onSurface()) }
        else null
        // sun while dark (tap -> light), moon while light (tap -> dark)
        toolbar.menu.findItem(MENU_THEME)?.icon =
            ContextCompat.getDrawable(
                this,
                if (Glass.isDark(this)) R.drawable.ic_sun else R.drawable.ic_moon,
            )?.apply { setTint(onSurface()) }
        toolbar.menu.findItem(MENU_THEME)?.title =
            if (Glass.isDark(this)) "Tema terang" else "Tema gelap"
    }

    // uiMode is in configChanges, so the light/dark switch rebuilds the view
    // tree in place instead of recreating the activity - the in-memory session
    // (and the tab the user was on) survives.
    override fun onConfigurationChanged(newConfig: android.content.res.Configuration) {
        super.onConfigurationChanged(newConfig)
        val pos = if (::tabs.isInitialized) tabs.selectedTabPosition else 0
        buildUi()
        rebuildTabs()
        if (pos > 0) tabs.getTabAt(pos)?.select()
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
        signResult = null; verifyResult = null; saveButton = null; changeDocButton = null
        val v = if (loggedIn) when (pos) {
            0 -> screenHome(); 1 -> screenSign(); 2 -> screenVerify(); else -> screenAccount()
        } else when (pos) {
            0 -> screenLogin(); 1 -> screenRegister(); else -> screenVerifyPublic()
        }
        container.removeAllViews()
        container.addView(v)
        syncChrome()

        // Smooth page transition, then the children reveal one by one.
        container.animate().cancel()
        container.alpha = 0f
        container.translationY = dpF(12f)
        container.animate()
            .alpha(1f).translationY(0f)
            .setDuration(260L)
            .setInterpolator(DecelerateInterpolator(1.5f))
            .start()
        (v as? LinearLayout)?.let { Glass.staggerReveal(it, 70L) }
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
                    ui {
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
                    ui { snack(r.message.ifEmpty { "Akun dibuat (${r.status})" }) }
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
                ui {
                    status.text = when (cs.state) {
                        "active" -> "Sertifikat aktif — siap menandatangani."
                        "pending" -> "Sertifikat belum terbit. Coba lagi sebentar."
                        else -> "Status sertifikat: ${cs.state}"
                    }
                }
            }
        })
        // ---- dashboard figures -------------------------------------------
        addView(statRow())
        addView(sectionTitle("Aktivitas 6 bulan terakhir"))
        val chart = BarChartView(themed())
        addView(card { addView(chart) })
        loadStats(chart)

        // ---- the two real actions ----------------------------------------
        addView(sectionTitle("Aksi"))
        addView(bigAction(R.drawable.logo_signing, "Tanda Tangani Dokumen",
            "Pilih PDF, tandatangani di perangkat ini") {
            tabs.getTabAt(1)?.select()
        })
        addView(bigAction(R.drawable.logo_qrverify, "Verifikasi Dokumen",
            "Periksa keaslian sebuah PDF bertanda tangan") {
            tabs.getTabAt(2)?.select()
        })

        // ---- Root CA is narrative, not a peer of the two actions ----------
        addView(sectionTitle("Rantai kepercayaan"))
        addView(trustNarrative())

        addView(sectionTitle("Tentang fitur"))
        addView(explainer("Tanda Tangani Dokumen",
            "Memberi tanda tangan digital pada PDF di perangkat Anda. Kunci privat tidak pernah dikirim ke server.\n\n" +
            "• Memilih dokumen PDF yang akan ditandatangani.\n" +
            "• Menandatangani di perangkat, lalu menghasilkan PDF bertanda tangan.\n" +
            "• Menyertakan QR agar penerima mudah memvalidasi.\n\n" +
            "Tanda tangan digital di sini bukan sekadar gambar, melainkan mekanisme kriptografis yang membuktikan " +
            "dokumen berasal dari perangkat bersertifikat dan isinya tidak berubah setelah ditandatangani."))
        addView(explainer("Verifikasi Dokumen",
            "Memeriksa keaslian dan keutuhan PDF yang sudah ditandatangani. Verifikasi menjawab:\n\n" +
            "• Apakah dokumen benar-benar punya tanda tangan digital?\n" +
            "• Apakah tanda tangan itu masih valid?\n" +
            "• Apakah dokumen berubah setelah ditandatangani?\n" +
            "• Apakah rantai sertifikat berakhir pada Root CA yang dipercaya?\n\n" +
            "Hasilnya bisa berupa Valid, Dokumen Berubah, Sertifikat Tidak Dipercaya, atau Tanda Tangan Tidak Valid."))
        addView(explainer("Root CA Trusted",
            "CA (Certificate Authority) adalah pihak yang menerbitkan sertifikat digital. Di puncaknya ada Root CA " +
            "sebagai titik kepercayaan utama (trust anchor).\n\n" +
            "• Menjadi acuan tunggal saat memeriksa sertifikat.\n" +
            "• Memisahkan sertifikat yang ada di dalam PDF dari sertifikat yang benar-benar dipercaya sistem.\n" +
            "• Mengurangi risiko menerima sertifikat yang dibuat sendiri.\n\n" +
            "Identitas Root CA ditampilkan sebagai fingerprint sehingga bisa dibandingkan dengan yang seharusnya."))
    }

    private fun screenSign(): View = page {
        addView(heading("Tanda tangani dokumen"))
        addView(card {
            val letterNo = field(this, "Nomor surat", signLetterNo)
            val subject = field(this, "Perihal surat", signLetterSubject)
            val reason = field(this, "Alasan penandatanganan", signReason.ifEmpty { "Persetujuan" })
            val place = field(this, "Dikeluarkan di (kota)", signIssuedPlace)
            fun captureForm() {
                signLetterNo = letterNo.text.toString().trim()
                signLetterSubject = subject.text.toString().trim()
                signReason = reason.text.toString().trim().ifEmpty { "Persetujuan" }
                signIssuedPlace = place.text.toString().trim()
            }
            addView(primary("Pilih PDF") {
                captureForm()
                pickToSign.launch(arrayOf("application/pdf"))
            })
            // Offered only once a document is loaded, so the signer can swap it
            // without leaving the screen.
            changeDocButton = tonal("Ganti dokumen") {
                captureForm()
                clearSignedState()
                pickToSign.launch(arrayOf("application/pdf"))
            }.apply { visibility = if (pendingSignUri == null) View.GONE else View.VISIBLE }
            addView(changeDocButton)
            addView(hint("QR “TTD Elektronik” ditempel di titik yang Anda pilih pada dokumen."))
            addView(hint("Ukuran maksimal ${AppCore.MAX_SIGN_MB} MB per dokumen."))
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
        // The fingerprint match is no longer a separate form: verifying a
        // document runs it automatically (the reservation id comes from the
        // signature) and the verdict reports the outcome. The file is still
        // never uploaded - only its SHA-512 goes to the server.
        addView(hint("Sidik jari SHA-512 berkas otomatis dicocokkan dengan catatan server, " +
            "dan hasilnya ditampilkan di bawah. Berkasnya sendiri tidak diunggah."))
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
                ui { status.text = "Sertifikat: ${cs.state}" + (cs.serial?.let { "  ·  $it" } ?: "") }
            }
        })
        addView(card {
            addView(tonal("Laporkan perangkat hilang") {
                task { core.reportLost(); ui { snack("Dilaporkan ke server.") } }
            })
            addView(danger("Reset perangkat ini") {
                task { core.reset(); ui { snack("Kunci & sertifikat lokal dihapus.") } }
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
            ui {
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

        // Same pair as the desktop client: sign, or swap the file. Saving has
        // its own button under the result, so neither of these promises it.
        host.addView(LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(primary("Tanda tangani dokumen") {
                pendingSignUri?.let { confirmThenSign(it) }
            }.apply {
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { rightMargin = dp(8) }
            })
            addView(tonal("Ganti berkas") {
                clearSignedState()
                pickToSign.launch(arrayOf("application/pdf"))
            }.apply {
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
            })
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
        val prog = progressCard("Memulai…")
        sink.removeAllViews()
        sink.addView(prog.view)
        task {
            try {
                val r = core.signPdf(
                    uri, signReason, core.state.accountEmail ?: "", places,
                    signIssuedPlace, signLetterNo, signLetterSubject,
                ) { step, label, pct ->
                    ui { prog.update(step, AppCore.SIGN_STEPS, label, pct) }
                }
                lastSigned = r.signedPdf
                ui {
                    prog.stop()
                    sink.removeAllViews()
                    sink.addView(signResultView(r))
                    sink.addView(signedActions())
                    snack(if (r.submitted) "Berhasil ditandatangani & tercatat di server." else "Tersimpan di perangkat, tapi pengiriman ke server GAGAL.")
                }
            } catch (t: Throwable) {
                ui {
                    prog.stop()
                    sink.removeAllViews()
                    sink.addView(verdictCard(false, "Gagal menandatangani", emptyList(),
                        errText(t) + "\n\nDokumen belum ditandatangani. Anda bisa langsung mencoba lagi."))
                }
            }
        }
    }

    /**
     * The actions that only make sense once a document has been signed. They
     * live under the result, so clearing signResult (a new run, or leaving the
     * tab) takes them away with it.
     */
    private fun signedActions(): View {
        val row = LinearLayout(themed()).apply {
            orientation = LinearLayout.VERTICAL
            alpha = 0f
            translationY = dpF(10f)
            animate().alpha(1f).translationY(0f).setStartDelay(120L).setDuration(320L).start()
        }
        saveButton = primary("Simpan PDF hasil") {
            if (lastSigned == null) snack("Belum ada hasil") else saveSigned.launch("dokumen-bertandatangan.pdf")
        }
        row.addView(saveButton)
        row.addView(tonal("Ganti dokumen") {
            clearSignedState()
            pickToSign.launch(arrayOf("application/pdf"))
        })
        return row
    }

    /** Drop the finished document so the next run starts clean. */
    private fun clearSignedState() {
        lastSigned = null
        savedStamps.clear()
        placementBuilt = false
        placementHost?.removeAllViews()
        signResult?.removeAllViews()
        stampCountLabel?.text = "1"
    }

    /** The outcome of a signature. A PDF that was signed but never reached the
     *  server gets a warning and a resend button — its QR points at nothing yet. */
    private fun signResultView(r: AppCore.SignResult): View {
        if (r.submitted) {
            return verdictCard(
                true, "Berhasil — ditandatangani & tercatat di server",
                listOf(
                    "Status" to serverStatusText(r.serverStatus),
                    "ID verifikasi" to r.publicId,
                    "Tautan / QR" to r.verificationUrl,
                ),
                "Tap “Simpan PDF hasil” untuk mengunduh berkasnya.",
            )
        }
        return LinearLayout(themed()).apply {
            orientation = LinearLayout.VERTICAL
            addView(verdictCard(
                false, "Ditandatangani, tapi BELUM tercatat di server",
                listOf("Penyebab" to errText(Exception(r.submitError)), "ID verifikasi" to r.publicId),
                "PDF sudah ditandatangani, tetapi pengiriman ke server gagal sehingga QR-nya belum bisa diverifikasi. " +
                    "Tap “Kirim ulang ke server” (paling lambat 2 jam setelah penandatanganan).\n\nDetail teknis: ${r.submitError}",
                warn = true,
            ))
            addView(primary("Kirim ulang ke server") { retrySubmit(r) })
        }
    }

    private fun retrySubmit(r: AppCore.SignResult) {
        val sink = signResult ?: return
        val prog = progressCard("Mengirim ulang ke server…")
        sink.removeAllViews()
        sink.addView(prog.view)
        task {
            try {
                val status = core.retrySubmit(r.publicId, r.signedPdf) { step, label, pct ->
                    ui { prog.update(step, AppCore.SIGN_STEPS, label, pct) }
                }
                ui {
                    prog.stop()
                    sink.removeAllViews()
                    sink.addView(signResultView(r.copy(submitted = true, serverStatus = status, submitError = "")))
                    sink.addView(signedActions())
                    snack("Berhasil tercatat di server.")
                }
            } catch (t: Throwable) {
                ui {
                    prog.stop()
                    sink.removeAllViews()
                    sink.addView(signResultView(r.copy(submitError = t.message ?: t.javaClass.simpleName)))
                    snack("Masih gagal: " + errText(t))
                }
            }
        }
    }

    private fun serverStatusText(s: String): String = when (s) {
        "accepted" -> "Tercatat & diverifikasi server"
        "", "submitted" -> "Tercatat di server"
        else -> s
    }

    private fun mbText(bytes: Long): String = String.format(java.util.Locale("id"), "%.1f", bytes / 1048576.0)

    /** Step, percentage and elapsed time of a running signature — a long
     *  upload on a slow link looks frozen without it. */
    private class SignProgress(val view: View, val step: TextView, val meta: TextView, val bar: LinearProgressIndicator) {
        val started = System.currentTimeMillis()
        var ticker: Runnable? = null
    }

    private fun progressCard(title: String): SignProgress {
        val step = TextView(themed()).apply {
            text = title; textSize = 15f; typeface = Typeface.DEFAULT_BOLD; setTextColor(onSurface())
        }
        val meta = TextView(themed()).apply { textSize = 12.5f; setTextColor(muted()); setPadding(0, dp(4), 0, 0) }
        val bar = LinearProgressIndicator(themed()).apply {
            max = 100
            setProgressCompat(2, false)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(10) }
        }
        val p = SignProgress(card { addView(step); addView(meta); addView(bar) }, step, meta, bar)
        val tick = object : Runnable {
            override fun run() {
                val s = (System.currentTimeMillis() - p.started) / 1000
                val elapsed = if (s < 60) "$s detik" else "${s / 60} menit ${s % 60} detik"
                meta.text = "Sudah berjalan $elapsed. Jangan tutup aplikasi." +
                    if (s > 60) " Koneksi tampaknya lambat — proses tetap berjalan." else ""
                meta.postDelayed(this, 1000)
            }
        }
        p.ticker = tick
        tick.run()
        return p
    }

    private fun SignProgress.update(n: Int, total: Int, label: String, pct: Int) {
        step.text = "Langkah $n dari $total: $label" + if (pct >= 0) " — $pct%" else "…"
        val within = if (pct >= 0) pct else 50
        bar.setProgressCompat(maxOf(2, ((n - 1) * 100 + within) / total), true)
    }

    private fun SignProgress.stop() {
        ticker?.let { meta.removeCallbacks(it) }
    }

    private fun runVerify(uri: Uri) {
        val sink = verifyResult ?: return
        val server = pendingVerifyServer
        showScanning(sink, "Memeriksa dokumen…")
        task {
            val json = if (server != null) core.verifyPublic(server, uri) else core.verifyPdf(uri)
            Glass.bumpVerifyCount(this)   // device-local tally for the dashboard
            ui { sink.removeAllViews(); sink.addView(verdictFromJson(json)) }
        }
    }

    /** Inline "document being scanned" loader, replaced by the verdict. */
    private fun showScanning(sink: LinearLayout, label: String) {
        val row = LinearLayout(themed()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }
        row.addView(ScanDocView(themed()))
        val col = LinearLayout(themed()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), 0, 0, 0)
            layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
        }
        col.addView(TextView(themed()).apply {
            text = label; textSize = 12.5f
            typeface = Glass.typeface(context, true)
            setTextColor(muted())
        })
        col.addView(LinearProgressIndicator(themed()).apply {
            isIndeterminate = true
            trackCornerRadius = dp(3)
            setIndicatorColor(Glass.accent(context), Glass.cyan(context), Glass.violet(context))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(9) }
        })
        row.addView(col)
        val cardView = GlassCard(themed()).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(12) }
            addView(row)
            alpha = 0f
            animate().alpha(1f).setDuration(240L).start()
        }
        sink.removeAllViews()
        sink.addView(cardView)
    }

    /** Hash-only check: digest the file on-device and ask the server whether
     *  that is the byte sequence it issued for the id. Nothing of the document
     *  is uploaded. */
    private fun runHashVerify(uri: Uri) {
        val sink = verifyResult ?: return
        val srv = core.state.serverUrl
        val id = pendingHashId
        showScanning(sink, "Menghitung sidik jari & mencocokkan…")
        task {
            val res = core.verifyByHash(srv, id, uri)
            ui { sink.removeAllViews(); sink.addView(verdictFromHash(res)) }
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
                "Nomor surat" to it.optString("letter_no"),
                "Perihal surat" to it.optString("letter_subject"),
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
            ui { sink.removeAllViews(); sink.addView(verdictFromRecord(json)) }
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
            add("Nomor surat" to rec.optString("letter_no"))
            add("Perihal surat" to rec.optString("letter_subject"))
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

    /**
     * The automatic fingerprint check AppCore folds into a local verification
     * result. Nothing is typed in and the document is never uploaded - only
     * its SHA-512 goes to the server.
     */
    private fun hashCheckRow(o: org.json.JSONObject): Pair<String, String>? {
        val hc = o.optJSONObject("hash_check") ?: return null
        val k = "Sidik jari vs catatan server"
        if (!hc.optBoolean("checked")) {
            return k to ("tidak diperiksa — " + hc.optString("reason").ifEmpty { "tidak diketahui" })
        }
        return k to if (hc.optBoolean("match")) "COCOK — byte-identik dengan yang diterbitkan server"
                    else "TIDAK COCOK — berkas berbeda dari yang diterbitkan server"
    }

    private fun dnPart(subject: String, key: String): String = Dn.part(subject, key)

    private fun verdictFromJson(json: String): View {
        val top = runCatching { org.json.JSONObject(json) }.getOrNull()
            ?: return verdictCard(false, "Hasil tidak terbaca", emptyList())
        val o = top.optJSONObject("verification") ?: top
        val sigs = o.optJSONArray("signatures")
        if (o.optBoolean("valid") && sigs != null && sigs.length() > 0) {
            val s = sigs.getJSONObject(0)
            val subject = s.optString("subject")
            val name = dnPart(subject, "CN").ifEmpty { "-" }
            val org = dnPart(subject, "O").ifEmpty { "-" }
            val pid = s.optString("contact").removePrefix("pqc-public-id:")
            // The letter number and subject come from the server record: public
            // verify returns it directly, a local verify folds the same record
            // into the automatic fingerprint check.
            val letter = top.optJSONObject("record")
                ?: o.optJSONObject("hash_check")?.optJSONObject("record")
            val rows = mutableListOf(
                "Penanda tangan" to name,
                "Instansi" to org,
                "Nomor surat" to (letter?.optString("letter_no") ?: ""),
                "Perihal surat" to (letter?.optString("letter_subject") ?: ""),
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
            hashCheckRow(o)?.let { rows += it }
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

    private fun verdictCard(ok: Boolean, title: String, rows: List<Pair<String, String>>, note: String? = null, warn: Boolean = false): View =
        card {
            val color = when {
                ok -> 0xFF15803D.toInt()
                warn -> 0xFFB45309.toInt()
                else -> 0xFFB91C1C.toInt()
            }
            val head = LinearLayout(themed()).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            head.addView(TextView(themed()).apply {
                text = when {
                    ok -> "✓"
                    warn -> "!"
                    else -> "✕"
                }
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

    /**
     * runOnUiThread with the safety net task() gives the background half.
     * task()'s try/catch only wraps the worker; whatever it posts runs later
     * on the main looper, so a slip in a result builder killed the app instead
     * of reporting itself. Rendering a verdict must never be fatal.
     */
    private fun ui(block: () -> Unit) = runOnUiThread {
        try {
            block()
        } catch (t: Throwable) {
            snack("Gagal menampilkan hasil: " + errText(t))
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
            m.contains("timeout", true) || m.contains("timed out", true) || m.contains("Connection reset", true) ||
                m.contains("Broken pipe", true) || m.contains("unexpected end of stream", true) ||
                m.contains("connection abort", true) ->
                "Koneksi ke server terputus atau terlalu lambat. Periksa internet Anda, lalu coba lagi."
            m.contains("melebihi batas", true) -> "$m. Kompres atau pecah PDF-nya dulu."
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
            setPadding(dp(18), dp(18), dp(18), dp(18))
            build()
        }
        wireImeSubmit(inner)
        return GlassCard(themed()).apply {
            useCompatPadding = false
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(12) }
            addView(inner)
        }
    }

    /**
     * Keyboard "Go"/Enter runs the card's primary action, matching the desktop
     * client. The last field gets Done, the others Next, so the keyboard walks
     * the form and submits at the end.
     */
    private fun wireImeSubmit(root: LinearLayout) {
        val fields = mutableListOf<TextInputEditText>()
        val buttons = mutableListOf<MaterialButton>()
        fun walk(v: View) {
            when (v) {
                is TextInputEditText -> fields.add(v)
                is MaterialButton -> buttons.add(v)
                is android.view.ViewGroup -> for (i in 0 until v.childCount) walk(v.getChildAt(i))
            }
        }
        walk(root)
        val primary = buttons.firstOrNull() ?: return
        fields.forEachIndexed { i, f ->
            val last = i == fields.lastIndex
            f.imeOptions = if (last) android.view.inputmethod.EditorInfo.IME_ACTION_DONE
                           else android.view.inputmethod.EditorInfo.IME_ACTION_NEXT
            // NOT setSingleLine(): that installs SingleLineTransformationMethod
            // and so removes the password masking. maxLines keeps one line
            // without touching the transformation.
            f.maxLines = 1
            if (last) {
                f.setOnEditorActionListener { _, actionId, event ->
                    val enter = actionId == android.view.inputmethod.EditorInfo.IME_ACTION_DONE ||
                        actionId == android.view.inputmethod.EditorInfo.IME_ACTION_GO ||
                        (event != null && event.keyCode == android.view.KeyEvent.KEYCODE_ENTER &&
                            event.action == android.view.KeyEvent.ACTION_DOWN)
                    if (enter && primary.isEnabled) {
                        hideKeyboard(f)
                        primary.performClick()
                        true
                    } else false
                }
            }
        }
    }

    private fun hideKeyboard(v: View) {
        (getSystemService(android.content.Context.INPUT_METHOD_SERVICE)
            as? android.view.inputmethod.InputMethodManager)
            ?.hideSoftInputFromWindow(v.windowToken, 0)
    }

    private fun heading(t: String) = TextView(themed()).apply {
        text = t; textSize = 23f
        typeface = Glass.typeface(context, true) ?: Typeface.DEFAULT_BOLD
        setTextColor(Glass.textPrimary(context))
        letterSpacing = -0.02f
        setPadding(0, dp(6), 0, dp(4))
    }

    private fun hint(t: String) = TextView(themed()).apply {
        text = t; textSize = 12.5f
        typeface = Glass.typeface(context, false)
        setTextColor(muted()); setPadding(dp(2), dp(10), dp(2), 0)
    }

    private fun field(parent: LinearLayout, hint: String, text: String = "", password: Boolean = false): TextInputEditText {
        // Pill-shaped, matching the desktop client. The outlined style has to
        // come from the constructor context: setting boxBackgroundMode alone
        // leaves the floating label without its cutout.
        val outlined = ContextThemeWrapper(
            this, com.google.android.material.R.style.Widget_Material3_TextInputLayout_OutlinedBox,
        )
        val til = TextInputLayout(outlined).apply {
            this.hint = hint
            boxBackgroundMode = TextInputLayout.BOX_BACKGROUND_OUTLINE
            val r = dpF(26f)                       // half the field height -> pill
            setBoxCornerRadii(r, r, r, r)
            boxBackgroundColor = Glass.cardFill(context)
            setBoxStrokeColorStateList(
                android.content.res.ColorStateList(
                    arrayOf(intArrayOf(android.R.attr.state_focused), intArrayOf()),
                    intArrayOf(Glass.accent(context), Glass.cardStroke(context)),
                ),
            )
            hintTextColor = android.content.res.ColorStateList.valueOf(Glass.textMuted(context))
            if (password) {
                // masked by default, with an eye to reveal it
                endIconMode = TextInputLayout.END_ICON_PASSWORD_TOGGLE
                setEndIconTintList(android.content.res.ColorStateList.valueOf(Glass.textMuted(context)))
            }
            setPadding(0, 0, 0, 0)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(11) }
        }
        val et = TextInputEditText(til.context).apply {
            setText(text)
            // setInputType switches password boxes to monospace, so the face
            // is applied after it
            if (password) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            typeface = Glass.typeface(context, false) ?: Typeface.DEFAULT
            setTextColor(Glass.textPrimary(context))
            // the rounded outline needs breathing room at the ends
            setPadding(dp(20), dp(17), if (password) dp(8) else dp(20), dp(17))
        }
        til.addView(et)
        // hidden by default; the eye icon at the end shows / hides the text
        if (password) til.endIconMode = TextInputLayout.END_ICON_PASSWORD_TOGGLE
        parent.addView(til)
        return et
    }

    private fun mkBtn(label: String, onClick: () -> Unit) = MaterialButton(themed()).apply {
        text = label
        typeface = Glass.typeface(context, true)
        setOnClickListener { onClick() }
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(12) }
        Glass.springPress(this)   // microinteraction; does not consume the click
    }

    /** Primary CTA: the palette's signature blue -> cyan -> violet gradient. */
    private fun primary(l: String, c: () -> Unit) = mkBtn(l, c).apply {
        // MaterialButton logs that it manages its own background; a custom one
        // is still honoured, and springPress supplies the press feedback.
        background = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(Glass.accent(context), Glass.cyan(context), Glass.violet(context))
        ).apply { cornerRadius = dpF(14f) }
        setTextColor(Color.WHITE)
    }

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

    /**
     * Headline action card: brand logo tile + title, on a glass card with the
     * rotating border gradient reserved for important elements.
     * [iconRes] resolves per theme via drawable-nodpi / drawable-night-nodpi.
     */
    private fun bigAction(iconRes: Int, title: String, desc: String, onClick: () -> Unit): View {
        val row = LinearLayout(themed()).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }
        row.addView(ImageView(themed()).apply {
            setImageResource(iconRes)
            val sz = dp(54)
            background = GradientDrawable().apply {
                cornerRadius = dpF(15f)
                setColor(Glass.cardFill(context))
                setStroke(dp(1), Glass.cardStroke(context))
            }
            setPadding(dp(5), dp(5), dp(5), dp(5))
            layoutParams = LinearLayout.LayoutParams(sz, sz)
        })
        val txt = LinearLayout(themed()).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(15), 0, 0, 0)
        }
        txt.addView(TextView(themed()).apply {
            text = title; textSize = 15.5f; typeface = Typeface.DEFAULT_BOLD
            setTextColor(Glass.textPrimary(context))
        })
        txt.addView(TextView(themed()).apply {
            text = desc; textSize = 12.5f; setTextColor(muted())
        })
        row.addView(txt)
        return GlassCard(themed(), glow = true).apply {
            isClickable = true; isFocusable = true
            setOnClickListener { onClick() }
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(12) }
            addView(row)
        }
    }

    // ---- dashboard builders ----

    private fun sectionTitle(t: String) = TextView(themed()).apply {
        text = t; textSize = 13.5f
        typeface = Glass.typeface(context, true)
        setTextColor(Glass.textPrimary(context))
        letterSpacing = 0.01f
        setPadding(dp(2), dp(20), 0, dp(2))
    }

    private val statValues = mutableListOf<TextView>()

    private fun statRow(): View {
        statValues.clear()
        val row = LinearLayout(themed()).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(12) }
        }
        val specs = listOf(
            Triple("DITANDATANGANI", "0", "dokumen"),
            Triple("BULAN INI", "0", "dokumen"),
            Triple("DIVERIFIKASI", "0", "perangkat ini"),
        )
        specs.forEachIndexed { i, (k, v, u) ->
            val tile = GlassCard(themed()).apply {
                radius = Glass.dp(context, 15f)
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply {
                    if (i > 0) leftMargin = dp(9)
                }
            }
            val col = LinearLayout(themed()).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(12), dp(12), dp(12), dp(12))
            }
            col.addView(TextView(themed()).apply {
                text = k; textSize = 9.5f; letterSpacing = 0.05f
                typeface = Glass.typeface(context, true)
                setTextColor(Glass.textMuted(context))
            })
            val value = TextView(themed()).apply {
                text = v; textSize = 24f
                typeface = Glass.typeface(context, true)
                setTextColor(Glass.accent(context))
                setPadding(0, dp(3), 0, 0)
            }
            statValues.add(value)
            col.addView(value)
            col.addView(TextView(themed()).apply {
                text = u; textSize = 10.5f
                typeface = Glass.typeface(context, false)
                setTextColor(Glass.textMuted(context))
            })
            tile.addView(col)
            row.addView(tile)
        }
        return row
    }

    /** Fills the tiles and the chart from the account's real signature list. */
    private fun loadStats(chart: BarChartView) {
        val months = listOf("Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des")
        thread {
            var total = 0
            var thisMonth = 0
            val buckets = IntArray(6)
            val labels = ArrayList<String>(6)
            val now = java.util.Calendar.getInstance()
            val keys = ArrayList<String>(6)
            for (i in 5 downTo 0) {
                val c = java.util.Calendar.getInstance()
                c.add(java.util.Calendar.MONTH, -i)
                labels.add(months[c.get(java.util.Calendar.MONTH)])
                keys.add("${c.get(java.util.Calendar.YEAR)}-${c.get(java.util.Calendar.MONTH)}")
            }
            val nowKey = "${now.get(java.util.Calendar.YEAR)}-${now.get(java.util.Calendar.MONTH)}"
            try {
                val list = core.history()
                total = list.size
                // server serialises store.Signature without json tags -> Go field names
                for (item in list) {
                    val ts = item.optString("CreatedAt", item.optString("created_at", ""))
                    if (ts.isEmpty()) continue
                    val d = parseTs(ts) ?: continue
                    val c = java.util.Calendar.getInstance().apply { time = d }
                    val k = "${c.get(java.util.Calendar.YEAR)}-${c.get(java.util.Calendar.MONTH)}"
                    val idx = keys.indexOf(k)
                    if (idx >= 0) buckets[idx]++
                    if (k == nowKey) thisMonth++
                }
            } catch (_: Throwable) { /* offline or not enrolled yet - show zeros */ }
            val t = total; val m = thisMonth
            ui {
                if (statValues.size >= 3) {
                    Glass.countUp(statValues[0], t)
                    Glass.countUp(statValues[1], m)
                    Glass.countUp(statValues[2], Glass.verifyCount(this))
                }
                chart.setData(labels, buckets.toList())
            }
        }
    }

    /** RFC3339 timestamps as Go emits them, with or without fractional seconds. */
    private fun parseTs(s: String): java.util.Date? {
        val cleaned = s.replace("Z", "+0000").replace(Regex("([+-]\\d{2}):(\\d{2})$"), "$1$2")
        for (p in listOf("yyyy-MM-dd'T'HH:mm:ss.SSSZ", "yyyy-MM-dd'T'HH:mm:ssZ")) {
            try {
                return java.text.SimpleDateFormat(p, java.util.Locale.US).parse(cleaned)
            } catch (_: Throwable) { /* try the next pattern */ }
        }
        return null
    }

    private fun trustNarrative(): View {
        val outer = LinearLayout(themed()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }
        val head = LinearLayout(themed()).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
        }
        head.addView(ImageView(themed()).apply {
            setImageResource(R.drawable.logo_catrusted)
            layoutParams = LinearLayout.LayoutParams(dp(44), dp(44))
        })
        val ht = LinearLayout(themed()).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(13), 0, 0, 0)
        }
        ht.addView(TextView(themed()).apply {
            text = "Root CA Trusted — dasar kepercayaan"
            textSize = 13.5f; typeface = Glass.typeface(context, true)
            setTextColor(Glass.textPrimary(context))
        })
        head.addView(ht)
        outer.addView(head)
        outer.addView(TextView(themed()).apply {
            text = "Setiap verifikasi menelusuri rantai sertifikat sampai ke Root CA eksplisit yang " +
                   "dikonfigurasi aplikasi — bukan sertifikat yang kebetulan menempel di dalam PDF. " +
                   "Sertifikat yang dibuat sendiri karena itu tidak otomatis dipercaya."
            textSize = 12.5f; typeface = Glass.typeface(context, false)
            setTextColor(muted()); setPadding(0, dp(10), 0, dp(4))
        })
        // the chain, as stacked nodes
        listOf(
            "Root CA Trusted" to "trust anchor",
            "Intermediate CA" to "penerbit",
            "Sertifikat Penandatangan" to "perangkat ini",
            "Dokumen PDF Bertanda Tangan" to "hasil",
        ).forEachIndexed { i, (name, role) ->
            val node = LinearLayout(themed()).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(dp(12), dp(9), dp(12), dp(9))
                background = GradientDrawable().apply {
                    cornerRadius = dpF(11f)
                    setColor(Glass.cardFill(context))
                    setStroke(dp(1), Glass.cardStroke(context))
                }
                layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                    topMargin = if (i == 0) dp(10) else dp(6)
                }
                alpha = 0f
                animate().alpha(1f).setStartDelay(120L + i * 70L).setDuration(360L).start()
            }
            node.addView(View(themed()).apply {
                background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(Glass.cyan(context)) }
                layoutParams = LinearLayout.LayoutParams(dp(8), dp(8)).apply { rightMargin = dp(10) }
            })
            node.addView(TextView(themed()).apply {
                text = name; textSize = 12.5f
                typeface = Glass.typeface(context, true)
                setTextColor(Glass.textPrimary(context))
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
            })
            node.addView(TextView(themed()).apply {
                text = role; textSize = 11f
                typeface = Glass.typeface(context, false)
                setTextColor(Glass.textMuted(context))
            })
            outer.addView(node)
        }
        return GlassCard(themed()).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(12) }
            addView(outer)
        }
    }

    /** Collapsible explanation block. */
    private fun explainer(title: String, body: String): View {
        val wrap = LinearLayout(themed()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(15), dp(13), dp(15), dp(13))
        }
        val chevron = TextView(themed()).apply {
            text = "›"; textSize = 17f
            typeface = Glass.typeface(context, true)
            setTextColor(Glass.textMuted(context))
        }
        val head = LinearLayout(themed()).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
        }
        head.addView(TextView(themed()).apply {
            text = title; textSize = 13.5f
            typeface = Glass.typeface(context, true)
            setTextColor(Glass.textPrimary(context))
            layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
        })
        head.addView(chevron)
        val bodyView = TextView(themed()).apply {
            text = body; textSize = 12.5f
            typeface = Glass.typeface(context, false)
            setTextColor(muted())
            setPadding(0, dp(10), 0, 0)
            visibility = View.GONE
        }
        wrap.addView(head)
        wrap.addView(bodyView)
        return GlassCard(themed()).apply {
            isClickable = true; isFocusable = true
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(9) }
            addView(wrap)
            setOnClickListener {
                val opening = bodyView.visibility != View.VISIBLE
                bodyView.visibility = if (opening) View.VISIBLE else View.GONE
                if (opening) {
                    bodyView.alpha = 0f; bodyView.translationY = -Glass.dp(context, 8f)
                    bodyView.animate().alpha(1f).translationY(0f).setDuration(280L).start()
                }
                chevron.animate().rotation(if (opening) 90f else 0f).setDuration(280L).start()
            }
        }
    }

    private fun onSurface() = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOnSurface, Color.BLACK)
    private fun muted() = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOnSurfaceVariant, Color.GRAY)
    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
    private fun dpF(v: Float) = v * resources.displayMetrics.density
}
