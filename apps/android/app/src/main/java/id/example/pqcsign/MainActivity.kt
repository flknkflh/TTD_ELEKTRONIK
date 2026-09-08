package id.example.pqcsign

import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.LinearLayout
import android.widget.TextView
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
import id.example.pqcsign.app.AppCore
import id.example.pqcsign.app.AppState
import kotlin.concurrent.thread

/**
 * PQC PDF Sign — Android client (Rencana V1 §21). Material 3, built in code:
 * a tab bar over a swappable content area. Pre-login: Masuk / Daftar /
 * Verifikasi (public, no account). Post-login: Beranda / Tanda Tangan /
 * Verifikasi / Akun. All crypto stays in AppCore / the AAR.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var core: AppCore
    private lateinit var toolbar: MaterialToolbar
    private lateinit var tabs: TabLayout
    private lateinit var progress: LinearProgressIndicator
    private lateinit var container: LinearLayout

    private var loggedIn = false
    private var signReason = "Persetujuan"
    private var lastSigned: ByteArray? = null

    // result sinks for the current screen
    private var signResult: LinearLayout? = null
    private var verifyResult: LinearLayout? = null

    private val pickToSign = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) confirmThenSign(uri)
    }
    private val pickToVerify = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) runVerify(uri)
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
    }

    private fun screenRegister(): View = page {
        addView(heading("Daftar akun"))
        addView(card {
            val srv = field(this, "Alamat server", core.state.serverUrl)
            val name = field(this, "Nama lengkap")
            val org = field(this, "Instansi")
            val email = field(this, "Email")
            val pw = field(this, "Kata sandi (min. 8 karakter)", password = true)
            addView(primary("Daftar") {
                task {
                    core.connect(srv.text.toString().trim(), true)
                    val r = core.register(
                        name.text.toString().trim(), org.text.toString().trim(),
                        email.text.toString().trim(), pw.text.toString(),
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
        })
        verifyResult = LinearLayout(themed()).apply { orientation = LinearLayout.VERTICAL }
        addView(verifyResult)
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
            addView(primary("Pilih PDF & tanda tangani") {
                signReason = reason.text.toString().trim().ifEmpty { "Persetujuan" }
                pickToSign.launch(arrayOf("application/pdf"))
            })
            addView(tonal("Simpan PDF hasil") {
                if (lastSigned == null) snack("Belum ada hasil") else saveSigned.launch("dokumen-bertandatangan.pdf")
            })
            addView(hint("Halaman verifikasi ber-QR ditambahkan otomatis di akhir dokumen."))
        })
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
        task {
            val r = core.signPdf(uri, signReason, core.state.accountEmail ?: "")
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
            if (top.optBoolean("registered")) rows += "Terdaftar di server" to "ya"
            if (pid.isNotEmpty()) rows += "ID verifikasi" to pid
            return verdictCard(
                true, "Tanda tangan SAH", rows,
                "Waktu di atas dari jam perangkat penandatangan, bukan stempel waktu tepercaya.",
            )
        }
        val errs = o.optJSONArray("errors") ?: sigs?.optJSONObject(0)?.optJSONArray("errors")
        val detail = (0 until (errs?.length() ?: 0)).joinToString("\n") { "• " + errs!!.optString(it) }
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
