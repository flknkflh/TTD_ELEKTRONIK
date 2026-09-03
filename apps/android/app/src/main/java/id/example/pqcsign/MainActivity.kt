package id.example.pqcsign

import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import id.example.pqcsign.app.AppCore
import id.example.pqcsign.app.AppState
import kotlin.concurrent.thread

/**
 * PQC PDF Sign — Android client (Rencana V1 §21). Plain-Views multi-screen
 * shell over AppCore. Compose migration + visual polish is a later slice; the
 * key-security path (KeyVault, on-device sign, local-verify-before-upload) is
 * the substance and is exercised here and by the Diagnostics spike.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var core: AppCore
    private lateinit var content: LinearLayout
    private lateinit var out: TextView

    private var pendingSign: Triple<Uri, String, String>? = null // uri, reason, signer
    private var lastSigned: ByteArray? = null

    private val pickToSign = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) confirmThenSign(uri)
    }
    private val pickToVerify = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) run("verify") { core.verifyPdf(uri) }
    }
    private val saveSigned = registerForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri ->
        val bytes = lastSigned
        if (uri != null && bytes != null) {
            contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
            toast("Tersimpan (${bytes.size} B)")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        core = AppCore(this, AppState(this))

        val pad = dp(12)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        val nav = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(pad, pad, pad, 0) }
        val hs = android.widget.HorizontalScrollView(this).apply { addView(nav) }
        listOf(
            "Login" to ::screenLogin, "Perangkat" to ::screenRegister, "Sertifikat" to ::screenCert,
            "Tanda tangan" to ::screenSign, "Verifikasi" to ::screenVerify, "QR" to ::screenQr,
            "Riwayat" to ::screenHistory, "Keamanan" to ::screenSecurity, "Diagnostik" to ::screenDiag,
        ).forEach { (label, builder) ->
            nav.addView(Button(this).apply { text = label; setOnClickListener { show(builder()) } })
        }
        root.addView(hs)

        content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(pad, pad, pad, pad) }
        out = TextView(this).apply {
            typeface = android.graphics.Typeface.MONOSPACE; textSize = 11f
            setTextIsSelectable(true); text = "PQC PDF Sign — pilih menu di atas.\n"
        }
        val body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        body.addView(content)
        body.addView(TextView(this).apply { text = "\nHasil:"; setPadding(pad, pad, pad, 0) })
        body.addView(out, LinearLayout.LayoutParams(MATCH, 0, 1f).also { it.setMargins(pad, 0, pad, pad) })
        root.addView(ScrollView(this).apply { addView(body) }, LinearLayout.LayoutParams(MATCH, 0, 1f))

        setContentView(root)
        show(screenLogin())
    }

    // ---- screens ----

    private fun screenLogin(): View = column {
        addView(label("Server URL"))
        val srv = field(core.state.serverUrl)
        addView(srv)
        addView(label("Email")); val email = field(core.state.accountEmail ?: "")
        addView(email)
        addView(label("Password")); val pw = field("", password = true); addView(pw)
        addView(label("Kode TOTP (jika MFA aktif)")); val code = field(""); addView(code)
        addView(button("Masuk") {
            run("login") {
                core.connect(srv.text.toString().trim(), true)
                core.login(email.text.toString().trim(), pw.text.toString(), code.text.toString().trim())
                "login OK" + if (core.mfaRequired) " (butuh kode)" else ""
            }
        })
    }

    private fun screenRegister(): View = column {
        addView(TextView(context).apply { text = "Membuat kunci ML-DSA-65 di perangkat lalu dibungkus Android Keystore." })
        addView(label("Label perangkat")); val lbl = field("Android ${android.os.Build.MODEL}")
        addView(lbl)
        addView(button("Daftarkan perangkat") {
            run("register") {
                val r = core.registerDevice(lbl.text.toString().trim())
                "device_id=${r.deviceId}\nenrollment_id=${r.enrollmentId}\nkey security: ${r.securityLevel}"
            }
        })
    }

    private fun screenCert(): View = column {
        addView(button("Periksa status sertifikat") {
            run("cert") {
                val s = core.certificateStatus()
                "state=${s.state}" + (s.serial?.let { "\nserial=$it\nsubject=${s.subject}\ndoc-signing EKU=${s.hasDocSigningEku}" } ?: "")
            }
        })
    }

    private fun screenSign(): View = column {
        addView(label("Alasan")); val reason = field("Persetujuan"); addView(reason)
        addView(label("Nama penanda tangan")); val name = field(core.state.accountEmail ?: ""); addView(name)
        addView(button("Pilih PDF & tanda tangani") {
            pendingSign = Triple(Uri.EMPTY, reason.text.toString(), name.text.toString())
            pickToSign.launch(arrayOf("application/pdf"))
        })
        addView(button("Simpan PDF hasil") {
            if (lastSigned == null) toast("Belum ada hasil") else saveSigned.launch("signed-android.pdf")
        })
    }

    private fun screenVerify(): View = column {
        addView(button("Pilih PDF & verifikasi (lokal)") { pickToVerify.launch(arrayOf("application/pdf")) })
    }

    private fun screenQr(): View = column {
        addView(TextView(context).apply { text = "Tempel URL verifikasi (dari QR) untuk membuka catatan server." })
        val u = field("https://verify.example.id/v/")
        addView(u)
        addView(button("Buka di browser") {
            runCatching { startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, Uri.parse(u.text.toString().trim()))) }
                .onFailure { toast("URL tidak valid") }
        })
        addView(TextView(context).apply { text = "\nPemindai QR dalam aplikasi = slice UI berikutnya." })
    }

    private fun screenHistory(): View = column {
        addView(button("Muat riwayat") {
            run("history") { core.history().joinToString("\n") { it.toString() }.ifEmpty { "(kosong)" } }
        })
    }

    private fun screenSecurity(): View = column {
        addView(button("Aktifkan MFA (tampilkan secret)") {
            run("mfa") { val (s, url) = core.startMfaSetup(); "secret=$s\n$url" }
        })
        addView(label("Kode konfirmasi MFA")); val code = field(""); addView(code)
        addView(button("Konfirmasi MFA") { run("mfa") { core.confirmMfa(code.text.toString().trim()); "MFA dikonfirmasi" } })
        addView(button("Laporkan perangkat hilang") { run("report") { core.reportLost(); "dilaporkan" } })
        addView(button("Security level kunci") { run("sec") { core.securityLevel() } })
        addView(button("RESET (hapus vault lokal)") {
            run("reset") { core.reset(); "vault dihapus" }
        })
    }

    private fun screenDiag(): View = column {
        addView(TextView(context).apply { text = "Menjalankan spike M1 (fixture lokal): keygen + sign + verify + tolak PDF diubah." })
        addView(button("Jalankan spike") {
            setBusy(true)
            thread {
                try {
                    val res = SpikeRunner(assets).run { line -> append(line) }
                    runOnUiThread { toast(if (res.passed) "SPIKE PASSED" else "SPIKE FAILED"); setBusy(false) }
                } catch (t: Throwable) {
                    append("ERROR: ${t.message}"); runOnUiThread { setBusy(false) }
                }
            }
        })
    }

    // ---- sign flow with biometric ----

    private fun confirmThenSign(uri: Uri) {
        val ps = pendingSign ?: Triple(uri, "Persetujuan", core.state.accountEmail ?: "")
        val reason = ps.second; val signer = ps.third
        val can = BiometricManager.from(this).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
        if (can != BiometricManager.BIOMETRIC_SUCCESS) {
            append("Tidak ada biometrik/PIN perangkat — melanjutkan (kebijakan lab).")
            doSign(uri, reason, signer)
            return
        }
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    doSign(uri, reason, signer)
                }
                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    append("Konfirmasi dibatalkan: $msg")
                }
            })
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Konfirmasi tanda tangan")
                .setSubtitle("Buka kunci untuk memakai kunci perangkat")
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
                )
                .build()
        )
    }

    private fun doSign(uri: Uri, reason: String, signer: String) {
        run("sign") {
            val r = core.signPdf(uri, reason, signer)
            lastSigned = r.signedPdf
            "public_id=${r.publicId}\nserver=${r.serverStatus}\noriginal=${r.originalSha512.take(24)}…\nsigned=${r.signedSha512.take(24)}…\n\nGunakan \"Simpan PDF hasil\"."
        }
    }

    // ---- infra ----

    private fun run(tag: String, block: () -> String) {
        setBusy(true)
        out.text = ""
        thread {
            val msg = try { block() } catch (t: Throwable) { "ERROR [$tag]: ${t.message}" }
            runOnUiThread { append(msg); setBusy(false) }
        }
    }

    private fun append(s: String) = runOnUiThread { out.append(s); out.append("\n") }
    private fun setBusy(b: Boolean) = runOnUiThread { content.isEnabled = !b }
    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()
    private fun show(v: View) { content.removeAllViews(); content.addView(v) }

    private fun column(build: LinearLayout.() -> Unit) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL; build()
    }
    private fun label(t: String) = TextView(this).apply { text = t; setPadding(0, dp(8), 0, 0) }
    private fun field(v: String, password: Boolean = false) = EditText(this).apply {
        setText(v)
        if (password) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    }
    private fun button(t: String, onClick: () -> Unit) = Button(this).apply {
        text = t; setOnClickListener { onClick() }; gravity = Gravity.CENTER
    }
    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private companion object {
        const val MATCH = LinearLayout.LayoutParams.MATCH_PARENT
    }
}
