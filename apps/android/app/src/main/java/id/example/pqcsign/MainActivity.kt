package id.example.pqcsign

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import id.example.pqcsign.core.SigningEngine
import kotlin.concurrent.thread

/**
 * Minimal spike UI — plain android.app.Activity, no AndroidX, no XML layout,
 * so the debug APK has essentially nothing between the button and the AAR.
 */
class MainActivity : Activity() {

    private lateinit var output: TextView
    private lateinit var runButton: Button
    private lateinit var keyButton: Button
    private lateinit var saveButton: Button
    private var lastSignedPdf: ByteArray? = null

    private val reqCreateDoc = 42

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }

        root.addView(TextView(this).apply {
            text = "PQC PDF Sign V1 — M1 on-device spike\nML-DSA-65 · PAdES-B · SHA-512"
            setTypeface(typeface, Typeface.BOLD)
        })

        runButton = Button(this).apply {
            text = "Jalankan spike (keygen + sign + verify)"
            setOnClickListener { runSpike() }
        }
        keyButton = Button(this).apply {
            text = "Generate key saja (ukur waktu)"
            setOnClickListener { runKeygenOnly() }
        }
        saveButton = Button(this).apply {
            text = "Simpan signed.pdf"
            isEnabled = false
            setOnClickListener { startSave() }
        }
        root.addView(runButton)
        root.addView(keyButton)
        root.addView(saveButton)

        output = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 11f
            setTextIsSelectable(true)
            setTextColor(Color.DKGRAY)
            text = "Siap. Tekan \"Jalankan spike\".\n"
        }
        val scroll = ScrollView(this).apply { addView(output) }
        root.addView(scroll, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))

        setContentView(root)
    }

    private fun setBusy(busy: Boolean) {
        runButton.isEnabled = !busy
        keyButton.isEnabled = !busy
    }

    private fun append(s: String) = runOnUiThread {
        output.append(s)
        output.append("\n")
    }

    private fun runSpike() {
        setBusy(true)
        output.text = ""
        thread {
            try {
                val res = SpikeRunner(assets).run { line -> append(line) }
                lastSignedPdf = res.signedSamplePdf
                runOnUiThread {
                    saveButton.isEnabled = res.signedSamplePdf != null
                    setBusy(false)
                    Toast.makeText(this,
                        if (res.passed) "Spike PASSED" else "Spike FAILED",
                        Toast.LENGTH_LONG).show()
                }
            } catch (t: Throwable) {
                append("\nERROR: ${t.javaClass.simpleName}: ${t.message}")
                append(android.util.Log.getStackTraceString(t))
                runOnUiThread { setBusy(false) }
            }
        }
    }

    private fun runKeygenOnly() {
        setBusy(true)
        thread {
            try {
                val t0 = System.nanoTime()
                val key = SigningEngine.generateKey()
                val ms = (System.nanoTime() - t0) / 1_000_000
                val pub = SigningEngine.exportPublicKeyPem(key)
                append("keygen: PKCS#8 ${key.size} B in ${ms} ms")
                append(String(pub).trim())
            } catch (t: Throwable) {
                append("ERROR: ${t.message}")
            } finally {
                runOnUiThread { setBusy(false) }
            }
        }
    }

    private fun startSave() {
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/pdf"
            putExtra(Intent.EXTRA_TITLE, "signed-android.pdf")
        }
        startActivityForResult(intent, reqCreateDoc)
    }

    @Deprecated("plain Activity spike; ComponentActivity result API arrives with M5")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != reqCreateDoc || resultCode != RESULT_OK) return
        val uri: Uri = data?.data ?: return
        val bytes = lastSignedPdf ?: return
        try {
            contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
            Toast.makeText(this, "Tersimpan (${bytes.size} B)", Toast.LENGTH_LONG).show()
            append("\nsigned PDF disimpan ke $uri")
        } catch (t: Throwable) {
            Toast.makeText(this, "Gagal simpan: ${t.message}", Toast.LENGTH_LONG).show()
        }
    }
}
