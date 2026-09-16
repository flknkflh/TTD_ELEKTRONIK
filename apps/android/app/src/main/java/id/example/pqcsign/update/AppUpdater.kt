package id.example.pqcsign.update

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import id.example.pqcsign.BuildConfig
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** About -> check -> download -> verify -> explicit install. No lab TLS bypass. */
class AppUpdater(private val activity: AppCompatActivity) {
    companion object {
        private const val ORIGIN = "https://136.244.116.132"
        private const val MAX_APK = 256L * 1024 * 1024
    }
    private val client = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false)
        .connectTimeout(20, TimeUnit.SECONDS).readTimeout(60, TimeUnit.SECONDS)
        .callTimeout(10, TimeUnit.MINUTES).build()
    private val file get() = File(activity.cacheDir, "updates/update.apk")
    private var pending: JSONObject? = null
    private var ready: JSONObject? = null
    private var busy = false
    private var status = "Periksa apakah versi baru tersedia."
    private var notes = ""
    private var percent = -1
    private var showProgress = false
    private var dialog: AlertDialog? = null
    private var statusView: TextView? = null
    private var notesView: TextView? = null
    private var bar: ProgressBar? = null
    private var checkButton: Button? = null
    private var downloadButton: Button? = null
    private var installButton: Button? = null

    private fun ui(block: () -> Unit) = activity.runOnUiThread {
        if (!activity.isFinishing && !activity.isDestroyed) block()
    }
    private fun render() {
        statusView?.text = status; notesView?.text = notes
        bar?.visibility = if (showProgress) View.VISIBLE else View.GONE
        bar?.isIndeterminate = percent < 0
        if (percent >= 0) bar?.progress = percent
        checkButton?.isEnabled = !busy && ready == null
        downloadButton?.visibility = if (pending != null && ready == null) View.VISIBLE else View.GONE
        downloadButton?.isEnabled = !busy
        installButton?.visibility = if (ready != null) View.VISIBLE else View.GONE
        installButton?.isEnabled = !busy
    }
    fun showAbout() {
        if (dialog?.isShowing == true) return
        val pad = (24 * activity.resources.displayMetrics.density).toInt()
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL; setPadding(pad, pad / 2, pad, pad / 2)
        }
        fun text(value: String) = TextView(activity).apply {
            text = value; textSize = 16f; setPadding(0, pad / 3, 0, pad / 3); content.addView(this)
        }
        text("Aplikasi penandatanganan PDF dengan kriptografi pascakuantum ML-DSA-65. Tanda tangan dibuat pada perangkat Anda; QR menghubungkan dokumen ke layanan verifikasi HTTPS.")
        text("Versi terpasang: ${BuildConfig.VERSION_NAME} · Android")
        text("Pembaruan aplikasi").setTypeface(null, android.graphics.Typeface.BOLD)
        statusView = text(status).apply { accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE }
        notesView = text(notes)
        bar = ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal).apply { max = 100; content.addView(this) }
        fun button(label: String, action: () -> Unit) = Button(activity).apply {
            text = label; setOnClickListener { action() }; content.addView(this)
        }
        checkButton = button("Periksa pembaruan") { checkUpdate() }
        downloadButton = button("Unduh pembaruan") { pending?.let { download(it) } }
        installButton = button("Instal pembaruan") { install() }
        dialog = AlertDialog.Builder(activity).setTitle("Tentang PQC PDF Sign")
            .setView(ScrollView(activity).apply { addView(content) }).setPositiveButton("Tutup", null).create()
        render(); dialog?.show()
    }
    private fun checkUpdate() {
        if (busy) return
        busy = true; status = "Memeriksa pembaruan…"; percent = -1; showProgress = true; render()
        thread {
            try {
                val channel = if (BuildConfig.DEBUG) "android-debug" else "android"
                val manifest = client.newCall(Request.Builder().url("$ORIGIN/updates/$channel.json").build()).execute().use {
                    if (it.code == 404) null else {
                        check(it.isSuccessful) { "Server pembaruan: HTTP ${it.code}" }
                        val bytes = it.body!!.byteStream().use { stream ->
                            val out = ByteArrayOutputStream(); val buf = ByteArray(4096)
                            while (true) {
                                val n = stream.read(buf); if (n < 0) break
                                check(out.size() + n <= 65536) { "Manifest terlalu besar" }; out.write(buf, 0, n)
                            }
                            out.toByteArray()
                        }
                        JSONObject(String(bytes, Charsets.UTF_8))
                    }
                }
                if (manifest == null || manifest.getLong("version_code") <= BuildConfig.VERSION_CODE) {
                    ui { pending = null; notes = ""; status = if (manifest == null) "Belum ada pembaruan yang diterbitkan." else "Versi aplikasi Anda sudah terbaru." }
                } else {
                    check(manifest.getString("platform") == channel) { "Platform pembaruan tidak sesuai" }
                    check(Regex("/updates/[A-Za-z0-9._-]+\\.apk").matches(manifest.getString("path"))) { "Alamat unduhan tidak valid" }
                    check(manifest.getLong("size") in 1..MAX_APK) { "Ukuran pembaruan tidak valid" }
                    check(Regex("[a-f0-9]{64}").matches(manifest.getString("sha256"))) { "Checksum tidak valid" }
                    ui {
                        pending = manifest; notes = manifest.optString("notes", "Tidak ada catatan perubahan.").take(4000)
                        status = "Versi ${manifest.getString("version")} tersedia · ${manifest.getLong("size") / 1048576} MB"
                    }
                }
            } catch (e: Exception) { ui { status = "Pemeriksaan gagal: ${e.message}. Silakan coba lagi." } }
            finally { ui { busy = false; showProgress = false; render() } }
        }
    }
    private fun validateAPK(manifest: JSONObject) {
        check(file.isFile && file.length() == manifest.getLong("size")) { "Unduhan tidak lengkap; unduh ulang" }
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(65536)
            while (true) { val n = input.read(buffer); if (n < 0) break; digest.update(buffer, 0, n) }
        }
        check(digest.digest().joinToString("") { "%02x".format(it) } == manifest.getString("sha256")) { "Checksum tidak cocok" }
        val pm = activity.packageManager
        val archive = pm.getPackageArchiveInfo(file.path, PackageManager.GET_SIGNING_CERTIFICATES) ?: error("APK tidak valid")
        val installed = pm.getPackageInfo(activity.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        check(archive.packageName == activity.packageName && archive.longVersionCode == manifest.getLong("version_code") && archive.longVersionCode > BuildConfig.VERSION_CODE) { "Identitas/versi APK berbeda" }
        check(archive.signingInfo!!.apkContentsSigners.map { it.toCharsString() }.toSet() == installed.signingInfo!!.apkContentsSigners.map { it.toCharsString() }.toSet()) {
            "Kunci penandatangan APK berbeda. Hubungi pengelola; jangan hapus aplikasi lama."
        }
    }
    private fun download(manifest: JSONObject) {
        if (busy) return
        busy = true; ready = null; percent = 0; showProgress = true; status = "Mengunduh pembaruan: 0%"; render()
        thread {
            try {
                file.parentFile!!.mkdirs()
                val size = manifest.getLong("size")
                client.newCall(Request.Builder().url(ORIGIN + manifest.getString("path")).build()).execute().use { response ->
                    check(response.isSuccessful) { "Unduhan: HTTP ${response.code}" }
                    response.body!!.byteStream().use { input -> file.outputStream().use { output ->
                        val buffer = ByteArray(65536); var total = 0L; var lastPercent = -1
                        while (true) {
                            val n = input.read(buffer); if (n < 0) break
                            total += n; check(total <= size) { "Unduhan melebihi ukuran manifest" }; output.write(buffer, 0, n)
                            val p = (total * 100 / size).toInt()
                            if (p != lastPercent) { lastPercent = p; ui { percent = p; status = "Mengunduh pembaruan: $p%"; render() } }
                        }
                        check(total == size) { "Unduhan tidak lengkap" }
                    } }
                }
                ui { percent = -1; status = "Memverifikasi unduhan…"; render() }
                validateAPK(manifest)
                ui { ready = manifest; percent = 100; status = "Unduhan selesai dan terverifikasi. Pembaruan siap diinstal." }
            } catch (e: Exception) { file.delete(); ui { ready = null; status = "Unduhan gagal: ${e.message}" } }
            finally { ui { busy = false; showProgress = false; render() } }
        }
    }
    private fun install() {
        if (busy) return
        val manifest = ready ?: return
        if (!activity.packageManager.canRequestPackageInstalls()) {
            status = "Izinkan pemasangan dari aplikasi ini, lalu kembali dan tekan Instal pembaruan. Unduhan tetap tersimpan."; render()
            try { activity.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${activity.packageName}"))) }
            catch (e: Exception) { status = "Tidak dapat membuka pengaturan: ${e.message}"; render() }
            return
        }
        busy = true; showProgress = true; percent = -1; status = "Menyiapkan instalasi…"; render()
        thread {
            try {
                validateAPK(manifest)
                ui {
                    try {
                        val uri = FileProvider.getUriForFile(activity, "${activity.packageName}.updates", file)
                        activity.startActivity(Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
                        status = "Selesaikan pemasangan di layar Android. Jika dibatalkan, tekan Instal pembaruan lagi."
                    } catch (e: Exception) { status = "Tidak dapat membuka pemasang: ${e.message}" }
                }
            } catch (e: Exception) { ui { ready = null; status = "Validasi gagal: ${e.message}. Unduh ulang pembaruan." } }
            finally { ui { busy = false; showProgress = false; render() } }
        }
    }
}
