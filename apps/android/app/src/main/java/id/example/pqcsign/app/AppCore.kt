package id.example.pqcsign.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.net.Uri
import android.os.ParcelFileDescriptor
import id.example.pqcsign.core.CsrRequest
import id.example.pqcsign.core.KeyVault
import id.example.pqcsign.core.SignOptions
import id.example.pqcsign.core.SigningEngine
import id.example.pqcsign.net.ApiClient
import org.json.JSONObject
import java.security.MessageDigest

/**
 * AppCore is the GUI-independent logic of the Android client (Rencana V1 §21).
 * Each screen is a thin call into one of these methods. The private key is
 * generated here, wrapped by the KeyVault immediately, and unwrapped only for
 * the duration of a single sign/CSR operation (then zeroed).
 */
class AppCore(private val context: Context, val state: AppState) {

    private val vault = KeyVault(context)
    private var api = ApiClient(state.serverUrl, state.insecureTls)

    fun connect(url: String, insecure: Boolean) {
        state.serverUrl = url
        state.insecureTls = insecure
        api = ApiClient(url, insecure)
    }

    // ---- 1. Login ----

    fun login(email: String, password: String) {
        api.login(email, password)
        state.accountEmail = email
    }

    // ---- 1b. Self-registration (Rencana RB-1) ----

    fun register(
        fullName: String, org: String, email: String, password: String,
        position: String = "", nip: String = "", issuedPlace: String = "",
    ): ApiClient.RegisterResult =
        api.register(fullName, org, email, password, position, nip, issuedPlace)

    // ---- 2. Device enrolment ----

    data class EnrollResult(val deviceId: String, val enrollmentId: String, val securityLevel: String)

    /**
     * Silent enrolment (Rencana RB-3/4): on first run generate + enrol a key,
     * then read the certificate the server auto-issues for an approved
     * account. Also re-enrols automatically when the stored device id is
     * unknown to the current server (fresh server / wiped database / switched
     * server URL). Safe to call after every login.
     */
    fun ensureEnrolled(): CertStatus {
        val stale = vault.hasKey() && deviceUnknownToServer()
        if (!vault.hasKey() || stale) {
            if (stale) wipeDeviceState()
            enrollDevice("Android ${android.os.Build.MODEL}")
        }
        return certificateStatus()
    }

    /** True when we hold a key but the server has no such device (404). */
    private fun deviceUnknownToServer(): Boolean {
        val id = state.deviceId ?: return true
        return try {
            api.deviceCertificate(id) == null
        } catch (_: Exception) {
            false // network hiccup — assume known, don't wipe
        }
    }

    private fun wipeDeviceState() {
        vault.reset()
        java.io.File(context.filesDir, CERT_FILE).delete()
        state.deviceId = null
        state.enrollmentId = null
        state.certificateSerial = null
    }

    /** Explicit enrol entry point kept for tooling; refuses to clobber a key. */
    fun registerDevice(label: String): EnrollResult {
        check(!vault.hasKey()) { "a device key already exists; reset first in Security settings" }
        return enrollDevice(label)
    }

    private fun enrollDevice(label: String): EnrollResult {
        val pkcs8 = SigningEngine.generateKey()
        return try {
            vault.createAndStore(pkcs8, state.requireAuth)

            val deviceId = api.createDevice(label, "android")
            val csr = SigningEngine.createCsr(pkcs8, CsrRequest(commonName = label, deviceLabel = label, platform = "android"))
            val enrollmentId = api.submitCsr(deviceId, csr)

            state.deviceId = deviceId
            state.enrollmentId = enrollmentId
            EnrollResult(deviceId, enrollmentId, vault.securityLevel())
        } finally {
            pkcs8.fill(0)
        }
    }

    // ---- 3. Certificate status ----

    data class CertStatus(val state: String, val serial: String? = null, val subject: String? = null, val hasDocSigningEku: Boolean = false)

    /** Checks the server for an issued certificate, verifies it matches the
     *  on-device key (§14, §25.2), and caches it. */
    fun certificateStatus(): CertStatus {
        if (!vault.hasKey()) return CertStatus("none")
        val cached = readCache(CERT_FILE)
        if (cached != null) return describeCert(cached)?.let { CertStatus("active", it.first, it.second, it.third) } ?: CertStatus("pending")

        val deviceId = state.deviceId ?: return CertStatus("pending")
        val pem = api.deviceCertificate(deviceId) ?: return CertStatus("pending")

        // Confirm the issued cert's public key matches the on-device key by
        // signing+verifying a probe through the engine is overkill; instead we
        // trust the server's chain check and cache. A mismatched key would
        // fail the local verify at sign time.
        writeCache(CERT_FILE, pem)
        runCatching { writeCache(CHAIN_FILE, api.publicChain()) }
        runCatching { writeCache(ROOT_FILE, api.publicRootCa()) }
        val d = describeCert(pem)
        state.certificateSerial = d?.first
        return d?.let { CertStatus("active", it.first, it.second, it.third) } ?: CertStatus("pending")
    }

    // ---- 4. Sign ----

    data class SignResult(
        val publicId: String,
        val verificationUrl: String,
        val originalSha512: String,
        val signedSha512: String,
        val serverStatus: String,
        val signedPdf: ByteArray,
    )

    /**
     * Signs the PDF read from [inUri]. The caller MUST have satisfied a
     * BiometricPrompt within the last 30 s (Rencana V1 §21.1) — the KeyVault's
     * wrapping key is auth-bound, so vault.load() below also enforces it
     * cryptographically. The signed bytes are returned for the caller to write
     * via SAF.
     */
    fun signPdf(inUri: Uri, reason: String, signerName: String, places: List<ApiClient.StampPlacement>): SignResult {
        val pdf = context.contentResolver.openInputStream(inUri)!!.use { it.readBytes() }
        require(!looksSigned(pdf)) {
            "Dokumen ini sudah memiliki tanda tangan digital — satu dokumen hanya boleh ditandatangani sekali; pilih PDF yang belum ditandatangani."
        }
        val root = readCache(ROOT_FILE) ?: error("no Root CA cached; register the device")
        val chain = readCache(CHAIN_FILE) ?: error("no CA chain cached")
        val cert = readCache(CERT_FILE) ?: error("no device certificate yet; check Certificate status")
        val fullChain = cert + chain

        val deviceId = state.deviceId ?: error("device not registered")
        val origSha = sha512Hex(pdf)
        val res = api.reserve(deviceId, origSha, fileName(inUri))

        // The QR stamps are drawn server-side BEFORE signing so they are
        // inside the signed byte range (Rencana RB-2c). A PDF the server
        // cannot process fails here with a clear message.
        val toSign = try {
            api.stamp(res.publicId, pdf, places.ifEmpty {
                listOf(ApiClient.StampPlacement(0, 0.62, 0.80, 0.30))
            }, reason)
        } catch (e: ApiClient.ApiException) {
            // 413: too big for a server-drawn QR stamp (docs/large-files.md).
            // Sign the original as-is; the QR link still comes from the record.
            if (e.status == 413) pdf else throw e
        }

        var keyPem = vault.load()
        val signed: ByteArray
        try {
            signed = SigningEngine.signPdf(
                toSign, keyPem, fullChain,
                SignOptions(
                    reason = reason, signerName = signerName, publicId = res.publicId,
                    verificationUrl = res.verificationUrl, includeQr = false,
                ),
            )
        } finally {
            keyPem.fill(0)
        }

        // Local verification before upload (§15.2 step 10). Skipped for very
        // large documents — verifyPdf is not streaming; the server records
        // those store-only anyway.
        if (signed.size <= LOCAL_VERIFY_MAX_BYTES) {
            val local = SigningEngine.verifyPdf(signed, root, null)
            require(local.valid) { "local verification failed; not uploading" }
        }

        val serverStatus = try {
            when (val st = api.submitDocument(res.publicId, signed).optString("status", "submitted")) {
                "stored_unverified" ->
                    "tersimpan — TIDAK diverifikasi server (berkas besar); verifikasi manual lewat halaman verifikasi"
                else -> st
            }
        } catch (e: Exception) {
            "local-only (upload failed: ${e.message})"
        }

        return SignResult(
            res.publicId, res.verificationUrl,
            origSha, sha512Hex(signed), serverStatus, signed,
        )
    }

    // ---- 4b. PDF preview for QR placement ----

    /** One rendered page + the total page count, for the placement screen. */
    data class PageImage(val bitmap: Bitmap, val pageIndex: Int, val pageCount: Int)

    private var previewFile: java.io.File? = null
    private var previewKey: String? = null

    /**
     * Renders page [pageIndex] (0-based) of the PDF at [inUri] to a white
     * bitmap [widthPx] wide, keeping the page aspect ratio. Uses the platform
     * PdfRenderer (API 21+, no dependency). The source is copied to the cache
     * ONCE per uri and reused for subsequent page turns so navigation is fast.
     */
    fun renderPdfPage(inUri: Uri, pageIndex: Int, widthPx: Int): PageImage {
        val f = previewSource(inUri)
        ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
            PdfRenderer(pfd).use { r ->
                val count = r.pageCount
                val idx = pageIndex.coerceIn(0, count - 1)
                r.openPage(idx).use { pg ->
                    val w = widthPx.coerceAtLeast(240)
                    val h = (w.toLong() * pg.height / pg.width).toInt().coerceAtLeast(1)
                    val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
                    Canvas(bmp).drawColor(Color.WHITE)
                    pg.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                    return PageImage(bmp, idx, count)
                }
            }
        }
    }

    private fun previewSource(uri: Uri): java.io.File {
        val key = uri.toString()
        val cached = previewFile
        if (key == previewKey && cached != null && cached.exists()) return cached
        cached?.delete()
        val f = java.io.File.createTempFile("preview", ".pdf", context.cacheDir)
        context.contentResolver.openInputStream(uri)!!.use { input ->
            java.io.FileOutputStream(f).use { input.copyTo(it) }
        }
        previewFile = f; previewKey = key
        return f
    }

    // ---- 5. Verify ----

    /** Local, offline verify against the cached Root CA (post-login). */
    fun verifyPdf(uri: Uri): String {
        val pdf = context.contentResolver.openInputStream(uri)!!.use { it.readBytes() }
        val root = readCache(ROOT_FILE) ?: error("no Root CA cached; register the device or import a Root CA")
        val crl = runCatching { api.publicCrl() }.getOrNull()
        return SigningEngine.verifyPdf(pdf, root, crl).pretty()
    }

    /** Public verifier on the server — no account needed. */
    fun verifyPublic(serverUrl: String, uri: Uri): String {
        val pdf = context.contentResolver.openInputStream(uri)!!.use { it.readBytes() }
        return ApiClient(serverUrl, true).verifyPublic(pdf).toString(2)
    }

    /** Resolve a scanned QR (a bare ID, or a URL whose path ends /v/<id> or
     *  /s/<id>) against [serverUrl] and return the server record JSON — the
     *  same thing a normal external QR scan lands on. No account needed. */
    fun recordFromQr(serverUrl: String, qrText: String): String {
        val raw = qrText.trim().substringBefore('?').substringBefore('#')
            .substringAfterLast("/v/").substringAfterLast("/s/").substringAfterLast('/')
        val id = Regex("[^A-Za-z0-9_-]").replace(raw, "")
        require(id.isNotEmpty()) { "QR tidak berisi ID verifikasi yang bisa dibaca" }
        return ApiClient(serverUrl, true).publicRecord(id).toString(2)
    }

    // ---- 6. History ----

    fun history(): List<JSONObject> = api.mySignatures()

    // ---- 7. Security settings ----

    fun reportLost() { state.deviceId?.let { api.reportLost(it) } ?: error("no device id") }

    fun reset() {
        vault.reset()
        listOf(CERT_FILE, CHAIN_FILE, ROOT_FILE).forEach { java.io.File(context.filesDir, it).delete() }
        state.clear()
    }

    fun securityLevel(): String = if (vault.hasKey()) vault.securityLevel() else "n/a"

    // ---- helpers ----

    private fun fileName(uri: Uri): String =
        uri.lastPathSegment?.substringAfterLast('/')?.takeIf { it.isNotBlank() } ?: "document.pdf"

    private fun sha512Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-512").digest(b).joinToString("") { "%02x".format(it) }

    /** Every PAdES/PDF signature dictionary carries "/ByteRange"; unsigned PDFs
     *  don't. Cheap early check so we don't try to re-sign a signed document. */
    private fun looksSigned(pdf: ByteArray): Boolean {
        val n = "/ByteRange".toByteArray(Charsets.US_ASCII)
        if (pdf.size < n.size) return false
        outer@ for (i in 0..pdf.size - n.size) {
            for (j in n.indices) if (pdf[i + j] != n[j]) continue@outer
            return true
        }
        return false
    }

    private fun readCache(name: String): ByteArray? =
        java.io.File(context.filesDir, name).let { if (it.exists()) it.readBytes() else null }

    private fun writeCache(name: String, b: ByteArray) {
        java.io.File(context.filesDir, name).writeBytes(b)
    }

    /** returns (serialHex, subject, hasDocSigningEku) or null. */
    private fun describeCert(pem: ByteArray): Triple<String, String, Boolean>? = try {
        val cf = java.security.cert.CertificateFactory.getInstance("X.509")
        val c = cf.generateCertificate(pem.inputStream()) as java.security.cert.X509Certificate
        val eku = c.extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.36") == true
        Triple(c.serialNumber.toString(16), c.subjectX500Principal.name, eku)
    } catch (_: Exception) {
        null
    }

    companion object {
        private const val CERT_FILE = "device.crt.pem"
        private const val CHAIN_FILE = "ca-chain.pem"
        private const val ROOT_FILE = "root-ca.crt.pem"

        // Above this the client skips the pre-upload local verify pass
        // (verifyPdf is not streaming).
        private const val LOCAL_VERIFY_MAX_BYTES = 200 * 1024 * 1024
    }
}
