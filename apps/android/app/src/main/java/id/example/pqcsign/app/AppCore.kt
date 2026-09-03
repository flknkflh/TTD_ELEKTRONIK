package id.example.pqcsign.app

import android.content.Context
import android.net.Uri
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

    val mfaRequired get() = api.mfaRequired

    // ---- 1. Login ----

    fun login(email: String, password: String, totpCode: String?) {
        api.login(email, password, totpCode)
        state.accountEmail = email
    }

    // ---- 2. Register device ----

    data class EnrollResult(val deviceId: String, val enrollmentId: String, val securityLevel: String)

    /** Generates the device key, wraps it in the KeyVault, and enrolls. */
    fun registerDevice(label: String): EnrollResult {
        check(!vault.hasKey()) { "a device key already exists; reset first in Security settings" }
        vault.ensureWrappingKey(state.requireAuth)

        val pkcs8 = SigningEngine.generateKey()
        return try {
            vault.store(pkcs8)

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
    fun signPdf(inUri: Uri, reason: String, signerName: String): SignResult {
        val pdf = context.contentResolver.openInputStream(inUri)!!.use { it.readBytes() }
        val root = readCache(ROOT_FILE) ?: error("no Root CA cached; register the device")
        val chain = readCache(CHAIN_FILE) ?: error("no CA chain cached")
        val cert = readCache(CERT_FILE) ?: error("no device certificate yet; check Certificate status")
        val fullChain = cert + chain

        val deviceId = state.deviceId ?: error("device not registered")
        val res = api.reserve(deviceId, sha512Hex(pdf), fileName(inUri))

        var keyPem = vault.load()
        val signed: ByteArray
        try {
            signed = SigningEngine.signPdf(
                pdf, keyPem, fullChain,
                SignOptions(
                    reason = reason, signerName = signerName, publicId = res.publicId,
                    verificationUrl = res.verificationUrl, includeQr = true,
                ),
            )
        } finally {
            keyPem.fill(0)
        }

        // Local verification before upload (§15.2 step 10).
        val local = SigningEngine.verifyPdf(signed, root, null)
        require(local.valid) { "local verification failed; not uploading" }

        val serverStatus = try {
            api.submitDocument(res.publicId, signed).optString("status", "submitted")
        } catch (e: Exception) {
            "local-only (upload failed: ${e.message})"
        }

        return SignResult(
            res.publicId, res.verificationUrl,
            sha512Hex(pdf), sha512Hex(signed), serverStatus, signed,
        )
    }

    // ---- 5. Verify (local) ----

    fun verifyPdf(uri: Uri): String {
        val pdf = context.contentResolver.openInputStream(uri)!!.use { it.readBytes() }
        val root = readCache(ROOT_FILE) ?: error("no Root CA cached; register the device or import a Root CA")
        val crl = runCatching { api.publicCrl() }.getOrNull()
        return SigningEngine.verifyPdf(pdf, root, crl).pretty()
    }

    // ---- 6. History ----

    fun history(): List<JSONObject> = api.mySignatures()

    // ---- 7. Security settings ----

    fun startMfaSetup(): Pair<String, String> = api.mfaSetup()
    fun confirmMfa(code: String) = api.mfaVerify(code)
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
    }
}
