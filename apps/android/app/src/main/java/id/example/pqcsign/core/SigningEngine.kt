package id.example.pqcsign.core

import id.example.pqcsign.mobilebridge.Mobilebridge
import org.json.JSONObject

/**
 * Thin Kotlin wrapper over the gomobile AAR (`core/mobilebridge`).
 *
 * Skeleton for M5 — NOT yet compiled by Gradle in this repo. It shows the
 * intended seam: the Kotlin layer owns Android Keystore wrapping + biometric
 * gating (Rencana V1 §12.2), and hands the engine only the plaintext PKCS#8
 * bytes for the duration of a single call.
 *
 * Invariants:
 *  - `privateKeyPkcs8` is unwrapped by [id.example.pqcsign.security] right
 *    before a call and zeroed right after. Never log it, never put it on the
 *    clipboard, never write it to cache.
 *  - All trust decisions use the bundled Root CA PEM, never a root from a PDF.
 */
object SigningEngine {

    /** Generate a device ML-DSA-65 key. Returns PKCS#8 DER — wrap immediately. */
    fun generateKey(): ByteArray = Mobilebridge.generateKey()

    fun exportPublicKeyPem(privateKeyPkcs8: ByteArray): ByteArray =
        Mobilebridge.exportPublicKey(privateKeyPkcs8)

    fun createCsr(privateKeyPkcs8: ByteArray, request: CsrRequest): ByteArray =
        Mobilebridge.createCSR(privateKeyPkcs8, request.toJson())

    fun signPdf(
        pdf: ByteArray,
        privateKeyPkcs8: ByteArray,
        certChainPem: ByteArray,
        options: SignOptions,
    ): ByteArray = Mobilebridge.signPDF(pdf, privateKeyPkcs8, certChainPem, options.toJson())

    /** Returns the shared verification JSON (Rencana V1 §11.3). */
    fun verifyPdf(pdf: ByteArray, rootPem: ByteArray, crlPem: ByteArray?): VerifyResult {
        val json = Mobilebridge.verifyPDF(pdf, rootPem, crlPem ?: ByteArray(0))
        return VerifyResult(JSONObject(json))
    }
}

data class CsrRequest(
    val commonName: String,
    val organization: String? = null,
    val deviceLabel: String? = null,
    val platform: String = "android",
) {
    fun toJson(): String = JSONObject().apply {
        put("common_name", commonName)
        organization?.let { put("organization", it) }
        deviceLabel?.let { put("device_label", it) }
        put("platform", platform)
    }.toString()
}

data class SignOptions(
    val reason: String? = null,
    val location: String? = null,
    val signerName: String? = null,
    val publicId: String? = null,
    val verificationUrl: String? = null,
    val includeQr: Boolean = true,
    val page: Int = 1,
) {
    fun toJson(): String = JSONObject().apply {
        reason?.let { put("reason", it) }
        location?.let { put("location", it) }
        signerName?.let { put("signer_name", it) }
        publicId?.let { put("public_id", it) }
        verificationUrl?.let { put("verification_url", it) }
        put("include_qr", includeQr)
        put("page", page)
    }.toString()
}

class VerifyResult(private val root: JSONObject) {
    val valid: Boolean get() = root.optBoolean("valid", false)
    val documentSha512: String get() = root.optString("document_sha512")
    val signatures: JSONObject? get() = root.optJSONObject("signatures")
    fun raw(): JSONObject = root
}
