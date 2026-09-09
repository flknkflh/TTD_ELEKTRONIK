package id.example.pqcsign.net

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * ApiClient is the Android client's typed wrapper over the receiver API
 * (Rencana V1 §17). It performs no crypto and holds no private key.
 *
 * insecureTls accepts a self-signed server cert — LAB ONLY (Caddy internal
 * CA, §22.2). Production must use a real certificate.
 */
class ApiClient(baseUrl: String, insecureTls: Boolean = false) {

    private val base = baseUrl.trimEnd('/')
    private var token: String? = null

    private val http: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .apply { if (insecureTls) trustEverything(this) }
        .build()

    class ApiException(val status: Int, message: String) : Exception("server $status: $message")

    private val JSON = "application/json".toMediaType()
    private val PEM = "application/x-pem-file".toMediaType()
    private val PDF = "application/pdf".toMediaType()

    fun setToken(t: String) { token = t }
    fun token(): String? = token

    private fun req(method: String, path: String, body: RequestBody?): ByteArray {
        val b = Request.Builder().url(base + path)
        token?.let { b.header("Authorization", "Bearer $it") }
        when (method) {
            "GET" -> b.get()
            "POST" -> b.post(body ?: emptyBody())
            "PUT" -> b.put(body ?: emptyBody())
            else -> error("method $method")
        }
        val resp = try {
            http.newCall(b.build()).execute()
        } catch (e: javax.net.ssl.SSLException) {
            throw ApiException(0, "TLS handshake failed (${e.message}). If the server is plain HTTP (tools/dev-up.sh), use an http:// URL.")
        }
        resp.use { r ->
            val bytes = r.body?.bytes() ?: ByteArray(0)
            if (!r.isSuccessful) {
                val msg = runCatching { JSONObject(String(bytes)).optString("error") }.getOrNull()
                    ?.takeIf { it.isNotEmpty() } ?: String(bytes).trim()
                throw ApiException(r.code, msg)
            }
            return bytes
        }
    }

    private fun emptyBody(): RequestBody = ByteArray(0).toRequestBody(null, 0, 0)
    private fun json(o: JSONObject): RequestBody = o.toString().toRequestBody(JSON)
    private fun obj(bytes: ByteArray): JSONObject =
        if (bytes.isEmpty()) JSONObject() else JSONObject(String(bytes))

    // ---- auth ----

    data class RegisterResult(val accountId: String, val status: String, val message: String)

    /** Self-registers an account (Rencana RB-1). It is created pending; an
     *  admin approves it before login works. */
    fun register(fullName: String, org: String, email: String, password: String): RegisterResult {
        val o = obj(req("POST", "/api/v1/auth/register", json(JSONObject().apply {
            put("email", email); put("password", password)
            put("full_name", fullName); put("organization", org); put("display_name", fullName)
        })))
        return RegisterResult(o.optString("account_id"), o.optString("status"), o.optString("message"))
    }

    /** Login stores the access token. */
    fun login(email: String, password: String) {
        val o = obj(req("POST", "/api/v1/auth/login", json(JSONObject().apply {
            put("email", email); put("password", password)
        })))
        token = o.optString("access_token").ifEmpty { null }
        if (token == null) throw ApiException(500, "no access token")
    }

    // ---- devices & enrollment ----

    fun createDevice(label: String, platform: String): String =
        obj(req("POST", "/api/v1/devices", json(JSONObject().apply {
            put("label", label); put("platform", platform)
        }))).optString("device_id")

    fun submitCsr(deviceId: String, csrPem: ByteArray): String =
        obj(req("POST", "/api/v1/devices/$deviceId/csr", csrPem.toRequestBody(PEM)))
            .optString("enrollment_id")

    /** Returns the issued cert PEM, or null if not yet issued (HTTP 404). */
    fun deviceCertificate(deviceId: String): ByteArray? = try {
        req("GET", "/api/v1/devices/$deviceId/certificate", null)
    } catch (e: ApiException) {
        if (e.status == 404) null else throw e
    }

    fun reportLost(deviceId: String) {
        req("POST", "/api/v1/devices/$deviceId/report-lost", null)
    }

    // ---- public CA material ----

    fun publicRootCa(): ByteArray = req("GET", "/api/v1/public/ca/root.crt", null)
    fun publicChain(): ByteArray = req("GET", "/api/v1/public/ca/chain.pem", null)
    fun publicCrl(): ByteArray = req("GET", "/api/v1/public/ca/crl.pem", null)

    // ---- signatures ----

    data class Reservation(val publicId: String, val verificationUrl: String, val expiresAt: String)

    fun reserve(deviceId: String, originalSha512: String, fileName: String): Reservation {
        val o = obj(req("POST", "/api/v1/signatures/reserve", json(JSONObject().apply {
            put("device_id", deviceId); put("original_sha512", originalSha512); put("file_name", fileName)
        })))
        return Reservation(o.optString("public_id"), o.optString("verification_url"), o.optString("expires_at"))
    }

    /** Where the signer dropped the QR box: page (1-based) + a page-relative
     *  rectangle with the origin at the top-left (x,y = top-left corner,
     *  w = width; all fractions in 0..1). */
    data class StampPlacement(val page: Int, val x: Double, val y: Double, val w: Double)

    /** Uploads the original PDF and returns it with one "TTD Elektronik" QR
     *  stamp drawn at the requested spot (Rencana RB-2c), ready to sign
     *  on-device. The page count is unchanged. */
    fun stamp(publicId: String, pdf: ByteArray, place: StampPlacement, reason: String): ByteArray {
        val enc = { d: Double -> java.net.URLEncoder.encode(String.format(java.util.Locale.US, "%.4f", d), "UTF-8") }
        val sb = StringBuilder("?x=${enc(place.x)}&y=${enc(place.y)}&w=${enc(place.w)}")
        if (place.page > 0) sb.append("&page=${place.page}")
        if (reason.isNotEmpty()) sb.append("&reason=" + java.net.URLEncoder.encode(reason, "UTF-8"))
        return req("POST", "/api/v1/signatures/$publicId/stamp$sb", pdf.toRequestBody(PDF))
    }

    /** Returns the server's JSON result (status "accepted" on success). */
    fun submitDocument(publicId: String, signedPdf: ByteArray): JSONObject =
        obj(req("PUT", "/api/v1/signatures/$publicId/document", signedPdf.toRequestBody(PDF)))

    fun mySignatures(): List<JSONObject> {
        val arr = obj(req("GET", "/api/v1/me/signatures", null)).optJSONArray("signatures") ?: return emptyList()
        return (0 until arr.length()).map { arr.getJSONObject(it) }
    }

    fun verifyPublic(pdf: ByteArray): JSONObject {
        val body = MultipartBody.Builder().setType(MultipartBody.FORM)
            .addFormDataPart("file", "document.pdf", pdf.toRequestBody(PDF))
            .build()
        return obj(req("POST", "/api/v1/verify", body))
    }

    /** The display-safe server record for one signature ID (what a scanned QR
     *  resolves to). No account needed. Throws ApiException(404) if unknown. */
    fun publicRecord(publicId: String): JSONObject =
        obj(req("GET", "/api/v1/public/signatures/" + java.net.URLEncoder.encode(publicId, "UTF-8"), null))
}

private fun trustEverything(b: OkHttpClient.Builder) {
    val tm = object : X509TrustManager {
        override fun checkClientTrusted(c: Array<out java.security.cert.X509Certificate>?, a: String?) {}
        override fun checkServerTrusted(c: Array<out java.security.cert.X509Certificate>?, a: String?) {}
        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
    }
    val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf(tm), java.security.SecureRandom()) }
    b.sslSocketFactory(ctx.socketFactory, tm)
    b.hostnameVerifier(HostnameVerifier { _, _ -> true })
}
