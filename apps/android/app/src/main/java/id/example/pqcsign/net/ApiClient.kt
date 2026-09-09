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
        .readTimeout(2, TimeUnit.MINUTES)   // headroom for one ~8 MiB upload chunk on a slow link
        .writeTimeout(2, TimeUnit.MINUTES)
        .apply { if (insecureTls) trustEverything(this) }
        .build()

    class ApiException(val status: Int, message: String) : Exception("server $status: $message")

    private val JSON = "application/json".toMediaType()
    private val PEM = "application/x-pem-file".toMediaType()
    private val PDF = "application/pdf".toMediaType()
    private val OCTET = "application/octet-stream".toMediaType()

    // Bodies larger than this are pushed through /api/v1/uploads in chunks
    // instead of one request (docs/large-files.md).
    private val uploadChunkBytes = 8 * 1024 * 1024

    fun setToken(t: String) { token = t }
    fun token(): String? = token

    private fun req(method: String, path: String, body: RequestBody?): ByteArray {
        val b = Request.Builder().url(base + path)
        token?.let { b.header("Authorization", "Bearer $it") }
        when (method) {
            "GET" -> b.get()
            "POST" -> b.post(body ?: emptyBody())
            "PUT" -> b.put(body ?: emptyBody())
            "PATCH" -> b.patch(body ?: emptyBody())
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
    fun register(
        fullName: String, org: String, email: String, password: String,
        position: String = "", nip: String = "", issuedPlace: String = "",
    ): RegisterResult {
        val o = obj(req("POST", "/api/v1/auth/register", json(JSONObject().apply {
            put("email", email); put("password", password)
            put("full_name", fullName); put("organization", org); put("display_name", fullName)
            put("position", position); put("nip", nip); put("issued_place", issuedPlace)
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

    /** Uploads the original PDF and returns it with one caption+QR stamp per
     *  placement (Rencana RB-2c), ready to sign on-device. Page count
     *  unchanged. Placements go as a JSON `stamps` param; a single placement
     *  also sends page/x/y/w for older servers. */
    fun stamp(publicId: String, pdf: ByteArray, places: List<StampPlacement>, reason: String): ByteArray {
        val q = StringBuilder("?")
        if (reason.isNotEmpty()) q.append("reason=").append(java.net.URLEncoder.encode(reason, "UTF-8")).append('&')
        val arr = org.json.JSONArray()
        for (p in places) arr.put(JSONObject().apply {
            put("page", p.page); put("x", p.x); put("y", p.y); put("w", p.w)
        })
        q.append("stamps=").append(java.net.URLEncoder.encode(arr.toString(), "UTF-8"))
        if (places.size == 1) {
            val p = places[0]
            val f = { d: Double -> String.format(java.util.Locale.US, "%.4f", d) }
            q.append("&x=").append(f(p.x)).append("&y=").append(f(p.y)).append("&w=").append(f(p.w))
            if (p.page > 0) q.append("&page=").append(p.page)
        }
        if (pdf.size > uploadChunkBytes) {
            val id = uploadBytes(pdf)
            q.append("&upload_id=").append(id)
            return req("POST", "/api/v1/signatures/$publicId/stamp$q", null)
        }
        return req("POST", "/api/v1/signatures/$publicId/stamp$q", pdf.toRequestBody(PDF))
    }

    /** Returns the server's JSON result (status "accepted", or
     *  "stored_unverified" for a document too large to verify server-side). */
    fun submitDocument(publicId: String, signedPdf: ByteArray): JSONObject {
        if (signedPdf.size > uploadChunkBytes) {
            val id = uploadBytes(signedPdf)
            return obj(req("PUT", "/api/v1/signatures/$publicId/document?upload_id=$id", null))
        }
        return obj(req("PUT", "/api/v1/signatures/$publicId/document", signedPdf.toRequestBody(PDF)))
    }

    /** Pushes [data] to a fresh resumable upload and returns its id. */
    private fun uploadBytes(data: ByteArray): String {
        val id = obj(req("POST", "/api/v1/uploads", null)).optString("upload_id")
        require(id.isNotEmpty()) { "respons unggah tanpa upload_id" }
        var off = 0
        while (off < data.size) {
            val end = minOf(off + uploadChunkBytes, data.size)
            val part = data.copyOfRange(off, end)
            val res = obj(req("PATCH", "/api/v1/uploads/$id?offset=$off", part.toRequestBody(OCTET)))
            val got = res.optInt("received", off)
            require(got > off) { "unggah macet di offset $off" }
            off = got
        }
        return id
    }

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
