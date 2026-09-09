package id.example.pqcsign

import id.example.pqcsign.net.ApiClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/** JVM unit tests for the receiver client's request shaping + response
 *  parsing (Rencana V1 §17). No Android framework, no device. */
class ApiClientTest {

    private lateinit var server: MockWebServer
    private lateinit var api: ApiClient

    @Before fun setUp() {
        server = MockWebServer().also { it.start() }
        api = ApiClient(server.url("/").toString().trimEnd('/'))
    }

    @After fun tearDown() = server.shutdown()

    private fun json(code: Int, body: String) =
        server.enqueue(MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(body))

    @Test fun login_stores_token() {
        json(200, """{"access_token":"tok123","token_type":"Bearer"}""")
        api.login("u@x", "pw")
        assertEquals("tok123", api.token())

        val rec: RecordedRequest = server.takeRequest()
        assertEquals("POST /api/v1/auth/login", "${rec.method} ${rec.path}")
        assertTrue(rec.body.readUtf8().contains("\"email\":\"u@x\""))
    }

    @Test fun login_throws_on_401() {
        json(401, """{"error":"invalid credentials"}""")
        try {
            api.login("u@x", "pw")
            fail("expected ApiException")
        } catch (e: ApiClient.ApiException) {
            assertEquals(401, e.status)
        }
    }

    @Test fun bearer_token_is_attached_after_login() {
        json(200, """{"access_token":"abc"}""")
        api.login("u", "p")
        server.takeRequest()

        json(201, """{"device_id":"dev_1","status":"active"}""")
        assertEquals("dev_1", api.createDevice("Laptop", "android"))
        val rec = server.takeRequest()
        assertEquals("Bearer abc", rec.getHeader("Authorization"))
    }

    @Test fun deviceCertificate_returns_null_on_404() {
        api.setToken("t")
        server.enqueue(MockResponse().setResponseCode(404).setBody("""{"error":"not issued"}"""))
        assertNull(api.deviceCertificate("dev_1"))
    }

    @Test fun reserve_parses_public_id_and_url() {
        api.setToken("t")
        json(201, """{"public_id":"sig_42","verification_url":"https://v/sig_42","expires_at":"z"}""")
        val r = api.reserve("dev_1", "abc", "doc.pdf")
        assertEquals("sig_42", r.publicId)
        assertEquals("https://v/sig_42", r.verificationUrl)
        assertTrue(server.takeRequest().body.readUtf8().contains("\"device_id\":\"dev_1\""))
    }

    @Test fun submitDocument_puts_pdf_and_reads_status() {
        api.setToken("t")
        json(200, """{"public_id":"sig_42","status":"accepted"}""")
        val res = api.submitDocument("sig_42", "%PDF-1.7 fake".toByteArray())
        assertEquals("accepted", res.optString("status"))
        val rec = server.takeRequest()
        assertEquals("PUT /api/v1/signatures/sig_42/document", "${rec.method} ${rec.path}")
        assertEquals("application/pdf", rec.getHeader("Content-Type"))
    }

    @Test fun register_sends_signer_profile_fields() {
        json(201, """{"account_id":"acct_9","status":"pending","message":"menunggu persetujuan admin"}""")
        val r = api.register("Budi Santoso", "Dinas Kominfo", "budi@x", "budi12345", "Kepala Seksi", "199001")
        assertEquals("acct_9", r.accountId)
        assertEquals("pending", r.status)
        val body = server.takeRequest().body.readUtf8()
        assertTrue(body.contains("\"full_name\":\"Budi Santoso\""))
        assertTrue(body.contains("\"organization\":\"Dinas Kominfo\""))
        assertTrue(body.contains("\"position\":\"Kepala Seksi\""))
        assertTrue(body.contains("\"nip\":\"199001\""))
    }

    @Test fun stamp_posts_pdf_with_placements_and_returns_stamped_bytes() {
        api.setToken("t")
        server.enqueue(
            MockResponse().setResponseCode(200)
                .setHeader("Content-Type", "application/pdf").setBody("%PDF-1.7 stamped"),
        )
        val out = api.stamp(
            "sig_1", "%PDF-1.7 orig".toByteArray(),
            listOf(
                ApiClient.StampPlacement(page = 2, x = 0.6, y = 0.8, w = 0.25),
                ApiClient.StampPlacement(page = 1, x = 0.1, y = 0.1, w = 0.2),
            ),
            "Persetujuan", "Jakarta",
        )
        assertEquals("%PDF-1.7 stamped", String(out))
        val rec = server.takeRequest()
        assertEquals("POST", rec.method)
        assertTrue(rec.path!!.startsWith("/api/v1/signatures/sig_1/stamp?"))
        assertTrue(rec.path!!.contains("stamps="))
        assertTrue(rec.path!!.contains("reason=Persetujuan"))
        assertTrue(rec.path!!.contains("issued_place=Jakarta"))
        assertEquals("application/pdf", rec.getHeader("Content-Type"))
    }

    @Test fun server_error_body_surfaces_in_exception() {
        api.setToken("t")
        server.enqueue(MockResponse().setResponseCode(422).setBody("""{"error":"public id mismatch"}"""))
        try {
            api.submitDocument("sig_x", ByteArray(3))
            fail("expected ApiException")
        } catch (e: ApiClient.ApiException) {
            assertEquals(422, e.status)
            assertTrue(e.message!!.contains("public id mismatch"))
        }
    }
}
