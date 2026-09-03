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

    @Test fun login_stores_token_and_sends_code() {
        json(200, """{"access_token":"tok123","token_type":"Bearer","mfa":true}""")
        api.login("u@x", "pw", "654321")
        assertEquals("tok123", api.token())

        val rec: RecordedRequest = server.takeRequest()
        assertEquals("POST /api/v1/auth/login", "${rec.method} ${rec.path}")
        assertTrue(rec.body.readUtf8().contains("\"code\":\"654321\""))
    }

    @Test fun login_flags_mfa_required_on_401() {
        json(401, """{"error":"TOTP code required","mfa_required":true}""")
        try {
            api.login("u@x", "pw", null)
            fail("expected ApiException")
        } catch (e: ApiClient.ApiException) {
            assertEquals(401, e.status)
        }
        assertTrue(api.mfaRequired)
    }

    @Test fun bearer_token_is_attached_after_login() {
        json(200, """{"access_token":"abc"}""")
        api.login("u", "p", null)
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
