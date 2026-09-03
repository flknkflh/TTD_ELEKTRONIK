package id.example.pqcsign

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import id.example.pqcsign.core.KeyVault
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs on a device/emulator: the Android Keystore wrapping of the device key
 * (Rencana V1 §12.2, §26). Not run in the JVM CI lane — needs the platform
 * Keystore.
 */
@RunWith(AndroidJUnit4::class)
class KeyVaultInstrumentedTest {

    private val ctx get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun wrap_unwrap_round_trip() {
        val v = KeyVault(ctx)
        v.reset()
        assertFalse(v.hasKey())
        v.ensureWrappingKey(requireAuth = false)

        val secret = ByteArray(96) { (it * 7 + 1).toByte() }
        v.store(secret)
        assertTrue(v.hasKey())
        assertArrayEquals(secret, v.load())

        // A second store() uses a fresh IV -> different file bytes.
        v.store(secret)
        assertArrayEquals(secret, v.load())

        v.reset()
        assertFalse(v.hasKey())
    }

    @Test fun tampered_blob_fails_to_open() {
        val v = KeyVault(ctx)
        v.reset()
        v.ensureWrappingKey(requireAuth = false)
        v.store(ByteArray(64) { 9 })

        val f = java.io.File(java.io.File(ctx.filesDir, "vault"), "device-key.enc")
        val raw = f.readBytes()
        raw[raw.size - 1] = (raw[raw.size - 1] + 1).toByte() // corrupt the GCM tag
        f.writeBytes(raw)

        try {
            v.load()
            fail("tampered blob was accepted")
        } catch (_: Exception) {
            // expected: AEADBadTagException
        }
        v.reset()
    }

    @Test fun security_level_is_reported() {
        val v = KeyVault(ctx)
        v.reset()
        v.ensureWrappingKey(requireAuth = false)
        val level = v.securityLevel()
        assertTrue(level in setOf("strongbox", "tee", "tee-or-strongbox", "software"))
        v.reset()
    }
}
