package id.example.pqcsign.core

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * KeyVault protects the device ML-DSA-65 private key on Android (Rencana V1
 * §12.2):
 *
 *   - a per-install AES-256-GCM wrapping key lives in the Android Keystore
 *     (hardware-backed where available; device-unlock gated),
 *   - the ML-DSA PKCS#8 bytes are AES-GCM-encrypted with it and stored in the
 *     app's internal storage (never external/shared),
 *   - the file is excluded from Auto Backup via data_extraction_rules.xml.
 *
 * The ML-DSA key itself is NOT claimed hardware-backed — the platform Keystore
 * has no ML-DSA algorithm; only the wrapping key is. The plaintext key exists
 * only transiently in memory for one sign/CSR call.
 */
class KeyVault(context: Context) {

    private val appContext = context.applicationContext
    private val vaultFile = File(File(appContext.filesDir, "vault").apply { mkdirs() }, "device-key.enc")

    companion object {
        private const val KS = "AndroidKeyStore"
        private const val WRAP_ALIAS = "pqc_pdf_sign_wrapping_key_v1"
        private const val GCM_TAG_BITS = 128
        private const val IV_LEN = 12
    }

    fun hasKey(): Boolean = vaultFile.exists()

    /** Creates the Keystore wrapping key if absent. requireAuth gates use of
     *  the key behind a recent device unlock / biometric. */
    fun ensureWrappingKey(requireAuth: Boolean) {
        val ks = KeyStore.getInstance(KS).apply { load(null) }
        if (ks.containsAlias(WRAP_ALIAS)) return

        val spec = KeyGenParameterSpec.Builder(
            WRAP_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).apply {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setKeySize(256)
            setRandomizedEncryptionRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setUnlockedDeviceRequired(true)
                // Prefer StrongBox; fall back handled by catch in generate().
                setIsStrongBoxBacked(true)
            }
            if (requireAuth) {
                setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(30, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                }
            }
        }.build()

        try {
            generate(spec)
        } catch (_: Exception) {
            // No StrongBox on this device — retry without it.
            val fallback = KeyGenParameterSpec.Builder(
                WRAP_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            ).apply {
                setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                setKeySize(256)
                setRandomizedEncryptionRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setUnlockedDeviceRequired(true)
                if (requireAuth) setUserAuthenticationRequired(true)
            }.build()
            generate(fallback)
        }
    }

    private fun generate(spec: KeyGenParameterSpec) {
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KS)
        kg.init(spec)
        kg.generateKey()
    }

    private fun wrappingKey(): SecretKey {
        val ks = KeyStore.getInstance(KS).apply { load(null) }
        return (ks.getEntry(WRAP_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
    }

    /** securityLevel reports where the wrapping key lives: "strongbox",
     *  "tee", or "software" (Rencana V1 §12.2 — record TEE/StrongBox). */
    fun securityLevel(): String {
        return try {
            val key = wrappingKey()
            val factory = SecretKeyFactory.getInstance(key.algorithm, KS)
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
                    when (info.securityLevel) {
                        KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
                        else -> "software"
                    }
                @Suppress("DEPRECATION") info.isInsideSecureHardware -> "tee-or-strongbox"
                else -> "software"
            }
        } catch (_: Exception) {
            "unknown"
        }
    }

    /** Encrypts and stores the PKCS#8 key. Overwrites any existing blob with a
     *  fresh IV. */
    fun store(pkcs8: ByteArray) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())
        val iv = cipher.iv
        val ct = cipher.doFinal(pkcs8)
        val out = ByteArray(1 + iv.size + ct.size)
        out[0] = iv.size.toByte()
        System.arraycopy(iv, 0, out, 1, iv.size)
        System.arraycopy(ct, 0, out, 1 + iv.size, ct.size)
        val tmp = File(vaultFile.parentFile, "device-key.enc.tmp")
        tmp.writeBytes(out)
        if (!tmp.renameTo(vaultFile)) { vaultFile.writeBytes(out); tmp.delete() }
    }

    /** Decrypts the stored key. The caller MUST zero the result after use.
     *  Throws if the Keystore refuses (e.g. auth required and not satisfied)
     *  or the blob is corrupt. */
    fun load(): ByteArray {
        val raw = vaultFile.readBytes()
        require(raw.isNotEmpty()) { "vault empty" }
        val ivLen = raw[0].toInt()
        require(ivLen in 12..16 && raw.size > 1 + ivLen) { "vault blob malformed" }
        val iv = raw.copyOfRange(1, 1 + ivLen)
        val ct = raw.copyOfRange(1 + ivLen, raw.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ct)
    }

    /** Removes the encrypted blob and the Keystore wrapping key (§12.3 reset /
     *  lost-key recovery). */
    fun reset() {
        vaultFile.delete()
        runCatching {
            KeyStore.getInstance(KS).apply { load(null) }.deleteEntry(WRAP_ALIAS)
        }
    }
}
