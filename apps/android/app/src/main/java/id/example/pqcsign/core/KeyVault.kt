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

    /** Back-compat: create the wrapping key if absent (does not verify it is
     *  usable — prefer createAndStore for the enrol path). */
    fun ensureWrappingKey(requireAuth: Boolean) {
        val ks = KeyStore.getInstance(KS).apply { load(null) }
        if (ks.containsAlias(WRAP_ALIAS) && vaultFile.exists()) return
        runCatching { ks.deleteEntry(WRAP_ALIAS) }
        generate(specs(requireAuth).first())
    }

    /**
     * Creates a wrapping key and stores the PKCS#8 key under it, proving the
     * key is actually usable (some OEMs let a key be *created* with a flag but
     * throw at first *use*). It walks from the §12.2-ideal spec (StrongBox +
     * unlocked-device [+ biometric when requireAuth]) down to a plain
     * non-exportable AndroidKeyStore AES key, so enrolment — which runs
     * silently right after login, before any BiometricPrompt — never
     * dead-ends with "User not authenticated". requireAuth is honoured on
     * every rung: when true, biometric/PIN binding is kept and only the
     * device-state / StrongBox flags are shed.
     */
    fun createAndStore(pkcs8: ByteArray, requireAuth: Boolean) {
        val ks = KeyStore.getInstance(KS).apply { load(null) }
        var last: Exception? = null
        for (spec in specs(requireAuth)) {
            try {
                runCatching { ks.deleteEntry(WRAP_ALIAS) }
                generate(spec)
                store(pkcs8) // real encrypt — surfaces use-time rejections
                return
            } catch (e: Exception) {
                last = e
            }
        }
        runCatching { ks.deleteEntry(WRAP_ALIAS) }
        throw IllegalStateException("KeyVault: no usable AndroidKeyStore wrapping key on this device", last)
    }

    /** Wrapping-key specs, most-hardened first. */
    private fun specs(requireAuth: Boolean): List<KeyGenParameterSpec> {
        val rungs = listOf(
            Pair(true, true),   // StrongBox + unlocked-device
            Pair(false, true),  // TEE + unlocked-device
            Pair(false, false), // TEE, no device-state gate
        )
        return rungs.map { (strongbox, unlockedOnly) ->
            KeyGenParameterSpec.Builder(
                WRAP_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            ).apply {
                setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                setKeySize(256)
                setRandomizedEncryptionRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    if (strongbox) setIsStrongBoxBacked(true)
                    if (unlockedOnly) setUnlockedDeviceRequired(true)
                }
                if (requireAuth) {
                    setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setUserAuthenticationParameters(
                            30, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                        )
                    }
                }
            }.build()
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
