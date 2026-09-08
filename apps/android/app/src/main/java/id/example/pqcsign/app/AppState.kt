package id.example.pqcsign.app

import android.content.Context

/** Non-secret local bookkeeping (Rencana V1 §18-equivalent for the client). */
class AppState(context: Context) {
    private val sp = context.applicationContext.getSharedPreferences("pqc_state", Context.MODE_PRIVATE)

    var serverUrl: String
        // Default matches tools/dev-up.sh (plain HTTP on :8099). For a TLS
        // server (Caddy) use https:// and keep insecureTls on for a lab cert.
        get() = sp.getString("server_url", "http://10.0.2.2:8099") ?: ""
        set(v) = sp.edit().putString("server_url", v.trim().trimEnd('/'))
            .apply()

    var insecureTls: Boolean
        get() = sp.getBoolean("insecure_tls", true)
        set(v) = sp.edit().putBoolean("insecure_tls", v).apply()

    var accountEmail: String?
        get() = sp.getString("account_email", null)
        set(v) = sp.edit().putString("account_email", v).apply()

    var deviceId: String?
        get() = sp.getString("device_id", null)
        set(v) = sp.edit().putString("device_id", v).apply()

    var enrollmentId: String?
        get() = sp.getString("enrollment_id", null)
        set(v) = sp.edit().putString("enrollment_id", v).apply()

    var certificateSerial: String?
        get() = sp.getString("cert_serial", null)
        set(v) = sp.edit().putString("cert_serial", v).apply()

    // Default false in the RB flow: enrolment runs silently right after login
    // (no BiometricPrompt yet), so the wrapping key must be usable without a
    // fresh auth. The app still shows a BiometricPrompt before every signature.
    // Set true to additionally bind the key to biometric/PIN at the Keystore.
    var requireAuth: Boolean
        get() = sp.getBoolean("require_auth", false)
        set(v) = sp.edit().putBoolean("require_auth", v).apply()

    fun clear() = sp.edit().clear().apply()
}
