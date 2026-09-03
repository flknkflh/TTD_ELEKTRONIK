package id.example.pqcsign.app

import android.content.Context

/** Non-secret local bookkeeping (Rencana V1 §18-equivalent for the client). */
class AppState(context: Context) {
    private val sp = context.applicationContext.getSharedPreferences("pqc_state", Context.MODE_PRIVATE)

    var serverUrl: String
        get() = sp.getString("server_url", "https://10.0.2.2:8443") ?: ""
        set(v) = sp.edit().putString("server_url", v).apply()

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

    var requireAuth: Boolean
        get() = sp.getBoolean("require_auth", true)
        set(v) = sp.edit().putBoolean("require_auth", v).apply()

    fun clear() = sp.edit().clear().apply()
}
