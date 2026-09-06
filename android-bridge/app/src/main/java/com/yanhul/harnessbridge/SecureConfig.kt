package com.yanhul.harnessbridge

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys

object SecureConfig {
    private const val PREFS = "bridge_secure"
    private const val ENDPOINT = "endpoint"
    private const val TOKEN = "token"
    private const val PHONE = "phone"

    private fun prefs(context: Context) = EncryptedSharedPreferences.create(
        PREFS,
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
        context,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun save(context: Context, endpoint: String, token: String, phone: String) {
        prefs(context).edit()
            .putString(ENDPOINT, endpoint.trim().trimEnd('/'))
            .putString(TOKEN, token.trim())
            .putString(PHONE, phone.trim())
            .apply()
    }

    fun endpoint(context: Context): String? = prefs(context).getString(ENDPOINT, null)
    fun token(context: Context): String? = prefs(context).getString(TOKEN, null)
    fun phone(context: Context): String? = prefs(context).getString(PHONE, null)
    fun ready(context: Context): Boolean = !endpoint(context).isNullOrBlank() && !token(context).isNullOrBlank()
}
