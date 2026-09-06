package com.yanhul.harnessbridge

import android.Manifest
import android.app.Activity
import android.os.Bundle
import android.content.pm.PackageManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.view.ViewGroup
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

class MainActivity : Activity() {
    private val requestCode = 42

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val endpoint = EditText(this).apply { hint = "https://gateway.example.com"; setText(SecureConfig.endpoint(this@MainActivity).orEmpty()) }
        val token = EditText(this).apply { hint = "Android gateway token"; setText(SecureConfig.token(this@MainActivity).orEmpty()); inputType = 0x00000081 }
        val phone = EditText(this).apply { hint = "Authorized phone (+country...)"; setText(SecureConfig.phone(this@MainActivity).orEmpty()) }
        val status = TextView(this).apply { text = "Configure gateway, then grant SMS permissions." }
        val save = Button(this).apply {
            text = "Save configuration"
            setOnClickListener {
                try {
                    require(endpoint.text.toString().startsWith("https://")) { "HTTPS endpoint required" }
                    require(token.text.isNotBlank()) { "Gateway token required" }
                    SecureConfig.save(this@MainActivity, endpoint.text.toString(), token.text.toString(), phone.text.toString())
                    status.text = "Saved. Bridge is ready: ${SecureConfig.ready(this@MainActivity)}"
                } catch (e: IllegalArgumentException) { status.text = e.message.orEmpty() }
            }
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 48, 32, 32)
            addView(TextView(this@MainActivity).apply { text = "Harness Gateway SMS Bridge" })
            addView(endpoint, lp())
            addView(token, lp())
            addView(phone, lp())
            addView(save, lp())
            addView(status, lp())
        }
        setContentView(root)
        requestSmsPermissions()
    }

    private fun requestSmsPermissions() {
        val needed = arrayOf(Manifest.permission.RECEIVE_SMS, Manifest.permission.SEND_SMS)
            .filter { ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }
        if (needed.isNotEmpty()) ActivityCompat.requestPermissions(this, needed.toTypedArray(), requestCode)
    }

    private fun lp() = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { setMargins(0, 12, 0, 12) }
}
