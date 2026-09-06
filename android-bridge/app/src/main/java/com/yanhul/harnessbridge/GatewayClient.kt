package com.yanhul.harnessbridge

import android.content.Context
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI

object GatewayClient {
    data class Result(val code: Int, val body: String)

    fun sendCommand(context: Context, sender: String, text: String): Result {
        val base = SecureConfig.endpoint(context) ?: error("bridge endpoint not configured")
        val token = SecureConfig.token(context) ?: error("bridge token not configured")
        val uri = URI.create("$base/sms/command")
        require(uri.scheme == "https") { "gateway endpoint must use HTTPS" }

        val payload = JSONObject().put("text", text).toString()
        val connection = (uri.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 10_000
            readTimeout = 10_000
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("X-Gateway-Token", token)
            setRequestProperty("X-SMS-Sender", sender)
        }
        return try {
            connection.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
            val stream = if (connection.responseCode in 200..399) connection.inputStream else connection.errorStream
            val body = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
            Result(connection.responseCode, body.take(1000))
        } finally {
            connection.disconnect()
        }
    }
}
