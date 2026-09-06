package com.yanhul.harnessbridge

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.telephony.SmsManager
import android.telephony.SmsMessage
import java.util.concurrent.Executors

class SmsReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != "android.provider.Telephony.SMS_RECEIVED") return
        val pending = goAsync()
        val snapshot = context.applicationContext
        val bundle: Bundle = intent.extras ?: run { pending.finish(); return }
        val pdus = bundle.get("pdus") as? Array<*> ?: run { pending.finish(); return }
        val format = bundle.getString("format")
        val messages = pdus.mapNotNull { pdu ->
            try { SmsMessage.createFromPdu(pdu as ByteArray, format) } catch (_: Exception) { null }
        }
        if (messages.isEmpty()) { pending.finish(); return }

        val sender = messages.first().originatingAddress ?: run { pending.finish(); return }
        val text = messages.joinToString(separator = "") { it.messageBody.orEmpty() }.trim()
        if (!isCommand(text)) { pending.finish(); return }

        Executors.newSingleThreadExecutor().execute {
            try {
                if (!SecureConfig.ready(snapshot)) return@execute
                val result = GatewayClient.sendCommand(snapshot, sender, text)
                // Never expose gateway credentials or full internal records by SMS.
                val reply = when (result.code) {
                    in 200..299 -> "Gateway OK: ${result.body.take(700)}"
                    else -> "Gateway ERROR ${result.code}: ${result.body.take(500)}"
                }
                if (SecureConfig.phone(snapshot).isNullOrBlank() || SecureConfig.phone(snapshot) == sender) {
                    SmsManager.getDefault().sendTextMessage(sender, null, reply, null, null)
                }
            } finally {
                pending.finish()
            }
        }
    }

    private fun isCommand(text: String): Boolean {
        val cmd = text.substringBefore(' ').uppercase()
        return cmd in setOf("SUA", "BOQUA", "RETRY", "STATUS", "STOP")
    }
}
