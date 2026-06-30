package com.tgproxy.checker

import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.Locale

enum class ProxyType { MTPROTO, SOCKS5 }

data class ProxyItem(
    val type: ProxyType,
    val host: String,
    val port: Int,
    val secret: String? = null,
    val user: String? = null,
    val pass: String? = null,
    val originalUrl: String,
    var ping: Long = -1,
    var status: String = "Waiting" // "Waiting", "Checking", "Working", "Failed"
)

object ProxyChecker {

    // آی‌پی یکی از سرورهای هسته مرکزی تلگرام برای ارزیابی صحت مسیردهی پروکسی‌های SOCKS5
    private const val TELEGRAM_TEST_IP = "91.108.56.111"
    private const val TELEGRAM_TEST_PORT = 443

    /**
     * تحلیل و پارس انواع مختلف لینک‌های پروکسی تلگرام
     */
    fun parseProxy(url: String): ProxyItem? {
        try {
            val cleaned = url.trim()
            if (cleaned.isEmpty()) return null

            if (cleaned.startsWith("tg://proxy") || cleaned.contains("t.me/proxy")) {
                val corrected = cleaned.replace("https://t.me/proxy", "tg://proxy")
                    .replace("http://t.me/proxy", "tg://proxy")
                val uri = Uri.parse(corrected)
                val server = uri.getQueryParameter("server") ?: return null
                val port = uri.getQueryParameter("port")?.toIntOrNull() ?: return null
                val secret = uri.getQueryParameter("secret") ?: return null
                return ProxyItem(ProxyType.MTPROTO, server, port, secret = secret, originalUrl = cleaned)
            } else if (cleaned.startsWith("tg://socks") || cleaned.contains("t.me/socks")) {
                val corrected = cleaned.replace("https://t.me/socks", "tg://socks")
                    .replace("http://t.me/socks", "tg://socks")
                val uri = Uri.parse(corrected)
                val server = uri.getQueryParameter("server") ?: return null
                val port = uri.getQueryParameter("port")?.toIntOrNull() ?: return null
                val user = uri.getQueryParameter("user")
                val pass = uri.getQueryParameter("pass")
                return ProxyItem(ProxyType.SOCKS5, server, port, user = user, pass = pass, originalUrl = cleaned)
            } else if (cleaned.startsWith("socks5://", ignoreCase = true) || cleaned.startsWith("socks://", ignoreCase = true)) {
                val uri = Uri.parse(cleaned)
                val server = uri.host ?: return null
                val port = if (uri.port != -1) uri.port else 1080
                val userInfo = uri.userInfo?.split(":")
                val user = userInfo?.getOrNull(0)
                val pass = userInfo?.getOrNull(1)
                
                // فرمت استاندارد خروجی برای تلگرام
                val tgFormat = "tg://socks?server=$server&port=$port" +
                        (if (user != null) "&user=$user" else "") +
                        (if (pass != null) "&pass=$pass" else "")
                return ProxyItem(ProxyType.SOCKS5, server, port, user = user, pass = pass, originalUrl = tgFormat)
            }
        } catch (e: Exception) {
            // خطای پارس لینک متنی
        }
        return null
    }

    /**
     * تست بومی کانکشن پروکسی بهینه‌سازی شده با سوکت‌های سطح پایین جاوا
     */
    suspend fun checkSingleProxy(proxy: ProxyItem, timeoutMs: Int): ProxyItem = withContext(Dispatchers.IO) {
        proxy.status = "Checking"
        val start = System.currentTimeMillis()
        var socket: Socket? = null
        try {
            if (proxy.type == ProxyType.SOCKS5) {
                // برای SOCKS5، یک اتصال واقعی از کانال پروکسی به سمت آی‌پی تلگرام برقرار می‌شود
                val socksProxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(proxy.host, proxy.port))
                socket = Socket(socksProxy)
                socket.connect(InetSocketAddress(TELEGRAM_TEST_IP, TELEGRAM_TEST_PORT), timeoutMs)
                proxy.ping = System.currentTimeMillis() - start
                proxy.status = "Working"
            } else {
                // برای پروکسی‌های MTProto، کانکشن مستقیم به خود سرور میزبان تست می‌شود
                socket = Socket()
                socket.connect(InetSocketAddress(proxy.host, proxy.port), timeoutMs)
                proxy.ping = System.currentTimeMillis() - start
                proxy.status = "Working"
            }
        } catch (e: Exception) {
            proxy.status = "Failed"
            proxy.ping = -1
        } finally {
            try {
                socket?.close()
            } catch (ignored: Exception) {}
        }
        proxy
    }
}
