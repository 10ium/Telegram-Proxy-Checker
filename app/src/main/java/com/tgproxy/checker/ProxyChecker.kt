package com.tgproxy.checker

import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

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
        try {
            if (proxy.type == ProxyType.SOCKS5) {
                // برای SOCKS5، یک اتصال واقعی از کانال پروکسی به سمت آی‌پی تلگرام برقرار می‌شود
                val socksProxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(proxy.host, proxy.port))
                val socket = Socket()
                val start = System.currentTimeMillis()
                socket.connect(InetSocketAddress(proxy.host, proxy.port), timeoutMs)
                
                // برقراری سوکت از بستر پروکسی به مقصد دیتاسنتر آزمایشی تلگرام
                val tunneledSocket = Socket(socksProxy)
                tunneledSocket.connect(InetSocketAddress(TELEGRAM_TEST_IP, TELEGRAM_TEST_PORT), timeoutMs)
                
                proxy.ping = System.currentTimeMillis() - start
                proxy.status = "Working"
                try { tunneledSocket.close() } catch (ignored: Exception) {}
                try { socket.close() } catch (ignored: Exception) {}
            } else {
                // برای پروکسی‌های MTProto، دست‌تکانی رمزگذاری شده واقعی و بومی برقرار می‌شود
                val ping = performMtprotoHandshake(proxy.host, proxy.port, proxy.secret ?: "", timeoutMs)
                if (ping > 0) {
                    proxy.ping = ping
                    proxy.status = "Working"
                } else {
                    proxy.status = "Failed"
                    proxy.ping = -1
                }
            }
        } catch (e: Exception) {
            proxy.status = "Failed"
            proxy.ping = -1
        }
        proxy
    }

    /**
     * برقراری ارتباط با پکیج دست‌تکانی شبیه‌ساز رمزگذاری تلگرام (Obfuscated2)
     */
    private fun performMtprotoHandshake(host: String, port: Int, secretHex: String, timeoutMs: Int): Long {
        val start = System.currentTimeMillis()
        var socket: Socket? = null
        try {
            val rawSecret = parseSecret(secretHex)
            if (rawSecret.size != 16) return -1

            socket = Socket()
            socket.connect(InetSocketAddress(host, port), timeoutMs)
            socket.soTimeout = timeoutMs

            // تولید بافر اولیه ۶۴ بایتی
            val random = SecureRandom()
            val initBuffer = ByteArray(64)
            
            while (true) {
                random.nextBytes(initBuffer)
                val val0 = initBuffer[0].toInt() and 0xFF
                val val4 = (initBuffer[4].toInt() and 0xFF) or 
                           (initBuffer[5].toInt() and 0xFF shl 8) or 
                           (initBuffer[6].toInt() and 0xFF shl 16) or 
                           (initBuffer[7].toInt() and 0xFF shl 24)
                           
                if (val0 != 0xef && val4 != 0x00000000 && val4 != 0xefefefef && val4 != 0x44444444) {
                    break
                }
            }

            // تنظیم پروتکل همگام‌سازی (Padded Intermediate)
            initBuffer[56] = 0xdd.toByte()
            initBuffer[57] = 0xdd.toByte()
            initBuffer[58] = 0xdd.toByte()
            initBuffer[59] = 0xdd.toByte()

            // تنظیم شناسه دیتاسنتر آزمایشی (DC 2)
            initBuffer[60] = 0xfe.toByte()
            initBuffer[61] = 0xff.toByte()

            // مشتق‌سازی کلید متقارن برای رمزگذاری هدر
            val keyBytes = ByteArray(32)
            System.arraycopy(initBuffer, 8, keyBytes, 0, 32)
            
            val md = MessageDigest.getInstance("SHA-256")
            md.update(keyBytes)
            md.update(rawSecret)
            val encryptKey = md.digest()

            val encryptIv = ByteArray(16)
            System.arraycopy(initBuffer, 40, encryptIv, 0, 16)

            // رمزگذاری بافر با الگوریتم AES-CTR
            val cipher = Cipher.getInstance("AES/CTR/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encryptKey, "AES"), IvParameterSpec(encryptIv))
            val encryptedInit = cipher.doFinal(initBuffer)

            System.arraycopy(encryptedInit, 56, initBuffer, 56, 8)

            // ارسال هدر به سمت پروکسی سرور
            val out = socket.getOutputStream()
            out.write(initBuffer)
            out.flush()

            // دریافت پاسخ ۶۴ بایتی معتبر از پروکسی
            val input = socket.getInputStream()
            val responseBuffer = ByteArray(64)
            var bytesRead = 0
            while (bytesRead < 64) {
                val read = input.read(responseBuffer, bytesRead, 64 - bytesRead)
                if (read == -1) break
                bytesRead += read
            }

            if (bytesRead == 64) {
                return System.currentTimeMillis() - start
            }
        } catch (e: Exception) {
            // خطا
        } finally {
            try { socket?.close() } catch (ignored: Exception) {}
        }
        return -1
    }

    private fun parseSecret(secretHex: String): ByteArray {
        val clean = secretHex.trim().lowercase()
        val hex = if (clean.startsWith("ee") || clean.startsWith("dd")) {
            if (clean.length >= 34) clean.substring(2, 34) else clean
        } else {
            clean
        }
        return hexToBytes(hex)
    }

    private fun hexToBytes(hex: String): ByteArray {
        val l = hex.length
        val data = ByteArray(l / 2)
        var i = 0
        try {
            while (i < l) {
                val firstDigit = Character.digit(hex[i], 16)
                val secondDigit = Character.digit(hex[i + 1], 16)
                if (firstDigit == -1 || secondDigit == -1) {
                    return ByteArray(0)
                }
                data[i / 2] = ((firstDigit shl 4) + secondDigit).toByte()
                i += 2
            }
        } catch (e: Exception) {
            return ByteArray(0)
        }
        return data
    }
}
