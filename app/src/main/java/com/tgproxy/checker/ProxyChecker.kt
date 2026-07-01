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
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

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

    // پیکربندی TrustManager بدون بررسی سخت‌گیرانه برای پذیرش گواهینامه‌های خودامضا در Fake TLS
    private val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    })

    private val sslSocketFactory by lazy {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, SecureRandom())
        sslContext.socketFactory
    }

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
                
                val tgFormat = "tg://socks?server=$server&port=$port" +
                        (if (user != null) "&user=$user" else "") +
                        (if (pass != null) "&pass=$pass" else "")
                return ProxyItem(ProxyType.SOCKS5, server, port, user = user, pass = pass, originalUrl = tgFormat)
            }
        } catch (e: Exception) {
            // خطا در پارس لینک
        }
        return null
    }

    /**
     * تست بومی کانکشن پروکسی بهینه‌سازی شده با سوکت‌های سطح پایین جاوا
     */
    suspend fun checkSingleProxy(proxy: ProxyItem, timeoutMs: Int): ProxyItem = withContext(Dispatchers.IO) {
        proxy.status = "Checking"
        var socket: Socket? = null
        var tunneledSocket: Socket? = null
        try {
            if (proxy.type == ProxyType.SOCKS5) {
                val start = System.currentTimeMillis()
                
                // بررسی مستقیم در دسترس بودن پورت پروکسی SOCKS5
                socket = Socket()
                socket.soTimeout = timeoutMs
                socket.connect(InetSocketAddress(proxy.host, proxy.port), timeoutMs)
                
                // تونل کردن سوکت به سمت دیتاسنتر آزمایشی واقعی تلگرام
                val socksProxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(proxy.host, proxy.port))
                tunneledSocket = Socket(socksProxy)
                tunneledSocket.soTimeout = timeoutMs
                tunneledSocket.connect(InetSocketAddress(TELEGRAM_TEST_IP, TELEGRAM_TEST_PORT), timeoutMs)
                
                proxy.ping = System.currentTimeMillis() - start
                proxy.status = "Working"
            } else {
                // تست هوشمند انواع پروکسی‌های MTProto (ساده یا Fake TLS)
                val resultPing = checkMtProtoProxy(proxy.host, proxy.port, proxy.secret ?: "", timeoutMs)
                if (resultPing > 0L) {
                    proxy.ping = resultPing
                    proxy.status = "Working"
                } else {
                    proxy.status = "Failed"
                    proxy.ping = -1
                }
            }
        } catch (e: Exception) {
            proxy.status = "Failed"
            proxy.ping = -1
        } finally {
            try { tunneledSocket?.close() } catch (ignored: Exception) {}
            try { socket?.close() } catch (ignored: Exception) {}
        }
        proxy
    }

    /**
     * شبیه‌سازی پروتکل رمزنگاری کانال ارتباطی پروکسی تلگرام
     */
    private fun checkMtProtoProxy(host: String, port: Int, secretHex: String, timeoutMs: Int): Long {
        val start = System.currentTimeMillis()
        val cleanSecret = secretHex.trim().lowercase()

        // ارزیابی اولیه اینکه آیا کانال از نوع Fake TLS است یا ساده
        val isFakeTls = cleanSecret.startsWith("ee") && cleanSecret.length > 34

        if (isFakeTls) {
            // --- فرآیند اعتبارسنجی پروکسی‌های مدرن Fake TLS ---
            var rawSocket: Socket? = null
            var sslSocket: SSLSocket? = null
            try {
                // استخراج دامنه شبیه‌سازی شده فیلترینگ از انتهای سکرت رمز
                val domainHex = cleanSecret.substring(34)
                val domainBytes = hexToBytes(domainHex)
                if (domainBytes.isEmpty()) return -1L
                val domain = String(domainBytes, Charsets.UTF_8).trim()

                rawSocket = Socket()
                rawSocket.connect(InetSocketAddress(host, port), timeoutMs)
                
                sslSocket = sslSocketFactory.createSocket(rawSocket, host, port, true) as SSLSocket
                sslSocket.soTimeout = timeoutMs

                // تنظیم SNI شبیه‌سازی شده در هدر کلاینت هلو برای عبور از DPI فیلترینگ
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                    val sslParams = sslSocket.sslParameters
                    sslParams.serverNames = listOf(java.net.SNIHostName(domain))
                    sslSocket.sslParameters = sslParams
                }

                // انجام دست‌تکانی واقعی TLS با سرور پروکسی
                sslSocket.startHandshake()
                
                // در صورت موفقیت‌آمیز بودن ارتباط امن دوطرفه، اتصال پروکسی معتبر است
                return System.currentTimeMillis() - start
            } catch (e: Exception) {
                // شکست فرآیند ارتباط امن
            } finally {
                try { sslSocket?.close() } catch (ignored: Exception) {}
                try { rawSocket?.close() } catch (ignored: Exception) {}
            }
        } else {
            // --- فرآیند اعتبارسنجی پیشرفته پروکسی‌های MTProto ساده (Obfuscated2) ---
            var socket: Socket? = null
            try {
                val rawSecret = parseSecret(cleanSecret)
                if (rawSecret.size != 16) return -1L

                socket = Socket()
                socket.connect(InetSocketAddress(host, port), timeoutMs)
                socket.soTimeout = timeoutMs

                // تولید بایت‌های اولیه تصادفی ۶۴ تایی هدر
                val random = SecureRandom()
                val initBuffer = ByteArray(64)
                
                while (true) {
                    random.nextBytes(initBuffer)
                    val val0 = initBuffer[0].toInt() and 0xFF
                    val val4 = (initBuffer[4].toInt() and 0xFF) or 
                               (initBuffer[5].toInt() and 0xFF shl 8) or 
                               (initBuffer[6].toInt() and 0xFF shl 16) or 
                               (initBuffer[7].toInt() and 0xFF shl 24)
                               
                    if (val0 != 0xef && val4 != 0x00000000 && val4 != 0xefefefef.toInt() && val4 != 0x44444444) {
                        break
                    }
                }

                // ثبت بایت‌های جفت‌سازی پکت‌ها (Padded Intermediate)
                initBuffer[56] = 0xdd.toByte()
                initBuffer[57] = 0xdd.toByte()
                initBuffer[58] = 0xdd.toByte()
                initBuffer[59] = 0xdd.toByte()

                // اتصال به سرور مرکزی دیتاسنتر آزمایشی تلگرام (DC 2)
                initBuffer[60] = 0xfe.toByte()
                initBuffer[61] = 0xff.toByte()

                // استخراج کلید و بردار رمزی فرستنده (Encryption)
                val keyBytes = ByteArray(32)
                System.arraycopy(initBuffer, 8, keyBytes, 0, 32)
                
                val md = MessageDigest.getInstance("SHA-256")
                md.update(keyBytes)
                md.update(rawSecret)
                val encryptKey = md.digest()

                val encryptIv = ByteArray(16)
                System.arraycopy(initBuffer, 40, encryptIv, 0, 16)

                // رمزنگاری هدر آغازین با AES-CTR
                val cipher = Cipher.getInstance("AES/CTR/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encryptKey, "AES"), IvParameterSpec(encryptIv))
                val encryptedInit = cipher.doFinal(initBuffer)

                System.arraycopy(encryptedInit, 56, initBuffer, 56, 8)

                // ارسال هدر رمزنگاری‌شده به سوکت پروکسی
                val out = socket.getOutputStream()
                out.write(initBuffer)
                out.flush()

                // تلاش برای خواندن ۶۴ بایت هدر پاسخ سرور پروکسی تلگرام
                val input = socket.getInputStream()
                val responseBuffer = ByteArray(64)
                var bytesRead = 0
                while (bytesRead < 64) {
                    val read = input.read(responseBuffer, bytesRead, 64 - bytesRead)
                    if (read == -1) break
                    bytesRead += read
                }

                if (bytesRead == 64) {
                    // محاسبه کلید و بردار رمزگشایی متقارن (Decryption) بر اساس معکوس بافر هدر کلاینت
                    val decryptKeyBytes = ByteArray(32)
                    for (i in 0..31) {
                        decryptKeyBytes[i] = initBuffer[55 - i]
                    }
                    val mdDec = MessageDigest.getInstance("SHA-256")
                    mdDec.update(decryptKeyBytes)
                    mdDec.update(rawSecret)
                    val decryptKey = mdDec.digest()

                    val decryptIv = ByteArray(16)
                    for (i in 0..15) {
                        decryptIv[i] = initBuffer[23 - i]
                    }

                    // رمزگشایی داده‌های دریافتی برای راستی آزمایی
                    val decryptCipher = Cipher.getInstance("AES/CTR/NoPadding")
                    decryptCipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(decryptKey, "AES"), IvParameterSpec(decryptIv))
                    val decrypted = decryptCipher.doFinal(responseBuffer)

                    // راستی آزمایی بایت همگام‌سازی پروتکل تلگرام (باید dd, ee یا ef باشد)
                    val protoByte = decrypted[56]
                    if (protoByte == 0xdd.toByte() || protoByte == 0xee.toByte() || protoByte == 0xef.toByte()) {
                        if (decrypted[57] == protoByte && decrypted[58] == protoByte && decrypted[59] == protoByte) {
                            return System.currentTimeMillis() - start
                        }
                    }
                }
            } catch (e: Exception) {
                // شکست ارتباط
            } finally {
                try { socket?.close() } catch (ignored: Exception) {}
            }
        }
        return -1L
    }

    private fun parseSecret(cleanSecret: String): ByteArray {
        val hex = if (cleanSecret.startsWith("ee") || cleanSecret.startsWith("dd")) {
            if (cleanSecret.length >= 34) cleanSecret.substring(2, 34) else cleanSecret
        } else {
            cleanSecret
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
