package com.tgproxy.checker

import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

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
     * استخراج هوشمند و پاک‌سازی پروکسی‌ها از متن‌های به‌هم‌ریخته، نامنظم و فاقد ساختار
     */
    fun extractProxiesFromText(text: String): List<ProxyItem> {
        if (text.trim().isEmpty()) return emptyList()
        
        // الگوی هوشمند شناسایی لینک‌های معتبر پروکسی در میان متون نامنظم و تبلیغاتی
        val proxyRegex = Regex(
            """(?i)(tg://proxy\?[^\s"'\n\r<>]+|https?://(?:t\.me|telegram\.me)/proxy\?[^\s"'\n\r<>]+|tg://socks\?[^\s"'\n\r<>]+|https?://(?:t\.me|telegram\.me)/socks\?[^\s"'\n\r<>]+|socks5?://[^\s"'\n\r<>]+)"""
        )
        val matches = proxyRegex.findAll(text)
        val rawList = matches.mapNotNull { parseProxy(it.value) }.toList()
        
        // حذف تکراری‌ها بر اساس زوج سرور، پورت و سکرت جهت بهینه‌سازی سرعت تست فرآیند
        return rawList.distinctBy { 
            if (it.type == ProxyType.MTPROTO) "${it.host}:${it.port}:${it.secret}"
            else "${it.host}:${it.port}:${it.user}:${it.pass}"
        }
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
                var secret = uri.getQueryParameter("secret") ?: return null
                
                // پاک‌سازی پیشرفته سکرت مطابق با منطق کارآمد پروژه Go
                secret = secret.split("**")[0].split("#")[0]
                secret = secret.trimEnd(')', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '`', '~', '[', ']', '{', '}', '|', ';', ':', '\'', ',', '.', '<', '>', '?', '/', ' ', '\t', '\n', '\r')
                
                if (secret.isEmpty()) return null
                
                val cleanUrl = "tg://proxy?server=$server&port=$port&secret=$secret"
                return ProxyItem(ProxyType.MTPROTO, server, port, secret = secret, originalUrl = cleanUrl)
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
        try {
            if (proxy.type == ProxyType.SOCKS5) {
                val start = System.currentTimeMillis()
                
                // اتصال مستقیم و تونل کردن سوکت SOCKS5 به دیتاسنتر واقعی تلگرام
                val socksProxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(proxy.host, proxy.port))
                val socket = Socket(socksProxy)
                socket.soTimeout = timeoutMs
                socket.connect(InetSocketAddress(TELEGRAM_TEST_IP, TELEGRAM_TEST_PORT), timeoutMs)
                
                proxy.ping = System.currentTimeMillis() - start
                proxy.status = "Working"
                try { socket.close() } catch (ignored: Exception) {}
            } else {
                // تست دقیق MTProto با شبیه‌سازی handshake و ارسال پکت req_pq_multi به DC واقعی
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
        }
        proxy
    }

    /**
     * شبیه‌سازی کامل و دقیق رمزنگاری MTProto، ارسال req_pq_multi و دریافت resPQ برای صحت‌سنجی نهایی با سرور تلگرام
     */
    private fun checkMtProtoProxy(host: String, port: Int, secretHex: String, timeoutMs: Int): Long {
        val start = System.currentTimeMillis()
        val cleanSecret = secretHex.trim().lowercase()

        val isFakeTls = cleanSecret.startsWith("ee") && cleanSecret.length > 34
        var rawSocket: Socket? = null
        var socketToUse: Socket? = null

        try {
            rawSocket = Socket()
            rawSocket.soTimeout = timeoutMs
            rawSocket.connect(InetSocketAddress(host, port), timeoutMs)

            socketToUse = if (isFakeTls) {
                val domainHex = cleanSecret.substring(34)
                val domainBytes = hexToBytes(domainHex)
                if (domainBytes.isEmpty()) return -1L
                val domain = String(domainBytes, Charsets.UTF_8).trim()

                val sslSocket = sslSocketFactory.createSocket(rawSocket, host, port, true) as SSLSocket
                sslSocket.soTimeout = timeoutMs

                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                    val sslParams = sslSocket.sslParameters
                    sslParams.serverNames = listOf(javax.net.ssl.SNIHostName(domain))
                    sslSocket.sslParameters = sslParams
                }

                sslSocket.startHandshake()
                sslSocket
            } else {
                rawSocket
            }

            // رمزگشایی سکرت
            val rawSecret = parseSecret(cleanSecret)
            if (rawSecret.size != 16) return -1L

            // تولید بایت‌های اولیه تصادفی هدر Obfuscated2 (۶۴ بایتی)
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

            // استفاده از پروتکل استاندارد Padded-Intermediate (0xdddddddd) برای پشتیبانی حداکثری پروکسی‌ها
            initBuffer[56] = 0xdd.toByte()
            initBuffer[57] = 0xdd.toByte()
            initBuffer[58] = 0xdd.toByte()
            initBuffer[59] = 0xdd.toByte()

            // هدایت به دیتاسنتر ۲ تولیدی تلگرام (DC 2 Production، به صورت علامت‌دار و لیتل-اندین: -2 معادل 0xfe 0xff)
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

            val encryptCipher = Cipher.getInstance("AES/CTR/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(encryptKey, "AES"), IvParameterSpec(encryptIv))
            }

            // رمزنگاری ۸ بایت پایانی هدر
            val encrypted8 = encryptCipher.update(initBuffer, 56, 8)
            System.arraycopy(encrypted8, 0, initBuffer, 56, 8)

            // ارسال هدر هندی‌شیک به سوکت
            val out = socketToUse.getOutputStream()
            out.write(initBuffer)
            out.flush()

            // دریافت هدر هندی‌شیک پاسخ سرور (۶۴ بایت)
            val input = socketToUse.getInputStream()
            val responseBuffer = ByteArray(64)
            var bytesRead = 0
            while (bytesRead < 64) {
                val read = input.read(responseBuffer, bytesRead, 64 - bytesRead)
                if (read == -1) return -1L
                bytesRead += read
            }

            // استخراج کلید و بردار رمزی معکوس برای دریافت (Decryption)
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

            val decryptCipher = Cipher.getInstance("AES/CTR/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(decryptKey, "AES"), IvParameterSpec(decryptIv))
            }

            // رفع باگ بحرانی: رمزگشایی هندی‌شیک سرور باید دقیقاً از آفست ۵۶ شروع شود تا همگام‌سازی کلید AES خراب نشود
            val decrypted8 = decryptCipher.update(responseBuffer, 56, 8)
            System.arraycopy(decrypted8, 0, responseBuffer, 56, 8)

            // راستی‌آزمایی پروتکل هندی‌شیک پاسخ پروکسی (باید 0xdd, 0xee یا 0xef باشد)
            val protoByte = responseBuffer[56]
            if (protoByte != 0xdd.toByte() && protoByte != 0xee.toByte() && protoByte != 0xef.toByte()) {
                return -1L
            }
            if (responseBuffer[57] != protoByte || responseBuffer[58] != protoByte || responseBuffer[59] != protoByte) {
                return -1L
            }

            // --- ارسال درخواست req_pq_multi برای راستی‌آزمایی در سطح دیتاسنترهای تلگرام ---
            val msgId = ((System.currentTimeMillis() / 1000) shl 32) and -4L
            val nonce = ByteArray(16).apply { random.nextBytes(this) }
            
            val tlBody = ByteBuffer.allocate(20).apply {
                order(ByteOrder.LITTLE_ENDIAN)
                putInt(0xbe7e8ef1.toInt()) // constructor_id
                put(nonce)
            }.array()

            val unencryptedMsg = ByteBuffer.allocate(20 + tlBody.size).apply {
                order(ByteOrder.LITTLE_ENDIAN)
                putLong(0L) // auth_key_id
                putLong(msgId) // msg_id
                putInt(tlBody.size) // body size (20)
                put(tlBody)
            }.array()

            // بسته‌بندی بر مبنای فریم Padded-Intermediate: [اندازه دیتا: ۴ بایت] [دیتا] [پدینگ رندوم]
            val payload = unencryptedMsg
            val paddingLen = 4
            val padding = ByteArray(paddingLen).apply { random.nextBytes(this) }
            val totalLength = payload.size + paddingLen

            val frame = ByteBuffer.allocate(4 + totalLength).apply {
                order(ByteOrder.LITTLE_ENDIAN)
                putInt(totalLength)
                put(payload)
                put(padding)
            }.array()

            // رمزنگاری فریم و ارسال به سوکت
            val encryptedFrame = encryptCipher.update(frame)
            out.write(encryptedFrame)
            out.flush()

            // خواندن هدر فریم دریافتی (۴ بایت طول فریم)
            val lenBuffer = ByteArray(4)
            var lenBytesRead = 0
            while (lenBytesRead < 4) {
                val read = input.read(lenBuffer, lenBytesRead, 4 - lenBytesRead)
                if (read == -1) return -1L
                lenBytesRead += read
            }
            val decryptedLenBuffer = decryptCipher.update(lenBuffer)
            val responseLen = ByteBuffer.wrap(decryptedLenBuffer).order(ByteOrder.LITTLE_ENDIAN).int

            if (responseLen <= 0 || responseLen > 65536) {
                return -1L
            }

            // خواندن کل بدنه فریم پاسخ
            val responsePayload = ByteArray(responseLen)
            var payloadBytesRead = 0
            while (payloadBytesRead < responseLen) {
                val read = input.read(responsePayload, payloadBytesRead, responseLen - payloadBytesRead)
                if (read == -1) return -1L
                payloadBytesRead += read
            }
            val decryptedPayload = decryptCipher.update(responsePayload)

            // بررسی سلامت پاسخ دریافتی در قالب پکت unencrypted تلگرام
            if (decryptedPayload.size < 24) {
                return -1L
            }
            val wrapBuffer = ByteBuffer.wrap(decryptedPayload).order(ByteOrder.LITTLE_ENDIAN)
            val responseAuthKeyId = wrapBuffer.getLong(0)
            if (responseAuthKeyId != 0L) {
                return -1L
            }
            val responseConstructorId = wrapBuffer.getInt(20)
            
            if (responseConstructorId == 0x05162463) { // resPQ شناسه سازنده تایید موفق تلگرام
                return System.currentTimeMillis() - start
            }

        } catch (e: Exception) {
            // هندشیک ناموفق
        } finally {
            try { socketToUse?.close() } catch (ignored: Exception) {}
            try { rawSocket?.close() } catch (ignored: Exception) {}
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
        if (l % 2 != 0) {
            return try {
                android.util.Base64.decode(hex, android.util.Base64.DEFAULT or android.util.Base64.NO_PADDING or android.util.Base64.URL_SAFE)
            } catch (e: Exception) {
                ByteArray(0)
            }
        }
        val data = ByteArray(l / 2)
        var i = 0
        try {
            while (i < l) {
                val firstDigit = Character.digit(hex[i], 16)
                val secondDigit = Character.digit(hex[i + 1], 16)
                if (firstDigit == -1 || secondDigit == -1) {
                    return android.util.Base64.decode(hex, android.util.Base64.DEFAULT or android.util.Base64.NO_PADDING or android.util.Base64.URL_SAFE)
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
