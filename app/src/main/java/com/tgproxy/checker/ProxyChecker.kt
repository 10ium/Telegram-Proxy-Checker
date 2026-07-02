package com.tgproxy.checker

import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
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

    // آی‌پی یکی از سرورهای هسته مرکزی تلگرام برای ارزیابی صحت مسیردهی پروکسی‌ها
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
        
        // فاز اول: پیش‌ارزیابی سریع اتصال TCP جهت مسدود نشدن ترد روی پروکسی‌های مرده
        val tcpTimeout = minOf(timeoutMs, 1500)
        if (!isTcpReachable(proxy.host, proxy.port, tcpTimeout)) {
            proxy.status = "Failed"
            proxy.ping = -1
            return@withContext proxy
        }

        // فاز دوم: شبیه‌سازی دقیق و کامل پروتکل‌ها
        try {
            if (proxy.type == ProxyType.SOCKS5) {
                val resultPing = checkSocks5Proxy(proxy, timeoutMs)
                if (resultPing > 0L) {
                    proxy.ping = resultPing
                    proxy.status = "Working"
                } else {
                    proxy.status = "Failed"
                    proxy.ping = -1
                }
            } else {
                // تست دقیق MTProto با شبیه‌سازی handshake و ارسال پکت req_pq_multi به دیتاسنتر واقعی
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
     * ارزیابی دسترسی اولیه پورت TCP
     */
    private fun isTcpReachable(host: String, port: Int, timeoutMs: Int): Boolean {
        var socket: Socket? = null
        return try {
            socket = Socket()
            socket.connect(InetSocketAddress(host, port), timeoutMs)
            true
        } catch (e: Exception) {
            false
        } finally {
            try { socket?.close() } catch (ignored: Exception) {}
        }
    }

    /**
     * شبیه‌سازی کامل و نخ‌امن (Thread-Safe) ارتباط SOCKS5 بدون دستکاری تنظیمات گلوبال JVM
     */
    private fun checkSocks5Proxy(proxy: ProxyItem, timeoutMs: Int): Long {
        val start = System.currentTimeMillis()
        var socket: Socket? = null
        try {
            socket = Socket()
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(proxy.host, proxy.port), timeoutMs)

            val out = socket.getOutputStream()
            val input = socket.getInputStream()

            // ۱. ارسال سیگنال اولیه SOCKS5
            val hasAuth = !proxy.user.isNullOrEmpty()
            if (hasAuth) {
                out.write(byteArrayOf(0x05, 0x02, 0x00, 0x02)) // پشتیبانی از No-Auth و User/Pass
            } else {
                out.write(byteArrayOf(0x05, 0x01, 0x00)) // پشتیبانی فقط از No-Auth
            }
            out.flush()

            // ۲. دریافت پاسخ احراز هویت سرور
            val greetingRes = ByteArray(2)
            if (readFully(input, greetingRes) != 2 || greetingRes[0] != 0x05.toByte()) {
                return -1L
            }

            val selectedMethod = greetingRes[1].toInt() and 0xFF
            if (selectedMethod == 0x02) {
                // ارسال اطلاعات احراز هویت به سرور
                val userBytes = proxy.user!!.toByteArray(Charsets.UTF_8)
                val passBytes = (proxy.pass ?: "").toByteArray(Charsets.UTF_8)

                val authPayload = ByteArray(3 + userBytes.size + passBytes.size)
                authPayload[0] = 0x01 // نسخه پروتکل احراز هویت
                authPayload[1] = userBytes.size.toByte()
                System.arraycopy(userBytes, 0, authPayload, 2, userBytes.size)
                authPayload[2 + userBytes.size] = passBytes.size.toByte()
                System.arraycopy(passBytes, 0, authPayload, 3 + userBytes.size, passBytes.size)

                out.write(authPayload)
                out.flush()

                val authRes = ByteArray(2)
                if (readFully(input, authRes) != 2 || authRes[1] != 0x00.toByte()) {
                    return -1L // تایید اعتبار رد شد
                }
            } else if (selectedMethod != 0x00) {
                return -1L // متد احراز هویت نامعتبر است
            }

            // ۳. برقراری مسیر تونل به سمت سرور تست تلگرام
            val ipParts = TELEGRAM_TEST_IP.split(".").map { it.toInt().toByte() }
            if (ipParts.size != 4) return -1L

            val connPayload = ByteArray(10)
            connPayload[0] = 0x05 // نسخه SOCKS
            connPayload[1] = 0x01 // دستور CONNECT
            connPayload[2] = 0x00 // فیلد رزرو شده
            connPayload[3] = 0x01 // نوع آدرس: IPv4
            connPayload[4] = ipParts[0]
            connPayload[5] = ipParts[1]
            connPayload[6] = ipParts[2]
            connPayload[7] = ipParts[3]
            connPayload[8] = (TELEGRAM_TEST_PORT shr 8).toByte()
            connPayload[9] = (TELEGRAM_TEST_PORT and 0xFF).toByte()

            out.write(connPayload)
            out.flush()

            // ۴. بررسی موفقیت ایجاد تونل
            val connResHead = ByteArray(4)
            if (readFully(input, connResHead) != 4 || connResHead[1] != 0x00.toByte()) {
                return -1L // اتصال در محیط پروکسی امکان‌پذیر نیست
            }

            // رد کردن فیلدهای متغیر آدرس و پورت پاسخ
            val atyp = connResHead[3].toInt() and 0xFF
            val skipLen = when (atyp) {
                0x01 -> 4 + 2 // IPv4 (4) + Port (2)
                0x03 -> {
                    val domainLen = input.read()
                    if (domainLen == -1) return -1L
                    domainLen + 2
                }
                0x04 -> 16 + 2 // IPv6 (16) + Port (2)
                else -> return -1L
            }

            val skipBuf = ByteArray(skipLen)
            if (readFully(input, skipBuf) != skipLen) {
                return -1L
            }

            return System.currentTimeMillis() - start
        } catch (e: Exception) {
            // ایجاد خطا در پردازش
        } finally {
            try { socket?.close() } catch (ignored: Exception) {}
        }
        return -1L
    }

    /**
     * شبیه‌سازی کامل و دقیق رمزنگاری MTProto، ارسال req_pq_multi و دریافت resPQ برای صحت‌سنجی نهایی با سرور تلگرام
     */
    private fun checkMtProtoProxy(host: String, port: Int, secretHex: String, timeoutMs: Int): Long {
        val start = System.currentTimeMillis()

        // دیکد کردن هوشمند سکرت (هگزادسیمال و بیس۶۴)
        val decodedSecret = decodeSecret(secretHex)
        if (decodedSecret.size < 16) return -1L

        val hasPrefix = decodedSecret.size > 16 && (decodedSecret[0] == 0xdd.toByte() || decodedSecret[0] == 0xee.toByte())
        val isFakeTls = decodedSecret.size > 17 && decodedSecret[0] == 0xee.toByte()

        val rawSecret = if (hasPrefix) {
            decodedSecret.copyOfRange(1, 17)
        } else {
            decodedSecret.copyOf(16)
        }

        val domain = if (isFakeTls) {
            val domainBytes = decodedSecret.copyOfRange(17, decodedSecret.size)
            String(domainBytes, Charsets.UTF_8).trim()
        } else {
            ""
        }

        var rawSocket: Socket? = null
        var socketToUse: Socket? = null

        try {
            rawSocket = Socket()
            rawSocket.soTimeout = timeoutMs
            rawSocket.connect(InetSocketAddress(host, port), timeoutMs)

            socketToUse = if (isFakeTls && domain.isNotEmpty()) {
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

            // تولید بایت‌های اولیه تصادفی هدر Obfuscated2 (۶۴ بایتی)
            val random = SecureRandom()
            val initBuffer = ByteArray(64)
            while (true) {
                random.nextBytes(initBuffer)
                
                val val0 = initBuffer[0].toInt() and 0xFF
                if (val0 == 0xef) continue
                
                val firstInt = (initBuffer[0].toInt() and 0xFF) or
                               (initBuffer[1].toInt() and 0xFF shl 8) or
                               (initBuffer[2].toInt() and 0xFF shl 16) or
                               (initBuffer[3].toInt() and 0xFF shl 24)
                               
                if (firstInt == 0xdddddddd.toInt() || 
                    firstInt == 0xeeeeeeee.toInt() || 
                    firstInt == 0xefefefef.toInt() ||
                    firstInt == 0x44444444 || // "DDDD"
                    firstInt == 0x45472020 || // "GET "
                    firstInt == 0x54534f50 || // "POST"
                    firstInt == 0x44414548) { // "HEAD"
                    continue
                }
                
                val secondInt = (initBuffer[4].toInt() and 0xFF) or
                                (initBuffer[5].toInt() and 0xFF shl 8) or
                                (initBuffer[6].toInt() and 0xFF shl 16) or
                                (initBuffer[7].toInt() and 0xFF shl 24)
                if (secondInt == 0) continue
                
                break
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

            // اصلاح اساسی: فرآیند رمزنگاری هدر جهت به‌روزشانی صحیح وضعیت Keystream در حالت CTR کاملاً بازنویسی شد
            val encryptedBuffer = encryptCipher.update(initBuffer)
            System.arraycopy(encryptedBuffer, 56, initBuffer, 56, 8)

            // ارسال هدر هندی‌شیک به سوکت
            val out = socketToUse.getOutputStream()
            out.write(initBuffer)
            out.flush()

            // استخراج کلید و بردار رمزی معکوس برای دریافت کلاینت (Decryption)
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

            // اکنون منتظر بایت‌های پاسخ رمزنگاری‌شده واقعی سرور می‌مانیم
            val input = socketToUse.getInputStream()

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

    /**
     * دیکد کردن جامع سکرت‌ها اعم از فرمت‌های هگزادسیمال و بیس۶۴
     */
    private fun decodeSecret(secretStr: String): ByteArray {
        val clean = secretStr.trim().trimEnd(
            ')', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '`', '~', 
            '[', ']', '{', '}', '|', ';', ':', '\'', ',', '.', '<', '>', '?', '/', ' ', '\t', '\n', '\r'
        ).lowercase()

        // ۱. تلاش برای دیکد کردن به صورت هگزادسیمال
        try {
            if (clean.all { it in "0123456789abcdef" } && clean.length % 2 == 0) {
                val data = ByteArray(clean.length / 2)
                for (i in data.indices) {
                    data[i] = ((Character.digit(clean[i * 2], 16) shl 4) + Character.digit(clean[i * 2 + 1], 16)).toByte()
                }
                return data
            }
        } catch (e: Exception) {
            // انتقال به کاندیدای بعدی
        }

        // ۲. تلاش برای دیکد کردن به صورت بیس۶۴ (فرمت‌های استاندارد و URL Safe)
        val base64Flags = android.util.Base64.DEFAULT or android.util.Base64.NO_PADDING or android.util.Base64.URL_SAFE
        try {
            return android.util.Base64.decode(clean, base64Flags)
        } catch (e: Exception) {
            // انتقال به کاندیدای بعدی
        }
        try {
            return android.util.Base64.decode(clean, android.util.Base64.DEFAULT)
        } catch (e: Exception) {
            // عدم موفقیت نهایی
        }
        return ByteArray(0)
    }

    /**
     * کمکی برای خواندن کامل بایت‌های مدنظر از ورودی سوکت
     */
    private fun readFully(input: java.io.InputStream, buffer: ByteArray): Int {
        var bytesRead = 0
        while (bytesRead < buffer.size) {
            val read = input.read(buffer, bytesRead, buffer.size - bytesRead)
            if (read == -1) break
            bytesRead += read
        }
        return bytesRead
    }
}
