package com.tgproxy.checker

import android.net.Uri
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

enum class ProxyType { MTPROTO, SOCKS5, HTTP, WEBPROXY }

// کلاس داده کاملاً غیرقابل تغییر (Immutable) با شناسه یکتا جهت پیشگیری قطعی از کرش در Jetpack Compose
data class ProxyItem(
    val id: String = UUID.randomUUID().toString(),
    val type: ProxyType,
    val host: String,
    val port: Int,
    val secret: String? = null,
    val user: String? = null,
    val pass: String? = null,
    val originalUrl: String,
    val ping: Long = -1,
    val status: String = "Waiting" // "Waiting", "Checking", "Working", "Failed"
)

object ProxyChecker {

    private const val TELEGRAM_TEST_IP = "91.108.56.111"
    private const val TELEGRAM_TEST_PORT = 443

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
     * استخراج هوشمند و پاک‌سازی هر ۴ نوع پروکسی رسمی تلگرام از متن‌های ورودی
     */
    fun extractProxiesFromText(text: String): List<ProxyItem> {
        if (text.trim().isEmpty()) return emptyList()
        
        val proxyRegex = Regex(
            """(?i)(tg://(?:proxy|socks|http|webproxy)\?[^\s"'\n\r<>]+|https?://(?:t\.me|telegram\.me)/(?:proxy|socks|http|webproxy)\?[^\s"'\n\r<>]+|socks5?://[^\s"'\n\r<>]+)"""
        )
        val matches = proxyRegex.findAll(text)
        val rawList = matches.mapNotNull { parseProxy(it.value) }.toList()
        
        // یکتاسازی بر اساس نوع، سرور، پورت، سکرت و احراز هویت
        return rawList.distinctBy { 
            "${it.type}:${it.host.lowercase()}:${it.port}:${it.secret ?: ""}:${it.user ?: ""}:${it.pass ?: ""}"
        }
    }

    /**
     * تحلیل و پارس ایمن انواع لینک‌های پروکسی تلگرام با اعتبارسنجی محدوده پورت
     */
    fun parseProxy(url: String): ProxyItem? {
        try {
            val cleaned = url.trim()
            if (cleaned.isEmpty()) return null

            // ۱. پروتکل MTProto
            if (cleaned.startsWith("tg://proxy", ignoreCase = true) || cleaned.contains("t.me/proxy", ignoreCase = true)) {
                val corrected = cleaned.replace("https://t.me/proxy", "tg://proxy", ignoreCase = true)
                    .replace("http://t.me/proxy", "tg://proxy", ignoreCase = true)
                val uri = Uri.parse(corrected)
                val server = uri.getQueryParameter("server")?.trim() ?: return null
                val port = uri.getQueryParameter("port")?.toIntOrNull() ?: return null
                if (server.isEmpty() || port !in 1..65535) return null

                var secret = uri.getQueryParameter("secret")?.trim() ?: return null
                secret = secret.split("**")[0].split("#")[0]
                secret = secret.trimEnd(')', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '`', '~', '[', ']', '{', '}', '|', ';', ':', '\'', ',', '.', '<', '>', '?', '/', ' ', '\t', '\n', '\r')
                if (secret.isEmpty()) return null
                
                val cleanUrl = "tg://proxy?server=$server&port=$port&secret=$secret"
                return ProxyItem(type = ProxyType.MTPROTO, host = server, port = port, secret = secret, originalUrl = cleanUrl)
            }
            
            // ۲. پروتکل SOCKS5
            if (cleaned.startsWith("tg://socks", ignoreCase = true) || cleaned.contains("t.me/socks", ignoreCase = true)) {
                val corrected = cleaned.replace("https://t.me/socks", "tg://socks", ignoreCase = true)
                    .replace("http://t.me/socks", "tg://socks", ignoreCase = true)
                val uri = Uri.parse(corrected)
                val server = uri.getQueryParameter("server")?.trim() ?: return null
                val port = uri.getQueryParameter("port")?.toIntOrNull() ?: return null
                if (server.isEmpty() || port !in 1..65535) return null

                val user = uri.getQueryParameter("user")?.trim()
                val pass = uri.getQueryParameter("pass")?.trim()
                val tgFormat = "tg://socks?server=$server&port=$port" +
                        (if (!user.isNullOrEmpty()) "&user=$user" else "") +
                        (if (!pass.isNullOrEmpty()) "&pass=$pass" else "")
                return ProxyItem(type = ProxyType.SOCKS5, host = server, port = port, user = user, pass = pass, originalUrl = tgFormat)
            }
            if (cleaned.startsWith("socks5://", ignoreCase = true) || cleaned.startsWith("socks://", ignoreCase = true)) {
                val uri = Uri.parse(cleaned)
                val server = uri.host?.trim() ?: return null
                val port = if (uri.port != -1) uri.port else 1080
                if (server.isEmpty() || port !in 1..65535) return null

                val userInfo = uri.userInfo?.split(":")
                val user = userInfo?.getOrNull(0)
                val pass = userInfo?.getOrNull(1)
                val tgFormat = "tg://socks?server=$server&port=$port" +
                        (if (!user.isNullOrEmpty()) "&user=$user" else "") +
                        (if (!pass.isNullOrEmpty()) "&pass=$pass" else "")
                return ProxyItem(type = ProxyType.SOCKS5, host = server, port = port, user = user, pass = pass, originalUrl = tgFormat)
            }

            // ۳. پروتکل HTTP Proxy
            if (cleaned.startsWith("tg://http", ignoreCase = true) || cleaned.contains("t.me/http", ignoreCase = true)) {
                val corrected = cleaned.replace("https://t.me/http", "tg://http", ignoreCase = true)
                    .replace("http://t.me/http", "tg://http", ignoreCase = true)
                val uri = Uri.parse(corrected)
                val server = uri.getQueryParameter("server")?.trim() ?: return null
                val port = uri.getQueryParameter("port")?.toIntOrNull() ?: 8080
                if (server.isEmpty() || port !in 1..65535) return null

                val user = uri.getQueryParameter("user")?.trim()
                val pass = uri.getQueryParameter("pass")?.trim()
                val tgFormat = "tg://http?server=$server&port=$port" +
                        (if (!user.isNullOrEmpty()) "&user=$user" else "") +
                        (if (!pass.isNullOrEmpty()) "&pass=$pass" else "")
                return ProxyItem(type = ProxyType.HTTP, host = server, port = port, user = user, pass = pass, originalUrl = tgFormat)
            }

            // ۴. پروتکل WebProxy تلگرام
            if (cleaned.startsWith("tg://webproxy", ignoreCase = true) || cleaned.contains("t.me/webproxy", ignoreCase = true)) {
                val corrected = cleaned.replace("https://t.me/webproxy", "tg://webproxy", ignoreCase = true)
                    .replace("http://t.me/webproxy", "tg://webproxy", ignoreCase = true)
                val uri = Uri.parse(corrected)
                val server = uri.getQueryParameter("server")?.trim() ?: return null
                val port = uri.getQueryParameter("port")?.toIntOrNull() ?: 443
                if (server.isEmpty() || port !in 1..65535) return null

                val secret = uri.getQueryParameter("secret")?.trim()
                val cleanUrl = "tg://webproxy?server=$server&port=$port" +
                        (if (!secret.isNullOrEmpty()) "&secret=$secret" else "")
                return ProxyItem(type = ProxyType.WEBPROXY, host = server, port = port, secret = secret, originalUrl = cleanUrl)
            }
        } catch (e: Throwable) {
            // هندلینگ ایمن هرگونه خطای پارس
        }
        return null
    }

    /**
     * تست بومی کانکشن پروکسی با تضمین کامل عدم پرتاب استثنا به لایه UI
     */
    suspend fun checkSingleProxy(proxy: ProxyItem, timeoutMs: Int, enableTcpPrecheck: Boolean = true): ProxyItem = withContext(Dispatchers.IO) {
        // فاز اول: پیش‌ارزیابی سریع اتصال TCP
        if (enableTcpPrecheck) {
            val tcpTimeout = minOf(timeoutMs, 1500)
            if (!isTcpReachable(proxy.host, proxy.port, tcpTimeout)) {
                return@withContext proxy.copy(status = "Failed", ping = -1)
            }
        }

        // فاز دوم: شبیه‌سازی دقیق و کامل پروتکل‌ها
        try {
            val resultPing = when (proxy.type) {
                ProxyType.MTPROTO -> checkMtProtoProxy(proxy.host, proxy.port, proxy.secret ?: "", timeoutMs)
                ProxyType.SOCKS5 -> checkSocks5Proxy(proxy, timeoutMs)
                ProxyType.HTTP -> checkHttpProxy(proxy, timeoutMs)
                ProxyType.WEBPROXY -> checkWebProxy(proxy, timeoutMs)
            }

            if (resultPing > 0L) {
                proxy.copy(status = "Working", ping = resultPing)
            } else {
                proxy.copy(status = "Failed", ping = -1)
            }
        } catch (e: Throwable) {
            proxy.copy(status = "Failed", ping = -1)
        }
    }

    private fun isTcpReachable(host: String, port: Int, timeoutMs: Int): Boolean {
        if (port !in 1..65535 || host.isBlank()) return false
        var socket: Socket? = null
        return try {
            socket = Socket()
            socket.connect(InetSocketAddress(host, port), timeoutMs)
            true
        } catch (e: Throwable) {
            false
        } finally {
            try { socket?.close() } catch (ignored: Throwable) {}
        }
    }

    private fun checkHttpProxy(proxy: ProxyItem, timeoutMs: Int): Long {
        if (proxy.port !in 1..65535 || proxy.host.isBlank()) return -1L
        val start = System.currentTimeMillis()
        var socket: Socket? = null
        try {
            socket = Socket()
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(proxy.host, proxy.port), timeoutMs)

            val out = socket.getOutputStream()
            val input = socket.getInputStream()

            val reqBuilder = StringBuilder()
            reqBuilder.append("CONNECT $TELEGRAM_TEST_IP:$TELEGRAM_TEST_PORT HTTP/1.1\r\n")
            reqBuilder.append("Host: $TELEGRAM_TEST_IP:$TELEGRAM_TEST_PORT\r\n")
            reqBuilder.append("Proxy-Connection: Keep-Alive\r\n")

            if (!proxy.user.isNullOrEmpty()) {
                val authString = "${proxy.user}:${proxy.pass ?: ""}"
                val authBase64 = Base64.encodeToString(authString.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
                reqBuilder.append("Proxy-Authorization: Basic $authBase64\r\n")
            }
            reqBuilder.append("\r\n")

            out.write(reqBuilder.toString().toByteArray(Charsets.US_ASCII))
            out.flush()

            val reader = BufferedReader(InputStreamReader(input, Charsets.US_ASCII))
            val statusLine = reader.readLine() ?: return -1L
            if (statusLine.startsWith("HTTP/") && statusLine.contains("200")) {
                return System.currentTimeMillis() - start
            }
        } catch (e: Throwable) {
            // خطای اتصال
        } finally {
            try { socket?.close() } catch (ignored: Throwable) {}
        }
        return -1L
    }

    private fun checkWebProxy(proxy: ProxyItem, timeoutMs: Int): Long {
        if (proxy.port !in 1..65535 || proxy.host.isBlank()) return -1L
        val start = System.currentTimeMillis()
        var rawSocket: Socket? = null
        var sslSocket: SSLSocket? = null
        try {
            rawSocket = Socket()
            rawSocket.soTimeout = timeoutMs
            rawSocket.connect(InetSocketAddress(proxy.host, proxy.port), timeoutMs)

            sslSocket = sslSocketFactory.createSocket(rawSocket, proxy.host, proxy.port, true) as SSLSocket
            sslSocket.soTimeout = timeoutMs

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                try {
                    val sslParams = sslSocket.sslParameters
                    sslParams.serverNames = listOf(javax.net.ssl.SNIHostName(proxy.host))
                    sslSocket.sslParameters = sslParams
                } catch (ignored: Throwable) {}
            }

            sslSocket.startHandshake()

            val out = sslSocket.getOutputStream()
            val input = sslSocket.getInputStream()
            val req = "GET / HTTP/1.1\r\nHost: ${proxy.host}\r\nUser-Agent: Mozilla/5.0 (Telegram)\r\nConnection: close\r\n\r\n"
            out.write(req.toByteArray(Charsets.US_ASCII))
            out.flush()

            val buffer = ByteArray(32)
            val read = input.read(buffer)
            if (read > 0) {
                return System.currentTimeMillis() - start
            }
        } catch (e: Throwable) {
            // خطا در هندشیک
        } finally {
            try { sslSocket?.close() } catch (ignored: Throwable) {}
            try { rawSocket?.close() } catch (ignored: Throwable) {}
        }
        return -1L
    }

    private fun checkSocks5Proxy(proxy: ProxyItem, timeoutMs: Int): Long {
        if (proxy.port !in 1..65535 || proxy.host.isBlank()) return -1L
        val start = System.currentTimeMillis()
        var socket: Socket? = null
        try {
            socket = Socket()
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(proxy.host, proxy.port), timeoutMs)

            val out = socket.getOutputStream()
            val input = socket.getInputStream()

            val hasAuth = !proxy.user.isNullOrEmpty()
            if (hasAuth) {
                out.write(byteArrayOf(0x05, 0x02, 0x00, 0x02))
            } else {
                out.write(byteArrayOf(0x05, 0x01, 0x00))
            }
            out.flush()

            val greetingRes = ByteArray(2)
            if (readFully(input, greetingRes) != 2 || greetingRes[0] != 0x05.toByte()) {
                return -1L
            }

            val selectedMethod = greetingRes[1].toInt() and 0xFF
            if (selectedMethod == 0x02) {
                val userBytes = proxy.user!!.toByteArray(Charsets.UTF_8)
                val passBytes = (proxy.pass ?: "").toByteArray(Charsets.UTF_8)

                val authPayload = ByteArray(3 + userBytes.size + passBytes.size)
                authPayload[0] = 0x01
                authPayload[1] = userBytes.size.toByte()
                System.arraycopy(userBytes, 0, authPayload, 2, userBytes.size)
                authPayload[2 + userBytes.size] = passBytes.size.toByte()
                System.arraycopy(passBytes, 0, authPayload, 3 + userBytes.size, passBytes.size)

                out.write(authPayload)
                out.flush()

                val authRes = ByteArray(2)
                if (readFully(input, authRes) != 2 || authRes[1] != 0x00.toByte()) {
                    return -1L
                }
            } else if (selectedMethod != 0x00) {
                return -1L
            }

            val ipParts = TELEGRAM_TEST_IP.split(".").map { it.toInt().toByte() }
            if (ipParts.size != 4) return -1L

            val connPayload = ByteArray(10)
            connPayload[0] = 0x05
            connPayload[1] = 0x01
            connPayload[2] = 0x00
            connPayload[3] = 0x01
            connPayload[4] = ipParts[0]
            connPayload[5] = ipParts[1]
            connPayload[6] = ipParts[2]
            connPayload[7] = ipParts[3]
            connPayload[8] = (TELEGRAM_TEST_PORT shr 8).toByte()
            connPayload[9] = (TELEGRAM_TEST_PORT and 0xFF).toByte()

            out.write(connPayload)
            out.flush()

            val connResHead = ByteArray(4)
            if (readFully(input, connResHead) != 4 || connResHead[1] != 0x00.toByte()) {
                return -1L
            }

            val atyp = connResHead[3].toInt() and 0xFF
            val skipLen = when (atyp) {
                0x01 -> 4 + 2
                0x03 -> {
                    val domainLen = input.read()
                    if (domainLen == -1) return -1L
                    domainLen + 2
                }
                0x04 -> 16 + 2
                else -> return -1L
            }

            val skipBuf = ByteArray(skipLen)
            if (readFully(input, skipBuf) != skipLen) {
                return -1L
            }

            return System.currentTimeMillis() - start
        } catch (e: Throwable) {
            // خطا در پردازش سوکت
        } finally {
            try { socket?.close() } catch (ignored: Throwable) {}
        }
        return -1L
    }

    private fun checkMtProtoProxy(host: String, port: Int, secretHex: String, timeoutMs: Int): Long {
        if (port !in 1..65535 || host.isBlank()) return -1L
        val start = System.currentTimeMillis()

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
                    try {
                        val sslParams = sslSocket.sslParameters
                        sslParams.serverNames = listOf(javax.net.ssl.SNIHostName(domain))
                        sslSocket.sslParameters = sslParams
                    } catch (ignored: Throwable) {}
                }

                sslSocket.startHandshake()
                sslSocket
            } else {
                rawSocket
            }

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
                    firstInt == 0x44444444 || 
                    firstInt == 0x45472020 || 
                    firstInt == 0x54534f50 || 
                    firstInt == 0x44414548) { 
                    continue
                }
                
                val secondInt = (initBuffer[4].toInt() and 0xFF) or
                                (initBuffer[5].toInt() and 0xFF shl 8) or
                                (initBuffer[6].toInt() and 0xFF shl 16) or
                                (initBuffer[7].toInt() and 0xFF shl 24)
                if (secondInt == 0) continue
                
                break
            }

            initBuffer[56] = 0xdd.toByte()
            initBuffer[57] = 0xdd.toByte()
            initBuffer[58] = 0xdd.toByte()
            initBuffer[59] = 0xdd.toByte()

            initBuffer[60] = 0xfe.toByte()
            initBuffer[61] = 0xff.toByte()

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

            val encryptedBuffer = encryptCipher.update(initBuffer)
            System.arraycopy(encryptedBuffer, 56, initBuffer, 56, 8)

            val out = socketToUse.getOutputStream()
            out.write(initBuffer)
            out.flush()

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

            val msgId = ((System.currentTimeMillis() / 1000) shl 32) and -4L
            val nonce = ByteArray(16).apply { random.nextBytes(this) }
            
            val tlBody = ByteBuffer.allocate(20).apply {
                order(ByteOrder.LITTLE_ENDIAN)
                putInt(0xbe7e8ef1.toInt())
                put(nonce)
            }.array()

            val unencryptedMsg = ByteBuffer.allocate(20 + tlBody.size).apply {
                order(ByteOrder.LITTLE_ENDIAN)
                putLong(0L)
                putLong(msgId)
                putInt(tlBody.size)
                put(tlBody)
            }.array()

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

            val encryptedFrame = encryptCipher.update(frame)
            out.write(encryptedFrame)
            out.flush()

            val input = socketToUse.getInputStream()

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

            val responsePayload = ByteArray(responseLen)
            var payloadBytesRead = 0
            while (payloadBytesRead < responseLen) {
                val read = input.read(responsePayload, payloadBytesRead, responseLen - payloadBytesRead)
                if (read == -1) return -1L
                payloadBytesRead += read
            }
            val decryptedPayload = decryptCipher.update(responsePayload)

            if (decryptedPayload.size < 24) {
                return -1L
            }
            val wrapBuffer = ByteBuffer.wrap(decryptedPayload).order(ByteOrder.LITTLE_ENDIAN)
            val responseAuthKeyId = wrapBuffer.getLong(0)
            if (responseAuthKeyId != 0L) {
                return -1L
            }
            val responseConstructorId = wrapBuffer.getInt(20)
            
            if (responseConstructorId == 0x05162463) {
                return System.currentTimeMillis() - start
            }

        } catch (e: Throwable) {
            // هندلینگ ایمن هرگونه خطای شبکه یا الگوریتم
        } finally {
            try { socketToUse?.close() } catch (ignored: Throwable) {}
            try { rawSocket?.close() } catch (ignored: Throwable) {}
        }
        return -1L
    }

    private fun decodeSecret(secretStr: String): ByteArray {
        val clean = secretStr.trim().trimEnd(
            ')', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '`', '~', 
            '[', ']', '{', '}', '|', ';', ':', '\'', ',', '.', '<', '>', '?', '/', ' ', '\t', '\n', '\r'
        ).lowercase()

        try {
            if (clean.all { it in "0123456789abcdef" } && clean.length % 2 == 0) {
                val data = ByteArray(clean.length / 2)
                for (i in data.indices) {
                    data[i] = ((Character.digit(clean[i * 2], 16) shl 4) + Character.digit(clean[i * 2 + 1], 16)).toByte()
                }
                return data
            }
        } catch (ignored: Throwable) {}

        val base64Flags = Base64.DEFAULT or Base64.NO_PADDING or Base64.URL_SAFE
        try {
            return Base64.decode(clean, base64Flags)
        } catch (ignored: Throwable) {}
        try {
            return Base64.decode(clean, Base64.DEFAULT)
        } catch (ignored: Throwable) {}
        return ByteArray(0)
    }

    private fun readFully(input: InputStream, buffer: ByteArray): Int {
        var bytesRead = 0
        while (bytesRead < buffer.size) {
            val read = input.read(buffer, bytesRead, buffer.size - bytesRead)
            if (read == -1) break
            bytesRead += read
        }
        return bytesRead
    }
}
