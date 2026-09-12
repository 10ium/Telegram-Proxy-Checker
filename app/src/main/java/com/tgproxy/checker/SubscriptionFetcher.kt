package com.tgproxy.checker

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

object SubscriptionFetcher {

    /**
     * دریافت اطلاعات از آدرس سابسکریپشن با مهلت زمانی بالا و مقاوم در برابر اختلالات شبکه
     */
    suspend fun fetchSubscription(urlStr: String, logger: (String) -> Unit): List<ProxyItem> = withContext(Dispatchers.IO) {
        val proxies = mutableListOf<ProxyItem>()
        var connection: HttpURLConnection? = null
        try {
            val url = URL(urlStr.trim())
            connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = true
            // افزایش زمان انتظار به ۲۵ ثانیه برای اتصال و ۴۵ ثانیه برای خواندن لیست‌های حجیم
            connection.connectTimeout = 25000
            connection.readTimeout = 45000
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            connection.setRequestProperty("Accept", "*/*")

            val responseCode = connection.responseCode
            if (responseCode != HttpURLConnection.HTTP_OK) {
                logger("Error response ($responseCode): $urlStr")
                return@withContext emptyList()
            }

            // خواندن استریمی و خط‌به‌خط پاسخ برای پیشگیری از پر شدن حافظه در فایل‌های بزرگ
            val reader = BufferedReader(InputStreamReader(connection.inputStream, Charsets.UTF_8), 32768)
            val contentBuilder = StringBuilder()
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                contentBuilder.append(line).append("\n")
            }
            reader.close()

            var rawData = contentBuilder.toString().trim()

            // بررسی و دیکود خودکار Base64 در صورت انکود بودن کل خروجی
            if (!rawData.contains("tg://") && !rawData.contains("socks") && rawData.isNotEmpty()) {
                try {
                    val cleanBase64 = rawData.replace("\r", "").replace("\n", "").trim()
                    val decodedBytes = try {
                        Base64.decode(cleanBase64, Base64.DEFAULT or Base64.NO_PADDING or Base64.URL_SAFE)
                    } catch (e: Throwable) {
                        Base64.decode(cleanBase64, Base64.DEFAULT)
                    }
                    val decodedText = String(decodedBytes, Charsets.UTF_8)
                    if (decodedText.contains("tg://") || decodedText.contains("socks") || decodedText.contains("http")) {
                        rawData = decodedText
                    }
                } catch (ignored: Throwable) {
                    // متن دیکود نشد یا بیس۶۴ نبود
                }
            }

            // استخراج هوشمند پروکسی‌ها از متن
            val extracted = ProxyChecker.extractProxiesFromText(rawData)
            proxies.addAll(extracted)

            logger("Loaded ${proxies.size} proxies: $urlStr")

        } catch (e: Throwable) {
            logger("Failed to load sub: $urlStr - ${e.localizedMessage ?: "Timeout/Network Error"}")
        } finally {
            try { connection?.disconnect() } catch (ignored: Throwable) {}
        }
        proxies
    }
}
