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
     * دریافت اطلاعات از آدرس سابسکریپشن و اعتبارسنجی تاریخ آپدیت (محدودیت ۷ روز)
     */
    suspend fun fetchSubscription(urlStr: String, logger: (String) -> Unit): List<ProxyItem> = withContext(Dispatchers.IO) {
        val proxies = mutableListOf<ProxyItem>()
        var connection: HttpURLConnection? = null
        try {
            val url = URL(urlStr)
            connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 8000
            connection.readTimeout = 8000
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

            // ۱. بررسی هدر تاریخ آخرین ویرایش (Last-Modified)
            val lastModified = connection.lastModified
            if (lastModified > 0) {
                val oneWeekAgo = System.currentTimeMillis() - (7 * 24 * 60 * 60 * 1000L)
                if (lastModified < oneWeekAgo) {
                    logger("Skipped (Older than 7 days): $urlStr")
                    return@withContext emptyList()
                }
            }

            val responseCode = connection.responseCode
            if (responseCode != HttpURLConnection.HTTP_OK) {
                logger("Error response ($responseCode): $urlStr")
                return@withContext emptyList()
            }

            val reader = BufferedReader(InputStreamReader(connection.inputStream))
            val content = StringBuilder()
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                content.append(line).append("\n")
            }
            reader.close()

            var rawData = content.toString().trim()

            // ۲. بررسی دیکود احتمالی Base64 (بسیاری از لینک‌های اشتراک بیست‌۶۴ هستند)
            if (!rawData.contains("tg://") && !rawData.contains("socks") && rawData.isNotEmpty()) {
                try {
                    val decodedBytes = Base64.decode(rawData, Base64.DEFAULT)
                    rawData = String(decodedBytes)
                } catch (ignored: Exception) {}
            }

            // ۳. استخراج و پارس پروکسی‌ها از متن دریافتی
            rawData.split("\n").forEach { rawLine ->
                val proxy = ProxyChecker.parseProxy(rawLine)
                if (proxy != null) {
                    proxies.add(proxy)
                }
            }
            logger("Successfully parsed ${proxies.size} proxies: $urlStr")

        } catch (e: Exception) {
            logger("Failed to load sub: $urlStr - ${e.localizedMessage}")
        } finally {
            connection?.disconnect()
        }
        proxies
    }
}
