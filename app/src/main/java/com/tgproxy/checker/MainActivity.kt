package com.tgproxy.checker

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.io.OutputStreamWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import com.tgproxy.checker.R

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Color(0xFF3B82F6),
                    secondary = Color(0xFF10B981),
                    background = Color(0xFF0F172A),
                    surface = Color(0xFF1E293B)
                )
            ) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    CheckerScreen()
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CheckerScreen() {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    // متغیرهای حالت
    var inputText by remember { mutableStateOf("") }
    var concurrencyText by remember { mutableStateOf("50") }
    var timeoutText by remember { mutableStateOf("5") }
    var topNText by remember { mutableStateOf("5") }

    var isChecking by remember { mutableStateOf(false) }
    var checkJob by remember { mutableStateOf<Job?>(null) }

    val proxyList = remember { mutableStateListOf<ProxyItem>() }
    val logsList = remember { mutableStateListOf<String>() }

    // آمار زنده
    var checkedCount by remember { mutableIntStateOf(0) }
    var workingCount by remember { mutableIntStateOf(0) }
    var failedCount by remember { mutableIntStateOf(0) }

    // منابع اشتراک پیش‌فرض از داخل دستورات کاربر
    val defaultSubs = listOf(
        "https://raw.githubusercontent.com/10Dream/VpnClashFaCollector/refs/heads/main/sub/all/tg.txt",
        "https://raw.githubusercontent.com/10ium/VpnClashFaCollector/refs/heads/main/sub/all/tg.txt",
        "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGProto/refs/heads/main/proxies-tested.txt",
        "https://raw.githubusercontent.com/SoliSpirit/mtproto/refs/heads/master/all_proxies.txt",
        "https://raw.githubusercontent.com/Therealwh/MTPproxyLIST/refs/heads/main/verified/proxy_all_tme_verified.txt",
        "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/protocols/mtproto.txt",
        "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_all.txt",
        "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/socks5.txt",
        "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/refs/heads/main/proxy_list.txt"
    )

    fun appendLog(message: String) {
        val timeStamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        logsList.add("[$timeStamp] $message")
    }

    // متد شروع تایید همزمان پروکسی‌ها
    fun startValidation() {
        val concurrency = concurrencyText.toIntOrNull() ?: 50
        val timeoutSec = timeoutText.toIntOrNull() ?: 5
        val timeoutMs = timeoutSec * 1000

        // استخراج پروکسی‌ها از متن ورودی
        val lines = inputText.split("\n")
        val parsedList = lines.mapNotNull { ProxyChecker.parseProxy(it) }.distinctBy { "${it.host}:${it.port}" }

        if (parsedList.isEmpty()) {
            Toast.makeText(context, context.getString(R.string.toast_empty), Toast.LENGTH_SHORT).show()
            return
        }

        proxyList.clear()
        proxyList.addAll(parsedList)

        // بازنشانی آمار
        checkedCount = 0
        workingCount = 0
        failedCount = 0
        logsList.clear()
        isChecking = true

        appendLog("Starting verify process for ${parsedList.size} proxies...")

        checkJob = coroutineScope.launch {
            val semaphore = Semaphore(concurrency)
            val jobs = parsedList.map { proxy ->
                launch {
                    semaphore.withPermit {
                        if (!isChecking) return@launch
                        val result = ProxyChecker.checkSingleProxy(proxy, timeoutMs)
                        
                        // یافتن و آپدیت آیتم در لیست ری‌اکتیو جهت نمایش در UI
                        val index = proxyList.indexOfFirst { it.host == result.host && it.port == result.port }
                        if (index != -1) {
                            proxyList[index] = result
                        }

                        if (result.status == "Working") {
                            workingCount++
                            appendLog("✔ ACTIVE [${result.type}] ${result.host}:${result.port} - ${result.ping}ms")
                        } else {
                            failedCount++
                        }
                        checkedCount++
                    }
                }
            }
            jobs.forEach { it.join() }
            isChecking = false
            appendLog("Verification finished! Working: $workingCount, Failed: $failedCount")
        }
    }

    fun stopValidation() {
        isChecking = false
        checkJob?.cancel()
        appendLog("Verification stopped by user.")
    }

    // لود لینک‌های اشتراک در ورودی
    fun loadDefaultSubscriptions() {
        coroutineScope.launch {
            appendLog("Fetching default subscription links...")
            val fetchedProxies = mutableListOf<String>()
            defaultSubs.forEach { subUrl ->
                val list = SubscriptionFetcher.fetchSubscription(subUrl) { msg ->
                    appendLog(msg)
                }
                list.forEach { fetchedProxies.add(it.originalUrl) }
            }
            if (fetchedProxies.isNotEmpty()) {
                inputText = fetchedProxies.joinToString("\n")
                appendLog("Loaded ${fetchedProxies.size} proxies from sub links.")
            } else {
                appendLog("No fresh proxies found in sub links (within last 7 days).")
            }
        }
    }

    // متدهای مربوط به کپی و خروجی
    fun copyAllToClipboard() {
        val working = proxyList.filter { it.status == "Working" }.sortedBy { it.ping }
        if (working.isEmpty()) {
            Toast.makeText(context, context.getString(R.string.toast_empty), Toast.LENGTH_SHORT).show()
            return
        }
        val text = working.joinToString("\n") { it.originalUrl }
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("working_proxies", text))
        Toast.makeText(context, context.getString(R.string.toast_copied), Toast.LENGTH_SHORT).show()
    }

    fun copyTopNToClipboard() {
        val n = topNText.toIntOrNull() ?: 5
        val working = proxyList.filter { it.status == "Working" }.sortedBy { it.ping }.take(n)
        if (working.isEmpty()) {
            Toast.makeText(context, context.getString(R.string.toast_empty), Toast.LENGTH_SHORT).show()
            return
        }
        val text = working.joinToString("\n") { it.originalUrl }
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("top_n_proxies", text))
        Toast.makeText(context, "${context.getString(R.string.toast_copied)} (Top $n)", Toast.LENGTH_SHORT).show()
    }

    fun exportAsTxt() {
        val working = proxyList.filter { it.status == "Working" }.sortedBy { it.ping }
        if (working.isEmpty()) {
            Toast.makeText(context, context.getString(R.string.toast_empty), Toast.LENGTH_SHORT).show()
            return
        }
        val text = working.joinToString("\n") { it.originalUrl }
        try {
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, text)
                putExtra(Intent.EXTRA_SUBJECT, "Telegram Working Proxies")
            }
            context.startActivity(Intent.createChooser(intent, "Share Proxies"))
        } catch (e: Exception) {
            Toast.makeText(context, "Error sharing file: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        // هدر برنامه
        Text(
            text = stringResource(id = R.string.title),
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            color = Color.White,
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 12.dp),
            textAlign = TextAlign.Center
        )

        // ردیف تنظیمات: همزمانی و تایم اوت
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedTextField(
                value = concurrencyText,
                onValueChange = { if (it.all { char -> char.isDigit() }) concurrencyText = it },
                label = { Text(stringResource(id = R.string.placeholder_concurrency)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.weight(1f),
                singleLine = true
            )
            OutlinedTextField(
                value = timeoutText,
                onValueChange = { if (it.all { char -> char.isDigit() }) timeoutText = it },
                label = { Text(stringResource(id = R.string.placeholder_timeout)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.weight(1f),
                singleLine = true
            )
        }

        // باکس دریافت اشتراک‌های پیش‌فرض
        Button(
            onClick = { loadDefaultSubscriptions() },
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 8.dp),
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
        ) {
            Text(stringResource(id = R.string.load_subs_btn))
        }

        // ادیت باکس ورودی لیست خام پروکسی‌ها
        OutlinedTextField(
            value = inputText,
            onValueChange = { inputText = it },
            label = { Text(stringResource(id = R.string.input_label)) },
            modifier = Modifier
                .fillMaxWidth()
                .height(130.dp),
            maxLines = 1000
        )

        // دکمه کنترل عملیات
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = { if (isChecking) stopValidation() else startValidation() },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (isChecking) Color.Red else Color(0xFF10B981)
                )
            ) {
                Text(if (isChecking) stringResource(id = R.string.stop_btn) else stringResource(id = R.string.start_btn))
            }
        }

        // بخش نمایش آمار تست‌ها
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 8.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = stringResource(id = R.string.stats_checked, checkedCount, proxyList.size),
                    color = Color.White,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = stringResource(id = R.string.stats_working, workingCount),
                    color = Color(0xFF10B981),
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = stringResource(id = R.string.stats_failed, failedCount),
                    color = Color(0xFFEF4444),
                    fontWeight = FontWeight.Bold
                )
            }
        }

        // بخش کنسول لاگ زنده سیستم
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .clip(RoundedCornerShape(8.dp))
                .background(Color.Black)
                .border(1.dp, Color(0xFF334155), RoundedCornerShape(8.dp))
                .padding(8.dp)
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                reverseLayout = true
            ) {
                items(logsList.asReversed()) { log ->
                    Text(
                        text = log,
                        color = if (log.contains("✔ ACTIVE")) Color(0xFF10B981) else Color(0xFFcbd5e1),
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(bottom = 2.dp)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // ردیف کپی و خروجی‌ها
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = { copyAllToClipboard() },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6))
            ) {
                Text(stringRes
