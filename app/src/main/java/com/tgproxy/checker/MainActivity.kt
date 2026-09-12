package com.tgproxy.checker

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class InputMode { PASTE, FILE, SUBS }
enum class PresetMode { FAST, BALANCED, NATIONAL, CUSTOM }

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Color(0xFF3B82F6),
                    secondary = Color(0xFF10B981),
                    background = Color(0xFF0B1329),
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
    val prefs = remember { context.getSharedPreferences("tg_proxy_checker_prefs", Context.MODE_PRIVATE) }

    // ۱۰ منبع سابسکریپشن معتبر و آزمایش‌شده
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

    // متغیرهای وضعیت ذخیره‌شده
    var inputText by remember { mutableStateOf(prefs.getString("input_text", "") ?: "") }
    var concurrencyText by remember { mutableStateOf(prefs.getString("concurrency", "25") ?: "25") }
    var timeoutText by remember { mutableStateOf(prefs.getString("timeout", "5") ?: "5") }
    var topNText by remember { mutableStateOf(prefs.getString("top_n", "10") ?: "10") }
    var enableTcpPrecheck by remember { mutableStateOf(prefs.getBoolean("tcp_precheck", true)) }
    var currentPreset by remember { mutableStateOf(PresetMode.BALANCED) }

    var inputMode by remember { 
        mutableStateOf(
            try { 
                InputMode.valueOf(prefs.getString("input_mode", InputMode.PASTE.name) ?: InputMode.PASTE.name) 
            } catch(e: Exception) { 
                InputMode.PASTE 
            }
        ) 
    }
    var subscriptionLinksText by remember { 
        mutableStateOf(prefs.getString("sub_links", defaultSubs.joinToString("\n")) ?: defaultSubs.joinToString("\n")) 
    }

    // تب‌ها: 0 = ورودی و تنظیمات، 1 = پروکسی‌های سالم، 2 = مانیتور و لاگ‌ها
    var selectedTab by remember { mutableIntStateOf(0) }

    // ذخیره خودکار تنظیمات
    LaunchedEffect(inputText) { prefs.edit().putString("input_text", inputText).apply() }
    LaunchedEffect(concurrencyText) { prefs.edit().putString("concurrency", concurrencyText).apply() }
    LaunchedEffect(timeoutText) { prefs.edit().putString("timeout", timeoutText).apply() }
    LaunchedEffect(topNText) { prefs.edit().putString("top_n", topNText).apply() }
    LaunchedEffect(enableTcpPrecheck) { prefs.edit().putBoolean("tcp_precheck", enableTcpPrecheck).apply() }
    LaunchedEffect(inputMode) { prefs.edit().putString("input_mode", inputMode.name).apply() }
    LaunchedEffect(subscriptionLinksText) { prefs.edit().putString("sub_links", subscriptionLinksText).apply() }

    // متغیرهای عملیات و لغو/توقف
    var isChecking by remember { mutableStateOf(false) }
    var checkJob by remember { mutableStateOf<Job?>(null) }

    var isFetchingSubs by remember { mutableStateOf(false) }
    var fetchSubsJob by remember { mutableStateOf<Job?>(null) }

    // لیست پروکسی‌های سالم به همراه لیست لاگ‌ها
    val workingProxies = remember { mutableStateListOf<ProxyItem>() }
    val logsList = remember { mutableStateListOf<String>() }

    // شمارنده‌های زنده و دقیق
    var totalCount by remember { mutableIntStateOf(0) }
    var checkedCount by remember { mutableIntStateOf(0) }
    var workingCount by remember { mutableIntStateOf(0) }
    var failedCount by remember { mutableIntStateOf(0) }

    // تفکیک آمار ۴ پروتکل در پروکسی‌های سالم
    var workingMtprotoCount by remember { mutableIntStateOf(0) }
    var workingSocks5Count by remember { mutableIntStateOf(0) }
    var workingHttpCount by remember { mutableIntStateOf(0) }
    var workingWebproxyCount by remember { mutableIntStateOf(0) }

    // کمترین و میانگین پینگ
    var bestPing by remember { mutableLongStateOf(-1L) }
    var totalPingSum by remember { mutableLongStateOf(0L) }
    val avgPing = if (workingCount > 0) (totalPingSum / workingCount) else -1L

    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            coroutineScope.launch {
                try {
                    val inputStream = context.contentResolver.openInputStream(it)
                    val text = inputStream?.bufferedReader()?.use { reader -> reader.readText() } ?: ""
                    inputText = text
                    Toast.makeText(context, "فایل متنی با موفقیت لود شد!", Toast.LENGTH_SHORT).show()
                } catch (e: Exception) {
                    Toast.makeText(context, "خطا در خواندن فایل: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    fun appendLog(message: String) {
        val timeStamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        if (logsList.size > 500) {
            logsList.removeRange(0, 100)
        }
        logsList.add("[$timeStamp] $message")
    }

    fun applyPreset(preset: PresetMode) {
        currentPreset = preset
        when (preset) {
            PresetMode.FAST -> {
                timeoutText = "3"
                concurrencyText = "50"
                enableTcpPrecheck = true
            }
            PresetMode.BALANCED -> {
                timeoutText = "5"
                concurrencyText = "25"
                enableTcpPrecheck = true
            }
            PresetMode.NATIONAL -> {
                timeoutText = "60"
                concurrencyText = "10"
                enableTcpPrecheck = false
            }
            PresetMode.CUSTOM -> {}
        }
    }

    fun pasteFromClipboard() {
        try {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            if (clipboard.hasPrimaryClip()) {
                val item = clipboard.primaryClip?.getItemAt(0)
                val pasteText = item?.text?.toString() ?: ""
                if (pasteText.isNotEmpty()) {
                    inputText = pasteText
                    Toast.makeText(context, "متن با موفقیت جایگذاری شد!", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(context, "کلیپ‌بورد فاقد متن است!", Toast.LENGTH_SHORT).show()
                }
            } else {
                Toast.makeText(context, "کلیپ‌بورد خالی است!", Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            Toast.makeText(context, "خطا در دسترسی به کلیپ‌بورد: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
        }
    }

    // متوقف کردن عملیات بررسی پروکسی‌ها
    fun stopValidation() {
        isChecking = false
        checkJob?.cancel()
        appendLog("⏹️ فرآیند بررسی توسط کاربر متوقف شد.")
        Toast.makeText(context, "بررسی پروکسی‌ها متوقف شد.", Toast.LENGTH_SHORT).show()
    }

    // لغو کردن عملیات دریافت سابسکریپشن‌ها
    fun cancelSubscriptionFetch() {
        isFetchingSubs = false
        fetchSubsJob?.cancel()
        appendLog("⏹️ دریافت سابسکریپشن‌ها توسط کاربر لغو شد.")
        Toast.makeText(context, "دریافت سابسکریپشن‌ها لغو شد.", Toast.LENGTH_SHORT).show()
    }

    fun startValidation() {
        val concurrency = (concurrencyText.toIntOrNull() ?: 25).coerceIn(1, 100)
        val timeoutSec = (timeoutText.toIntOrNull() ?: 5).coerceIn(1, 120)
        val timeoutMs = timeoutSec * 1000

        val parsedList = ProxyChecker.extractProxiesFromText(inputText)
        if (parsedList.isEmpty()) {
            Toast.makeText(context, context.getString(R.string.toast_empty), Toast.LENGTH_SHORT).show()
            return
        }

        // مقداردهی اولیه متغیرهای مانیتورینگ
        workingProxies.clear()
        totalCount = parsedList.size
        checkedCount = 0
        workingCount = 0
        failedCount = 0
        workingMtprotoCount = 0
        workingSocks5Count = 0
        workingHttpCount = 0
        workingWebproxyCount = 0
        bestPing = -1L
        totalPingSum = 0L
        logsList.clear()
        isChecking = true
        
        // سوئیچ خودکار به تب پروکسی‌های سالم برای نمایش همزمان نتایج
        selectedTab = 1

        appendLog("Extracted ${parsedList.size} unique proxies across 4 protocols.")
        appendLog("Precheck TCP: ${if (enableTcpPrecheck) "Enabled" else "Disabled (Deep Mode)"}")
        appendLog("Starting verify process (Timeout: ${timeoutSec}s, Concurrency: $concurrency)...")

        checkJob = coroutineScope.launch {
            val channel = Channel<ProxyItem>(Channel.UNLIMITED)
            parsedList.forEach { channel.trySend(it) }
            channel.close()

            // استفاده از ورکرپول کنترل‌شده به جای اسپاون نامحدود کوروتین برای جلوگیری قطعی از کرش
            val workers = (1..concurrency).map {
                launch(Dispatchers.IO) {
                    for (proxy in channel) {
                        if (!isChecking) break
                        val result = ProxyChecker.checkSingleProxy(proxy, timeoutMs, enableTcpPrecheck)
                        withContext(Dispatchers.Main) {
                            if (result.status == "Working") {
                                workingProxies.add(result)
                                when (result.type) {
                                    ProxyType.MTPROTO -> workingMtprotoCount++
                                    ProxyType.SOCKS5 -> workingSocks5Count++
                                    ProxyType.HTTP -> workingHttpCount++
                                    ProxyType.WEBPROXY -> workingWebproxyCount++
                                }
                                if (bestPing == -1L || result.ping < bestPing) {
                                    bestPing = result.ping
                                }
                                totalPingSum += result.ping
                                workingCount++
                                appendLog("✔ ACTIVE [${result.type}] ${result.host}:${result.port} - ${result.ping}ms")
                            } else {
                                failedCount++
                            }
                            checkedCount++
                        }
                    }
                }
            }
            workers.forEach { it.join() }
            isChecking = false
            appendLog("Verification finished! Working: $workingCount, Failed: $failedCount")
        }
    }

    fun loadSubscriptions() {
        if (isFetchingSubs) {
            cancelSubscriptionFetch()
            return
        }
        val links = subscriptionLinksText.split("\n").map { it.trim() }.filter { it.isNotEmpty() }
        if (links.isEmpty()) {
            Toast.makeText(context, "لیست لینک‌های اشتراک خالی است!", Toast.LENGTH_SHORT).show()
            return
        }
        isFetchingSubs = true
        fetchSubsJob = coroutineScope.launch {
            appendLog("Fetching subscription links with extended timeout...")
            val fetchedProxies = mutableListOf<String>()
            for (subUrl in links) {
                if (!isFetchingSubs) break
                val list = SubscriptionFetcher.fetchSubscription(subUrl) { msg ->
                    appendLog(msg)
                }
                list.forEach { fetchedProxies.add(it.originalUrl) }
            }
            isFetchingSubs = false
            if (fetchedProxies.isNotEmpty()) {
                inputText = fetchedProxies.distinct().joinToString("\n")
                appendLog("Loaded ${fetchedProxies.size} proxies from subscriptions.")
                inputMode = InputMode.PASTE
                Toast.makeText(context, "تعداد ${fetchedProxies.size} پروکسی استخراج شد!", Toast.LENGTH_SHORT).show()
            } else {
                appendLog("No proxies could be extracted from subscription links.")
                Toast.makeText(context, "هیچ پروکسی دریافت نشد.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    fun copyAllToClipboard() {
        val working = workingProxies.sortedBy { it.ping }
        if (working.isEmpty()) {
            Toast.makeText(context, context.getString(R.string.toast_empty), Toast.LENGTH_SHORT).show()
            return
        }
        val text = working.joinToString("\n\n") { it.originalUrl }
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("working_proxies", text))
        Toast.makeText(context, context.getString(R.string.toast_copied), Toast.LENGTH_SHORT).show()
    }

    fun copyTopNToClipboard() {
        val n = topNText.toIntOrNull() ?: 10
        val working = workingProxies.sortedBy { it.ping }.take(n)
        if (working.isEmpty()) {
            Toast.makeText(context, context.getString(R.string.toast_empty), Toast.LENGTH_SHORT).show()
            return
        }
        val text = working.joinToString("\n\n") { it.originalUrl }
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("top_n_proxies", text))
        Toast.makeText(context, "${context.getString(R.string.toast_copied)} ($n تای برتر)", Toast.LENGTH_SHORT).show()
    }

    fun connectToProxy(proxyUrl: String) {
        try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(proxyUrl))
            context.startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(context, "خطا در باز کردن تلگرام: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
        }
    }

    fun connectToBestProxy() {
        val best = workingProxies.minByOrNull { it.ping }
        if (best == null) {
            Toast.makeText(context, "هیچ پروکسی سالمی یافت نشد! ابتدا تست را آغاز کنید.", Toast.LENGTH_SHORT).show()
            return
        }
        connectToProxy(best.originalUrl)
    }

    fun exportAsTxt() {
        val working = workingProxies.sortedBy { it.ping }
        if (working.isEmpty()) {
            Toast.makeText(context, context.getString(R.string.toast_empty), Toast.LENGTH_SHORT).show()
            return
        }
        val text = working.joinToString("\n\n") { it.originalUrl }
        try {
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, text)
                putExtra(Intent.EXTRA_SUBJECT, "Telegram Working Proxies")
            }
            context.startActivity(Intent.createChooser(intent, "اشتراک پروکسی‌های سالم"))
        } catch (e: Exception) {
            Toast.makeText(context, "خطا در اشتراک فایل: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
        }
    }

    fun exportAsJson() {
        val working = workingProxies.sortedBy { it.ping }
        if (working.isEmpty()) {
            Toast.makeText(context, context.getString(R.string.toast_empty), Toast.LENGTH_SHORT).show()
            return
        }
        try {
            val jsonArray = JSONArray()
            working.forEach { p ->
                val obj = JSONObject().apply {
                    put("type", p.type.name)
                    put("host", p.host)
                    put("port", p.port)
                    if (!p.secret.isNullOrEmpty()) put("secret", p.secret)
                    if (!p.user.isNullOrEmpty()) put("user", p.user)
                    if (!p.pass.isNullOrEmpty()) put("pass", p.pass)
                    put("ping_ms", p.ping)
                    put("url", p.originalUrl)
                }
                jsonArray.put(obj)
            }
            val jsonText = jsonArray.toString(2)
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/json"
                putExtra(Intent.EXTRA_TEXT, jsonText)
                putExtra(Intent.EXTRA_SUBJECT, "Telegram Working Proxies (JSON)")
            }
            context.startActivity(Intent.createChooser(intent, "اشتراک فایل JSON"))
        } catch (e: Exception) {
            Toast.makeText(context, "خطا در تولید JSON: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(top = 6.dp)
    ) {
        // هدر برنامه همراه با نشان وضعیت توقف سریع
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = stringResource(id = R.string.title),
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )

            // دکمه سراسری توقف در صورت فعال بودن عملیات
            if (isChecking) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(Color(0xFFEF4444))
                        .clickable { stopValidation() }
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = "⏹️ توقف بررسی",
                        color = Color.White,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            } else if (isFetchingSubs) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(Color(0xFFEF4444))
                        .clickable { cancelSubscriptionFetch() }
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = "⏹️ لغو دریافت",
                        color = Color.White,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }

        // نوار تب‌های سه‌گانه
        TabRow(
            selectedTabIndex = selectedTab,
            containerColor = MaterialTheme.colorScheme.surface,
            contentColor = Color.White
        ) {
            Tab(
                selected = selectedTab == 0,
                onClick = { selectedTab = 0 },
                text = { Text(stringResource(R.string.tab_input), fontSize = 12.sp, fontWeight = FontWeight.Bold) }
            )
            Tab(
                selected = selectedTab == 1,
                onClick = { selectedTab = 1 },
                text = { 
                    Text(
                        stringResource(R.string.tab_working, workingCount), 
                        fontSize = 12.sp, 
                        fontWeight = FontWeight.Bold,
                        color = if (workingCount > 0) Color(0xFF10B981) else Color.White
                    ) 
                }
            )
            Tab(
                selected = selectedTab == 2,
                onClick = { selectedTab = 2 },
                text = { Text(stringResource(R.string.tab_logs), fontSize = 12.sp, fontWeight = FontWeight.Bold) }
            )
        }

        Spacer(modifier = Modifier.height(6.dp))

        // --- محتوای تب اول: ورودی و تنظیمات هوشمند ---
        if (selectedTab == 0) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(horizontal = 16.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                // کارت عضویت در کانال تلگرام
                Card(
                    onClick = {
                        try {
                            val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/vpnclashfa"))
                            context.startActivity(intent)
                        } catch (e: Exception) {
                            Toast.makeText(context, "خطا در باز کردن تلگرام: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF1D9BF0).copy(alpha = 0.15f)),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF1D9BF0))
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp, horizontal = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "📢 کانال تلگرام: vpnclashfa@",
                            color = Color(0xFF60A5FA),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            textAlign = TextAlign.Center
                        )
                    }
                }

                // بخش انتخاب پروفایل‌های هوشمند
                Text(
                    text = stringResource(R.string.preset_label),
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium,
                    modifier = Modifier.padding(top = 4.dp, bottom = 4.dp)
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    FilterChip(
                        selected = currentPreset == PresetMode.FAST,
                        onClick = { applyPreset(PresetMode.FAST) },
                        label = { Text("🚀 سریع", fontSize = 11.sp) },
                        modifier = Modifier.weight(1f)
                    )
                    FilterChip(
                        selected = currentPreset == PresetMode.BALANCED,
                        onClick = { applyPreset(PresetMode.BALANCED) },
                        label = { Text("⚖️ متعادل", fontSize = 11.sp) },
                        modifier = Modifier.weight(1f)
                    )
                    FilterChip(
                        selected = currentPreset == PresetMode.NATIONAL,
                        onClick = { applyPreset(PresetMode.NATIONAL) },
                        label = { Text("🐢 اختلال شدید", fontSize = 11.sp) },
                        modifier = Modifier.weight(1.3f)
                    )
                }

                // ردیف فیلدهای عددی همزمانی و تایم‌اوت
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = concurrencyText,
                        onValueChange = { 
                            if (it.all { char -> char.isDigit() }) {
                                concurrencyText = it
                                currentPreset = PresetMode.CUSTOM
                            }
                        },
                        label = { Text(stringResource(id = R.string.placeholder_concurrency)) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = timeoutText,
                        onValueChange = { 
                            if (it.all { char -> char.isDigit() }) {
                                timeoutText = it
                                currentPreset = PresetMode.CUSTOM
                            }
                        },
                        label = { Text(stringResource(id = R.string.placeholder_timeout)) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                }

                // سوییچ فعال/غیرفعال‌سازی پیش‌چک TCP
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = stringResource(R.string.tcp_precheck_label),
                        color = Color.White,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium
                    )
                    Switch(
                        checked = enableTcpPrecheck,
                        onCheckedChange = { 
                            enableTcpPrecheck = it
                            currentPreset = PresetMode.CUSTOM
                        }
                    )
                }

                Spacer(modifier = Modifier.height(4.dp))

                // چیپ‌های انتخاب نحوه ورود داده
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    val modes = listOf(
                        InputMode.PASTE to "کلیپ‌بورد / متن",
                        InputMode.FILE to "انتخاب فایل",
                        InputMode.SUBS to "سابسکریپشن‌ها"
                    )
                    modes.forEach { (mode, label) ->
                        val isSelected = inputMode == mode
                        FilterChip(
                            selected = isSelected,
                            onClick = { inputMode = mode },
                            label = { Text(label, fontSize = 11.sp, fontWeight = FontWeight.Medium) },
                            modifier = Modifier.weight(1f)
                        )
                    }
                }

                // رندر بخش ورودی بر مبنای نوع انتخاب‌شده
                when (inputMode) {
                    InputMode.PASTE -> {
                        Column {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(bottom = 6.dp),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Button(
                                    onClick = { pasteFromClipboard() },
                                    modifier = Modifier.weight(1f),
                                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
                                ) {
                                    Text("جایگذاری از کلیپ‌بورد", fontSize = 11.sp)
                                }
                                Button(
                                    onClick = { inputText = "" },
                                    modifier = Modifier.weight(1f),
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEF4444))
                                ) {
                                    Text("پاک کردن متن", fontSize = 11.sp)
                                }
                            }
                            OutlinedTextField(
                                value = inputText,
                                onValueChange = { inputText = it },
                                label = { Text("پروکسی‌های هر ۴ پروتکل تلگرام (MTProto / SOCKS / HTTP / WebProxy)") },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(170.dp),
                                maxLines = 2000
                            )
                        }
                    }
                    InputMode.FILE -> {
                        Column {
                            Button(
                                onClick = { filePickerLauncher.launch("text/*") },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(bottom = 6.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
                            ) {
                                Text("انتخاب فایل متنی (.txt)", fontSize = 12.sp)
                            }
                            OutlinedTextField(
                                value = inputText,
                                onValueChange = { inputText = it },
                                label = { Text("محتوای فایل انتخاب‌شده") },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(170.dp),
                                maxLines = 2000
                            )
                        }
                    }
                    InputMode.SUBS -> {
                        Column {
                            Button(
                                onClick = { 
                                    if (isFetchingSubs) cancelSubscriptionFetch() else loadSubscriptions() 
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(bottom = 6.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = if (isFetchingSubs) Color(0xFFEF4444) else MaterialTheme.colorScheme.primary
                                )
                            ) {
                                if (isFetchingSubs) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        CircularProgressIndicator(
                                            modifier = Modifier.size(16.dp), 
                                            color = Color.White, 
                                            strokeWidth = 2.dp
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Text("⏹️ لغو دریافت سابسکریپشن‌ها", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                    }
                                } else {
                                    Text(stringResource(id = R.string.load_subs_btn), fontSize = 12.sp)
                                }
                            }
                            OutlinedTextField(
                                value = subscriptionLinksText,
                                onValueChange = { subscriptionLinksText = it },
                                label = { Text("لینک‌های سابسکریپشن عمومی و شخصی (خط‌به‌خط)") },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(170.dp),
                                maxLines = 2000
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                // دکمه شروع یا توقف عملیات بررسی
                Button(
                    onClick = { 
                        if (isChecking) stopValidation() else startValidation() 
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (isChecking) Color(0xFFEF4444) else Color(0xFF10B981)
                    )
                ) {
                    Text(
                        text = if (isChecking) "⏹️ توقف فرآیند بررسی پروکسی‌ها" else "شروع بررسی دقیق هر ۴ پروتکل ⚡", 
                        fontSize = 14.sp, 
                        fontWeight = FontWeight.Bold, 
                        color = Color.White
                    )
                }
                
                Spacer(modifier = Modifier.height(24.dp))
            }
        }

        // --- محتوای تب دوم: لیست تعاملی پروکسی‌های سالم و داشبورد آمار ---
        if (selectedTab == 1) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(horizontal = 16.dp)
            ) {
                // کارت داشبورد آمار کلی
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 6.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = stringResource(id = R.string.stats_checked, checkedCount, totalCount),
                                color = Color.White,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = stringResource(id = R.string.stats_working, workingCount),
                                color = Color(0xFF10B981),
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = stringResource(id = R.string.stats_failed, failedCount),
                                color = Color(0xFFEF4444),
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }

                        Spacer(modifier = Modifier.height(6.dp))

                        // تفکیک آمار ۴ پروتکل در پروکسی‌های سالم
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text("🛡️ MTProto: $workingMtprotoCount", color = Color(0xFF60A5FA), fontSize = 11.sp)
                            Text("🧦 SOCKS: $workingSocks5Count", color = Color(0xFFA78BFA), fontSize = 11.sp)
                            Text("🌐 HTTP: $workingHttpCount", color = Color(0xFFFBBF24), fontSize = 11.sp)
                            Text("⚡ Web: $workingWebproxyCount", color = Color(0xFF2DD4BF), fontSize = 11.sp)
                        }

                        if (bestPing > 0L) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text("⚡ بهترین پینگ: ${bestPing}ms", color = Color(0xFF34D399), fontSize = 11.sp)
                                Text("میانگین پینگ: ${avgPing}ms", color = Color(0xFF94A3B8), fontSize = 11.sp)
                            }
                        }
                    }
                }

                // نوار پیشرفت و دکمه توقف فوری در صورت فعال بودن بررسی
                if (isChecking) {
                    val progress = if (totalCount > 0) (checkedCount.toFloat() / totalCount.toFloat()).coerceIn(0f, 1f) else 0f
                    LinearProgressIndicator(
                        progress = progress,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 6.dp)
                            .clip(RoundedCornerShape(4.dp)),
                        color = Color(0xFF3B82F6),
                        trackColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.5f)
                    )
                    Button(
                        onClick = { stopValidation() },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 6.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEF4444))
                    ) {
                        Text(
                            text = "⏹️ توقف فرآیند بررسی پروکسی‌ها", 
                            fontSize = 12.sp, 
                            fontWeight = FontWeight.Bold, 
                            color = Color.White
                        )
                    }
                }

                // دکمه اتصال به بهترین پروکسی
                Button(
                    onClick = { connectToBestProxy() },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1D9BF0))
                ) {
                    Text(
                        text = "🚀 اتصال مستقیم به بهترین پروکسی (کمترین پینگ)",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                }

                Spacer(modifier = Modifier.height(6.dp))

                // دکمه‌های کپی و خروجی‌ها
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Button(
                        onClick = { copyAllToClipboard() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6)),
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 6.dp)
                    ) {
                        Text(stringResource(id = R.string.copy_all), fontSize = 11.sp)
                    }
                    Button(
                        onClick = { exportAsTxt() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF059669)),
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 6.dp)
                    ) {
                        Text(stringResource(id = R.string.export_file), fontSize = 11.sp)
                    }
                    Button(
                        onClick = { exportAsJson() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1)),
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 6.dp)
                    ) {
                        Text(stringResource(id = R.string.export_json), fontSize = 11.sp)
                    }
                }

                Spacer(modifier = Modifier.height(6.dp))

                // ردیف کپی N تای برتر
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = topNText,
                        onValueChange = { if (it.all { char -> char.isDigit() }) topNText = it },
                        label = { Text("تعداد", fontSize = 10.sp) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.width(75.dp),
                        singleLine = true
                    )
                    Button(
                        onClick = { copyTopNToClipboard() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF8B5CF6)),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 6.dp)
                    ) {
                        Text(
                            text = "📋 کپی $topNText تای برتر",
                            fontSize = 12.sp,
                            maxLines = 1
                        )
                    }
                }

                Spacer(modifier = Modifier.height(6.dp))

                // لیست تعاملی پروکسی‌های سالم با شناسه کاملاً یکتا برای جلوگیری قطعی از کرش
                val sortedWorking = remember(workingProxies.size, isChecking) {
                    workingProxies.sortedBy { it.ping }
                }

                if (sortedWorking.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .weight(1f),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = if (isChecking) "در حال بررسی پروکسی‌ها... ⏳" else "هنوز پروکسی سالمی ثبت نشده است.\nاز تب اول بررسی را شروع کنید.",
                            color = Color(0xFF64748B),
                            fontSize = 13.sp,
                            textAlign = TextAlign.Center
                        )
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .weight(1f)
                    ) {
                        items(sortedWorking, key = { it.id }) { proxy ->
                            Card(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp),
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(10.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            // برچسب نوع پروتکل
                                            val badgeColor = when (proxy.type) {
                                                ProxyType.MTPROTO -> Color(0xFF3B82F6)
                                                ProxyType.SOCKS5 -> Color(0xFF8B5CF6)
                                                ProxyType.HTTP -> Color(0xFFF59E0B)
                                                ProxyType.WEBPROXY -> Color(0xFF14B8A6)
                                            }
                                            Box(
                                                modifier = Modifier
                                                    .clip(RoundedCornerShape(4.dp))
                                                    .background(badgeColor)
                                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                                            ) {
                                                Text(
                                                    text = proxy.type.name,
                                                    color = Color.White,
                                                    fontSize = 10.sp,
                                                    fontWeight = FontWeight.Bold
                                                )
                                            }
                                            Spacer(modifier = Modifier.width(8.dp))
                                            // برچسب پینگ
                                            val pingColor = when {
                                                proxy.ping in 1..300 -> Color(0xFF10B981)
                                                proxy.ping in 301..800 -> Color(0xFFF59E0B)
                                                else -> Color(0xFFEF4444)
                                            }
                                            Text(
                                                text = "${proxy.ping} ms",
                                                color = pingColor,
                                                fontSize = 11.sp,
                                                fontWeight = FontWeight.Bold
                                            )
                                        }
                                        Spacer(modifier = Modifier.height(4.dp))
                                        Text(
                                            text = "${proxy.host}:${proxy.port}",
                                            color = Color.White,
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.Medium,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }

                                    // دکمه‌های عملیات روی کارت
                                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                        Button(
                                            onClick = {
                                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                                clipboard.setPrimaryClip(ClipData.newPlainText("proxy", proxy.originalUrl))
                                                Toast.makeText(context, "کپی شد!", Toast.LENGTH_SHORT).show()
                                            },
                                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF334155)),
                                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                                            modifier = Modifier.height(32.dp)
                                        ) {
                                            Text("📋 کپی", fontSize = 11.sp)
                                        }
                                        Button(
                                            onClick = { connectToProxy(proxy.originalUrl) },
                                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1D9BF0)),
                                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                                            modifier = Modifier.height(32.dp)
                                        ) {
                                            Text("🚀 اتصال", fontSize = 11.sp, color = Color.White)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // --- محتوای تب سوم: مانیتور و لاگ‌های سیستمی ---
        if (selectedTab == 2) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(horizontal = 16.dp)
            ) {
                // دکمه کنترل توقف/شروع
                Button(
                    onClick = { if (isChecking) stopValidation() else startValidation() },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (isChecking) Color(0xFFEF4444) else Color(0xFF10B981)
                    )
                ) {
                    Text(
                        text = if (isChecking) stringResource(id = R.string.stop_btn) else stringResource(id = R.string.start_btn),
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                }

                Spacer(modifier = Modifier.height(6.dp))

                // نوار پیشرفت
                if (isChecking && totalCount > 0) {
                    val progress = (checkedCount.toFloat() / totalCount.toFloat()).coerceIn(0f, 1f)
                    LinearProgressIndicator(
                        progress = progress,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 6.dp)
                            .clip(RoundedCornerShape(4.dp)),
                        color = MaterialTheme.colorScheme.primary,
                        trackColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.5f)
                    )
                }

                // کادر ترمینال متنی لاگ‌ها
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
            }
        }
    }
}
