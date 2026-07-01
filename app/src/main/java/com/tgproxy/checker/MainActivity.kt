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
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import com.tgproxy.checker.R

enum class InputMode { PASTE, FILE, SUBS }

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
    
    // راه‌اندازی ذخیره‌ساز محلی تنظیمات برای ماندگاری اطلاعات
    val prefs = remember { context.getSharedPreferences("tg_proxy_checker_prefs", Context.MODE_PRIVATE) }

    // منابع اشتراک پیش‌فرض
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

    // متغیرهای حالت متصل به SharedPreferences
    var inputText by remember { mutableStateOf(prefs.getString("input_text", "") ?: "") }
    var concurrencyText by remember { mutableStateOf(prefs.getString("concurrency", "50") ?: "50") }
    var timeoutText by remember { mutableStateOf(prefs.getString("timeout", "5") ?: "5") }
    var topNText by remember { mutableStateOf(prefs.getString("top_n", "5") ?: "5") }
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

    // ذخیره خودکار تغییرات تنظیمات در زمان ویرایش کاربر
    LaunchedEffect(inputText) { prefs.edit().putString("input_text", inputText).apply() }
    LaunchedEffect(concurrencyText) { prefs.edit().putString("concurrency", concurrencyText).apply() }
    LaunchedEffect(timeoutText) { prefs.edit().putString("timeout", timeoutText).apply() }
    LaunchedEffect(topNText) { prefs.edit().putString("top_n", topNText).apply() }
    LaunchedEffect(inputMode) { prefs.edit().putString("input_mode", inputMode.name).apply() }
    LaunchedEffect(subscriptionLinksText) { prefs.edit().putString("sub_links", subscriptionLinksText).apply() }

    var isChecking by remember { mutableStateOf(false) }
    var checkJob by remember { mutableStateOf<Job?>(null) }

    val proxyList = remember { mutableStateListOf<ProxyItem>() }
    val logsList = remember { mutableStateListOf<String>() }

    // آمار زنده
    var checkedCount by remember { mutableIntStateOf(0) }
    var workingCount by remember { mutableIntStateOf(0) }
    var failedCount by remember { mutableIntStateOf(0) }

    // راه‌انداز فایل‌پیکر سیستم اندروید برای ایمپورت فایل متنی
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            coroutineScope.launch {
                try {
                    val contentResolver = context.contentResolver
                    val inputStream = contentResolver.openInputStream(it)
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
        logsList.add("[$timeStamp] $message")
    }

    // جایگذاری متن از کلیپ‌بورد سیستم
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

    // لود لینک‌های اشتراک از کادر قابل ویرایش
    fun loadSubscriptions() {
        val links = subscriptionLinksText.split("\n").map { it.trim() }.filter { it.isNotEmpty() }
        if (links.isEmpty()) {
            Toast.makeText(context, "لیست لینک‌های اشتراک خالی است!", Toast.LENGTH_SHORT).show()
            return
        }
        coroutineScope.launch {
            appendLog("Fetching subscription links...")
            val fetchedProxies = mutableListOf<String>()
            links.forEach { subUrl ->
                val list = SubscriptionFetcher.fetchSubscription(subUrl) { msg ->
                    appendLog(msg)
                }
                list.forEach { fetchedProxies.add(it.originalUrl) }
            }
            if (fetchedProxies.isNotEmpty()) {
                inputText = fetchedProxies.joinToString("\n")
                appendLog("Loaded ${fetchedProxies.size} proxies from sub links.")
                // سوئیچ خودکار به تب اول برای ادیت پروکسی‌ها
                inputMode = InputMode.PASTE
            } else {
                appendLog("No fresh proxies found in sub links (within last 7 days).")
            }
        }
    }

    // متدهای مربوط به کپی و خروجی با الگو دو خط فاصله جدید
    fun copyAllToClipboard() {
        val working = proxyList.filter { it.status == "Working" }.sortedBy { it.ping }
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
        val n = topNText.toIntOrNull() ?: 5
        val working = proxyList.filter { it.status == "Working" }.sortedBy { it.ping }.take(n)
        if (working.isEmpty()) {
            Toast.makeText(context, context.getString(R.string.toast_empty), Toast.LENGTH_SHORT).show()
            return
        }
        val text = working.joinToString("\n\n") { it.originalUrl }
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
        val text = working.joinToString("\n\n") { it.originalUrl }
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
                .padding(bottom = 6.dp),
            textAlign = TextAlign.Center
        )

        // بخش گرافیکی دعوت به کانال تلگرام حامی برنامه
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
                .padding(bottom = 12.dp),
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
                    text = "📢 عضویت در کانال تلگرام vpnclashfa",
                    color = Color(0xFF60A5FA),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center
                )
            }
        }

        // ردیف تنظیمات: همزمانی و تایم اوت
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 12.dp),
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

        // نوار انتخاب سه حالته ورودی‌ها با فیلتر چیپ‌ها
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            val modes = listOf(
                InputMode.PASTE to "کلیپ‌بورد / متن",
                InputMode.FILE to "انتخاب فایل",
                InputMode.SUBS to "لینک‌های اشتراک"
            )
            modes.forEach { (mode, label) ->
                val isSelected = inputMode == mode
                FilterChip(
                    selected = isSelected,
                    onClick = { inputMode = mode },
                    label = { Text(label, fontSize = 11.sp, fontWeight = FontWeight.Medium) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = MaterialTheme.colorScheme.primary,
                        selectedLabelColor = Color.White
                    ),
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // رندر کردن ویجت ورودی بر مبنای نوع انتخاب‌شده با برچسب‌های ثابت و رفع همپوشانی
        when (inputMode) {
            InputMode.PASTE -> {
                Column {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 8.dp),
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
                        label = { Text("لیست پروکسی‌ها (هر پروکسی در یک خط)") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(130.dp),
                        maxLines = 1000
                    )
                }
            }
            InputMode.FILE -> {
                Column {
                    Button(
                        onClick = { filePickerLauncher.launch("text/*") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 8.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
                    ) {
                        Text("انتخاب فایل متنی (.txt)", fontSize = 13.sp)
                    }
                    OutlinedTextField(
                        value = inputText,
                        onValueChange = { inputText = it },
                        label = { Text("لیست پروکسی‌های بارگذاری شده از فایل") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(130.dp),
                        maxLines = 1000
                    )
                }
            }
            InputMode.SUBS -> {
                Column {
                    Button(
                        onClick = { loadSubscriptions() },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 8.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
                    ) {
                        Text(stringResource(id = R.string.load_subs_btn), fontSize = 13.sp)
                    }
                    OutlinedTextField(
                        value = subscriptionLinksText,
                        onValueChange = { subscriptionLinksText = it },
                        label = { Text("لینک‌های اشتراک پروکسی (قابل ویرایش)") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(130.dp),
                        maxLines = 1000
                    )
                }
            }
        }

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

        // نمایش پیشرفت زنده تست
        if (isChecking && proxyList.isNotEmpty()) {
            val progress = checkedCount.toFloat() / proxyList.size.toFloat()
            LinearProgressIndicator(
                progress = progress,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 8.dp)
                    .clip(RoundedCornerShape(4.dp)),
                color = MaterialTheme.colorScheme.primary,
                trackColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.5f)
            )
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
                Text(stringResource(id = R.string.copy_all), fontSize = 11.sp)
            }
            Button(
                onClick = { exportAsTxt() },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF059669))
            ) {
                Text(stringResource(id = R.string.export_file), fontSize = 11.sp)
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // کپی تعداد مشخص از بهترین‌ها با طراحی کامپکت و عاری از به‌هم‌ریختگی
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = topNText,
                onValueChange = { if (it.all { char -> char.isDigit() }) topNText = it },
                label = { Text("تعداد برتر", fontSize = 10.sp) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.width(90.dp),
                singleLine = true
            )
            Button(
                onClick = { copyTopNToClipboard() },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF8B5CF6)),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(
                    text = "کپی $topNText پروکسی برتر",
                    fontSize = 12.sp,
                    maxLines = 1
                )
            }
        }
    }
}
