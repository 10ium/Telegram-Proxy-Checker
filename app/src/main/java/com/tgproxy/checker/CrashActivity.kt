package com.tgproxy.checker

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

class CrashActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val crashLog = intent.getStringExtra("CRASH_LOG") ?: "No error details available."

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
                    CrashScreen(crashLog = crashLog) {
                        val restartIntent = Intent(this, MainActivity::class.java).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                        }
                        startActivity(restartIntent)
                        finish()
                    }
                }
            }
        }
    }
}

@Composable
fun CrashScreen(crashLog: String, onRestart: () -> Unit) {
    val context = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(16.dp))

        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(8.dp))
                .background(Color(0xFFEF4444).copy(alpha = 0.2f))
                .border(1.dp, Color(0xFFEF4444), RoundedCornerShape(8.dp))
                .padding(horizontal = 12.dp, vertical = 6.dp)
        ) {
            Text(
                text = "⚠️ گزارش خطای سیستمی (Crash Report)",
                color = Color(0xFFF87171),
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = "برنامه با یک خطای غیرمنتظره متوقف شد.\nبرای رفع سریع مشکل، دکمه کپی زیر را بزنید و متن را برای برنامه‌نویس ارسال کنید:",
            color = Color(0xFFE2E8F0),
            fontSize = 12.sp,
            textAlign = TextAlign.Center,
            lineHeight = 18.sp
        )

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Telegram_Proxy_Crash_Log", crashLog))
                Toast.makeText(context, "✅ متن کامل خطا در کلیپ‌بورد کپی شد!", Toast.LENGTH_LONG).show()
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6))
        ) {
            Text(
                text = "📋 کپی متن کامل خطا (جهت ارسال به پشتیبانی)",
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        OutlinedButton(
            onClick = onRestart,
            modifier = Modifier
                .fillMaxWidth()
                .height(44.dp)
        ) {
            Text(
                text = "🔄 راه‌اندازی مجدد برنامه",
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFF10B981)
            )
        }

        Spacer(modifier = Modifier.height(14.dp))

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .clip(RoundedCornerShape(8.dp))
                .background(Color.Black)
                .border(1.dp, Color(0xFF334155), RoundedCornerShape(8.dp))
                .padding(10.dp)
        ) {
            Text(
                text = crashLog,
                color = Color(0xFFFCA5A5),
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
            )
        }
    }
}
