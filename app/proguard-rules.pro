# Proguard rules for Telegram Proxy Checker
-keepattributes *Annotation*
-keepclassmembers class * {
    @androidx.compose.runtime.Composable *;
    @androidx.compose.runtime.ReadOnlyComposable *;
}
-keep class androidx.compose.** { *; }
-keep class androidx.compose.animation.** { *; }
-keep class androidx.compose.animation.core.** { *; }
-keep class androidx.compose.material3.** { *; }
-keep class com.tgproxy.checker.** { *; }
-dontwarn androidx.compose.**
