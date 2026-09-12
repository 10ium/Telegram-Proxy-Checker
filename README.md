# 🛡️ Telegram Proxy Checker Android

A powerful, native Android application written in Kotlin and Jetpack Compose to extract, sanitize, and verify **all 4 official Telegram proxy protocols** with real protocol handshakes directly to Telegram datacenters, completely eliminating the "Connecting..." freeze issue.

📢 **Official Telegram Channel:** [@vpnclashfa](https://t.me/vpnclashfa)

---

## 🌟 Key Features

* **🌐 Full 4-Protocol Support:**
  1. **MTProto:** Classic 16-byte hex secrets, `dd`-prefixed secrets, and anti-censorship **Fake-TLS** (`ee`-prefixed secrets with SNI domain spoofing).
  2. **SOCKS5:** RFC1928 native socket handshakes with optional username/password authentication (`tg://socks` and `socks5://`).
  3. **HTTP / HTTPS:** HTTP CONNECT tunneling to Telegram core servers with optional Basic auth (`tg://http` and standard HTTP proxies).
  4. **WebProxy:** Telegram's modern WebProxy protocol over TLS/WebSocket on port 443 (`tg://webproxy`).
* **🎯 Intelligent Speed & Network Presets:**
  * 🚀 **Fast:** Timeout 3s | Concurrency 50 | TCP Pre-check ON
  * ⚖️ **Balanced (Default):** Timeout 5s | Concurrency 25 | TCP Pre-check ON
  * 🐢 **Heavy Censorship / Intranet:** Timeout 60s (1 min) | Concurrency 10 | TCP Pre-check OFF (deep verification bypassing national firewalls without dropping slow proxies)
  * 🛠️ **Custom:** Fully manual control over timeout, concurrency, and TCP pre-check.
* **📋 Interactive Working Proxies List:**
  * Individual cards for every verified proxy
  * Color-coded protocol tags and latency badges (🟢 < 300ms, 🟡 < 800ms, 🔴 > 800ms)
  * 🚀 **1-Tap Connect** to launch individual proxies directly in Telegram
  * 📋 **1-Tap Copy** for individual proxy links
* **📊 Real-Time Stats Dashboard:**
  * Live breakdown of working proxies by protocol (`MTProto`, `SOCKS5`, `HTTP`, `WebProxy`)
  * Lowest latency (best ping) and average ping calculation
* **📥 Resilient Subscription System:**
  * High timeouts (25s connect / 45s read) and streaming reading to handle massive lists under poor internet conditions without premature cancellation
  * Built-in curated list of 10 active public subscriptions
  * Automatic Base64 decoding
* **💾 Rich Export Tools:**
  * 1-Click connect best proxy to Telegram
  * Copy Top N (default top 10)
  * Copy all working proxies
  * Share as Text (.txt) or structured JSON (.json)
* **🤖 GitHub Actions CI/CD:**
  * Automated building, versioning, signing, and releasing of signed release APKs (`Telegram-Proxy-Checker-vX.X.X.apk`).

---

## 📦 Tech Stack & Architecture

* **Kotlin & Jetpack Compose:** Material 3 dark-themed modern UI
* **Coroutines & Semaphores:** Non-blocking concurrent socket verification
* **Low-Level Sockets:** Pure Java/Android socket implementations avoiding JVM global proxy pollution
