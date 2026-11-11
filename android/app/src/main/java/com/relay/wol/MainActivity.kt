package com.relay.wol
import android.content.*
import android.net.Uri
import android.os.*
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.text.input.PasswordVisualTransformation
import kotlinx.coroutines.delay
import java.net.HttpURLConnection
import java.net.URL

const val TS_PKG = "com.tailscale.ipn"

/** Mints a one-time Tailscale auth key (valid 1 hour) using the owner's API access token. */
fun createAuthKey(api: String): String {
    val c = URL("https://api.tailscale.com/api/v2/tailnet/-/keys").openConnection() as HttpURLConnection
    c.requestMethod = "POST"; c.doOutput = true; c.connectTimeout = 10000; c.readTimeout = 10000
    c.setRequestProperty("Authorization", "Bearer $api"); c.setRequestProperty("Content-Type", "application/json")
    c.outputStream.use { it.write("""{"capabilities":{"devices":{"create":{"reusable":false,"ephemeral":false,"preauthorized":true}}},"expirySeconds":3600}""".toByteArray()) }
    val ok = c.responseCode in 200..299
    val txt = (if (ok) c.inputStream else c.errorStream).bufferedReader().readText()
    if (!ok) throw Exception("HTTP ${c.responseCode}: ${txt.take(100)}")
    return org.json.JSONObject(txt).getString("key")
}

class MainActivity : ComponentActivity() {
    private var clipKey by mutableStateOf<String?>(null)
    override fun onWindowFocusChanged(f: Boolean) {
        super.onWindowFocusChanged(f)
        if (!f) return
        val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        val t = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()?.trim()
        if (t != null && t.startsWith("tskey-api-")) { clipKey = t; if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip() }
    }
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 0)
        if (prefs(this).getBoolean("on", true)) startForegroundService(Intent(this, RelayService::class.java))
        setContent { MaterialTheme(colorScheme = darkColorScheme(primary = Color(0xFF6C8CFF))) { Screen() } }
    }

    private fun tsInstalled() = runCatching { packageManager.getPackageInfo(TS_PKG, 0); true }.getOrDefault(false)
    private fun batteryOk() = (getSystemService(POWER_SERVICE) as PowerManager).isIgnoringBatteryOptimizations(packageName)
    private fun installTs() = runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=$TS_PKG"))) }
        .onFailure { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=$TS_PKG"))) }
    private fun openTs() { packageManager.getLaunchIntentForPackage(TS_PKG)?.let { startActivity(it) } }
    private fun askBattery() = startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))

    @Composable fun Card(content: @Composable ColumnScope.() -> Unit) =
        Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(Color(0x14FFFFFF)).padding(20.dp), content = content)

    @Composable fun StepRow(done: Boolean, title: String, action: String, enabled: Boolean, onClick: () -> Unit) {
        Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(if (done) "✔" else "○", color = if (done) Color(0xFF22C55E) else Color.Gray, fontSize = 20.sp)
            Text(title, color = Color.White, modifier = Modifier.weight(1f).padding(horizontal = 12.dp))
            if (!done) Button(onClick, enabled = enabled) { Text(action) }
        }
    }

    @Composable fun Screen() {
        var installed by remember { mutableStateOf(tsInstalled()) }
        var ip by remember { mutableStateOf<String?>(null) }
        var batt by remember { mutableStateOf(batteryOk()) }
        var on by remember { mutableStateOf(prefs(this).getBoolean("on", true)) }
        var apiKey by remember { mutableStateOf(prefs(this).getString("api", "") ?: "") }
        var pcToken by remember { mutableStateOf("") }
        var msg by remember { mutableStateOf("") }
        var log by remember { mutableStateOf(loadLog(this)) }
        var clients by remember { mutableStateOf(loadClients(this)) }
        var pinState by remember { mutableStateOf(loadPins(this)) }
        var lan by remember { mutableStateOf(loadLan(this)) }
        var hosts by remember { mutableStateOf(loadHosts(this)) }
        var scanning by remember { mutableStateOf(false) }
        var page by rememberSaveable { mutableStateOf("home") }     // home | approved | devices | logs
        var confirmRemove by remember { mutableStateOf<Client?>(null) }
        var confirmHost by remember { mutableStateOf<Host?>(null) }
        var openId by rememberSaveable { mutableStateOf("") }       // secret of the expanded client row
        BackHandler(page != "home") { page = "home" }
        var tried by rememberSaveable { mutableStateOf(0) }   // each step auto-opens once

        LaunchedEffect(Unit) { while (true) { installed = tsInstalled(); ip = tailscaleIp(); batt = batteryOk(); log = loadLog(this@MainActivity); clients = loadClients(this@MainActivity); pinState = loadPins(this@MainActivity); lan = loadLan(this@MainActivity); hosts = loadHosts(this@MainActivity); delay(1500) } }
        LaunchedEffect(installed, ip, batt) {
            when {
                !installed && tried and 1 == 0 -> { tried = tried or 1; installTs() }
                installed && ip == null && tried and 2 == 0 -> { tried = tried or 2; openTs() }
                installed && ip != null && !batt && tried and 4 == 0 -> { tried = tried or 4; askBattery() }
            }
        }
        val ready = installed && ip != null && batt
        val generate: () -> Unit = {
            msg = "Generating…"; pcToken = ""
            Thread { try {
                val myIp = tailscaleIp() ?: throw Exception("Tailscale is not connected on this phone")
                val unused = loadClients(this@MainActivity).firstOrNull { it.ip.isEmpty() }       // a token nobody has used yet: never make a second one, reuse it
                val key = createAuthKey(apiKey.trim())
                val sec = unused?.secret ?: newSecret()   // one token = one device (a client OR a host); it gets bound to the first device that uses it
                val full = "$key~$sec~$myIp"; val now = System.currentTimeMillis()
                editClients(this@MainActivity) { l -> val k = l.indexOfFirst { it.secret == sec }; if (k >= 0) l[k] = l[k].copy(token = full, made = now) else l += Client(sec, "", "", 0, 0, 0, "pc", full, now) }
                pcToken = full; msg = if (unused != null) "Your unused token was renewed (same token, fresh Tailscale key). Use it before making another." else "Done. Paste this token into the PC app."
            } catch (e: Exception) {
                if (e.message?.contains("HTTP 401") == true || e.message?.contains("HTTP 403") == true) {
                    apiKey = ""; prefs(this@MainActivity).edit().remove("api").apply()
                    msg = "Tailscale access expired. Tap the button to sign in again."
                } else msg = "Failed: ${e.message}" } }.start()
        }
        LaunchedEffect(clipKey) { clipKey?.let { apiKey = it; prefs(this@MainActivity).edit().putString("api", it).apply(); clipKey = null; generate() } }

        fun fmt(t: Long) = if (t <= 0) "—" else java.text.SimpleDateFormat("dd MMM yyyy HH:mm", java.util.Locale.getDefault()).format(java.util.Date(t))
        confirmRemove?.let { c -> AlertDialog(onDismissRequest = { confirmRemove = null },
            title = { Text("Remove ${c.name.ifEmpty { "this token" }}?") },
            text = { Text("Its token stops working immediately, so it can no longer use this phone." + if (c.role == "host") " The saved MAC address of this host is deleted too." else "") },
            confirmButton = { TextButton({ editClients(this@MainActivity) { l -> l.removeAll { it.secret == c.secret } }; if (c.role == "host" && c.ip.isNotEmpty()) editHosts(this@MainActivity) { l -> l.removeAll { it.ip == c.ip } }; clients = loadClients(this@MainActivity); hosts = loadHosts(this@MainActivity); confirmRemove = null }) { Text("Remove", color = Color(0xFFEF4444)) } },
            dismissButton = { TextButton({ confirmRemove = null }) { Text("Cancel") } }) }

        confirmHost?.let { h -> AlertDialog(onDismissRequest = { confirmHost = null },
            title = { Text("Remove ${h.name.ifEmpty { h.ip }}?") },
            text = { Text("The saved MAC address of this host and its token are deleted from this phone. To add the host again, generate a new token and paste it into WoL Host > Set up.") },
            confirmButton = { TextButton({ editHosts(this@MainActivity) { l -> l.removeAll { it.ip == h.ip } }; editClients(this@MainActivity) { l -> l.removeAll { it.role == "host" && it.ip == h.ip } }
                hosts = loadHosts(this@MainActivity); clients = loadClients(this@MainActivity); confirmHost = null }) { Text("Remove", color = Color(0xFFEF4444)) } },
            dismissButton = { TextButton({ confirmHost = null }) { Text("Cancel") } }) }

        // a host whose token was used is detected at once (its first request marks the token as WoL Host's); its MAC address is added as soon as it arrives
        val shownClients = clients.filter { it.role != "host" }      // WoL Host's own token is listed under Hosts only, never as a client
        val pendingHosts = clients.filter { it.role == "host" && it.ip.isNotEmpty() && hosts.none { h -> h.ip == it.ip } }
        Column(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0xFF0B1020), Color(0xFF1A1440))))
            .statusBarsPadding().verticalScroll(rememberScrollState()).padding(20.dp).navigationBarsPadding(), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            if (page == "logs") {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextButton({ page = "home" }) { Text("← Back") }
                    Text("Wake log", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.weight(1f))
                    TextButton({ prefs(this@MainActivity).edit().remove("log").apply(); log = emptyList() }) { Text("Clear") }
                }
                Card {
                    if (log.isEmpty()) Text("No wake requests yet.", color = Color.Gray)
                    log.forEach { Text(it, color = Color.White, fontSize = 12.sp, modifier = Modifier.padding(vertical = 2.dp)) }
                }
                return@Column
            }
            Text("⏻ WoL Relay", fontSize = 30.sp, fontWeight = FontWeight.Bold, color = Color.White)
            TabRow(selectedTabIndex = if (page == "approved") 1 else if (page == "devices") 2 else 0, containerColor = Color.Transparent) {
                Tab(page == "home", { page = "home" }, text = { Text("Home") })
                Tab(page == "approved", { page = "approved" }, text = { Text("Clients (${shownClients.count { it.ip.isNotEmpty() }})") })
                Tab(page == "devices", { page = "devices" }, text = { Text("Hosts (${hosts.size + pendingHosts.size})") })
            }
            if (page == "devices") {
                Card {
                    Text("Hosts", color = Color.White, fontWeight = FontWeight.SemiBold)
                    Text("A host is a PC set up with WoL Host. When it joins with a token it sends its Tailscale IP and physical MAC address here, so this phone can wake it. Clients get this list automatically when they join. Remove a host to forget it.",
                        color = Color.Gray, fontSize = 13.sp, modifier = Modifier.padding(top = 6.dp))
                }
                pendingHosts.forEach { c -> Card {
                    Text(c.name.ifEmpty { c.ip }, color = Color.White, fontWeight = FontWeight.SemiBold)
                    Text("Detected · waiting for its MAC address", color = Color(0xFFF59E0B), fontSize = 13.sp, modifier = Modifier.padding(top = 2.dp))
                    Text("Tailscale IP: ${c.ip}", color = Color.Gray, fontSize = 13.sp, modifier = Modifier.padding(top = 4.dp))
                    OutlinedButton({ confirmRemove = c }, Modifier.fillMaxWidth().padding(top = 10.dp)) { Text("Remove host", color = Color(0xFFEF4444)) }
                } }
                if (hosts.isEmpty() && pendingHosts.isEmpty()) Card { Text("No hosts yet. Generate a token on the Home tab and paste it into WoL Host > Set up; the host appears here by itself.", color = Color.Gray) }
                hosts.sortedByDescending { it.updated }.forEach { h -> Card {
                    Text(h.name.ifEmpty { h.ip }, color = Color.White, fontWeight = FontWeight.SemiBold)
                    h.macs.forEach { Text("MAC  $it", color = Color.White, fontSize = 13.sp, modifier = Modifier.padding(top = 2.dp)) }
                    Text("Tailscale IP: ${h.ip}", color = Color.Gray, fontSize = 13.sp, modifier = Modifier.padding(top = 4.dp))
                    Text("Saved: ${fmt(h.updated)}", color = Color.Gray, fontSize = 13.sp)
                    OutlinedButton({ confirmHost = h }, Modifier.fillMaxWidth().padding(top = 10.dp)) { Text("Remove host", color = Color(0xFFEF4444)) }
                } }
                Card {
                    Text("Network scan", color = Color.White, fontWeight = FontWeight.SemiBold)
                    Text("Physical MAC addresses this phone finds on its Wi-Fi / LAN. WoL Remote gets this list from here, and only with the access PIN set in WoL Host.",
                        color = Color.Gray, fontSize = 13.sp, modifier = Modifier.padding(vertical = 6.dp))
                    Button({ if (!scanning) { scanning = true
                            Thread { runCatching { saveLan(this@MainActivity, discoverLan()) }; scanning = false }.start() } },
                        Modifier.fillMaxWidth(), enabled = !scanning) { Text(if (scanning) "Scanning…" else "Scan now") }
                }
                lan.forEach { d -> Card {
                    Text(d.mac, color = Color.White, fontWeight = FontWeight.SemiBold)
                    Text(d.ip, color = Color.Gray, fontSize = 13.sp)
                } }
                return@Column
            }
            if (page == "approved") {
                if (shownClients.isEmpty()) Card { Text("No clients yet. Generate a token on the Home tab and paste it into the app.", color = Color.Gray) }
                shownClients.sortedByDescending { it.last }.forEach { c ->
                    val bound = c.ip.isNotEmpty(); val open = openId == c.secret
                    Card {
                        Row(Modifier.fillMaxWidth().clickable { openId = if (open) "" else c.secret }, verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(if (bound) c.name.ifEmpty { c.ip } else "Unused token", color = Color.White, fontWeight = FontWeight.SemiBold)
                                Text(if (bound) "Approved · ${c.ip}${if (c.role == "host") " · WoL Host (PIN sync)" else ""}" else "Waiting for a client or host to connect", color = if (bound) Color(0xFF22C55E) else Color(0xFFF59E0B), fontSize = 13.sp)
                            }
                            Text(if (open) "▲" else "▼", color = Color.Gray)
                        }
                        if (open) {
                            Column(Modifier.padding(top = 12.dp)) {
                                if (bound) {
                                    Text("Name: ${c.name.ifEmpty { "—" }}", color = Color.White, fontSize = 13.sp)
                                    Text("Tailscale IP: ${c.ip}", color = Color.White, fontSize = 13.sp)
                                    Text("First connected: ${fmt(c.first)}", color = Color.White, fontSize = 13.sp)
                                    Text("Last seen: ${fmt(c.last)}", color = Color.White, fontSize = 13.sp)
                                    Text("Wake requests: ${c.wakes}", color = Color.White, fontSize = 13.sp)
                                } else Text("This token has not been used yet. The first client or host that uses it will be locked to it.", color = Color.Gray, fontSize = 13.sp)
                                OutlinedButton({ confirmRemove = c }, Modifier.fillMaxWidth().padding(top = 10.dp)) { Text(if (bound) "Remove client" else "Delete token", color = Color(0xFFEF4444)) }
                            }
                        }
                    }
                }
                if (shownClients.isNotEmpty()) OutlinedButton({ editClients(this@MainActivity) { l -> l.removeAll { it.role != "host" } }; clients = loadClients(this@MainActivity); pcToken = ""; openId = ""; msg = "All clients unpaired." },
                    Modifier.fillMaxWidth().padding(top = 12.dp)) { Text("Unpair all clients", color = Color(0xFFEF4444)) }
                return@Column
            }
            if (!ready) Card {
                Text("Setup", color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 18.sp)
                Text("Finish these steps once. Each opens automatically and this screen updates when it's done.",
                    color = Color.Gray, modifier = Modifier.padding(vertical = 6.dp))
                StepRow(installed, "Install Tailscale", "Install", true) { installTs() }
                StepRow(ip != null, "Sign in to Tailscale", "Sign in", installed) { openTs() }
                StepRow(batt, "Keep relay always on", "Allow", true) { askBattery() }
            } else Card { Text("✔ Setup complete", color = Color(0xFF22C55E), fontWeight = FontWeight.SemiBold) }
            Card {
                Text("PC token", color = Color.White, fontWeight = FontWeight.SemiBold)
                Text("Each token works for ONE PC only. Generate a separate token for every PC you want to connect. First time only: the app opens Tailscale so you can sign in and copy an access token; it picks it up automatically.",
                    color = Color.Gray, fontSize = 13.sp, modifier = Modifier.padding(vertical = 6.dp))
                val unusedTok = clients.firstOrNull { it.ip.isEmpty() && it.token.isNotEmpty() && System.currentTimeMillis() - it.made < 3300000 }      // its Tailscale key is still valid (1 h)
                Button({ if (unusedTok != null) { pcToken = unusedTok.token; msg = "You already have an unused token. Use it first - a new one can only be made after it has joined a device." }
                    else if (apiKey.isBlank()) {
                        msg = "Sign in, tap \"Generate access token\", then Copy. Come back here and I'll finish automatically."
                        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://login.tailscale.com/admin/settings/keys")))
                    } else generate() },
                    Modifier.fillMaxWidth()) { Text(if (unusedTok != null) "Show unused token" else if (apiKey.isBlank()) "Get access from Tailscale & generate token" else "Generate PC token") }
                if (msg.isNotEmpty()) Text(msg, color = Color(0xFF9DB2FF), modifier = Modifier.padding(top = 8.dp))
                if (pcToken.isNotEmpty()) {
                    Text(pcToken, color = Color.White, fontSize = 13.sp, modifier = Modifier.padding(vertical = 8.dp))
                    OutlinedButton({ (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("t", pcToken)) },
                        Modifier.fillMaxWidth()) { Text("Copy token") }
                }
            }
            Card {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Relay service", color = Color.White, fontWeight = FontWeight.SemiBold)
                        Text(if (on) "Running in background" else "Stopped", color = if (on) Color(0xFF22C55E) else Color(0xFFEF4444))
                    }
                    Switch(on, { on = it; prefs(this@MainActivity).edit().putBoolean("on", it).apply()
                        val i = Intent(this@MainActivity, RelayService::class.java)
                        if (it) startForegroundService(i) else stopService(i) })
                }
            }
            Card {
                Text("Tailscale", color = Color.White, fontWeight = FontWeight.SemiBold)
                Text(if (ip != null) "● Connected  $ip" else "● Not connected", color = if (ip != null) Color(0xFF22C55E) else Color(0xFFF59E0B))
                Text("Link your PC with a token: generate one in the PC token card above and paste it into the PC app.", color = Color(0xFF9DB2FF), modifier = Modifier.padding(top = 8.dp))
            }
            OutlinedButton({ page = "logs" }, Modifier.fillMaxWidth()) { Text("Wake log (${log.size})") }
        }
    }
}
