package com.relay.wol
import android.app.*
import android.content.*
import android.net.Uri
import android.os.*
import java.io.File
import java.net.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

const val PORT = 48999
fun prefs(c: Context) = c.getSharedPreferences("wol", 0)
fun token(c: Context): String = prefs(c).getString("token", null) ?: java.util.UUID.randomUUID().toString().replace("-", "").take(24).also { prefs(c).edit().putString("token", it).apply() }
fun tailscaleIp(): String? = NetworkInterface.getNetworkInterfaces().toList().flatMap { it.inetAddresses.toList() }
    .filterIsInstance<Inet4Address>().map { it.hostAddress!! }.firstOrNull { val p = it.split("."); p[0] == "100" && p[1].toInt() in 64..127 }

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) { if (prefs(c).getBoolean("on", true)) c.startForegroundService(Intent(c, RelayService::class.java)) }
}

fun hmac(key: String, msg: String): String = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key.toByteArray(), "HmacSHA256")) }
    .doFinal(msg.toByteArray()).joinToString("") { "%02x".format(it) }

private val LOG_LOCK = Any()
fun addLog(c: Context, text: String) = synchronized(LOG_LOCK) {
    val stamp = java.text.SimpleDateFormat("dd MMM HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date())
    val old = org.json.JSONArray(prefs(c).getString("log", "[]"))
    val n = org.json.JSONArray().put("$stamp  $text")
    for (i in 0 until minOf(old.length(), 199)) n.put(old.getString(i))
    prefs(c).edit().putString("log", n.toString()).apply()
}
fun loadLog(c: Context): List<String> = runCatching {
    val a = org.json.JSONArray(prefs(c).getString("log", "[]")); (0 until a.length()).map { a.getString(it) }
}.getOrDefault(emptyList())

/** A PC that is (or will be) allowed to wake through this phone. One token = one device: the first PC that uses it is bound to it. */
data class Client(val secret: String, val name: String, val ip: String, val first: Long, val last: Long, val wakes: Int, val role: String = "pc", val token: String = "", val made: Long = 0)

private val CLIENT_LOCK = Any()
fun newSecret(): String = java.util.UUID.randomUUID().toString().replace("-", "").take(24)
fun loadClients(c: Context): List<Client> = runCatching {
    val p = prefs(c)
    val a = org.json.JSONArray(p.getString("clients", "[]"))
    val list = (0 until a.length()).map { val o = a.getJSONObject(it)
        Client(o.getString("secret"), o.optString("name"), o.optString("ip"), o.optLong("first"), o.optLong("last"), o.optInt("wakes"), o.optString("role", "pc").ifEmpty { "pc" }, o.optString("token"), o.optLong("made")) }
    // migrate tokens made by older versions (unbound)
    val old = p.getStringSet("secrets", null)
    if (old != null) { old.filter { s -> list.none { it.secret == s } }.forEach { list += Client(it, "", "", 0, 0, 0) }
        p.edit().remove("secrets").putString("clients", clientsJson(list)).apply() }
    list.toList()
}.getOrDefault(emptyList())
private fun clientsJson(l: List<Client>): String { val a = org.json.JSONArray()
    l.forEach { a.put(org.json.JSONObject().put("secret", it.secret).put("name", it.name).put("ip", it.ip).put("first", it.first).put("last", it.last).put("wakes", it.wakes).put("role", it.role).put("token", it.token).put("made", it.made)) }
    return a.toString() }
/** Atomic read-modify-write of the client list. */
fun editClients(c: Context, f: (MutableList<Client>) -> Unit) = synchronized(CLIENT_LOCK) {
    val l = loadClients(c).toMutableList(); f(l); prefs(c).edit().putString("clients", clientsJson(l)).apply() }

// ---------------- Hosts: PCs that joined with a token send their physical MAC address(es) here (WoL Host > Set up) ----------------
data class Host(val ip: String, val name: String, val macs: List<String>, val updated: Long)
private val HOST_LOCK = Any()
private val MAC_RE = Regex("([0-9a-f]{2}:){5}[0-9a-f]{2}")
private val IP_RE = Regex("(\\d{1,3}\\.){3}\\d{1,3}")
/** The Tailscale IP a host reports in its sethost data ("100.x.y.z,aa:bb:..") or "" when it sent none (older WoL Host). */
fun parseReportedIp(data: String): String = data.split(",", ";", " ").map { it.trim() }.firstOrNull { IP_RE.matches(it) } ?: ""
/** What clients get: every saved host with its Tailscale IP and MAC addresses, as one line of JSON. */
fun hostsForClients(c: Context): String { val a = org.json.JSONArray()
    loadHosts(c).forEach { a.put(org.json.JSONObject().put("ip", it.ip).put("name", it.name).put("macs", org.json.JSONArray(it.macs))) }
    return a.toString() }
private fun hostsJson(l: List<Host>): String { val a = org.json.JSONArray()
    l.forEach { a.put(org.json.JSONObject().put("ip", it.ip).put("name", it.name).put("macs", org.json.JSONArray(it.macs)).put("updated", it.updated)) }
    return a.toString() }
fun loadHosts(c: Context): List<Host> = synchronized(HOST_LOCK) { runCatching {
    val a = org.json.JSONArray(prefs(c).getString("hosts", "[]"))
    (0 until a.length()).map { val o = a.getJSONObject(it); val m = o.optJSONArray("macs")
        Host(o.optString("ip"), o.optString("name"), if (m == null) emptyList() else (0 until m.length()).map { i -> m.getString(i) }, o.optLong("updated")) }
}.getOrDefault(emptyList()) }
/** Atomic read-modify-write of the host list. */
fun editHosts(c: Context, f: (MutableList<Host>) -> Unit) = synchronized(HOST_LOCK) {
    val l = loadHosts(c).toMutableList(); f(l); prefs(c).edit().putString("hosts", hostsJson(l)).apply() }
/** "aa:bb:..,cc-dd-.." -> clean, lower-case, colon-separated MACs (invalid and all-zero entries dropped). */
fun parseMacs(data: String): List<String> = data.split(",", ";", " ").map { it.trim().lowercase().replace("-", ":") }
    .filter { MAC_RE.matches(it) && it != "00:00:00:00:00:00" }.distinct().take(8)

// ---------------- Access PINs: one per Windows account (set in WoL Host > Remote PIN, pushed here by that PC) ----------------
// Wake and discover requests must carry the PIN of ANY of these accounts while at least one is active. Only salted PBKDF2 hashes are kept; each entry
// disappears by itself when its time is up.
private const val PIN_ITER = 200000
fun pbkdf(pin: String, salt: ByteArray): String =
    javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(javax.crypto.spec.PBEKeySpec(pin.toCharArray(), salt, PIN_ITER, 256))
        .encoded.joinToString("") { "%02x".format(it) }
fun hexBytes(h: String): ByteArray = ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
data class PinEntry(val user: String, val salt: String, val hash: String, val exp: Long)      // exp = epoch seconds, 0 = permanent; user = "" for a PIN from an older version
private val PIN_LOCK = Any()
private fun pinsJson(l: List<PinEntry>): String { val a = org.json.JSONArray()
    l.forEach { a.put(org.json.JSONObject().put("user", it.user).put("salt", it.salt).put("hash", it.hash).put("exp", it.exp)) }
    return a.toString() }
/** Stores the whole list (and drops the single PIN an older version kept). */
fun savePins(c: Context, l: List<PinEntry>) = prefs(c).edit().putString("pins", pinsJson(l)).remove("pin_salt").remove("pin_hash").remove("pin_exp").apply()
fun clearPins(c: Context) = savePins(c, emptyList())
fun loadPins(c: Context): List<PinEntry> = synchronized(PIN_LOCK) {
    val p = prefs(c)
    val all = runCatching {
        val a = org.json.JSONArray(p.getString("pins", "[]"))
        (0 until a.length()).map { val o = a.getJSONObject(it); PinEntry(o.optString("user"), o.getString("salt"), o.getString("hash"), o.optLong("exp")) }
    }.getOrDefault(emptyList()).toMutableList()
    val h = p.getString("pin_hash", "") ?: ""; val sl = p.getString("pin_salt", "") ?: ""        // the one PIN an older version kept
    if (all.isEmpty() && h.isNotEmpty() && sl.isNotEmpty()) all += PinEntry("", sl, h, p.getLong("pin_exp", 0L))
    val now = System.currentTimeMillis() / 1000
    val live = all.filter { it.exp == 0L || now < it.exp }
    if (live.size != all.size) { savePins(c, live); addLog(c, "⏱ ${all.size - live.size} access PIN(s) expired and were removed") }
    live
}
/** data = "all:<user hex>:<salt hex>:<hash hex>:<expiry epoch s, 0 = never>;<next account>..." , "clear", or (older WoL Host) "set:<salt>:<hash>:<expiry>" (sent by WoL Host) -> reply line */
fun applyPin(c: Context, d: String): String {
    if (d == "clear") { if (loadPins(c).isNotEmpty()) addLog(c, "🔓 Access PINs removed by WoL Host"); clearPins(c); return "OK" }
    val list = mutableListOf<PinEntry>()
    if (d.startsWith("all:")) {
        for (e in d.removePrefix("all:").split(";").filter { it.isNotEmpty() }) {
            val f = e.split(":")
            if (f.size != 4 || !Regex("([0-9a-f]{2})*").matches(f[0]) || !Regex("[0-9a-f]{32}").matches(f[1]) || !Regex("[0-9a-f]{64}").matches(f[2])) return "ERROR bad PIN data"
            val exp = f[3].toLongOrNull() ?: return "ERROR bad PIN data"
            list += PinEntry(String(hexBytes(f[0]), Charsets.UTF_8), f[1], f[2], exp)
        }
        if (list.isEmpty()) return "ERROR bad PIN data"
    } else {
        val p = d.split(":")
        if (p.size != 4 || p[0] != "set" || !Regex("[0-9a-f]{32}").matches(p[1]) || !Regex("[0-9a-f]{64}").matches(p[2])) return "ERROR bad PIN data"
        list += PinEntry("", p[1], p[2], p[3].toLongOrNull() ?: return "ERROR bad PIN data")
    }
    val before = loadPins(c).map { it.hash to it.exp }.toSet()
    savePins(c, list)
    if (before != list.map { it.hash to it.exp }.toSet()) addLog(c, "🔒 ${list.size} access PIN(s) synced from WoL Host" + (if (list.any { it.user.isNotEmpty() }) ": " + list.joinToString(", ") { it.user } else ""))
    return "OK"
}
private val PIN_FAILS = mutableListOf<Long>()
fun pinLocked(): Boolean = synchronized(PIN_FAILS) { val now = System.currentTimeMillis(); PIN_FAILS.removeAll { now - it > 300000 }; PIN_FAILS.size >= 5 }
fun pinFailed() { synchronized(PIN_FAILS) { PIN_FAILS.add(System.currentTimeMillis()) } }

// ---------------- Devices on the phone's own network (physical MAC addresses only) ----------------
data class Dev(val ip: String, val mac: String)
fun ipToInt(s: String): Int = s.split(".").fold(0) { a, b -> (a shl 8) or b.toInt() }
fun intToIp(v: Int): String = "${(v ushr 24) and 255}.${(v ushr 16) and 255}.${(v ushr 8) and 255}.${v and 255}"
/** A real network card: not broadcast / multicast, and not "locally administered" (virtual adapters, phones' private Wi-Fi addresses). */
fun isPhysicalMac(m: String): Boolean {
    val b = m.split(":").mapNotNull { it.toIntOrNull(16) }
    if (b.size != 6 || b.all { it == 0 } || b.all { it == 255 }) return false
    if ((b[0] and 1) != 0) return false
    if ((b[0] and 2) != 0) return false
    return true
}
/** Every address of the subnet(s) the phone is on (Tailscale and link-local excluded; at most a /24 each). */
fun lanTargets(): List<String> {
    val out = mutableListOf<String>()
    NetworkInterface.getNetworkInterfaces().toList().filter { it.isUp && !it.isLoopback }.forEach { n ->
        n.interfaceAddresses.forEach { a ->
            val ad = a.address
            if (ad is Inet4Address) {
                val s = ad.hostAddress ?: return@forEach
                val p = s.split(".")
                if (p[0] == "100" && p[1].toInt() in 64..127) return@forEach
                if (s.startsWith("169.254.")) return@forEach
                val own = ipToInt(s)
                val prefix = maxOf(a.networkPrefixLength.toInt(), 24)
                val net = own and (-1 shl (32 - prefix))
                for (i in 1 until (1 shl (32 - prefix)) - 1) { val t = net + i; if (t != own) out.add(intToIp(t)) }
            }
        }
    }
    return out.distinct()
}
/** Pokes every address once so the phone learns their MAC addresses, then reads the neighbour table. */
fun discoverLan(): List<Dev> {
    val targets = lanTargets()
    if (targets.isEmpty()) return emptyList()
    runCatching { DatagramSocket().use { d -> val b = ByteArray(1)
        for (t in targets) runCatching { d.send(DatagramPacket(b, 1, InetAddress.getByName(t), 9)) } } }
    Thread.sleep(2000)
    val seen = linkedMapOf<String, Dev>()
    runCatching {
        File("/proc/net/arp").readLines().drop(1).map { it.trim().split(Regex("\\s+")) }.forEach { c ->
            if (c.size >= 4 && c[2] != "0x0") { val mac = c[3].lowercase(); if (isPhysicalMac(mac)) seen[mac] = Dev(c[0], mac) }
        }
    }
    if (seen.isEmpty()) runCatching {            // newer Android versions hide /proc/net/arp from apps: ask the neighbour table instead
        val pr = Runtime.getRuntime().exec(arrayOf("ip", "neigh"))
        pr.inputStream.bufferedReader().readLines().forEach { l ->
            val m = Regex("^(\\d+\\.\\d+\\.\\d+\\.\\d+).*lladdr\\s+([0-9a-fA-F:]{17})").find(l)
            if (m != null) { val mac = m.groupValues[2].lowercase(); if (isPhysicalMac(mac)) seen[mac] = Dev(m.groupValues[1], mac) }
        }
    }
    return seen.values.toList()
}
fun devsJson(l: List<Dev>): String { val a = org.json.JSONArray(); l.forEach { a.put(org.json.JSONObject().put("ip", it.ip).put("mac", it.mac)) }; return a.toString() }
fun saveLan(c: Context, l: List<Dev>) = prefs(c).edit().putString("lan", devsJson(l)).putLong("lan_t", System.currentTimeMillis()).apply()
fun loadLan(c: Context): List<Dev> = runCatching {
    val a = org.json.JSONArray(prefs(c).getString("lan", "[]")); (0 until a.length()).map { val o = a.getJSONObject(it); Dev(o.optString("ip"), o.optString("mac")) }
}.getOrDefault(emptyList())

class RelayService : Service() {
    @Volatile private var running = false
    private var server: ServerSocket? = null
    private var wl: PowerManager.WakeLock? = null

    override fun onBind(i: Intent?) = null
    override fun onStartCommand(i: Intent?, f: Int, id: Int): Int {
        val ch = "relay"
        getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel(ch, "Relay", NotificationManager.IMPORTANCE_LOW))
        startForeground(1, Notification.Builder(this, ch).setContentTitle("WoL Relay active").setContentText("Listening on port $PORT")
            .setSmallIcon(android.R.drawable.ic_lock_power_off).setOngoing(true).build())
        wl = (getSystemService(POWER_SERVICE) as PowerManager).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "wol:relay").apply { acquire() }
        if (!running) { running = true; Thread { loop() }.start() }
        return START_STICKY
    }
    override fun onDestroy() { running = false; server?.close(); wl?.release() }

    private fun loop() {
        while (running) try {
            server = ServerSocket().apply { reuseAddress = true; bind(InetSocketAddress(PORT)) }
            while (running) { val s = server!!.accept(); Thread { handle(s) }.start() }
        } catch (e: Exception) { Thread.sleep(3000) }
    }

    private fun handle(s: Socket) = s.use {
        val out = s.getOutputStream()
        fun reply(t: String) { out.write((t + "\n").toByteArray()); out.flush() }
        try {
            // Auth = Tailscale: only peers inside the tailnet (100.64.0.0/10) are accepted
            val src = (s.remoteSocketAddress as InetSocketAddress).address.hostAddress ?: ""
            val p = src.split(".")
            if (p.size != 4 || p[0] != "100" || p[1].toIntOrNull() !in 64..127) return reply("DENIED")
            s.soTimeout = 8000
            val j = org.json.JSONObject(s.getInputStream().bufferedReader().readLine())
            val mac = j.optString("mac"); val ip = j.optString("ip")
            // Token check: request must be signed with a secret from a PC token generated on this phone
            val act = j.optString("action"); val t = j.optString("ts"); val data = j.optString("data"); val roleReq = j.optString("role")
            val msg = if (data.isEmpty()) "$t|$mac|$ip|$act" else "$t|$mac|$ip|$act|$data"      // the access PIN / PIN data is signed too
            val fresh = Math.abs(System.currentTimeMillis() / 1000 - (t.toLongOrNull() ?: 0L)) <= 60
            val sig = j.optString("sig")
            val devName = j.optString("name").trim().take(40)
            // Each token belongs to ONE device: the first PC that uses it is bound to its Tailscale IP; any other device using it is refused.
            // If the same token is reused on a different device, the previous device is removed and the new one replaces it.
            var verdict = "INVALID"; var clRole = "pc"
            synchronized(CLIENT_LOCK) {
                val list = loadClients(this@RelayService).toMutableList()
                val i = if (fresh) list.indexOfFirst { java.security.MessageDigest.isEqual(hmac(it.secret, msg).toByteArray(), sig.toByteArray()) } else -1
                if (i >= 0) {
                    val cl = list[i]; val now = System.currentTimeMillis()
                    val wantRole = if (roleReq == "host") "host" else "pc"
                    val previousOwners = list.filter { it.secret == cl.secret && it.ip != src }
                    val sameTokenMoved = cl.ip.isNotEmpty() && cl.ip != src
                    if (sameTokenMoved && previousOwners.isNotEmpty()) {
                        list.removeAll(previousOwners)
                        addLog(this@RelayService, "↻ ${devName.ifEmpty { src }} ($src) reused an existing token; previous connection removed")
                    }
                    if (cl.ip.isNotEmpty() && cl.ip != src && !sameTokenMoved) verdict = "BOUND"
                    else if (cl.ip.isNotEmpty() && cl.role != wantRole) verdict = if (cl.role == "host") "ISHOST" else "ISCLIENT"
                    else { verdict = "OK"
                        // A device keeps ONE token per kind: when it joins with a new token, its previous token(s) of the same kind are deleted.
                        val old = if (cl.ip.isEmpty()) list.filter { it.ip == src && it.role == wantRole && it.secret != cl.secret } else emptyList()
                        if (old.isNotEmpty()) { list.removeAll(old); addLog(this@RelayService, "↻ ${devName.ifEmpty { src }} ($src) joined with a new token - previous token deleted") }
                        val k = list.indexOfFirst { it.secret == cl.secret }
                        list[k] = cl.copy(ip = src, name = devName.ifEmpty { cl.name.ifEmpty { src } }, first = if (cl.first == 0L) now else cl.first, last = now, token = "",
                            role = if (cl.ip.isEmpty()) (if (roleReq == "host") "host" else "pc") else cl.role)      // the role is fixed by the first use of a token
                        clRole = list[k].role
                        prefs(this@RelayService).edit().putString("clients", clientsJson(list)).apply()
                        if (cl.ip.isEmpty()) addLog(this@RelayService, "＋ Approved new client ${list[k].name} ($src)") }
                }
            }
            if (verdict == "ISHOST") { addLog(this@RelayService, "✖ Rejected $src: this token belongs to a host, not a client"); return reply("DENIED (this token already belongs to a host)") }
            if (verdict == "ISCLIENT") { addLog(this@RelayService, "✖ Rejected $src: this token belongs to a client, not a host"); return reply("DENIED (this token already belongs to a client)") }
            if (verdict == "BOUND") { addLog(this@RelayService, "✖ Rejected $src: token already belongs to another client"); return reply("DENIED (token already used by another client)") }
            if (verdict != "OK") { addLog(this@RelayService, "✖ Rejected request from $src (invalid token)"); return reply("DENIED (invalid token)") }
            if (act == "ping") return reply("PONG|${Build.MODEL}")
            if (act == "setpin") {                                   // only the token that WoL Host itself used may set or remove the access PIN
                if (clRole != "host") { addLog(this@RelayService, "✖ $src tried to change the access PIN (not WoL Host)"); return reply("DENIED (only WoL Host may set the access PIN)") }
                return reply(applyPin(this@RelayService, data))
            }
            if (act == "sethost") {                                  // WoL Host reports its physical MAC address(es) right after it joined with its token
                if (clRole != "host") { addLog(this@RelayService, "✖ $src tried to register a host (not WoL Host)"); return reply("DENIED (only WoL Host may register a host)") }
                val macs = parseMacs(data)
                if (macs.isEmpty()) return reply("ERROR no valid MAC address")
                val nm = devName.ifEmpty { src }; val now = System.currentTimeMillis()
                val said = parseReportedIp(data)      // the token is bound to the address the request really came from, so that one is saved (a different reported one is only logged)
                if (said.isNotEmpty() && said != src) addLog(this@RelayService, "⚠ Host $nm reported $said but connected from $src - saved $src")
                editHosts(this@RelayService) { l -> l.removeAll { it.ip == src || it.macs.any { m -> m in macs } }; l += Host(src, nm, macs, now) }
                addLog(this@RelayService, "＋ Host $nm ($src) saved with MAC ${macs.joinToString(", ")}")
                return reply("OK")
            }
            if (act == "hosts") {                                    // the saved hosts (Tailscale IP + MAC) go to every linked client without a PIN, so adding a token never asks for one; waking [...]
                val txt = hostsForClients(this@RelayService)
                return reply("HOSTS|$txt")                           // not logged: clients ask for this every 30 s
            }
            val pins = loadPins(this@RelayService)
            var pinUser = ""                                         // whose PIN opened this request (for the log)
            if (pins.isNotEmpty()) {                                 // wake and discover need the PIN of one of the accounts while any is active
                if (pinLocked()) { addLog(this@RelayService, "✖ $src locked out: too many wrong PINs"); return reply("DENIED (too many wrong PINs, try again in a few minutes)") }
                if (data.isEmpty()) return reply("NEED_PIN")
                val who = pins.firstOrNull { java.security.MessageDigest.isEqual(pbkdf(data, hexBytes(it.salt)).toByteArray(), it.hash.toByteArray()) }
                if (who == null) { pinFailed(); addLog(this@RelayService, "✖ $src sent a wrong access PIN"); return reply("BAD_PIN") }
                pinUser = who.user
            }
            val viaPin = if (pinUser.isNotEmpty()) " [PIN of $pinUser]" else ""
            if (act == "discover") {
                val devs = discoverLan(); saveLan(this@RelayService, devs)
                addLog(this@RelayService, "🔎 Found ${devs.size} physical device(s) for $src$viaPin"); return reply("MACS|" + devsJson(devs))
            }
            val m = mac.ifEmpty { arpLookup(ip) } ?: run { addLog(this@RelayService, "✖ Wake ${ip.ifEmpty { "?" }} from $src failed: MAC unknown"); return reply("NEED_MAC (IP not in ARP cache, update WoL Host)") }
            sendMagic(m, ip.ifEmpty { null })
            editClients(this@RelayService) { l -> val k = l.indexOfFirst { it.ip == src }; if (k >= 0) l[k] = l[k].copy(wakes = l[k].wakes + 1) }
            addLog(this@RelayService, "✔ Wake $m${if (ip.isNotEmpty()) " ($ip)" else ""} from $src$viaPin"); reply("OK")
        } catch (e: Exception) { runCatching { reply("ERROR ${e.message}") } }
    }

    private fun arpLookup(ip: String): String? = runCatching {
        File("/proc/net/arp").readLines().drop(1).map { it.split(Regex("\\s+")) }
            .firstOrNull { it[0] == ip && it[3] != "00:00:00:00:00:00" }?.get(3)
    }.getOrNull()

    private fun sendMagic(mac: String, ip: String?) {
        val b = mac.split(":", "-").map { it.toInt(16).toByte() }.toByteArray()
        val data = ByteArray(6) { 0xFF.toByte() } + ByteArray(96).also { for (i in 0 until 16) b.copyInto(it, i * 6) }
        val targets = mutableListOf("255.255.255.255")
        NetworkInterface.getNetworkInterfaces().toList().forEach { n -> n.interfaceAddresses.forEach { a -> a.broadcast?.hostAddress?.let { targets += it } } }
        ip?.let { targets += it }
        DatagramSocket().use { d -> d.broadcast = true
            for (t in targets.distinct()) for (p in intArrayOf(9, 7)) runCatching { d.send(DatagramPacket(data, data.size, InetAddress.getByName(t), p)) } }
    }
}
