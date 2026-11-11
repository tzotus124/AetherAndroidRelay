# WoL Remote - PC controller: wake PCs and stream them with Moonlight (Sunshine on the PC) over Tailscale. Moonlight is fetched automatically.
# pip install pywebview   (GPU-accelerated window; optional: pip install customtkinter for the --classic fallback)
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import random, base64, ctypes, hashlib, hmac, json, os, platform, re, shutil, socket, subprocess, sys, tempfile, threading, time, urllib.request, zipfile
CFG = os.path.join(os.path.expanduser("~"), ".wol_remote.json")
PORT = 48999
MAC = r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
IPV4 = r"(\d{1,3}\.){3}\d{1,3}"
NOWIN = {"creationflags": 0x08000000} if os.name == "nt" else {}   # no flashing console windows in the .exe
def _run(*a, **k): return subprocess.run(*a, **NOWIN, **k)
try:
    import customtkinter as ctk                      # only the classic fallback window needs it
    ctk.set_appearance_mode("dark"); ctk.set_default_color_theme("blue")
except ImportError: ctk = None

def load():
    d = {"phones": [], "pcs": [], "stream": {}}
    try: d.update(json.load(open(CFG)))
    except Exception: pass
    if d.get("secret") and d.get("phone") and not d["phones"]:   # migrate old single-phone config
        d["phones"] = [{"name": "Phone", "ip": d["phone"], "secret": d["secret"]}]
    pcs = []
    for p in d["pcs"]:                                            # migrate old {name, mac} entries
        if "ip" in p or "macs" in p: pcs.append(p); continue
        a = p.get("mac", "")
        pcs.append({"name": p["name"], "ip": a if re.fullmatch(IPV4, a) else "", "macs": [a] if re.fullmatch(MAC, a) else [], "learned": False})
    d["pcs"] = pcs; d.setdefault("stream", {})
    return d
def save(c):
    tmp = CFG + ".tmp"
    try:
        with open(tmp, "w") as f: json.dump(c, f)
        os.replace(tmp, CFG)                                  # on a full disk the old file survives instead of being truncated to nothing
    except OSError:
        try: os.remove(tmp)
        except OSError: pass
        raise
    try: os.chmod(CFG, 0o600)
    except Exception: pass

def exe():
    w = r"C:\Program Files\Tailscale\tailscale.exe"
    return w if os.name == "nt" and os.path.exists(w) else "tailscale"
def ts(*a):
    try:
        r = _run([exe(), *a], capture_output=True, text=True, timeout=90)
        return (r.stdout + r.stderr).strip()
    except FileNotFoundError: return "Tailscale not installed. Get it from tailscale.com/download"
    except Exception as e: return str(e)

def ts_fast():
    """Instant (no subprocess) hint that Tailscale is up: the route to Tailscale's own address 100.100.100.100 leaves through a 100.x address. No packet is sent."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            u.connect(("100.100.100.100", 53)); return u.getsockname()[0].startswith("100.")
    except Exception: return False

def ts_installed():
    """True when the Tailscale command-line program exists on this PC."""
    return (os.name == "nt" and os.path.exists(r"C:\Program Files\Tailscale\tailscale.exe")) or bool(shutil.which("tailscale"))
_TSA = {"t": 0.0, "v": {}}
def ts_account(force=False):
    """This computer's Tailscale login, read from `tailscale status --json` (cached 30 s): {"state", "login" (e-mail account), "name", "tailnet" (network name)}. {} when Tailscale does not answer."""
    if not force and time.time() - _TSA["t"] < 30: return _TSA["v"]
    out = {}
    try:
        d = json.loads(_run([exe(), "status", "--json"], capture_output=True, text=True, timeout=20).stdout)
        me = d.get("Self") or {}; u = (d.get("User") or {}).get(str(me.get("UserID"))) or {}
        out = {"state": d.get("BackendState") or "", "login": u.get("LoginName") or "", "name": u.get("DisplayName") or "", "tailnet": (d.get("CurrentTailnet") or {}).get("Name") or ""}
    except Exception: out = {}
    _TSA["t"] = time.time(); _TSA["v"] = out; return out
def ts_label(a=None):
    """What to show next to "connected": the e-mail account of the Tailscale login, or the name of the tailnet (a key from the phone's account is often 'tagged' and has no e-mail)."""
    a = ts_account() if a is None else a
    lg = a.get("login") or ""
    return lg if "@" in lg else (a.get("tailnet") or a.get("name") or "")

class PinNeeded(Exception):
    """The PC or the phone wants the access PIN (set in WoL Host > Remote PIN). str(e) is 'NEED_PIN' (none given) or 'BAD_PIN' (wrong)."""
APIN = {}                                   # host Tailscale IP -> the access PIN to send with every command to that PC's WoL Host

def request(host, secret, action, mac="", ip="", timeout=8, data=""):
    """One signed request to the phone. `data` (the access PIN for wake / discover) is part of the signature."""
    t = str(int(time.time()))
    sig = hmac.new(secret.encode(), (f"{t}|{mac}|{ip}|{action}" + (f"|{data}" if data else "")).encode(), hashlib.sha256).hexdigest()
    body = {"ts": t, "mac": mac, "ip": ip, "action": action, "sig": sig, "name": socket.gethostname()}
    if data: body["data"] = data
    with socket.create_connection((host, PORT), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((json.dumps(body) + "\n").encode())
        return s.makefile().readline().strip()

def parse_token(tok):                      # token = "<tailscale key>~<secret>[~ignored]"
    p = tok.strip().split("~")
    if len(p) not in (2, 3) or not p[0].startswith("tskey-") or len(p[1]) < 16: return None
    return p[0], p[1], (p[2] if len(p) == 3 else "")

def peers():
    """Android devices on the tailnet."""
    try: d = json.loads(_run([exe(), "status", "--json"], capture_output=True, text=True, timeout=30).stdout)
    except Exception: return []
    out = []
    for p in (d.get("Peer") or {}).values():
        if str(p.get("OS", "")).lower() == "android":
            ip = next((i for i in p.get("TailscaleIPs", []) if "." in i), None)
            if ip: out.append({"name": p.get("HostName", "phone"), "ip": ip})
    return out

def probe(ip, secret):
    """-> ('ready', model) token accepted | ('needs', '') relay app present but token missing/wrong | ('offline', '')"""
    try: r = request(ip, secret, "ping", timeout=4)
    except Exception: return "offline", ""
    if r.startswith("PONG"): return "ready", r.split("|", 1)[1] if "|" in r else ""
    return ("needs", "") if r.startswith("DENIED") else ("offline", "")

def probe_raw(ip, secret):
    """The phone's raw answer to a ping ('' when it does not answer)."""
    try: return request(ip, secret, "ping", timeout=4)
    except Exception: return ""

def probe_all(devs, secrets):
    with ThreadPoolExecutor(8) as ex:
        return list(ex.map(lambda d: probe(d["ip"], secrets.get(d["ip"], "x" * 24)), devs))

HPORT = 48998
def norm(m): return re.sub(r"[^0-9a-f]", "", m.lower())

def all_peers():
    try: d = json.loads(_run([exe(), "status", "--json"], capture_output=True, text=True, timeout=30).stdout)
    except Exception: return []
    out = []
    for p in (d.get("Peer") or {}).values():
        ip = next((i for i in p.get("TailscaleIPs", []) if "." in i), None)
        if ip and p.get("Online"): out.append({"name": p.get("HostName", "pc"), "ip": ip, "os": str(p.get("OS", ""))})
    return out

def host_info(ip, timeout=6):
    """Ask the WoL Host agent on a tailnet device who it is (name, MACs, LAN IPs)."""
    try:
        with socket.create_connection((ip, HPORT), timeout=timeout) as s:
            s.settimeout(max(timeout, 8)); s.sendall(b"info\n"); d = json.loads(s.makefile().readline()); d["ip"] = ip; d["_t"] = time.time() * 1000; return d
    except Exception: return None

def host_cmd(ip, line, timeout=20):
    """Send one command line to the WoL Host agent, return its one-line reply. The access PIN (when known) rides in front: @PIN@command."""
    pin = APIN.get(ip)
    with socket.create_connection((ip, HPORT), timeout=6) as s:
        s.settimeout(timeout); s.sendall(((f"@{pin}@" if pin else "") + line + "\n").encode()); r = s.makefile().readline().strip()
    if r in ("ERR NEED_PIN", "ERR BAD_PIN"): raise PinNeeded(r[4:])
    return r

def host_rpc(ip, obj, timeout=20):
    """Send one JSON command to the WoL Host agent (sign in / sign out / verify). -> {"ok": bool, "msg": str}"""
    pin = APIN.get(ip)
    with socket.create_connection((ip, HPORT), timeout=6) as s:
        s.settimeout(timeout); s.sendall((json.dumps({**obj, **({"apin": pin} if pin else {})}) + "\n").encode()); r = s.makefile().readline().strip()
    try: res = json.loads(r)
    except Exception: return {"ok": False, "msg": r or "No reply from the host - is WoL Host updated (This PC > UPDATE)?"}
    if isinstance(res, dict) and res.get("needpin") in ("NEED_PIN", "BAD_PIN"): raise PinNeeded(res["needpin"])
    return res

# Saved passwords and access keys are encrypted with Windows DPAPI: only your own Windows account on this PC can decrypt them.
class _BLOB(ctypes.Structure): _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_char))]
def _dpapi(data, enc):
    if os.name != "nt": raise RuntimeError("saving credentials is only supported on Windows")
    buf = ctypes.create_string_buffer(data, len(data)); inb = _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))); out = _BLOB()
    f = ctypes.windll.crypt32.CryptProtectData if enc else ctypes.windll.crypt32.CryptUnprotectData
    if not f(ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(out)): raise RuntimeError("Windows could not " + ("encrypt" if enc else "decrypt") + " the value")
    try: return ctypes.string_at(out.pbData, out.cbData)
    finally: ctypes.windll.kernel32.LocalFree(out.pbData)
def protect(t): return base64.b64encode(_dpapi(t.encode("utf-8"), True)).decode()
def unprotect(t): return _dpapi(base64.b64decode(t), False).decode("utf-8")

# ---------------- Moonlight: the stream client (the PC runs Sunshine). Downloaded automatically, nothing to install by hand ----------------
# Moonlight Embedded (the Linux/ARM build) has no Windows version, so on Windows the app fetches the official portable Moonlight PC build,
# which speaks the same protocol and has the same command-line pairing/streaming.
APP_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
_ML_OLD = os.path.join(os.path.expanduser("~"), ".wol_remote", "moonlight")     # where older versions put it (kept as a place to look)
_DD = os.environ.get("WOL_DATA_DRIVE", "D:").rstrip("\\")                         # set WOL_DATA_DRIVE to another drive letter, or empty to keep C:
ML_HOME = os.path.join(_DD + "\\", "WoLRemote", "moonlight") if os.name == "nt" and _DD and _DD.upper() != os.environ.get("SystemDrive", "C:").upper() and os.path.isdir(_DD + "\\") else _ML_OLD
ML_API = "https://api.github.com/repos/moonlight-stream/moonlight-qt/releases/latest"
PRESETS = {"Smooth · 720p · 60 fps · 10 Mbps": (1280, 720, 60, 10000), "Balanced · 1080p · 60 fps · 20 Mbps": (1920, 1080, 60, 20000),
           "Sharp · 1080p · 60 fps · 35 Mbps": (1920, 1080, 60, 35000), "Low bandwidth · 720p · 30 fps · 4 Mbps": (1280, 720, 30, 4000)}
DEFAULT_PRESET = "Balanced · 1080p · 60 fps · 20 Mbps"
CODECS = {"auto": None, "h264": "H.264", "h265": "HEVC", "av1": "AV1"}
CUSTOM = "Custom…"                                       # quality choice that uses the resolution / fps / Mbps typed on the Moonlight settings page
_ANY = "Default"                                          # "Default" = pass nothing, Moonlight decides. Only what you change is ever sent to it.
# (section, key, label, hint, command-line flag, choices {shown: value} - or None for a Default / On / Off switch)
ML_SPEC = [
    ("Video", "display", "Window mode", "How the stream window opens.", "--display-mode", {_ANY: None, "Windowed": "windowed", "Fullscreen": "fullscreen", "Borderless window": "borderless"}),
    ("Video", "decoder", "Video decoder", "Hardware is faster. Software is a fallback if the picture is broken.", "--video-decoder", {_ANY: None, "Hardware": "hardware", "Software": "software"}),
    ("Video", "vsync", "V-Sync", "Smoother picture, a little more delay.", "--vsync", None),
    ("Video", "pacing", "Frame pacing", "Evens out frame timing, adds a little delay.", "--frame-pacing", None),
    ("Video", "hdr", "HDR", "Needs an HDR display and the HEVC or AV1 codec.", "--hdr", None),
    ("Video", "yuv444", "Full colour (YUV 4:4:4)", "Sharper text. Needs a PC graphics card and codec that support it.", "--yuv444", None),
    ("Video", "overlay", "Performance overlay", "Shows fps, bitrate and delay on top of the stream.", "--performance-overlay", None),
    ("Audio", "audio", "Audio channels", "", "--audio-config", {_ANY: None, "Stereo": "stereo", "5.1 surround": "5.1-surround", "7.1 surround": "7.1-surround"}),
    ("Audio", "audiohost", "Also play audio on the PC", "", "--audio-on-host", None),
    ("Audio", "mute", "Mute when the window loses focus", "", "--mute-on-focus-loss", None),
    ("Input", "syskeys", "Capture system keys", "Send Alt+Tab, the Windows key and so on to the PC.", "--capture-system-keys", {_ANY: None, "Never": "never", "Fullscreen only": "fullscreen", "Always": "always"}),
    ("Input", "multipad", "Multiple controllers", "", "--multi-controller", None),
    ("Input", "bgpad", "Controllers work in the background", "", "--background-gamepad", None),
    ("Input", "absmouse", "Absolute mouse mode", "Better for desktop use, worse for most games.", "--absolute-mouse", None),
    ("Input", "swapmouse", "Swap mouse buttons", "", "--mouse-buttons-swap", None),
    ("Input", "revscroll", "Reverse scroll direction", "", "--reverse-scroll-direction", None),
    ("Input", "touchpad", "Touchscreen acts as a trackpad", "", "--touchscreen-trackpad", None),
    ("Session", "gameopt", "Optimise game settings", "Lets the PC change game resolution and settings to match the stream.", "--game-optimization", None),
    ("Session", "quitafter", "Close the app on the PC when the stream ends", "", "--quit-after", None),
    ("Session", "keepawake", "Keep this computer awake while streaming", "", "--keep-awake", None)]
ML_PIN = "v6.1.0"                                          # known-good release, used when GitHub's API/redirect can't be reached
ML_REPO = "https://github.com/moonlight-stream/moonlight-qt"
def _ml_dirs():
    out = [os.path.join(APP_DIR, "moonlight"), ML_HOME, _ML_OLD]
    if os.name == "nt":                                    # a normal install (MSI / winget) counts too
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs")):
            try: out += [os.path.join(base, d) for d in os.listdir(base) if d.lower().startswith("moonlight")] if base else []
            except Exception: pass
    return out
def find_moonlight():
    """A Moonlight binary: a copy bundled in ./moonlight next to the app, else the auto-downloaded one, else an installed one, else one on PATH."""
    names = ["moonlight.exe"] if os.name == "nt" else ["moonlight"]
    for base in _ml_dirs():
        for root, _, files in os.walk(base):
            hit = next((f for f in files if f.lower() in names), None)
            if hit: return os.path.join(root, hit)
    return next((w for w in (shutil.which(n) for n in names) if w), "")
def _ml_download(url, dest, say, label):
    """urllib first; if that fails (proxy / TLS / antivirus quirks) Windows' own curl.exe, which uses the system certificate store."""
    err = None
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "WoL-Remote"}), timeout=60) as r, open(dest, "wb") as f:
            total, got = int(r.headers.get("Content-Length") or 0), 0
            while True:
                b = r.read(1 << 16)
                if not b: break
                f.write(b); got += len(b)
                if total: say(f"Downloading Moonlight {label}… {got * 100 // total}%")
        return
    except Exception as e: err = e
    curl = shutil.which("curl.exe") or shutil.which("curl")
    if curl:
        say(f"Downloading Moonlight {label} (alternate method)…")
        r = _run([curl, "-L", "--fail", "--silent", "--show-error", "--retry", "2", "-o", dest, url], capture_output=True, text=True, timeout=900)
        if r.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) > 1_000_000: return
        err = RuntimeError((r.stderr or "").strip()[:160] or str(err))
    raise err
def ml_install(say):
    """Get Moonlight with no user action: official portable build from GitHub (API, then the releases page, then a pinned version), then winget."""
    if os.name != "nt": raise RuntimeError("automatic download is Windows-only - install Moonlight with your package manager so `moonlight` is on PATH")
    arch = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64", "x86": "x86", "i386": "x86", "i686": "x86"}.get(platform.machine().lower(), "x64")
    hdr, errs, cands = {"User-Agent": "WoL-Remote"}, [], []
    def url_for(tag): return f"{ML_REPO}/releases/download/{tag}/MoonlightPortable-{arch}-{tag.lstrip('v')}.zip"
    try:
        rel = json.load(urllib.request.urlopen(urllib.request.Request(ML_API, headers=hdr), timeout=20))
        a = next((x for x in rel.get("assets", []) if re.fullmatch(rf"MoonlightPortable-{arch}-.*\.zip", x["name"], re.I)), None)
        if a: dg = a.get("digest") or ""; cands.append((rel.get("tag_name", ""), a["browser_download_url"], dg[7:] if dg.startswith("sha256:") else ""))
    except Exception as e: errs.append(f"GitHub API: {str(e)[:90]}")
    try:
        tag = urllib.request.urlopen(urllib.request.Request(ML_REPO + "/releases/latest", headers=hdr), timeout=20).geturl().rstrip("/").rsplit("/", 1)[-1]
        if re.fullmatch(r"v?\d[\w.\-]*", tag) and tag not in [c[0] for c in cands]: cands.append((tag, url_for(tag), ""))
    except Exception as e: errs.append(f"releases page: {str(e)[:90]}")
    if ML_PIN not in [c[0] for c in cands]: cands.append((ML_PIN, url_for(ML_PIN), ""))
    os.makedirs(os.path.dirname(ML_HOME), exist_ok=True); zp = os.path.join(os.path.dirname(ML_HOME), "MoonlightPortable.zip")       # download next to the install, not into C:\\ temp
    for tag, url, sha in cands:
        try:
            _ml_download(url, zp, say, tag)
            if sha and hashlib.sha256(open(zp, "rb").read()).hexdigest() != sha.lower(): raise RuntimeError("checksum mismatch")
            say("Unpacking Moonlight…"); tmp = ML_HOME + ".new"; shutil.rmtree(tmp, ignore_errors=True)
            with zipfile.ZipFile(zp) as z: z.extractall(tmp)
            shutil.rmtree(ML_HOME, ignore_errors=True); os.makedirs(os.path.dirname(ML_HOME), exist_ok=True); os.replace(tmp, ML_HOME)
            try: os.remove(zp)
            except Exception: pass
            return
        except Exception as e:
            errs.append(f"{tag}: {str(e)[:90]}")
            try: os.remove(zp)
            except Exception: pass
    if shutil.which("winget"):                              # last resort: the official installer through winget
        say("Installing Moonlight with winget…")
        try: _run(["winget", "install", "-e", "--id", "MoonlightGameStreamingProject.Moonlight", "--silent", "--accept-source-agreements", "--accept-package-agreements"], capture_output=True, timeout=900)
        except Exception as e: errs.append(f"winget: {str(e)[:90]}")
        if find_moonlight(): return
        errs.append("winget did not install it")
    raise RuntimeError(" | ".join(errs) or "no download source reachable")
def ml_args(ml, ip, st):
    if st.get("preset") == CUSTOM:
        c = st.get("custom") or {}
        try: w, h = (int(x) for x in str(c.get("res", "1920x1080")).lower().replace("×", "x").split("x")); fps = int(c.get("fps") or 60); kbps = int(float(c.get("mbps") or 20) * 1000)
        except Exception: w, h, fps, kbps = PRESETS[DEFAULT_PRESET]                       # unreadable custom values: fall back instead of failing to start
    else: w, h, fps, kbps = PRESETS.get(st.get("preset"), PRESETS[DEFAULT_PRESET])
    codec = CODECS.get(st.get("codec", "auto")); o = st.get("ml") or {}; extra = []
    for _sec, key, _lab, _hint, flag, opts in ML_SPEC:
        v = o.get(key, _ANY)
        if opts is None:
            if v == "On": extra.append(flag)
            elif v == "Off": extra.append("--no-" + flag[2:])
        elif opts.get(v): extra += [flag, opts[v]]
    return ([ml, "--resolution", f"{w}x{h}", "--fps", str(fps), "--bitrate", str(kbps)] + (["--video-codec", codec] if codec else []) + extra
            + ["stream", ip, st.get("app") or "Desktop"])
def ml_unpair(ml, ip):
    """`moonlight unpair <host>` forgets this PC's pairing on the client side. -> (ok, message)"""
    try: r = _run([ml, "unpair", ip], capture_output=True, text=True, timeout=30); out = (r.stdout + r.stderr).strip()
    except Exception as e: return False, str(e)[:150]
    return (r.returncode == 0 or bool(re.search(r"not paired|unpaired|Displays help|Usage:|Arguments:", out, re.I))), out[-150:]       # this Moonlight has no unpair command (it prints its help): forget the pairing here; Sunshine decides at the next Pair
def pin_users(h):
    """Accounts that sign in remotely with a PIN (lower case): Microsoft accounts (Windows Hello PIN) + accounts with a remote PIN set in WoL Host > TimeGuard."""
    h = h or {}; return [x.lower() for x in list(h.get("msa") or []) + list(h.get("hostpin") or [])]
def ml_is_paired(ml, ip):
    """Ask Moonlight itself (`moonlight list <host>`) whether it is really paired with this PC. -> True / False / None (could not tell)"""
    try: r = _run([ml, "list", ip], capture_output=True, text=True, timeout=20); out = (r.stdout + r.stderr)
    except Exception: return None
    if re.search(r"not been paired|not paired|needs? to be paired|pair before", out, re.I): return False
    return True if r.returncode == 0 else None
def ml_forget_hosts(ml):
    """Wipe Moonlight's own memory of paired PCs so the next pairing really starts again. Needed when the PC's Sunshine lost its pairing list: Moonlight would still
    say "already paired", never pair, and every connection would fail the certificate check. The portable build keeps this in a "Moonlight Game Streaming Project" folder
    next to its exe; an installed copy keeps its hosts in the registry. Stream settings are not lost: this app passes them on the command line every time. -> number of things removed"""
    done = 0
    if os.name == "nt":
        r = _run(["reg", "delete", r"HKCU\Software\Moonlight Game Streaming Project\Moonlight\hosts", "/f"], capture_output=True, text=True); done += r.returncode == 0
    exe_dir = os.path.dirname(ml)
    for base in {exe_dir, os.path.dirname(exe_dir)}:
        try:
            for d in os.listdir(base):
                p = os.path.join(base, d)
                if os.path.isdir(p) and d.lower().startswith("moonlight game streaming"): shutil.rmtree(p, ignore_errors=True); done += 1
        except OSError: pass
    return done
def stream_signin(pc, h, user, pin, say, pw="", other_user="", other_pin=""):
    """Streaming needs the user's remote PIN (set in WoL Host > Remote PIN) EVERY time - nothing is saved here. The PC checks it, signs the user in once when it
    is at the sign-in screen, and Sunshine has to run for them. say(msg, level) reports progress. -> (host info, None) or (None, error text)
    Accounts that keep their Windows / Microsoft password ("pinmode" on the host) need the PIN AND that password to be signed IN (pw); an already signed-in user needs the PIN only."""
    ip = h["ip"]; key = user.lower(); dual = key in [x.lower() for x in (h.get("pinmode") or [])]
    if key not in [x.lower() for x in (h.get("hostpin") or [])]:
        return None, f"{user} has no remote PIN yet. On that PC open WoL Host > Remote PIN and set one."
    ss = h.get("sessions")
    if ss is None: return None, "This PC runs an old WoL Host. On it open WoL Host > This PC > UPDATE."
    others = [x["user"] for x in ss if x["user"].lower() != key]
    if others and not (other_user and other_user.lower() == others[0].lower() and len(other_pin) >= 4):
        return None, f"{others[0]} is signed in on this PC. Press Stream again and enter {others[0]}'s PIN to sign them out first."
    if others and others[0].lower() not in [x.lower() for x in (h.get("hostpin") or [])]:
        return None, f"{others[0]} is signed in and has no remote PIN, so they cannot be signed out from here. Set a PIN for them in WoL Host > Remote PIN."
    say(f"Checking {user}'s PIN…", None)
    try: r = host_rpc(ip, {"cmd": "verify", "user": user, "pin": pin}, 30)
    except Exception as e: return None, f"The PC did not answer the PIN check: {e}"
    if not r.get("ok"): return None, str(r.get("msg") or "That PIN is wrong.")
    if others:                                                                 # the new user's PIN is right: now (and only now) sign the user who is on the PC out
        if dual and not pw: return None, f"Signing {user} in needs the PIN and {user}'s password. Enter both."
        say(f"Signing {others[0]} out…", None)
        try: r = host_rpc(ip, {"cmd": "logoff", "user": others[0], "pin": other_pin}, 70)
        except Exception as e: return None, f"The PC did not answer the sign-out: {e}"
        if not r.get("ok"): return None, str(r.get("msg") or f"Could not sign {others[0]} out.")
        for i in range(30):
            time.sleep(2); hh = host_info(ip)
            if hh and "sessions" in hh and not hh["sessions"]: h, ss = hh, []; break
        else: return None, f"{others[0]} is still signing out. Try again in a moment."
        say(f"✔ {others[0]} signed out.", "ok")
    up = lambda x: bool(x and (x.get("sunshine") or {}).get("running"))
    if not any(x["user"].lower() == key for x in ss):                          # the PC is at its sign-in screen: sign the user in - ONE attempt
        if dual and not pw: return None, f"Signing {user} in needs the PIN and {user}'s password. Enter both."
        say(f"The PC is at the sign-in screen - signing {user} in…", None)
        try: base = ((host_info(ip) or h).get("login_fail") or {}).get("ts", 0)
        except Exception: base = 0
        try: r = host_rpc(ip, {"cmd": "login", "user": user, "pin": pin, **({"pw": pw} if dual else {})}, 100)
        except Exception as e: return None, f"The PC did not answer the sign-in: {e}"
        if not r.get("ok"): return None, str(r.get("msg") or "Sign-in was refused.")
        for i in range(60):                                                    # the PC itself gives up after ~80 s: wait 2 min at most, never type again
            if i % 3 == 0: say(f"Waiting for {user} to sign in… ({i * 2}s)", None)
            time.sleep(2); hh = host_info(ip)
            if hh and any(x["user"].lower() == key for x in hh.get("sessions", [])): h = hh; break
            if hh and ((hh.get("login_fail") or {}).get("ts", 0) > base):
                if hh["login_fail"].get("why") == "no_screen": return None, "The PC's sign-in screen was not ready, so nothing was typed. Try again in a moment."
                return None, f"Windows did not accept {user}'s {'password' if dual else 'PIN'}."
        else: return None, f"{user} did not sign in. Check the PC and try again."
        say(f"✔ {user} is signed in. Waiting for Sunshine…", "ok")
    elif not up(h):
        say("Sunshine is not running for the signed-in user - starting it…", None)
        try: host_cmd(ip, "sunstart", 60)
        except Exception: pass                                                 # an older WoL Host does not know this command: it starts Sunshine by itself soon
    if up(h): return h, None
    for i in range(36):                                                        # Sunshine starts inside the user's session: wait up to ~3 min
        hh = host_info(ip)
        if up(hh): return hh, None
        if i in (1, 5, 11, 18, 26):                                            # it does not always start by itself right after a sign-in: ask the host to start it (again), like the "starting it…" path above
            say("Sunshine is not running yet - starting it…", None)
            try: host_cmd(ip, "sunstart", 60)
            except Exception: pass
        say(f"Waiting for Sunshine to start… ({i * 5}s)", None); time.sleep(5)
    return None, "Sunshine did not start in time. Open WoL Host on the PC > This PC > Start Sunshine."

def _ml_pair_once(ml, ip, name, pin):
    """One `moonlight pair` run. With `pin` we choose the PIN ourselves (Moonlight only shows it in its own window, where nothing can read it) and keep
    sending it to the host agent - which types it into Sunshine - until Sunshine takes it. Without `pin` the PIN is read from Moonlight's console output.
    -> (ok, message, option_not_supported)"""
    p = subprocess.Popen([ml, "pair"] + (["--pin", pin] if pin else []) + [ip], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, **NOWIN)
    dog = threading.Timer(90, p.kill); dog.start()
    out, st = [], {"done": False, "started": False, "err": None}
    def send(code):
        for _ in range(60):                                    # Sunshine only accepts the PIN once Moonlight's request has reached it: keep trying
            if st["done"] or p.poll() is not None: return
            try: r = host_cmd(ip, f"pair|{code}|{name}")
            except Exception as e: r = f"ERR host unreachable ({e})"
            if r == "OK": return
            if re.search(r"unreachable|not set up|bad PIN", r): st["err"] = r.removeprefix("ERR "); p.kill(); return
            time.sleep(1)
        st["err"] = "Sunshine did not accept the PIN"; p.kill()
    def start(code):
        if not st["started"]: st["started"] = True; threading.Thread(target=send, args=(code,), daemon=True).start()
    if pin: start(pin)
    try:
        for line in p.stdout:
            line = line.strip(); out.append(line); m = re.search(r"PIN[^0-9]*(\d{4})", line)
            if m and not pin: start(m.group(1))
        p.wait()
    finally: st["done"] = True; dog.cancel()
    text = " ".join(out)
    if re.search(r"already paired", text, re.I) or p.returncode == 0: return True, "paired", False
    if st["err"]: return False, st["err"], False
    if pin and p.returncode not in (0, None) and re.search(r"unknown option|unrecognized|unexpected|Usage:|Options:", text, re.I): return False, text[:200], True
    return False, (" | ".join(out[-3:]) or "Moonlight did not pair (no PIN was shown or accepted)")[:200], False
def ml_pair(ml, ip, name):
    """Pair Moonlight with the Sunshine on `ip`, entering the PIN automatically. -> (ok, message)"""
    pin = f"{random.SystemRandom().randrange(10000):04d}"
    ok, msg, unsupported = _ml_pair_once(ml, ip, name, pin)
    if unsupported: ok, msg, _ = _ml_pair_once(ml, ip, name, None)         # an older Moonlight without --pin: read the PIN it prints instead
    return ok, msg

def mac_set(h): return {norm(m) for m in (h.get("macs", []) + h.get("wol_macs", []))}
def match_host(pc, hosts):
    """Find the scanned host that owns one of the PC's MAC addresses."""
    want = {norm(m) for m in pc.get("macs", [])}
    h = next((h for h in hosts if want and want & mac_set(h)), None)
    return h or next((h for h in hosts if pc.get("name") and h.get("name", "").lower() == pc["name"].lower()), None)   # same computer name as a fallback
def resolve_host(pc):
    """Find a saved PC on the tailnet by MAC (its Tailscale IP is learned automatically); fall back to the last known IP."""
    h = match_host(pc, scan_hosts([pc]))
    if h: return h
    if pc.get("ip"):
        h = host_info(pc["ip"])
        if h and (not pc.get("macs") or match_host(pc, [h])): return h
    return None

_NOHOST = {}                                    # tailnet IP -> when it last did NOT answer as a WoL Host (not asked again for 8 s)
def detect_hosts(skip_ips):
    """Hosts that joined the phone's tailnet with a token, found WITHOUT the relay phone: every other online tailnet computer (phones and saved PCs left out) is asked once
    on the WoL Host port; only a real WoL Host agent answers. -> [host info dicts]"""
    now = time.time()
    ips = [p["ip"] for p in all_peers() if p["ip"] not in skip_ips and p.get("os", "").lower() not in ("android", "ios") and now - _NOHOST.get(p["ip"], 0) > 8]
    if not ips: return []
    with ThreadPoolExecutor(min(8, len(ips))) as ex: res = list(ex.map(lambda i: host_info(i, 2), ips))
    out = []
    for ip, h in zip(ips, res):
        if h and h.get("name"): out.append(h)
        else: _NOHOST[ip] = now
    return out
ONLINE_IPS = set()
def scan_hosts(pcs=()):
    """NO network scan: only the saved PCs are contacted, at the Tailscale IP their WoL Host sent to the relay phone (with its physical MACs).
    ONLINE_IPS comes from the local Tailscale status (nothing is sent over the network for it)."""
    global ONLINE_IPS
    ps = all_peers(); ONLINE_IPS = {p["ip"] for p in ps}
    known = {pc.get("ip") for pc in pcs if pc.get("ip")}
    ips = [p["ip"] for p in ps if p["ip"] in known]
    if not ips: return []
    with ThreadPoolExecutor(min(12, len(ips))) as ex: return [r for r in ex.map(host_info, ips) if r]

AUTO_MS = 10000          # the full refresh (every device on the tailnet) runs this often
WARN = "#f59e0b"        # colour value ml_install() passes for a warning (the web page maps it to its own warn colour)

HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>WoL Remote</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>:root{color-scheme:dark;--bg:#070a14;--side:#090d1a;--surf:#0e1424;--raised:#141b30;--raised2:#1a2240;--line:rgba(255,255,255,.075);--line2:rgba(255,255,255,.14);
--tx:#e9edfb;--mut:#8a93b8;--dim:#566086;--acc:#6c8cff;--acc2:#9b7bff;--ok:#34d399;--warn:#fbbf24;--bad:#f87171;--r:16px;
--f:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,Roboto,sans-serif;--m:"Cascadia Mono",Consolas,ui-monospace,monospace;--ease:cubic-bezier(.2,.7,.2,1)}
*{box-sizing:border-box;margin:0}
html,body{height:100%;background:var(--bg);color:var(--tx);font:400 13.5px/1.45 var(--f);-webkit-font-smoothing:antialiased;overflow:hidden;user-select:none;cursor:default}
body::before{content:"";position:fixed;inset:0;pointer-events:none;background:radial-gradient(900px 500px at 85% -10%,rgba(108,140,255,.10),transparent 60%),radial-gradient(700px 500px at -5% 105%,rgba(155,123,255,.07),transparent 60%)}
input,textarea,pre,.tsel{user-select:text}
::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:8px;border:3px solid transparent;background-clip:content-box}::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.2);background-clip:content-box;border:3px solid transparent}
.app{position:relative;display:grid;grid-template-columns:252px 1fr;height:100vh}
.side{background:linear-gradient(180deg,var(--side),#070b17);border-right:1px solid var(--line);display:flex;flex-direction:column;padding:26px 14px 16px}
.brand{display:flex;align-items:center;gap:12px;padding:0 8px 26px}
.mark{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;background:linear-gradient(135deg,var(--acc),var(--acc2));box-shadow:0 8px 24px -6px rgba(108,140,255,.55),inset 0 1px 0 rgba(255,255,255,.3);color:#fff}
.brand b{display:block;font-size:16.5px;letter-spacing:-.01em}.brand small{color:var(--mut);font-size:11.5px}
.nav{display:flex;flex-direction:column;gap:3px}
.nav button{all:unset;box-sizing:border-box;position:relative;display:flex;align-items:center;gap:12px;padding:11px 14px;border-radius:12px;color:var(--mut);font-weight:600;font-size:13.5px;cursor:pointer;transition:background .15s,color .15s}
.nav button:hover{background:rgba(255,255,255,.04);color:var(--tx)}
.nav button.on{background:linear-gradient(90deg,rgba(108,140,255,.16),rgba(108,140,255,.04));color:#fff}
.nav button.on::before{content:"";position:absolute;left:-14px;top:9px;bottom:9px;width:3px;border-radius:0 3px 3px 0;background:linear-gradient(var(--acc),var(--acc2))}
.nav button.on svg{color:var(--acc)}
.nav button:focus-visible,.btn:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
.sfoot{margin-top:auto;display:flex;flex-direction:column;gap:8px}
.chip{display:flex;align-items:center;gap:9px;padding:9px 13px;border-radius:12px;background:var(--surf);border:1px solid var(--line);font-weight:600;font-size:12.5px;color:var(--mut);cursor:default}
.chip.click{cursor:pointer}.chip.click:hover{border-color:var(--line2)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--c,var(--dim));flex:none;position:relative}
.dot.live::after{content:"";position:absolute;inset:0;border-radius:50%;background:var(--c);animation:ping 2s var(--ease) infinite}
@keyframes ping{0%{transform:scale(1);opacity:.7}100%{transform:scale(2.8);opacity:0}}
.c-ok{--c:var(--ok)}.c-warn{--c:var(--warn)}.c-bad{--c:var(--bad)}.c-acc{--c:var(--acc)}.c-mut{--c:var(--dim)}
main{overflow:auto;padding:30px 36px 96px;position:relative}
.page{display:none;max-width:1000px;margin:0 auto}
.page.on{display:block;animation:in .22s var(--ease)}
@keyframes in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.head{display:flex;align-items:flex-start;gap:16px;margin-bottom:22px}
.head h1{font-size:26px;font-weight:700;letter-spacing:-.02em;line-height:1.15}
.head p{color:var(--mut);margin-top:5px;max-width:620px}
.head .sp{flex:1}
.card{background:linear-gradient(180deg,rgba(255,255,255,.028),rgba(255,255,255,.01)),var(--surf);border:1px solid var(--line);border-radius:var(--r);padding:18px;margin-bottom:16px}
.card.flush{padding:8px}
.card h3{font-size:15px;font-weight:700;margin-bottom:4px}
.card .sub{color:var(--mut);font-size:12.5px;margin-bottom:14px}
.list{display:flex;flex-direction:column;gap:8px}
.row{display:flex;align-items:center;gap:14px;padding:13px 15px;background:var(--raised);border:1px solid var(--line);border-radius:14px;transition:border-color .15s,transform .15s var(--ease)}
.row:hover{border-color:var(--line2)}
.row.hl-ok{box-shadow:inset 0 0 0 1.5px var(--ok)}.row.hl-acc{box-shadow:inset 0 0 0 1.5px var(--acc)}
.row .grow{flex:1;min-width:0}
.row .t{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-weight:700;font-size:14.5px}
.row .m{font-family:var(--m);font-size:12px;color:var(--mut);margin-top:3px;overflow:hidden;text-overflow:ellipsis}
.row .m.acc{color:var(--acc)}
.row .why{font-size:11.5px;color:var(--warn);margin-top:4px}
.row .acts{display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end}
.av{width:44px;height:44px;border-radius:13px;flex:none;display:grid;place-items:center;background:linear-gradient(145deg,rgba(108,140,255,.18),rgba(155,123,255,.08));border:1px solid var(--line);color:var(--acc)}
.pill{display:inline-flex;align-items:center;gap:5px;font:700 10px/1 var(--f);letter-spacing:.07em;text-transform:uppercase;padding:5px 9px;border-radius:999px;color:var(--c,var(--mut));background:color-mix(in srgb,var(--c,var(--mut)) 14%,transparent);border:1px solid color-mix(in srgb,var(--c,var(--mut)) 28%,transparent)}
.btn{all:unset;box-sizing:border-box;display:inline-flex;align-items:center;justify-content:center;gap:8px;height:38px;padding:0 16px;border-radius:11px;font-weight:700;font-size:13px;color:#fff;cursor:pointer;white-space:nowrap;border:1px solid transparent;transition:transform .12s var(--ease),filter .15s,background .15s,border-color .15s,box-shadow .15s}
.btn:active:not([disabled]){transform:scale(.97)}
.btn[disabled]{opacity:.45;cursor:not-allowed}
.btn.primary{background:linear-gradient(135deg,var(--acc),var(--acc2));box-shadow:0 6px 18px -8px rgba(108,140,255,.8),inset 0 1px 0 rgba(255,255,255,.22)}
.btn.primary:hover:not([disabled]){filter:brightness(1.1)}
.btn.ok{background:linear-gradient(135deg,#22c58b,#16a370);box-shadow:0 6px 18px -8px rgba(34,197,139,.8),inset 0 1px 0 rgba(255,255,255,.2)}
.btn.ok:hover:not([disabled]){filter:brightness(1.1)}
.btn.warn{background:linear-gradient(135deg,#f5a524,#d97706)}
.btn.ghost{background:rgba(255,255,255,.03);border-color:var(--line2)}.btn.ghost:hover:not([disabled]){background:rgba(255,255,255,.07)}
.btn.outline{color:var(--acc);border-color:rgba(108,140,255,.5);background:rgba(108,140,255,.06)}.btn.outline:hover:not([disabled]){background:rgba(108,140,255,.14)}
.btn.danger{color:var(--bad);border-color:rgba(248,113,113,.4);background:rgba(248,113,113,.05)}.btn.danger:hover:not([disabled]){background:rgba(248,113,113,.14)}
.btn.lg{height:50px;font-size:14.5px;border-radius:13px;width:100%}.btn.sm{height:32px;padding:0 12px;font-size:12px;border-radius:9px}.btn.sq{width:38px;padding:0}.btn.sq.sm{width:32px}
.btn.busy::before{content:"";width:14px;height:14px;border-radius:50%;border:2px solid rgba(255,255,255,.35);border-top-color:#fff;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.in,.sel{all:unset;box-sizing:border-box;width:100%;height:42px;padding:0 14px;border-radius:11px;background:var(--bg);border:1px solid var(--line2);color:var(--tx);font:500 13.5px var(--f);transition:border-color .15s,box-shadow .15s;user-select:text}
.in.mono{font-family:var(--m);font-size:13px}.in.sm{height:34px;width:auto}
.in:focus,.sel:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(108,140,255,.2)}
.in::placeholder{color:var(--dim)}
.sel{appearance:none;-webkit-appearance:none;cursor:pointer;padding-right:34px;line-height:40px;background:var(--bg) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%238a93b8' stroke-width='3'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E") no-repeat right 12px center}
.sel.sm{height:34px;line-height:32px;width:auto;min-width:130px}
.sel option{background:#10162a;color:var(--tx)}
label.f{display:block;font:700 10.5px var(--f);letter-spacing:.08em;text-transform:uppercase;color:var(--mut);margin:0 0 6px 2px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.hbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.sec{display:flex;align-items:center;gap:9px;margin:22px 4px 10px;font:700 11px var(--f);letter-spacing:.1em;text-transform:uppercase;color:var(--mut)}
.sec::before{content:"";width:6px;height:6px;border-radius:50%;background:linear-gradient(var(--acc),var(--acc2))}
.empty{display:flex;flex-direction:column;align-items:center;text-align:center;padding:38px 16px;color:var(--mut)}
.empty .ic{width:68px;height:68px;border-radius:22px;display:grid;place-items:center;background:var(--raised);border:1px solid var(--line);color:var(--acc);margin-bottom:14px}
.empty b{color:var(--tx);font-size:15px;margin-bottom:4px}
.seg{display:inline-flex;padding:3px;gap:2px;background:var(--bg);border:1px solid var(--line2);border-radius:11px}
.seg button{all:unset;box-sizing:border-box;padding:6px 13px;border-radius:8px;font:700 12px var(--f);color:var(--mut);cursor:pointer;transition:background .15s,color .15s}
.seg button:hover{color:var(--tx)}.seg button.on{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff}
.steps{display:flex;flex-direction:column;gap:12px;margin-bottom:18px}
.step{display:flex;align-items:center;gap:14px}
.num{width:28px;height:28px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(135deg,var(--acc),var(--acc2));font-weight:800;font-size:12px;flex:none}
.setting{display:flex;align-items:center;gap:18px;padding:12px 14px;background:var(--raised);border:1px solid var(--line);border-radius:13px}
.setting .grow{flex:1;min-width:0}.setting b{font-size:13.5px}.setting small{display:block;color:var(--mut);font-size:11.5px;margin-top:2px}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:6px}
.tile{padding:15px 16px;background:var(--surf);border:1px solid var(--line);border-radius:14px}
.tile small{display:block;font:700 10px var(--f);letter-spacing:.09em;text-transform:uppercase;color:var(--mut);margin-bottom:8px}
.tile b{display:flex;align-items:center;gap:8px;font-size:14.5px}
.kv{display:flex;align-items:center;gap:16px;padding:12px 15px;background:var(--raised);border:1px solid var(--line);border-radius:13px}
.kv>span{width:170px;color:var(--mut);flex:none}.kv code{font:700 14px var(--m);flex:1;overflow:hidden;text-overflow:ellipsis}
.progress{height:8px;border-radius:6px;background:var(--raised2);overflow:hidden;margin:16px 0 4px}
.progress i{display:block;height:100%;width:100%;transform-origin:left;transform:scaleX(0);background:linear-gradient(90deg,var(--acc),var(--acc2));transition:transform .4s var(--ease);will-change:transform}
pre.log{background:var(--surf);border:1px solid var(--line);border-radius:14px;padding:16px;font:12px/1.6 var(--m);color:#cdd5f5;overflow:auto;white-space:pre-wrap;word-break:break-word;min-height:300px;max-height:calc(100vh - 190px)}
.preview{font:11.5px var(--m);color:var(--dim);margin-top:12px;word-break:break-all}
.toasts{position:fixed;left:252px;right:0;bottom:22px;display:flex;justify-content:center;pointer-events:none;z-index:50}
.toast{pointer-events:auto;display:flex;align-items:flex-start;gap:12px;max-width:760px;padding:13px 18px;border-radius:14px;background:rgba(20,27,48,.92);backdrop-filter:blur(14px);border:1px solid var(--line2);box-shadow:0 18px 50px -12px rgba(0,0,0,.7);transform:translateY(24px);opacity:0;transition:transform .28s var(--ease),opacity .28s;will-change:transform,opacity;white-space:pre-line}
.toast.show{transform:none;opacity:1}
.toast .dot{margin-top:6px}
.scrim{position:fixed;inset:0;z-index:100;background:rgba(3,5,12,.62);backdrop-filter:blur(6px);display:grid;place-items:center;animation:fade .15s}
@keyframes fade{from{opacity:0}}
.modal{width:min(440px,92vw);padding:24px;border-radius:20px;background:var(--surf);border:1px solid var(--line2);box-shadow:0 30px 80px -20px #000;animation:pop .22s var(--ease)}
@keyframes pop{from{opacity:0;transform:translateY(10px) scale(.97)}}
.modal h2{font-size:17px;margin-bottom:6px}.modal p{color:var(--mut);margin-bottom:16px}.modal .acts{display:flex;justify-content:flex-end;gap:10px;margin-top:18px}
.check{display:flex;align-items:center;gap:10px;margin-top:14px;color:var(--mut);font-size:12.5px;cursor:pointer}
.check input{accent-color:var(--acc);width:16px;height:16px}
.banner{display:none;margin-bottom:16px;padding:11px 15px;border-radius:12px;background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.35);color:var(--bad)}
.banner.on{display:block}
svg.i{width:1em;height:1em;flex:none;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
@media (max-width:900px){.app{grid-template-columns:72px 1fr}.nav button span,.brand div,.chip span,.sfoot .chip small{display:none}.toasts{left:72px}.tiles{grid-template-columns:1fr 1fr}.grid2{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style></head><body><div class="app" id="app"></div><div class="toasts"><div class="toast" id="toast"></div></div>
<script>const ICONS={
power:'<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.77.04"/>',
key:'<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
user:'<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
gamepad:'<line x1="6" x2="10" y1="12" y2="12"/><line x1="8" x2="8" y1="10" y2="14"/><line x1="15" x2="15.01" y1="13" y2="13"/><line x1="18" x2="18.01" y1="11" y2="11"/><rect width="20" height="12" x="2" y="6" rx="2"/>',
sliders:'<line x1="21" x2="14" y1="4" y2="4"/><line x1="10" x2="3" y1="4" y2="4"/><line x1="21" x2="12" y1="12" y2="12"/><line x1="8" x2="3" y1="12" y2="12"/><line x1="21" x2="16" y1="20" y2="20"/><line x1="12" x2="3" y1="20" y2="20"/><line x1="14" x2="14" y1="2" y2="6"/><line x1="8" x2="8" y1="10" y2="14"/><line x1="16" x2="16" y1="18" y2="22"/>',
phone:'<rect width="14" height="20" x="5" y="2" rx="2"/><path d="M12 18h.01"/>',
activity:'<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
monitor:'<rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>',
refresh:'<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>',
copy:'<rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
x:'<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
check:'<path d="M20 6 9 17l-5-5"/>',
play:'<polygon points="6 3 20 12 6 21 6 3"/>',
stop:'<rect width="14" height="14" x="5" y="5" rx="2"/>',
link:'<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
logout:'<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/>',
login:'<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" x2="3" y1="12" y2="12"/>',
plus:'<path d="M5 12h14"/><path d="M12 5v14"/>',
trash:'<path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>',
globe:'<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
wrench:'<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
upload:'<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" x2="12" y1="3" y2="15"/>',
cpu:'<rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/>',
shield:'<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
list:'<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
wifi:'<path d="M12 20h.01"/><path d="M2 8.82a15 15 0 0 1 20 0"/><path d="M5 12.86a10 10 0 0 1 14 0"/><path d="M8.5 16.43a5 5 0 0 1 7 0"/>'};
const $=(s,r=document)=>r.querySelector(s), sleep=ms=>new Promise(r=>setTimeout(r,ms));
function ic(n,sz){const t=document.createElement('template');t.innerHTML=`<svg class="i" viewBox="0 0 24 24" style="width:${sz||18}px;height:${sz||18}px">${ICONS[n]||''}</svg>`;return t.content.firstChild}
function add(e,k){for(const c of k.flat(9)){if(c==null||c===false)continue;e.append(c.nodeType?c:document.createTextNode(c))}}
function h(tag,a,...k){const e=document.createElement(tag);for(const[n,v]of Object.entries(a||{})){if(v==null||v===false)continue;if(n==='class')e.className=v;else if(n==='html')e.innerHTML=v;else if(n==='style')e.style.cssText=v;else if(n.startsWith('on'))e.addEventListener(n.slice(2),v);else if(n in e)e[n]=v;else e.setAttribute(n,v===true?'':v)}add(e,k);return e}
function sig(el,v){const j=JSON.stringify(v);if(el._s===j)return false;el._s=j;return true}
function fail(e){console.error(e);toast('Unexpected error: '+(e&&e.message||e),'bad')}
let READY=new Promise(r=>window.pywebview?r():window.addEventListener('pywebviewready',()=>r()));
async function api(m,...a){await READY;try{return await window.pywebview.api[m](...a)}catch(e){fail(e)}}
function btn(label,kind,fn,o={}){const b=h('button',{class:`btn ${kind||''} ${o.cls||''}`,type:'button',title:o.title,disabled:!!o.disabled,onclick:async()=>{if(b.disabled)return;try{await fn()}catch(x){fail(x)}}},o.icon?ic(o.icon,o.size||16):null,label?h('span',{},label):null);return b}
const pill=(t,k)=>h('span',{class:'pill c-'+(k||'mut')},t);
const avatar=n=>h('div',{class:'av'},ic(n,22));
const section=t=>h('div',{class:'sec'},t);
function empty(icon,title,sub){return h('div',{class:'empty'},h('div',{class:'ic'},ic(icon,30)),h('b',{},title),h('span',{style:'white-space:pre-line'},sub))}
function field(label,input){return h('div',{},h('label',{class:'f'},label),input)}
function seg(vals,cur,cb){const w=h('div',{class:'seg'});const paint=v=>[...w.children].forEach(b=>b.classList.toggle('on',b.dataset.v===v));vals.forEach(v=>w.append(h('button',{type:'button','data-v':v,onclick:()=>{paint(v);cb(v)}},v)));paint(cur);w.set=paint;return w}
function select(vals,cur,cb,cls){const s=h('select',{class:'sel '+(cls||''),onchange:()=>cb(s.value)},vals.map(v=>h('option',{value:v},v)));s.value=cur;return s}
function setVal(el,v){if(document.activeElement!==el&&el.value!==v)el.value=v}
// ---- toast
let _tt;function toast(t,k){const e=$('#toast');e.replaceChildren(h('span',{class:'dot c-'+(k||'mut')}),h('span',{},t));requestAnimationFrame(()=>e.classList.add('show'));clearTimeout(_tt);_tt=setTimeout(()=>e.classList.remove('show'),k==='bad'?14000:8000)}
// ---- modal
function modal({title,text,body,ok='OK',cancel='Cancel',danger,onok}){return new Promise(res=>{
  const close=v=>{s.remove();document.removeEventListener('keydown',kd);res(v)};
  const kd=e=>{if(e.key==='Escape')close(null);if(e.key==='Enter'&&e.target.tagName!=='BUTTON'){e.preventDefault();go()}};
  const go=()=>{const v=onok?onok():true;if(v)close(v)};
  const s=h('div',{class:'scrim',onmousedown:e=>{if(e.target===s)close(null)}},h('div',{class:'modal',role:'dialog'},h('h2',{},title),text?h('p',{},text):null,body,
    h('div',{class:'acts'},btn(cancel,'ghost',()=>close(null)),btn(ok,danger?'danger':'primary',go))));
  document.body.append(s);document.addEventListener('keydown',kd);setTimeout(()=>{const i=$('input',s);i&&i.focus()},50)})}
const confirmBox=(title,text,ok='Confirm',danger=true)=>modal({title,text,ok,danger});
async function askPin(user,what,note){
  const i=h('input',{class:'in',type:'password',placeholder:'PIN',inputmode:'numeric',autocomplete:'off'});
  return modal({title:'PIN for '+user,text:note||('Enter the PIN that was set for '+user+' in WoL Host > Remote PIN on that PC. It also wakes the PC and starts the stream, so you type it only once.'),body:[i],ok:what||'Continue',
    onok:()=>{if(!i.value||i.value.length<4){i.focus();toast('A PIN is at least 4 characters','bad');return null}return i.value}})}
async function askAccessPin(n){
  const i=h('input',{class:'in',type:'password',placeholder:'Access PIN',inputmode:'numeric',autocomplete:'off'}),c=h('input',{type:'checkbox'});
  return modal({title:'Access PIN for '+n.label,text:(n.why==='BAD_PIN'?'That access PIN was not accepted. ':'')+'Waking and scanning need the PIN of one of the PC’s accounts (set in WoL Host > Remote PIN on the PC).',
    body:[i,h('label',{style:'display:flex;gap:8px;align-items:center;margin-top:12px;font-size:13px'},c,h('span',{},'Remember it on this computer (encrypted for your Windows account)'))],ok:'Continue',
    onok:()=>{if(!/^[0-9]{4,32}$/.test(i.value)){i.focus();toast('The access PIN is 4 to 32 digits.','bad');return null}return{pin:i.value,keep:c.checked}}})}
async function askPinPw(user,what){
  const i=h('input',{class:'in',type:'password',placeholder:'PIN',inputmode:'numeric',autocomplete:'off'}),w=h('input',{class:'in',type:'password',placeholder:'Password',autocomplete:'off',style:'margin-top:8px'});
  return modal({title:'PIN and password for '+user,text:'Signing '+user+' in needs both: the PIN set for '+user+' in WoL Host > Remote PIN on that PC, and '+user+'\u2019s own Windows / Microsoft account password. Both are asked every time and never saved.',body:[i,w],ok:what||'Continue',
    onok:()=>{if(!i.value||i.value.length<4){i.focus();toast('A PIN is at least 4 characters','bad');return null}if(!w.value){w.focus();toast('Enter the password too','bad');return null}return{pin:i.value,pw:w.value}}})}
async function copy(t,what){try{await navigator.clipboard.writeText(t)}catch(e){const a=h('textarea',{value:t,style:'position:fixed;opacity:0'});document.body.append(a);a.select();document.execCommand('copy');a.remove()}toast('Copied '+(what||t),'ok')}
// ---- GPU check: proves the page is really composited on the graphics card
function gpuInfo(){try{const c=document.createElement('canvas'),gl=c.getContext('webgl2')||c.getContext('webgl');if(!gl)return{hw:false,name:'WebGL unavailable'};const x=gl.getExtension('WEBGL_debug_renderer_info'),n=String(x?gl.getParameter(x.UNMASKED_RENDERER_WEBGL):gl.getParameter(gl.RENDERER));
  return{hw:!/swiftshader|llvmpipe|software|basic render|microsoft basic|softpipe/i.test(n),name:n.replace(/^ANGLE \((.*)\)$/,'$1').replace(/,? ?Direct3D\S*.*$/,'').replace(/^[^,]+, /,'')}}catch(e){return{hw:false,name:'unknown'}}}
// ---- app shell
let S=null,M=null,CUR=null,PAGES={};
function shell(o){
  const nav=h('div',{class:'nav'}),main=h('main',{});const bn=h('div',{class:'banner'},'Lost connection to the app - close and reopen it.');main.append(bn);
  o.nav.forEach(([k,label,icon])=>{const b=h('button',{type:'button','data-k':k,onclick:()=>go(k)},ic(icon,18),h('span',{},label));nav.append(b);const el=h('section',{class:'page','data-k':k});main.append(el);PAGES[k]={el,...o.pages[k](el)}});
  const g=gpuInfo(),gp=h('div',{class:'chip c-'+(g.hw?'ok':'warn'),title:g.hw?'The interface is drawn by your graphics card ('+g.name+')':'Software rendering. Start without --software-ui for GPU drawing.'},h('span',{class:'dot'}),h('span',{},g.hw?'GPU accelerated':'Software rendering'));
  const foot=h('div',{class:'sfoot'},o.foot||[],gp);
  $('#app').append(h('aside',{class:'side'},h('div',{class:'brand'},h('div',{class:'mark'},ic(o.icon,22)),h('div',{},h('b',{},o.title),h('small',{},o.sub))),nav,foot),main);
  window.__nav=nav;window.__banner=bn;return{foot,main}}
function go(k){CUR=k;for(const[n,p]of Object.entries(PAGES))p.el.classList.toggle('on',n===k);__nav.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.k===k));api('page',k);const p=PAGES[k];if(p.enter)p.enter();renderCur();$('main').scrollTop=0}
function renderCur(){if(!S||!CUR)return;const p=PAGES[CUR];if(p.render)p.render(S);if(window.__side)window.__side(S)}
async function run(o){
  await READY;M=await window.pywebview.api.meta();const sh=shell(o);window.__foot=sh.foot;o.start&&o.start();go(o.first());
  let rev=0,lastToast=0,lastGo=0,bad=0,lastPin=0,pinOpen=false;
  for(;;){try{const s=await window.pywebview.api.poll(rev);bad=0;__banner.classList.remove('on');
      if(s){rev=s.rev;S=s;if(s.toast&&s.toast.id!==lastToast){const first=!lastToast;lastToast=s.toast.id;if(!first||s.toast.t!=='Ready')toast(s.toast.t,s.toast.c)}
        if(s.go&&s.go.id!==lastGo){lastGo=s.go.id;go(s.go.page)}else renderCur();
        if(s.need_pin&&s.need_pin.id!==lastPin&&!pinOpen){const q=s.need_pin;lastPin=q.id;pinOpen=true;askAccessPin(q).then(r=>{pinOpen=false;if(r)api('submit_pin',q.id,r.pin,r.keep);else api('cancel_pin',q.id)})}}}
    catch(e){if(++bad>4)__banner.classList.add('on')}
    await sleep(450)}}

const head=(t,s,...a)=>h('div',{class:'head'},h('div',{},h('h1',{},t),h('p',{},s)),h('div',{class:'sp'}),...a);
const NAVS=[['link','Link with token','key'],['stream','Stream','gamepad'],['moonlight','Stream settings','sliders'],['phones','Relay phones','phone'],['log','Activity','activity']];
const TICKS=new Set(),mmss=s=>{s=Math.max(0,Math.round(s));const m=Math.floor(s/60),r=s%60;return m+':'+String(r).padStart(2,'0')};
const idleChip=(icon,label)=>{const sp=h('span',{}),c=h('div',{class:'chip',style:'display:none;gap:8px;white-space:nowrap'},ic(icon,15),sp);c._d=null;
  c.show=(left,t,tip,done)=>{c._d=(left==null||left<0)?null:{left,t:t||Date.now(),done};c.title=tip||'';c.tick()};
  c.tick=()=>{const d=c._d;if(!d){c.style.display='none';return}const l=d.left-(Date.now()-d.t)/1000;c.style.display='';sp.textContent=l<=0&&d.done?d.done:label+' '+mmss(l)};
  TICKS.add(c);return c};
setInterval(()=>TICKS.forEach(c=>c.tick()),500);
const done=(el,v)=>{if(v)el.value=''};
const tgHms=s=>{s=Math.max(0,Math.floor(s));const h=Math.floor(s/3600),m=Math.floor(s%3600/60),r=s%60;return h?h+':'+String(m).padStart(2,'0')+':'+String(r).padStart(2,'0'):m+':'+String(r).padStart(2,'0')};
const tgWhy=b=>!b?'':b==='balance'?'Limited by the total time balance of this account.':b==='weekly'?'Limited by the weekly limit of this account.':b==='monthly'?'Limited by the monthly limit of this account.':b.startsWith('hours:')?'Allowed hours end at '+b.slice(6)+'.':b.startsWith('closed:')?'Outside the allowed hours: they start at '+b.slice(7)+'.':'';
function tgUpd(e){const b=e.dataset.b||'',run=e.dataset.r==='1',l=Math.max(0,+e.dataset.l-(run?(Date.now()-(+e.dataset.t||Date.now()))/1000:0));
  e.textContent=l<=0?(b.startsWith('closed:')?'Outside allowed hours':'Time is up'):'Time left '+tgHms(l);e.className='pill tgchip c-'+(l<=0?'bad':l<300?'warn':'acc')}
setInterval(()=>document.querySelectorAll('.tgchip').forEach(tgUpd),500);
// TimeGuard time of an account the PC manages (WoL Host > TimeGuard > Accounts > Manage): x = host.tg[user], t = when the host answered; counts down while the user is signed in
const tgChip=(x,t)=>{if(!x||x.left==null||x.left<0)return null;const e=h('span',{class:'pill tgchip c-acc',title:tgWhy(x.by)+(x.run?' The time runs while this user is signed in.':' The time does not run while this user is signed out.'),'data-l':String(x.left),'data-t':String(t||Date.now()),'data-r':x.run?'1':'0','data-b':x.by||''});tgUpd(e);return e};
const PG={};
const tsChip=h('div',{class:'chip c-warn',style:'margin-top:12px'},h('span',{class:'dot'}),h('span',{},'Checking…'));
PG.link=el=>{
  const key=h('input',{class:'in mono',placeholder:'Paste token here',style:'height:52px',spellcheck:false}),
  cb=btn('Connect','primary lg',async()=>{if(!key.value.trim())return toast('Paste the token first.','bad');await api('connect',key.value)},{icon:'link',size:18});
  const steps=['Open WoL Relay on your phone','Tap “Generate PC token” and copy it','Paste it below and press Connect - PCs running WoL Host are detected and added automatically'];
  const sb=btn('Setup','ok lg',()=>api('setup'),{icon:'wrench',size:18}),sst=h('div',{class:'sub',style:'margin:10px 0 0'},'Checking…');
  el.append(head('Link with token','One token from the phone app is all you need'),
    h('div',{class:'card'},h('h3',{},'Setup'),h('div',{class:'sub'},'Installs Tailscale and Moonlight on this PC if they are missing. Do this first, then link with the token below.'),sb,sst),
    h('div',{class:'card'},h('div',{class:'steps'},steps.map((t,i)=>h('div',{class:'step'},h('div',{class:'num'},String(i+1)),h('span',{},t)))),key,h('div',{style:'height:12px'}),cb,tsChip));
  let was=false;
  return{render(S){sb.disabled=S.setup_busy;sb.classList.toggle('busy',!!S.setup_busy);sst.textContent='Tailscale: '+(S.ts_installed?'installed ✔':'not installed')+'   ·   Moonlight: '+(S.ml_ok?'installed ✔':'not installed');cb.disabled=S.connecting;cb.classList.toggle('busy',S.connecting);if(was&&!S.connecting&&S.connect_ok)key.value='';was=S.connecting}}};
PG.phones=el=>{
  const list=h('div',{class:'list'});
  el.append(head('Relay phones','Android phones on your tailnet running WoL Relay',btn('Rescan','ghost',()=>api('refresh'),{icon:'refresh'})),h('div',{class:'card flush'},list));
  return{
    render(S){
    if(sig(list,S.phones)){
    list.replaceChildren(...(S.phones.length?S.phones.map(d=>{const[t,c]=d.st==='ready'&&d.linked?['Ready','ok']:d.st==='needs'?['Needs token','warn']:d.linked?['Linked · offline','bad']:['Offline','mut'];
      return h('div',{class:'row'},avatar('phone'),h('div',{class:'grow'},h('div',{class:'t'},d.name),h('div',{class:'m'},d.ip)),pill(t,c),d.linked?btn('Unpair','danger',()=>api('unpair_phone',d.ip),{cls:'sm'}):null)}):[empty('phone','No relay phones found','Install WoL Relay on your phone and connect it to Tailscale.')]))}
  }}};
PG.log=el=>{const pre=h('pre',{class:'log'});el.append(head('Activity','Everything the app has done this session',btn('Copy','ghost',()=>copy(pre.textContent,'log'),{icon:'copy'})),pre);
  return{render(S){if(sig(pre,S.hist)){pre.textContent=S.hist.join('\n')||'Nothing yet.';pre.scrollTop=pre.scrollHeight}}}};
PG.stream=el=>{
  const pre=select([],'',v=>api('set_pref','preset',v),'sm'),cod=select([],'',v=>api('set_pref','codec',v),'sm'),mls=h('div',{class:'sub',style:'margin:0'}),mlb=btn('Download now','outline',()=>api('ml_retry'),{icon:'upload',cls:'sm'}),mlr=h('div',{class:'hbar',style:'margin-top:12px'},mls,mlb),
    offb=btn('Shut down','danger',async()=>{const q=S&&S.pcs.find(x=>x.name===S.sel);if(!q)return;
      if(await confirmBox('Shut down \u201c'+(q.label||q.name)+'\u201d?','The PC turns off. Use Stream with a username and Remote PIN to turn it on again.','Shut down'))api('shutdown_pc',q.name)},{icon:'power',cls:'sm'}),
    rmb=btn('Remove','danger',async()=>{const q=S&&S.pcs.find(x=>x.name===S.sel);if(!q)return;
      if(await confirmBox('Remove \u201c'+(q.label||q.name)+'\u201d?','It is removed from this app only. Nothing changes on the PC.','Remove'))api('del_pc',q.name)},{icon:'trash',cls:'sm'}),
    sel=select([],'',v=>api('select_pc',v),'sm'),pcs=h('div',{class:'hbar',style:'margin:0;flex:1;justify-content:flex-end'}),ul=h('div',{class:'list'}),fl=h('div',{class:'list'}),sv=h('div',{class:'list'});
  let init=false;const inact=idleChip('activity','Sign-out for inactivity in'),shutc=idleChip('power','PC shuts down in');
  const unI=h('input',{class:'in sm',placeholder:'Username',autocomplete:'off',spellcheck:false,style:'width:190px'}),
    pnI=h('input',{class:'in sm',type:'password',placeholder:'Remote PIN',inputmode:'numeric',autocomplete:'off',style:'width:150px'});
  const stN=h('span',{class:'sub',style:'margin:0;flex:1 1 260px;min-width:0'});          // messages of this box: right of the Add button, not in a pop-up below
  let cdT=null;
  const note=(t,k)=>{clearInterval(cdT);cdT=null;stN.textContent=t||'';stN.style.color=k==='bad'?'var(--bad)':k==='ok'?'var(--ok)':k==='warn'?'var(--warn)':'var(--mut)'};
  const cool=(msg,n)=>{note(msg,'bad');const end=Date.now()+n*1000;                // "Too many wrong attempts - try again in 30s": counts down, the cooldown is 30 seconds
    cdT=setInterval(()=>{const l=Math.ceil((end-Date.now())/1000);if(l<=0){note('The cooldown is over: you can try again.','ok');return}stN.textContent=msg.replace(/\d+s/,l+'s')},250)};
  let checking=false;
  async function streamAs(u,pin,pw,remember){                                      // sign in (waking the PC if needed) and stream as a typed username + Remote PIN
    const p=S&&S.pcs.find(x=>x.name===S.sel);if(!p){note('Pick a PC first.','bad');return false}
    const hh=p.host,ss=(hh&&hh.sessions)||[],users=(hh?hh.users:p.users_seen)||[],dualL=((hh?hh.pinmode:p.dual_seen)||[]).map(x=>x.toLowerCase()),pins=((hh?hh.hostpin:p.pin_seen)||[]).map(x=>x.toLowerCase());
    const k=u.toLowerCase(),real=users.find(x=>x.toLowerCase()===k);
    if(users.length&&!real){note('\u201c'+u+'\u201d is not a Windows user on this PC.','bad');return false}
    u=real||u;
    if(pins.length&&!pins.includes(k)){note(u+' has no remote PIN yet. On that PC open WoL Host > Remote PIN and set one.','bad');return false}
    const on=ss.find(x=>x.user.toLowerCase()===k),blocked=ss.length>0&&!on,need=dualL.includes(k)&&!on;
    let o='',op='';
    if(blocked){o=ss[0].user;
      if(!pins.includes(o.toLowerCase())){note(o+' is signed in and has no remote PIN, so they cannot be signed out from here. Set a PIN for '+o+' in WoL Host > Remote PIN.','bad');return false}
      if(checking)return false;checking=true;note('Checking '+u+'\u2019s PIN\u2026','mut');         // first: is the PIN of the account being signed IN correct? only then ask for the PIN of the user who is on the PC
      let vr;try{vr=await api('verify_login',p.name,u,pin,!!remember)}finally{checking=false}
      if(vr&&vr.ok===false){if(vr.wait)cool(vr.msg,vr.wait);else note(vr.msg||'That PIN was not accepted for '+u+'.','bad');return false}
      const q=await askPin(o,'Sign out & continue','Enter '+o+'\u2019s PIN to sign '+o+' out of the PC first. Then '+u+' is signed in and streamed.');if(!q)return false;op=q}
    api('stream',p.name,u,pin,!hh,need?pw:'',o,op,!!remember);return true}
  let fillFor=null;const rmI=h('input',{type:'checkbox'});rmI.checked=true;
  const fgb=btn('Forget saved','ghost',()=>{unI.value='';pnI.value='';api('forget_login',S.sel)},{icon:'trash',cls:'sm'});
  const curPc=()=>S&&S.pcs.find(x=>x.name===S.sel),savedFor=u=>{const q=curPc();return!!(q&&(q.saved_users||[]).some(x=>x.toLowerCase()===u.trim().toLowerCase()))};
  const ph=()=>{pnI.placeholder=savedFor(unI.value)?'Remote PIN (saved)':'Remote PIN'};unI.addEventListener('input',ph);
  let adding=false;
  const addb=btn('Add','outline',async()=>{
    const u=unI.value.trim();
    if(!u){unI.focus();return note('Enter the username.','bad')}
    if(!/^[0-9]{4,32}$/.test(pnI.value)){pnI.focus();return note('Enter the Remote PIN (4 to 32 digits) to save it.','bad')}
    if(adding||!S||!S.sel||addb.disabled)return;adding=true;addb.disabled=true;note('Saving '+u+'\u2026','mut');
    try{const r=await api('add_login',S.sel,u,pnI.value);if(r){if(r.wait&&!r.ok)cool(r.msg,r.wait);else note(r.msg,r.lv);if(r.ok)pnI.value=''}}finally{adding=false;addb.disabled=!(curPc()&&curPc().host)}},{icon:'plus',size:14,title:'Saves this username and PIN on this computer (no stream is started)'});
  for(const i of[unI,pnI])i.addEventListener('keydown',e=>{if(e.key==='Enter')addb.click()}),i.addEventListener('input',()=>note(''));
  el.append(head('Stream','Pick a PC, then stream as an active user or enter a username and its Remote PIN, and Moonlight connects',shutc,inact),
    h('div',{class:'card'},h('div',{class:'hbar'},h('b',{},'Quality'),pre,h('b',{style:'margin-left:10px'},'Codec'),cod,h('div',{class:'sp',style:'flex:1'}),btn('More settings','ghost',()=>go('moonlight'),{icon:'sliders',cls:'sm'})),mlr),
    h('div',{class:'sec'},'PC'),h('div',{class:'card'},h('div',{class:'hbar'},h('b',{},'PC'),sel,pcs,offb,rmb)),
    h('div',{class:'sec'},'Stream with a username'),h('div',{class:'card'},h('div',{class:'hbar'},unI,pnI,addb,stN),h('div',{class:'hbar',style:'margin-top:10px'},h('label',{style:'display:flex;gap:8px;align-items:center;font-size:13px'},rmI,h('span',{},'Remember the username and PIN on this computer')),fgb)),sv,fl,
    h('div',{class:'sec'},'Active Users'),h('div',{class:'card flush'},ul));
  return{enter(){api('select_pc',null)},render(S){
    if(!init){init=true;for(const o of M.presets.concat([M.custom]))pre.append(h('option',{value:o},o));for(const o of M.codecs)cod.append(h('option',{value:o},o))}
    {let best=null;for(const p of S.pcs){const hh=p.host;if(!hh||!hh.idle||!hh.idle.users)continue;for(const x of(hh.sessions||[])){const l=hh.idle.users[(x.user||'').toLowerCase()];if(l==null||l<0)continue;if(!best||(x.state==='active'&&best.st!=='active'))best={l,t:hh.t,u:x.user,pc:p.label||p.name,st:x.state}}}
      inact.show(best&&best.l,best&&best.t,best?best.u+' is signed out of '+best.pc+' after 15 minutes without keyboard, mouse or controller input. Any input resets it.':'','Signing out…')}
    {let b=null;for(const p of S.pcs){const hh=p.host;if(!hh||!hh.idle||hh.idle.login==null||hh.idle.login<0||(hh.sessions&&hh.sessions.length))continue;if(!b||hh.idle.login<b.l)b={l:hh.idle.login,t:hh.t,pc:p.label||p.name}}
      shutc.show(b&&b.l,b&&b.t,b?b.pc+' is at the sign-in screen: it shuts down by itself after 5 minutes with nobody signed in. Signing a user in stops it.':'','PC shutting down…')}
    const st=S.stream;setVal(pre,[...M.presets,M.custom].includes(st.preset)?st.preset:M.default_preset);setVal(cod,M.codecs.includes(st.codec)?st.codec:'auto');
    mls.textContent=S.mlstat.t;mlb.style.display=S.ml_ok?'none':'';mls.style.color=S.mlstat.c==='ok'?'var(--ok)':S.mlstat.c==='warn'?'var(--warn)':'var(--mut)';
    if(sig(sel,S.pcs.map(p=>[p.name,p.label])))sel.replaceChildren(...(S.pcs.length?S.pcs.map(p=>h('option',{value:p.name},p.label||p.name)):[h('option',{value:''},'(no PCs yet)')]));
    setVal(sel,S.sel||'');
    const p=S.pcs.find(x=>x.name===S.sel),hh=p&&p.host,sun=hh&&hh.sunshine;rmb.disabled=!p||!!p.live||!!p.busy;
    if(fillFor!==S.sel){fillFor=S.sel;unI.value=(p&&(p.saved_user||(p.saved_users||[])[0]))||'';pnI.value=''}
    fgb.style.display=p&&p.has_pin?'':'none';ph();
    addb.disabled=adding||!hh;addb.title=hh?'Saves this username and PIN on this computer (no stream is started)':'The PC is offline: users can be added once it is online.';
    {const sn=((hh&&hh.sessions)||[]).map(x=>x.user.toLowerCase()),anyIn=((p&&p.saved_users)||[]).some(u=>sn.includes(u.toLowerCase())),busy=!!(p&&(p.live||p.busy));      // locked while a saved user is signed in or signing in
      fgb.disabled=anyIn||busy;fgb.title=anyIn?'A saved user is signed in: it can be forgotten after they sign out.':busy?'The PC is signing in or streaming: wait until it is finished.':'Forget every saved username and PIN of this PC'}
    {const su=(p&&p.saved_users)||[],ss=((hh&&hh.sessions)||[]).map(x=>x.user.toLowerCase()),tgm=hh&&hh.tg;     // the saved users of this PC, right below the username box
      if(sig(sv,[S.sel,su,ss,!!p,!!hh,p&&p.live,p&&p.busy,tgm]))sv.replaceChildren(...(su.length?[section('Saved users'),h('div',{class:'card flush'},...su.map(u=>h('div',{class:'row'},avatar('user'),h('div',{class:'grow'},h('div',{class:'t'},u,ss.includes(u.toLowerCase())?pill('Signed in','ok'):null,tgChip(tgm&&tgm[u.toLowerCase()],hh&&hh.t)),h('div',{class:'m'},'PIN saved on this computer')),
        hh?btn('Stream','primary',()=>streamAs(u,'','',true),{icon:'play',size:14,cls:'sm',disabled:!p||!!p.live||!!p.busy,title:'Streams as '+u+' with the saved PIN'})
          :btn(p&&p.busy?'Waking…':'Wake','warn',()=>api('wake_user',p.name,u,''),{icon:'power',size:14,cls:'sm',disabled:!p||!!p.busy,title:'The PC is off: wakes it with '+u+'\u2019s saved PIN. Stream appears when it reaches the sign-in screen.'}),
        ss.includes(u.toLowerCase())&&!(p&&p.live)?btn('Sign out','danger',async()=>{if(await confirmBox('Sign out '+u+'?','Unsaved work in their open programs will be lost.','Sign out'))api('signout_user',p.name,u,'')},{icon:'logout',cls:'sm',disabled:!p||!!p.busy,title:'Signs '+u+' out of the PC with the saved PIN'}):null,
        (()=>{const lk=ss.includes(u.toLowerCase()),why=lk?u+' is signed in: sign them out first to forget the saved PIN.':(p&&(p.live||p.busy))?'The PC is signing in or streaming: wait until it is finished.':'';
          return btn('Forget','ghost',()=>api('forget_login',S.sel,u),{icon:'trash',cls:'sm',disabled:!!why,title:why||'Forget the saved PIN of '+u})})())))]:[]))}
    if(sig(pcs,[p&&[p.name,p.paired,p.live,p.busy,p.macs.length,!!hh,sun&&sun.running,sun===null||sun===undefined]])){
      pcs.replaceChildren(...(!p?[]:[p.live?pill('Live','acc'):null,pill(hh?'Online':p.ts_up?'On Tailscale · host not answering':'Host offline',hh?'ok':p.ts_up?'warn':'mut'),hh&&!p.live?pill(sun&&sun.running?'Sunshine ready':sun==null?'Update host':(hh.sessions&&hh.sessions.length)?'Sunshine off':'Sign-in screen',sun&&sun.running?'ok':'warn'):null,pill(p.paired?'Paired':'Not paired',p.paired?'acc':'mut'),
        p.live?btn('Stop','danger',()=>api('stop_stream',p.name),{icon:'stop',cls:'sm'}):null].filter(Boolean)));
      const who=hh&&hh.sessions&&hh.sessions[0];offb.style.display=(!hh||p.live)?'none':'';
      offb.disabled=!hh||!!p.busy||!hh.has_sessions||!!who;offb.title=!hh?'':!hh.has_sessions?'Update WoL Host on this PC (This PC > UPDATE) to use this.':who?who.user+' is signed in: Shut down only works when nobody is signed in.':'Turn this PC off (nobody is signed in).'}
    if(sig(ul,[S.sel,p&&[p.name,p.label,p.paired,p.live,p.busy,p.host,p.users_seen,p.pin_seen,p.dual_seen,p.macs.length,p.saved_user,p.has_pin]])){
      if(!p)ul.replaceChildren(empty('gamepad','No PCs yet','Link with a token on the Link with token page.\nInstall WoL Host on it to enable streaming.'));
      else{
        const ss=(hh&&hh.sessions)||[],dualL=((hh?hh.pinmode:p.dual_seen)||[]).map(x=>x.toLowerCase()),pins=((hh?hh.hostpin:p.pin_seen)||[]).map(x=>x.toLowerCase()),old=hh&&sun==null;
        if(old)ul.replaceChildren(empty('wrench','Host agent is outdated','On that PC open WoL Host > This PC > UPDATE.'));
        else if(!hh)ul.replaceChildren(empty('power','PC is offline','Stream appears when the PC reaches its sign-in screen.\nTo wake it, use a saved user above.'));
        else if(!ss.length)ul.replaceChildren(empty('user','Nobody is signed in','Enter a username and its Remote PIN above to sign in and stream.'));
        else ul.replaceChildren(...ss.map(x=>{const u=x.user,has=pins.includes(u.toLowerCase());
          return h('div',{class:'row hl-ok'},avatar('user'),
            h('div',{class:'grow'},h('div',{class:'t'},u,pill('Signed in · '+x.state,'ok'),tgChip(hh.tg&&hh.tg[u.toLowerCase()],hh.t),pill(has?(dualL.includes(u.toLowerCase())?'PIN + password':'PIN set'):'No PIN',has?'acc':'mut')),has?null:h('div',{class:'why'},'No remote PIN: set one on that PC in WoL Host > Remote PIN.')),
            h('div',{class:'acts'},
              has&&!p.live?btn('Sign out','danger',async()=>{const sv=savedFor(u),r=sv?'':await askPin(u,'Sign out');if((sv||r)&&await confirmBox('Sign out '+u+'?','Unsaved work in their open programs will be lost.','Sign out'))api('signout_user',p.name,u,r)},{icon:'logout',cls:'sm',disabled:p.busy}):null,
              btn('Stream','primary',async()=>{
                if(!has)return toast(u+' has no remote PIN yet. On that PC open WoL Host > Remote PIN and set one.','bad');
                const sv=savedFor(u),r=sv?'':await askPin(u,'Stream');if(sv||r)api('stream',p.name,u,r,false,'','','',false)},{icon:'play',size:14,disabled:p.busy||p.live})))}))}}
    if(sig(fl,S.found)){const found=S.found.map(f=>h('div',{class:'row'},avatar('monitor'),h('div',{class:'grow'},h('div',{class:'t'},f.label||f.name||f.ip),h('div',{class:'m'},f.ip)),btn('Save','outline',()=>api('add_found',f.ip),{icon:'plus',cls:'sm'})));
      fl.replaceChildren(...(found.length?[section('Detected on your tailnet (not saved yet)'),h('div',{class:'card flush'},...found)]:[]))}
  }}};
PG.moonlight=el=>{
  const box=h('div',{class:'card'}),pv=h('div',{class:'preview'});let gen=-1;
  el.append(head('Stream settings','How the stream looks, sounds and behaves. “Default” leaves the choice to Moonlight - only what you change is sent to it.'),box,pv);
  const line=(t,hint,ctl)=>h('div',{class:'setting'},h('div',{class:'grow'},h('b',{},t),hint?h('small',{},hint):null),ctl);
  const timers={};const deb=(k,f)=>{clearTimeout(timers[k]);timers[k]=setTimeout(f,250)};
  const txt=(ph,val,w,cb,mono=true)=>{const i=h('input',{class:'in sm'+(mono?' mono':''),placeholder:ph,value:val||'',style:'width:'+w+'px',oninput:()=>deb(ph,()=>cb(i.value.trim()))});return i};
  function build(S){gen=S.reset_n;const st=S.stream,o=st.ml||{},cu=st.custom||{};box.replaceChildren();
    box.append(h('div',{class:'list'}));const L=box.firstChild;let sec='';
    const sc=t=>L.append(section(t));
    sc('Quality');
    const pr=select([...M.presets,M.custom],[...M.presets,M.custom].includes(st.preset)?st.preset:M.default_preset,v=>api('set_pref','preset',v));pr.style.width='300px';pr.dataset.k='preset';L.append(line('Quality','Resolution, frame rate and bitrate in one choice.',pr));
    L.append(line('Custom quality','Used when Quality is “Custom…”: resolution (e.g. 2560x1440), frame rate, bitrate in Mbps.',h('div',{class:'hbar',style:'flex-wrap:nowrap'},txt('1920x1080',cu.res,120,v=>api('set_custom','res',v)),txt('fps',cu.fps,64,v=>api('set_custom','fps',v)),txt('Mbps',cu.mbps,74,v=>api('set_custom','mbps',v)))));
    const co=select(M.codecs,M.codecs.includes(st.codec)?st.codec:'auto',v=>api('set_pref','codec',v));co.style.width='130px';co.dataset.k='codec';L.append(line('Video codec','Auto lets Moonlight pick. HEVC and AV1 look better at low bitrates if your PCs support them.',co));
    sec='Quality';
    for(const[s,key,label,hint,opts]of M.spec){if(s!==sec){sec=s;sc(sec)}
      const cur=o[key]||M.any;let c;
      if(opts==null)c=seg([M.any,'On','Off'],cur,v=>api('set_ml',key,v));else{c=select(opts,opts.includes(cur)?cur:M.any,v=>api('set_ml',key,v));c.style.width='200px'}
      L.append(line(label,hint,c));
      if(s==='Session'&&key==='gameopt')L.append(line('App to stream','The Sunshine app to open. “Desktop” is the whole PC.',txt('Desktop',st.app,200,v=>api('set_pref','app',v))))}
    L.append(h('div',{style:'display:flex;justify-content:flex-end;margin-top:14px'},btn('Reset all to default','danger',async()=>{if(await confirmBox('Reset stream settings?','Every Moonlight option goes back to Default.','Reset'))api('ml_reset')},{icon:'refresh'})))}
  return{render(S){if(gen!==S.reset_n)build(S);pv.textContent=S.mlprev;box.querySelectorAll('select[data-k]').forEach(s=>setVal(s,S.stream[s.dataset.k]||s.value))}}};
run({title:'WoL Remote',sub:'Wake & control over Tailscale',icon:'power',nav:NAVS,pages:PG,first:()=>M.has_phones?'stream':'link',
  start(){window.__side=S=>{const k=S.ts===null?'warn':S.ts?'ok':'bad';tsChip.className='chip c-'+k+(S.ts?'':'');tsChip.lastChild.textContent=S.ts===null?'Checking…':S.ts?'Tailscale connected'+(S.ts_net?' · '+S.ts_net:''):'Tailscale offline';tsChip.title=S.ts&&S.ts_net?'Connected to Tailscale as '+S.ts_net:'';tsChip.lastChild.style.cssText='overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0';tsChip.style.maxWidth='100%';tsChip.firstChild.classList.toggle('live',!!S.ts)}}});
</script></body></html>'''

# =====================================================================================================================
#  GPU-accelerated interface (WebView2 / Chromium). All the logic above is reused; this layer only presents it.
#  Needs:  pip install pywebview     (the Microsoft WebView2 runtime ships with Windows 11 and current Windows 10)
#  Flags:  --software-ui = turn GPU drawing off (troubleshooting)
# =====================================================================================================================
def _log_error(name, text):
    try: open(os.path.join(os.path.expanduser("~"), name), "a").write(text + "\n")
    except Exception: pass


class _Tray:
    """Notification-area (tray) icon with balloon notifications, plain ctypes (no extra package). Left click = open, right click = menu (Open / Exit). Windows only; .ok tells if it started."""
    WM_CB = 0x8001
    def __init__(self, on_open, on_exit, tip="WoL Remote"):
        self.on_open, self.on_exit, self.tip = on_open, on_exit, tip
        self.hwnd = None; self.ok = False; self._ready = threading.Event(); self._nid = None; self._s32 = None
        if os.name != "nt": return
        threading.Thread(target=self._loop, daemon=True).start()
        self._ready.wait(5)
    def _call(self, f): threading.Thread(target=f, daemon=True).start()
    def _loop(self):
        try:
            from ctypes import wintypes as w
            u32, s32, k32 = ctypes.windll.user32, ctypes.windll.shell32, ctypes.windll.kernel32
            LRESULT = ctypes.c_ssize_t; self._s32 = s32
            WNDPROC = ctypes.WINFUNCTYPE(LRESULT, w.HWND, w.UINT, w.WPARAM, w.LPARAM)
            class WNDCLASS(ctypes.Structure): _fields_ = [("style", w.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int), ("hInstance", w.HINSTANCE), ("hIcon", w.HICON),
                                                          ("hCursor", w.HANDLE), ("hbrBackground", w.HBRUSH), ("lpszMenuName", w.LPCWSTR), ("lpszClassName", w.LPCWSTR)]
            class GUID(ctypes.Structure): _fields_ = [("a", ctypes.c_ulong), ("b", ctypes.c_ushort), ("c", ctypes.c_ushort), ("d", ctypes.c_ubyte * 8)]
            class NID(ctypes.Structure): _fields_ = [("cbSize", w.DWORD), ("hWnd", w.HWND), ("uID", w.UINT), ("uFlags", w.UINT), ("uCallbackMessage", w.UINT), ("hIcon", w.HICON), ("szTip", ctypes.c_wchar * 128),
                                                     ("dwState", w.DWORD), ("dwStateMask", w.DWORD), ("szInfo", ctypes.c_wchar * 256), ("uVersion", w.UINT), ("szInfoTitle", ctypes.c_wchar * 64),
                                                     ("dwInfoFlags", w.DWORD), ("guidItem", GUID), ("hBalloonIcon", w.HICON)]
            u32.DefWindowProcW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]; u32.DefWindowProcW.restype = LRESULT
            u32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASS)]
            u32.CreateWindowExW.argtypes = [w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, w.HWND, w.HMENU, w.HINSTANCE, w.LPVOID]; u32.CreateWindowExW.restype = w.HWND
            u32.GetMessageW.argtypes = [ctypes.POINTER(w.MSG), w.HWND, w.UINT, w.UINT]
            u32.PostMessageW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
            u32.DestroyWindow.argtypes = [w.HWND]; u32.SetForegroundWindow.argtypes = [w.HWND]
            u32.CreatePopupMenu.restype = w.HMENU; u32.AppendMenuW.argtypes = [w.HMENU, w.UINT, ctypes.c_size_t, w.LPCWSTR]
            u32.TrackPopupMenu.argtypes = [w.HMENU, w.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int, w.HWND, ctypes.c_void_p]; u32.DestroyMenu.argtypes = [w.HMENU]
            u32.LoadIconW.argtypes = [w.HINSTANCE, ctypes.c_void_p]; u32.LoadIconW.restype = w.HICON
            s32.ExtractIconW.argtypes = [w.HINSTANCE, w.LPCWSTR, w.UINT]; s32.ExtractIconW.restype = w.HICON
            s32.Shell_NotifyIconW.argtypes = [w.DWORD, ctypes.POINTER(NID)]
            k32.GetModuleHandleW.argtypes = [w.LPCWSTR]; k32.GetModuleHandleW.restype = w.HINSTANCE
            inst = k32.GetModuleHandleW(None); created = u32.RegisterWindowMessageW("TaskbarCreated")
            icon = s32.ExtractIconW(inst, sys.executable, 0) if getattr(sys, "frozen", False) else None
            if not icon or icon == 1: icon = u32.LoadIconW(None, 32512)                       # the default application icon
            def add():
                n = NID(); n.cbSize = ctypes.sizeof(NID); n.hWnd = self.hwnd; n.uID = 1; n.uFlags = 0x7; n.uCallbackMessage = self.WM_CB; n.hIcon = icon; n.szTip = self.tip
                self._nid = n; return bool(s32.Shell_NotifyIconW(0, ctypes.byref(n)))
            def menu(hwnd):
                m = u32.CreatePopupMenu(); u32.AppendMenuW(m, 0, 1, "Open WoL Remote"); u32.AppendMenuW(m, 0, 2, "Exit")
                pt = w.POINT(); u32.GetCursorPos(ctypes.byref(pt)); u32.SetForegroundWindow(hwnd)
                cmd = u32.TrackPopupMenu(m, 0x100 | 0x2, pt.x, pt.y, 0, hwnd, None)                # TPM_RETURNCMD | TPM_RIGHTBUTTON
                u32.PostMessageW(hwnd, 0, 0, 0); u32.DestroyMenu(m)
                if cmd == 1: self._call(self.on_open)
                elif cmd == 2: self._call(self.on_exit)
            def proc(hwnd, msg, wp, lp):
                try:
                    if msg == self.WM_CB:
                        ev = lp & 0xFFFF
                        if ev in (0x202, 0x203, 0x405): self._call(self.on_open)                    # left click / double click / click on a notification
                        elif ev in (0x205, 0x7B): menu(hwnd)                                         # right click
                        return 0
                    if created and msg == created: add(); return 0                                  # Explorer restarted: put the icon back
                    if msg == 0x0010: u32.DestroyWindow(hwnd); return 0                              # WM_CLOSE
                    if msg == 0x0002:                                                                # WM_DESTROY
                        if self._nid is not None: s32.Shell_NotifyIconW(2, ctypes.byref(self._nid))
                        u32.PostQuitMessage(0); return 0
                except Exception as e: _log_error(".wol_remote_error.log", f"tray: {e!r}")
                return u32.DefWindowProcW(hwnd, msg, wp, lp)
            self._proc = WNDPROC(proc)
            wc = WNDCLASS(); wc.lpfnWndProc = self._proc; wc.hInstance = inst; wc.lpszClassName = "WoLRemoteTray"
            u32.RegisterClassW(ctypes.byref(wc))
            self.hwnd = u32.CreateWindowExW(0, "WoLRemoteTray", "WoL Remote", 0, 0, 0, 0, 0, None, None, inst, None)
            self.ok = bool(self.hwnd) and add()
        except Exception as e: _log_error(".wol_remote_error.log", f"tray start: {e!r}"); self.ok = False
        finally: self._ready.set()
        if not self.ok: return
        from ctypes import wintypes as w
        msg = w.MSG()
        while ctypes.windll.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            ctypes.windll.user32.TranslateMessage(ctypes.byref(msg)); ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))
    def notify(self, title, text):
        """A Windows notification from the tray icon."""
        if not (self.ok and self._nid is not None): return
        try:
            n = self._nid; n.uFlags = 0x10; n.szInfoTitle = str(title)[:63]; n.szInfo = str(text)[:255]; n.dwInfoFlags = 1          # NIF_INFO, NIIF_INFO
            self._s32.Shell_NotifyIconW(1, ctypes.byref(n))
        except Exception as e: _log_error(".wol_remote_error.log", f"tray notify: {e!r}")
    def remove(self):
        if self.ok and self.hwnd:
            try: ctypes.windll.user32.PostMessageW(self.hwnd, 0x0010, 0, 0)
            except Exception: pass
            self.ok = False

class WebApi:
    """Everything the page can call. Public methods are exposed to JavaScript; attributes starting with _ are private."""
    BUSY_MAX = 180          # seconds: a per-PC "busy" claim (wake / sign-in / stream start) expires by itself after this, so a stuck task can never grey out the buttons for good
    def __init__(self):
        self._cfg = load(); self._lock = threading.RLock(); self._rev = 1; self._hist = deque(maxlen=300)
        self._toast = {"id": 0, "t": "Ready", "c": ""}; self._go = {"id": 0, "page": ""}
        self._refreshing = False; self._again = False; self._procs = {}; self._busy = {}; self._busy_lock = threading.Lock()
        self._stat = {}; self._devs = []; self._hosts = {}; self._found = []; self._ts_net = ""; self._ts_ok = True if ts_fast() else None          # connected: the chip shows it at once; otherwise it says Checking until the real check answers
        self._sel_pc = None; self._cur = None; self._mlstat = {"t": "", "c": ""}; self._ml_lock = threading.Lock()
        self._win = None; self._tray = None; self._hidden = False; self._quitting = False          # window hides to the tray (the X button); _hidden = it is in the tray now
        self._connecting = False; self._connect_ok = False; self._setup_busy = False; self._reset_n = 0; self._closed = False; self._ml_ok = bool(find_moonlight()); self._ml_try = 0.0
        self._apin = {}; self._pinreq = None; self._pinretry = None; self._pinid = 0; self._lan = {}                  # access PINs (only the ones kept with "Remember"), the open PIN question, devices the phones found
        for k, v in (self._cfg.get("apins") or {}).items():
            try: self._apin[k] = unprotect(v)
            except Exception: pass
        threading.Thread(target=self._get_ml, daemon=True).start()
        threading.Thread(target=self._loop, daemon=True).start()
        threading.Thread(target=self._fast_loop, daemon=True).start()
        threading.Thread(target=self._host_sync_loop, daemon=True).start()
        threading.Thread(target=self._detect_loop, daemon=True).start()

    # ---- plumbing
    def _bump(self):
        with self._lock: self._rev += 1
    def _say(self, t, col=""):
        t = str(t); self._hist.append(time.strftime("%H:%M:%S  ") + t.replace("\n", " "))
        with self._lock: self._toast = {"id": self._toast["id"] + 1, "t": t, "c": col}; self._rev += 1
    def _goto(self, page):
        with self._lock: self._go = {"id": self._go["id"] + 1, "page": page}; self._rev += 1
    def _run(self, f):
        def w():
            try: f()
            except Exception as e:
                import traceback; _log_error(".wol_remote_error.log", traceback.format_exc()); self._say(f"✖ Unexpected error: {e}", "bad")
        threading.Thread(target=w, daemon=True).start()
    def _loop(self):
        while not self._closed:
            self._refresh()
            if not self._ml_ok and time.time() - self._ml_try > 90: self._run(self._get_ml)          # keep trying to fetch Moonlight on its own
            time.sleep(AUTO_MS / 1000)
    HOST_SYNC_S = 3                                                   # the relay phone's host list (Tailscale IP + MACs) is asked for again this often
    def _host_sync_loop(self):
        """Always detecting: every HOST_SYNC_S seconds ask each linked relay phone for its hosts, silently (no messages, no PIN question). A host that joins the phone AFTER this
        client was linked shows up by itself within a few seconds. A round never overlaps the next one; while a token is being linked the link step does the asking."""
        while not self._closed:
            t0 = time.time()
            try:
                if not self._connecting and self._cfg["phones"]:
                    new = 0
                    for ph in list(self._cfg["phones"]):
                        if self._closed: break
                        new += self._sync_hosts(ph["ip"], quiet=True) or 0
                    if new: self._run(self._refresh)                       # a new PC: look at once whether it is online
            except Exception as e: _log_error(".wol_remote_error.log", f"host sync: {e!r}")
            time.sleep(max(0.5, self.HOST_SYNC_S - (time.time() - t0)))
    DETECT_S = 3                                                      # hosts that joined the tailnet are looked for this often (not only in the 10 s full refresh)
    def _detect_loop(self):
        """Detect WoL Hosts straight on the tailnet every DETECT_S seconds, as fast as the relay phone's host list. Silent; a new PC is saved and its state looked up at once."""
        while not self._closed:
            t0 = time.time()
            try:
                if not self._connecting and not self._refreshing and ts_fast():
                    before = len(self._cfg["pcs"])
                    self._adopt_hosts(detect_hosts({p.get("ip") for p in self._cfg["pcs"]} | {p["ip"] for p in self._cfg["phones"]}))
                    if len(self._cfg["pcs"]) != before: self._run(self._refresh)
            except Exception as e: _log_error(".wol_remote_error.log", f"detect loop: {e!r}")
            time.sleep(max(0.5, self.DETECT_S - (time.time() - t0)))
    def _fast_loop(self):
        """Stream page: ask the selected PC for its state every ~1.5 s (users, who is signed in, countdowns); the full refresh takes 10 s and scans every device."""
        miss, last = 0, None
        sk = lambda d: json.dumps({k: (d or {}).get(k) for k in ("sessions", "users", "msa", "hostpin", "pinmode", "login_fail", "sunshine", "name", "label")}, sort_keys=True, default=str)
        def idle_moved(old, new):          # the page counts down by itself; only a real jump (activity, session change) needs a new snapshot
            a, b = (old or {}).get("idle") or {}, (new or {}).get("idle") or {}
            if bool(a) != bool(b): return True
            tt = ((new or {}).get("_t", 0) - (old or {}).get("_t", 0)) / 1000.0
            def jump(x, y):
                if x is None or y is None or x < 0 or y < 0: return x != y
                return abs((x - tt) - y) > 3
            if jump(a.get("login"), b.get("login")): return True
            au, bu = a.get("users") or {}, b.get("users") or {}
            return set(au) != set(bu) or any(jump(au[k], bu[k]) for k in au)
        while not self._closed:
            key = (self._cur, self._sel_pc)
            time.sleep(0.3 if key != last else 1.5); last = key
            try:
                if self._refreshing or self._cur != "stream" or not self._sel_pc: continue
                n = self._sel_pc
                if self._is_busy(n) or self._streaming(n): continue
                pc = self._pc(n); ip = pc.get("ip") if pc else ""
                if not ip: continue
                h = host_info(ip)
                if self._sel_pc != n or self._is_busy(n): continue                     # the selection or an action moved on while we asked
                if not h:
                    miss += 1
                    if miss >= 2 and n in self._hosts: self._hosts.pop(n, None); self._bump()      # two misses in a row: really unreachable
                    continue
                miss = 0; old = self._hosts.get(n); self._hosts[n] = h
                if sk(h) != sk(old) or idle_moved(old, h): self._learn(pc, h); self._bump()
            except Exception as e: _log_error(".wol_remote_error.log", f"fast refresh: {e!r}")
    def _claim(self, n):
        with self._busy_lock:
            e = self._busy.get(n)
            if e and time.time() - e[1] < self.BUSY_MAX: return False
            self._busy[n] = (object(), time.time()); return True
    def _is_busy(self, n):
        with self._busy_lock:
            e = self._busy.get(n); return bool(e and time.time() - e[1] < self.BUSY_MAX)
    def _release(self, n):
        """Let go of the claim early (the stream: once Moonlight is open the PC must stay operable)."""
        with self._busy_lock: self._busy.pop(n, None)
        self._bump()
    def _guarded(self, n, f):
        with self._busy_lock: mine = (self._busy.get(n) or (None,))[0]
        try: f()
        finally:
            with self._busy_lock:
                if (self._busy.get(n) or (None,))[0] is mine: self._busy.pop(n, None)          # only our own claim: never one a later action made
            self._bump()
    def _streaming(self, n): p = self._procs.get(n); return bool(p and p[0].poll() is None)
    def _pc(self, name): return next((p for p in self._cfg["pcs"] if p["name"] == name), None)
    def _logins(self, pc):
        """The usernames + PINs remembered for this PC: {lowercase name: {"user": name, "pin": DPAPI blob}}. A single login saved by an older version is carried over."""
        lg = pc.setdefault("saved_logins", {})
        if pc.get("saved_pin") and pc.get("saved_user"):
            lg.setdefault(pc["saved_user"].lower(), {"user": pc["saved_user"], "pin": pc["saved_pin"]}); pc.pop("saved_pin", None)
        return lg
    def _saved_pin(self, pc, user):
        """The Remote PIN remembered for this username on this PC (encrypted with Windows DPAPI). The page never sees it."""
        try:
            e = self._logins(pc).get((user or "").strip().lower()) if pc else None
            if e and e.get("pin"): return unprotect(e["pin"])
        except Exception: pass
        return ""
    def forget_login(self, name, user=None):
        pc = self._pc(name)
        if not pc: return
        lg = self._logins(pc); user = (user or "").strip()
        signed = {(x.get("user") or "").lower() for x in ((self._hosts.get(name) or {}).get("sessions") or [])}          # saved users that are signed in right now
        if self._is_busy(name) or self._streaming(name) or (signed & ({user.lower()} if user else set(lg))):
            self._say("Cannot forget the saved login while that user is signed in or signing in. Sign out first.", "bad"); return
        if user:
            e = lg.pop(user.lower(), None)
            if (pc.get("saved_user") or "").lower() == user.lower(): pc.pop("saved_user", None)
            if e: save(self._cfg); self._bump(); self._say(f"Forgot the saved PIN for {e.get('user') or user} on {pc.get('label') or name}.")
            return
        lg.clear(); pc.pop("saved_user", None); pc.pop("saved_pin", None); save(self._cfg); self._bump(); self._say(f"Forgot the saved usernames and PINs for {pc.get('label') or name}.")
    def verify_login(self, name, user, pin="", remember=False):
        """Checks the PIN of the account that is about to be signed IN, BEFORE the page asks for the PIN of the user who is on the PC (nothing is signed in or out here).
        -> {"ok": False, "msg": ...} only when the PC definitely refused the PIN; {"ok": True/None} otherwise (None = could not be checked: the normal flow carries on and checks it again)."""
        pc = self._pc(name); user = (user or "").strip(); pin = pin or ""
        if not pc or not user: return {"ok": None}
        if not pin: pin = self._saved_pin(pc, user)
        if len(pin) < 4: return {"ok": False, "msg": "Enter the user's PIN (4 or more characters)."}
        key = "pc:" + pc["name"]; prev = self._apin.get(key)
        try:
            h = (host_info(pc["ip"], 3) if pc.get("ip") else None) or resolve_host(pc)
            if not h: return {"ok": None}
            if re.fullmatch(r"\d{4,32}", pin): self._apin[key] = pin          # same as stream(): the account's PIN is also the access PIN
            self._pin_check(pc, h["ip"])
            r = host_rpc(h["ip"], {"cmd": "verify", "user": user, "pin": pin}, 30)
        except PinNeeded:
            if prev is None: self._apin.pop(key, None)
            else: self._apin[key] = prev
            return {"ok": False, "msg": f"That PIN was not accepted for {user}. Check it and press Stream again."}
        except Exception: return {"ok": None}
        if not r.get("ok"):
            if prev is None: self._apin.pop(key, None)
            else: self._apin[key] = prev
            return {"ok": False, "msg": str(r.get("msg") or "That PIN is wrong."), **({"wait": int(r["wait"])} if r.get("wait") else {})}
        if remember and r.get("checked") and re.fullmatch(r"\d{4,32}", pin):          # the PC accepted this username + PIN: remember it now (it shows under "Saved users"), even if the other user is not signed out after all
            try: self._logins(pc)[user.lower()] = {"user": user, "pin": protect(pin)}; pc["saved_user"] = user; save(self._cfg); self._bump()
            except Exception as e: self._say(f"Could not save the PIN: {e}", "warn")
        return {"ok": True}
    def add_login(self, name, user, pin):
        """The "Add" button: remember a username + Remote PIN for this PC (shown under "Saved users"). When the PC answers it must accept the PIN first; when it is off the login is kept unchecked. -> bool saved"""
        pc = self._pc(name); user = (user or "").strip(); pin = pin or ""
        if not pc: return self._res(False, "Pick a PC first.", "bad")
        if not user: return self._res(False, "Enter the username.", "bad")
        if not re.fullmatch(r"\d{4,32}", pin): return self._res(False, "Only a PIN of 4 to 32 digits can be saved.", "bad")
        h = self._hosts.get(name) or {}; users = h.get("users") or pc.get("users_seen") or []
        if users:
            real = next((x for x in users if x.lower() == user.lower()), None)
            if not real: return self._res(False, f"\u201c{user}\u201d is not a Windows user on this PC.", "bad")
            user = real
        r = self.verify_login(name, user, pin, False)
        if r.get("ok") is False: return self._res(False, str(r.get("msg") or "That PIN was not accepted."), "bad", r.get("wait"))
        try: self._logins(pc)[user.lower()] = {"user": user, "pin": protect(pin)}; pc["saved_user"] = user; save(self._cfg); self._bump()
        except Exception as e: return self._res(False, f"Could not save the PIN: {e}", "bad")
        return self._res(True, f"✔ Saved {user} on {pc.get('label') or name}." if r.get("ok") else f"Saved {user} on {pc.get('label') or name} - the PC did not answer, so the PIN was not checked.", "ok" if r.get("ok") else "warn")
    def _res(self, ok, msg, lv, wait=None):
        """Answer for a button that shows its message next to itself: it goes into the activity log, not into a pop-up."""
        self._hist.append(time.strftime("%H:%M:%S  ") + str(msg).replace("\n", " ")); return {"ok": ok, "msg": str(msg), "lv": lv, **({"wait": int(wait)} if wait else {})}
    def _learn(self, pc, h):
        wm = h.get("wol_macs") or h.get("macs", []); ch = False
        if wm and (not pc.get("macs") or pc.get("learned")) and pc.get("macs") != wm: pc["macs"] = wm; pc["learned"] = True; ch = True
        if h.get("ip") and pc.get("ip") != h["ip"]: pc["ip"] = h["ip"]; ch = True
        lab = (h.get("label") or h.get("name") or "").strip()                    # the PC's name is set on the PC (WoL Host > This PC), never here
        if lab and pc.get("label") != lab: pc["label"] = lab; ch = True
        if "users" in h and (pc.get("users_seen") != h.get("users") or pc.get("pin_seen") != (h.get("hostpin") or []) or pc.get("dual_seen") != (h.get("pinmode") or [])): pc["users_seen"] = h.get("users") or []; pc["pin_seen"] = list(h.get("hostpin") or []); pc["dual_seen"] = list(h.get("pinmode") or []); ch = True
        if ch: save(self._cfg)

    # ---- state the page polls
    def meta(self):
        spec = [[s, k, lab, hint, (list(opts) if opts is not None else None)] for s, k, lab, hint, _f, opts in ML_SPEC]
        return {"presets": list(PRESETS), "default_preset": DEFAULT_PRESET, "codecs": list(CODECS), "custom": CUSTOM, "any": _ANY,
                "spec": spec, "has_phones": bool(self._cfg["phones"] or self._cfg["pcs"])}
    def poll(self, rev):
        with self._lock:
            if rev == self._rev: return None
            r = self._rev
        return self._snap(r)
    def _snap(self, rev):
        cfg = self._cfg; hosts = dict(self._hosts)
        def hv(h): return None if not h else {"ip": h.get("ip"), "name": h.get("name", ""), "sunshine": h.get("sunshine"), "sessions": h.get("sessions") or [],
                                              "has_sessions": "sessions" in h, "idle": h.get("idle"), "tg": h.get("tg") or {}, "t": h.get("_t"), "users": h.get("users") or [], "msa": list(h.get("msa") or []), "hostpin": list(h.get("hostpin") or []), "pinmode": list(h.get("pinmode") or [])}          # Microsoft accounts -> Windows PIN, everyone else -> local Windows password
        pcs = [{"name": p["name"], "ip": p.get("ip", ""), "macs": list(p.get("macs", [])), "paired": bool(p.get("paired")), "host": hv(hosts.get(p["name"])),
                "ts_up": bool(p.get("ip")) and p.get("ip") in ONLINE_IPS, "live": self._streaming(p["name"]), "busy": self._is_busy(p["name"]), "label": p.get("label") or p["name"], "users_seen": list(p.get("users_seen") or []), "pin_seen": list(p.get("pin_seen") or []), "dual_seen": list(p.get("dual_seen") or []), "saved_user": p.get("saved_user") or "", "saved_users": [e.get("user") or k for k, e in self._logins(p).items()], "has_pin": bool(self._logins(p))} for p in cfg["pcs"]]
        linked = {p["ip"]: p for p in cfg["phones"]}; rows = {d["ip"]: d["name"] for d in self._devs}
        for ip, p in linked.items(): rows[ip] = p["name"]
        phones = [{"ip": ip, "name": n, "st": self._stat.get(ip, "offline"), "linked": ip in linked} for ip, n in rows.items()]
        st = cfg["stream"]
        try: prev = "Moonlight will run:  moonlight " + " ".join(ml_args("moonlight", "<PC>", st)[1:])
        except Exception: prev = ""
        known = {m.lower(): (p.get("label") or p["name"]) for p in cfg["pcs"] for m in p.get("macs", [])}
        names = [p["name"] for p in cfg["pcs"]]; sel = self._sel_pc if self._sel_pc in names else (names[0] if names else None)
        return {"rev": rev, "ts": self._ts_ok, "ts_net": self._ts_net, "toast": dict(self._toast), "go": dict(self._go), "pcs": pcs, "phones": phones,
                "found": [{"name": h.get("name", ""), "label": h.get("label") or h.get("name", ""), "ip": h["ip"]} for h in self._found], "stream": {"preset": st.get("preset", DEFAULT_PRESET), "codec": st.get("codec", "auto"),
                "app": st.get("app", ""), "ml": st.get("ml") or {}, "custom": st.get("custom") or {}}, "mlprev": prev, "mlstat": dict(self._mlstat),
                "sel": sel, "hist": list(self._hist), "ml_ok": self._ml_ok, "setup_busy": self._setup_busy, "ts_installed": ts_installed(), "need_pin": dict(self._pinreq) if self._pinreq else None,
                "lan": [{"ip": ip, "busy": v["busy"], "t": v["t"], "devs": [{"ip": d["ip"], "mac": d["mac"], "known": known.get(d["mac"])} for d in v["devs"]]} for ip, v in list(self._lan.items())], "connecting": self._connecting, "connect_ok": self._connect_ok, "reset_n": self._reset_n}
    def page(self, k): self._cur = k

    # ---- refresh
    def refresh(self): self._refresh()
    def _refresh(self):
        if self._refreshing: self._again = True; return
        self._refreshing = True
        try:
            ok = ts("ip", "-4").lstrip().startswith("100.")                      # quick local check (no peer list): show the Tailscale chip right away, the slower scans follow
            if self._ts_ok is None or self._ts_ok != ok: self._ts_ok = ok; self._bump()
            net = ts_label() if ok else ""                                                  # the account / network name shown next to "Tailscale connected"
            if net != self._ts_net: self._ts_net = net; self._bump()
            devs = peers() if ok else []
            linked = {p["ip"]: p["secret"] for p in self._cfg["phones"]}
            allv = devs + [{"name": p["name"], "ip": p["ip"]} for p in self._cfg["phones"] if p["ip"] not in {d["ip"] for d in devs}]
            for d, (st, _) in zip(allv, probe_all(allv, linked)): self._stat[d["ip"]] = st
            self._devs = devs; hosts, found = {}, []
            if ok:
                if True:                                                         # PCs on this tailnet are detected by themselves: no relay phone needed
                    try: self._adopt_hosts(detect_hosts({p.get("ip") for p in self._cfg["pcs"]} | {p["ip"] for p in self._cfg["phones"]}))
                    except Exception as e: _log_error(".wol_remote_error.log", f"detect hosts: {e!r}")
                allh = scan_hosts(self._cfg["pcs"])
                for pc in self._cfg["pcs"]:
                    h = match_host(pc, allh) or (host_info(pc["ip"]) if pc.get("ip") else None)
                    if h: hosts[pc["name"]] = h; self._learn(pc, h)
                found = []                                                       # unknown devices are never looked for: PCs come from the relay phone
            self._hosts, self._found, self._ts_ok = hosts, found, ok
            self._bump()
        except Exception as e: _log_error(".wol_remote_error.log", f"refresh: {e!r}")
        finally:
            self._refreshing = False
            if self._again: self._again = False; self._run(self._refresh)

    # ---- PCs
    def _adopt_hosts(self, found):
        """Save hosts that answered directly on the tailnet (no relay phone needed). Their MAC addresses come from the host itself, so Wake works later as soon as the relay is online."""
        changed = False
        for h in found:
            hip = str(h.get("ip", "")); macs = [m for m in (str(x).lower().replace("-", ":") for x in (h.get("wol_macs") or h.get("macs", []))) if re.fullmatch(MAC, m)]
            old = next((p for p in self._cfg["pcs"] if (hip and p.get("ip") == hip) or ({norm(m) for m in macs} & {norm(m) for m in p.get("macs", [])})), None)
            if old:
                if hip and old.get("ip") != hip: old["ip"] = hip; changed = True
                merged = list(dict.fromkeys(old.get("macs", []) + macs))
                if merged != old.get("macs", []): old["macs"] = merged; changed = True
                continue
            name = str(h.get("name") or hip).strip()[:40] or hip
            if any(p["name"] == name for p in self._cfg["pcs"]): name = f"{name} ({hip})"
            self._cfg["pcs"].append({"name": name, "ip": hip, "macs": macs, "learned": bool(macs)}); changed = True
            self._say(f"✔ Detected “{h.get('label') or name}” on the tailnet.", "ok")
        if changed: save(self._cfg); self._bump()
    def add_by_ip(self, ip):
        ip = (ip or "").strip()
        if not (re.fullmatch(IPV4, ip) and ip.startswith("100.")): self._say("Enter the PC's Tailscale IP (100.x.x.x).", "bad"); return False
        def f():
            self._say(f"Contacting {ip}…"); h = host_info(ip) or {}; macs = h.get("wol_macs") or h.get("macs", []); name = h.get("name") or ip
            old = self._pc(name) or {}
            self._cfg["pcs"] = [p for p in self._cfg["pcs"] if p["name"] != name] + [{**old, "name": name, "ip": ip, "macs": macs or old.get("macs", []), "learned": bool(macs)}]
            pc = self._pc(name)
            if h and pc: self._learn(pc, h)
            save(self._cfg); self._sel_pc = name
            self._say(f"✔ Added “{h.get('label') or name}”." if h else f"Added {ip}, but WoL Host did not answer yet - is the PC on and set up?", "ok" if h else "warn"); self._refresh()
        self._run(f); return True
    def add_found(self, ip):
        h = next((x for x in self._found if x["ip"] == ip), None)
        if not h: return
        macs = h.get("wol_macs") or h.get("macs", [])
        self._cfg["pcs"] = [p for p in self._cfg["pcs"] if p.get("ip") != h["ip"] and p["name"] != h.get("name")] + [{"name": h.get("name", h["ip"]), "ip": h["ip"], "macs": macs, "learned": True}]
        pc = self._pc(h.get("name", h["ip"]))
        if pc: self._learn(pc, h)
        save(self._cfg); self._say(f"Saved “{h.get('label') or h.get('name', h['ip'])}”.", "ok"); self._run(self._refresh)
    def del_pc(self, n):
        if self._streaming(n): return self._say(f"Stop the stream to {n} before removing it.", "warn")
        self._cfg["pcs"] = [p for p in self._cfg["pcs"] if p["name"] != n]; save(self._cfg)
        self._hosts.pop(n, None)
        if self._sel_pc == n: self._sel_pc = None
        self._say(f"Removed “{n}”."); self._bump()
    def unpair_phone(self, ip):
        self._cfg["phones"] = [p for p in self._cfg["phones"] if p["ip"] != ip]; save(self._cfg); self._bump(); self._run(self._refresh)

    # ---- wake
    def _do_wake(self, a, label="", pin=""):
        """-> (ok, message, pin_problem) ; pin_problem is 'NEED_PIN' / 'BAD_PIN' when a phone asked for the access PIN."""
        mac, ip = (a, "") if re.fullmatch(MAC, a) else ("", a); errs = []; pf = None
        for p in self._cfg["phones"]:
            try:
                r = request(p["ip"], p["secret"], "wake", mac, ip, data=pin)
                if r == "OK": return True, f"✔ Magic packet for {label or a} sent via {p['name']}", None
                if r in ("NEED_PIN", "BAD_PIN"): pf = pf or r; errs.append(f"{p['name']}: access PIN {'needed' if r == 'NEED_PIN' else 'wrong'}")
                else: errs.append(f"{p['name']}: {r}")
            except Exception: errs.append(f"{p['name']}: relay offline - waking needs the phone online (open WoL Relay and check Tailscale)")
        return False, "✖ " + (" | ".join(errs) or "no relay phone linked"), pf
    def _wake_pc(self, pc):
        """Wake by every known MAC through the phones, with the access PIN. Raises PinNeeded when a phone wants (another) PIN."""
        macs = pc.get("macs") or []
        if not macs: return False, f"✖ No MAC known for {pc['name']}. Open Relay phones and add it from the devices the phone found, or press Connect while the PC is on so it is learned automatically."
        pin = self._apin.get("pc:" + pc["name"], "")
        with ThreadPoolExecutor(len(macs)) as ex: res = list(ex.map(lambda m: self._do_wake(m, pc["name"], pin), macs))          # all MACs at once
        for ok, m, _ in res:
            if ok: return True, m
        pf = next((x[2] for x in res if x[2]), None)
        if pf: raise PinNeeded(pf)
        return res[0][0], res[0][1]
    def wake_user(self, name, user="", pin=""):
        """Wake an offline PC with the same Remote PIN that streaming uses (the saved PIN of `user`, or a typed `pin`). Waits until the host agent answers (the PC is at its
        sign-in screen) so the page can switch from Wake to Stream. The magic packet is repeated while waiting: one sent while the PC is still shutting down is lost."""
        pc = self._pc(name)
        if not pc: return
        n = name; user = (user or "").strip(); pin = pin or ""
        if not pin and user: pin = self._saved_pin(pc, user)
        if not re.fullmatch(r"\d{4,32}", pin): return self._say("Enter the Remote PIN (4 to 32 digits) to wake the PC.", "bad")
        if not self._cfg["phones"]: self._goto("link"); return self._say("Link a phone first: paste its token.", "bad")
        if self._streaming(n): return self._say(f"Already streaming {n}.")
        if not self._claim(n): return self._say(f"Already working on {n} - please wait.")
        self._apin["pc:" + pc["name"]] = pin; self._bump()
        def f():
            h = host_info(pc["ip"], 3) if pc.get("ip") else None
            if h: self._hosts[n] = h; self._learn(pc, h); self._bump(); return self._say(f"{n} is already awake.", "ok")
            self._say(f"Waking {pc.get('label') or n}…"); ok, m = self._wake_pc(pc); self._say(m, "ok" if ok else "bad")
            if not ok: return
            for i in range(120):                                              # up to 4 minutes: boot, Tailscale, the host agent
                time.sleep(2)
                if self._closed: return
                if i and i % 12 == 0:                                         # every ~25 s: send the packet again (the first one can be missed)
                    try: self._wake_pc(pc)
                    except Exception: pass
                self._say(f"Waiting for {n} to start… ({i * 2}s)")
                h = host_info(pc["ip"], 1.5) if pc.get("ip") else None
                if not h and i % 5 == 4: h = resolve_host(pc)
                if h and "sessions" in h:
                    self._hosts[n] = h; self._learn(pc, h); self._bump()
                    self._notify("PC is awake", f"{pc.get('label') or n} is awake and at its sign-in screen. You can stream now.")
                    return self._say(f"✔ {pc.get('label') or n} is awake. Stream is available now.", "ok")
            self._notify("PC did not wake", f"{pc.get('label') or n} did not come online.")
            self._say(f"✖ {n} did not come online. Check that it is plugged in and WoL Host is set up (Tailscale must run before sign-in), then press Wake again.", "bad")
        def f_pin():
            try: f()
            except PinNeeded:
                self._apin.pop("pc:" + pc["name"], None); self._say("✖ That PIN was not accepted. Check it and press Wake again.", "bad")
        self._run(lambda: self._guarded(n, f_pin))
    def wake_pc(self, name):
        pc = self._pc(name)
        if not pc: return
        if not self._cfg["phones"]: self._goto("link"); return self._say("Link a phone first: paste its token.", "bad")
        def f(): self._say(f"Waking {name}…"); ok, m = self._wake_pc(pc); self._say(m, "ok" if ok else "bad")
        self._run(self._pin_wrap(pc, lambda _p: self.wake_pc(name), f))

    # ---- wake / scan PIN = the remote PIN of any account on the PC (set in WoL Host > Remote PIN). Streaming and sign-out reuse the account PIN already typed (see stream / signout_user);
    #      this question is only asked for a plain "Wake" or a network scan.
    def _ask_pin(self, key, label, why, retry):
        """Show the PIN box in the window. When the person answers, `retry(pin)` runs the action again."""
        if why == "BAD_PIN":
            self._apin.pop(key, None)
            if (self._cfg.get("apins") or {}).pop(key, None) is not None: save(self._cfg)
        with self._lock:
            self._pinid += 1; self._pinreq = {"id": self._pinid, "key": key, "label": label, "why": why}; self._pinretry = retry
        self._say(f"The access PIN for {label} is {'wrong' if why == 'BAD_PIN' else 'needed'}.", "warn"); self._bump()
    def submit_pin(self, rid, pin, keep):
        pin = str(pin or "").strip()
        if not re.fullmatch(r"\d{4,32}", pin): self._say("The access PIN is 4 to 32 digits.", "bad"); return False
        with self._lock:
            req, retry = self._pinreq, self._pinretry
            if not req or req["id"] != rid: return False
            self._pinreq = self._pinretry = None
        self._apin[req["key"]] = pin
        ap = self._cfg.setdefault("apins", {})
        if keep: ap[req["key"]] = protect(pin)
        else: ap.pop(req["key"], None)
        save(self._cfg); self._bump()
        if retry: self._run(lambda: retry(pin))
        return True
    def cancel_pin(self, rid):
        with self._lock:
            if self._pinreq and self._pinreq["id"] == rid: self._pinreq = self._pinretry = None
        self._bump()
    def _pin_wrap(self, pc, retry, f):
        def g():
            try: f()
            except PinNeeded as e: self._ask_pin("pc:" + pc["name"], pc.get("label") or pc["name"], str(e), retry)
        return g
    def _pin_check(self, pc, ip):
        """Before anything is done on an online PC: does it accept our access PIN? Raises PinNeeded when not."""
        p = self._apin.get("pc:" + pc["name"], "")
        if p: APIN[ip] = p
        else: APIN.pop(ip, None)
        try: host_rpc(ip, {"cmd": "accesscheck"}, 10)
        except PinNeeded: raise
        except Exception: pass                                           # an old WoL Host does not know the PIN: nothing to check

    # ---- devices the phone finds on its network (needs the access PIN)
    def discover(self, ip):
        ph = next((p for p in self._cfg["phones"] if p["ip"] == ip), None)
        if not ph: return
        st = self._lan.setdefault(ip, {"devs": [], "t": 0, "busy": False})
        if st["busy"]: return
        st["busy"] = True; self._bump()
        def f():
            try:
                key = "phone:" + ip; pin = self._apin.get(key) or next(iter(self._apin.values()), "")
                self._say(f"Asking {ph['name']} for the devices on its network…")
                try: r = request(ip, ph["secret"], "discover", data=pin, timeout=40)
                except Exception as e: return self._say(f"✖ {ph['name']} did not answer: {e}", "bad")
                if r in ("NEED_PIN", "BAD_PIN"): return self._ask_pin(key, ph["name"], r, lambda _p: self.discover(ip))
                if not r.startswith("MACS|"): return self._say(f"✖ {ph['name']}: {r or 'no answer'}", "bad")
                devs = [{"ip": str(d.get("ip", "")), "mac": str(d.get("mac", "")).lower()} for d in json.loads(r[5:]) if re.fullmatch(MAC, str(d.get("mac", "")))]
                st["devs"] = devs; st["t"] = time.time()
                self._say(f"✔ {ph['name']} found {len(devs)} physical device{'s' if len(devs) != 1 else ''} on its network.", "ok")
            except Exception as e: self._say(f"✖ Scan failed: {e}", "bad")
            finally: st["busy"] = False; self._bump()
        self._run(f)
    def _sync_hosts(self, ip, quiet=False):
        """Ask the phone for the hosts that joined it (Tailscale IP + MAC addresses) and add them as PCs. Runs right after a token was used and then all the time in the background
        (quiet=True: no messages, no PIN question - it uses the PIN the app already holds and just tries again next round). -> number of new PCs, or None."""
        ph = next((p for p in self._cfg["phones"] if p["ip"] == ip), None)
        if not ph: return None
        key = "phone:" + ip; pin = self._apin.get(key) or next(iter(self._apin.values()), "")
        try: r = request(ip, ph["secret"], "hosts", data=pin, timeout=6 if quiet else 15)
        except Exception as e:
            if not quiet: self._say(f"✖ {ph['name']} did not send its hosts: {e}", "bad")
            return None
        if r in ("NEED_PIN", "BAD_PIN"):
            if not quiet: self._ask_pin(key, ph["name"], r, lambda _p: self._sync_hosts(ip))
            else: self._hosts_need_pin = True
            return None
        if not r.startswith("HOSTS|"):
            if not quiet: self._say(f"✖ {ph['name']}: {r or 'no answer'} (update the WoL Relay app on the phone)", "bad")
            return None
        try: hosts = json.loads(r[6:])
        except Exception: return None
        new = 0; changed = False
        for h in hosts if isinstance(hosts, list) else []:
            hip = str(h.get("ip", "")); name = str(h.get("name") or hip).strip()[:40] or hip
            macs = [m for m in (str(x).lower().replace("-", ":") for x in h.get("macs", [])) if re.fullmatch(MAC, m)]
            if not macs and not hip: continue
            old = next((p for p in self._cfg["pcs"] if {norm(m) for m in macs} & {norm(m) for m in p.get("macs", [])} or (hip and p.get("ip") == hip)), None)
            if old:                                                        # already known: only fill in what is missing / changed
                if hip and old.get("ip") != hip: old["ip"] = hip; changed = True
                merged = list(dict.fromkeys(old.get("macs", []) + macs))
                if merged != old.get("macs", []): old["macs"] = merged; changed = True
            else:
                if any(p["name"] == name for p in self._cfg["pcs"]): name = f"{name} ({hip})"
                self._cfg["pcs"].append({"name": name, "ip": hip, "macs": macs, "learned": True}); new += 1; changed = True
        if changed: save(self._cfg); self._bump()
        return new
    def add_mac(self, mac, ip=""):
        m = (mac or "").strip().lower().replace("-", ":")
        if not re.fullmatch(MAC, m): return self._say("That is not a MAC address.", "bad")
        old = next((p for p in self._cfg["pcs"] if m in p.get("macs", [])), None)
        if old: return self._say(f"Already saved as “{old.get('label') or old['name']}”.")
        name = "PC " + m[-5:].replace(":", "").upper()                                  # a placeholder: the PC's real name comes from WoL Host on that PC
        self._cfg["pcs"] = [p for p in self._cfg["pcs"] if p["name"] != name] + [{"name": name, "ip": "", "macs": [m], "learned": False}]
        save(self._cfg); self._say("Saved. The PC's name appears once WoL Host on it answers.", "ok"); self._run(self._refresh)

    # ---- link with token
    def connect(self, tok):
        parts = parse_token(tok or "")
        if not parts: self._say("Invalid token. Copy the whole token from the phone app.", "bad"); return False
        if self._connecting: return False
        k, secret, pip = parts; extra = ["--unattended"] if os.name == "nt" else []
        self._connecting = True; self._connect_ok = False; self._bump()
        def f():
            try:
                self._say("1/3  Connecting to Tailscale…")
                if "100." not in ts("status"):                                   # already on a tailnet: never re-join with the key (a used key could disconnect this PC)
                    self._say("1/3  Joining the Tailscale network with the token…")
                    out = ts("up", f"--auth-key={k}", "--force-reauth", "--reset", *extra)
                    if "not installed" in out and os.name == "nt":
                        self._say("Installing Tailscale…")
                        _run(["winget", "install", "-e", "--id", "Tailscale.Tailscale", "--silent", "--accept-source-agreements", "--accept-package-agreements"], capture_output=True)
                        out = ts("up", f"--auth-key={k}", "--force-reauth", "--reset", *extra)
                    if "100." not in ts("status"):
                        return self._say(f"✖ Could not join with this token (expired or already used? make a new one).\n{out[:200]}", "bad")
                self._ts_ok = True; self._ts_net = ts_label(ts_account(True)); self._bump()
                self._say("1/3  ✔ Connected to Tailscale" + (f" ({self._ts_net})" if self._ts_net else "") + ".", "ok")
                self._say("2/3  Scanning the tailnet for PCs…"); before = len(self._cfg["pcs"])
                for i in range(5):                                               # PCs are found on the tailnet itself - the relay phone is not needed for this
                    self._adopt_hosts(detect_hosts({p.get("ip") for p in self._cfg["pcs"]}))
                    if len(self._cfg["pcs"]) > before: break
                    time.sleep(2)
                n = len(self._cfg["pcs"]) - before
                self._say(f"✔ Connected. {n} PC{'s' if n != 1 else ''} detected on the tailnet." if n else "✔ Connected. No PC with WoL Host found yet - they appear automatically when they come online.", "ok")
                self._connect_ok = True; self._goto("stream"); self._run(self._refresh)
                self._run(lambda: self._link_relay(secret, pip))                 # the relay phone is looked for in the background
            finally: self._connecting = False; self._bump()
        self._run(f); return True
    def _link_relay(self, secret, pip):
        """Background: look for the relay phone this token belongs to and link it (needed for Wake). Gives up after ~3 minutes; never blocks the PCs list."""
        if getattr(self, "_relay_busy", False): return
        self._relay_busy = True
        try:
            for _ in range(90):
                if self._closed: return
                devs = peers()
                if pip and pip not in {d["ip"] for d in devs}: devs.append({"name": pip, "ip": pip})
                res = probe_all(devs, {d["ip"]: secret for d in devs})
                found = [(d, r) for d, r in zip(devs, res) if r[0] == "ready"]
                if found:
                    for d, (_, model) in found:
                        self._cfg["phones"] = [p for p in self._cfg["phones"] if p["ip"] != d["ip"]] + [{"name": model or d["name"], "ip": d["ip"], "secret": secret}]
                    save(self._cfg); self._bump()
                    for d, _ in found: self._sync_hosts(d["ip"], quiet=True)
                    return self._say(f"✔ Relay phone linked: {', '.join(m or d['name'] for d, (_, m) in found)}. Wake is available now.", "ok")
                why = next((r for d, r in ((d, probe_raw(d["ip"], secret)) for d in devs) if r.startswith("DENIED")), "")
                if why: return self._say(f"The relay phone refused this token: {why}. Remove the old entry in the WoL Relay app, or make a new token. PCs are still detected on the tailnet.", "warn")
                time.sleep(2)
            self._say("The relay phone did not answer yet. PCs are detected on the tailnet; open WoL Relay on the phone and paste a fresh token to enable Wake.", "warn")
        finally: self._relay_busy = False

    # ---- Moonlight
    def _ml_say(self, t, col=""): self._mlstat = {"t": t, "c": col}; self._bump()
    def setup(self):
        """SETUP button: installs Tailscale and Moonlight, whichever of them is missing. Safe to press again."""
        if self._setup_busy: return self._say("Setup is already running - please wait.", "warn")
        def f():
            self._setup_busy = True; self._bump()
            try:
                fails = []
                if ts_installed(): self._say("Tailscale is already installed.", "ok")
                elif os.name != "nt": fails.append("Tailscale: install it from tailscale.com/download, then press Setup again")
                else:
                    self._say("Installing Tailscale… (this can take a minute)")
                    try: _run(["winget", "install", "-e", "--id", "Tailscale.Tailscale", "--silent", "--accept-source-agreements", "--accept-package-agreements"], capture_output=True, timeout=900)
                    except FileNotFoundError: pass
                    except Exception as e: _log_error(".wol_remote_error.log", f"Tailscale install failed: {e}")
                    if not ts_installed(): fails.append("Tailscale could not be installed (winget missing or blocked) - get it from tailscale.com/download")
                    else: _TSA["t"] = 0.0
                if find_moonlight(): self._upd_ml()
                else:
                    self._say("Installing Moonlight…")
                    if not self._get_ml(): fails.append("Moonlight could not be downloaded - details are in the Activity tab")
                if fails: self._say("✖ " + " · ".join(fails), "bad")
                else: self._say("✔ Setup finished: Tailscale and Moonlight are installed. Paste the phone token below and press Connect.", "ok")
            finally: self._setup_busy = False; self._bump()
        self._run(f)
    def ml_retry(self): self._say("Downloading Moonlight…"); self._run(self._get_ml)
    def _upd_ml(self):
        p = find_moonlight(); self._ml_ok = bool(p); self._ml_say(f"✔  Moonlight ready ({p})" if p else "Moonlight will be downloaded automatically.", "ok" if p else "")
    def _get_ml(self):
        with self._ml_lock:
            p = find_moonlight()
            if p: self._upd_ml(); return p
            self._ml_try = time.time()
            try: ml_install(lambda t, c=None: self._ml_say(t, "warn" if c == WARN else ""))
            except Exception as e:
                _log_error(".wol_remote_error.log", f"Moonlight download failed: {e}")
                self._ml_say("✖  Could not get Moonlight yet - retrying automatically. Details are in the Activity tab.", "warn"); self._say(f"✖ Moonlight download failed: {str(e)[:500]}", "bad"); return ""
            self._upd_ml(); return find_moonlight()
    def set_pref(self, k, v): self._cfg["stream"][k] = v; save(self._cfg); self._bump()
    def set_ml(self, k, v): self._cfg["stream"].setdefault("ml", {})[k] = v; save(self._cfg); self._bump()
    def set_custom(self, k, v): self._cfg["stream"].setdefault("custom", {})[k] = (v or "").strip(); save(self._cfg); self._bump()
    def ml_reset(self):
        st = self._cfg["stream"]
        for k in ("preset", "codec", "app", "ml", "custom"): st.pop(k, None)
        save(self._cfg); self._reset_n += 1; self._say("Moonlight settings are back to default.", "ok")

    # ---- streaming
    def stop_stream(self, n):
        if self._streaming(n): self._procs[n][0].terminate(); self._say(f"Stopped streaming {n}.")
    def on_close(self):
        """The window's X button: hide to the tray and keep running (streams and wake-ups continue). Only the tray menu's Exit really closes the app."""
        if not self._quitting and self._win is not None and self._tray is not None and self._tray.ok:
            try:
                first = not self._hidden; self._win.hide(); self._hidden = True
                if first: self._notify("WoL Remote is still running", "It keeps running in the tray. Click the icon to open it, right-click for Exit.")
                return False                                                  # cancel the close
            except Exception as e: _log_error(".wol_remote_error.log", f"hide to tray: {e!r}")
        self._shutdown(); return True
    def _shutdown(self):
        self._closed = True
        for n in list(self._procs): self.stop_stream(n)
        if self._tray: self._tray.remove()
    def _notify(self, title, text):
        """A Windows notification, only while the window is hidden in the tray (otherwise the in-app message is enough)."""
        if self._hidden and self._tray is not None: self._tray.notify(title, text)
    def _tray_open(self):
        self._hidden = False
        try: self._win.show(); self._win.restore()
        except Exception as e: _log_error(".wol_remote_error.log", f"tray open: {e!r}")
    def _tray_exit(self):
        self._quitting = True; self._shutdown()
        try: self._win.destroy()
        except Exception: os._exit(0)
    def stream(self, name, user=None, pin=None, wake=False, pw="", other_user="", other_pin="", remember=False):
        pc = self._pc(name)
        if not pc: return
        n = name; user = (user or "").strip(); pin = pin or ""; pw = pw or ""; other_user = (other_user or "").strip(); other_pin = other_pin or ""
        if not pin: pin = self._saved_pin(pc, user)                                  # nothing typed: the PIN remembered for this username
        if not user or len(pin) < 4: return self._say("Enter the user's PIN (4 or more characters).", "bad")
        if self._streaming(n): return self._say(f"Already streaming {n}.")
        if not self._claim(n): return self._say(f"Already working on {n} - please wait.")
        if re.fullmatch(r"\d{4,32}", pin): self._apin["pc:" + pc["name"]] = pin          # the account's PIN is also the wake / stream PIN: it is sent to the phone and to the PC, nothing more is asked
        self._bump()
        def f0():
            woke = False
            if not ((host_info(pc["ip"], 4) if pc.get("ip") else None) or resolve_host(pc)):         # offline: Stream is not available - the PC is woken with Wake, and Stream comes back at its sign-in screen
                return self._say(f"✖ {n} is offline. Press Wake first; Stream is available once it reaches the sign-in screen.", "bad")
            self._say("Getting Moonlight ready…" if not find_moonlight() else f"Connecting to {n}…"); ml = self._get_ml()
            if not ml: return self._say("✖ Moonlight isn't available (download failed - check your internet connection and try again).", "bad")
            self._say(f"Connecting to {n}…"); h = resolve_host(pc)
            if not h:                                   # the button's "wake" flag comes from a cached view that can be stale: whenever the PC does not answer, wake it
                if not self._cfg["phones"]: self._goto("link"); return self._say("Link a phone first: paste its token.", "bad")
                if not woke:
                    self._say(f"{n} does not answer - waking it…")
                    woke, m = self._wake_pc(pc); self._say(m, "ok" if woke else "bad")
                    if not woke: return
                for i in range(120):                    # up to 4 minutes: boot, Tailscale, the host agent
                    self._say(f"Waiting for {n} to start… ({i * 2}s)"); time.sleep(2)
                    h = host_info(pc["ip"], 1.5) if pc.get("ip") else None        # the known address first: one quick request
                    if not h and i % 5 == 4: h = resolve_host(pc)                 # every few rounds the full scan (the address can have changed)
                    if h and ((h.get("sunshine") or {}).get("running") or ("sessions" in h and not h["sessions"])): break
            if not h: return self._say(f"✖ {n} did not answer. If it woke up, it may not be on Tailscale yet at its sign-in screen: on the PC press WoL Host > This PC > UPDATE once (that switches Tailscale to run before sign-in).", "bad")
            self._pin_check(pc, h["ip"])                    # the access PIN: asked right here when the PC wants one (the phone already asked it for the wake-up)
            sun = h.get("sunshine")
            if sun is None: return self._say("✖ This PC runs an old WoL Host without Sunshine. Install the new WoL Host and run setup again.", "bad")
            h2, err = stream_signin(pc, h, user, pin, lambda m, lv=None: self._say(m, lv) if lv else self._say(m), pw, other_user, other_pin)
            if not h2: return self._say(f"✖ {err}", "bad")
            if remember and re.fullmatch(r"\d{4,32}", pin):                          # the PIN was accepted: remember the username + PIN (PIN encrypted for this Windows account)
                try: self._logins(pc)[user.lower()] = {"user": user, "pin": protect(pin)}; pc["saved_user"] = user; save(self._cfg); self._bump()
                except Exception as e: self._say(f"Could not save the PIN: {e}", "warn")
            h = h2; self._learn(pc, h); ip = h["ip"]; save(self._cfg)
            if 0 <= (h.get("disk_free_mb") if h.get("disk_free_mb") is not None else -1) < 500: return self._say(f"✖ The PC's system drive has only {h['disk_free_mb']} MB free. Sunshine cannot save its pairing or logs - free some space on it first.", "bad")
            my_name = f"WoL Remote ({socket.gethostname()})"; known = (h.get("sunshine") or {}).get("client_names")
            if known is None or my_name not in known:                           # the user's PIN was correct, so pair for real: Sunshine does not have this client (list empty / lost / cannot be read)
                if pc.get("paired"): self._say("Sunshine on the PC does not know this app (pairing lost) - pairing again…", "warn")
                ml_forget_hosts(ml); pc["paired"] = False; save(self._cfg)
            for attempt in (1, 2):                     # attempt 2 only happens when Moonlight said "not paired": pair now, then stream again
                st = ml_is_paired(ml, ip)                                  # ask Moonlight for the truth: the saved flag can be stale, and every user has their own Sunshine
                if st is not None and bool(pc.get("paired")) != st: pc["paired"] = st; save(self._cfg)
                if not pc.get("paired"):
                    self._say(f"{n} is not paired yet - pairing with Sunshine first (one time only)…"); ok, m = ml_pair(ml, ip, f"WoL Remote ({socket.gethostname()})")
                    if not ok: return self._say(f"✖ Pairing failed: {m}", "bad")
                    hh = host_info(ip) or {}
                    if ml_is_paired(ml, ip) is False or (hh.get("sunshine") or {}).get("clients") == 0 or my_name not in ((hh.get("sunshine") or {}).get("client_names") or [my_name]): pc["paired"] = False; save(self._cfg); return self._say("✖ Pairing finished but Sunshine did not keep it. Free some space on the PC's data drive and run WoL Host > Set up again.", "bad")
                    pc["paired"] = True; pc["paired_user"] = ((h.get("sessions") or [{}])[0].get("user") or "").lower() or None; save(self._cfg)
                try: host_cmd(ip, "prime", 20)                      # wake the session's mouse / keyboard input before Moonlight connects (an older WoL Host just ignores this)
                except Exception: pass
                p = subprocess.Popen(ml_args(ml, ip, self._cfg["stream"]), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, **NOWIN)
                tail = deque(maxlen=12); self._procs[n] = (p, tail)
                threading.Thread(target=lambda p=p, tail=tail: [tail.append(l.strip()) for l in p.stdout], daemon=True).start()
                threading.Thread(target=self._prime_while_streaming, args=(p, ip), daemon=True).start()
                self._release(n)                                    # Moonlight may sit on "connecting" for ever: that must never grey out the buttons - Stop ends it
                self._say(f"✔ Streaming {n}. Close the stream window or press Stop to end it.", "ok"); self._notify("Stream started", f"Streaming {pc.get('label') or n}.")
                rc = p.wait(); time.sleep(0.4); msg = " | ".join(list(tail)[-3:])
                if rc not in (0, None) and not self._streaming(n):
                    if re.search("pair", msg, re.I):
                        pc["paired"] = False; ml_forget_hosts(ml); save(self._cfg)            # the saved flag was stale: Moonlight is not really paired
                        if attempt == 1: self._say(f"{n} is not paired - starting pairing…", "warn"); continue
                    self._say(f"✖ Stream ended ({rc}): {msg or 'no output'}", "bad")
                else: self._say(f"Stream to {n} ended.")
                break
        def f0_pin():
            try: f0()
            except PinNeeded:                                  # the phone or the PC did not accept the PIN just typed: say so here instead of asking for a second "access PIN"
                self._apin.pop("pc:" + pc["name"], None); self._say(f"✖ That PIN was not accepted for {user}. Check it and press Stream again.", "bad")
        self._run(lambda: self._guarded(n, f0_pin))
    def _prime_while_streaming(self, p, ip):
        """Moonlight needs a few seconds to connect: wake the PC's mouse / keyboard input again once it has (harmless: a 1-pixel nudge and one Shift tap)."""
        for wait in (6, 10):
            time.sleep(wait)
            if p.poll() is not None or self._closed: return
            try: host_cmd(ip, "prime", 20)
            except Exception: pass
    def pair(self, name):
        pc = self._pc(name)
        if not pc: return
        n = name
        if self._streaming(n): return self._say(f"Already streaming {n}.")
        if not self._claim(n): return self._say(f"Already working on {n} - please wait.")
        self._bump()
        def f():
            self._say("Getting Moonlight ready…"); ml = self._get_ml()
            if not ml: return self._say("✖ Moonlight isn't available (download failed - check your internet connection).", "bad")
            h = resolve_host(pc); sun = (h or {}).get("sunshine")
            if not h: return self._say("✖ Host not found. Is the PC on and WoL Host running?", "bad")
            if sun is None: return self._say("✖ Host agent is outdated. On the PC: WoL Host > This PC > UPDATE.", "bad")
            if not sun.get("running"): return self._say("✖ Sunshine isn't running: stream a user from the Stream tab first." if not h.get("sessions") else "✖ Sunshine isn't running in the signed-in session yet.", "bad")
            self._learn(pc, h); self._say(f"Pairing with {n}…"); ok, m = ml_pair(ml, h["ip"], f"WoL Remote ({socket.gethostname()})")
            if ok: pc["paired"] = True; save(self._cfg)
            self._say(f"✔ Paired with {n}." if ok else f"✖ Pairing failed: {m}", "ok" if ok else "bad")
        self._run(lambda: self._guarded(n, f))
    def shutdown_pc(self, name):
        """Shut the PC down - only while nobody is signed in (the host checks again itself)."""
        pc = self._pc(name)
        if not pc: return
        n = name
        if self._streaming(n): return self._say("Stop the stream first.", "bad")
        if not self._claim(n): return self._say(f"Already working on {n} - please wait.")
        self._bump()
        def f():
            h = resolve_host(pc); ip = (h or {}).get("ip") or pc.get("ip")
            if not h or not ip: return self._say(f"✖ {n} is not reachable.", "bad")
            if "sessions" not in h: return self._say("✖ This PC's WoL Host is too old for Shut down: press UPDATE on it (This PC).", "bad")
            if h["sessions"]: return self._say(f"✖ {h['sessions'][0]['user']} is signed in on {n}: it can only be shut down when nobody is signed in.", "bad")
            self._pin_check(pc, ip)
            try: r = host_cmd(ip, "shutdown", 20)
            except PinNeeded: raise
            except Exception as e: return self._say(f"✖ Could not reach {n}: {e}", "bad")
            if r == "OK": self._say(f"✔ {n} is shutting down.", "ok"); self._hosts.pop(n, None)
            else: self._say(f"✖ {n} refused: {r.removeprefix('ERR ') or 'no reason given'}", "bad")
        self._run(lambda: self._guarded(n, self._pin_wrap(pc, lambda _p: self.shutdown_pc(name), f)))
    def unpair(self, name):
        pc = self._pc(name)
        if not pc: return
        n = name
        if self._streaming(n): return self._say("Stop the stream first.", "bad")
        if not self._claim(n): return self._say(f"Already working on {n} - please wait.")
        self._bump()
        def f():
            ml = find_moonlight(); h = resolve_host(pc); ip = (h or {}).get("ip") or pc.get("ip")
            if ml and ip:
                ok, m = ml_unpair(ml, ip)
                if not ok: return self._say(f"✖ Unpair failed: {m or 'Moonlight gave no reason'}", "bad")
            pc["paired"] = False; save(self._cfg); self._say(f"✔ Unpaired from {n}.", "ok")
        self._run(lambda: self._guarded(n, f))

    # ---- Stream page: PC and users
    def select_pc(self, name):
        names = [p["name"] for p in self._cfg["pcs"]]
        new = name if name in names else (self._sel_pc if self._sel_pc in names else (names[0] if names else None))
        if new != self._sel_pc: self._sel_pc = new
        self._bump(); pc = self._pc(new)
        if not pc: return
        def f():
            h = host_info(pc["ip"]) if pc.get("ip") else None                     # ask the PC we already know directly (one quick request) ...
            if h and pc.get("macs") and not match_host(pc, [h]): h = None
            if not h: h = resolve_host(pc)                                        # ... and only scan the whole tailnet when that fails
            if h: self._hosts[pc["name"]] = h; self._learn(pc, h)
            self._bump()
        self._run(f)
    def signout_user(self, name, user, pin):
        """Sign a user out of the PC. Their remote PIN is needed every time."""
        pc = self._pc(name); user = (user or "").strip(); pin = pin or ""
        if not pc: return
        if not pin: pin = self._saved_pin(pc, user)
        if len(pin) < 4: return self._say("Enter the user's PIN (4 or more characters).", "bad")
        n = name
        if self._streaming(n): return self._say("Stop the stream first.", "bad")
        if not self._claim(n): return self._say(f"Already working on {n} - please wait.")
        if re.fullmatch(r"\d{4,32}", pin): self._apin["pc:" + pc["name"]] = pin          # the account's PIN is also the PIN the PC asks for before it does anything
        self._bump()
        def f():
            h = resolve_host(pc)
            if not h: return self._say("✖ Host not found. Is the PC on, with WoL Host running?", "bad")
            self._pin_check(pc, h["ip"])
            self._say(f"Signing {user} out of {pc.get('label') or n}…")
            try: r = host_rpc(h["ip"], {"cmd": "logoff", "user": user, "pin": pin}, 70)
            except PinNeeded: raise
            except Exception as e: return self._say(f"✖ The PC did not answer: {e}", "bad")
            if not r.get("ok"): return self._say(f"✖ {r.get('msg') or 'Sign-out was refused.'}", "bad")
            for _ in range(20):
                time.sleep(2); hh = host_info(h["ip"])
                if hh and not any(x["user"].lower() == user.lower() for x in hh.get("sessions", [])):
                    self._hosts[n] = hh; self._run(self._refresh); return self._say(f"✔ {user} signed out. The PC is at the sign-in screen.", "ok")
            self._say(f"{user} is still signing out…", "warn")
        self._run(lambda: self._guarded(n, self._pin_wrap(pc, lambda _p: self.signout_user(name, user, pin), f)))

def _webview2_present():
    if os.name != "nt": return True
    for root in ("HKLM\\SOFTWARE\\WOW6432Node", "HKLM\\SOFTWARE", "HKCU\\SOFTWARE"):
        try:
            r = _run(["reg", "query", root + "\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", "/v", "pv"], capture_output=True, text=True)
            if r.returncode == 0 and "pv" in r.stdout: return True
        except Exception: pass
    return False

def run_web():
    """Open the GPU-accelerated window. True = it ran; False = it could not start (the caller falls back to the classic window)."""
    try:
        import webview
        if os.name == "nt" and not _webview2_present():
            _run(["winget", "install", "-e", "--id", "Microsoft.EdgeWebView2Runtime", "--silent", "--accept-source-agreements", "--accept-package-agreements"], capture_output=True)
        flags = "--disable-gpu" if "--software-ui" in sys.argv else "--enable-gpu-rasterization --ignore-gpu-blocklist --enable-zero-copy --enable-features=CanvasOopRasterization"
        os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (os.environ.get("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "") + " " + flags).strip()
        api = WebApi()
        win = webview.create_window("WoL Remote", html=HTML, js_api=api, width=1200, height=820, min_size=(980, 700), background_color="#070a14", text_select=True)
        api._win = win; api._tray = _Tray(api._tray_open, api._tray_exit)
        win.events.closing += api.on_close
        webview.start(gui="edgechromium" if os.name == "nt" else None)
        return True
    except Exception:
        import traceback; _log_error(".wol_remote_error.log", "web UI failed, using classic window:\n" + traceback.format_exc()); return False

def run_classic():
    """The old customtkinter window was removed (it still had the Login user tab and saved PINs). Tell the person what the main window needs."""
    msg = "WoL Remote could not open its window.\nInstall pywebview (pip install pywebview) and the Microsoft WebView2 runtime, then start it again.\n\nDetails: " + os.path.join(os.path.expanduser("~"), ".wol_remote_error.log")
    try:
        import tkinter as tk, tkinter.messagebox as mb
        r = tk.Tk(); r.withdraw(); mb.showerror("WoL Remote", msg); r.destroy()
    except Exception: print(msg)

if __name__ == "__main__":
    if not run_web(): run_classic()
